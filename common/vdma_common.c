// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#include "vdma_common.h"

#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/circ_buf.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/kernel.h>


#define CHANNEL_BASE_OFFSET(channel_index, direction) (((direction) == HAILO_DMA_TO_DEVICE) ? \
    (((channel_index) << 5) + 0x0) : (((channel_index) << 5) + 0x10))

#define CHANNEL_CONTROL_OFFSET      (0x0)
#define CHANNEL_DEPTH_ID_OFFSET     (0x1)
#define CHANNEL_NUM_AVAIL_OFFSET    (0x2)
#define CHANNEL_NUM_PROC_OFFSET     (0x4)
#define CHANNEL_NUM_ONGOING_OFFSET  (0x6)
#define CHANNEL_ERROR_OFFSET        (0x8)
#define CHANNEL_ADDRESS_L_OFFSET    (0x0A)
#define CHANNEL_ADDRESS_H_OFFSET    (0x0C)

// Total register for each channel edge (edge - one of the sides, h2d/d2h)
#define CHANNEL_REGISTERS_SIZE      (0x10)

#define VDMA_CHANNEL_CONTROL_MASK (0xFC)
#define VDMA_CHANNEL_CONTROL_START_RESUME (0b01)
#define VDMA_CHANNEL_CONTROL_START_PAUSE (0b11)
#define VDMA_CHANNEL_CONTROL_ABORT (0b00)
#define VDMA_CHANNEL_CONTROL_ABORT_PAUSE (0b10)
#define VDMA_CHANNEL_CONTROL_START_ABORT_PAUSE_RESUME_BITMASK (0x3)
#define VDMA_CHANNEL_DEPTH_MASK (0x78)

#define VDMA_CHANNEL_NUM_PROCESSED_WIDTH (16)
#define VDMA_CHANNEL_NUM_PROCESSED_MASK ((1 << VDMA_CHANNEL_NUM_PROCESSED_WIDTH) - 1)
#define VDMA_CHANNEL_NUM_ONGOING_MASK VDMA_CHANNEL_NUM_PROCESSED_MASK
#define VDMA_CHANNEL_DESC_DEPTH_SHIFT (3)

#define VDMA_CHANNEL__MAX_CHECKS_CHANNEL_IS_IDLE (10000)

// On Accelerator mode, the data id for the host memory is 0,
// while in VPU mode the channel id is not used (reserved field), and should
// be se to 0.
#define VDMA_CHANNEL_DATA_ID       (0)
#define DESCRIPTOR_LIST_MAX_DEPTH (16)

#define DELAY_AFTER_CHANNEL_PAUSE_MICROSECONDS (8)

#define DESCRIPTOR_PAGE_SIZE_SHIFT (8)
#define DESCRIPTOR_DESC_CONTROL (0x2)
#define DESCRIPTOR_ADDR_L_MASK (0xFFFFFFC0)

#define DWORD_SIZE                  (4)
#define WORD_SIZE                   (2)
#define BYTE_SIZE                   (1)

#define TIMESTAMPS_CIRC_SPACE(timestamp_list) \
    CIRC_SPACE((timestamp_list).head, (timestamp_list).tail, CHANNEL_IRQ_TIMESTAMPS_SIZE)
#define TIMESTAMPS_CIRC_CNT(timestamp_list) \
    CIRC_CNT((timestamp_list).head, (timestamp_list).tail, CHANNEL_IRQ_TIMESTAMPS_SIZE)

#ifndef for_each_sgtable_dma_sg
#define for_each_sgtable_dma_sg(sgt, sg, i)	\
    for_each_sg((sgt)->sgl, sg, (sgt)->nents, i)
#endif /* for_each_sgtable_dma_sg */

// control_reg_value is an inout param
static void hailo_vdma_channel_pause(struct hailo_resource *vdma_registers, size_t control_reg_addr, u8 *control_reg_value)
{
    *control_reg_value = (*control_reg_value & VDMA_CHANNEL_CONTROL_MASK) | VDMA_CHANNEL_CONTROL_START_PAUSE;
    hailo_resource_write8(vdma_registers, control_reg_addr, *control_reg_value);
}

// control_reg_value is an inout param
static void hailo_vdma_channel_abort(struct hailo_resource *vdma_registers, size_t control_reg_addr, u8 *control_reg_value)
{
    *control_reg_value = (*control_reg_value & VDMA_CHANNEL_CONTROL_MASK) | VDMA_CHANNEL_CONTROL_ABORT;
    hailo_resource_write8(vdma_registers, control_reg_addr, *control_reg_value);
}

bool hailo_vdma_channel_is_idle(struct hailo_resource *vdma_registers, size_t channel_index,
    size_t to_device_max_desc_count, size_t from_device_max_desc_count)
{
    // Num processed and ongoing are next to each other in the memory. 
    // Reading them both in order to save BAR reads.
    size_t to_device_num_proc_ongoing_offset = 
        CHANNEL_BASE_OFFSET(channel_index, HAILO_DMA_TO_DEVICE) + CHANNEL_NUM_PROC_OFFSET;
    size_t from_device_num_proc_ongoing_offset = 
        CHANNEL_BASE_OFFSET(channel_index, HAILO_DMA_FROM_DEVICE) + CHANNEL_NUM_PROC_OFFSET;
    u32 to_device_num_processed_ongoing = hailo_resource_read32(vdma_registers, to_device_num_proc_ongoing_offset);
    u32 from_device_num_processed_ongoing = hailo_resource_read32(vdma_registers, from_device_num_proc_ongoing_offset);

    u16 to_device_num_processed = to_device_num_processed_ongoing & VDMA_CHANNEL_NUM_PROCESSED_MASK;
    u16 to_device_num_ongoing = 
        (to_device_num_processed_ongoing >> VDMA_CHANNEL_NUM_PROCESSED_WIDTH) & VDMA_CHANNEL_NUM_ONGOING_MASK;
    u16 from_device_num_processed = from_device_num_processed_ongoing & VDMA_CHANNEL_NUM_PROCESSED_MASK;
    u16 from_device_num_ongoing = 
        (from_device_num_processed_ongoing >> VDMA_CHANNEL_NUM_PROCESSED_WIDTH) & VDMA_CHANNEL_NUM_ONGOING_MASK;

    if ((to_device_num_processed % to_device_max_desc_count) == (to_device_num_ongoing % to_device_max_desc_count)  && 
        (from_device_num_processed % from_device_max_desc_count) == (from_device_num_ongoing % from_device_max_desc_count)) {
            return true;
    }

    return false;
}

int hailo_vdma_wait_until_channel_idle(struct hailo_resource *vdma_registers, size_t channel_index)
{
    bool is_idle = false;
    uint32_t check_counter = 0; 
    size_t to_device_channel_depth_offset = CHANNEL_BASE_OFFSET(channel_index, HAILO_DMA_TO_DEVICE) + CHANNEL_DEPTH_ID_OFFSET;
    size_t from_device_channel_depth_offset = CHANNEL_BASE_OFFSET(channel_index, HAILO_DMA_FROM_DEVICE) + CHANNEL_DEPTH_ID_OFFSET;

    u8 to_device_depth_id = hailo_resource_read8(vdma_registers, to_device_channel_depth_offset);
    u8 from_device_depth_id = hailo_resource_read8(vdma_registers, from_device_channel_depth_offset);

    u8 to_device_depth = (to_device_depth_id  & VDMA_CHANNEL_DEPTH_MASK) >> VDMA_CHANNEL_DESC_DEPTH_SHIFT;
    u8 from_device_depth = (from_device_depth_id  & VDMA_CHANNEL_DEPTH_MASK) >> VDMA_CHANNEL_DESC_DEPTH_SHIFT;

    size_t to_device_max_desc_count = (size_t)(1 << to_device_depth);
    size_t from_device_max_desc_count = (size_t)(1 << from_device_depth);

    for (check_counter = 0; check_counter < VDMA_CHANNEL__MAX_CHECKS_CHANNEL_IS_IDLE; check_counter++) {
        is_idle = hailo_vdma_channel_is_idle(vdma_registers, channel_index, to_device_max_desc_count, from_device_max_desc_count);
        if (is_idle) {
            return 0;
        }
    }

    return -ETIMEDOUT;
}

static int hailo_vdma_stop_channel(struct hailo_resource *vdma_registers, size_t channel_index)
{
    int err = 0;
    size_t to_device_control_reg_addr = CHANNEL_BASE_OFFSET(channel_index, HAILO_DMA_TO_DEVICE) + CHANNEL_CONTROL_OFFSET;
    size_t from_device_control_reg_addr = CHANNEL_BASE_OFFSET(channel_index, HAILO_DMA_FROM_DEVICE) + CHANNEL_CONTROL_OFFSET;
    u8 to_device_control_reg = hailo_resource_read8(vdma_registers, to_device_control_reg_addr);
    u8 from_device_control_reg = hailo_resource_read8(vdma_registers, from_device_control_reg_addr);

    if (((to_device_control_reg & VDMA_CHANNEL_CONTROL_START_ABORT_PAUSE_RESUME_BITMASK) == VDMA_CHANNEL_CONTROL_ABORT_PAUSE) &&
            ((from_device_control_reg & VDMA_CHANNEL_CONTROL_START_ABORT_PAUSE_RESUME_BITMASK) == VDMA_CHANNEL_CONTROL_ABORT_PAUSE)) {
        // The channel is aborted (we set the channel to VDMA_CHANNEL_CONTROL_ABORT_PAUSE at the end of this function)
        return 0;
    }

    // Pause the channel
    // The channel is paused to allow for "all transfers from fetched descriptors..." to be "...completed"
    // (from PLDA PCIe refernce manual, "9.2.5 Starting a Channel and Transferring Data")
    hailo_vdma_channel_pause(vdma_registers, to_device_control_reg_addr, &to_device_control_reg);
    hailo_vdma_channel_pause(vdma_registers, from_device_control_reg_addr, &from_device_control_reg);

    // Even if channel is stuck and not idle, force abort and return error in the end
    err = hailo_vdma_wait_until_channel_idle(vdma_registers, channel_index);

    // Abort the channel (even of hailo_vdma_wait_until_channel_idle function fails)
    hailo_vdma_channel_abort(vdma_registers, to_device_control_reg_addr, &to_device_control_reg);
    hailo_vdma_channel_abort(vdma_registers, from_device_control_reg_addr, &from_device_control_reg);

    return err;
}

void hailo_vdma_program_descriptor(struct hailo_vdma_descriptor *descriptor, uint64_t dma_address, size_t page_size,
    uint8_t data_id)
{
    descriptor->PageSize_DescControl = (uint32_t)((page_size << DESCRIPTOR_PAGE_SIZE_SHIFT) +
        DESCRIPTOR_DESC_CONTROL);
    descriptor->AddrL_rsvd_DataID = (uint32_t)(((dma_address & DESCRIPTOR_ADDR_L_MASK)) | data_id);
    descriptor->AddrH = (uint32_t)(dma_address >> 32);
    descriptor->RemainingPageSize_Status = 0 ;
}

static uint8_t get_channel_id(uint8_t channel_index)
{
    if (channel_index < VDMA_DEST_CHANNELS_START) {
        // H2D channel
        return channel_index;
    }
    else if ((channel_index >= VDMA_DEST_CHANNELS_START) && 
             (channel_index < MAX_VDMA_CHANNELS_PER_ENGINE)) {
        // D2H channel
        return channel_index - VDMA_DEST_CHANNELS_START;
    }
    else {
        return INVALID_VDMA_CHANNEL;
    }
}

int hailo_vdma_program_descriptors_list(
    struct hailo_desc_list_bind_vdma_buffer_params *params,
    struct hailo_vdma_descriptors_list *desc_list,
    struct sg_table *buffer,
    encode_desc_dma_address_t address_encoder,
    uint8_t data_id)
{
    struct hailo_vdma_descriptor *dma_desc = NULL;
    const uint8_t channel_id = get_channel_id(params->channel_index);
    uint32_t desc_index = 0;
    uint32_t max_desc_index = 0;
    uint32_t desc_in_sg = 0;
    dma_addr_t desc_buffer_addr = 0;
    uint64_t encoded_addr = 0;
    uint32_t desc_per_sg = 0;
    struct scatterlist *sg_entry = NULL;
    unsigned int i = 0;

    if (!is_powerof2(params->desc_page_size)) {
        return -EFAULT;
    }

    if (params->starting_desc >= desc_list->desc_count) {
        return -EFAULT;
    }

    // On circular buffer, allow programming  desc_count descriptors (starting
    // from starting_desc). On non circular, don't allow is to pass desc_count
    max_desc_index = desc_list->is_circular ?
        params->starting_desc + desc_list->desc_count - 1 :
        desc_list->desc_count - 1;
    desc_index = params->starting_desc;
    for_each_sgtable_dma_sg(buffer, sg_entry, i) {
        desc_per_sg = DIV_ROUND_UP(sg_dma_len(sg_entry), params->desc_page_size);
        desc_buffer_addr = sg_dma_address(sg_entry);
        for (desc_in_sg = 0; desc_in_sg < desc_per_sg; desc_in_sg++) {
            if (desc_index > max_desc_index) {
                return -ERANGE;
            }

            encoded_addr = address_encoder(desc_buffer_addr, channel_id);
            if (INVALID_VDMA_ADDRESS == encoded_addr) {
                return -EFAULT;
            }

            dma_desc = &desc_list->desc_list[desc_index % desc_list->desc_count];
            hailo_vdma_program_descriptor(dma_desc, encoded_addr,
                params->desc_page_size, data_id);

            desc_buffer_addr += params->desc_page_size;
            desc_index++;
        }
    }

    return 0;
}

static void hailo_vdma_push_timestamp(struct hailo_channel_interrupt_timestamp_list *timestamp_list,
    struct hailo_resource *vdma_registers, size_t channel_index, enum hailo_dma_data_direction direction)
{
    size_t num_proc_offset = CHANNEL_BASE_OFFSET(channel_index, direction) + CHANNEL_NUM_PROC_OFFSET;
    u16 num_processed = hailo_resource_read16(vdma_registers, num_proc_offset);
    if (TIMESTAMPS_CIRC_SPACE(*timestamp_list) != 0) {
        timestamp_list->timestamps[timestamp_list->head].timestamp_ns = ktime_get_ns();
        timestamp_list->timestamps[timestamp_list->head].desc_num_processed = num_processed;
        timestamp_list->head = (timestamp_list->head + 1) & CHANNEL_IRQ_TIMESTAMPS_SIZE_MASK;
    }
}

// Returns false if there are no items
static bool hailo_vdma_pop_timestamp(struct hailo_channel_interrupt_timestamp_list *timestamp_list,
    struct hailo_channel_interrupt_timestamp *out_timestamp)
{
    if (0 == TIMESTAMPS_CIRC_CNT(*timestamp_list)) {
        return false;
    }

    *out_timestamp = timestamp_list->timestamps[timestamp_list->tail];
    timestamp_list->tail = (timestamp_list->tail+1) & CHANNEL_IRQ_TIMESTAMPS_SIZE_MASK;
    return true;
}

static void hailo_vdma_pop_timestamps_to_response(struct hailo_channel_interrupt_timestamp_list *timestamp_list,
    struct hailo_vdma_interrupts_read_timestamp_params *result)
{
    const uint32_t max_timestamps = ARRAY_SIZE(result->timestamps);
    uint32_t i = 0;

    while (hailo_vdma_pop_timestamp(timestamp_list, &result->timestamps[i]) && (i < max_timestamps)) {
        i++;
    }

    result->timestamps_count = i;
}

int hailo_vdma_channel_read_register(struct hailo_vdma_channel_read_register_params *params,
    struct hailo_resource *vdma_registers)
{
    size_t offset = 0;

    // check for valid input, engine_index is validated in the specific driver (in order to get the right
    // vdma_registers resource).
    if (params->channel_index >= MAX_VDMA_CHANNELS_PER_ENGINE) {
        return -EINVAL;
    }

    if (!((HAILO_DMA_FROM_DEVICE == params->direction) || (HAILO_DMA_TO_DEVICE == params->direction))) {
        return -EINVAL;
    }

    if (params->offset >= CHANNEL_REGISTERS_SIZE) {
        return -EINVAL;
    }

    offset = CHANNEL_BASE_OFFSET(params->channel_index, params->direction) + params->offset;
    switch (params->reg_size) {
    case DWORD_SIZE:
        params->data = hailo_resource_read32(vdma_registers, offset);
        break;
    case WORD_SIZE:
        params->data = (uint32_t)hailo_resource_read16(vdma_registers, offset);
        break;
    case BYTE_SIZE:
        params->data = (uint32_t)hailo_resource_read8(vdma_registers, offset);
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

int hailo_vdma_channel_write_register(struct hailo_vdma_channel_write_register_params *params,
    struct hailo_resource *vdma_registers)
{
    size_t offset = 0;

    // check for valid input, engine_index is validated in the specific driver (in order to get the right
    // vdma_registers resource).
    if (params->channel_index >= MAX_VDMA_CHANNELS_PER_ENGINE) {
        return -EINVAL;
    }

    if (!((HAILO_DMA_FROM_DEVICE == params->direction) || (HAILO_DMA_TO_DEVICE == params->direction))) {
        return -EINVAL;
    }

    if (params->offset >= CHANNEL_REGISTERS_SIZE) {
        return -EINVAL;
    }

    offset = CHANNEL_BASE_OFFSET(params->channel_index, params->direction) + params->offset;
    switch (params->reg_size) {
    case DWORD_SIZE:
        hailo_resource_write32(vdma_registers, offset, params->data);
        break;
    case WORD_SIZE:
        hailo_resource_write16(vdma_registers, offset, (uint16_t)params->data);
        break;
    case BYTE_SIZE:
        hailo_resource_write8(vdma_registers, offset, (uint8_t)params->data);
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static inline enum hailo_dma_data_direction hailo_vdma_get_channel_direction(u8 channel_index)
{
    BUG_ON(channel_index >= MAX_VDMA_CHANNELS_PER_ENGINE);
    return (channel_index < VDMA_DEST_CHANNELS_START) ?
        HAILO_DMA_TO_DEVICE : HAILO_DMA_FROM_DEVICE;
}

static enum hailo_dma_data_direction other_direction(enum hailo_dma_data_direction dir)
{
    return (dir == HAILO_DMA_TO_DEVICE) ?
        HAILO_DMA_FROM_DEVICE :
        HAILO_DMA_TO_DEVICE;
}

void hailo_vdma_engine_init(struct hailo_vdma_engine *engine,
    const struct hailo_resource *channel_registers)
{
    u8 i = 0;

    engine->channel_registers = *channel_registers;

    for (i = 0; i < ARRAY_SIZE(engine->channels); ++i) {
        engine->channels[i].direction = hailo_vdma_get_channel_direction(i);
        engine->channels[i].timestamp_measure_enabled = false;
    }

    engine->enabled_channels = 0x0;
    engine->interrupted_channels = 0x0;
}

void hailo_vdma_engine_enable_channel_interrupts(struct hailo_vdma_engine *engine, u32 bitmap,
    bool measure_timestamp)
{
    struct hailo_vdma_channel *channel = NULL;
    u8 channel_index = 0;

    for_each_vdma_channel(engine, channel, channel_index) {
        if (hailo_test_bit(channel_index, &bitmap)) {
            channel->timestamp_measure_enabled = measure_timestamp;
            channel->timestamp_list.head = channel->timestamp_list.tail = 0;
        }
    }

    engine->enabled_channels |= bitmap;
}

void hailo_vdma_engine_disable_channel_interrupts(struct hailo_vdma_engine *engine, u32 bitmap)
{
    engine->enabled_channels &= ~bitmap;
}

void hailo_vdma_engine_push_timestamps(struct hailo_vdma_engine *engine, u32 bitmap)
{
    struct hailo_vdma_channel *channel = NULL;
    u8 channel_index = 0;

    for_each_vdma_channel(engine, channel, channel_index) {
        if (unlikely(hailo_test_bit(channel_index, &bitmap) &&
                channel->timestamp_measure_enabled)) {
            hailo_vdma_push_timestamp(&channel->timestamp_list,
                &engine->channel_registers, channel_index, channel->direction);
        }
    }
}

int hailo_vdma_engine_read_timestamps(struct hailo_vdma_engine *engine,
    struct hailo_vdma_interrupts_read_timestamp_params *params)
{
    struct hailo_vdma_channel *channel = NULL;

    if (params->channel_index >= MAX_VDMA_CHANNELS_PER_ENGINE) {
        return -EINVAL;
    }

    channel = &engine->channels[params->channel_index];
    hailo_vdma_pop_timestamps_to_response(&channel->timestamp_list, params);
    return 0;
}

int hailo_vdma_engine_stop_all_channels(struct hailo_vdma_engine *engine)
{
    struct hailo_vdma_channel *channel = NULL;
    u8 channel_index = 0;
    int local_err = -EINVAL;
    int err = 0; // success oriented

    for_each_vdma_channel(engine, channel, channel_index) {
        local_err = hailo_vdma_stop_channel(&engine->channel_registers, channel_index);
        if (local_err != 0) {
            err = local_err;
            // continue
        }
    }

    return err;
}

void hailo_vdma_engine_clear_channel_interrupts(struct hailo_vdma_engine *engine, u32 bitmap)
{
    engine->interrupted_channels &= ~bitmap;
}

void hailo_vdma_engine_set_channel_interrupts(struct hailo_vdma_engine *engine, u32 bitmap)
{
    engine->interrupted_channels |= bitmap;
}

static bool channel_control_reg_is_active(u8 control)
{
    return (control & VDMA_CHANNEL_CONTROL_START_ABORT_PAUSE_RESUME_BITMASK) ==
        VDMA_CHANNEL_CONTROL_START_RESUME;
}

static void fill_channel_irq_data(struct hailo_vdma_interrupts_channel_data *irq_data,
    struct hailo_vdma_engine *engine, u8 engine_index,
    struct hailo_vdma_channel *channel, u8 channel_index)
{
    const size_t host_offset = CHANNEL_BASE_OFFSET(channel_index, channel->direction);
    const size_t device_offset = CHANNEL_BASE_OFFSET(channel_index, other_direction(channel->direction));
    struct hailo_resource *vdma_registers = &engine->channel_registers;
    u8 host_control = 0;
    u8 device_control = 0;

    irq_data->engine_index = engine_index;
    irq_data->channel_index = channel_index;

    host_control = hailo_resource_read8(vdma_registers, host_offset + CHANNEL_CONTROL_OFFSET);
    device_control = hailo_resource_read8(vdma_registers, device_offset + CHANNEL_CONTROL_OFFSET);
    irq_data->is_active = channel_control_reg_is_active(host_control) &&
        channel_control_reg_is_active(device_control);

    irq_data->host_num_processed = hailo_resource_read16(vdma_registers, host_offset + CHANNEL_NUM_PROC_OFFSET);
    irq_data->host_error = hailo_resource_read8(vdma_registers, host_offset + CHANNEL_ERROR_OFFSET);
    irq_data->device_error = hailo_resource_read8(vdma_registers, device_offset + CHANNEL_ERROR_OFFSET);
}

int hailo_vdma_engine_fill_irq_data(struct hailo_vdma_interrupts_wait_params *irq_data,
    struct hailo_vdma_engine *engine, u8 engine_index, u32 irq_channels_bitmap)
{
    struct hailo_vdma_channel *channel = NULL;
    u8 channel_index = 0;

    for_each_vdma_channel(engine, channel, channel_index) {
        if (!hailo_test_bit(channel_index, &irq_channels_bitmap)) {
            continue;
        }

        if (irq_data->channels_count >= ARRAY_SIZE(irq_data->irq_data)) {
            return -EINVAL;
        }

        fill_channel_irq_data(&irq_data->irq_data[irq_data->channels_count],
            engine, engine_index, channel, channel_index);
        irq_data->channels_count++;
    }

    return 0;
}