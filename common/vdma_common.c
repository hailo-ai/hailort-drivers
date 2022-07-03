// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#include "vdma_common.h"


#define CHANNEL_BASE_OFFSET(channel_index, direction) (((direction) == HAILO_DMA_TO_DEVICE) ? \
    (((channel_index) << 5) + 0x0) : (((channel_index) << 5) + 0x10))

#define CHANNEL_CONTROL_OFFSET      (0x0)
#define CHANNEL_DEPTH_ID_OFFSET     (0x1)
#define CHANNEL_NUM_AVAIL_OFFSET    (0x2)
#define CHANNEL_NUM_PROC_OFFSET     (0x4)
#define CHANNEL_NUM_ONGOING_OFFSET  (0x6)
#define CHANNEL_ADDRESS_L_OFFSET    (0x0A)
#define CHANNEL_ADDRESS_H_OFFSET    (0x0C)

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

#define TIMESTAMPS_CIRC_SPACE(timestamp_list) \
    CIRC_SPACE((timestamp_list).head, (timestamp_list).tail, CHANNEL_IRQ_TIMESTAMPS_SIZE)
#define TIMESTAMPS_CIRC_CNT(timestamp_list) \
    CIRC_CNT((timestamp_list).head, (timestamp_list).tail, CHANNEL_IRQ_TIMESTAMPS_SIZE)


// control_reg_value is an inout param
static void start_vdma_control_register(struct hailo_resource *vdma_registers, size_t channel_index,
    enum hailo_dma_data_direction direction, u8 *control_reg_value)
{
    size_t control_reg_addr = CHANNEL_BASE_OFFSET(channel_index, direction) + CHANNEL_CONTROL_OFFSET;
    *control_reg_value = (*control_reg_value & VDMA_CHANNEL_CONTROL_MASK) | VDMA_CHANNEL_CONTROL_START_RESUME;
    hailo_resource_write8(vdma_registers, control_reg_addr, *control_reg_value);
}

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

int hailo_vdma_start_channel(struct hailo_resource *vdma_registers, size_t channel_index,
    enum hailo_dma_data_direction direction, uint64_t desc_dma_address, uint8_t desc_depth)
{
    size_t channel_offset = CHANNEL_BASE_OFFSET(channel_index, direction);
    uint16_t dma_address_l = 0;
    uint32_t dma_address_h = 0;
    uint8_t depth_id = 0;
    u8 to_device_control_reg = 0;
    u8 from_device_control_reg = 0;
    int err = 0;

    if (((desc_dma_address & 0xFFFF) != 0) || 
         (desc_depth > DESCRIPTOR_LIST_MAX_DEPTH)) {
        return -EINVAL;
    }

    // According to spec, depth 16 is equivalent to depth 0.
    if (DESCRIPTOR_LIST_MAX_DEPTH == desc_depth) {
        desc_depth = 0;
    }

    // Stop old channel state
    err = hailo_vdma_stop_channel(vdma_registers, channel_index, &to_device_control_reg, &from_device_control_reg);
    if (err != 0) {
        return err;
    }

    // Configure address, depth and id
    dma_address_l = (uint16_t)((desc_dma_address >> 16) & 0xFFFF);
    hailo_resource_write16(vdma_registers, channel_offset+CHANNEL_ADDRESS_L_OFFSET, dma_address_l);

    dma_address_h = (uint32_t)(desc_dma_address >> 32);
    hailo_resource_write32(vdma_registers, channel_offset+CHANNEL_ADDRESS_H_OFFSET, dma_address_h);

    depth_id = (uint8_t)((desc_depth << VDMA_CHANNEL_DESC_DEPTH_SHIFT) | VDMA_CHANNEL_DATA_ID);
    hailo_resource_write8(vdma_registers, channel_offset+CHANNEL_DEPTH_ID_OFFSET, depth_id);

    // Start channel
    start_vdma_control_register(vdma_registers, channel_index, HAILO_DMA_TO_DEVICE, &to_device_control_reg);
    start_vdma_control_register(vdma_registers, channel_index, HAILO_DMA_FROM_DEVICE, &from_device_control_reg);

    return 0;
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

int hailo_vdma_stop_channel(struct hailo_resource *vdma_registers, size_t channel_index,
    u8 *to_device_control_reg, u8 *from_device_control_reg)
{
    int err = 0;
    size_t to_device_control_reg_addr = CHANNEL_BASE_OFFSET(channel_index, HAILO_DMA_TO_DEVICE) + CHANNEL_CONTROL_OFFSET;
    size_t from_device_control_reg_addr = CHANNEL_BASE_OFFSET(channel_index, HAILO_DMA_FROM_DEVICE) + CHANNEL_CONTROL_OFFSET;

    *to_device_control_reg = hailo_resource_read8(vdma_registers, to_device_control_reg_addr);
    *from_device_control_reg = hailo_resource_read8(vdma_registers, from_device_control_reg_addr);

    if (((*to_device_control_reg & VDMA_CHANNEL_CONTROL_START_ABORT_PAUSE_RESUME_BITMASK) == VDMA_CHANNEL_CONTROL_ABORT_PAUSE) &&
            ((*from_device_control_reg & VDMA_CHANNEL_CONTROL_START_ABORT_PAUSE_RESUME_BITMASK) == VDMA_CHANNEL_CONTROL_ABORT_PAUSE)) {
        // The channel is aborted (we set the channel to VDMA_CHANNEL_CONTROL_ABORT_PAUSE at the end of this function)
        return 0;
    }

    // Pause the channel
    // The channel is paused to allow for "all transfers from fetched descriptors..." to be "...completed"
    // (from PLDA PCIe refernce manual, "9.2.5 Starting a Channel and Transferring Data")
    hailo_vdma_channel_pause(vdma_registers, to_device_control_reg_addr, to_device_control_reg);
    hailo_vdma_channel_pause(vdma_registers, from_device_control_reg_addr, from_device_control_reg);

    // Even if channel is stuck and not idle, force abort and return error in the end
    err = hailo_vdma_wait_until_channel_idle(vdma_registers, channel_index);

    // Abort the channel (even of hailo_vdma_wait_until_channel_idle function fails)
    hailo_vdma_channel_abort(vdma_registers, to_device_control_reg_addr, to_device_control_reg);
    hailo_vdma_channel_abort(vdma_registers, from_device_control_reg_addr, from_device_control_reg);

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

void hailo_vdma_push_timestamp(struct hailo_channel_interrupt_timestamp_list *timestamp_list,
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

bool hailo_vdma_pop_timestamp(struct hailo_channel_interrupt_timestamp_list *timestamp_list,
    struct hailo_channel_interrupt_timestamp *out_timestamp)
{
    if (0 == TIMESTAMPS_CIRC_CNT(*timestamp_list)) {
        return false;
    }

    *out_timestamp = timestamp_list->timestamps[timestamp_list->tail];
    timestamp_list->tail = (timestamp_list->tail+1) & CHANNEL_IRQ_TIMESTAMPS_SIZE_MASK;
    return true;
}
