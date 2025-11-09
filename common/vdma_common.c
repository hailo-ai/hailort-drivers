// SPDX-License-Identifier: MIT
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include "vdma_common.h"

#include <linux/types.h>
#include <linux/bug.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/kconfig.h>
#include <linux/printk.h>
#include <linux/io.h>
#include <linux/io-64-nonatomic-hi-lo.h>

#define VDMA_CHANNEL_CONTROL_START (0x1)
#define VDMA_CHANNEL_CONTROL_ABORT (0b00)
#define VDMA_CHANNEL_CONTROL_ABORT_PAUSE (0b10)
#define VDMA_CHANNEL_CONTROL_START_ABORT_PAUSE_RESUME_BITMASK (0x3)
#define VDMA_CHANNEL_CONTROL_START_ABORT_BITMASK (0x1)
#define VDMA_CHANNEL_CONTROL_MASK (0xFC)
#define VDMA_CHANNEL_CONTROL_START_RESUME (0b01)
#define VDMA_CHANNEL_CONTROL_START_PAUSE (0b11)
#define VDMA_CHANNEL_CONTROL_ABORT (0b00)
#define VDMA_CHANNEL_CONTROL_ABORT_PAUSE (0b10)
#define VDMA_CHANNEL_CONTROL_START_ABORT_PAUSE_RESUME_BITMASK (0x3)
#define VDMA_CHANNEL_DESC_DEPTH_WIDTH (4)
#define VDMA_CHANNEL_DESC_DEPTH_SHIFT (11)
#define VDMA_CHANNEL_DATA_ID_SHIFT (8)
#define VDMA_CHANNEL__MAX_CHECKS_CHANNEL_IS_IDLE (10000)
#define VDMA_CHANNEL__ADDRESS_L_OFFSET          (0x0A)
#define VDMA_CHANNEL__ALIGNED_ADDRESS_L_OFFSET  (0x8)
#define VDMA_CHANNEL__ADDRESS_H_OFFSET          (0x0C)

#define DESCRIPTOR_PAGE_SIZE_SHIFT (8)
#define DESCRIPTOR_DESC_CONTROL (0x2)
#define DESCRIPTOR_ADDR_MASK (~0x3FULL)
#define DESCRIPTOR_LIST_MAX_DEPTH (16)

#define DESCRIPTOR_PAGE_SIZE_CONTROL_REG(page_size) \
    (((page_size) << DESCRIPTOR_PAGE_SIZE_SHIFT) + DESCRIPTOR_DESC_CONTROL)

#define DESCRIPTOR_DESC_STATUS_DONE_BIT  (0x0)
#define DESCRIPTOR_DESC_STATUS_ERROR_BIT (0x1)
#define DESCRIPTOR_DESC_STATUS_MASK (0xFF)

#define DESC_STATUS_REQ                       (1 << 0)
#define DESC_STATUS_REQ_ERR                   (1 << 1)
#define DESC_REQUEST_IRQ_PROCESSED            (1 << 2)
#define DESC_REQUEST_IRQ_ERR                  (1 << 3)

#define VDMA_CHANNEL_NUM_PROCESSED_WIDTH (16)
#define VDMA_CHANNEL_NUM_PROCESSED_MASK ((1 << VDMA_CHANNEL_NUM_PROCESSED_WIDTH) - 1)
#define VDMA_CHANNEL_NUM_ONGOING_MASK VDMA_CHANNEL_NUM_PROCESSED_MASK

#define TIMESTAMPS_CIRC_SPACE(timestamp_list) \
    CIRC_SPACE((timestamp_list).head, (timestamp_list).tail, CHANNEL_IRQ_TIMESTAMPS_SIZE)
#define TIMESTAMPS_CIRC_CNT(timestamp_list) \
    CIRC_CNT((timestamp_list).head, (timestamp_list).tail, CHANNEL_IRQ_TIMESTAMPS_SIZE)

#ifndef for_each_sgtable_dma_sg
#define for_each_sgtable_dma_sg(sgt, sg, i)	\
    for_each_sg((sgt)->sgl, sg, (sgt)->nents, i)
#endif /* for_each_sgtable_dma_sg */


static u8 vdma_regs_get_channel_depth(u32 regs_p0)
{
    u8 depth = READ_BITS_AT_OFFSET(VDMA_CHANNEL_DESC_DEPTH_WIDTH, VDMA_CHANNEL_DESC_DEPTH_SHIFT, regs_p0);
    // According to spec, depth 0 is equivalent to depth DESCRIPTOR_LIST_MAX_DEPTH.
    return (0 == depth) ? DESCRIPTOR_LIST_MAX_DEPTH : depth;
}

static void clear_dirty_desc(struct hailo_vdma_descriptors_list *desc_list, u16 desc)
{
    desc_list->desc_list[desc].PageSize_DescControl =
        (u32)((desc_list->desc_page_size << DESCRIPTOR_PAGE_SIZE_SHIFT) + DESCRIPTOR_DESC_CONTROL);
}

static void clear_dirty_descs(struct hailo_vdma_channel *channel,
    struct hailo_transfer *ongoing_transfer)
{
    u8 i = 0;
    struct hailo_vdma_descriptors_list *desc_list = channel->last_desc_list;
    BUG_ON(ongoing_transfer->dirty_descs_count > ARRAY_SIZE(ongoing_transfer->dirty_descs));
    for (i = 0; i < ongoing_transfer->dirty_descs_count; i++) {
        clear_dirty_desc(desc_list, ongoing_transfer->dirty_descs[i]);
    }
}

static bool validate_last_desc_status(struct hailo_vdma_channel *channel,
    struct hailo_transfer *ongoing_transfer)
{
    u16 last_desc = ongoing_transfer->last_desc;
    u32 last_desc_control = channel->last_desc_list->desc_list[last_desc].RemainingPageSize_Status &
        DESCRIPTOR_DESC_STATUS_MASK;
    if (!hailo_test_bit(DESCRIPTOR_DESC_STATUS_DONE_BIT, &last_desc_control)) {
        pr_err("Expecting desc %d to be done\n", last_desc);
        return false;
    }
    if (hailo_test_bit(DESCRIPTOR_DESC_STATUS_ERROR_BIT, &last_desc_control)) {
        pr_err("Got unexpected error on desc %d\n", last_desc);
        return false;
    }

    return true;
}

static inline void hailo_vdma_program_descriptor(struct hailo_vdma_descriptor *descriptor, u64 dma_address,
    u32 page_size_control_reg)
{
    descriptor->PageSize_DescControl = page_size_control_reg;
    descriptor->AddrL_rsvd_DataID = (u32)(dma_address);
    descriptor->AddrH = (u32)(dma_address >> 32);
    descriptor->RemainingPageSize_Status = 0;
}

static inline u64 get_masked_channel_id(u8 channel_index, struct hailo_vdma_hw *vdma_hw)
{
    u8 channel_id = (channel_index < MAX_VDMA_CHANNELS_PER_ENGINE) ? (channel_index & vdma_hw->channel_id_mask) : INVALID_VDMA_CHANNEL;
    return (((u64)channel_id & vdma_hw->channel_id_mask) << vdma_hw->channel_id_shift) | vdma_hw->ddr_data_id;
}

/**
 * Program a continuous chunk of descriptors (i.e no wrap around to the first descriptor)
 *
 * Notice - this function should be extremely optimized for performance since it is the bottleneck of
 * the entire program.
 */
static void program_continuous_descriptors_in_chunk(u64 chunk_addr, struct hailo_vdma_descriptor *desc,
    u32 desc_count, u32 transfer_size, u32 page_size, u32 total_desc_programmed)
{
    // The pattern is (pages_in_transfer - 1) pages of page size and a residue page
    const u32 pages_in_transfer = DIV_ROUND_UP(transfer_size, page_size);
    u32 idx_in_pattern = pages_in_transfer - 1 - (total_desc_programmed % pages_in_transfer);
    const u32 residue = (transfer_size % page_size) == 0 ? page_size : (transfer_size % page_size);

    // pre calculate the control register values
    const u32 page_size_control_reg = DESCRIPTOR_PAGE_SIZE_CONTROL_REG(page_size);
    const u32 residue_control_reg = DESCRIPTOR_PAGE_SIZE_CONTROL_REG(residue);

    while (desc_count --> 0) {
        hailo_vdma_program_descriptor(desc, chunk_addr,
            (idx_in_pattern == 0) ? residue_control_reg : page_size_control_reg);
        chunk_addr += page_size;
        desc++;

        // reduce index_in_pattern by 1 (or wrap around to the last index in pattern)
        idx_in_pattern = (idx_in_pattern == 0) ? pages_in_transfer - 1 : idx_in_pattern - 1;
    }
}

/**
 * Program the descriptors list into a chunk of continuous memory.
 *
 * @param chunk_addr - the encoded address of the chunk.
 * @param chunk_size - chunk size in bytes.
 * @param transfer_size - transfer size in bytes.
 * @param total_desc_programmed - the total number of descriptors already programmed.
 *                                This arg is used to get the right place in the pattern (a single pattern can cross
 *                                the chunk boundaries).
 */
void hailo_vdma_program_descriptors_in_chunk(
    u64 chunk_addr,
    unsigned int chunk_size,
    struct hailo_vdma_descriptors_list *desc_list,
    u32 starting_desc,
    u32 transfer_size,
    u32 total_desc_programmed)
{
    const u16 page_size = desc_list->desc_page_size;
    const u32 descs_to_program = DIV_ROUND_UP(chunk_size, page_size);
    u32 descs_to_end = min(descs_to_program, desc_list->desc_count - starting_desc);
    u32 descs_from_start = descs_to_program - descs_to_end;

    BUG_ON(starting_desc >= desc_list->desc_count);

    // Program in two continuous chunks (may have wrap around to the first descriptor)
    program_continuous_descriptors_in_chunk(chunk_addr, &desc_list->desc_list[starting_desc], descs_to_end,
        transfer_size, page_size, total_desc_programmed);
    chunk_addr += descs_to_end * page_size;
    total_desc_programmed += descs_to_end;

    if (descs_from_start > 0) {
        program_continuous_descriptors_in_chunk(chunk_addr, &desc_list->desc_list[0], descs_from_start,
            transfer_size, page_size, total_desc_programmed);
        chunk_addr += descs_from_start * page_size;
        total_desc_programmed += descs_from_start;
    }
}

static unsigned long get_interrupts_bitmask(struct hailo_vdma_hw *vdma_hw,
    enum hailo_vdma_interrupts_domain interrupts_domain, bool is_debug)
{
    unsigned long bitmask = 0;

    if (0 != (HAILO_VDMA_INTERRUPTS_DOMAIN_DEVICE & interrupts_domain)) {
        bitmask |= vdma_hw->device_interrupts_bitmask;
    }
    if (0 != (HAILO_VDMA_INTERRUPTS_DOMAIN_HOST & interrupts_domain)) {
        bitmask |= vdma_hw->host_interrupts_bitmask;
    }

    if (bitmask != 0) {
        bitmask |= DESC_REQUEST_IRQ_PROCESSED | DESC_REQUEST_IRQ_ERR;
        if (is_debug) {
            bitmask |= DESC_STATUS_REQ | DESC_STATUS_REQ_ERR;
        }
    }

    return bitmask;
}

static struct scatterlist *sg_next_mapped(struct scatterlist *sg)
{
    struct scatterlist *next = sg_next(sg);
    if (!next || sg_dma_address(next) == 0) {
        // When mapping the scatterlist, the actual mapped entry count may be less than
        // the original entry count (since the kernel may merge multiple sg entries into one).
        // When dma_address is NULL it means we finished the mapping.
        return NULL;
    }
    return next;
}

static struct scatterlist *sg_skip_offset(struct scatterlist *sg, u32 *skip_bytes)
{
    for (; sg; sg = sg_next_mapped(sg)) {
        if (sg_dma_len(sg) > *skip_bytes) {
            return sg;
        }

        *skip_bytes -= sg_dma_len(sg);
    }
    return NULL;
}

int hailo_vdma_program_descriptors_list(
    struct hailo_vdma_hw *vdma_hw,
    struct hailo_vdma_descriptors_list *desc_list,
    u32 starting_desc,
    struct sg_table *sgt,
    u32 sgt_offset,
    u32 transfer_size,
    u32 transfers_count,
    u8 channel_index,
    enum hailo_vdma_interrupts_domain last_desc_interrupts,
    bool is_debug)
{
    struct scatterlist *sg = NULL;
    u32 skip_bytes = sgt_offset;
    const u32 aligned_transfer_size = ALIGN(transfer_size, desc_list->desc_page_size);
    u32 program_size = aligned_transfer_size * transfers_count;
    u32 total_desc_to_program = DIV_ROUND_UP(program_size, desc_list->desc_page_size);
    u32 desc_programmed = 0;
    // On circular buffer, allow programming  desc_count descriptors (starting
    // from starting_desc). On non circular, don't allow is to pass desc_count
    const u32 max_descs_to_program = desc_list->is_circular ?
        desc_list->desc_count:
        (desc_list->desc_count - starting_desc);
    u64 masked_channel_id = get_masked_channel_id(channel_index, vdma_hw);

    if (sgt_offset % desc_list->desc_page_size != 0) {
        pr_err("Invalid buffer offset %u. desc_list->desc_page_size %d\n",
            sgt_offset, desc_list->desc_page_size);
        return -EINVAL;
    }
    if (starting_desc >= desc_list->desc_count) {
        pr_err("Invalid starting_desc %u. desc_list->desc_count %u\n",
            starting_desc, desc_list->desc_count);
        return -EINVAL;
    }
    if (total_desc_to_program > max_descs_to_program) {
        pr_err("Desc programmed size %u is larger than max_descs_to_program %u\n",
            total_desc_to_program, max_descs_to_program);
        return -EINVAL;
    }

    for (sg = sg_skip_offset(sgt->sgl, &skip_bytes); sg; sg = sg_next_mapped(sg)) {
        const dma_addr_t chunk_start_addr = sg_dma_address(sg) + skip_bytes;
        const u32 chunk_size = min((u32)program_size, sg_dma_len(sg) - skip_bytes);

        hailo_vdma_program_descriptors_in_chunk(
            (chunk_start_addr & DESCRIPTOR_ADDR_MASK) | masked_channel_id,
            chunk_size, desc_list,
            starting_desc & desc_list->desc_count_mask,
            transfer_size,
            desc_programmed);
        starting_desc += DIV_ROUND_UP(chunk_size, desc_list->desc_page_size);
        desc_programmed += DIV_ROUND_UP(chunk_size, desc_list->desc_page_size);
        program_size -= ALIGN(chunk_size, desc_list->desc_page_size);
        skip_bytes = 0; // Only the first chunk may start at the middle
        if (program_size == 0) {
            break;
        }
    }

    if (program_size != 0) {
        // We didn't program all the buffer.
        pr_err("Didn't program all the buffer. program_size=%u\n", program_size);
        return -EINVAL;
    }

    if (desc_programmed != total_desc_to_program) {
        pr_err("Desc programmed size %u is not equal to total_desc_to_program %u\n", desc_programmed, total_desc_to_program);
        return -EINVAL;
    }

    // program last desc
    desc_list->desc_list[(starting_desc - 1) % desc_list->desc_count].PageSize_DescControl |=
        get_interrupts_bitmask(vdma_hw, last_desc_interrupts, is_debug);

    return (int)desc_programmed;
}

static int program_last_desc(
    struct hailo_vdma_hw *vdma_hw,
    struct hailo_vdma_descriptors_list *desc_list,
    u32 starting_desc,
    struct hailo_vdma_mapped_transfer_buffer *transfer_buffer,
    enum hailo_vdma_interrupts_domain last_desc_interrupts,
    bool is_debug)
{
    u8 control = (u8)(DESCRIPTOR_DESC_CONTROL | get_interrupts_bitmask(vdma_hw, last_desc_interrupts, is_debug));
    u32 total_descs = DIV_ROUND_UP(transfer_buffer->size, desc_list->desc_page_size);
    u32 last_desc = (starting_desc + total_descs - 1) % desc_list->desc_count;
    u32 last_desc_size = transfer_buffer->size - (total_descs - 1) * desc_list->desc_page_size;

    // Configure only last descriptor with residue size
    desc_list->desc_list[last_desc].PageSize_DescControl = (u32)
        ((last_desc_size << DESCRIPTOR_PAGE_SIZE_SHIFT) + control);
    return (int)total_descs;
}

static bool channel_control_reg_is_active(u8 control)
{
    return (control & VDMA_CHANNEL_CONTROL_START_ABORT_BITMASK) == VDMA_CHANNEL_CONTROL_START;
}

static int validate_channel_state(struct hailo_vdma_channel *channel)
{
    u32 host_regs_value = ioread32(channel->host_regs);
    const u8 control = READ_BITS_AT_OFFSET(BYTE_SIZE * BITS_IN_BYTE, CHANNEL_CONTROL_OFFSET * BITS_IN_BYTE, host_regs_value);
    const u16 hw_num_avail = READ_BITS_AT_OFFSET(WORD_SIZE * BITS_IN_BYTE, CHANNEL_NUM_AVAIL_OFFSET * BITS_IN_BYTE, host_regs_value);

    if (!channel_control_reg_is_active(control)) {
        return -ECONNRESET;
    }

    if (hw_num_avail != channel->state.num_avail) {
        pr_err("Channel %d hw state out of sync. num available is %d, expected %d\n",
            channel->index, hw_num_avail, channel->state.num_avail);
        return -EIO;
    }

    return 0;
}

void hailo_vdma_set_num_avail(u8 __iomem *regs, u16 num_avail)
{
    u32 regs_val = ioread32(regs);
    iowrite32(WRITE_BITS_AT_OFFSET(WORD_SIZE * BITS_IN_BYTE, CHANNEL_NUM_AVAIL_OFFSET * BITS_IN_BYTE, regs_val, num_avail),
        regs);
}

u16 hailo_vdma_get_num_proc(u8 __iomem *regs)
{
    return READ_BITS_AT_OFFSET(WORD_SIZE * BITS_IN_BYTE, 0, ioread32(regs + CHANNEL_NUM_PROC_OFFSET));
}

int hailo_vdma_prepare_transfer(
    struct hailo_vdma_hw *vdma_hw,
    u8 channel_index,
    struct hailo_vdma_descriptors_list *desc_list,
    u8 buffers_count,
    enum hailo_vdma_interrupts_domain first_desc_interrupts,
    enum hailo_vdma_interrupts_domain last_desc_interrupts,
    bool is_debug,
    struct hailo_transfer *prepared_transfer,
    bool is_cyclic)
{
    u32 total_descs = 0;
    u32 last_desc = U32_MAX;
    u8 i = 0;
    u32 starting_desc = desc_list->num_programmed;
    u32 first_desc = starting_desc;
    if (buffers_count > HAILO_MAX_BUFFERS_PER_SINGLE_TRANSFER) {
        pr_err("Too many buffers %u for single transfer\n", buffers_count);
        return -EINVAL;
    }

    BUILD_BUG_ON_MSG((HAILO_MAX_BUFFERS_PER_SINGLE_TRANSFER + 1) != ARRAY_SIZE(prepared_transfer->dirty_descs),
        "Unexpected amount of dirty descriptors");

    prepared_transfer->dirty_descs_count = buffers_count + 1;
    prepared_transfer->dirty_descs[0] = (u16)starting_desc;

    for (i = 0; i < buffers_count; i++) {
        const bool transfers_count = 1;
        int ret = (!is_cyclic) ?
            hailo_vdma_program_descriptors_list(vdma_hw, desc_list, starting_desc,
                prepared_transfer->buffers[i].sg_table, prepared_transfer->buffers[i].offset,
                prepared_transfer->buffers[i].size, transfers_count, channel_index, last_desc_interrupts, is_debug) :
            program_last_desc(vdma_hw, desc_list, starting_desc, &prepared_transfer->buffers[i],
                last_desc_interrupts, is_debug);
        if (ret < 0) {
            pr_err("Failed program descriptors list\n");
            return ret;
        }

        total_descs += ret;
        last_desc = (starting_desc + ret - 1) % desc_list->desc_count;
        starting_desc = (starting_desc + ret) % desc_list->desc_count;

        prepared_transfer->dirty_descs[i+1] = (u16)last_desc;
    }
    desc_list->num_programmed = ((desc_list->num_programmed + total_descs) % desc_list->desc_count);
    prepared_transfer->last_desc = (u16)last_desc;
    prepared_transfer->is_debug = is_debug;
    desc_list->desc_list[first_desc].PageSize_DescControl |=
        get_interrupts_bitmask(vdma_hw, first_desc_interrupts, is_debug);
    return total_descs;
}

void hailo_vdma_cancel_prepared_transfer(struct device *dev,
    struct hailo_vdma_descriptors_list *desc_list)
{
    while (desc_list->prepared_transfers && TRANSFERS_CIRC_CNT(*desc_list->prepared_transfers) > 0) {
        struct hailo_transfer prepared_transfer;
        hailo_vdma_transfer_pop(&desc_list->prepared_transfers, &prepared_transfer);
        hailo_vdma_transfer_done(dev, &prepared_transfer);
    }

    hailo_vdma_transfer_list_free(&desc_list->prepared_transfers);
    desc_list->prepared_transfers = NULL;
    desc_list->num_programmed = 0;
    desc_list->num_launched = 0;
}

int hailo_vdma_launch_transfer(
    struct hailo_vdma_channel *channel,
    struct hailo_vdma_descriptors_list *desc_list,
    struct hailo_transfer *ongoing_transfer)
{
    int ret = 0;
    u32 total_descs = 0;
    u32 descs_count = 0;
    channel->state.desc_count_mask = (desc_list->desc_count - 1);

    if (NULL == channel->last_desc_list) {
        // First transfer on this active channel, store desc list.
        channel->last_desc_list = desc_list;
    } else if (desc_list != channel->last_desc_list) {
        // Shouldn't happen, desc list may change only after channel deactivation.
        pr_err("Inconsistent desc list given to channel %d\n", channel->index);
        return -EINVAL;
    }

    ret = validate_channel_state(channel);
    if (ret < 0) {
        return ret;
    }

    if (channel->state.num_avail != (u16)desc_list->num_launched) {
        pr_err("Channel %d state out of sync. num available is %d, expected %d\n",
            channel->index, channel->state.num_avail, (u16)desc_list->num_launched);
        return -EIO;
    }

    hailo_vdma_transfer_push(&channel->ongoing_transfers, ongoing_transfer);
    descs_count = desc_list->desc_count;
    total_descs = (ongoing_transfer->last_desc + 1 + descs_count - desc_list->num_launched) % descs_count;
    desc_list->num_launched = (ongoing_transfer->last_desc + 1) % descs_count;
    channel->state.num_avail = (u16)desc_list->num_launched;
    hailo_vdma_set_num_avail(channel->host_regs, (u16)desc_list->num_launched);

    return (int)total_descs;
}

static void hailo_vdma_push_timestamp(struct hailo_vdma_channel *channel)
{
    struct hailo_channel_interrupt_timestamp_list *timestamp_list = &channel->timestamp_list;
    const u16 num_proc = hailo_vdma_get_num_proc(channel->host_regs);
    if (TIMESTAMPS_CIRC_SPACE(*timestamp_list) != 0) {
        timestamp_list->timestamps[timestamp_list->head].timestamp_ns = ktime_get_ns();
        timestamp_list->timestamps[timestamp_list->head].desc_num_processed = num_proc;
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

static void hailo_vdma_pop_timestamps_to_response(struct hailo_vdma_channel *channel,
    struct hailo_vdma_interrupts_read_timestamp_params *result)
{
    const u32 max_timestamps = ARRAY_SIZE(result->timestamps);
    u32 i = 0;

    while (hailo_vdma_pop_timestamp(&channel->timestamp_list, &result->timestamps[i]) &&
        (i < max_timestamps)) {
        // Although the hw_num_processed should be a number between 0 and
        // desc_count-1, if desc_count < 0x10000 (the maximum desc size),
        // the actual hw_num_processed is a number between 1 and desc_count.
        // Therefore the value can be desc_count, in this case we change it to
        // zero.
        result->timestamps[i].desc_num_processed = result->timestamps[i].desc_num_processed &
            channel->state.desc_count_mask;
        i++;
    }

    result->timestamps_count = i;
}

static void channel_state_init(struct hailo_vdma_channel_state *state)
{
    state->num_avail = state->num_proc = 0;

    // Special value used when the channel is not activate.
    state->desc_count_mask = U32_MAX;
}

static u8 __iomem *get_channel_regs(u8 __iomem *regs_base, u8 channel_index, bool is_host_side, u64 src_channels_bitmask)
{
    // Check if getting host side regs or device side
    u8 __iomem *channel_regs_base = regs_base + CHANNEL_BASE_OFFSET(channel_index);
    if (is_host_side) {
        return hailo_test_bit_64(channel_index, &src_channels_bitmask) ? channel_regs_base :
            (channel_regs_base + CHANNEL_DEST_REGS_OFFSET);
    } else {
        return hailo_test_bit_64(channel_index, &src_channels_bitmask) ? (channel_regs_base + CHANNEL_DEST_REGS_OFFSET) :
            channel_regs_base;
    }
}

void hailo_vdma_engine_init(struct hailo_vdma_engine *engine, u8 engine_index,
    const struct hailo_resource *channel_registers, u64 src_channels_bitmask, u16 channels_count)
{
    u8 channel_index = 0;
    struct hailo_vdma_channel *channel;

    engine->index = engine_index;
    engine->enabled_channels = 0x0;
    engine->channels_count = channels_count;

    for_each_vdma_channel(engine, channel, channel_index) {
        u8 __iomem *regs_base = (u8 __iomem *)channel_registers->address;
        channel->host_regs = get_channel_regs(regs_base, channel_index, true, src_channels_bitmask);
        channel->device_regs = get_channel_regs(regs_base, channel_index, false, src_channels_bitmask);
        channel->index = channel_index;
        channel->timestamp_measure_enabled = false;

        channel_state_init(&channel->state);
        channel->last_desc_list = NULL;
        channel->ongoing_transfers = NULL;
    }
}

/**
 * Enables the given channels bitmap in the given engine. Allows launching transfer
 * and reading interrupts from the channels.
 *
 * @param engine - dma engine.
 * @param bitmap - channels bitmap to enable.
 * @param measure_timestamp - if set, allow interrupts timestamp measure.
 */
void hailo_vdma_engine_enable_channels(struct hailo_vdma_engine *engine, u64 bitmap,
    bool measure_timestamp)
{
    struct hailo_vdma_channel *channel = NULL;
    u8 channel_index = 0;

    for_each_vdma_channel(engine, channel, channel_index) {
        if (hailo_test_bit_64(channel_index, &bitmap)) {
            channel->timestamp_measure_enabled = measure_timestamp;
            channel->timestamp_list.head = channel->timestamp_list.tail = 0;
        }
    }

    engine->enabled_channels |= bitmap;
}

/**
 * Disables the given channels bitmap in the given engine.
 *
 * @param dev - device object, depends on the platform
 * @param engine - dma engine.
 * @param bitmap - channels bitmap to enable.
 */
void hailo_vdma_engine_disable_channels(struct device *dev, struct hailo_vdma_engine *engine, u64 bitmap)
{
    struct hailo_vdma_channel *channel = NULL;
    u8 channel_index = 0;

    engine->enabled_channels &= ~bitmap;

    for_each_vdma_channel(engine, channel, channel_index) {
        if (hailo_test_bit_64(channel_index, &bitmap)) {
            channel_state_init(&channel->state);

            while (channel->ongoing_transfers && TRANSFERS_CIRC_CNT(*channel->ongoing_transfers) > 0) {
                struct hailo_transfer transfer;
                hailo_vdma_transfer_pop(&channel->ongoing_transfers, &transfer);

                if (channel->last_desc_list == NULL) {
                    pr_err("Channel %d has ongoing transfers but no desc list\n", channel->index);
                    continue;
                }

                clear_dirty_descs(channel, &transfer);
                hailo_vdma_transfer_done(dev, &transfer);
            }
            if (channel->last_desc_list != NULL) {
                channel->last_desc_list->num_launched = 0;
                channel->last_desc_list->num_programmed = 0;
            }

            // Free the ongoing transfers list
            hailo_vdma_transfer_list_free(&channel->ongoing_transfers);

            channel->last_desc_list = NULL;
        }
    }
}

void hailo_vdma_engine_push_timestamps(struct hailo_vdma_engine *engine, u64 bitmap)
{
    struct hailo_vdma_channel *channel = NULL;
    u8 channel_index = 0;

    for_each_vdma_channel(engine, channel, channel_index) {
        if (unlikely(hailo_test_bit_64(channel_index, &bitmap) &&
                channel->timestamp_measure_enabled)) {
            hailo_vdma_push_timestamp(channel);
        }
    }
}

int hailo_vdma_engine_read_timestamps(struct hailo_vdma_engine *engine,
    struct hailo_vdma_interrupts_read_timestamp_params *params)
{
    struct hailo_vdma_channel *channel = NULL;

    if (params->channel_index >= MAX_VDMA_CHANNELS_PER_ENGINE) {
        pr_err("Failed to read timestamps, invalid channel index %u\n", params->channel_index);
        return -EINVAL;
    }

    channel = &engine->channels[params->channel_index];
    hailo_vdma_pop_timestamps_to_response(channel, params);
    return 0;
}

static bool is_desc_between(u16 begin, u16 end, u16 desc)
{
    if (begin == end) {
        // There is nothing between
        return false;
    }
    if (begin < end) {
        // desc needs to be in [begin, end)
        return (begin <= desc) && (desc < end);
    }
    else {
        // desc needs to be in [0, end) or [begin, m_descs.size()-1]
        return (desc < end) || (begin <= desc);
    }
}

static bool is_transfer_complete(struct hailo_vdma_channel *channel,
    struct hailo_transfer *transfer, u16 hw_num_proc)
{
    if (channel->state.num_avail == hw_num_proc) {
        return true;
    }

    return is_desc_between(channel->state.num_proc, hw_num_proc, transfer->last_desc);
}

// Some drivers (pci_ep) does not support ioread64, so we need to read 32 bits at a time.
// We can optimize other drivers by using some ifdef.
static u64 ioread64_safe(u8 *addr)
{
    return ((u64)ioread32(addr + 4) << 32) | ioread32(addr);
}

static void fill_channel_irq_data(struct device *dev, struct hailo_vdma_interrupts_channel_data *irq_data,
    struct hailo_vdma_engine *engine, struct hailo_vdma_channel *channel)
{
    u8 transfers_completed = 0;
    bool validation_success = true;
    bool is_debug = false;

    // Reading 64 bits of the host registers to save pcie reads
    u64 host_regs_low_qword = ioread64_safe(channel->host_regs);
    u8 host_control = READ_BITS_AT_OFFSET(BYTE_SIZE * BITS_IN_BYTE, CHANNEL_CONTROL_OFFSET * BITS_IN_BYTE, host_regs_low_qword);
    bool is_active = channel_control_reg_is_active(host_control);

    // Although the hw_num_processed should be a number between 0 and
    // desc_count-1, if desc_count < 0x10000 (the maximum desc size),
    // the actual hw_num_processed is a number between 1 and desc_count.
    // Therefore the value can be desc_count, in this case we change it to
    // zero.
    u16 hw_num_proc = (u16)
        (READ_BITS_AT_OFFSET(WORD_SIZE * BITS_IN_BYTE, CHANNEL_NUM_PROC_OFFSET * BITS_IN_BYTE, host_regs_low_qword) &
         channel->state.desc_count_mask);

    while (channel->ongoing_transfers && TRANSFERS_CIRC_CNT(*channel->ongoing_transfers) > 0) {
        struct hailo_transfer *cur_transfer =
            &channel->ongoing_transfers->transfers[channel->ongoing_transfers->tail];
        if (!is_transfer_complete(channel, cur_transfer, hw_num_proc)) {
            break;
        }

        if (unlikely(cur_transfer->is_debug) &&
            !validate_last_desc_status(channel, cur_transfer)) {
            validation_success = false;
            is_debug = true;
        }

        clear_dirty_descs(channel, cur_transfer);
        hailo_vdma_transfer_done(dev, cur_transfer);
        channel->state.num_proc = (u16)((cur_transfer->last_desc + 1) & channel->state.desc_count_mask);

        hailo_vdma_transfer_pop(&channel->ongoing_transfers, NULL);
        transfers_completed++;
    }

    if (is_debug) {
        u8 src_err = READ_BITS_AT_OFFSET(BYTE_SIZE * BITS_IN_BYTE, 0, ioread32(channel->host_regs + CHANNEL_ERROR_OFFSET));
        u8 dst_err = READ_BITS_AT_OFFSET(BYTE_SIZE * BITS_IN_BYTE, 0, ioread32(channel->device_regs + CHANNEL_ERROR_OFFSET));

        if (src_err || dst_err) {
            pr_err("Error on channel %d: src 0x%x, dst 0x%x\n", channel->index, src_err, dst_err);
            validation_success = false;
        }
    }

    irq_data->engine_index = engine->index;
    irq_data->channel_index = channel->index;

    if (unlikely(!is_active)) {
        irq_data->data = HAILO_VDMA_TRANSFER_DATA_CHANNEL_NOT_ACTIVE;
    } else if (unlikely(!validation_success)) {
        irq_data->data = HAILO_VDMA_TRANSFER_DATA_CHANNEL_WITH_ERROR;
    } else {
        irq_data->data = transfers_completed;
    }
}

int hailo_vdma_engine_fill_irq_data(struct device *dev, struct hailo_vdma_interrupts_wait_params *irq_data,
    struct hailo_vdma_engine *engine, u64 irq_channels_bitmap)
{
    while (irq_channels_bitmap) {
        u8 channel_index = (u8)__builtin_ctzl(irq_channels_bitmap);
        struct hailo_vdma_channel *channel = &engine->channels[channel_index];
        irq_channels_bitmap &= ~(1ULL << channel_index);

        if (unlikely(channel->last_desc_list == NULL)) {
            // Channel not active or no transfer, skipping.
            continue;
        }

        if (unlikely(irq_data->channels_count >= ARRAY_SIZE(irq_data->irq_data))) {
            pr_err("Too many channels with interrupts\n");
            return -EINVAL;
        }

        fill_channel_irq_data(dev, &irq_data->irq_data[irq_data->channels_count], engine, channel);
        irq_data->channels_count++;
    }

    return 0;
}

// For all these functions - best way to optimize might be to not call the function when need to pause and then abort,
// Rather read value once and maybe save
// This function reads and writes the register - should try to make more optimized in future
static void start_vdma_control_register(u8 __iomem *host_regs)
{
    u32 host_regs_value = ioread32(host_regs);
    iowrite32(WRITE_BITS_AT_OFFSET(BYTE_SIZE * BITS_IN_BYTE, CHANNEL_CONTROL_OFFSET * BITS_IN_BYTE, host_regs_value,
        VDMA_CHANNEL_CONTROL_START_RESUME), host_regs);
}

static void hailo_vdma_channel_pause(u8 __iomem *host_regs)
{
    u32 host_regs_value = ioread32(host_regs);
    iowrite32(WRITE_BITS_AT_OFFSET(BYTE_SIZE * BITS_IN_BYTE, CHANNEL_CONTROL_OFFSET * BITS_IN_BYTE, host_regs_value,
        VDMA_CHANNEL_CONTROL_START_PAUSE), host_regs);
}

// This function reads and writes the register - should try to make more optimized in future
static void hailo_vdma_channel_abort(u8 __iomem *host_regs)
{
    u32 host_regs_value = ioread32(host_regs);
    iowrite32(WRITE_BITS_AT_OFFSET(BYTE_SIZE * BITS_IN_BYTE, CHANNEL_CONTROL_OFFSET * BITS_IN_BYTE, host_regs_value,
        VDMA_CHANNEL_CONTROL_ABORT), host_regs);
}

void hailo_vdma_start_channel(u8 __iomem *regs, uint64_t desc_dma_address, uint32_t desc_count,
    uint8_t data_id)
{
    u16 dma_address_l = 0;
    u32 dma_address_h = 0;
    u32 desc_depth_data_id = 0;
    u8 desc_depth = ceil_log2(desc_count);

    if (((desc_dma_address & 0xFFFF) != 0) ||
         (desc_depth > DESCRIPTOR_LIST_MAX_DEPTH)) {
        pr_err("Invalid descriptor address or depth\n");
        return;
    }

    // According to spec, depth 16 is equivalent to depth 0.
    if (DESCRIPTOR_LIST_MAX_DEPTH == desc_depth) {
        desc_depth = 0;
    }

    // Stop old channel state
    hailo_vdma_stop_channel(regs);

    // Configure address, depth and id
    dma_address_l = (uint16_t)((desc_dma_address >> 16) & 0xFFFF);
    iowrite32(WRITE_BITS_AT_OFFSET(WORD_SIZE * BITS_IN_BYTE, (VDMA_CHANNEL__ADDRESS_L_OFFSET -
        VDMA_CHANNEL__ALIGNED_ADDRESS_L_OFFSET) * BITS_IN_BYTE, ioread32(regs +
        VDMA_CHANNEL__ALIGNED_ADDRESS_L_OFFSET), dma_address_l), regs + VDMA_CHANNEL__ALIGNED_ADDRESS_L_OFFSET);

    dma_address_h = (uint32_t)(desc_dma_address >> 32);
    iowrite32(dma_address_h, regs + VDMA_CHANNEL__ADDRESS_H_OFFSET);

    desc_depth_data_id = (uint32_t)(desc_depth << VDMA_CHANNEL_DESC_DEPTH_SHIFT) |
        (data_id << VDMA_CHANNEL_DATA_ID_SHIFT);
    iowrite32(desc_depth_data_id, regs);

    start_vdma_control_register(regs);
}

static bool hailo_vdma_channel_is_idle(u8 __iomem *host_regs, size_t host_side_max_desc_count)
{
    // Num processed and ongoing are next to each other in the memory.
    // Reading them both in order to save BAR reads.
    u32 host_side_num_processed_ongoing = ioread32(host_regs + CHANNEL_NUM_PROC_OFFSET);
    u16 host_side_num_processed = (host_side_num_processed_ongoing & VDMA_CHANNEL_NUM_PROCESSED_MASK);
    u16 host_side_num_ongoing = (host_side_num_processed_ongoing >> VDMA_CHANNEL_NUM_PROCESSED_WIDTH) &
        VDMA_CHANNEL_NUM_ONGOING_MASK;

    if ((host_side_num_processed % host_side_max_desc_count) == (host_side_num_ongoing % host_side_max_desc_count)) {
        return true;
    }

    return false;
}

static int hailo_vdma_wait_until_channel_idle(u8 __iomem *host_regs)
{
    bool is_idle = false;
    uint32_t check_counter = 0;

    const u8 depth = vdma_regs_get_channel_depth(ioread32(host_regs));
    const u32 host_side_max_desc_count = (u32)(1ULL << depth);

    for (check_counter = 0; check_counter < VDMA_CHANNEL__MAX_CHECKS_CHANNEL_IS_IDLE; check_counter++) {
        is_idle = hailo_vdma_channel_is_idle(host_regs, host_side_max_desc_count);
        if (is_idle) {
            return 0;
        }
    }

    return -ETIMEDOUT;
}

void hailo_vdma_stop_channel(u8 __iomem *regs)
{
    int err = 0;
    u8 host_side_channel_regs = READ_BITS_AT_OFFSET(BYTE_SIZE * BITS_IN_BYTE, CHANNEL_CONTROL_OFFSET * BITS_IN_BYTE, ioread32(regs));

    if ((host_side_channel_regs & VDMA_CHANNEL_CONTROL_START_ABORT_PAUSE_RESUME_BITMASK) == VDMA_CHANNEL_CONTROL_ABORT_PAUSE) {
        // The channel is aborted (we set the channel to VDMA_CHANNEL_CONTROL_ABORT_PAUSE at the end of this function)
        return;
    }

    // Pause the channel
    // The channel is paused to allow for "all transfers from fetched descriptors..." to be "...completed"
    // (from PLDA PCIe refernce manual, "9.2.5 Starting a Channel and Transferring Data")
    hailo_vdma_channel_pause(regs);

    // Even if channel is stuck and not idle, force abort and return error in the end
    err = hailo_vdma_wait_until_channel_idle(regs);
    // Success oriented - if error occured print error but still abort channel
    if (err < 0) {
        pr_err("Timeout occured while waiting for channel to become idle\n");
    }

    // Abort the channel (even of hailo_vdma_wait_until_channel_idle function fails)
    hailo_vdma_channel_abort(regs);
}

bool hailo_check_channel_index(u8 channel_index, u64 src_channels_bitmask, bool is_input_channel)
{
    // return true if the bit state matches what we want for this channel type
    return (hailo_test_bit_64(channel_index, &src_channels_bitmask) == is_input_channel);
}