// SPDX-License-Identifier: MIT
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
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

#define VDMA_CHANNEL__MAX_CHECKS_CHANNEL_IS_IDLE (10000)

#define DESCRIPTOR_PAGE_SIZE_SHIFT (8)
#define DESCRIPTOR_DESC_CONTROL (0x2)
#define DESCRIPTOR_ADDR_MASK (~0x3FULL)
#define DESCRIPTOR_LIST_MAX_DEPTH (16)

#define DESCRIPTOR_PAGE_SIZE_CONTROL_REG(page_size) \
    (((page_size) << DESCRIPTOR_PAGE_SIZE_SHIFT) + DESCRIPTOR_DESC_CONTROL)

#define DESC_REQUEST_IRQ_PROCESSED            (1 << 2)
#define DESC_REQUEST_IRQ_ERR                  (1 << 3)

#define DESC_LIST_BASE(desc_list) ((struct hailo_vdma_descriptor *)(desc_list)->buffer.kernel_address)

static inline int transfer_push(struct hailo_transfer_list *transfers, struct hailo_transfer *transfer)
{
    /* Lazily allocate the list. */
    if (!transfers->list) {
        transfers->list = kzalloc(sizeof(struct hailo_transfer) * HAILO_VDMA_MAX_ONGOING_TRANSFERS, GFP_KERNEL);
        if (!transfers->list) {
            return -ENOMEM;
        }
    }

    if (CIRC_SPACE(transfers->head, transfers->tail, HAILO_VDMA_MAX_ONGOING_TRANSFERS) == 0) {
        return -EINVAL;
    }

    transfers->list[transfers->head] = *transfer;
    transfers->head = (transfers->head + 1) & HAILO_VDMA_MAX_ONGOING_TRANSFERS_MASK;

    return 0;
}

static inline bool transfer_peek(struct hailo_transfer_list *transfers, struct hailo_transfer **transfer)
{
    if (HAILO_TRANSFERS_CNT(transfers) == 0) {
        return false;
    }

    *transfer = &transfers->list[transfers->tail];
    return true;
}

static inline void transfer_pop(struct hailo_transfer_list *transfers)
{
    if (HAILO_TRANSFERS_CNT(transfers) > 0) {
        transfers->tail = (transfers->tail + 1) & HAILO_VDMA_MAX_ONGOING_TRANSFERS_MASK;
    }
}

static void clear_dirty_desc(struct hailo_vdma_descriptors_list *desc_list, u16 desc)
{
    DESC_LIST_BASE(desc_list)[desc].PageSize_DescControl =
        (u32)((desc_list->desc_page_size << DESCRIPTOR_PAGE_SIZE_SHIFT) + DESCRIPTOR_DESC_CONTROL);
}

static void clear_dirty_descs(struct hailo_vdma_channel *channel, struct hailo_transfer *ongoing_transfer)
{
    u8 i = 0;
    struct hailo_vdma_descriptors_list *desc_list = channel->desc_list;
    BUG_ON(ongoing_transfer->dirty_descs_count > ARRAY_SIZE(ongoing_transfer->dirty_descs));
    for (i = 0; i < ongoing_transfer->dirty_descs_count; i++) {
        clear_dirty_desc(desc_list, ongoing_transfer->dirty_descs[i]);
    }
}

static inline void hailo_vdma_program_descriptor(struct hailo_vdma_descriptor *descriptor, u64 dma_address,
    u32 page_size_control_reg)
{
    descriptor->PageSize_DescControl = page_size_control_reg;
    descriptor->AddrL_rsvd_DataID = (u32)(dma_address);
    descriptor->AddrH = (u32)(dma_address >> 32);
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
    program_continuous_descriptors_in_chunk(chunk_addr, &DESC_LIST_BASE(desc_list)[starting_desc], descs_to_end,
        transfer_size, page_size, total_desc_programmed);
    chunk_addr += descs_to_end * page_size;
    total_desc_programmed += descs_to_end;

    if (descs_from_start > 0) {
        program_continuous_descriptors_in_chunk(chunk_addr, DESC_LIST_BASE(desc_list), descs_from_start,
            transfer_size, page_size, total_desc_programmed);
        chunk_addr += descs_from_start * page_size;
        total_desc_programmed += descs_from_start;
    }
}

static unsigned long get_interrupts_bitmask(struct hailo_vdma_hw *vdma_hw, bool should_interrupt)
{
    if (should_interrupt) {
        return vdma_hw->interrupts_bitmask | DESC_REQUEST_IRQ_PROCESSED | DESC_REQUEST_IRQ_ERR;
    }
    return 0;
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

static struct scatterlist *sg_skip_offset(struct scatterlist *sg, u64 *skip_bytes)
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
    struct sg_table *sgt,
    u64 sgt_offset,
    u32 transfer_size,
    u32 transfers_count,
    u8 channel_index,
    bool should_interrupt)
{
    struct scatterlist *sg = NULL;
    u64 skip_bytes = sgt_offset;
    u32 starting_desc = desc_list->descs_programmed;
    const u32 aligned_transfer_size = ALIGN(transfer_size, desc_list->desc_page_size);
    u32 program_size = aligned_transfer_size * transfers_count;
    u32 total_desc_to_program = DIV_ROUND_UP(program_size, desc_list->desc_page_size);
    u32 desc_programmed = 0;
    // Only power-of-2 lists may wrap around; other lists must not program past desc_count.
    const u32 max_descs_to_program = is_powerof2(desc_list->desc_count) ?
        desc_list->desc_count: (desc_list->desc_count - starting_desc);
    u64 masked_channel_id = get_masked_channel_id(channel_index, vdma_hw);

    if (sgt_offset % desc_list->desc_page_size != 0) {
        pr_err("Invalid buffer offset %llu. desc_list->desc_page_size %d\n",
            (unsigned long long)sgt_offset, desc_list->desc_page_size);
        return -EINVAL;
    }

    if (total_desc_to_program > max_descs_to_program) {
        pr_err("Desc programmed size %u is larger than max_descs_to_program %u\n",
            total_desc_to_program, max_descs_to_program);
        return -EINVAL;
    }

    for (sg = sg_skip_offset(sgt->sgl, &skip_bytes); sg; sg = sg_next_mapped(sg)) {
        const dma_addr_t chunk_start_addr = sg_dma_address(sg) + skip_bytes;
        const u32 chunk_size = min((u32)program_size, (u32)(sg_dma_len(sg) - skip_bytes));

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
    DESC_LIST_BASE(desc_list)[(starting_desc - 1) % desc_list->desc_count].PageSize_DescControl |=
        get_interrupts_bitmask(vdma_hw, should_interrupt);

    desc_list->descs_programmed = starting_desc % desc_list->desc_count;

    return (int)desc_programmed;
}

static int program_last_desc(
    struct hailo_vdma_hw *vdma_hw,
    struct hailo_vdma_descriptors_list *desc_list,
    struct hailo_vdma_mapped_transfer_buffer *transfer_buffer,
    bool should_interrupt)
{
    u8 control = (u8)(DESCRIPTOR_DESC_CONTROL | get_interrupts_bitmask(vdma_hw, should_interrupt));
    u32 total_descs = DIV_ROUND_UP(transfer_buffer->size, desc_list->desc_page_size);
    u32 last_desc = (desc_list->descs_programmed + total_descs - 1) % desc_list->desc_count;
    u32 last_desc_size = transfer_buffer->size - (total_descs - 1) * desc_list->desc_page_size;

    // Configure only last descriptor with residue size
    DESC_LIST_BASE(desc_list)[last_desc].PageSize_DescControl = (u32)
        ((last_desc_size << DESCRIPTOR_PAGE_SIZE_SHIFT) + control);

    desc_list->descs_programmed = (desc_list->descs_programmed + total_descs) % desc_list->desc_count;

    return (int)total_descs;
}

int hailo_vdma_prepare_transfer(struct hailo_vdma_hw *vdma_hw, u8 channel_index,
    struct hailo_vdma_descriptors_list *desc_list, u8 buffers_count, struct hailo_transfer *prepared_transfer,
    bool is_programmed)
{
    u32 total_descs = 0;
    u32 last_desc = U32_MAX;
    u8 i = 0;
    int err = 0;

    if (buffers_count > HAILO_MAX_BUFFERS_PER_SINGLE_TRANSFER) {
        pr_err("Too many buffers %u for single transfer\n", buffers_count);
        err = -EINVAL;
        goto exit_err;
    }

    for (i = 0; i < buffers_count; i++) {
        const bool transfers_count = 1;
        err = is_programmed ?
            program_last_desc(vdma_hw, desc_list, &prepared_transfer->buffers[i], true) :
            hailo_vdma_program_descriptors_list(vdma_hw, desc_list, prepared_transfer->buffers[i].sg_table,
                prepared_transfer->buffers[i].offset, prepared_transfer->buffers[i].size, transfers_count,
                channel_index, true);
        if (err < 0) {
            pr_err("Failed program descriptors list\n");
            goto exit_err;
        }

        total_descs += err;
        last_desc = (desc_list->descs_programmed + desc_list->desc_count - 1) % desc_list->desc_count;
        prepared_transfer->dirty_descs[i] = (u16)last_desc;
    }

    prepared_transfer->dirty_descs_count = buffers_count;
    prepared_transfer->last_desc = (u16)last_desc;

    err = transfer_push(&desc_list->prepared_transfers, prepared_transfer);
    if (err < 0) {
        pr_err("Failed to push prepared transfer to list\n");
        goto exit_err;
    }

    return total_descs;

exit_err:
    hailo_vdma_transfer_release(prepared_transfer);
    return err;
}

void hailo_vdma_cancel_prepared_transfer(struct hailo_vdma_descriptors_list *desc_list)
{
    struct hailo_transfer *transfer = NULL;

    while (transfer_peek(&desc_list->prepared_transfers, &transfer)) {
        hailo_vdma_transfer_release(transfer);
        transfer_pop(&desc_list->prepared_transfers);
    }

    desc_list->descs_programmed = 0;
}

int hailo_vdma_launch_transfer(struct hailo_vdma_channel *channel, struct hailo_vdma_descriptors_list *desc_list)
{
    int err = 0;
    struct hailo_transfer *transfer = NULL;

    if (NULL == channel->desc_list) {
        /* First transfer on this active channel; store desc-list.
         * NOTE(amitaig): Nothing stops us from binding the same desc-list to several channels :( */
        channel->desc_list = desc_list;
    }

    if (desc_list != channel->desc_list) {
        // Shouldn't happen, desc list may change only after channel deactivation.
        pr_err("Inconsistent desc list given to channel %d\n", channel->hw_chan.index);
        return -EINVAL;
    }

    if (!vdma_channel_is_started(&channel->hw_chan)) {
        pr_err("Channel %d not started\n", channel->hw_chan.index);
        return -ECONNRESET;
    }

    if (!transfer_peek(&desc_list->prepared_transfers, &transfer)) {
        pr_err("No prepared transfer to launch on channel %d\n", channel->hw_chan.index);
        return -ENOENT;
    }

    err = transfer_push(&desc_list->ongoing_transfers, transfer);
    if (err < 0) {
        pr_err("Failed to push ongoing transfer to channel %d\n", channel->hw_chan.index);
        return err;
    }

    vdma_channel_set_available(&channel->hw_chan, (u16)((transfer->last_desc + 1) & desc_list->desc_count_mask));
    transfer_pop(&desc_list->prepared_transfers);

    return 0;
}

static int init_channel_pair(const struct vdma_channels *channels, struct hailo_vdma_channel_pair *pair, u8 channel_idx)
{
    int err = 0;
    struct vdma_chan *src = NULL;
    struct vdma_chan *dst = NULL;

    if (vdma_channel_direction_by_idx(channels->variant, channel_idx) == VDMA_H2D) {
        src = &pair->host.hw_chan;
        dst = &pair->device.hw_chan;
    } else {
        src = &pair->device.hw_chan;
        dst = &pair->host.hw_chan;
    }

    err = vdma_channel_src(channels, channel_idx, src);
    if (err != VDMA_SUCCESS) {
        return err;
    }

    err = vdma_channel_dest(channels, channel_idx, dst);
    if (err != VDMA_SUCCESS) {
        return err;
    }

    pair->host.desc_list = NULL;
    pair->device.desc_list = NULL;

    return 0;
}

int hailo_vdma_engine_init(struct hailo_vdma_engine *engine, u8 engine_index, enum vdma_engine_variant engine_variant,
    void __iomem *channel_regs)
{
    int err = 0;
    u8 idx = 0;
    struct vdma_channels hw_channels = {0};
    struct hailo_vdma_channel_pair *channel_pair = NULL;

    err = vdma_channels_init(&hw_channels, engine_variant, channel_regs);
    if (err != VDMA_SUCCESS) {
        pr_err("Failed to init vdma channels for engine %d: %d", engine_index, err);
        return -EINVAL;
    }

    engine->index = engine_index;
    engine->enabled_channels = 0x0;
    engine->channels_count = vdma_channels_count(hw_channels.variant);

    for_each_vdma_channel_pair(engine, channel_pair, idx) {
        err = init_channel_pair(&hw_channels, channel_pair, idx);
        if (err != VDMA_SUCCESS) {
            pr_err("Failed to init vdma channel %d for engine %d: %d", idx, engine_index, err);
            return -EINVAL;
        }
    }

    return 0;
}

void hailo_vdma_engine_enable_channels(struct hailo_vdma_engine *engine, u64 bitmap)
{
    engine->enabled_channels |= bitmap;
}

static void release_channel(struct hailo_vdma_channel *channel)
{
    struct hailo_transfer *transfer = NULL;

    if (channel->desc_list == NULL) {
        return;
    }

    while (transfer_peek(&channel->desc_list->ongoing_transfers, &transfer)) {
        clear_dirty_descs(channel, transfer);
        hailo_vdma_transfer_done(transfer);
        transfer_pop(&channel->desc_list->ongoing_transfers);
    }

    hailo_vdma_cancel_prepared_transfer(channel->desc_list);
    channel->desc_list = NULL;
}

void hailo_vdma_disable_channels(struct hailo_vdma_engine *engine, u64 bitmap)
{
    struct hailo_vdma_channel_pair *channel = NULL;
    u8 channel_index = 0;

    for_each_vdma_channel_pair(engine, channel, channel_index) {
        if (hailo_test_bit_64(channel_index, &bitmap)) {
            hailo_vdma_stop_channel(&channel->host);
            hailo_vdma_stop_channel(&channel->device);
        }
    }
}

void hailo_vdma_engine_release_channels(struct hailo_vdma_engine *engine, u64 bitmap)
{
    struct hailo_vdma_channel_pair *channel = NULL;
    u8 channel_index = 0;

    engine->enabled_channels &= ~bitmap;

    for_each_vdma_channel_pair(engine, channel, channel_index) {
        if (hailo_test_bit_64(channel_index, &bitmap)) {
            release_channel(&channel->host);
            release_channel(&channel->device);
        }
    }
}

static bool is_desc_between(u32 begin, u32 end, u32 desc)
{
    // if (begin <= end) then we need desc to be in [begin, end). Otherwise we need desc in [0, end) U [begin, inf).
    return (begin <= end) ? (begin <= desc) && (desc < end) : (desc < end) || (begin <= desc);
}

static bool is_transfer_done(u16 num_proc, u16 num_avail, u16 last_desc)
{
    // A transfer is done if its last desc is not ongoing, i.e. the last desc is NOT between processed and available.
    return !is_desc_between(num_proc, num_avail, last_desc);
}

static void fill_channel_irq_data(struct hailo_vdma_interrupts_channel_data *irq_data, struct hailo_vdma_engine *engine,
    struct hailo_vdma_channel *channel)
{
    struct hailo_transfer_list *ongoing = &channel->desc_list->ongoing_transfers;
    struct hailo_transfer *transfer = NULL;
    u8 transfers_completed = 0;
    u16 num_proc = vdma_channel_get_processed(&channel->hw_chan);
    u16 num_avail = vdma_channel_get_available(&channel->hw_chan);
    bool is_active = vdma_channel_is_started(&channel->hw_chan);

    while (transfer_peek(ongoing, &transfer) && is_transfer_done(num_proc, num_avail, transfer->last_desc)) {
        clear_dirty_descs(channel, transfer);
        hailo_vdma_transfer_done(transfer);
        transfer_pop(ongoing);
        transfers_completed++;
    }

    irq_data->engine_index = engine->index;
    irq_data->channel_index = channel->hw_chan.index;

    if (unlikely(!is_active)) {
        irq_data->data = HAILO_VDMA_TRANSFER_DATA_CHANNEL_NOT_ACTIVE;
    } else {
        irq_data->data = transfers_completed;
    }
}

int hailo_vdma_engine_fill_irq_data(struct hailo_vdma_interrupts_wait_params *irq_data,
    struct hailo_vdma_engine *engine, u64 irq_channels_bitmap)
{
    u8 channel_index = 0;
    struct hailo_vdma_channel *channel = NULL;

    while (irq_channels_bitmap) {
        channel_index = (u8)__builtin_ctzl(irq_channels_bitmap);
        hailo_clear_bit(channel_index, &irq_channels_bitmap);
        channel = &engine->channels[channel_index].host;

        if (unlikely(channel->desc_list == NULL)) {
            /* Channel not active or no transfer, skipping. */
            continue;
        }

        if (unlikely(irq_data->channels_count >= ARRAY_SIZE(irq_data->irq_data))) {
            pr_err("Too many channels with interrupts\n");
            return -EINVAL;
        }

        fill_channel_irq_data(&irq_data->irq_data[irq_data->channels_count], engine, channel);
        irq_data->channels_count++;
    }

    return 0;
}

int hailo_vdma_start_channel(const struct hailo_vdma_channel *chan, uint64_t desc_dma_address, uint32_t desc_count,
    enum vdma_desc_list_type desc_list_type)
{
    int err = 0;
    struct vdma_desc_list_params desc_list = {
        .dma_address = desc_dma_address,
        .count = desc_count,
        .type = desc_list_type,
    };

    if (((desc_dma_address & 0xFFFF) != 0) || (desc_count > (1 << DESCRIPTOR_LIST_MAX_DEPTH))) {
        pr_err("Invalid descriptor address or depth\n");
        return -EINVAL;
    }

    hailo_vdma_stop_channel(chan);

    err = vdma_channel_configure(&chan->hw_chan, &desc_list);
    if (err != VDMA_SUCCESS) {
        pr_err("Failed to configure VDMA channel: %d", err);
        return -EIO;
    }

    vdma_channel_start(&chan->hw_chan);

    return 0;
}

static int hailo_vdma_wait_until_channel_idle(const struct vdma_chan *chan)
{
    uint32_t check_counter = 0;

    for (check_counter = 0; check_counter < VDMA_CHANNEL__MAX_CHECKS_CHANNEL_IS_IDLE; check_counter++) {
        if (vdma_channel_is_idle(chan)) {
            return 0;
        }
    }

    return -ETIMEDOUT;
}

void hailo_vdma_stop_channel(const struct hailo_vdma_channel *chan)
{
    if (!vdma_channel_is_started(&chan->hw_chan)) {
        return;
    }

    // NOTE(amitaig): Consider moving the pause-wait-abort pattern to the shared vDMA module.

    // The channel is paused to allow for "all transfers from fetched descriptors..." to be "...completed"
    // (from PLDA PCIe refernce manual, "9.2.5 Starting a Channel and Transferring Data")
    vdma_channel_pause(&chan->hw_chan);

    // Even if channel is stuck and not idle, force abort and return error in the end
    if (hailo_vdma_wait_until_channel_idle(&chan->hw_chan) != 0) {
        // Success oriented - if error occured print error but still abort channel
        pr_err("Timeout occured while waiting for channel to become idle\n");
    }

    // Abort the channel (even of hailo_vdma_wait_until_channel_idle function fails)
    vdma_channel_abort(&chan->hw_chan);
}
