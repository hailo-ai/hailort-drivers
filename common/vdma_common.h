// SPDX-License-Identifier: MIT
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_COMMON_VDMA_COMMON_H_
#define _HAILO_COMMON_VDMA_COMMON_H_

#include "hailo_resource.h"
#include "utils.h"
#include "driver_timeouts.h"

#include <vdma/channel.h>

#include <linux/circ_buf.h>
#include <linux/types.h>
#include <linux/scatterlist.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/device.h>

#define VDMA_DESCRIPTOR_LIST_ALIGN  (1 << 16)

#define HAILO_TRANSFERS_CNT(transfers) \
    ((transfers)->list ? CIRC_CNT((transfers)->head, (transfers)->tail, HAILO_VDMA_MAX_ONGOING_TRANSFERS) : 0)

#ifdef __cplusplus
extern "C"
{
#endif

struct hailo_vdma_descriptor {
    u32    PageSize_DescControl;
    u32    AddrL_rsvd_DataID;
    u32    AddrH;
    u32    RemainingPageSize_Status;
};

struct hailo_vdma_mapped_transfer_buffer {
    struct sg_table *sg_table;
    u32 size;
    u32 offset;

    // Opaque data for different driver implementations.
    void *opaque;
};

struct hailo_transfer {
    uint16_t last_desc;

    u8 buffers_count;
    struct hailo_vdma_mapped_transfer_buffer buffers[HAILO_MAX_BUFFERS_PER_SINGLE_TRANSFER];

    // Contains all descriptors that were programmed with non-default values for the transfer.
    uint8_t dirty_descs_count;
    uint16_t dirty_descs[HAILO_MAX_BUFFERS_PER_SINGLE_TRANSFER];

    // Opaque data for different driver implementations.
    void *opaque;
};

struct hailo_transfer_list {
    int head;
    int tail;
    struct hailo_transfer *list;
};

struct hailo_vdma_buffer {
    void *kernel_address;
    dma_addr_t dma_address;
    size_t size;
};

struct hailo_vdma_descriptors_list {
    struct hailo_transfer_list prepared_transfers;
    struct hailo_transfer_list ongoing_transfers;
    struct hailo_vdma_buffer buffer;
    u16 desc_page_size;
    u32 desc_count;
    u32 desc_count_mask;
    u32 descs_programmed;
};

struct hailo_vdma_channel {
    struct vdma_chan hw_chan;
    struct hailo_vdma_descriptors_list *desc_list;
};

struct hailo_vdma_channel_pair {
    struct hailo_vdma_channel host;
    struct hailo_vdma_channel device;
};

struct hailo_vdma_engine {
    u8 index;
    u8 channels_count;
    u64 enabled_channels;
    struct hailo_vdma_channel_pair channels[MAX_VDMA_CHANNELS_PER_ENGINE];
};

struct hailo_vdma_hw {
    u64 channel_id_mask;
    u8 channel_id_shift;

    // The data_id code of ddr addresses.
    u8 ddr_data_id;

    // Bitmask needed to set on each descriptor to enable interrupts.
    unsigned long interrupts_bitmask;

    enum vdma_engine_variant variant;
};

#define _for_each_element_array(array, size, element, index) \
    for (index = 0, element = &array[index]; index < size; index++, element = &array[index])

#define for_each_vdma_channel_pair(engine, channel_pair, channel_index) \
    _for_each_element_array((engine)->channels, (engine)->channels_count, channel_pair, channel_index)

void hailo_vdma_program_descriptors_in_chunk(
    dma_addr_t chunk_addr,
    unsigned int chunk_size,
    struct hailo_vdma_descriptors_list *desc_list,
    u32 starting_desc,
    u32 stride,
    u32 total_desc_programmed);

/**
 * Program the given descriptors list to map the given buffer.
 *
 * @param vdma_hw vdma hw object
 * @param desc_list descriptors list object to program
 * @param sgt scatter gather table to program to the descriptors list.
 * @param sgt_offset offset in the scatter gather table to program from.
 * @param transfer_size size of the transfer to program.
 * @param transfers_count number of transfers to program.
 * @param channel_index channel index of the channel attached.
 * @param should_interrupt if true, request an interrupt on the last programmed descriptor.
 * @return On success - the amount of descriptors programmed, negative value on error.
 *
 * Programming starts from where the previous programming of desc_list ended. If the list is circular, this
 * function may wrap around it.
 */
int hailo_vdma_program_descriptors_list(
    struct hailo_vdma_hw *vdma_hw,
    struct hailo_vdma_descriptors_list *desc_list,
    struct sg_table *sgt,
    u64 sgt_offset,
    u32 transfer_size,
    u32 transfers_count,
    u8 channel_index,
    bool should_interrupt);

static inline void hailo_vdma_transfer_list_free(struct hailo_transfer_list *transfers)
{
    /* NOTE(amitaig): Nothing drains the transfers-list here. Possible leak. */
    kfree(transfers->list);
    transfers->list = NULL;
    transfers->head = 0;
    transfers->tail = 0;
}

int hailo_vdma_prepare_transfer(
    struct hailo_vdma_hw *vdma_hw,
    u8 channel_index,
    struct hailo_vdma_descriptors_list *desc_list,
    u8 buffers_count,
    struct hailo_transfer *prepared_transfer,
    bool is_programmed);

void hailo_vdma_cancel_prepared_transfer(struct hailo_vdma_descriptors_list *desc_list);

int hailo_vdma_launch_transfer(struct hailo_vdma_channel *channel, struct hailo_vdma_descriptors_list *desc_list);

int hailo_vdma_engine_init(struct hailo_vdma_engine *engine, u8 engine_index, enum vdma_engine_variant engine_variant,
    void __iomem *channel_regs);

void hailo_vdma_engine_enable_channels(struct hailo_vdma_engine *engine, u64 bitmap);
void hailo_vdma_disable_channels(struct hailo_vdma_engine *engine, u64 bitmap);
void hailo_vdma_engine_release_channels(struct hailo_vdma_engine *engine, u64 bitmap);

// Assuming irq_data->channels_count contains the amount of channels already
// written (used for multiple engines).
int hailo_vdma_engine_fill_irq_data(struct hailo_vdma_interrupts_wait_params *irq_data,
    struct hailo_vdma_engine *engine, u64 irq_channels_bitmap);

// Release all resources associated with a transfer.
void hailo_vdma_transfer_release(struct hailo_transfer *transfer);

// Called when an ongoing transfer has completed. Should call hailo_vdma_transfer_release().
void hailo_vdma_transfer_done(struct hailo_transfer *transfer);

int hailo_vdma_start_channel(const struct hailo_vdma_channel *chan, uint64_t desc_dma_address, uint32_t desc_count,
    enum vdma_desc_list_type desc_list_type);
void hailo_vdma_stop_channel(const struct hailo_vdma_channel *chan);

#ifdef __cplusplus
}
#endif
#endif /* _HAILO_COMMON_VDMA_COMMON_H_ */
