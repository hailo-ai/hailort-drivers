// SPDX-License-Identifier: MIT
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_COMMON_VDMA_COMMON_H_
#define _HAILO_COMMON_VDMA_COMMON_H_

#include "hailo_resource.h"
#include "utils.h"

#include <linux/types.h>
#include <linux/scatterlist.h>
#include <linux/io.h>

#define VDMA_DESCRIPTOR_LIST_ALIGN  (1 << 16)
#define INVALID_VDMA_ADDRESS        (0)

#define CHANNEL_BASE_OFFSET(channel_index) ((channel_index) << 5)

#define CHANNEL_CONTROL_OFFSET      (0x0)
#define CHANNEL_DEPTH_ID_OFFSET     (0x1)
#define CHANNEL_NUM_AVAIL_OFFSET    (0x2)
#define CHANNEL_NUM_PROC_OFFSET     (0x4)
#define CHANNEL_ERROR_OFFSET        (0x8)
#define CHANNEL_DEST_REGS_OFFSET    (0x10)

#define DEFAULT_STRIDE              (0)

#ifndef HAILO_EMULATOR
#ifdef WINDOWS
#define PCI_SOC_CONTROL_CONNECT_TIMEOUT_MS          (10000)
#define PCI_EP_CONTROL_CONNECT_TIMEOUT_MARGIN_MS    (2000)
#else
#define PCI_SOC_CONTROL_CONNECT_TIMEOUT_MS          (1000)
#define PCI_EP_CONTROL_CONNECT_TIMEOUT_MARGIN_MS    (200)
#endif
#else
#define PCI_SOC_CONTROL_CONNECT_TIMEOUT_MS          (1000000)
#define PCI_EP_CONTROL_CONNECT_TIMEOUT_MARGIN_MS    (1000)
#endif /* ifndef HAILO_EMULATOR */
#define PCI_EP_CONTROL_CONNECT_TIMEOUT_MS           (PCI_SOC_CONTROL_CONNECT_TIMEOUT_MS - PCI_EP_CONTROL_CONNECT_TIMEOUT_MARGIN_MS)

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

struct hailo_vdma_descriptors_list {
    struct hailo_vdma_descriptor *desc_list;
    // Must be power of 2 if is_circular is set.
    u32                           desc_count;
    // The nearest power of 2 to desc_count (including desc_count), minus 1.
    // * If the list is circular, then 'index & desc_count_mask' can be used instead of modulo.
    // * Otherwise, we can't wrap around the list anyway. However, for any index < desc_count, 'index & desc_count_mask'
    //   will return the same value.
    u32                           desc_count_mask;
    u16                           desc_page_size;
    bool                          is_circular;
};

struct hailo_channel_interrupt_timestamp_list {
    int head;
    int tail;
    struct hailo_channel_interrupt_timestamp timestamps[CHANNEL_IRQ_TIMESTAMPS_SIZE];
};


// For each buffers in transfer, the last descriptor will be programmed with
// the residue size. In addition, if configured, the first descriptor (in
// all transfer) may be programmed with interrupts.
#define MAX_DIRTY_DESCRIPTORS_PER_TRANSFER      \
    (HAILO_MAX_BUFFERS_PER_SINGLE_TRANSFER + 1)

struct hailo_vdma_mapped_transfer_buffer {
    struct sg_table *sg_table;
    u32 size;
    u32 offset;
    void *opaque; // Drivers can set any opaque data here.
};

struct hailo_ongoing_transfer {
    uint16_t last_desc;

    u8 buffers_count;
    struct hailo_vdma_mapped_transfer_buffer buffers[HAILO_MAX_BUFFERS_PER_SINGLE_TRANSFER];

    // Contains all descriptors that were programmed with non-default values
    // for the transfer (by non-default we mean - different size or different
    // interrupts domain).
    uint8_t dirty_descs_count;
    uint16_t dirty_descs[MAX_DIRTY_DESCRIPTORS_PER_TRANSFER];

    // If set, validate descriptors status on transfer completion.
    bool is_debug;
};

struct hailo_ongoing_transfers_list {
    unsigned long head;
    unsigned long tail;
    struct hailo_ongoing_transfer transfers[HAILO_VDMA_MAX_ONGOING_TRANSFERS];
};

struct hailo_vdma_channel_state {
    // vdma channel counters. num_avail should be synchronized with the hw
    // num_avail value. num_proc is the last num proc updated when the user
    // reads interrupts.
    u16 num_avail;
    u16 num_proc;

    // Mask of the num-avail/num-proc counters.
    u32 desc_count_mask;
};

struct hailo_vdma_channel {
    u8 index;

    u8 __iomem *host_regs;
    u8 __iomem *device_regs;

    // Last descriptors list attached to the channel. When it changes,
    // assumes that the channel got reset.
    struct hailo_vdma_descriptors_list *last_desc_list;

    struct hailo_vdma_channel_state state;
    struct hailo_ongoing_transfers_list ongoing_transfers;

    bool timestamp_measure_enabled;
    struct hailo_channel_interrupt_timestamp_list timestamp_list;
};

struct hailo_vdma_engine {
    u8 index;
    u64 enabled_channels;
    struct hailo_vdma_channel channels[MAX_VDMA_CHANNELS_PER_ENGINE];
};

struct hailo_vdma_hw_ops {
    u64 channel_id_mask;
    u8 channel_id_shift;
};

struct hailo_vdma_hw {
    struct hailo_vdma_hw_ops hw_ops;

    // The data_id code of ddr addresses.
    u8 ddr_data_id;

    // Bitmask needed to set on each descriptor to enable interrupts (either host/device).
    unsigned long host_interrupts_bitmask;
    unsigned long device_interrupts_bitmask;

    // Bitmask for each vdma hw, which channels are src side by index (on pcie - 0x0..0000FFFF, pci ep - 0x0..FFFF0000)
    // dram[h10h/15x] - 0x0..0000FFFF, dram[h10h2] - 0x0..00FFFFFF
    u64 src_channels_bitmask;
};

#define _for_each_element_array(array, size, element, index) \
    for (index = 0, element = &array[index]; index < size; index++, element = &array[index])

#define for_each_vdma_channel(engine, channel, channel_index) \
    _for_each_element_array((engine)->channels, MAX_VDMA_CHANNELS_PER_ENGINE,   \
        channel, channel_index)

#define MAX_PCIE_VDMA_CHANNELS_PER_ENGINE (32)
#define for_each_pcie_vdma_channel(engine, channel, channel_index) \
    _for_each_element_array((engine)->channels, MAX_PCIE_VDMA_CHANNELS_PER_ENGINE,   \
        channel, channel_index)

int hailo_vdma_program_descriptors_in_chunk(
    dma_addr_t chunk_addr,
    unsigned int chunk_size,
    struct hailo_vdma_descriptors_list *desc_list,
    u32 desc_index,
    u32 max_desc_index,
    u8 data_id,
    u32 stride,
    u64 masked_channel_id);

/**
 * Program the given descriptors list to map the given buffer.
 *
 * @param vdma_hw vdma hw object
 * @param desc_list descriptors list object to program
 * @param starting_desc index of the first descriptor to program. If the list
 *                      is circular, this function may wrap around the list.
 * @param buffer buffer to program to the descriptors list.
 * @param should_bind If false, assumes the buffer was already bound to the
 *                    desc list. Used for optimization.
 * @param channel_index channel index of the channel attached.
 * @param last_desc_interrupts - interrupts settings on last descriptor.
 * @param is_debug program descriptors for debug run.
 * @param stride stride of the buffer - affects the real descriptor program size.
 *               If the stride is 0 (default), the stride is calculated as the desc_page_size.
 *
 * @return On success - the amount of descriptors programmed, negative value on error.
 */
int hailo_vdma_program_descriptors_list(
    struct hailo_vdma_hw *vdma_hw,
    struct hailo_vdma_descriptors_list *desc_list,
    u32 starting_desc,
    struct hailo_vdma_mapped_transfer_buffer *buffer,
    bool should_bind,
    u8 channel_index,
    enum hailo_vdma_interrupts_domain last_desc_interrupts,
    bool is_debug,
    u32 stride);

/**
 * Program the given descriptors list to map a given buffer in a batch pattern.
 *
 * @param vdma_hw vdma hw object
 * @param desc_list descriptors list object to program
 * @param starting_desc index of the first descriptor to program. If the list
 *                     is circular, this function may wrap around the list.
 * @param base_buffer buffer to program to the descriptors list.
 * @param buffer_offset offset in the buffer to start the program from.
 * @param transfer_size size of each transfer in the batch to program.
 * @param batch_size amount of transfers to program.
 * @param should_bind If false, assumes the buffer was already bound to the desc list.
 *                    Used for optimization.
 * @param channel_index channel index of the channel attached.
 * @param last_desc_interrupts - interrupts settings on last descriptor of each transfer.
 * @param is_debug program descriptors for debug run.
 * @param stride stride of the buffer - affects the real descriptor program size.
 *               If the stride is 0 (default), the stride is calculated as the desc_page_size.
 */
int hailo_vdma_program_descriptors_list_batch(
    struct hailo_vdma_hw *vdma_hw,
    struct hailo_vdma_descriptors_list *desc_list,
    u32 starting_desc,
    struct sg_table *base_buffer,
    u32 buffer_offset,
    u32 transfer_size,
    u32 batch_size,
    bool should_bind,
    u8 channel_index,
    enum hailo_vdma_interrupts_domain last_desc_interrupts,
    bool is_debug,
    u32 stride);

void hailo_vdma_set_num_avail(u8 __iomem *regs, u16 num_avail);

u16 hailo_vdma_get_num_proc(u8 __iomem *regs);

/**
 * Launch a transfer on some vdma channel. Includes:
 *      1. Binding the transfer buffers to the descriptors list.
 *      2. Program the descriptors list.
 *      3. Increase num available
 *
 * @param vdma_hw vdma hw object
 * @param channel vdma channel object.
 * @param desc_list descriptors list object to program.
 * @param starting_desc index of the first descriptor to program.
 * @param buffers_count amount of transfer mapped buffers to program.
 * @param buffers array of buffers to program to the descriptors list.
 * @param should_bind whether to bind the buffer to the descriptors list.
 * @param first_interrupts_domain - interrupts settings on first descriptor.
 * @param last_desc_interrupts - interrupts settings on last descriptor.
 * @param is_debug program descriptors for debug run, adds some overhead (for
 *                 example, hw will write desc complete status).
 *
 * @return On success - the amount of descriptors programmed, negative value on error.
 */
int hailo_vdma_launch_transfer(
    struct hailo_vdma_hw *vdma_hw,
    struct hailo_vdma_channel *channel,
    struct hailo_vdma_descriptors_list *desc_list,
    u32 starting_desc,
    u8 buffers_count,
    struct hailo_vdma_mapped_transfer_buffer *buffers,
    bool should_bind,
    enum hailo_vdma_interrupts_domain first_interrupts_domain,
    enum hailo_vdma_interrupts_domain last_desc_interrupts,
    bool is_debug);

void hailo_vdma_engine_init(struct hailo_vdma_engine *engine, u8 engine_index,
    const struct hailo_resource *channel_registers, u64 src_channels_bitmask);

void hailo_vdma_engine_enable_channels(struct hailo_vdma_engine *engine, u64 bitmap,
    bool measure_timestamp);

void hailo_vdma_engine_disable_channels(struct hailo_vdma_engine *engine, u64 bitmap);

void hailo_vdma_engine_push_timestamps(struct hailo_vdma_engine *engine, u64 bitmap);
int hailo_vdma_engine_read_timestamps(struct hailo_vdma_engine *engine,
    struct hailo_vdma_interrupts_read_timestamp_params *params);

typedef void(*transfer_done_cb_t)(struct hailo_ongoing_transfer *transfer, void *opaque);

// Assuming irq_data->channels_count contains the amount of channels already
// written (used for multiple engines).
int hailo_vdma_engine_fill_irq_data(struct hailo_vdma_interrupts_wait_params *irq_data,
    struct hailo_vdma_engine *engine, u64 irq_channels_bitmap, void *transfer_done_opaque);

void transfer_done(struct hailo_ongoing_transfer *transfer, void *opaque);

void hailo_vdma_start_channel(u8 __iomem *regs, uint64_t desc_dma_address, uint32_t desc_count, uint8_t data_id);
void hailo_vdma_stop_channel(u8 __iomem *regs);

bool hailo_check_channel_index(u8 channel_index, u64 src_channels_bitmask, bool is_input_channel);

#ifdef __cplusplus
}
#endif
#endif /* _HAILO_COMMON_VDMA_COMMON_H_ */
