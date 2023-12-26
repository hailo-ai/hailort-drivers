// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_COMMON_VDMA_COMMON_H_
#define _HAILO_COMMON_VDMA_COMMON_H_

#include "hailo_resource.h"
#include "utils.h"

#include <linux/types.h>
#include <linux/scatterlist.h>

#define VDMA_DESCRIPTOR_LIST_ALIGN  (1 << 16)
#define INVALID_VDMA_ADDRESS        (0)

#ifdef __cplusplus
extern "C"
{
#endif

struct hailo_vdma_descriptor {
    uint32_t    PageSize_DescControl;
    uint32_t    AddrL_rsvd_DataID;
    uint32_t    AddrH;
    uint32_t    RemainingPageSize_Status;
};

struct hailo_vdma_descriptors_list {
    struct hailo_vdma_descriptor *desc_list;
    uint32_t                      desc_count;  // Must be power of 2 if is_circular is set.
    bool                          is_circular;
};

struct hailo_channel_interrupt_timestamp_list {
    int head;
    int tail;
    struct hailo_channel_interrupt_timestamp timestamps[CHANNEL_IRQ_TIMESTAMPS_SIZE];
};

struct hailo_vdma_channel {
    // direction of the channel. should be only from_device or to_device
    enum hailo_dma_data_direction direction;
    bool timestamp_measure_enabled;
    struct hailo_channel_interrupt_timestamp_list timestamp_list;
};

struct hailo_vdma_engine {
    struct hailo_resource channel_registers;
    u32 enabled_channels;
    u32 interrupted_channels;
    struct hailo_vdma_channel channels[MAX_VDMA_CHANNELS_PER_ENGINE];
};

#define _for_each_element_array(array, size, element, index) \
    for (index = 0, element = &array[index]; index < size; index++, element = &array[index])

#define for_each_vdma_channel(engine, channel, channel_index) \
    _for_each_element_array(engine->channels, MAX_VDMA_CHANNELS_PER_ENGINE,   \
        channel, channel_index)

void hailo_vdma_program_descriptor(struct hailo_vdma_descriptor *descriptor, uint64_t dma_address, size_t page_size,
    uint8_t data_id);

typedef uint64_t (*encode_desc_dma_address_t)(dma_addr_t dma_address, uint8_t channel_id);

int hailo_vdma_program_descriptors_list(
    struct hailo_desc_list_bind_vdma_buffer_params *params,
    struct hailo_vdma_descriptors_list *desc_list,
    struct sg_table *buffer,
    dma_addr_t mmio_dma_address,
    uint32_t size,
    encode_desc_dma_address_t address_encoder,
    uint8_t data_id);

int hailo_vdma_channel_read_register(struct hailo_vdma_channel_read_register_params *params,
    struct hailo_resource *vdma_registers);
int hailo_vdma_channel_write_register(struct hailo_vdma_channel_write_register_params *params,
    struct hailo_resource *vdma_registers);

void hailo_vdma_engine_init(struct hailo_vdma_engine *engine,
    const struct hailo_resource *channel_registers);

// enable/disable channels interrupt (does not update interrupts mask because the
// implementation is different between PCIe and DRAM DMA. To support it we
// can add some ops struct to the engine).
void hailo_vdma_engine_enable_channel_interrupts(struct hailo_vdma_engine *engine, u32 bitmap,
    bool measure_timestamp);
void hailo_vdma_engine_disable_channel_interrupts(struct hailo_vdma_engine *engine, u32 bitmap);

void hailo_vdma_engine_push_timestamps(struct hailo_vdma_engine *engine, u32 bitmap);
int hailo_vdma_engine_read_timestamps(struct hailo_vdma_engine *engine,
    struct hailo_vdma_interrupts_read_timestamp_params *params);

static inline bool hailo_vdma_engine_got_interrupt(struct hailo_vdma_engine *engine,
    u32 channels_bitmap)
{
    // Reading interrupts without lock is ok (needed only for writes)
    const bool any_interrupt = (0 != (channels_bitmap & engine->interrupted_channels));
    const bool any_disabled = (channels_bitmap != (channels_bitmap & engine->enabled_channels));
    return (any_disabled || any_interrupt);
}

// Set/Clear/Read channels interrupts, must called under some lock (driver specific)
void hailo_vdma_engine_clear_channel_interrupts(struct hailo_vdma_engine *engine, u32 bitmap);
void hailo_vdma_engine_set_channel_interrupts(struct hailo_vdma_engine *engine, u32 bitmap);

static inline u32 hailo_vdma_engine_read_interrupts(struct hailo_vdma_engine *engine,
    u32 requested_bitmap)
{
    // Interrupts only for channels that are requested and enabled.
    u32 irq_channels_bitmap = requested_bitmap &
                          engine->enabled_channels &
                          engine->interrupted_channels;
    engine->interrupted_channels &= ~irq_channels_bitmap;

    return irq_channels_bitmap;
}

// Assuming irq_data->channels_count contains the amount of channels already
// written (used for multiple engines).
int hailo_vdma_engine_fill_irq_data(struct hailo_vdma_interrupts_wait_params *irq_data,
    struct hailo_vdma_engine *engine, u8 engine_index, u32 irq_channels_bitmap);

#ifdef __cplusplus
}
#endif
#endif /* _HAILO_COMMON_VDMA_COMMON_H_ */
