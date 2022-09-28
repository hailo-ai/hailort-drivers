// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/
/**
 * Hailo vdma engine definitions
 */

#ifndef _HAILO_VDMA_VDMA_H_
#define _HAILO_VDMA_VDMA_H_

#include "hailo_ioctl_common.h"
#include "hailo_resource.h"
#include "vdma_common.h"

#include <linux/dma-mapping.h>
#include <linux/types.h>
#include <linux/semaphore.h>

#define VDMA_CHANNEL_CONTROL_REG_OFFSET(channel_index, direction) (((direction) == DMA_TO_DEVICE) ? \
            (((channel_index) << 5) + 0x0) : (((channel_index) << 5) + 0x10))
#define VDMA_CHANNEL_CONTROL_REG_ADDRESS(vdma_registers, channel_index, direction) \
    ((u8*)((vdma_registers)->address) + VDMA_CHANNEL_CONTROL_REG_OFFSET(channel_index, direction))

#define VDMA_CHANNEL_NUM_PROC_OFFSET(channel_index, direction) (((direction) == DMA_TO_DEVICE) ? \
            (((channel_index) << 5) + 0x4) : (((channel_index) << 5) + 0x14))
#define VDMA_CHANNEL_NUM_PROC_ADDRESS(vdma_registers, channel_index, direction) \
    ((u8*)((vdma_registers)->address) + VDMA_CHANNEL_NUM_PROC_OFFSET(channel_index, direction))


struct hailo_vdma_buffer {
    struct list_head            mapped_user_buffer_list;
    void __user                 *user_address;
    size_t                      handle;
    uint32_t                    size;
    enum dma_data_direction     data_direction;
    struct sg_table             sg_table;
    // Can be INVALID_DRIVER_HANDLE_VALUE if the buffer is allocated by the user
    uintptr_t                   driver_buffer_handle;
};

struct hailo_descriptors_list {
    struct list_head            descriptors_buffer_list;
    uintptr_t                   handle;
    void                        *kernel_address;
    dma_addr_t                  dma_address;
    uint32_t                    desc_count;
    uint32_t                    buffer_size;
};

struct hailo_vdma_low_memory_buffer {
    struct list_head                    vdma_low_memory_buffer_list;
    uintptr_t                           handle;
    size_t                              pages_count;
    void                                **pages_address;
};

struct hailo_vdma_continuous_buffer {
    struct list_head    continuous_buffer_list;
    uintptr_t           handle;
    void                *kernel_address;
    dma_addr_t          dma_address;
    size_t              size;
};

struct hailo_vdma_channel {
    // direction of the channel. should be only from_device or to_device
    enum dma_data_direction direction;
    // Unique identifer to the opened channel. The channel is enabled if this value
    // it not INVALID_CHANNEL_HANDLE_VALUE
    u64 handle;
    // called from the interrupt handler to notify that an interrupt was raised
    struct completion completion;

    bool timestamp_measure_enabled;
    struct hailo_channel_interrupt_timestamp_list timestamp_list;

    bool should_abort;
};


struct hailo_vdma_controller;
struct hailo_vdma_controller_ops {
    void (*update_channel_interrupts)(struct hailo_vdma_controller *controller, size_t engine_index,
        uint32_t channels_bitmap);
    uint64_t (*encode_channel_dma_address)(dma_addr_t dma_address, uint8_t channel_id);
    uint64_t (*encode_desc_dma_address)(dma_addr_t dma_address, uint8_t channel_id);
    uint8_t (*get_dma_data_id)(void);
};

struct hailo_vdma_channel_interrupts {
    spinlock_t lock;
    uint32_t channel_data_source;
    uint32_t channel_data_dest;
};

struct hailo_vdma_engine {
    struct hailo_resource channel_registers;
    struct hailo_vdma_channel channels[MAX_VDMA_CHANNELS_PER_ENGINE];
    struct hailo_vdma_channel_interrupts interrupts;
};

struct hailo_vdma_controller {
    struct hailo_vdma_controller_ops *ops;
    struct device *dev;

    size_t vdma_engines_count;
    struct hailo_vdma_engine *vdma_engines;

    atomic64_t last_channel_handle;
    struct file *used_by_filp;
};

struct hailo_vdma_file_context {
    // Amount of engines is in hailo_vdma_controller::vdma_engines_count
    uint32_t enabled_channels_per_engine[MAX_VDMA_ENGINES];

    atomic_t last_vdma_user_buffer_handle;
    struct list_head mapped_user_buffer_list;

    // Last_vdma_handle works as a handle for vdma decriptor list and for the vdma buffer -
    // there will be no collisions between the two
    atomic_t last_vdma_handle;
    struct list_head descriptors_buffer_list;
    struct list_head vdma_low_memory_buffer_list;
    struct list_head continuous_buffer_list;
};


int hailo_vdma_controller_init(struct hailo_vdma_controller *controller,
    struct device *dev, struct hailo_vdma_controller_ops *ops,
    struct hailo_resource *channel_registers_per_engine, size_t engines_count);

void hailo_vdma_file_context_init(struct hailo_vdma_file_context *context);
void hailo_vdma_file_context_finalize(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller, struct file *filp);

void hailo_vdma_irq_handler(struct hailo_vdma_controller *controller, size_t engine_index,
    u32 channel_data_source, u32 channel_data_dest);

// TODO: reduce params count
long hailo_vdma_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned int cmd, unsigned long arg, struct file *filp, struct semaphore *mutex, bool *should_up_board_mutex);

int hailo_vdma_mmap(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    struct vm_area_struct *vma, uintptr_t vdma_handle);

uint8_t hailo_vdma_get_channel_id(uint8_t channel_index);
enum dma_data_direction get_dma_direction(enum hailo_dma_data_direction hailo_direction);

#endif /* _HAILO_VDMA_VDMA_H_ */