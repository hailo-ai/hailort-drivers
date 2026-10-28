// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
 **/
/**
 * Hailo vdma engine definitions
 */

#ifndef _HAILO_VDMA_VDMA_H_
#define _HAILO_VDMA_VDMA_H_

#include "hailo_ioctl_common.h"
#include "hailo_resource.h"
#include "monitor.h"
#include "vdma_common.h"

#include <linux/dma-mapping.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/dma-buf.h>
#include <linux/version.h>
#include <linux/xarray.h>

#define VDMA_CHANNEL_CONTROL_REG_OFFSET(channel_index, direction) (((direction) == DMA_TO_DEVICE) ? \
            (((channel_index) << 5) + 0x0) : (((channel_index) << 5) + 0x10))
#define VDMA_CHANNEL_CONTROL_REG_ADDRESS(vdma_registers, channel_index, direction) \
    ((u8*)((vdma_registers)->address) + VDMA_CHANNEL_CONTROL_REG_OFFSET(channel_index, direction))

#define VDMA_CHANNEL_NUM_PROC_OFFSET(channel_index, direction) (((direction) == DMA_TO_DEVICE) ? \
            (((channel_index) << 5) + 0x4) : (((channel_index) << 5) + 0x14))
#define VDMA_CHANNEL_NUM_PROC_ADDRESS(vdma_registers, channel_index, direction) \
    ((u8*)((vdma_registers)->address) + VDMA_CHANNEL_NUM_PROC_OFFSET(channel_index, direction))

#define DMA_DIRECTION_EQUALS(curr, other) (curr == DMA_BIDIRECTIONAL || curr == other)

#define for_each_vdma_engine(controller, engine, engine_index)                          \
    _for_each_element_array(controller->vdma_engines, controller->vdma_engines_count,   \
        engine, engine_index)

// dmabuf is supported from linux kernel version 3.3
#if LINUX_VERSION_CODE < KERNEL_VERSION( 3, 3, 0 )
// Make dummy struct with one byte (C standards does not allow empty struct) - in order to not have to ifdef everywhere
struct hailo_dmabuf_info {
    uint8_t dummy;
};
#else
// dmabuf_sg_table is needed because in dma_buf_unmap_attachment() the sg_table's address has to match the
// The one returned from dma_buf_map_attachment() - otherwise we would need to malloc each time
struct hailo_dmabuf_info {
    struct dma_buf *dmabuf;
    struct dma_buf_attachment *dmabuf_attachment;
    struct sg_table *dmabuf_sg_table;
};
#endif // LINUX_VERSION_CODE < KERNEL_VERSION( 3, 3, 0 )

struct hailo_vdma_mapped_buffer {
    struct list_head            mapped_user_buffer_list;
    size_t                      handle;

    struct kref                 kref;
    struct device               *device;

    enum hailo_dma_buffer_type  buffer_type;
    u32                         size;
    uintptr_t                   addr_or_fd;
    enum dma_data_direction     data_direction;

    struct sg_table             sg_table;

    // If this flag is set, the buffer pointed by sg_table is not backed by
    // 'struct page' (only by pure pfn). On this case, accessing to the page,
    // or calling APIs that access the page (e.g. dma_sync_sg_for_cpu) is not
    // allowed.
    bool                        is_mmio;

    // Relevant paramaters that need to be saved in case of dmabuf - otherwise struct pointers will be NULL
    struct hailo_dmabuf_info    dmabuf_info;
};

struct hailo_vdma_controller;
struct hailo_vdma_controller_ops {
    void (*update_channel_interrupts)(struct hailo_vdma_controller *controller, size_t engine_index,
        u64 channels_bitmap);
};

struct hailo_vdma_controller {
    struct hailo_vdma_hw             *hw;
    struct hailo_vdma_controller_ops *ops;
    struct device                    *dev;

    size_t                   vdma_engines_count;
    struct hailo_vdma_engine *vdma_engines;

    struct list_head context_list;
    spinlock_t       context_list_lock;

    struct file *used_by_filp;

    // Total amount of CMA memory allocated by continuous buffer allocations
    atomic64_t cma_in_use;

    // Total amount of CMA memory allocated by descriptor list allocations
    atomic64_t desc_cma_in_use;

    struct hailo_vdma_monitor monitor;
};

struct hailo_vdma_context_channels {
    u64                enabled_bitmap[MAX_VDMA_ENGINES];
    u64                interrupted_bitmap[MAX_VDMA_ENGINES];
    wait_queue_head_t  interrupts_wq;
    spinlock_t         lock;
};

// vDMA state of a single open file.
struct hailo_vdma_context {
    struct list_head context_list;
    // NULL once the context is finalized.
    struct hailo_vdma_controller *ctrl;

    atomic_t last_vdma_user_buffer_handle;
    struct list_head mapped_user_buffer_list;

    struct xarray desc_lists;
    struct xarray continuous_buffers;

    struct hailo_vdma_context_channels channels;
};

void hailo_vdma_init_context_channels(struct hailo_vdma_context *context);

u64 hailo_vdma_context_get_enabled_channels_bitmap(struct hailo_vdma_context *context, u8 engine_idx);
void hailo_vdma_context_set_enabled_channels(struct hailo_vdma_context *context, u8 engine_idx, u64 bitmap);
void hailo_vdma_context_clear_enabled_channels(struct hailo_vdma_context *context, u8 engine_idx, u64 bitmap);

u64 hailo_vdma_context_get_and_clear_interrupts(struct hailo_vdma_context *context, u8 engine_idx, u64 bitmap);
void hailo_vdma_context_set_channel_interrupts(struct hailo_vdma_context *context, u8 engine_idx, u64 bitmap);
void hailo_vdma_context_clear_channel_interrupts(struct hailo_vdma_context *context, u8 engine_idx, u64 bitmap);

int hailo_vdma_context_wait_for_interrupt(struct hailo_vdma_context *context, u64 bitmaps[MAX_VDMA_ENGINES]);

int hailo_vdma_controller_init(struct hailo_vdma_controller *controller,
    struct device *dev, struct hailo_vdma_hw *vdma_hw,
    struct hailo_vdma_controller_ops *ops,
    struct hailo_resource *channel_registers_per_engine, size_t engines_count);
void hailo_vdma_controller_finalize(struct hailo_vdma_controller *controller);

void hailo_vdma_update_interrupts_mask(struct hailo_vdma_controller *controller,
    size_t engine_index);

void hailo_vdma_context_init(struct hailo_vdma_context *context, struct hailo_vdma_controller *controller);
void hailo_vdma_context_finalize(struct hailo_vdma_context *context, struct file *filp);

void hailo_vdma_wakeup_interrupts(struct hailo_vdma_controller *controller, u8 engine_index, u64 channels_bitmap);
void hailo_vdma_irq_handler(struct hailo_vdma_controller *controller, size_t engine_index,
    u64 channels_bitmap);

void hailo_vdma_disable_channels_per_engine(struct hailo_vdma_context *context, u8 engine_index,
    u64 channels_bitmap);

// TODO: reduce params count
long hailo_vdma_ioctl(struct hailo_vdma_context *context, unsigned int cmd, unsigned long arg, struct file *filp,
    struct semaphore *mutex, bool *should_up_board_mutex);

int hailo_vdma_mmap(struct hailo_vdma_context *context, struct vm_area_struct *vma, uintptr_t vdma_handle);

enum dma_data_direction get_dma_direction(enum hailo_dma_data_direction hailo_direction);

#endif /* _HAILO_VDMA_VDMA_H_ */
