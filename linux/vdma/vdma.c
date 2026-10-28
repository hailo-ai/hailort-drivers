// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
 **/

#define pr_fmt(fmt) "hailo: " fmt

#include "vdma.h"
#include "memory.h"
#include "ioctl.h"
#include "logs.h"

#include <linux/sched.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <linux/dma-map-ops.h>
#else
#include <linux/dma-mapping.h>
#endif


static struct hailo_vdma_engine* init_vdma_engines(struct device *dev,
    struct hailo_resource *channel_regs_per_engine, size_t engines_count, enum vdma_engine_variant engine_variant)
{
    int err = 0;
    struct hailo_vdma_engine *engines = NULL;
    u8 i = 0;

    engines = devm_kmalloc_array(dev, engines_count, sizeof(*engines), GFP_KERNEL);
    if (NULL == engines) {
        dev_err(dev, "Failed allocating vdma engines\n");
        return ERR_PTR(-ENOMEM);
    }

    for (i = 0; i < engines_count; i++) {
        err = hailo_vdma_engine_init(&engines[i], i, engine_variant, (void*)channel_regs_per_engine[i].address);
        if (err < 0) {
            dev_err(dev, "Failed to init vDMA engine %d: %d\n", i, err);
            return ERR_PTR(err);
        }
    }

    return engines;
}

static int hailo_set_dma_mask(struct device *dev)
{
    int err = -EINVAL;
    /* Check and configure DMA length */
    if (!(err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64)))) {
        dev_notice(dev, "Probing: Enabled 64 bit dma\n");
    } else if (!(err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(48)))) {
        dev_notice(dev, "Probing: Enabled 48 bit dma\n");
    } else if (!(err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(40)))) {
        dev_notice(dev, "Probing: Enabled 40 bit dma\n");
    } else if (!(err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(36)))) {
        dev_notice(dev, "Probing: Enabled 36 bit dma\n");
    } else if (!(err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32)))) {
        dev_notice(dev, "Probing: Enabled 32 bit dma\n");
    } else {
        dev_err(dev, "Probing: Error enabling dma %d\n", err);
        return err;
    }

    return 0;
}

void hailo_vdma_init_context_channels(struct hailo_vdma_context *context)
{
    u8 engine_idx = 0;

    BUILD_BUG_ON_MSG(MAX_VDMA_CHANNELS_PER_ENGINE > sizeof(context->channels.enabled_bitmap[0]) * BITS_IN_BYTE,
        "Unexpected amount of VDMA channels per engine");

    for (engine_idx = 0; engine_idx < MAX_VDMA_ENGINES; engine_idx++) {
        context->channels.enabled_bitmap[engine_idx] = 0;
        context->channels.interrupted_bitmap[engine_idx] = 0;
    }

    spin_lock_init(&context->channels.lock);
    init_waitqueue_head(&context->channels.interrupts_wq);
}

u64 hailo_vdma_context_get_enabled_channels_bitmap(struct hailo_vdma_context *context, u8 engine_idx)
{
    unsigned long flags = 0;
    u64 bitmap = 0;

    spin_lock_irqsave(&context->channels.lock, flags);
    bitmap = context->channels.enabled_bitmap[engine_idx];
    spin_unlock_irqrestore(&context->channels.lock, flags);

    return bitmap;
}

u64 hailo_vdma_context_get_and_clear_interrupts(struct hailo_vdma_context *context, u8 engine_idx, u64 bitmap)
{
    unsigned long flags = 0;
    u64 irq_bitmap = 0;

    spin_lock_irqsave(&context->channels.lock, flags);
    irq_bitmap = (context->channels.interrupted_bitmap[engine_idx] & bitmap);
    context->channels.interrupted_bitmap[engine_idx] &= ~irq_bitmap;
    spin_unlock_irqrestore(&context->channels.lock, flags);

    return irq_bitmap;
}

void hailo_vdma_context_set_enabled_channels(struct hailo_vdma_context *context, u8 engine_idx, u64 bitmap)
{
    unsigned long flags = 0;

    spin_lock_irqsave(&context->channels.lock, flags);
    context->channels.enabled_bitmap[engine_idx] |= bitmap;
    spin_unlock_irqrestore(&context->channels.lock, flags);
}

void hailo_vdma_context_clear_enabled_channels(struct hailo_vdma_context *context, u8 engine_idx, u64 bitmap)
{
    unsigned long flags = 0;

    spin_lock_irqsave(&context->channels.lock, flags);
    context->channels.enabled_bitmap[engine_idx] &= ~bitmap;
    spin_unlock_irqrestore(&context->channels.lock, flags);

    wake_up_interruptible_all(&context->channels.interrupts_wq);
}

void hailo_vdma_context_set_channel_interrupts(struct hailo_vdma_context *context, u8 engine_idx, u64 bitmap)
{
    u64 enabled_interrupts = 0;
    unsigned long flags = 0;

    spin_lock_irqsave(&context->channels.lock, flags);
    enabled_interrupts = (context->channels.enabled_bitmap[engine_idx] & bitmap);
    context->channels.interrupted_bitmap[engine_idx] |= enabled_interrupts;
    spin_unlock_irqrestore(&context->channels.lock, flags);

    if (enabled_interrupts) {
        wake_up_interruptible_all(&context->channels.interrupts_wq);
    }
}

void hailo_vdma_context_clear_channel_interrupts(struct hailo_vdma_context *context, u8 engine_idx, u64 bitmap)
{
    unsigned long flags = 0;

    spin_lock_irqsave(&context->channels.lock, flags);
    context->channels.interrupted_bitmap[engine_idx] &= ~bitmap;
    spin_unlock_irqrestore(&context->channels.lock, flags);
}

static bool channels_interrupted_or_disabled(struct hailo_vdma_context *context, u64 bitmaps[MAX_VDMA_ENGINES])
{
    u8 engine_idx = 0;
    bool interrupted = false, disabled = false;
    unsigned long flags = 0;

    spin_lock_irqsave(&context->channels.lock, flags);
    for(engine_idx = 0; engine_idx < MAX_VDMA_ENGINES; engine_idx++) {
        interrupted |= (bitmaps[engine_idx] & context->channels.interrupted_bitmap[engine_idx]);
        disabled |= ((bitmaps[engine_idx]) != (bitmaps[engine_idx] & context->channels.enabled_bitmap[engine_idx]));
    }
    spin_unlock_irqrestore(&context->channels.lock, flags);

    return (interrupted || disabled);
}

int hailo_vdma_context_wait_for_interrupt(struct hailo_vdma_context *context, u64 bitmaps[MAX_VDMA_ENGINES])
{
    if (channels_interrupted_or_disabled(context, bitmaps)) {
        return 0;
    }
    return wait_event_interruptible(context->channels.interrupts_wq, channels_interrupted_or_disabled(context, bitmaps));
}

void hailo_vdma_wakeup_interrupts(struct hailo_vdma_controller *controller, u8 engine_index, u64 channels_bitmap)
{
    struct hailo_vdma_context *context = NULL;
    unsigned long flags = 0;

    spin_lock_irqsave(&controller->context_list_lock, flags);
    list_for_each_entry(context, &controller->context_list, context_list) {
        hailo_vdma_context_set_channel_interrupts(context, engine_index, channels_bitmap);
    }
    spin_unlock_irqrestore(&controller->context_list_lock, flags);
}

int hailo_vdma_controller_init(struct hailo_vdma_controller *controller,
    struct device *dev, struct hailo_vdma_hw *vdma_hw,
    struct hailo_vdma_controller_ops *ops,
    struct hailo_resource *channel_registers_per_engine, size_t engines_count)
{
    int err = 0;
    controller->hw = vdma_hw;
    controller->ops = ops;
    controller->dev = dev;

    controller->vdma_engines_count = engines_count;
    controller->vdma_engines = init_vdma_engines(dev, channel_registers_per_engine, engines_count, vdma_hw->variant);
    if (IS_ERR(controller->vdma_engines)) {
        dev_err(dev, "Failed initialized vdma engines\n");
        return PTR_ERR(controller->vdma_engines);
    }

    controller->used_by_filp = NULL;
    atomic64_set(&controller->cma_in_use, 0);
    atomic64_set(&controller->desc_cma_in_use, 0);

    /* Check and configure DMA length */
    err = hailo_set_dma_mask(dev);
    if (0 > err) {
        return err;
    }

    if (get_dma_ops(controller->dev)) {
        hailo_dev_notice(controller->dev, "Probing: Using specialized dma_ops=%ps", get_dma_ops(controller->dev));
    }

    INIT_LIST_HEAD(&controller->context_list);
    spin_lock_init(&controller->context_list_lock);

    hailo_vdma_monitor_init(&controller->monitor);

    return 0;
}

void hailo_vdma_context_init(struct hailo_vdma_context *context, struct hailo_vdma_controller *controller)
{
    unsigned long flags = 0;

    atomic_set(&context->last_vdma_user_buffer_handle, 0);
    INIT_LIST_HEAD(&context->mapped_user_buffer_list);

    xa_init_flags(&context->desc_lists, XA_FLAGS_ALLOC1);
    xa_init_flags(&context->continuous_buffers, XA_FLAGS_ALLOC1);

    hailo_vdma_init_context_channels(context);

    spin_lock_irqsave(&controller->context_list_lock, flags);
    list_add(&context->context_list, &controller->context_list);
    spin_unlock_irqrestore(&controller->context_list_lock, flags);

    context->ctrl = controller;
}

void hailo_vdma_update_interrupts_mask(struct hailo_vdma_controller *controller,
    size_t engine_index)
{
    struct hailo_vdma_engine *engine = &controller->vdma_engines[engine_index];
    controller->ops->update_channel_interrupts(controller, engine_index, engine->enabled_channels);
}

void hailo_vdma_context_finalize(struct hailo_vdma_context *context, struct file *filp)
{
    size_t engine_index = 0;
    struct hailo_vdma_engine *engine = NULL;
    u64 channels_bitmap = 0;
    unsigned long flags = 0;

    spin_lock_irqsave(&context->ctrl->context_list_lock, flags);
    list_del(&context->context_list);
    spin_unlock_irqrestore(&context->ctrl->context_list_lock, flags);

    for_each_vdma_engine(context->ctrl, engine, engine_index) {
        channels_bitmap = hailo_vdma_context_get_enabled_channels_bitmap(context, engine_index);
        if (channels_bitmap) {
            hailo_vdma_disable_channels_per_engine(context, engine_index, channels_bitmap);
        }
    }

    hailo_vdma_clear_mapped_user_buffer_list(context);
    hailo_vdma_clear_desc_lists(context);
    hailo_vdma_clear_continuous_buffers(context);

    xa_destroy(&context->desc_lists);
    xa_destroy(&context->continuous_buffers);

    if (filp == context->ctrl->used_by_filp) {
        context->ctrl->used_by_filp = NULL;
    }

    context->ctrl = NULL;
}

void hailo_vdma_irq_handler(struct hailo_vdma_controller *controller, size_t engine_index, u64 channels_bitmap)
{
    struct hailo_vdma_engine *engine = NULL;

    BUG_ON(engine_index >= controller->vdma_engines_count);
    engine = &controller->vdma_engines[engine_index];

    hailo_vdma_wakeup_interrupts(controller, engine_index, channels_bitmap);
}

void hailo_vdma_disable_channels_per_engine(struct hailo_vdma_context *context, u8 engine_index,
    u64 channels_bitmap)
{
    struct hailo_vdma_engine *engine = &context->ctrl->vdma_engines[engine_index];
    hailo_vdma_engine_release_channels(engine, channels_bitmap);
    hailo_vdma_update_interrupts_mask(context->ctrl, engine_index);
    hailo_vdma_context_clear_channel_interrupts(context, engine_index, channels_bitmap);

    hailo_dev_info(context->ctrl->dev, "Disabled channels for engine %u, bitmap 0x%llx\n",
        engine_index, channels_bitmap);

    hailo_vdma_context_clear_enabled_channels(context, engine_index, channels_bitmap);
}

long hailo_vdma_ioctl(struct hailo_vdma_context *context, unsigned int cmd, unsigned long arg, struct file *filp,
    struct semaphore *mutex, bool *should_up_board_mutex)
{
    switch (cmd) {
    case HAILO_VDMA_ENABLE_CHANNELS:
        return hailo_vdma_enable_channels_ioctl(context, arg);
    case HAILO_VDMA_DISABLE_CHANNELS:
        return hailo_vdma_disable_channels_ioctl(context, arg);
    case HAILO_VDMA_INTERRUPTS_WAIT:
        return hailo_vdma_interrupts_wait_ioctl(context, arg, mutex, should_up_board_mutex);
    case HAILO_VDMA_BUFFER_MAP:
        return hailo_vdma_buffer_map_ioctl(context, arg);
    case HAILO_VDMA_BUFFER_UNMAP:
        return hailo_vdma_buffer_unmap_ioctl(context, arg);
    case HAILO_VDMA_BUFFER_SYNC:
        return hailo_vdma_buffer_sync_ioctl(context, arg);
    case HAILO_DESC_LIST_CREATE:
        return hailo_desc_list_create_ioctl(context, arg);
    case HAILO_DESC_LIST_RELEASE:
        return hailo_desc_list_release_ioctl(context, arg);
    case HAILO_DESC_LIST_PROGRAM:
        return hailo_desc_list_program_ioctl(context, arg);
    case HAILO_MARK_AS_IN_USE:
        return hailo_mark_as_in_use(context->ctrl, arg, filp);
    case HAILO_VDMA_CONTINUOUS_BUFFER_ALLOC:
        return hailo_vdma_continuous_buffer_alloc_ioctl(context, arg);
    case HAILO_VDMA_CONTINUOUS_BUFFER_FREE:
        return hailo_vdma_continuous_buffer_free_ioctl(context, arg);
    case HAILO_VDMA_LAUNCH_TRANSFER:
        return hailo_vdma_launch_transfer_ioctl(context, arg);
    case HAILO_VDMA_PREPARE_TRANSFER:
        return hailo_vdma_prepare_transfer_ioctl(context, arg);
    case HAILO_VDMA_CANCEL_PREPARED_TRANSFER:
        return hailo_vdma_cancel_prepared_transfer_ioctl(context, arg);

    default:
        hailo_dev_err(context->ctrl->dev, "Invalid vDMA ioctl code 0x%x (nr: %d)\n", cmd, _IOC_NR(cmd));
        return -ENOTTY;
    }
}

static int continuous_buffer_mmap(struct hailo_vdma_controller *controller, struct hailo_vdma_buffer *buffer,
    struct vm_area_struct *vma)
{
    int err = 0;
    const unsigned long vsize = vma->vm_end - vma->vm_start;

    if (vsize > buffer->size) {
        hailo_dev_err(controller->dev, "mmap size should be less than %zu (given %lu)\n", buffer->size, vsize);
        return -EINVAL;
    }

    err = dma_mmap_coherent(controller->dev, vma, buffer->kernel_address, buffer->dma_address, vsize);
    if (err < 0) {
        hailo_dev_err(controller->dev, " vdma_mmap failed dma_mmap_coherent %d\n", err);
        return err;
    }

    return 0;
}

int hailo_vdma_mmap(struct hailo_vdma_context *context, struct vm_area_struct *vma, uintptr_t vdma_handle)
{
    struct hailo_vdma_buffer *continuous_buffer = hailo_vdma_get_continuous_buffer(context, vdma_handle);

    if (!continuous_buffer) {
        hailo_dev_err(context->ctrl->dev, "Can't mmap vdma handle: %llu (not existing)\n", (u64)vdma_handle);
        return -EINVAL;
    }

    return continuous_buffer_mmap(context->ctrl, continuous_buffer, vma);
}

enum dma_data_direction get_dma_direction(enum hailo_dma_data_direction hailo_direction)
{
    switch (hailo_direction) {
    case HAILO_DMA_BIDIRECTIONAL:
        return DMA_BIDIRECTIONAL;
    case HAILO_DMA_TO_DEVICE:
        return DMA_TO_DEVICE;
    case HAILO_DMA_FROM_DEVICE:
        return DMA_FROM_DEVICE;
    default:
        pr_err("Invalid hailo direction %d\n", hailo_direction);
        return DMA_NONE;
    }
}
