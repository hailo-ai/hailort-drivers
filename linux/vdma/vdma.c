// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#define pr_fmt(fmt) "hailo: " fmt

#include "vdma.h"
#include "channel.h"
#include "memory.h"
#include "ioctl.h"
#include "utils/logs.h"


void hailo_vdma_controller_init(struct hailo_vdma_controller *controller,
    struct device *dev, struct hailo_resource *vdma_registers, struct hailo_vdma_controller_ops *ops)
{
    int i = 0;

    controller->ops = ops;

    controller->dev = dev;
    controller->registers = *vdma_registers;

    for (i = 0; i < ARRAY_SIZE(controller->channels); ++i) {
        controller->channels[i].handle = INVALID_CHANNEL_HANDLE_VALUE;
        controller->channels[i].direction = DMA_NONE;
        init_completion(&controller->channels[i].completion);
        controller->channels[i].timestamp_measure_enabled = false;
        controller->channels[i].should_abort = false;
    }

    atomic64_set(&controller->last_channel_handle, 0);

    controller->used_by_filp = NULL;

    controller->channels_interrupts.channel_data_dest = 0;
    controller->channels_interrupts.channel_data_source = 0;
    spin_lock_init(&controller->channels_interrupts.lock);
}

void hailo_vdma_file_context_init(struct hailo_vdma_file_context *context)
{
    context->enabled_channels = 0;

    atomic_set(&context->last_vdma_user_buffer_handle, 0);
    INIT_LIST_HEAD(&context->mapped_user_buffer_list);

    atomic_set(&context->last_vdma_handle, 0);
    INIT_LIST_HEAD(&context->descriptors_buffer_list);
    INIT_LIST_HEAD(&context->vdma_low_memory_buffer_list);
    INIT_LIST_HEAD(&context->continuous_buffer_list);
}

void hailo_vdma_file_context_finalize(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller, struct file *filp)
{
    size_t i = 0;

    for (i = 0; i < MAX_VDMA_CHANNELS; ++i) {
        if (test_bit(i, &context->enabled_channels)) {
            hailo_vdma_channel_disable_internal(context, controller, i);
        }
    }

    hailo_vdma_clear_mapped_user_buffer_list(context, controller);
    hailo_vdma_clear_descriptors_buffer_list(context, controller);
    hailo_vdma_clear_low_memory_buffer_list(context);
    hailo_vdma_clear_continuous_buffer_list(context, controller);

    if (filp == controller->used_by_filp) {
        controller->used_by_filp = NULL;
    }
}

void hailo_vdma_irq_handler(struct hailo_vdma_controller *controller,
    u32 channel_data_source, u32 channel_data_dest)
{
    size_t i = 0;
    unsigned long irq_saved_flags = 0;

    for (i = 0; i < ARRAY_SIZE(controller->channels); ++i) {
        if ((test_bit(i, (ulong *)&channel_data_source)) || (test_bit(i, (ulong *)&channel_data_dest))) {
            hailo_vdma_channel_irq_handler(controller, i);
        }
    }

    spin_lock_irqsave(&controller->channels_interrupts.lock, irq_saved_flags);
    controller->channels_interrupts.channel_data_source |= channel_data_source;
    controller->channels_interrupts.channel_data_dest |= channel_data_dest;
    spin_unlock_irqrestore(&controller->channels_interrupts.lock, irq_saved_flags);

    for (i = 0; i < ARRAY_SIZE(controller->channels); ++i) {
        if ((test_bit(i, (ulong *)&channel_data_source)) || (test_bit(i, (ulong *)&channel_data_dest))) {
            complete(&(controller->channels[i].completion));
        }
    }
}

long hailo_vdma_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned int cmd, unsigned long arg, struct file *filp, struct semaphore *mutex, bool *should_up_board_mutex)
{
    switch (cmd) {
    case HAILO_VDMA_CHANNEL_ENABLE:
        return hailo_vdma_channel_enable(context, controller, arg);
    case HAILO_VDMA_CHANNEL_DISABLE:
        return hailo_vdma_channel_disable(context, controller, arg);
    case HAILO_VDMA_CHANNEL_WAIT_INT:
        return hailo_vdma_channel_wait_interrupts_ioctl(controller, arg, mutex, should_up_board_mutex);
    case HAILO_VDMA_BUFFER_MAP:
        return hailo_vdma_buffer_map_ioctl(context, controller, arg);
    case HAILO_VDMA_BUFFER_UNMAP:
        return hailo_vdma_buffer_unmap_ioctl(context, controller, arg);
    case HAILO_VDMA_BUFFER_SYNC:
        return hailo_vdma_buffer_sync(context, controller, arg);
    case HAILO_DESC_LIST_CREATE:
        return hailo_desc_list_create_ioctl(context, controller, arg);
    case HAILO_DESC_LIST_RELEASE:
        return hailo_desc_list_release_ioctl(context, controller, arg);
    case HAILO_DESC_LIST_BIND_VDMA_BUFFER:
        return hailo_desc_list_bind_vdma_buffer(context, controller, arg);
    case HAILO_VDMA_CHANNEL_ABORT:
        return hailo_vdma_channel_abort(controller, arg);
    case HAILO_VDMA_CHANNEL_REGISTERS:
        return hailo_vdma_channel_registers_ioctl(controller, arg);
    case HAILO_VDMA_CHANNEL_CLEAR_ABORT:
        return hailo_vdma_channel_clear_abort(controller, arg);
    case HAILO_VDMA_LOW_MEMORY_BUFFER_ALLOC:
        return hailo_vdma_low_memory_buffer_alloc_ioctl(context, controller, arg);
    case HAILO_VDMA_LOW_MEMORY_BUFFER_FREE:
        return hailo_vdma_low_memory_buffer_free_ioctl(context, controller, arg);
    case HAILO_MARK_AS_IN_USE:
        return hailo_mark_as_in_use(controller, arg, filp);
    case HAILO_VDMA_CONTINUOUS_BUFFER_ALLOC:
        return hailo_vdma_continuous_buffer_alloc_ioctl(context, controller, arg);
    case HAILO_VDMA_CONTINUOUS_BUFFER_FREE:
        return hailo_vdma_continuous_buffer_free_ioctl(context, controller, arg);
    default:
        hailo_dev_err(controller->dev, "Invalid vDMA ioctl code 0x%x (nr: %d)\n", cmd, _IOC_NR(cmd));
        return -ENOTTY;
    }
}

static int desc_list_mmap(struct hailo_vdma_controller *controller,
    struct hailo_descriptors_list *vdma_descriptors_buffer, struct vm_area_struct *vma)
{
    int err = 0;
    unsigned long vsize = vma->vm_end - vma->vm_start;

    if (vsize > vdma_descriptors_buffer->buffer_size) {
        hailo_dev_err(controller->dev, "Requested size to map (%lx) is larger than the descriptor list size(%x)\n",
            vsize, vdma_descriptors_buffer->buffer_size);
        return -EINVAL;
    }

    if (!IS_ENABLED(CONFIG_X86)) { /* for avoiding warnings arch/x86/mm/pat.c */
        err = dma_mmap_coherent(controller->dev, vma, vdma_descriptors_buffer->kernel_address,
            vdma_descriptors_buffer->dma_address, vsize);
        if (err != 0) {
            hailo_dev_err(controller->dev, " vdma_mmap failed dma_mmap_coherent %d\n", err);
            return err;
        }
    } else {
        unsigned long pfn = virt_to_phys(vdma_descriptors_buffer->kernel_address) >> PAGE_SHIFT;
        err = remap_pfn_range(vma, vma->vm_start, pfn, vsize, vma->vm_page_prot);
        if (err != 0) {
            hailo_dev_err(controller->dev, " vdma_mmap failed remap_pfn_range %d\n", err);
            return err;
        }
    }

    return 0;
}

static int low_memory_buffer_mmap(struct hailo_vdma_controller *controller,
    struct hailo_vdma_low_memory_buffer *vdma_buffer, struct vm_area_struct *vma)
{
    int err     = 0;
    size_t i    = 0;
    unsigned long vsize         = vma->vm_end - vma->vm_start;
    unsigned long orig_vm_start = vma->vm_start;
    unsigned long orig_vm_end   = vma->vm_end;
    unsigned long page_fn       = 0;

    if (vsize != vdma_buffer->pages_count * PAGE_SIZE) {
        hailo_dev_err(controller->dev, "mmap size should be %lu (given %lu)\n",
            vdma_buffer->pages_count * PAGE_SIZE, vsize);
        return -EINVAL;
    }

    for (i = 0 ; i < vdma_buffer->pages_count ; i++) {
        if (i > 0) {
            vma->vm_start = vma->vm_end;
        }
        vma->vm_end = vma->vm_start + PAGE_SIZE;

        page_fn = virt_to_phys(vdma_buffer->pages_address[i]) >> PAGE_SHIFT ;
        err = remap_pfn_range(vma, vma->vm_start, page_fn, PAGE_SIZE, vma->vm_page_prot);

        if (err != 0) {
            hailo_dev_err(controller->dev, " fops_mmap failed mapping kernel page %d\n", err);
            return err;
        }
    }

    vma->vm_start = orig_vm_start;
    vma->vm_end = orig_vm_end;

    return 0;
}

static int continuous_buffer_mmap(struct hailo_vdma_controller *controller,
    struct hailo_vdma_continuous_buffer *buffer, struct vm_area_struct *vma)
{
    int err = 0;
    const unsigned long vsize = vma->vm_end - vma->vm_start;

    if (vsize > buffer->size) {
        hailo_dev_err(controller->dev, "mmap size should be less than %zu (given %lu)\n",
            buffer->size, vsize);
        return -EINVAL;
    }

    err = dma_mmap_coherent(controller->dev, vma, buffer->kernel_address,
        buffer->dma_address, vsize);
    if (err < 0) {
        hailo_dev_err(controller->dev, " vdma_mmap failed dma_mmap_coherent %d\n", err);
        return err;
    }

    return 0;
}

int hailo_vdma_mmap(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    struct vm_area_struct *vma, uintptr_t vdma_handle)
{
    struct hailo_descriptors_list *vdma_descriptors_buffer = NULL;
    struct hailo_vdma_low_memory_buffer *low_memory_buffer = NULL;
    struct hailo_vdma_continuous_buffer *continuous_buffer = NULL;

    hailo_dev_info(controller->dev, "Map vdma_handle %llu\n", (uint64_t)vdma_handle);
    if (NULL != (vdma_descriptors_buffer = hailo_vdma_get_descriptors_buffer(context, vdma_handle))) {
        return desc_list_mmap(controller, vdma_descriptors_buffer, vma);
    }
    else if (NULL != (low_memory_buffer = hailo_vdma_get_low_memory_buffer(context, vdma_handle))) {
        return low_memory_buffer_mmap(controller, low_memory_buffer, vma);
    }
    else if (NULL != (continuous_buffer = hailo_vdma_get_continuous_buffer(context, vdma_handle))) {
        return continuous_buffer_mmap(controller, continuous_buffer, vma);
    }
    else {
        hailo_dev_err(controller->dev, "Can't mmap vdma handle: %llu (not existing)\n", (uint64_t)vdma_handle);
        return -EINVAL;
    }
}

uint8_t hailo_vdma_get_channel_id(uint8_t channel_index)
{
    if (channel_index < VDMA_DEST_CHANNELS_START) {
        // H2D channel
        return channel_index;
    }
    else if ((channel_index >= VDMA_DEST_CHANNELS_START) && (channel_index < MAX_VDMA_CHANNELS)) {
        // D2H channel
        return channel_index - VDMA_DEST_CHANNELS_START;
    }
    else {
        return INVALID_VDMA_CHANNEL;
    }
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
