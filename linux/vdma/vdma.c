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

// Currently we support only one vdma engine
#define VDMA_ENGINES_COUNT (1)


static void init_single_vdma_engine(struct hailo_vdma_engine *engine,
    struct hailo_resource *channel_registers)
{
    int i = 0;

    engine->channel_registers = *channel_registers;

    for (i = 0; i < ARRAY_SIZE(engine->channels); ++i) {
        engine->channels[i].handle = INVALID_CHANNEL_HANDLE_VALUE;
        engine->channels[i].direction = DMA_NONE;
        init_completion(&engine->channels[i].completion);
        engine->channels[i].timestamp_measure_enabled = false;
        engine->channels[i].should_abort = false;
    }

    engine->interrupts.channel_data_dest = 0;
    engine->interrupts.channel_data_source = 0;
    spin_lock_init(&engine->interrupts.lock);
}

static struct hailo_vdma_engine* init_vdma_engines(struct device *dev,
    struct hailo_resource *channel_registers_per_engine, size_t engines_count)
{
    struct hailo_vdma_engine *engines = NULL;
    int i = 0;

    engines = devm_kmalloc_array(dev, engines_count, sizeof(*engines), GFP_KERNEL);
    if (NULL == engines) {
        dev_err(dev, "Failed allocating vdma engines\n");
        return ERR_PTR(-ENOMEM);
    }

    for (i = 0; i < engines_count; i++) {
        init_single_vdma_engine(&engines[i], &channel_registers_per_engine[i]);
    }

    return engines;
}

int hailo_vdma_controller_init(struct hailo_vdma_controller *controller,
    struct device *dev, struct hailo_vdma_controller_ops *ops,
    struct hailo_resource *channel_registers_per_engine, size_t engines_count)
{
    controller->ops = ops;
    controller->dev = dev;

    controller->vdma_engines_count = engines_count;
    controller->vdma_engines = init_vdma_engines(dev, channel_registers_per_engine, engines_count);
    if (IS_ERR(controller->vdma_engines)) {
        dev_err(dev, "Failed initialized vdma engines\n");
        return PTR_ERR(controller->vdma_engines);
    }

    atomic64_set(&controller->last_channel_handle, 0);
    controller->used_by_filp = NULL;
    return 0;
}

void hailo_vdma_file_context_init(struct hailo_vdma_file_context *context)
{
    int i = 0;
    for (i = 0; i < ARRAY_SIZE(context->enabled_channels_per_engine); i++) {
        context->enabled_channels_per_engine[i] = 0;
    }

    atomic_set(&context->last_vdma_user_buffer_handle, 0);
    INIT_LIST_HEAD(&context->mapped_user_buffer_list);

    atomic_set(&context->last_vdma_handle, 0);
    INIT_LIST_HEAD(&context->descriptors_buffer_list);
    INIT_LIST_HEAD(&context->vdma_low_memory_buffer_list);
    INIT_LIST_HEAD(&context->continuous_buffer_list);
}

static void disable_channels_per_engine(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller, size_t engine_index)
{
    static const bool STOP_CHANNEL = true;
    u32 channel_index = 0;
    for (channel_index = 0; channel_index < MAX_VDMA_CHANNELS_PER_ENGINE; channel_index++) {
        // We'll stop the channels here, in case they weren't stopped by the fw
        hailo_vdma_channel_disable_internal(context, controller, engine_index, channel_index, STOP_CHANNEL);
    }
}

void hailo_vdma_file_context_finalize(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller, struct file *filp)
{
    size_t engine_index = 0;

    // TODO: Use controller->used_by_filp to guard creation of vdma resources (or at least vdma channels).
    //       Currently we can guarantee that only one filp has access to vdma resources  
    //       due to user-mode flow in libhailort (HRT-8490)
    if (filp == controller->used_by_filp) {
        // If the current filp isn't marked as the "vdma user" (via used_by_filp), we won't close the vdma channels
        for (engine_index = 0; engine_index < controller->vdma_engines_count; engine_index++) {
            disable_channels_per_engine(context, controller, engine_index);
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
    size_t engine_index, u32 channel_data_source, u32 channel_data_dest)
{
    size_t i = 0;
    unsigned long irq_saved_flags = 0;
    struct hailo_vdma_engine *engine = NULL;

    BUG_ON(engine_index >= controller->vdma_engines_count);
    engine = &controller->vdma_engines[engine_index];

    for (i = 0; i < ARRAY_SIZE(engine->channels); ++i) {
        if ((hailo_test_bit(i, &channel_data_source)) || (hailo_test_bit(i, &channel_data_dest))) {
            hailo_vdma_channel_irq_handler(controller, engine_index, i);
        }
    }

    spin_lock_irqsave(&engine->interrupts.lock, irq_saved_flags);
    engine->interrupts.channel_data_source |= channel_data_source;
    engine->interrupts.channel_data_dest |= channel_data_dest;
    spin_unlock_irqrestore(&engine->interrupts.lock, irq_saved_flags);

    for (i = 0; i < ARRAY_SIZE(engine->channels); ++i) {
        if ((hailo_test_bit(i, &channel_data_source)) || (hailo_test_bit(i, &channel_data_dest))) {
            complete_all(&(engine->channels[i].completion));
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
    case HAILO_VDMA_CHANNEL_READ_REGISTER:
        return hailo_vdma_channel_read_register_ioctl(controller, arg);
    case HAILO_VDMA_CHANNEL_WRITE_REGISTER:
        return hailo_vdma_channel_write_register_ioctl(controller, arg);
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
    else if ((channel_index >= VDMA_DEST_CHANNELS_START) && 
             (channel_index < MAX_VDMA_CHANNELS_PER_ENGINE)) {
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
