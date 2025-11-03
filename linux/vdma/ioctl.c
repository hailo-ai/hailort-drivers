// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include "ioctl.h"
#include "memory.h"
#include "logs.h"
#include "utils.h"

#include <linux/slab.h>
#include <linux/uaccess.h>


long hailo_vdma_enable_channels_ioctl(struct hailo_vdma_controller *controller, unsigned long arg, struct hailo_vdma_file_context *context)
{
    struct hailo_vdma_enable_channels_params input;
    struct hailo_vdma_engine *engine = NULL;
    u8 engine_index = 0;
    u64 channels_bitmap = 0;

    if (copy_from_user(&input, (void *)arg, sizeof(input))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    // Validate params (ignoring engine_index >= controller->vdma_engines_count).
    for_each_vdma_engine(controller, engine, engine_index) {
        channels_bitmap = input.channels_bitmap_per_engine[engine_index];
        if (0 != (channels_bitmap & engine->enabled_channels)) {
            hailo_dev_err(controller->dev, "Trying to enable channels %llx that are already enabled %llx\n",
                channels_bitmap, engine->enabled_channels);
            return -EINVAL;
        }
    }

    for_each_vdma_engine(controller, engine, engine_index) {
        channels_bitmap = input.channels_bitmap_per_engine[engine_index];
        hailo_vdma_engine_enable_channels(engine, channels_bitmap,
            input.enable_timestamps_measure);
        hailo_vdma_update_interrupts_mask(controller, engine_index);
        hailo_dev_info(controller->dev, "Enabled interrupts for engine %u, channels bitmap 0x%llx\n",
            engine_index, channels_bitmap);

        hailo_vdma_context_set_enabled_channels(context, engine_index, channels_bitmap);
    }

    return 0;
}

long hailo_vdma_disable_channels_ioctl(struct hailo_vdma_controller *controller, unsigned long arg, struct hailo_vdma_file_context *context)
{
    struct hailo_vdma_disable_channels_params input;
    struct hailo_vdma_engine *engine = NULL;
    u8 engine_index = 0;
    u64 channels_bitmap = 0;

    if (copy_from_user(&input, (void*)arg, sizeof(input))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    // Validate params (ignoring engine_index >= controller->vdma_engines_count).
    for_each_vdma_engine(controller, engine, engine_index) {
        channels_bitmap = input.channels_bitmap_per_engine[engine_index];
        if (channels_bitmap != (channels_bitmap & engine->enabled_channels)) {
            hailo_dev_warn(controller->dev, "Trying to disable channels that were not enabled\n");
        }
    }

    for_each_vdma_engine(controller, engine, engine_index) {
        channels_bitmap = input.channels_bitmap_per_engine[engine_index];
        hailo_vdma_disable_channels_per_engine(controller, context, engine_index, channels_bitmap);
    }

    return 0;
}

void hailo_vdma_transfer_done(struct device *dev, struct hailo_transfer *transfer)
{
    u8 i = 0;
    for (i = 0; i < transfer->buffers_count; i++) {
        struct hailo_vdma_buffer *mapped_buffer = (struct hailo_vdma_buffer *)transfer->buffers[i].opaque;
        hailo_vdma_buffer_sync(dev, mapped_buffer, HAILO_SYNC_FOR_CPU,
            transfer->buffers[i].offset, transfer->buffers[i].size);
        hailo_vdma_buffer_put(mapped_buffer);
    }
}

long hailo_vdma_interrupts_wait_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg, struct semaphore *mutex, bool *should_up_board_mutex)
{
    long err = 0;
    struct hailo_vdma_interrupts_wait_params params = {0};
    struct hailo_vdma_engine *engine = NULL;
    bool bitmap_not_empty = false;
    u8 engine_index = 0;
    u64 irq_bitmap = 0;

    if (copy_from_user(&params, (void*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "HAILO_VDMA_INTERRUPTS_WAIT, copy_from_user fail\n");
        return -EFAULT;
    }

    // We don't need to validate that channels_bitmap_per_engine are enabled -
    // If the channel is not enabled we just return an empty interrupts list.

    // Validate params (ignoring engine_index >= controller->vdma_engines_count).
    // It us ok to wait on a disabled channel - the wait will just exit.
    for_each_vdma_engine(controller, engine, engine_index) {
        if (0 != params.channels_bitmap_per_engine[engine_index]) {
            bitmap_not_empty = true;
        }
    }
    if (!bitmap_not_empty) {
        hailo_dev_err(controller->dev, "Got an empty bitmap for wait interrupts\n");
        return -EINVAL;
    }

    up(mutex);
    err = hailo_vdma_context_wait_for_interrupt(context, params.channels_bitmap_per_engine);
    if (down_interruptible(mutex)) {
        pr_debug("hailo_vdma_interrupts_wait_ioctl: down_interruptible error (process was interrupted or killed)\n");
        *should_up_board_mutex = false;
        return -ERESTARTSYS;
    }

    if (!context->is_valid) {
        pr_err("hailo_vdma_interrupts_wait_ioctl, context is not valid\n");
        return -ENXIO;
    }

    if (err < 0) {
        hailo_dev_info(controller->dev,
            "wait channel interrupts failed with err=%ld (process was interrupted or killed)\n", err);
        return err;
    }

    params.channels_count = 0;
    for_each_vdma_engine(controller, engine, engine_index) {
        irq_bitmap = hailo_vdma_context_get_and_clear_interrupts(context, engine_index,
            params.channels_bitmap_per_engine[engine_index]);
        err = hailo_vdma_engine_fill_irq_data(controller->dev, &params, engine, irq_bitmap);
        if (err < 0) {
            hailo_dev_err(controller->dev, "Failed fill irq data %ld", err);
            return err;
        }
    }

    if (copy_to_user((void __user*)arg, &params, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        return -EFAULT;
    }

    return 0;
}

static uintptr_t hailo_get_next_vdma_handle(struct hailo_vdma_file_context *context)
{
    // Note: The kernel code left-shifts the 'offset' param from the user-space call to mmap by PAGE_SHIFT bits and
    // stores the result in 'vm_area_struct.vm_pgoff'. We pass the desc_handle to mmap in the offset param. To
    // counter this, we right-shift the desc_handle. See also 'mmap function'.
    uintptr_t next_handle = 0;
    next_handle = atomic_inc_return(&context->last_vdma_handle);
    return (next_handle << PAGE_SHIFT);
}

static struct hailo_vdma_buffer* get_or_map_buffer(
    struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller,
    struct hailo_vdma_transfer_buffer buffer,
    enum dma_data_direction direction)
{
    struct hailo_vdma_buffer *mapped_buffer = NULL;

    switch (buffer.buffer_type) {
    case HAILO_DMA_USER_PTR_BUFFER:
        hailo_dev_dbg(controller->dev, "mapping user-ptr buffer\n");
        mapped_buffer = hailo_vdma_find_mapped_buffer_by_address(context, buffer.addr_or_fd, buffer.size, direction);
        break;

    case HAILO_DMA_DMABUF_BUFFER:
        hailo_dev_dbg(controller->dev, "mapping dmabuf buffer\n");
        mapped_buffer = hailo_vdma_find_mapped_buffer_by_fd(context, buffer.addr_or_fd, buffer.size, direction);
        break;

    default:
        hailo_dev_err(controller->dev, "invalid user buffer type\n");
        return ERR_PTR(-EINVAL);
    }

    if (NULL == mapped_buffer) {
        // No buffer found: map a new one and add to list.
        mapped_buffer = hailo_vdma_buffer_map(controller->dev,
            buffer.addr_or_fd, buffer.size, direction, buffer.buffer_type);
        if (IS_ERR(mapped_buffer)) {
            if (PTR_ERR(mapped_buffer) != -EINTR) {
                hailo_dev_err(controller->dev, "failed map buffer %lx\n", buffer.addr_or_fd);
            }
            return mapped_buffer;
        }

        mapped_buffer->handle = atomic_inc_return(&context->last_vdma_user_buffer_handle);
        list_add(&mapped_buffer->mapped_user_buffer_list, &context->mapped_user_buffer_list);
        hailo_dev_dbg(controller->dev, "buffer %lx (handle %zu) is mapped\n", buffer.addr_or_fd, mapped_buffer->handle);
    } else {
        // Buffer found: incref.
        hailo_vdma_buffer_get(mapped_buffer);
    }

    return mapped_buffer;
}

static struct hailo_vdma_buffer* find_buffer(struct hailo_vdma_file_context *context,
                                             struct hailo_vdma_buffer_params params,
                                             enum dma_data_direction direction)
{
    return (HAILO_DMA_USER_PTR_BUFFER == params.type) ?
        hailo_vdma_find_mapped_buffer_by_exact_address(context, params.addr_or_fd, params.size, direction) :
        hailo_vdma_find_mapped_buffer_by_fd(context, params.addr_or_fd, params.size, direction);
}

long hailo_vdma_buffer_map_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_vdma_buffer_params params;
    struct hailo_vdma_buffer *buffer = NULL;
    enum dma_data_direction direction = DMA_NONE;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy from user fail\n");
        return -EFAULT;
    }

    direction = get_dma_direction(params.direction);
    if (DMA_NONE == direction) {
        hailo_dev_err(controller->dev, "invalid data direction %d\n", params.direction);
        return -EINVAL;
    }
    if (params.type >= HAILO_DMA_BUFFER_MAX_ENUM) {
        hailo_dev_err(controller->dev, "invalid buffer type %d\n", params.direction);
        return -EINVAL;
    }

    hailo_dev_dbg(controller->dev, "mapping buffer <0x%lx + 0x%lx> tgid: %u\n",
                  params.addr_or_fd, params.size, current->tgid);

    buffer = find_buffer(context, params, direction);
    if (NULL != buffer) {
        // Buffer has already been mapped: inc-ref and return.
        // TODO: may be wise to return an error here instead?
        hailo_vdma_buffer_get(buffer);
    } else {
        // Buffer not found: map a new one.
        // TODO: HRT-17044: investigate why using get_or_map_buffer here causes issues
        buffer = hailo_vdma_buffer_map(controller->dev, params.addr_or_fd, params.size, direction, params.type);
        if (IS_ERR(buffer)) {
            if (PTR_ERR(buffer) != -EINTR) {
                hailo_dev_err(controller->dev, "failed map buffer %lx\n", params.addr_or_fd);
            }
            return PTR_ERR(buffer);
        }
        buffer->handle = atomic_inc_return(&context->last_vdma_user_buffer_handle);
        list_add(&buffer->mapped_user_buffer_list, &context->mapped_user_buffer_list);
    }

    params.mapped_handle = buffer->handle;
    if (copy_to_user((void __user*)arg, &params, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        hailo_vdma_buffer_put(buffer);
        return -EFAULT;
    }

    return 0;
}

long hailo_vdma_buffer_unmap_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_vdma_buffer_params params;
    struct hailo_vdma_buffer *buffer = NULL;
    enum dma_data_direction direction = DMA_NONE;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy from user fail\n");
        return -EFAULT;
    }

    direction = get_dma_direction(params.direction);
    if (DMA_NONE == direction) {
        hailo_dev_err(controller->dev, "invalid data direction %d\n", params.direction);
        return -EINVAL;
    }
    if (params.type >= HAILO_DMA_BUFFER_MAX_ENUM) {
        hailo_dev_err(controller->dev, "invalid buffer type %d\n", params.direction);
        return -EINVAL;
    }

    hailo_dev_dbg(controller->dev, "unmap user buffer <0x%lx + 0x%lx>\n", params.addr_or_fd, params.size);

    buffer = find_buffer(context, params, direction);
    if (NULL == buffer) {
        hailo_dev_warn(controller->dev, "buffer <0x%lx + 0x%lx> not found\n", params.addr_or_fd, params.size);
        return -EINVAL;
    }

    hailo_vdma_buffer_put(buffer);

    return 0;
}

long hailo_vdma_buffer_sync_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_buffer_sync_params sync_info = {};
    struct hailo_vdma_buffer *mapped_buffer = NULL;

    if (copy_from_user(&sync_info, (void __user*)arg, sizeof(sync_info))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    if (!(mapped_buffer = hailo_vdma_find_mapped_buffer_by_handle(context, sync_info.handle))) {
        hailo_dev_err(controller->dev, "buffer handle %zu doesn't exist\n", sync_info.handle);
        return -EINVAL;
    }

    if ((sync_info.sync_type != HAILO_SYNC_FOR_CPU) && (sync_info.sync_type != HAILO_SYNC_FOR_DEVICE)) {
        hailo_dev_err(controller->dev, "Invalid sync_type given for vdma buffer sync.\n");
        return -EINVAL;
    }

    if (sync_info.offset + sync_info.count > mapped_buffer->size) {
        hailo_dev_err(controller->dev, "Invalid offset/count given for vdma buffer sync. offset %zu count %zu buffer size %u\n",
            sync_info.offset, sync_info.count, mapped_buffer->size);
        return -EINVAL;
    }

    hailo_vdma_buffer_sync(controller->dev, mapped_buffer, sync_info.sync_type,
        sync_info.offset, sync_info.count);
    return 0;
}

long hailo_desc_list_create_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_desc_list_create_params params;
    struct hailo_descriptors_list_buffer *descriptors_buffer = NULL;
    uintptr_t next_handle = 0;
    long err = -EINVAL;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    if (params.is_circular && !is_powerof2(params.desc_count)) {
        hailo_dev_err(controller->dev, "Invalid desc count given : %zu , circular descriptors count must be power of 2\n",
            params.desc_count);
        return -EINVAL;
    }

    if (!is_powerof2(params.desc_page_size)) {
        hailo_dev_err(controller->dev, "Invalid desc page size given : %u\n",
            params.desc_page_size);
        return -EINVAL;
    }

    hailo_dev_info(controller->dev,
        "Create desc list desc_count: %zu desc_page_size: %u\n",
        params.desc_count, params.desc_page_size);

    descriptors_buffer = kzalloc(sizeof(*descriptors_buffer), GFP_KERNEL);
    if (NULL == descriptors_buffer) {
        hailo_dev_err(controller->dev, "Failed to allocate buffer for descriptors list struct\n");
        return -ENOMEM;
    }

    next_handle = hailo_get_next_vdma_handle(context);

    err = hailo_desc_list_create(controller->dev, params.desc_count,
        params.desc_page_size, next_handle, params.is_circular,
        descriptors_buffer);
    if (err < 0) {
        hailo_dev_err(controller->dev, "failed to allocate descriptors buffer\n");
        kfree(descriptors_buffer);
        return err;
    }

    atomic64_add(descriptors_buffer->buffer_size, &controller->desc_cma_in_use);

    list_add(&descriptors_buffer->descriptors_buffer_list, &context->descriptors_buffer_list);

    // Note: The physical address is required for CONTEXT_SWITCH firmware controls
    BUILD_BUG_ON(sizeof(params.dma_address) < sizeof(descriptors_buffer->dma_address));
    params.dma_address = descriptors_buffer->dma_address;
    params.desc_handle = descriptors_buffer->handle;

    if (copy_to_user((void __user*)arg, &params, sizeof(params))){
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        list_del(&descriptors_buffer->descriptors_buffer_list);
        atomic64_sub(descriptors_buffer->buffer_size, &controller->desc_cma_in_use);
        hailo_desc_list_release(controller->dev, descriptors_buffer);
        kfree(descriptors_buffer);
        return -EFAULT;
    }

    hailo_dev_info(controller->dev, "Created desc list, handle 0x%llu\n",
        (u64)params.desc_handle);
    return 0;
}

long hailo_desc_list_release_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_desc_list_release_params params;
    struct hailo_descriptors_list_buffer *descriptors_buffer = NULL;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    descriptors_buffer = hailo_vdma_find_descriptors_buffer(context, params.desc_handle);
    if (descriptors_buffer == NULL) {
        hailo_dev_warn(controller->dev, "not found desc handle %llu\n", (unsigned long long)params.desc_handle);
        return -EINVAL;
    }

    list_del(&descriptors_buffer->descriptors_buffer_list);
    atomic64_sub(descriptors_buffer->buffer_size, &controller->desc_cma_in_use);
    hailo_desc_list_release(controller->dev, descriptors_buffer);
    kfree(descriptors_buffer);
    return 0;
}

long hailo_desc_list_program_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_desc_list_program_params configure_info;
    struct hailo_vdma_buffer *mapped_buffer = NULL;
    struct hailo_descriptors_list_buffer *descriptors_buffer = NULL;

    if (copy_from_user(&configure_info, (void __user*)arg, sizeof(configure_info))) {
        hailo_dev_err(controller->dev, "copy from user fail\n");
        return -EFAULT;
    }
    hailo_dev_info(controller->dev, "config buffer_handle=%zu desc_handle=%llu starting_desc=%u\n",
        configure_info.buffer_handle, (u64)configure_info.desc_handle, configure_info.starting_desc);

    mapped_buffer = hailo_vdma_find_mapped_buffer_by_handle(context, configure_info.buffer_handle);
    descriptors_buffer = hailo_vdma_find_descriptors_buffer(context, configure_info.desc_handle);
    if (mapped_buffer == NULL || descriptors_buffer == NULL) {
        hailo_dev_err(controller->dev, "invalid user/descriptors buffer\n");
        return -EINVAL;
    }

    return hailo_vdma_program_descriptors_list(
        controller->hw,
        &descriptors_buffer->desc_list,
        configure_info.starting_desc,
        &mapped_buffer->sg_table,
        configure_info.buffer_offset,
        configure_info.transfer_size,
        configure_info.transfers_count,
        configure_info.channel_index,
        configure_info.last_interrupts_domain,
        configure_info.is_debug
    );
}

long hailo_mark_as_in_use(struct hailo_vdma_controller *controller, unsigned long arg, struct file *filp)
{
    struct hailo_mark_as_in_use_params params = {0};

    // If device is used by this FD, return false to indicate its free for usage
    if (filp == controller->used_by_filp) {
        params.in_use = false;
    } else if (NULL != controller->used_by_filp) {
        params.in_use = true;
    } else {
        controller->used_by_filp = filp;
        params.in_use = false;
    }

    if (copy_to_user((void __user*)arg, &params, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        return -EFAULT;
    }

    return 0;
}

long hailo_vdma_continuous_buffer_alloc_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_allocate_continuous_buffer_params buf_info = {0};
    struct hailo_vdma_continuous_buffer *continuous_buffer = NULL;
    long err = -EINVAL;
    size_t aligned_buffer_size = 0;

    if (copy_from_user(&buf_info, (void __user*)arg, sizeof(buf_info))) {
        hailo_dev_err(controller->dev, "copy from user fail\n");
        return -EFAULT;
    }

    continuous_buffer = kzalloc(sizeof(*continuous_buffer), GFP_KERNEL);
    if (NULL == continuous_buffer) {
        hailo_dev_err(controller->dev, "memory alloc failed\n");
        return -ENOMEM;
    }

    // We use PAGE_ALIGN to support mmap
    aligned_buffer_size = PAGE_ALIGN(buf_info.buffer_size);
    err = hailo_vdma_continuous_buffer_alloc(controller->dev, aligned_buffer_size, continuous_buffer);
    if (err < 0) {
        kfree(continuous_buffer);
        return err;
    }

    atomic64_add(aligned_buffer_size, &controller->cma_in_use);

    continuous_buffer->handle = hailo_get_next_vdma_handle(context);
    list_add(&continuous_buffer->continuous_buffer_list, &context->continuous_buffer_list);

    buf_info.buffer_handle = continuous_buffer->handle;
    buf_info.dma_address = continuous_buffer->dma_address;
    if (copy_to_user((void __user*)arg, &buf_info, sizeof(buf_info))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        list_del(&continuous_buffer->continuous_buffer_list);
        atomic64_sub(aligned_buffer_size, &controller->cma_in_use);
        hailo_vdma_continuous_buffer_free(controller->dev, continuous_buffer);
        kfree(continuous_buffer);
        return -EFAULT;
    }

    return 0;
}

long hailo_vdma_continuous_buffer_free_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_free_continuous_buffer_params params;
    struct hailo_vdma_continuous_buffer *continuous_buffer = NULL;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy from user fail\n");
        return -EFAULT;
    }

    continuous_buffer = hailo_vdma_find_continuous_buffer(context, params.buffer_handle);
    if (NULL == continuous_buffer) {
        hailo_dev_warn(controller->dev, "vdma buffer handle %lx not found\n", params.buffer_handle);
        return -EINVAL;
    }

    list_del(&continuous_buffer->continuous_buffer_list);
    atomic64_sub(continuous_buffer->size, &controller->cma_in_use);
    hailo_vdma_continuous_buffer_free(controller->dev, continuous_buffer);
    kfree(continuous_buffer);
    return 0;
}

long hailo_vdma_interrupts_read_timestamps_ioctl(struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_interrupts_read_timestamp_params *params = &controller->read_interrupt_timestamps_params;
    struct hailo_vdma_engine *engine = NULL;
    int err = -EINVAL;

    hailo_dev_dbg(controller->dev, "Start read interrupt timestamps ioctl\n");

    if (copy_from_user(params, (void __user*)arg, sizeof(*params))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    if (params->engine_index >= controller->vdma_engines_count) {
        hailo_dev_err(controller->dev, "Invalid engine %u", params->engine_index);
        return -EINVAL;
    }
    engine = &controller->vdma_engines[params->engine_index];

    err = hailo_vdma_engine_read_timestamps(engine, params);
    if (err < 0) {
        hailo_dev_err(controller->dev, "Failed read engine interrupts for %u:%u",
            params->engine_index, params->channel_index);
        return err;
    }

    if (copy_to_user((void __user*)arg, params, sizeof(*params))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        return -EFAULT;
    }

    return 0;
}

static long hailo_prepare_transfer(struct hailo_vdma_controller *controller, struct hailo_vdma_file_context *context,
    struct hailo_vdma_prepare_transfer_params *params, struct hailo_vdma_descriptors_list *desc_list,
    struct hailo_transfer *prepare_transfer, bool is_cyclic)
{
    u8 i = 0;
    u8 j = 0;
    int ret = 0;
    enum dma_data_direction direction = DMA_NONE;

    if (params->buffers_count > ARRAY_SIZE(params->buffers)) {
        hailo_dev_err(controller->dev, "too many buffers %u\n", params->buffers_count);
        return -EINVAL;
    }

    direction = hailo_test_bit_64(params->channel_index, &controller->hw->src_channels_bitmask) ?
        DMA_TO_DEVICE : DMA_FROM_DEVICE;

    for (i = 0; i < params->buffers_count; i++) {
        u32 offset_from_map = 0;
        struct hailo_vdma_buffer *mapped_buffer;
        if (params->buffers[i].addr_or_fd == 0 || params->buffers[i].size == 0) {
            hailo_dev_err(controller->dev, "Invalid buffer %u, addr_or_fd: %lx, size: %u\n",
                i, params->buffers[i].addr_or_fd, params->buffers[i].size);
            return -EINVAL;
        }

        mapped_buffer = get_or_map_buffer(context, controller, params->buffers[i], direction);
        if (IS_ERR(mapped_buffer)) {
            if (PTR_ERR(mapped_buffer) != -EINTR) {
                hailo_dev_err(controller->dev, "failed get or map buffer %lx\n", params->buffers[i].addr_or_fd);
                //unmap previous mapped buffers
                for (j = 0; j < i; j++) {
                    hailo_vdma_buffer_put(prepare_transfer->buffers[j].opaque);
                }
            }
            return PTR_ERR(mapped_buffer);
        }

        if (HAILO_DMA_USER_PTR_BUFFER == mapped_buffer->buffer_type) {
            offset_from_map = (u32)(params->buffers[i].addr_or_fd - mapped_buffer->addr_or_fd);

            // Syncing the buffer to device change its ownership from host to the device.
            // We sync on D2H as well if the user owns the buffer since the buffer might have been changed by
            // the host between the time it was mapped and the current async transfer.
            hailo_vdma_buffer_sync(controller->dev, mapped_buffer, HAILO_SYNC_FOR_DEVICE,
                offset_from_map, params->buffers[i].size);
        }

        prepare_transfer->buffers[i].sg_table = &mapped_buffer->sg_table;
        prepare_transfer->buffers[i].size = params->buffers[i].size;
        prepare_transfer->buffers[i].offset = offset_from_map;
        prepare_transfer->buffers[i].opaque = mapped_buffer;
    }
    prepare_transfer->buffers_count = params->buffers_count;
    ret = hailo_vdma_prepare_transfer(
        controller->hw,
        params->channel_index,
        desc_list,
        params->buffers_count,
        params->first_interrupts_domain,
        params->last_interrupts_domain,
        params->is_debug,
        prepare_transfer,
        is_cyclic);


    if (ret < 0) {
        // Usually buffer_put() is called in hailo_vdma_transfer_done().
        // If we got an error, then we release the buffers here
        // instead for proper cleanup.
        hailo_vdma_transfer_done(controller->dev, prepare_transfer);
    }
    return ret;
}

long hailo_vdma_prepare_transfer_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_vdma_prepare_transfer_params params;
    struct hailo_transfer prepared_transfer = {0};
    struct hailo_descriptors_list_buffer *descriptors_buffer = NULL;
    int ret = 0;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy from user fail\n");
        return -EFAULT;
    }

    descriptors_buffer = hailo_vdma_find_descriptors_buffer(context, params.desc_handle);
    if (NULL == descriptors_buffer) {
        hailo_dev_err(controller->dev, "invalid descriptors list handle\n");
        return -EFAULT;
    }

    ret = hailo_prepare_transfer(controller,context, &params, &descriptors_buffer->desc_list, &prepared_transfer, false);
    if (ret < 0) {
        hailo_dev_err(controller->dev, "Failed to prepare transfer\n");
        return ret;
    }

    ret = hailo_vdma_transfer_push(&descriptors_buffer->desc_list.prepared_transfers, &prepared_transfer);
    if (ret < 0) {
        hailo_dev_err(controller->dev, "Failed to push prepared transfer to list\n");
        hailo_vdma_transfer_done(controller->dev, &prepared_transfer);
        return ret;
    }
    return ret;
}

long hailo_vdma_cancel_prepared_transfer_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_descriptors_list_buffer *descriptors_buffer = NULL;
    struct hailo_vdma_cancel_prepared_transfer_params params;

    if (copy_from_user(&params, (void *)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -ENOMEM;
    }

    descriptors_buffer = hailo_vdma_find_descriptors_buffer(context, params.desc_handle);
    if (NULL == descriptors_buffer) {
        hailo_dev_err(controller->dev, "Descriptors buffer not found for handle %llu\n", (u64)params.desc_handle);
        return -EINVAL;
    }
    hailo_vdma_cancel_prepared_transfer(controller->dev, &descriptors_buffer->desc_list);

    return 0;
}

long hailo_vdma_launch_transfer_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_vdma_launch_transfer_params params;
    struct hailo_vdma_engine *engine = NULL;
    struct hailo_vdma_channel *channel = NULL;
    struct hailo_descriptors_list_buffer *descriptors_buffer = NULL;
    struct hailo_transfer prepared_transfer = {0};
    int ret = 0;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy from user fail\n");
        return -EFAULT;
    }

    if (params.engine_index >= controller->vdma_engines_count) {
        hailo_dev_err(controller->dev, "Invalid engine %u", params.engine_index);
        return -EINVAL;
    }
    engine = &controller->vdma_engines[params.engine_index];

    if (params.prepare_transfer_params.channel_index >= ARRAY_SIZE(engine->channels)) {
        hailo_dev_err(controller->dev, "Invalid channel %u", params.prepare_transfer_params.channel_index);
        return -EINVAL;
    }
    channel = &engine->channels[params.prepare_transfer_params.channel_index];

    if (params.prepare_transfer_params.buffers_count > ARRAY_SIZE(params.prepare_transfer_params.buffers)) {
        hailo_dev_err(controller->dev, "too many buffers %u\n", params.prepare_transfer_params.buffers_count);
        return -EINVAL;
    }

    descriptors_buffer = hailo_vdma_find_descriptors_buffer(context, params.prepare_transfer_params.desc_handle);
    if (NULL == descriptors_buffer) {
        hailo_dev_err(controller->dev, "invalid descriptors list handle\n");
        return -EINVAL;
    }
  
    if (descriptors_buffer->desc_list.prepared_transfers && TRANSFERS_CIRC_CNT(*descriptors_buffer->desc_list.prepared_transfers) > 0) {
        ret = hailo_vdma_transfer_pop(&descriptors_buffer->desc_list.prepared_transfers, &prepared_transfer);
        if ( ret < 0) {
            hailo_dev_err(controller->dev, "Failed to pop ongoing transfer from list\n");
            return ret;
        }
    }
    else {
        ret = hailo_prepare_transfer(controller, context, &params.prepare_transfer_params, &descriptors_buffer->desc_list, &prepared_transfer, params.is_cyclic);
        if (ret < 0) {
            if (ret != -EINTR) {
                hailo_dev_err(controller->dev, "Failed to prepare transfer\n");
            }
            return ret;
        }
    }

    ret = hailo_vdma_launch_transfer(
        channel,
        &descriptors_buffer->desc_list,
        &prepared_transfer);

    if (ret < 0) {
        // Usually buffer_put() is called in hailo_vdma_transfer_done().
        // If we got an error, then we release the buffers here
        // instead for proper cleanup.
        hailo_vdma_transfer_done(controller->dev, &prepared_transfer);
    }
    return ret;
}
