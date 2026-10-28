// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
 **/

#include "ioctl.h"
#include "memory.h"
#include "logs.h"
#include "utils.h"

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/nospec.h>


long hailo_vdma_enable_channels_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    struct hailo_vdma_enable_channels_params input;
    struct hailo_vdma_engine *engine = NULL;
    u8 engine_index = 0;
    u64 channels_bitmap = 0;

    if (copy_from_user(&input, (void __user *)arg, sizeof(input))) {
        hailo_dev_err(context->ctrl->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    // Validate params (ignoring engine_index >= context->ctrl->vdma_engines_count).
    for_each_vdma_engine(context->ctrl, engine, engine_index) {
        channels_bitmap = input.channels_bitmap_per_engine[engine_index];
        if (0 != (channels_bitmap & engine->enabled_channels)) {
            hailo_dev_err(context->ctrl->dev, "Trying to enable channels %llx that are already enabled %llx\n",
                channels_bitmap, engine->enabled_channels);
            return -EINVAL;
        }
    }

    for_each_vdma_engine(context->ctrl, engine, engine_index) {
        channels_bitmap = input.channels_bitmap_per_engine[engine_index];
        hailo_vdma_engine_enable_channels(engine, channels_bitmap);
        hailo_vdma_update_interrupts_mask(context->ctrl, engine_index);

        hailo_vdma_context_set_enabled_channels(context, engine_index, channels_bitmap);
    }

    return 0;
}

long hailo_vdma_disable_channels_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    struct hailo_vdma_disable_channels_params input;
    struct hailo_vdma_engine *engine = NULL;
    u8 engine_index = 0;
    u64 channels_bitmap = 0;

    if (copy_from_user(&input, (void __user *)arg, sizeof(input))) {
        hailo_dev_err(context->ctrl->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    // Validate params (ignoring engine_index >= context->ctrl->vdma_engines_count).
    for_each_vdma_engine(context->ctrl, engine, engine_index) {
        channels_bitmap = input.channels_bitmap_per_engine[engine_index];
        if (channels_bitmap != (channels_bitmap & engine->enabled_channels)) {
            hailo_dev_warn(context->ctrl->dev, "Trying to disable channels that were not enabled\n");
        }
    }

    for_each_vdma_engine(context->ctrl, engine, engine_index) {
        channels_bitmap = input.channels_bitmap_per_engine[engine_index];
        hailo_vdma_disable_channels_per_engine(context, engine_index, channels_bitmap);
    }

    return 0;
}

void hailo_vdma_transfer_release(struct hailo_transfer *transfer)
{
    struct hailo_vdma_controller *controller = transfer->opaque;
    u8 i = 0;

    for (i = 0; i < transfer->buffers_count; i++) {
        struct hailo_vdma_mapped_buffer *mapped_buffer = transfer->buffers[i].opaque;
        hailo_vdma_mapped_buffer_sync(controller->dev, mapped_buffer, HAILO_SYNC_FOR_CPU,
            transfer->buffers[i].offset, transfer->buffers[i].size);
        hailo_vdma_mapped_buffer_put(mapped_buffer);
    }
}

void hailo_vdma_transfer_done(struct hailo_transfer *transfer)
{
    struct hailo_vdma_controller *controller = transfer->opaque;
    hailo_vdma_monitor_dec_ongoing(&controller->monitor);
    hailo_vdma_transfer_release(transfer);
}

long hailo_vdma_interrupts_wait_ioctl(struct hailo_vdma_context *context, unsigned long arg, struct semaphore *mutex,
    bool *should_up_board_mutex)
{
    long err = 0;
    struct hailo_vdma_interrupts_wait_params params = { { 0 } };
    struct hailo_vdma_engine *engine = NULL;
    bool bitmap_not_empty = false;
    u8 engine_index = 0;
    u64 irq_bitmap = 0;

    if (copy_from_user(&params, (void __user *)arg, sizeof(params))) {
        hailo_dev_err(context->ctrl->dev, "HAILO_VDMA_INTERRUPTS_WAIT, copy_from_user fail\n");
        return -EFAULT;
    }

    // We don't need to validate that channels_bitmap_per_engine are enabled -
    // If the channel is not enabled we just return an empty interrupts list.

    // Validate params (ignoring engine_index >= context->ctrl->vdma_engines_count).
    // It us ok to wait on a disabled channel - the wait will just exit.
    for_each_vdma_engine(context->ctrl, engine, engine_index) {
        if (0 != params.channels_bitmap_per_engine[engine_index]) {
            bitmap_not_empty = true;
        }
    }
    if (!bitmap_not_empty) {
        hailo_dev_err(context->ctrl->dev, "Got an empty bitmap for wait interrupts\n");
        return -EINVAL;
    }

    up(mutex);
    err = hailo_vdma_context_wait_for_interrupt(context, params.channels_bitmap_per_engine);
    if (down_interruptible(mutex)) {
        pr_debug("hailo_vdma_interrupts_wait_ioctl: down_interruptible error (process was interrupted or killed)\n");
        *should_up_board_mutex = false;
        return -ERESTARTSYS;
    }

    if (!context->ctrl) {
        pr_err("hailo_vdma_interrupts_wait_ioctl, context is not valid\n");
        return -ENXIO;
    }

    if (err < 0) {
        hailo_dev_info(context->ctrl->dev,
            "wait channel interrupts failed with err=%ld (process was interrupted or killed)\n", err);
        return err;
    }

    params.channels_count = 0;
    for_each_vdma_engine(context->ctrl, engine, engine_index) {
        irq_bitmap = hailo_vdma_context_get_and_clear_interrupts(context, engine_index,
            params.channels_bitmap_per_engine[engine_index]);
        err = hailo_vdma_engine_fill_irq_data(&params, engine, irq_bitmap);
        if (err < 0) {
            hailo_dev_err(context->ctrl->dev, "Failed fill irq data %ld", err);
            return err;
        }
    }

    if (copy_to_user((void __user*)arg, &params, sizeof(params))) {
        hailo_dev_err(context->ctrl->dev, "copy_to_user fail\n");
        return -EFAULT;
    }

    return 0;
}

static struct hailo_vdma_mapped_buffer* get_or_map_buffer(
    struct hailo_vdma_context *context,
    struct hailo_vdma_transfer_buffer buffer,
    enum dma_data_direction direction)
{
    struct hailo_vdma_mapped_buffer *mapped_buffer = NULL;

    switch (buffer.buffer_type) {
    case HAILO_DMA_USER_PTR_BUFFER:
        hailo_dev_dbg(context->ctrl->dev, "mapping user-ptr buffer\n");
        mapped_buffer = hailo_vdma_find_mapped_buffer_by_address(context, buffer.addr_or_fd, buffer.size, direction);
        break;

    case HAILO_DMA_DMABUF_BUFFER:
        hailo_dev_dbg(context->ctrl->dev, "mapping dmabuf buffer\n");
        mapped_buffer = hailo_vdma_find_mapped_buffer_by_fd(context, buffer.addr_or_fd, buffer.size, direction);
        break;

    default:
        hailo_dev_err(context->ctrl->dev, "invalid user buffer type\n");
        return ERR_PTR(-EINVAL);
    }

    if (NULL == mapped_buffer) {
        // No buffer found: map a new one and add to list.
        mapped_buffer = hailo_vdma_map_buffer(context->ctrl->dev,
            buffer.addr_or_fd, buffer.size, direction, buffer.buffer_type);
        if (IS_ERR(mapped_buffer)) {
            if (PTR_ERR(mapped_buffer) != -EINTR) {
                hailo_dev_err(context->ctrl->dev, "failed map buffer %lx\n", buffer.addr_or_fd);
            }
            return mapped_buffer;
        }

        mapped_buffer->handle = atomic_inc_return(&context->last_vdma_user_buffer_handle);
        list_add(&mapped_buffer->mapped_user_buffer_list, &context->mapped_user_buffer_list);
        hailo_dev_dbg(context->ctrl->dev, "buffer %lx (handle %zu) is mapped\n", buffer.addr_or_fd,
            mapped_buffer->handle);
    } else {
        // Buffer found: incref.
        hailo_vdma_mapped_buffer_get(mapped_buffer);
    }

    return mapped_buffer;
}

static struct hailo_vdma_mapped_buffer* find_buffer(struct hailo_vdma_context *context,
                                                    struct hailo_vdma_buffer_params params,
                                                    enum dma_data_direction direction)
{
    return (HAILO_DMA_USER_PTR_BUFFER == params.type) ?
        hailo_vdma_find_mapped_buffer_by_exact_address(context, params.addr_or_fd, params.size, direction) :
        hailo_vdma_find_mapped_buffer_by_fd(context, params.addr_or_fd, params.size, direction);
}

long hailo_vdma_buffer_map_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    struct hailo_vdma_buffer_params params;
    struct hailo_vdma_mapped_buffer *buffer = NULL;
    enum dma_data_direction direction = DMA_NONE;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(context->ctrl->dev, "copy from user fail\n");
        return -EFAULT;
    }

    direction = get_dma_direction(params.direction);
    if (DMA_NONE == direction) {
        hailo_dev_err(context->ctrl->dev, "invalid data direction %d\n", params.direction);
        return -EINVAL;
    }
    if (params.type >= HAILO_DMA_BUFFER_MAX_ENUM) {
        hailo_dev_err(context->ctrl->dev, "invalid buffer type %d\n", params.direction);
        return -EINVAL;
    }

    hailo_dev_dbg(context->ctrl->dev, "mapping buffer <0x%lx + 0x%lx> tgid: %u\n",
                  params.addr_or_fd, params.size, current->tgid);

    buffer = find_buffer(context, params, direction);
    if (NULL != buffer) {
        // Buffer has already been mapped: inc-ref and return.
        // TODO: may be wise to return an error here instead?
        hailo_vdma_mapped_buffer_get(buffer);
    } else {
        // Buffer not found: map a new one.
        // TODO: HRT-17044: investigate why using get_or_map_buffer here causes issues
        buffer = hailo_vdma_map_buffer(context->ctrl->dev, params.addr_or_fd, params.size, direction, params.type);
        if (IS_ERR(buffer)) {
            if (PTR_ERR(buffer) != -EINTR) {
                hailo_dev_err(context->ctrl->dev, "failed map buffer %lx\n", params.addr_or_fd);
            }
            return PTR_ERR(buffer);
        }
        buffer->handle = atomic_inc_return(&context->last_vdma_user_buffer_handle);
        list_add(&buffer->mapped_user_buffer_list, &context->mapped_user_buffer_list);
    }

    params.mapped_handle = buffer->handle;
    if (copy_to_user((void __user*)arg, &params, sizeof(params))) {
        hailo_dev_err(context->ctrl->dev, "copy_to_user fail\n");
        hailo_vdma_mapped_buffer_put(buffer);
        return -EFAULT;
    }

    return 0;
}

long hailo_vdma_buffer_unmap_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    struct hailo_vdma_buffer_params params;
    struct hailo_vdma_mapped_buffer *buffer = NULL;
    enum dma_data_direction direction = DMA_NONE;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(context->ctrl->dev, "copy from user fail\n");
        return -EFAULT;
    }

    direction = get_dma_direction(params.direction);
    if (DMA_NONE == direction) {
        hailo_dev_err(context->ctrl->dev, "invalid data direction %d\n", params.direction);
        return -EINVAL;
    }
    if (params.type >= HAILO_DMA_BUFFER_MAX_ENUM) {
        hailo_dev_err(context->ctrl->dev, "invalid buffer type %d\n", params.direction);
        return -EINVAL;
    }

    hailo_dev_dbg(context->ctrl->dev, "unmap user buffer <0x%lx + 0x%lx>\n", params.addr_or_fd, params.size);

    buffer = find_buffer(context, params, direction);
    if (NULL == buffer) {
        hailo_dev_warn(context->ctrl->dev, "buffer <0x%lx + 0x%lx> not found\n", params.addr_or_fd, params.size);
        return -EINVAL;
    }

    hailo_vdma_mapped_buffer_put(buffer);

    return 0;
}

long hailo_vdma_buffer_sync_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    struct hailo_vdma_buffer_sync_params sync_info = {};
    struct hailo_vdma_mapped_buffer *mapped_buffer = NULL;

    if (copy_from_user(&sync_info, (void __user*)arg, sizeof(sync_info))) {
        hailo_dev_err(context->ctrl->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    if (!(mapped_buffer = hailo_vdma_find_mapped_buffer_by_handle(context, sync_info.handle))) {
        hailo_dev_err(context->ctrl->dev, "buffer handle %zu doesn't exist\n", sync_info.handle);
        return -EINVAL;
    }

    if ((sync_info.sync_type != HAILO_SYNC_FOR_CPU) && (sync_info.sync_type != HAILO_SYNC_FOR_DEVICE)) {
        hailo_dev_err(context->ctrl->dev, "Invalid sync_type given for vdma buffer sync.\n");
        return -EINVAL;
    }

    if (sync_info.offset + sync_info.count > mapped_buffer->size) {
        hailo_dev_err(context->ctrl->dev,
            "Invalid offset/count given for vdma buffer sync. offset %zu count %zu buffer size %u\n",
            sync_info.offset, sync_info.count, mapped_buffer->size);
        return -EINVAL;
    }

    hailo_vdma_mapped_buffer_sync(context->ctrl->dev, mapped_buffer, sync_info.sync_type,
        sync_info.offset, sync_info.count);
    return 0;
}

long hailo_desc_list_create_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    struct hailo_desc_list_create_params params;
    struct hailo_vdma_descriptors_list *desc_list = NULL;
    uintptr_t desc_handle = 0;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(context->ctrl->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    if (!is_powerof2(params.desc_page_size)) {
        hailo_dev_err(context->ctrl->dev, "Invalid desc page size given : %u\n",
            params.desc_page_size);
        return -EINVAL;
    }

    hailo_dev_info(context->ctrl->dev,
        "Create desc list desc_count: %zu desc_page_size: %u\n",
        params.desc_count, params.desc_page_size);

    desc_list = hailo_vdma_add_desc_list(context, params.desc_count, params.desc_page_size, &desc_handle);
    if (IS_ERR(desc_list)) {
        hailo_dev_err(context->ctrl->dev, "failed to allocate descriptors buffer\n");
        return PTR_ERR(desc_list);
    }

    // Note: The physical address is required for CONTEXT_SWITCH firmware controls
    BUILD_BUG_ON(sizeof(params.dma_address) < sizeof(desc_list->buffer.dma_address));
    params.dma_address = desc_list->buffer.dma_address;
    params.desc_handle = desc_handle;

    if (copy_to_user((void __user*)arg, &params, sizeof(params))){
        hailo_dev_err(context->ctrl->dev, "copy_to_user fail\n");
        hailo_vdma_remove_desc_list(context, desc_handle);
        return -EFAULT;
    }

    hailo_dev_info(context->ctrl->dev, "Created desc list, handle 0x%llu\n",
        (u64)params.desc_handle);
    return 0;
}

long hailo_desc_list_release_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    struct hailo_desc_list_release_params params;
    int err = 0;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(context->ctrl->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    err = hailo_vdma_remove_desc_list(context, params.desc_handle);
    if (err < 0) {
        hailo_dev_warn(context->ctrl->dev, "not found desc handle %llu\n", (unsigned long long)params.desc_handle);
        return err;
    }

    return 0;
}

long hailo_desc_list_program_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    struct hailo_desc_list_program_params configure_info;
    struct hailo_vdma_mapped_buffer *mapped_buffer = NULL;
    struct hailo_vdma_descriptors_list *desc_list = NULL;

    if (copy_from_user(&configure_info, (void __user*)arg, sizeof(configure_info))) {
        hailo_dev_err(context->ctrl->dev, "copy from user fail\n");
        return -EFAULT;
    }

    mapped_buffer = hailo_vdma_find_mapped_buffer_by_handle(context, configure_info.buffer_handle);
    desc_list = hailo_vdma_get_desc_list(context, configure_info.desc_handle);
    if (mapped_buffer == NULL || desc_list == NULL) {
        hailo_dev_err(context->ctrl->dev, "invalid user/descriptors buffer\n");
        return -EINVAL;
    }

    if (configure_info.starting_desc == 0) {
        desc_list->descs_programmed = 0;
    }

    if (configure_info.starting_desc != desc_list->descs_programmed) {
        hailo_dev_err(context->ctrl->dev, "Invalid starting descriptor: %u\n", configure_info.starting_desc);
        return -EINVAL;
    }

    return hailo_vdma_program_descriptors_list(
        context->ctrl->hw,
        desc_list,
        &mapped_buffer->sg_table,
        configure_info.buffer_offset,
        configure_info.transfer_size,
        configure_info.transfers_count,
        configure_info.channel_index,
        false
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

long hailo_vdma_continuous_buffer_alloc_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    struct hailo_allocate_continuous_buffer_params buf_info = {0};
    struct hailo_vdma_buffer *continuous_buffer = NULL;
    uintptr_t buffer_handle = 0;
    size_t aligned_buffer_size = 0;

    if (copy_from_user(&buf_info, (void __user*)arg, sizeof(buf_info))) {
        hailo_dev_err(context->ctrl->dev, "copy from user fail\n");
        return -EFAULT;
    }

    // We use PAGE_ALIGN to support mmap
    aligned_buffer_size = PAGE_ALIGN(buf_info.buffer_size);
    continuous_buffer = hailo_vdma_add_continuous_buffer(context, aligned_buffer_size, &buffer_handle);
    if (IS_ERR(continuous_buffer)) {
        return PTR_ERR(continuous_buffer);
    }

    buf_info.buffer_handle = buffer_handle;
    buf_info.dma_address = continuous_buffer->dma_address;
    if (copy_to_user((void __user*)arg, &buf_info, sizeof(buf_info))) {
        hailo_dev_err(context->ctrl->dev, "copy_to_user fail\n");
        hailo_vdma_remove_continuous_buffer(context, buffer_handle);
        return -EFAULT;
    }

    return 0;
}

long hailo_vdma_continuous_buffer_free_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    int err = 0;
    struct hailo_free_continuous_buffer_params params;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(context->ctrl->dev, "copy from user fail\n");
        return -EFAULT;
    }

    err = hailo_vdma_remove_continuous_buffer(context, params.buffer_handle);
    if (err < 0) {
        hailo_dev_err(context->ctrl->dev, "Failed to free continuous buffer %lu\n", params.buffer_handle);
        return err;
    }

    return 0;
}

static enum dma_data_direction get_channel_direction(struct hailo_vdma_hw *hw, u8 channel_idx)
{
    enum dma_data_direction direction = DMA_NONE;
    bool is_h2d = (vdma_channel_direction_by_idx(hw->variant, channel_idx) == VDMA_H2D);
    direction = is_h2d ? DMA_TO_DEVICE : DMA_FROM_DEVICE;

    return direction;
}

static long hailo_prepare_transfer(struct hailo_vdma_context *context, struct hailo_vdma_transfer_params *params,
    struct hailo_vdma_descriptors_list *desc_list)
{
    struct hailo_transfer transfer = {0};
    enum dma_data_direction direction = DMA_NONE;
    u8 i = 0;
    u8 j = 0;

    if (params->buffers_count > ARRAY_SIZE(params->buffers)) {
        hailo_dev_err(context->ctrl->dev, "too many buffers %u\n", params->buffers_count);
        return -EINVAL;
    }

    direction = get_channel_direction(context->ctrl->hw, params->channel_index);

    for (i = 0; i < params->buffers_count; i++) {
        u32 offset_from_map = 0;
        struct hailo_vdma_mapped_buffer *mapped_buffer;
        if (params->buffers[i].addr_or_fd == 0 || params->buffers[i].size == 0) {
            hailo_dev_err(context->ctrl->dev, "Invalid buffer %u, addr_or_fd: %lx, size: %u\n",
                i, params->buffers[i].addr_or_fd, params->buffers[i].size);
            return -EINVAL;
        }

        mapped_buffer = get_or_map_buffer(context, params->buffers[i], direction);
        if (IS_ERR(mapped_buffer)) {
            if (PTR_ERR(mapped_buffer) != -EINTR) {
                hailo_dev_err(context->ctrl->dev, "failed get or map buffer %lx\n", params->buffers[i].addr_or_fd);
                //unmap previous mapped buffers
                for (j = 0; j < i; j++) {
                    hailo_vdma_mapped_buffer_put(transfer.buffers[j].opaque);
                }
            }
            return PTR_ERR(mapped_buffer);
        }

        if (HAILO_DMA_USER_PTR_BUFFER == mapped_buffer->buffer_type) {
            offset_from_map = (u32)(params->buffers[i].addr_or_fd - mapped_buffer->addr_or_fd);

            // Syncing the buffer to device change its ownership from host to the device.
            // We sync on D2H as well if the user owns the buffer since the buffer might have been changed by
            // the host between the time it was mapped and the current async transfer.
            hailo_vdma_mapped_buffer_sync(context->ctrl->dev, mapped_buffer, HAILO_SYNC_FOR_DEVICE,
                offset_from_map, params->buffers[i].size);
        }

        transfer.buffers[i].sg_table = &mapped_buffer->sg_table;
        transfer.buffers[i].size = params->buffers[i].size;
        transfer.buffers[i].offset = offset_from_map;
        transfer.buffers[i].opaque = mapped_buffer;
    }

    transfer.buffers_count = params->buffers_count;
    transfer.opaque = context->ctrl;

    return hailo_vdma_prepare_transfer(context->ctrl->hw, params->channel_index, desc_list, params->buffers_count,
        &transfer, params->is_programmed);
}

long hailo_vdma_prepare_transfer_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    struct hailo_vdma_transfer_params params;
    struct hailo_vdma_descriptors_list *desc_list = NULL;
    int ret = 0;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(context->ctrl->dev, "copy from user fail\n");
        return -EFAULT;
    }

    desc_list = hailo_vdma_get_desc_list(context, params.desc_handle);
    if (NULL == desc_list) {
        hailo_dev_err(context->ctrl->dev, "invalid descriptors list handle\n");
        return -EFAULT;
    }

    ret = hailo_prepare_transfer(context, &params, desc_list);
    if (ret < 0) {
        hailo_dev_err(context->ctrl->dev, "Failed to prepare transfer\n");
    }

    return ret;
}

long hailo_vdma_cancel_prepared_transfer_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    struct hailo_vdma_descriptors_list *desc_list = NULL;
    struct hailo_vdma_cancel_prepared_transfer_params params;

    if (copy_from_user(&params, (void __user *)arg, sizeof(params))) {
        hailo_dev_err(context->ctrl->dev, "copy_from_user fail\n");
        return -ENOMEM;
    }

    desc_list = hailo_vdma_get_desc_list(context, params.desc_handle);
    if (NULL == desc_list) {
        hailo_dev_err(context->ctrl->dev, "Descriptors buffer not found for handle %llu\n", (u64)params.desc_handle);
        return -EINVAL;
    }
    hailo_vdma_cancel_prepared_transfer(desc_list);

    return 0;
}

long hailo_vdma_launch_transfer_ioctl(struct hailo_vdma_context *context, unsigned long arg)
{
    struct hailo_vdma_transfer_params params;
    struct hailo_vdma_engine *engine = NULL;
    struct hailo_vdma_channel_pair *channel_pair = NULL;
    struct hailo_vdma_descriptors_list *desc_list = NULL;
    unsigned int engine_idx = 0;
    unsigned int channel_idx = 0;
    int err = 0;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(context->ctrl->dev, "copy from user fail\n");
        return -EFAULT;
    }

    engine_idx = params.engine_index;
    if (engine_idx >= context->ctrl->vdma_engines_count) {
        hailo_dev_err(context->ctrl->dev, "Invalid engine %u", engine_idx);
        return -EINVAL;
    }

    /* Sanitize user-supplied indices (engine_idx, channel_idx) via array_index_nospec() against
     * speculative out-of-bounds access past their bounds checks. See speculation.rst in the linux kernel docs. */
    engine_idx = array_index_nospec(engine_idx, context->ctrl->vdma_engines_count);
    engine = &context->ctrl->vdma_engines[engine_idx];

    channel_idx = params.channel_index;
    if (channel_idx >= ARRAY_SIZE(engine->channels)) {
        hailo_dev_err(context->ctrl->dev, "Invalid channel %u", channel_idx);
        return -EINVAL;
    }

    channel_idx = array_index_nospec(channel_idx, engine->channels_count);
    channel_pair = &engine->channels[channel_idx];

    if (params.buffers_count > ARRAY_SIZE(params.buffers)) {
        hailo_dev_err(context->ctrl->dev, "too many buffers %u\n", params.buffers_count);
        return -EINVAL;
    }

    desc_list = hailo_vdma_get_desc_list(context, params.desc_handle);
    if (NULL == desc_list) {
        hailo_dev_err(context->ctrl->dev, "invalid descriptors list handle\n");
        return -EINVAL;
    }

    if (0 == HAILO_TRANSFERS_CNT(&desc_list->prepared_transfers)) {
        err = hailo_prepare_transfer(context, &params, desc_list);
        if (err < 0) {
            return err;
        }
    }

    err = hailo_vdma_launch_transfer(&channel_pair->host, desc_list);
    if (err < 0) {
        hailo_dev_err(context->ctrl->dev, "Failed to launch transfer\n");
        return err;
    }

    hailo_vdma_monitor_inc_ongoing(&context->ctrl->monitor);

    return err;
}
