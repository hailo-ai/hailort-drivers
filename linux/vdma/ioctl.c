// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#include "ioctl.h"
#include "memory.h"
#include "utils/logs.h"
#include "utils.h"

#include <linux/slab.h>
#include <linux/uaccess.h>


long hailo_vdma_interrupts_enable_ioctl(struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_interrupts_enable_params input;
    struct hailo_vdma_engine *engine = NULL;
    u8 engine_index = 0;
    u32 channels_bitmap = 0;

    if (copy_from_user(&input, (void *)arg, sizeof(input))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -ENOMEM;
    }

    // Validate params (ignoring engine_index >= controller->vdma_engines_count).
    for_each_vdma_engine(controller, engine, engine_index) {
        channels_bitmap = input.channels_bitmap_per_engine[engine_index];
        if (0 != (channels_bitmap & engine->enabled_channels)) {
            hailo_dev_err(controller->dev, "Trying to enable channels that are already enabled\n");
            return -EINVAL;
        }
    }

    for_each_vdma_engine(controller, engine, engine_index) {
        channels_bitmap = input.channels_bitmap_per_engine[engine_index];
        hailo_vdma_engine_enable_channel_interrupts(engine, channels_bitmap,
            input.enable_timestamps_measure);
        hailo_vdma_update_interrupts_mask(controller, engine_index);
        hailo_dev_info(controller->dev, "Enabled interrupts for engine %u, channels bitmap 0x%x\n",
            engine_index, channels_bitmap);
    }

    return 0;
}

long hailo_vdma_interrupts_disable_ioctl(struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_interrupts_disable_params input;
    struct hailo_vdma_engine *engine = NULL;
    u8 engine_index = 0;
    u32 channels_bitmap = 0;

    if (copy_from_user(&input, (void*)arg, sizeof(input))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -ENOMEM;
    }

    // Validate params (ignoring engine_index >= controller->vdma_engines_count).
    for_each_vdma_engine(controller, engine, engine_index) {
        channels_bitmap = input.channels_bitmap_per_engine[engine_index];
        if (channels_bitmap != (channels_bitmap & engine->enabled_channels)) {
            hailo_dev_err(controller->dev, "Trying to disable channels that were not enabled\n");
            return -EINVAL;
        }
    }

    for_each_vdma_engine(controller, engine, engine_index) {
        channels_bitmap = input.channels_bitmap_per_engine[engine_index];
        hailo_vdma_engine_interrupts_disable(controller, engine, engine_index,
            channels_bitmap);
    }

    // Wake up threads waiting
    wake_up_interruptible_all(&controller->interrupts_wq);

    return 0;
}

static bool got_interrupt(struct hailo_vdma_controller *controller,
    u32 channels_bitmap_per_engine[MAX_VDMA_ENGINES])
{
    struct hailo_vdma_engine *engine = NULL;
    u8 engine_index = 0;
    for_each_vdma_engine(controller, engine, engine_index) {
        if (hailo_vdma_engine_got_interrupt(engine,
                channels_bitmap_per_engine[engine_index])) {
            return true;
        }
    }
    return false;
}

long hailo_vdma_interrupts_wait_ioctl(struct hailo_vdma_controller *controller, unsigned long arg,
    struct semaphore *mutex, bool *should_up_board_mutex)
{
    long err = 0;
    struct hailo_vdma_interrupts_wait_params intr_args = {0};
    struct hailo_vdma_engine *engine = NULL;
    bool bitmap_not_empty = false;
    u8 engine_index = 0;
    u32 irq_channels_bitmap = 0;
    unsigned long irq_saved_flags = 0;

    if (copy_from_user(&intr_args, (void*)arg, sizeof(intr_args))) {
        hailo_dev_err(controller->dev, "HAILO_VDMA_INTERRUPTS_WAIT, copy_from_user fail\n");
        return -ENOMEM;
    }

    // We don't need to validate that channels_bitmap_per_engine are enabled -
    // If the channel is not enabled we just return an empty interrupts list.

    // Validate params (ignoring engine_index >= controller->vdma_engines_count).
    // It us ok to wait on a disabled channel - the wait will just exit.
    for_each_vdma_engine(controller, engine, engine_index) {
        if (0 != intr_args.channels_bitmap_per_engine[engine_index]) {
            bitmap_not_empty = true;
        }
    }
    if (!bitmap_not_empty) {
        hailo_dev_err(controller->dev, "Got an empty bitmap for wait interrupts\n");
        return -EINVAL;
    }

    up(mutex);
    err = wait_event_interruptible(controller->interrupts_wq,
        got_interrupt(controller, intr_args.channels_bitmap_per_engine));
    if (err < 0) {
        hailo_dev_info(controller->dev,
            "wait channel interrupts failed with err=%ld (process was interrupted or killed)\n", err);
        *should_up_board_mutex = false;
        return err;
    }

    if (down_interruptible(mutex)) {
        hailo_dev_info(controller->dev, "down_interruptible error (process was interrupted or killed)\n");
        *should_up_board_mutex = false;
        return -ERESTARTSYS;
    }

    intr_args.channels_count = 0;
    for_each_vdma_engine(controller, engine, engine_index) {

        spin_lock_irqsave(&controller->interrupts_lock, irq_saved_flags);
        irq_channels_bitmap = hailo_vdma_engine_read_interrupts(engine,
            intr_args.channels_bitmap_per_engine[engine_index]);
        spin_unlock_irqrestore(&controller->interrupts_lock, irq_saved_flags);

        err = hailo_vdma_engine_fill_irq_data(&intr_args, engine, engine_index,
            irq_channels_bitmap);
        if (err < 0) {
            hailo_dev_err(controller->dev, "Failed fill irq data %ld", err);
            return err;
        }
    }

    if (copy_to_user((void __user*)arg, &intr_args, sizeof(intr_args))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        return -ENOMEM;
    }

    return 0;
}

long hailo_vdma_channel_read_register_ioctl(struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_channel_read_register_params params;
    int err = 0;
    size_t engine_index = 0;
    struct hailo_resource *channel_registers = NULL;

    hailo_dev_dbg(controller->dev, "Read vdma channel registers\n");

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -ENOMEM;
    }

    if (params.engine_index >= controller->vdma_engines_count) {
        hailo_dev_err(controller->dev, "Invalid engine %u", params.engine_index);
        return -EINVAL;
    }

    engine_index = params.engine_index;
    channel_registers = &controller->vdma_engines[engine_index].channel_registers;
    err = hailo_vdma_channel_read_register(&params, channel_registers);
    if (0 != err) {
        hailo_dev_err(controller->dev, "hailo vdma channel read registers failed with error %d\n", err);
        return -EINVAL;
    }

    if (copy_to_user((void __user *)arg, &params, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        return -ENOMEM;
    }

    return 0;
}

long hailo_vdma_channel_write_register_ioctl(struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_channel_write_register_params params;
    int err = 0;
    size_t engine_index = 0;
    struct hailo_resource *channel_registers = NULL;

    hailo_dev_dbg(controller->dev, "Write vdma channel registers\n");

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -ENOMEM;
    }

    if (params.engine_index >= controller->vdma_engines_count) {
        hailo_dev_err(controller->dev, "Invalid engine %u", params.engine_index);
        return -EINVAL;
    }

    engine_index = params.engine_index;
    channel_registers = &controller->vdma_engines[engine_index].channel_registers;
    err = hailo_vdma_channel_write_register(&params, channel_registers);
    if (0 != err) {
        hailo_dev_err(controller->dev, "hailo vdma channel write registers failed with error %d\n", err);
        return -EINVAL;
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

long hailo_vdma_buffer_map_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_vdma_buffer_map_params buf_info;
    struct hailo_vdma_buffer *mapped_buffer = NULL;
    enum dma_data_direction direction = DMA_NONE;
    struct hailo_vdma_low_memory_buffer *low_memory_buffer = NULL;

    if (copy_from_user(&buf_info, (void __user*)arg, sizeof(buf_info))) {
        hailo_dev_err(controller->dev, "copy from user fail\n");
        return -EFAULT;
    }

    hailo_dev_info(controller->dev, "address %px tgid %d size: %zu\n",
        buf_info.user_address, current->tgid, buf_info.size);

    direction = get_dma_direction(buf_info.data_direction);
    if (DMA_NONE == direction) {
        hailo_dev_err(controller->dev, "invalid data direction %d\n", buf_info.data_direction);
        return -EINVAL;
    }

    low_memory_buffer = hailo_vdma_find_low_memory_buffer(context, buf_info.allocated_buffer_handle);

    mapped_buffer = hailo_vdma_buffer_map(controller->dev,
        buf_info.user_address, buf_info.size, direction, low_memory_buffer);
    if (IS_ERR(mapped_buffer)) {
        hailo_dev_err(controller->dev, "failed map buffer %px\n",
            buf_info.user_address);
        return PTR_ERR(mapped_buffer);
    }

    mapped_buffer->handle = atomic_inc_return(&context->last_vdma_user_buffer_handle);
    buf_info.mapped_handle = mapped_buffer->handle;
    if (copy_to_user((void __user*)arg, &buf_info, sizeof(buf_info))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        hailo_vdma_buffer_put(mapped_buffer);
        return -EFAULT;
    }

    list_add(&mapped_buffer->mapped_user_buffer_list, &context->mapped_user_buffer_list);
    hailo_dev_info(controller->dev, "buffer %px (handle %zu) is mapped\n",
        buf_info.user_address, buf_info.mapped_handle);
    return 0;
}

long hailo_vdma_buffer_unmap_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_vdma_buffer *mapped_buffer = NULL;
    struct hailo_vdma_buffer_unmap_params buffer_unmap_params;

    if (copy_from_user(&buffer_unmap_params, (void __user*)arg, sizeof(buffer_unmap_params))) {
        hailo_dev_err(controller->dev, "copy from user fail\n");
        return -EFAULT;
    }

    hailo_dev_info(controller->dev, "unmap user buffer handle %zu\n", buffer_unmap_params.mapped_handle);

    mapped_buffer = hailo_vdma_find_mapped_user_buffer(context, buffer_unmap_params.mapped_handle);
    if (mapped_buffer == NULL) {
        hailo_dev_warn(controller->dev, "buffer handle %zu not found\n", buffer_unmap_params.mapped_handle);
        return -EINVAL;
    }

    list_del(&mapped_buffer->mapped_user_buffer_list);
    hailo_vdma_buffer_put(mapped_buffer);
    return 0;
}

static void hailo_vdma_sync_entire_buffer(struct hailo_vdma_buffer_sync_params *sync_info,
    struct hailo_vdma_buffer *mapped_buffer, struct hailo_vdma_controller *controller)
{
    if (sync_info->sync_type == HAILO_SYNC_FOR_CPU) {
        dma_sync_sg_for_cpu(controller->dev, mapped_buffer->sg_table.sgl, mapped_buffer->sg_table.nents,
            mapped_buffer->data_direction);
    } else {
        dma_sync_sg_for_device(controller->dev, mapped_buffer->sg_table.sgl, mapped_buffer->sg_table.nents,
            mapped_buffer->data_direction);
    }
}

typedef void (*dma_sync_single_callback)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
// Map sync_info->count bytes starting at sync_info->offset
static void hailo_vdma_sync_buffer_interval(struct hailo_vdma_buffer_sync_params *sync_info,
    struct hailo_vdma_buffer *mapped_buffer, struct hailo_vdma_controller *controller)
{
    unsigned long sync_start_offset = sync_info->offset;
    unsigned long sync_end_offset = sync_start_offset + sync_info->count;
    dma_sync_single_callback dma_sync_single = (sync_info->sync_type == HAILO_SYNC_FOR_CPU) ? dma_sync_single_for_cpu :
        dma_sync_single_for_device;
    struct scatterlist* sg_entry = NULL;
    unsigned long offset = 0;
    int i = 0;

    for_each_sg(mapped_buffer->sg_table.sgl, sg_entry, mapped_buffer->sg_table.nents, i) {
        // Check if the intervals: [offset, sg_dma_len(sg_entry)] and [sync_start_offset, sync_end_offset]
        // have any intersection. If offset isn't at the start of a sg_entry, we still want to sync it.
        if (max(sync_start_offset, offset) <= min(sync_end_offset, offset + sg_dma_len(sg_entry))) {
            dma_sync_single(controller->dev, sg_dma_address(sg_entry), sg_dma_len(sg_entry),
                mapped_buffer->data_direction);
        }

        offset += sg_dma_len(sg_entry);
    }
}

long hailo_vdma_buffer_sync(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_buffer_sync_params sync_info = {};
    struct hailo_vdma_buffer *mapped_buffer = NULL;

    if (copy_from_user(&sync_info, (void __user*)arg, sizeof(sync_info))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    if (!(mapped_buffer = hailo_vdma_find_mapped_user_buffer(context, sync_info.handle))) {
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

    if ((sync_info.offset == 0) && (sync_info.count == mapped_buffer->size)) {
        hailo_vdma_sync_entire_buffer(&sync_info, mapped_buffer, controller);
    } else {
        hailo_vdma_sync_buffer_interval(&sync_info, mapped_buffer, controller);
    }

    return 0;
}

long hailo_desc_list_create_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_desc_list_create_params create_descriptors_info;
    struct hailo_descriptors_list_buffer *descriptors_buffer = NULL;
    uintptr_t next_handle = 0;
    long err = -EINVAL;

    if (copy_from_user(&create_descriptors_info, (void __user*)arg, sizeof(create_descriptors_info))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    if (create_descriptors_info.is_circular && !is_powerof2(create_descriptors_info.desc_count)) {
        hailo_dev_err(controller->dev, "Invalid desc count given : %zu , circular descriptors count must be power of 2\n",
            create_descriptors_info.desc_count);
        return -EINVAL;
    }

    hailo_dev_info(controller->dev, "Create desc list desc_count: %zu\n", create_descriptors_info.desc_count);

    descriptors_buffer = kzalloc(sizeof(*descriptors_buffer), GFP_KERNEL);
    if (NULL == descriptors_buffer) {
        hailo_dev_err(controller->dev, "Failed to allocate buffer for descriptors list struct\n");
        return -ENOMEM;
    }

    next_handle = hailo_get_next_vdma_handle(context);

    err = hailo_desc_list_create(controller->dev, create_descriptors_info.desc_count, next_handle,
        create_descriptors_info.is_circular, descriptors_buffer);
    if (err < 0) {
        hailo_dev_err(controller->dev, "failed to allocate descriptors buffer\n");
        kfree(descriptors_buffer);
        return err;
    }

    list_add(&descriptors_buffer->descriptors_buffer_list, &context->descriptors_buffer_list);

    // Note: The physical address is required for CONTEXT_SWITCH firmware controls
    BUILD_BUG_ON(sizeof(create_descriptors_info.dma_address) < sizeof(descriptors_buffer->dma_address));
    create_descriptors_info.dma_address = descriptors_buffer->dma_address;
    create_descriptors_info.desc_handle = descriptors_buffer->handle;

    if(copy_to_user((void __user*)arg, &create_descriptors_info, sizeof(create_descriptors_info))){
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        list_del(&descriptors_buffer->descriptors_buffer_list);
        hailo_desc_list_release(controller->dev, descriptors_buffer);
        kfree(descriptors_buffer);
        return -EFAULT;
    }

    hailo_dev_info(controller->dev, "Created decc list, handle 0x%llu\n",
        (uint64_t)create_descriptors_info.desc_handle);
    return 0;
}

long hailo_desc_list_release_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    uintptr_t desc_handle = 0;
    struct hailo_descriptors_list_buffer *descriptors_buffer = NULL;

    if (copy_from_user(&desc_handle, (void __user*)arg, sizeof(uintptr_t))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    descriptors_buffer = hailo_vdma_find_descriptors_buffer(context, desc_handle);
    if (descriptors_buffer == NULL) {
        hailo_dev_warn(controller->dev, "not found desc handle %llu\n", (uint64_t)desc_handle);
        return -EINVAL;
    }

    list_del(&descriptors_buffer->descriptors_buffer_list);
    hailo_desc_list_release(controller->dev, descriptors_buffer);
    kfree(descriptors_buffer);
    return 0;
}

long hailo_desc_list_bind_vdma_buffer(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_desc_list_bind_vdma_buffer_params configure_info;
    struct hailo_vdma_buffer *mapped_buffer = NULL;
    struct hailo_descriptors_list_buffer *descriptors_buffer = NULL;
    const uint8_t data_id = controller->ops->get_dma_data_id();

    // TODO HRT-9946 validate if not circular desc list

    if (copy_from_user(&configure_info, (void __user*)arg, sizeof(configure_info))) {
        hailo_dev_err(controller->dev, "copy from user fail\n");
        return -EFAULT;
    }
    hailo_dev_info(controller->dev, "config buffer_handle=%zu desc_handle=%llu starting_desc=%u\n",
        configure_info.buffer_handle, (uint64_t)configure_info.desc_handle, configure_info.starting_desc);

    mapped_buffer = hailo_vdma_find_mapped_user_buffer(context, configure_info.buffer_handle);
    descriptors_buffer = hailo_vdma_find_descriptors_buffer(context, configure_info.desc_handle);
    if (mapped_buffer == NULL || descriptors_buffer == NULL) {
        hailo_dev_err(controller->dev, "invalid user/descriptors buffer\n");
        return -EFAULT;
    }

    return hailo_vdma_program_descriptors_list(&configure_info,
        &descriptors_buffer->desc_list,
        &mapped_buffer->sg_table,
        controller->ops->encode_desc_dma_address,
        data_id
    );
}

long hailo_vdma_low_memory_buffer_alloc_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_allocate_low_memory_buffer_params buf_info = {0};
    struct hailo_vdma_low_memory_buffer *low_memory_buffer = NULL;
    long err = -EINVAL;

    if (copy_from_user(&buf_info, (void __user*)arg, sizeof(buf_info))) {
        hailo_dev_err(controller->dev, "copy from user fail\n");
        return -EFAULT;
    }

    low_memory_buffer = kzalloc(sizeof(*low_memory_buffer), GFP_KERNEL);
    if (NULL == low_memory_buffer) {
        hailo_dev_err(controller->dev, "memory alloc failed\n");
        return -ENOMEM;
    }

    err = hailo_vdma_low_memory_buffer_alloc(buf_info.buffer_size, low_memory_buffer);
    if (err < 0) {
        kfree(low_memory_buffer);
        hailo_dev_err(controller->dev, "failed allocating buffer from driver\n");
        return err;
    }

    // Get handle for allocated buffer
    low_memory_buffer->handle = hailo_get_next_vdma_handle(context);

    list_add(&low_memory_buffer->vdma_low_memory_buffer_list, &context->vdma_low_memory_buffer_list);

    buf_info.buffer_handle = low_memory_buffer->handle;
    if (copy_to_user((void __user*)arg, &buf_info, sizeof(buf_info))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        list_del(&low_memory_buffer->vdma_low_memory_buffer_list);
        hailo_vdma_low_memory_buffer_free(low_memory_buffer);
        kfree(low_memory_buffer);
        return -EFAULT;
    }

    return 0;
}

long hailo_vdma_low_memory_buffer_free_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_vdma_low_memory_buffer *low_memory_buffer = NULL;
    uintptr_t buf_handle = (uintptr_t)arg;

    low_memory_buffer = hailo_vdma_find_low_memory_buffer(context, buf_handle);
    if (NULL == low_memory_buffer) {
        hailo_dev_warn(controller->dev, "vdma buffer handle %lx not found\n", buf_handle);
        return -EINVAL;
    }

    list_del(&low_memory_buffer->vdma_low_memory_buffer_list);
    hailo_vdma_low_memory_buffer_free(low_memory_buffer);
    kfree(low_memory_buffer);
    return 0;
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

    continuous_buffer->handle = hailo_get_next_vdma_handle(context);
    list_add(&continuous_buffer->continuous_buffer_list, &context->continuous_buffer_list);

    buf_info.buffer_handle = continuous_buffer->handle;
    buf_info.dma_address = continuous_buffer->dma_address;
    if (copy_to_user((void __user*)arg, &buf_info, sizeof(buf_info))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        list_del(&continuous_buffer->continuous_buffer_list);
        hailo_vdma_continuous_buffer_free(controller->dev, continuous_buffer);
        kfree(continuous_buffer);
        return -EFAULT;
    }

    return 0;
}

long hailo_vdma_continuous_buffer_free_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_continuous_buffer *continuous_buffer = NULL;
    uintptr_t buf_handle = (uintptr_t)arg;

    continuous_buffer = hailo_vdma_find_continuous_buffer(context, buf_handle);
    if (NULL == continuous_buffer) {
        hailo_dev_warn(controller->dev, "vdma buffer handle %lx not found\n", buf_handle);
        return -EINVAL;
    }

    list_del(&continuous_buffer->continuous_buffer_list);
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
        return -ENOMEM;
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
        return -ENOMEM;
    }

    return 0;
}