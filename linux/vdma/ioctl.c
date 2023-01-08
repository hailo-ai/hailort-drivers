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
    long err = -EFAULT;
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

    mapped_buffer = kzalloc(sizeof(*mapped_buffer), GFP_KERNEL);
    if (NULL == mapped_buffer) {
        hailo_dev_err(controller->dev, "memory alloc failed\n");
        return -ENOMEM;
    }

    low_memory_buffer = hailo_vdma_get_low_memory_buffer(context, buf_info.allocated_buffer_handle);

    err = hailo_vdma_buffer_map(controller->dev, buf_info.user_address, buf_info.size, direction,
        mapped_buffer, low_memory_buffer);
    if (err < 0) {
        kfree(mapped_buffer);
        hailo_dev_err(controller->dev, "failed map buffer with handle %lu\n",
            (long unsigned)buf_info.allocated_buffer_handle);
        return err;
    }

    mapped_buffer->driver_buffer_handle = buf_info.allocated_buffer_handle;
    mapped_buffer->handle = atomic_inc_return(&context->last_vdma_user_buffer_handle);
    list_add(&mapped_buffer->mapped_user_buffer_list, &context->mapped_user_buffer_list);
    buf_info.mapped_handle = mapped_buffer->handle;
    if (copy_to_user((void __user*)arg, &buf_info, sizeof(buf_info))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        list_del(&mapped_buffer->mapped_user_buffer_list);
        hailo_vdma_buffer_unmap(controller->dev, mapped_buffer);
        kfree(mapped_buffer);
        return -EFAULT;
    }
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

    mapped_buffer = hailo_vdma_get_mapped_user_buffer(context, buffer_unmap_params.mapped_handle);
    if (mapped_buffer == NULL) {
        hailo_dev_warn(controller->dev, "buffer handle %zu not found\n", buffer_unmap_params.mapped_handle);
        return -EINVAL;
    }

    list_del(&mapped_buffer->mapped_user_buffer_list);
    hailo_vdma_buffer_unmap(controller->dev, mapped_buffer);
    kfree(mapped_buffer);
    return 0;
}

long hailo_vdma_buffer_sync(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_buffer_sync_params sync_info = {};
    struct hailo_vdma_buffer *mapped_buffer = NULL;
    struct scatterlist* sg_entry = NULL;
    unsigned long buffer_start_offset = 0;
    unsigned long buffer_end_offset = 0;
    unsigned long offset = 0;
    int i = 0;


    if (copy_from_user(&sync_info, (void __user*)arg, sizeof(sync_info))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    if (!(mapped_buffer = hailo_vdma_get_mapped_user_buffer(context, sync_info.handle))) {
        hailo_dev_err(controller->dev, "buffer handle %zu doesn't exist\n", sync_info.handle);
        return -EINVAL;
    }

    if (!(sync_info.sync_type == HAILO_SYNC_FOR_HOST && hailo_buffer_from_device(mapped_buffer)) &&
        !(sync_info.sync_type == HAILO_SYNC_FOR_DEVICE && hailo_buffer_to_device(mapped_buffer))) {
            hailo_dev_err(controller->dev, "Invalid direction given for vdma buffer sync.\n");
            return -EINVAL;
    }

    if ((unsigned long)sync_info.buffer_address < (unsigned long)mapped_buffer->user_address ||
        (unsigned long)sync_info.buffer_address + sync_info.buffer_size > (unsigned long)mapped_buffer->user_address + mapped_buffer->size) {
            hailo_dev_err(controller->dev, "Invalid buffer given for vdma buffer sync.\n");
            return -EINVAL;
    }

    buffer_start_offset = (unsigned long)sync_info.buffer_address - (unsigned long)mapped_buffer->user_address;
    buffer_end_offset = buffer_start_offset + sync_info.buffer_size;

    for_each_sg(mapped_buffer->sg_table.sgl, sg_entry, mapped_buffer->sg_table.nents, i) {
        // Check if the intervals: [offset, sg_dma_len(sg_entry)] and [buffer_start_offset, buffer_end_offset]
        // have any intersection.
        if (max(buffer_start_offset, offset) <= min(buffer_end_offset, offset + sg_dma_len(sg_entry))) {
            if (sync_info.sync_type == HAILO_SYNC_FOR_HOST) {
                dma_sync_single_for_cpu(controller->dev, sg_dma_address(sg_entry), sg_dma_len(sg_entry),
                    mapped_buffer->data_direction);
            }
            else {
                dma_sync_single_for_device(controller->dev, sg_dma_address(sg_entry), sg_dma_len(sg_entry),
                    mapped_buffer->data_direction);
            }
        }

        offset += sg_dma_len(sg_entry);
    }


    return 0;
}

long hailo_desc_list_create_ioctl(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_desc_list_create_params create_descriptors_info;
    struct hailo_descriptors_list *descriptors_buffer = NULL;
    uintptr_t next_handle = 0;
    long err = -EINVAL;

    if (copy_from_user(&create_descriptors_info, (void __user*)arg, sizeof(create_descriptors_info))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    if (!is_powerof2(create_descriptors_info.desc_count)) {
        hailo_dev_err(controller->dev, "Invalid desc count given : %zu , must be power of 2\n",
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
        descriptors_buffer);
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
    struct hailo_descriptors_list *descriptors_buffer = NULL;

    if (copy_from_user(&desc_handle, (void __user*)arg, sizeof(uintptr_t))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    descriptors_buffer = hailo_vdma_get_descriptors_buffer(context, desc_handle);
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
    struct hailo_descriptors_list *descriptors_buffer = NULL;
    struct hailo_vdma_descriptor *dma_desc = NULL;
    uint8_t channel_id;
    const uint8_t data_id = controller->ops->get_dma_data_id();
    uint32_t starting_desc_index = 0;
    uint32_t desc_index = 0;
    uint32_t desc_in_sg = 0;
    dma_addr_t desc_buffer_addr = 0;
    uint64_t encoded_addr = 0;
    uint32_t desc_per_sg = 0;
    struct scatterlist *sg_entry = NULL;
    int i = 0;
    size_t offset_in_buffer = 0;

    if (copy_from_user(&configure_info, (void __user*)arg, sizeof(configure_info))) {
        hailo_dev_err(controller->dev, "copy from user fail\n");
        return -EFAULT;
    }

    if (!is_powerof2(configure_info.desc_page_size)) {
        hailo_dev_err(controller->dev, "invalid desc_page_size - %u (must be a power of two)\n",
            configure_info.desc_page_size);
        return -EFAULT;
    }

    if (0 != (configure_info.offset % configure_info.desc_page_size)) {
        hailo_dev_err(controller->dev, "invalid offset - %zu (must be a multiple of desc_page_size)\n",
            configure_info.offset);
        return -EFAULT;
    }

    // On hailo8, we allow channel_id may be INVALID_VDMA_CHANNEL.
    channel_id = hailo_vdma_get_channel_id(configure_info.channel_index);

    hailo_dev_info(controller->dev, "config buffer_handle=%zu desc_handle=%llu offset=%zu\n",
        configure_info.buffer_handle, (uint64_t)configure_info.desc_handle, configure_info.offset);

    mapped_buffer = hailo_vdma_get_mapped_user_buffer(context, configure_info.buffer_handle);
    descriptors_buffer = hailo_vdma_get_descriptors_buffer(context, configure_info.desc_handle);
    if (mapped_buffer == NULL || descriptors_buffer == NULL) {
        hailo_dev_err(controller->dev, "invalid user/descriptors buffer\n");
        return -EFAULT;
    }

    if (descriptors_buffer->desc_count * configure_info.desc_page_size < mapped_buffer->size) {
        hailo_dev_err(controller->dev, "descriptor buffer should be big enough (max size %u, user actual size %u)\n",
            descriptors_buffer->desc_count * configure_info.desc_page_size, mapped_buffer->size);
        return -EINVAL;
    }

    dma_desc = (struct hailo_vdma_descriptor*)descriptors_buffer->kernel_address;
    offset_in_buffer = configure_info.offset % mapped_buffer->size;
    // Get the index of the descriptor that corresponds to offset_in_buffer; relative to the start of the dma_desc array
    starting_desc_index = DESCRIPTORS_IN_BUFFER(offset_in_buffer, configure_info.desc_page_size);
    desc_index = descriptors_buffer->desc_count - starting_desc_index;
    // Assume that:
    // - the vdma buffer's pages are - p_0, p_1, ..., p_n
    // - the page that matches offset_in_buffer is p_i
    // - the descs are - d_0, d_1, ..., d_k (k >= n)
    // In the case of configure_info.offset == 0, p_i == p_0; we'll get the following binding:
    //       d_0             d_1       ...       d_n         (d_(n+1), ... d_k point to p_0, ..., p_(k-n))
    //        V               V                   V
    // | --- p_0 --- | | --- p_1 --- | ... | --- p_n --- |
    // And for configure_info.offset != 0, we'll get the following binding:
    //    d_(n-i+1)     d_(n-i+2)    ...         d_n               d_0               d_1         ...      d_(n-i)
    //        V             V                     V                 V                 V                     V
    // | --- p_0 --- | --- p_1 --- | ... | --- p_(i-1) --- | | --- p_i --- | | --- p_(i+1) --- | ... | --- p_n --- |
    for_each_sg(mapped_buffer->sg_table.sgl, sg_entry, mapped_buffer->sg_table.nents, i) {
        if ((sg_dma_len(sg_entry) % configure_info.desc_page_size) != 0) {
            hailo_dev_err(controller->dev, "invalid desc page size %u (should be a divisor of %zu)\n",
                configure_info.desc_page_size, (size_t)sg_dma_len(sg_entry));
            return -EFAULT;
        }
        desc_per_sg = sg_dma_len(sg_entry) / configure_info.desc_page_size;
        desc_buffer_addr = sg_dma_address(sg_entry);
        for (desc_in_sg = 0; desc_in_sg < desc_per_sg; desc_in_sg++) {
            encoded_addr = controller->ops->encode_desc_dma_address(desc_buffer_addr, channel_id);
            if (INVALID_VDMA_ADDRESS == encoded_addr) {
                hailo_dev_err(controller->dev, "Failed encoding dma address %pad for channel %u\n",
                    &desc_buffer_addr, configure_info.channel_index);
                return -EINVAL;
            }

            hailo_vdma_program_descriptor(&dma_desc[desc_index % descriptors_buffer->desc_count], encoded_addr,
                configure_info.desc_page_size, data_id);

            desc_buffer_addr += configure_info.desc_page_size;
            desc_index++;
        }
    }
    return 0;
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

    low_memory_buffer = hailo_vdma_get_low_memory_buffer(context, buf_handle);
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
        hailo_dev_err(controller->dev, "failed allocating continuous buffer\n");
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

    continuous_buffer = hailo_vdma_get_continuous_buffer(context, buf_handle);
    if (NULL == continuous_buffer) {
        hailo_dev_warn(controller->dev, "vdma buffer handle %lx not found\n", buf_handle);
        return -EINVAL;
    }

    list_del(&continuous_buffer->continuous_buffer_list);
    hailo_vdma_continuous_buffer_free(controller->dev, continuous_buffer);
    kfree(continuous_buffer);
    return 0;
}
