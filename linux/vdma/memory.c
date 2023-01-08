// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#define pr_fmt(fmt) "hailo: " fmt

#include "memory.h"
#include "utils/compact.h"

#include <linux/slab.h>
#include <linux/scatterlist.h>


#define SGL_MAX_SEGMENT_SIZE 	(0x10000)

static int hailo_set_sg_list(struct sg_table *sg_table, void __user* user_address, uint32_t size,
    struct hailo_vdma_low_memory_buffer *allocated_vdma_buffer);
static void hailo_clear_sg_list(struct sg_table *sgt, bool put_pages);

int hailo_vdma_buffer_map(struct device *dev, void __user *user_address, uint32_t size, 
    enum dma_data_direction data_direction, struct hailo_vdma_buffer *mapped_buffer,
    struct hailo_vdma_low_memory_buffer *allocated_vdma_buffer)
{
    int err = -EINVAL;

    err = hailo_set_sg_list(&mapped_buffer->sg_table, user_address, size, allocated_vdma_buffer);
    if (err < 0) {
        dev_err(dev, "failed to set sg list for user buffer %d\n", err);
        return err;
    }

    mapped_buffer->sg_table.nents = dma_map_sg(dev,
        mapped_buffer->sg_table.sgl, mapped_buffer->sg_table.orig_nents, data_direction);
    if (0 == mapped_buffer->sg_table.nents) {
        dev_err(dev, "failed to map sg list for user buffer\n");
        hailo_clear_sg_list(&mapped_buffer->sg_table, (NULL == allocated_vdma_buffer));
        return -ENXIO;
    }

    mapped_buffer->user_address = user_address;
    mapped_buffer->size = size;
    mapped_buffer->data_direction = data_direction;

    return 0;
}

void hailo_vdma_buffer_unmap(struct device *dev, struct hailo_vdma_buffer *mapped_buffer)
{
    dma_unmap_sg(dev, mapped_buffer->sg_table.sgl,
        mapped_buffer->sg_table.orig_nents, mapped_buffer->data_direction);
    
    // Check if clearing for user space buffer or driver allocated buffer
    if (INVALID_DRIVER_HANDLE_VALUE == mapped_buffer->driver_buffer_handle) {
        hailo_clear_sg_list(&mapped_buffer->sg_table, true);
    }
    else {
        hailo_clear_sg_list(&mapped_buffer->sg_table, false);
    }
}

struct hailo_vdma_buffer* hailo_vdma_get_mapped_user_buffer(struct hailo_vdma_file_context *context,
    size_t buffer_handle)
{
    struct hailo_vdma_buffer *cur = NULL;
    list_for_each_entry(cur, &context->mapped_user_buffer_list, mapped_user_buffer_list) {
        if (cur->handle == buffer_handle) {
            return cur;
        }
    }
    return NULL;
}

void hailo_vdma_clear_mapped_user_buffer_list(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller)
{
    struct hailo_vdma_buffer *cur = NULL, *next = NULL;
    list_for_each_entry_safe(cur, next, &context->mapped_user_buffer_list, mapped_user_buffer_list) {
        list_del(&cur->mapped_user_buffer_list);
        hailo_vdma_buffer_unmap(controller->dev, cur);
        kfree(cur);
    }
}


int hailo_desc_list_create(struct device *dev, uint32_t descriptors_count, uintptr_t desc_handle,
    struct hailo_descriptors_list *descriptors)
{
    size_t buffer_size = 0;
    const u64 align = VDMA_DESCRIPTOR_LIST_ALIGN; //First addr must be aligned on 64 KB  (from the VDMA registers documentation)

    buffer_size = descriptors_count * sizeof(struct hailo_vdma_descriptor);
    buffer_size = ALIGN(buffer_size, align);

    descriptors->kernel_address = dma_alloc_coherent(dev, buffer_size,
        &descriptors->dma_address, GFP_KERNEL | __GFP_ZERO);
    if (descriptors->kernel_address == NULL) {
        dev_err(dev, "Failed to allocate descriptors list, desc_count 0x%x, buffer_size 0x%zx\n",
            descriptors_count, buffer_size);
        return -ENOMEM;
    }

    descriptors->desc_count = descriptors_count;
    descriptors->buffer_size = buffer_size;
    descriptors->handle = desc_handle;

    return 0;
}

void hailo_desc_list_release(struct device *dev, struct hailo_descriptors_list *descriptors)
{
    dma_free_coherent(dev, descriptors->buffer_size, descriptors->kernel_address, descriptors->dma_address);
}

struct hailo_descriptors_list* hailo_vdma_get_descriptors_buffer(struct hailo_vdma_file_context *context,
    uintptr_t desc_handle)
{
    struct hailo_descriptors_list *cur = NULL;
    list_for_each_entry(cur, &context->descriptors_buffer_list, descriptors_buffer_list) {
        if (cur->handle == desc_handle) {
            return cur;
        }
    }
    return NULL;
}

void hailo_vdma_clear_descriptors_buffer_list(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller)
{
    struct hailo_descriptors_list *cur = NULL, *next = NULL;
    list_for_each_entry_safe(cur, next, &context->descriptors_buffer_list, descriptors_buffer_list) {
        list_del(&cur->descriptors_buffer_list);
        hailo_desc_list_release(controller->dev, cur);
        kfree(cur);
    }
}

int hailo_vdma_low_memory_buffer_alloc(size_t size, struct hailo_vdma_low_memory_buffer *low_memory_buffer)
{
    void *kernel_address = NULL;
    size_t pages_count = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    size_t num_allocated = 0, i = 0;
    void **pages = NULL;
    int err = -EINVAL;

    pages = kcalloc(pages_count, sizeof(*pages), GFP_KERNEL);
    if (NULL == pages) {
        pr_err("Failed to allocate pages for buffer (size %zu)", size);
        err = -ENOMEM;
        goto cleanup;
    }

    for (num_allocated = 0; num_allocated < pages_count; num_allocated++) {
        // __GFP_DMA32 flag is used to limit system memory allocations to the lowest 4 GB of physical memory in order to guarantee DMA 
        // Operations will not have to use bounce buffers on certain architectures (e.g 32-bit DMA enabled architectures)
        kernel_address = (void*)__get_free_page(__GFP_DMA32);
        if (NULL == kernel_address) {
            pr_err("Failed to allocate %zu coherent bytes\n", (size_t)PAGE_SIZE);
            err = -ENOMEM;
            goto cleanup;
        }

        pages[num_allocated] = kernel_address;
    }

    low_memory_buffer->pages_count = pages_count;
    low_memory_buffer->pages_address = pages;

    return 0;

cleanup:
    if (NULL != pages) {
        for (i = 0; i < num_allocated; i++) {
            free_page((long unsigned)pages[i]);
        }

        kfree(pages);
    }

    return err;
}

void hailo_vdma_low_memory_buffer_free(struct hailo_vdma_low_memory_buffer *low_memory_buffer)
{
    size_t i = 0;
    if (NULL == low_memory_buffer) {
        return;
    }

    for (i = 0; i < low_memory_buffer->pages_count; i++) {
        free_page((long unsigned)low_memory_buffer->pages_address[i]);
    }

    kfree(low_memory_buffer->pages_address);
}

struct hailo_vdma_low_memory_buffer* hailo_vdma_get_low_memory_buffer(struct hailo_vdma_file_context *context,
    uintptr_t buf_handle)
{
    struct hailo_vdma_low_memory_buffer *cur = NULL;
    list_for_each_entry(cur, &context->vdma_low_memory_buffer_list, vdma_low_memory_buffer_list) {
        if (cur->handle == buf_handle) {
            return cur;
        }
    }

    return NULL;
}

void hailo_vdma_clear_low_memory_buffer_list(struct hailo_vdma_file_context *context)
{
    struct hailo_vdma_low_memory_buffer *cur = NULL, *next = NULL;
    list_for_each_entry_safe(cur, next, &context->vdma_low_memory_buffer_list, vdma_low_memory_buffer_list) {
        list_del(&cur->vdma_low_memory_buffer_list);
        hailo_vdma_low_memory_buffer_free(cur);
        kfree(cur);
    }
}

int hailo_vdma_continuous_buffer_alloc(struct device *dev, size_t size,
    struct hailo_vdma_continuous_buffer *continuous_buffer)
{
    dma_addr_t dma_address = 0;
    void *kernel_address = NULL;

    kernel_address = dma_alloc_coherent(dev, size, &dma_address, GFP_KERNEL);
    if (NULL == kernel_address) {
        dev_err(dev, "Failed to allocate continuous buffer, size 0x%zx\n", size);
        return -ENOMEM;
    }

    continuous_buffer->kernel_address = kernel_address;
    continuous_buffer->dma_address = dma_address;
    continuous_buffer->size = size;
    return 0;
}

void hailo_vdma_continuous_buffer_free(struct device *dev,
    struct hailo_vdma_continuous_buffer *continuous_buffer)
{
    dma_free_coherent(dev, continuous_buffer->size, continuous_buffer->kernel_address,
        continuous_buffer->dma_address);
}

struct hailo_vdma_continuous_buffer* hailo_vdma_get_continuous_buffer(struct hailo_vdma_file_context *context,
    uintptr_t buf_handle)
{
    struct hailo_vdma_continuous_buffer *cur = NULL;
    list_for_each_entry(cur, &context->continuous_buffer_list, continuous_buffer_list) {
        if (cur->handle == buf_handle) {
            return cur;
        }
    }

    return NULL;
}

void hailo_vdma_clear_continuous_buffer_list(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller)
{
    struct hailo_vdma_continuous_buffer *cur = NULL, *next = NULL;
    list_for_each_entry_safe(cur, next, &context->continuous_buffer_list, continuous_buffer_list) {
        list_del(&cur->continuous_buffer_list);
        hailo_vdma_continuous_buffer_free(controller->dev, cur);
        kfree(cur);
    }
}

static int hailo_set_sg_list(struct sg_table *sg_table, void __user *user_address, uint32_t size,
    struct hailo_vdma_low_memory_buffer *allocated_vdma_buffer)
{
    int  nPages, result;
    struct page **pages;
    int i = 0;
    struct scatterlist *sg_alloc_res = NULL;

    nPages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    if ( !(pages = kmalloc(nPages * sizeof(*pages), GFP_KERNEL)) )
    {
        return -ENOMEM;
    }

    // Check weather mapping user allocated buffer or driver allocated buffer
    if (NULL == allocated_vdma_buffer) {
        mmap_read_lock(current->mm);
        result = get_user_pages_compact((unsigned long)user_address, nPages, FOLL_WRITE | FOLL_FORCE, pages, NULL);
        mmap_read_unlock(current->mm);

        if (result != nPages) {
            kfree(pages);
            return -EINVAL;
        }
    }
    // Meaning buffer we are mapping is driver allocated
    else {
        // Check to make sure in case user provides wrong buffer
        if ((size_t)nPages != allocated_vdma_buffer->pages_count) {
            pr_err("Recieved wrong amount of pages to map - user may have provided wrong buffer\n");
            return -EINVAL;
        }
        for (i = 0; i < nPages; i++) {
            pages[i] = virt_to_page(allocated_vdma_buffer->pages_address[i]);
        }
    }

    sg_alloc_res = sg_alloc_table_from_pages_segment_compat(sg_table, pages, nPages,
        0, size, SGL_MAX_SEGMENT_SIZE, NULL, 0, GFP_KERNEL);
    if (IS_ERR(sg_alloc_res)) {
        pr_err("sg table alloc failed (err %ld)..\n", PTR_ERR(sg_alloc_res));
        if (NULL == allocated_vdma_buffer) {
            for (i = 0; i < nPages; i++) {
                if (!PageReserved(pages[i])) {
                    SetPageDirty(pages[i]);
                }
                put_page(pages[i]);
            }
        }

        kfree(pages);
        return PTR_ERR(sg_alloc_res);
    }

    kfree(pages);
    return 0;
}

static void hailo_clear_sg_list(struct sg_table *sgt, bool put_pages) 
{
    struct sg_page_iter iter;
    struct page *page = NULL;

    if (put_pages) {
        for_each_sg_page(sgt->sgl, &iter, sgt->orig_nents, 0) {
            page = sg_page_iter_page(&iter);
            if (!PageReserved(page)) {
                SetPageDirty(page);
            }
            put_page(page);
        }
    }

    sg_free_table(sgt);
}

bool hailo_buffer_to_device(struct hailo_vdma_buffer *mapped_buffer)
{
    return (mapped_buffer->data_direction == DMA_BIDIRECTIONAL || 
        mapped_buffer->data_direction == DMA_TO_DEVICE);
}

bool hailo_buffer_from_device(struct hailo_vdma_buffer *mapped_buffer)
{
    return (mapped_buffer->data_direction == DMA_BIDIRECTIONAL || 
        mapped_buffer->data_direction == DMA_FROM_DEVICE);
}