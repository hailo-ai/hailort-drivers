// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#define pr_fmt(fmt) "hailo: " fmt

#include "memory.h"
#include "utils/compact.h"

#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/sched.h>


#define SGL_MAX_SEGMENT_SIZE 	(0x10000)

static int prepare_sg_table(struct sg_table *sg_table, void __user* user_address, uint32_t size,
    struct hailo_vdma_low_memory_buffer *allocated_vdma_buffer);
static void clear_sg_table(struct sg_table *sgt, bool put_pages);

struct hailo_vdma_buffer *hailo_vdma_buffer_map(struct device *dev,
    void __user *user_address, size_t size, enum dma_data_direction direction,
    struct hailo_vdma_low_memory_buffer *allocated_vdma_buffer)
{
    int ret = -EINVAL;
    struct hailo_vdma_buffer *mapped_buffer = NULL;
    struct sg_table sgt = {0};

    mapped_buffer = kzalloc(sizeof(*mapped_buffer), GFP_KERNEL);
    if (NULL == mapped_buffer) {
        dev_err(dev, "memory alloc failed\n");
        ret = -ENOMEM;
        goto cleanup;
    }

    ret = prepare_sg_table(&sgt, user_address, size, allocated_vdma_buffer);
    if (ret < 0) {
        dev_err(dev, "failed to set sg list for user buffer %d\n", ret);
        goto free_buffer_struct;
    }

    sgt.nents = dma_map_sg(dev, sgt.sgl, sgt.orig_nents, direction);
    if (0 == sgt.nents) {
        dev_err(dev, "failed to map sg list for user buffer\n");
        ret = -ENXIO;
        goto clear_sg_table;
    }

    kref_init(&mapped_buffer->kref);
    mapped_buffer->device = dev;
    mapped_buffer->user_address = user_address;
    mapped_buffer->size = size;
    mapped_buffer->data_direction = direction;
    mapped_buffer->sg_table = sgt;
    mapped_buffer->driver_buffer_handle = allocated_vdma_buffer ?
        (allocated_vdma_buffer->handle) : INVALID_DRIVER_HANDLE_VALUE;
    return mapped_buffer;

clear_sg_table:
    clear_sg_table(&sgt, (NULL == allocated_vdma_buffer));
free_buffer_struct:
    kfree(mapped_buffer);
cleanup:
    return ERR_PTR(ret);
}

static void unmap_buffer(struct kref *kref)
{
    bool put_pages = false;
    struct hailo_vdma_buffer *buf = container_of(kref, struct hailo_vdma_buffer, kref);

    dma_unmap_sg(buf->device, buf->sg_table.sgl, buf->sg_table.orig_nents,
        buf->data_direction);

    put_pages = ((INVALID_DRIVER_HANDLE_VALUE) == buf->driver_buffer_handle);
    clear_sg_table(&buf->sg_table, put_pages);
}

void hailo_vdma_buffer_get(struct hailo_vdma_buffer *buf)
{
    kref_get(&buf->kref);
}

void hailo_vdma_buffer_put(struct hailo_vdma_buffer *buf)
{
    kref_put(&buf->kref, unmap_buffer);
}

struct hailo_vdma_buffer* hailo_vdma_find_mapped_user_buffer(struct hailo_vdma_file_context *context,
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
        hailo_vdma_buffer_put(cur);
    }
}


int hailo_desc_list_create(struct device *dev, uint32_t descriptors_count, uintptr_t desc_handle, bool is_circular,
    struct hailo_descriptors_list_buffer *descriptors)
{
    size_t buffer_size = 0;
    const u64 align = VDMA_DESCRIPTOR_LIST_ALIGN; //First addr must be aligned on 64 KB  (from the VDMA registers documentation)

    buffer_size = descriptors_count * sizeof(struct hailo_vdma_descriptor);
    buffer_size = ALIGN(buffer_size, align);

    descriptors->kernel_address = dma_alloc_coherent(dev, buffer_size,
        &descriptors->dma_address, GFP_KERNEL | __GFP_ZERO);
    if (descriptors->kernel_address == NULL) {
        dev_err(dev, "Failed to allocate descriptors list, desc_count 0x%x, buffer_size 0x%zx, This failure means there is not a sufficient amount of CMA memory "
            "(contiguous physical memory), This usually is caused by lack of general system memory. Please check you have sufficent memory.\n",
            descriptors_count, buffer_size);
        return -ENOMEM;
    }

    descriptors->buffer_size = buffer_size;
    descriptors->handle = desc_handle;

    descriptors->desc_list.desc_list = descriptors->kernel_address;
    descriptors->desc_list.desc_count = descriptors_count;
    descriptors->desc_list.is_circular = is_circular;

    return 0;
}

void hailo_desc_list_release(struct device *dev, struct hailo_descriptors_list_buffer *descriptors)
{
    dma_free_coherent(dev, descriptors->buffer_size, descriptors->kernel_address, descriptors->dma_address);
}

struct hailo_descriptors_list_buffer* hailo_vdma_find_descriptors_buffer(struct hailo_vdma_file_context *context,
    uintptr_t desc_handle)
{
    struct hailo_descriptors_list_buffer *cur = NULL;
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
    struct hailo_descriptors_list_buffer *cur = NULL, *next = NULL;
    list_for_each_entry_safe(cur, next, &context->descriptors_buffer_list, descriptors_buffer_list) {
        list_del(&cur->descriptors_buffer_list);
        hailo_desc_list_release(controller->dev, cur);
        kfree(cur);
    }
}

int hailo_vdma_low_memory_buffer_alloc(size_t size, struct hailo_vdma_low_memory_buffer *low_memory_buffer)
{
    int ret = -EINVAL;
    void *kernel_address = NULL;
    size_t pages_count = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    size_t num_allocated = 0, i = 0;
    void **pages = NULL;

    pages = kcalloc(pages_count, sizeof(*pages), GFP_KERNEL);
    if (NULL == pages) {
        pr_err("Failed to allocate pages for buffer (size %zu)", size);
        ret = -ENOMEM;
        goto cleanup;
    }

    for (num_allocated = 0; num_allocated < pages_count; num_allocated++) {
        // __GFP_DMA32 flag is used to limit system memory allocations to the lowest 4 GB of physical memory in order to guarantee DMA 
        // Operations will not have to use bounce buffers on certain architectures (e.g 32-bit DMA enabled architectures)
        kernel_address = (void*)__get_free_page(__GFP_DMA32);
        if (NULL == kernel_address) {
            pr_err("Failed to allocate %zu coherent bytes\n", (size_t)PAGE_SIZE);
            ret = -ENOMEM;
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

    return ret;
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

struct hailo_vdma_low_memory_buffer* hailo_vdma_find_low_memory_buffer(struct hailo_vdma_file_context *context,
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
        dev_warn(dev, "Failed to allocate continuous buffer, size 0x%zx. This failure means there is not a sufficient amount of CMA memory "
            "(contiguous physical memory), This usually is caused by lack of general system memory. Please check you have sufficent memory.\n", size);
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

struct hailo_vdma_continuous_buffer* hailo_vdma_find_continuous_buffer(struct hailo_vdma_file_context *context,
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

static int prepare_sg_table(struct sg_table *sg_table, void __user *user_address, uint32_t size,
    struct hailo_vdma_low_memory_buffer *allocated_vdma_buffer)
{
    int ret = -EINVAL;
    int pinned_pages = 0;
    size_t npages = 0;
    struct page **pages = NULL;
    int i = 0;
    struct scatterlist *sg_alloc_res = NULL;

    npages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    pages = kvmalloc_array(npages, sizeof(*pages), GFP_KERNEL);
    if (!pages) {
        return -ENOMEM;
    }

    // Check whether mapping user allocated buffer or driver allocated buffer
    if (NULL == allocated_vdma_buffer) {
        mmap_read_lock(current->mm);
        pinned_pages = get_user_pages_compact((unsigned long)user_address, npages, FOLL_WRITE | FOLL_FORCE, pages, NULL);
        mmap_read_unlock(current->mm);

        if (pinned_pages < 0) {
            pr_err("get_user_pages failed with %d\n", pinned_pages);
            ret = pinned_pages;
            goto exit;
        } else if (pinned_pages != npages) {
            pr_err("Pinned %d out of %zu\n", pinned_pages, npages);
            ret = -EINVAL;
            goto release_pages;
        }

    } else {
        // Check to make sure in case user provides wrong buffer
        if (npages != allocated_vdma_buffer->pages_count) {
            pr_err("Received wrong amount of pages %zu to map expected %zu\n",
                npages, allocated_vdma_buffer->pages_count);
            ret = -EINVAL;
            goto exit;
        }
        for (i = 0; i < npages; i++) {
            pages[i] = virt_to_page(allocated_vdma_buffer->pages_address[i]);
        }
    }

    sg_alloc_res = sg_alloc_table_from_pages_segment_compat(sg_table, pages, npages,
        0, size, SGL_MAX_SEGMENT_SIZE, NULL, 0, GFP_KERNEL);
    if (IS_ERR(sg_alloc_res)) {
        ret = PTR_ERR(sg_alloc_res);
        pr_err("sg table alloc failed (err %d)..\n", ret);
        goto release_pages;
    }

    ret = 0;
    goto exit;
release_pages:
    for (i = 0; i < pinned_pages; i++) {
        if (!PageReserved(pages[i])) {
            SetPageDirty(pages[i]);
        }
        put_page(pages[i]);
    }
exit:
    kvfree(pages);
    return ret;
}

static void clear_sg_table(struct sg_table *sgt, bool put_pages)
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
