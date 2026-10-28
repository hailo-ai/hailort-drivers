// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
 **/
/**
 * vDMA memory utility (including allocation and mappings)
 */

#ifndef _HAILO_VDMA_MEMORY_H_
#define _HAILO_VDMA_MEMORY_H_

#include "vdma/vdma.h"

struct hailo_vdma_mapped_buffer *hailo_vdma_map_buffer(struct device *dev, uintptr_t user_address, size_t size,
    enum dma_data_direction direction, enum hailo_dma_buffer_type buffer_type);
void hailo_vdma_mapped_buffer_destroy(struct hailo_vdma_mapped_buffer *buf);
void hailo_vdma_mapped_buffer_get(struct hailo_vdma_mapped_buffer *buf);
void hailo_vdma_mapped_buffer_put(struct hailo_vdma_mapped_buffer *buf);

void hailo_vdma_mapped_buffer_sync(struct device *dev,
    struct hailo_vdma_mapped_buffer *mapped_buffer, enum hailo_vdma_buffer_sync_type sync_type,
    size_t offset, size_t size);

struct hailo_vdma_mapped_buffer* hailo_vdma_find_mapped_buffer_by_fd(struct hailo_vdma_context *context,
    uintptr_t fd, size_t total_size, enum dma_data_direction direction);
struct hailo_vdma_mapped_buffer* hailo_vdma_find_mapped_buffer_by_address(struct hailo_vdma_context *context,
    uintptr_t user_addres, size_t size, enum dma_data_direction direction);
struct hailo_vdma_mapped_buffer* hailo_vdma_find_mapped_buffer_by_exact_address(struct hailo_vdma_context *context,
    uintptr_t user_addres, size_t size, enum dma_data_direction direction);
struct hailo_vdma_mapped_buffer* hailo_vdma_find_mapped_buffer_by_handle(struct hailo_vdma_context *context,
    size_t buffer_handle);
void hailo_vdma_clear_mapped_user_buffer_list(struct hailo_vdma_context *context);

int hailo_vdma_buffer_alloc(struct device *dev, size_t size, struct hailo_vdma_buffer *buffer);
void hailo_vdma_buffer_free(struct device *dev, struct hailo_vdma_buffer *buffer);

struct hailo_vdma_descriptors_list *hailo_desc_list_alloc(struct device *dev, u32 descs_count, u16 desc_page_size);
void hailo_desc_list_free(struct device *dev, struct hailo_vdma_descriptors_list *desc_list);

struct hailo_vdma_descriptors_list *hailo_vdma_add_desc_list(struct hailo_vdma_context *context,
    u32 descs_count, u16 desc_page_size, uintptr_t *desc_handle);
struct hailo_vdma_descriptors_list *hailo_vdma_get_desc_list(struct hailo_vdma_context *context,
    uintptr_t desc_handle);
int hailo_vdma_remove_desc_list(struct hailo_vdma_context *context, uintptr_t desc_handle);
void hailo_vdma_clear_desc_lists(struct hailo_vdma_context *context);

struct hailo_vdma_buffer *hailo_vdma_add_continuous_buffer(struct hailo_vdma_context *context, size_t size,
    uintptr_t *buffer_handle);
struct hailo_vdma_buffer *hailo_vdma_get_continuous_buffer(struct hailo_vdma_context *context,
    uintptr_t buffer_handle);
int hailo_vdma_remove_continuous_buffer(struct hailo_vdma_context *context, uintptr_t buffer_handle);
void hailo_vdma_clear_continuous_buffers(struct hailo_vdma_context *context);
#endif /* _HAILO_VDMA_MEMORY_H_ */
