// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/
/**
 * vDMA memory utility (including allocation and mappings)
 */

#ifndef _HAILO_VDMA_MEMORY_H_
#define _HAILO_VDMA_MEMORY_H_

#include "vdma/vdma.h"

int hailo_vdma_buffer_map(struct device *dev, void __user *user_address, uint32_t size,
    enum dma_data_direction data_direction, struct hailo_vdma_buffer *mapped_buffer,
    struct hailo_vdma_low_memory_buffer *allocated_vdma_buffer);
void hailo_vdma_buffer_unmap(struct device *dev, struct hailo_vdma_buffer *mapped_buffer);
struct hailo_vdma_buffer* hailo_vdma_get_mapped_user_buffer(struct hailo_vdma_file_context *context,
    size_t buffer_handle);
void hailo_vdma_clear_mapped_user_buffer_list(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller);

int hailo_desc_list_create(struct device *dev, uint32_t descriptors_count, uintptr_t desc_handle,
    struct hailo_descriptors_list *descriptors);
void hailo_desc_list_release(struct device *dev, struct hailo_descriptors_list *descriptors);
struct hailo_descriptors_list* hailo_vdma_get_descriptors_buffer(struct hailo_vdma_file_context *context,
    uintptr_t desc_handle);
void hailo_vdma_clear_descriptors_buffer_list(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller);

int hailo_vdma_low_memory_buffer_alloc(size_t size, struct hailo_vdma_low_memory_buffer *low_memory_buffer);
void hailo_vdma_low_memory_buffer_free(struct hailo_vdma_low_memory_buffer *low_memory_buffer);
struct hailo_vdma_low_memory_buffer* hailo_vdma_get_low_memory_buffer(struct hailo_vdma_file_context *context,
    uintptr_t buf_handle);
void hailo_vdma_clear_low_memory_buffer_list(struct hailo_vdma_file_context *context);

int hailo_vdma_continuous_buffer_alloc(struct device *dev, size_t size,
    struct hailo_vdma_continuous_buffer *continuous_buffer);
void hailo_vdma_continuous_buffer_free(struct device *dev,
    struct hailo_vdma_continuous_buffer *continuous_buffer);
struct hailo_vdma_continuous_buffer* hailo_vdma_get_continuous_buffer(struct hailo_vdma_file_context *context,
    uintptr_t buf_handle);
void hailo_vdma_clear_continuous_buffer_list(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller);
bool hailo_buffer_to_device(struct hailo_vdma_buffer *mapped_buffer);
bool hailo_buffer_from_device(struct hailo_vdma_buffer *mapped_buffer);
#endif /* _HAILO_VDMA_MEMORY_H_ */