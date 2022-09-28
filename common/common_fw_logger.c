// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#include "types.h"
#include "common_fw_logger.h"
#include "hailo_resource.h"

#ifdef __linux__
#if LINUX_VERSION_CODE >= KERNEL_VERSION( 5, 0, 0 )
#define compatible_access_ok(a,b,c) access_ok(b, c)
#else
#define compatible_access_ok(a,b,c) access_ok(a, b, c)
#endif

#endif // ifdef __linux__

static inline size_t calculate_log_ready_to_read(FW_DEBUG_BUFFER_HEADER_t *header)
{
    size_t ready_to_read = 0;
    size_t host_offset = header->host_offset;
    size_t chip_offset = header->chip_offset;

    if (chip_offset >= host_offset) {
        ready_to_read = chip_offset - host_offset;
    } else {
        ready_to_read = DEBUG_BUFFER_DATA_SIZE - (host_offset - chip_offset);
    }

    return ready_to_read;
}

long hailo_read_firmware_log(struct hailo_resource *fw_logger_resource, struct hailo_read_log_params *params)
{
    FW_DEBUG_BUFFER_HEADER_t debug_buffer_header = {0};
    size_t read_offset = 0;
    size_t ready_to_read = 0;
    size_t size_to_read = 0;
    uintptr_t user_buffer = (uintptr_t)params->buffer;

    if (params->buffer_size > ARRAY_SIZE(params->buffer)) {
        return -EINVAL;
    }

    hailo_resource_read_buffer(fw_logger_resource, 0, sizeof(debug_buffer_header),
        &debug_buffer_header);

    /* Point to the start of the data buffer. */
    ready_to_read = calculate_log_ready_to_read(&debug_buffer_header);
    if (0 == ready_to_read) {
        params->read_bytes = 0;
        return 0;
    }
    /* If ready to read is bigger than the buffer size, read only buffer size bytes. */
    ready_to_read = min(ready_to_read, params->buffer_size);
    
    /* Point to the data that is read to be read by the host. */
    read_offset = sizeof(debug_buffer_header) + debug_buffer_header.host_offset;
    /* Check if the offset should cycle back to beginning. */
    if (DEBUG_BUFFER_DATA_SIZE <= debug_buffer_header.host_offset + ready_to_read) {
        size_to_read = DEBUG_BUFFER_DATA_SIZE - debug_buffer_header.host_offset;
        hailo_resource_read_buffer(fw_logger_resource, read_offset, size_to_read, (void*)user_buffer);

        user_buffer += size_to_read;
        size_to_read = ready_to_read - size_to_read;
        /* Point back to the beginning of the data buffer. */
        read_offset -= debug_buffer_header.host_offset;
    }
    else {
        size_to_read = ready_to_read;
    }

    /* size_to_read may become 0 if the read reached DEBUG_BUFFER_DATA_SIZE exactly */
    hailo_resource_read_buffer(fw_logger_resource, read_offset, size_to_read, (void*)user_buffer);

    /* Change current_offset to represent the new host offset. */
    read_offset += size_to_read;
    hailo_resource_write32(fw_logger_resource, offsetof(FW_DEBUG_BUFFER_HEADER_t, host_offset),
        (uint32_t)(read_offset - sizeof(debug_buffer_header)));
    
    params->read_bytes = ready_to_read;
    return 0;
}