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

static long read_resource_to_user(struct hailo_resource *fw_logger_resource, size_t src_offset, uintptr_t user_buffer,
    size_t user_buffer_size)
{
    uintptr_t dest = user_buffer; 
    size_t remaining = user_buffer_size;

// This function (read_resource_to_user) and hailo_read_firmware_log() are only used in __linux__, but are implemented in 
// common because we want to implement them for windows as well
#ifdef __linux__
    if (!compatible_access_ok(VERIFY_WRITE, (void *)user_buffer, user_buffer_size)) {
        return -EFAULT;
    }
#endif // ifdef __linux__

    while(remaining > 0)
    {
        if (remaining >= 4 && ((fw_logger_resource->address + src_offset) % 4) == 0) {
            uint32_t dword = hailo_resource_read32(fw_logger_resource, src_offset);

            if (copy_to_user((void*)dest, &dword, sizeof(dword))) {
                return -ENOMEM;
            }
            src_offset += 4;
            dest += 4;
            remaining -= 4;
        } else if (remaining >= 2 && ((fw_logger_resource->address + src_offset) % 2) == 0) {
            uint16_t word = hailo_resource_read16(fw_logger_resource, src_offset);
            if (copy_to_user((void*)dest, &word, sizeof(word))) {
                return -ENOMEM;
            }
            src_offset += 2;
            dest += 2;
            remaining -= 2;
        } else {
            uint8_t byte = hailo_resource_read8(fw_logger_resource, src_offset);
            if (copy_to_user((void*)dest, &byte, sizeof(byte))) {
                return -ENOMEM;
            }

            src_offset += 1;
            dest += 1;
            remaining -= 1;
        }
    }

    return 0;
}

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
    long err = 0;
    FW_DEBUG_BUFFER_HEADER_t debug_buffer_header = {0};
    size_t read_offset = 0;
    size_t ready_to_read = 0;
    size_t size_to_read = 0;
    uintptr_t user_buffer = (uintptr_t)params->buffer;

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
        if (0 > (err = read_resource_to_user(fw_logger_resource, read_offset, user_buffer, size_to_read))) {
            return err;
        }

        user_buffer += size_to_read;
        size_to_read = ready_to_read - size_to_read;
        /* Point back to the beginning of the data buffer. */
        read_offset -= debug_buffer_header.host_offset;
    }
    else {
        size_to_read = ready_to_read;
    }

    /* size_to_read may become 0 if the read reached DEBUG_BUFFER_DATA_SIZE exactly */
    if (size_to_read > 0) {
        if (0 > (err = read_resource_to_user(fw_logger_resource, read_offset, user_buffer, size_to_read))) {
            return err;
        }
    }

    /* Change current_offset to represent the new host offset. */
    read_offset += size_to_read;
    hailo_resource_write32(fw_logger_resource, offsetof(FW_DEBUG_BUFFER_HEADER_t, host_offset),
        (uint32_t)(read_offset - sizeof(debug_buffer_header)));
    
    params->read_bytes = ready_to_read;
    return 0;
}