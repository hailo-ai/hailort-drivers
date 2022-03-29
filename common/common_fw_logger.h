// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_COMMON_FIRMWARE_LOGGER_H_
#define _HAILO_COMMON_FIRMWARE_LOGGER_H_

#include "types.h"
#include "hailo_resource.h"

typedef struct {
    uint32_t host_offset;
    uint32_t chip_offset;
} FW_DEBUG_BUFFER_HEADER_t;

#define DEBUG_BUFFER_TOTAL_SIZE (4*1024)
#define DEBUG_BUFFER_DATA_SIZE (DEBUG_BUFFER_TOTAL_SIZE - sizeof(FW_DEBUG_BUFFER_HEADER_t))

long hailo_read_firmware_log(struct hailo_resource *fw_logger_resource, struct hailo_read_log_params *params);

#endif /* _HAILO_COMMON_FIRMWARE_LOGGER_H_ */
