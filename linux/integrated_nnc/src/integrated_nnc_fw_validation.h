// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _INTEGRATED_NNC_FW_VALIDATION_H_
#define _INTEGRATED_NNC_FW_VALIDATION_H_

#include "board.h"
#include "fw_validation.h"

/**
* Validates the FW headers.
* @param[in] board                      Board struct
* @param[in] address                    Address of the firmware.
* @param[in] firmware_size              Size of the firmware.
* @param[out] out_firmware_header   (optional) App firmware header
* @param[out] out_firmware_cert         (optional) Firmware certificate header
*/
int FW_VALIDATION__validate_fw_headers(
    struct hailo_board *board,
    uintptr_t firmware_base_address, u32 firmware_size,
    firmware_header_t **out_firmware_header,
    secure_boot_certificate_header_t **out_firmware_cert);

#endif //_INTEGRATED_NNC_FW_VALIDATION_H_