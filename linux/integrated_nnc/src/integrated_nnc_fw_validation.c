// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include "integrated_nnc_fw_validation.h"
#include <asm-generic/errno-base.h>

#include "logs.h"

#define MAXIMUM_CORE_FIRMWARE_CODE_SIZE (0x200000)


int FW_VALIDATION__validate_fw_headers(
    struct hailo_board *board,
    uintptr_t firmware_base_address, u32 firmware_size,
    firmware_header_t **out_firmware_header,
    secure_boot_certificate_header_t **out_firmware_cert)
{
    firmware_header_t *firmware_header = NULL;
    secure_boot_certificate_header_t *firmware_cert = NULL;
    int err = -EINVAL;
    u32 consumed_firmware_offset = 0;

    err = FW_VALIDATION__validate_fw_header(firmware_base_address, firmware_size, MAXIMUM_CORE_FIRMWARE_CODE_SIZE,
        &consumed_firmware_offset, &firmware_header, board->board_data->board_type);
    if (0 != err) {
        hailo_err(board, "Failed validating fw header");
        err = -EINVAL;
        goto exit;
    }

    err = FW_VALIDATION__validate_cert_header(firmware_base_address, firmware_size,
        &consumed_firmware_offset, &firmware_cert);
    if (0 != err) {
        hailo_err(board, "Failed validating fw certificate");
        err = -EINVAL;
        goto exit;
    }

    if (consumed_firmware_offset != firmware_size) {
        /* it is an error if there is leftover data after the last firmware header */
        hailo_err(board, "Firmware is larger then the declared firmware size");
        err = -EINVAL;
        goto exit;
    }

    /* the out params are all optional */
    if (NULL != out_firmware_header) {
        *out_firmware_header = firmware_header;
    }
    if (NULL != out_firmware_cert) {
        *out_firmware_cert = firmware_cert;
    }
    err = 0;

exit:
    return err;
}
