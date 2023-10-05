// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef PCIE_COMMON_FIRMWARE_HEADER_UTILS_H_
#define PCIE_COMMON_FIRMWARE_HEADER_UTILS_H_

#include "hailo_ioctl_common.h"

#define FIRMWARE_HEADER_MAGIC_HAILO8 (0x1DD89DE0)
#define FIRMWARE_HEADER_MAGIC_HAILO15 (0xE905DAAB)
// TODO - HRT-11344 : change fw magic to pluto specific
#define FIRMWARE_HEADER_MAGIC_PLUTO (0xE905DAAB)

#ifndef HAILO_EMULATOR
#define FIRMWARE_WAIT_TIMEOUT_MS (5000)
#else /* ifndef HAILO_EMULATOR */
#define FIRMWARE_WAIT_TIMEOUT_MS (500000)
#endif /* ifndef HAILO_EMULATOR */

typedef enum {
    FIRMWARE_HEADER_VERSION_INITIAL = 0,

    /* MUST BE LAST */
    FIRMWARE_HEADER_VERSION_COUNT
} firmware_header_version_t;

typedef struct {
    uint32_t magic;
    uint32_t header_version;
    uint32_t firmware_major;
    uint32_t firmware_minor;
    uint32_t firmware_revision;
    uint32_t code_size;
} firmware_header_t;


#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4200)
#endif /* _MSC_VER */

typedef struct {
    uint32_t key_size;
    uint32_t content_size;
    uint8_t certificates_data[0];
} secure_boot_certificate_t;

#ifdef _MSC_VER
#pragma warning(pop)
#endif /* _MSC_VER */

#define MINIMUM_FIRMWARE_CODE_SIZE (20*4)
#define MAXIMUM_FIRMWARE_CERT_KEY_SIZE (0x1000)
#define MAXIMUM_FIRMWARE_CERT_CONTENT_SIZE (0x1000)

int FW_VALIDATION__validate_fw_header(uintptr_t firmware_base_address,
    size_t firmware_size, uint32_t max_code_size, uint32_t *outer_consumed_firmware_offset,
    firmware_header_t **out_firmware_header, enum hailo_board_type board_type);

int FW_VALIDATION__validate_cert_header(uintptr_t firmware_base_address,
    size_t firmware_size, uint32_t *outer_consumed_firmware_offset, secure_boot_certificate_t **out_firmware_cert);

#endif