// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/types.h>
#include <linux/reset.h>
#include <linux/platform_device.h>
#include <linux/io.h>

#include "integrated_nnc_fw_validation.h"
#include "integrated_nnc_cpu.h"
#include "board.h"
#include "utils/integrated_nnc_utils.h"
#include "utils/logs.h"

static int hailo_write_core_firmware(struct hailo_board *board, firmware_header_t *fw_header)
{
    void *fw_code = NULL;
    void *fw_isr_vector = NULL;
    size_t fw_code_size;
    size_t fw_isr_vector_size;

    int err = -EINVAL;

    /* Make sure the resource is large enough to contain the data */
    if (board->integrated_nnc_cpu.fw_header.size < sizeof(firmware_header_t)) {
        hailo_err(board, "Memory resource for firmware header is not large enough. Should be at least 0x%zx bytes",
             sizeof(firmware_header_t));
        return -EINVAL;
    }

    if (board->integrated_nnc_cpu.fw_code.size + board->integrated_nnc_cpu.fw_isr_vector.size < fw_header->code_size) {
        hailo_err(board, "Memory resource for firmware code is not large enough. Should be at least 0x%x bytes",
             fw_header->code_size);
        return -EINVAL;
    }

    if (board->integrated_nnc_cpu.fw_isr_vector.size >= fw_header->code_size) {
        hailo_err(board, "firmware code size is to small. Should be at least 0x%zx bytes",
             board->integrated_nnc_cpu.fw_isr_vector.size);
        return -EINVAL;
    }

    err = reset_control_assert(board->integrated_nnc_cpu.reset);
    if (err < 0) {
        hailo_err(board, "Failed asserting core cpu reset, err %d\n", err);
        return err;
    }

    /* copy firmware header to mapped region */
    hailo_dbg(board, "write_buffer[fw_header]: to sram-virt[%lx] size %zx bytes from dram-virt[%lx]\n",
        board->integrated_nnc_cpu.fw_header.address, sizeof(firmware_header_t), (uintptr_t)fw_header);
    hailo_resource_write_buffer(&board->integrated_nnc_cpu.fw_header, 0,
        sizeof(firmware_header_t), fw_header);

    /* copy firmware code to mapped region (at this point the header was verified and we can trust the header declared size */
    fw_code = (void*)((u8*)fw_header + sizeof(firmware_header_t));
    fw_code_size = fw_header->code_size - board->integrated_nnc_cpu.fw_isr_vector.size;
    hailo_dbg(board, "write_buffer[fw_code]: to sram-virt[%lx] size %zx bytes from dram-virt[%lx]\n",
        board->integrated_nnc_cpu.fw_code.address, fw_code_size, (uintptr_t)fw_code);
    hailo_resource_write_buffer(&board->integrated_nnc_cpu.fw_code, 0,
        fw_code_size, fw_code);

    /* copy firmware isr_vectore to mapped region (at this point the header was verified and we can trust the header declared size */
    fw_isr_vector = (void*)((u8*)fw_header + sizeof(firmware_header_t) + fw_code_size);
    fw_isr_vector_size = board->integrated_nnc_cpu.fw_isr_vector.size;
    hailo_dbg(board, "write_buffer[fw_isr_vector]: to sram-virt[%lx] size %zx bytes from dram-virt[%lx]\n",
        board->integrated_nnc_cpu.fw_isr_vector.address, fw_isr_vector_size, (uintptr_t)fw_isr_vector);
    hailo_resource_write_buffer(&board->integrated_nnc_cpu.fw_isr_vector, 0,
        fw_isr_vector_size, fw_isr_vector);

    /* memory barrier just to make sure the firmware is fully written before we continue exectuion */
    mb();

    err = reset_control_deassert(board->integrated_nnc_cpu.reset);
    if (err < 0) {
        hailo_err(board, "Failed deasserting core cpu reset, err %d\n", err);
        return err;
    }

    return 0;
}

static bool hailo_wait_for_firmware(struct hailo_board *board)
{
    // TODO uncomment when hailo_is_firmware_loaded is implemented
    return true;
    // u32 retries = 0;
    // for (retries = 0; retries < FIRMWARE_LOAD_WAIT_MAX_RETRIES; retries++) {
    //     if (hailo_is_firmware_loaded(board)) {
    //         return true;
    //     }

    //     msleep(FIRMWARE_LOAD_SLEEP_MS);
    // }

    // return false;
}

int hailo_integrated_nnc_cpu_struct_init(struct hailo_board *board)
{
    int err = -EINVAL;
    struct hailo_resource fw_header = {};
    struct hailo_resource fw_code = {};
    struct hailo_resource fw_isr_vector = {};
    struct reset_control *cpu_reset = NULL;

    /* Retrieve core cpu reset from device-tree */
    cpu_reset = devm_reset_control_get_exclusive(&board->pDev->dev, "core-cpu");
    if (IS_ERR(cpu_reset)) {
        err = PTR_ERR(cpu_reset);
        hailo_err(board, "core cpu reset get failed: %d\n", err);
        return err;
    }

    err = hailo_ioremap_resource(board->pDev, &fw_header, "core-fw-data");
    if (err < 0) {
        hailo_err(board, "Failed ioremap fw header. err %d\n", err);
        return err;
    }

    err = hailo_ioremap_resource(board->pDev, &fw_code, "core-fw-code");
    if (err < 0) {
        hailo_err(board, "Failed ioremap fw code. err %d\n", err);
        return err;
    }

    err = hailo_ioremap_resource(board->pDev, &fw_isr_vector, "core-fw-isr-vector");
    if (err < 0) {
        hailo_err(board, "Failed ioremap fw isr-vector. err %d\n", err);
        return err;
    }
    board->integrated_nnc_cpu.reset = cpu_reset;
    board->integrated_nnc_cpu.fw_header = fw_header;
    board->integrated_nnc_cpu.fw_code = fw_code;
    board->integrated_nnc_cpu.fw_isr_vector = fw_isr_vector;

    /* Init nnc cpu usage ref count */
    atomic_set(&board->integrated_nnc_cpu.ref_count, 0);

    return 0;
}

int hailo_load_firmware(struct hailo_board *board)
{
    const struct firmware *firmware = NULL;
    int err = 0;
    firmware_header_t *firmware_header = NULL;

    err = request_firmware_direct(&firmware, board->board_data->fw_filename, &board->pDev->dev);
    if (err < 0) {
        hailo_warn(board, "Firmware file not found (/lib/firmware/%s), please upload the firmware manually\n",
            board->board_data->fw_filename);
        goto exit;
    }

    err = FW_VALIDATION__validate_fw_headers(board, (uintptr_t)firmware->data, firmware->size, &firmware_header, NULL);
    if (err < 0) {
        hailo_err(board, "Failed parsing firmware file\n");
        goto exit;
    }

    err = hailo_write_core_firmware(board, firmware_header);
    if (err < 0) {
        hailo_err(board, "Failed to write firmware");
        goto exit;
    }

    if (!hailo_wait_for_firmware(board)) {
        hailo_err(board, "Timeout waiting for firmware..\n");
        err = -ETIMEDOUT;
        goto exit;
    }

    hailo_notice(board, "Firmware was loaded successfully\n");
    err = 0;
exit:
    if (firmware != NULL) {
        release_firmware(firmware);
    }
    return err;
}
