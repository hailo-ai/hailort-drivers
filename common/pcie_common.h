// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_COMMON_PCIE_COMMON_H_
#define _HAILO_COMMON_PCIE_COMMON_H_

#include "hailo_resource.h"
#include "types.h"
#include "hailo_ioctl_common.h"
#include "fw_validation.h"
#include "fw_operation.h"
#include "utils.h"

#ifdef __linux__
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/scatterlist.h>
#include "utils/compact.h"
#endif

#define PCIE_D2H_NOTIFICATION_SRAM_OFFSET (0x640 + 0x640)
#define PCIE_REQUEST_SIZE_OFFSET (0x640)
#define BSC_IMASK_HOST (0x0188)
#define BCS_ISTATUS_HOST (0x018C)
#define BCS_DESTINATION_INTERRUPT_PER_CHANNEL (0x500)
#define BCS_SOURCE_INTERRUPT_PER_CHANNEL (0x400)

#define PCIE_HAILO8_BOARD_CFG_MAX_SIZE          (0x500)
#define PCIE_HAILO8_FW_CFG_MAX_SIZE             (0x500)

#define BCS_ISTATUS_HOST_FW_IRQ_CONTROL_MASK (0x04000000)
#define BCS_ISTATUS_HOST_FW_IRQ_NOTIFICATION (0x02000000)
#define BCS_ISTATUS_HOST_VDMA_SRC_IRQ_MASK   (0x000000FF)
#define BCS_ISTATUS_HOST_VDMA_DEST_IRQ_MASK  (0x0000FF00)

#define FW_CODE_SECTION_ALIGNMENT (4)

#define HAILO_PCIE_CONFIG_BAR       (0)
#define HAILO_PCIE_VDMA_REGS_BAR    (2)
#define HAILO_PCIE_FW_ACCESS_BAR    (4)

#define HAILO_PCIE_HOST_DMA_DATA_ID (0)
#define HAILO_PCIE_DMA_ENGINES_COUNT (1)

#define DRIVER_NAME		"hailo"

#define PCI_VENDOR_ID_HAILO           0x1e60
#define PCI_DEVICE_ID_HAILO_HAILO8    0x2864
#define PCI_DEVICE_ID_HAILO_MERCURY   0x45C4

struct hailo_pcie_resources {
    struct hailo_resource config;               // BAR0
    struct hailo_resource vdma_registers;       // BAR2
    struct hailo_resource fw_access;            // BAR4
    enum hailo_board_type board_type;
};

enum hailo_pcie_interrupt_masks {
    FW_CONTROL = BCS_ISTATUS_HOST_FW_IRQ_CONTROL_MASK,
    FW_NOTIFICATION = BCS_ISTATUS_HOST_FW_IRQ_NOTIFICATION,
    VDMA_SRC_IRQ_MASK = BCS_ISTATUS_HOST_VDMA_SRC_IRQ_MASK,
    VDMA_DEST_IRQ_MASK = BCS_ISTATUS_HOST_VDMA_DEST_IRQ_MASK
};

struct hailo_pcie_interrupt_source {
    uint32_t interrupt_bitmask;
    uint32_t channel_data_source;
    uint32_t channel_data_dest;
};

struct hailo_config_constants {
    const char *filename;
    u32 address;
    size_t max_size;
};

// TODO: HRT-6144 - Align Windows/Linux to QNX
#ifdef __QNX__
enum hailo_bar_index {
    BAR0 = 0,
    BAR2,
    BAR4,
    MAX_BAR
};
#else
enum hailo_bar_index {
    BAR0 = 0,
    BAR1,
    BAR2,
    BAR3,
    BAR4,
    BAR5,
    MAX_BAR
};
#endif // ifdef (__QNX__)

#ifdef __cplusplus
extern "C" {
#endif

// Reads the interrupt source from BARs, return false if there is no interrupt.
// note - this function clears the interrupt signals.
bool hailo_pcie_read_interrupt(struct hailo_pcie_resources *resources, struct hailo_pcie_interrupt_source *source);
void hailo_pcie_update_channel_interrupts_mask(struct hailo_pcie_resources *resources, uint32_t channels_bitmap);
void hailo_pcie_enable_interrupts(struct hailo_pcie_resources *resources);
void hailo_pcie_disable_interrupts(struct hailo_pcie_resources *resources);

int hailo_pcie_write_firmware_control(struct hailo_pcie_resources *resources, const struct hailo_fw_control *command);
int hailo_pcie_read_firmware_control(struct hailo_pcie_resources *resources, struct hailo_fw_control *command);

int hailo_pcie_write_firmware(struct hailo_pcie_resources *resources, const void *fw_data, size_t fw_size);
bool hailo_pcie_is_firmware_loaded(struct hailo_pcie_resources *resources);
bool hailo_pcie_wait_for_firmware(struct hailo_pcie_resources *resources);

int hailo_pcie_read_firmware_notification(struct hailo_pcie_resources *resources,
    struct hailo_d2h_notification *notification);

int hailo_pcie_write_config_common(struct hailo_pcie_resources *resources, const void* config_data,
    const size_t config_size, const struct hailo_config_constants *config_consts);
const struct hailo_config_constants* hailo_pcie_get_board_config_constants(const enum hailo_board_type board_type);
const struct hailo_config_constants* hailo_pcie_get_user_config_constants(const enum hailo_board_type board_type);
const char* hailo_pcie_get_fw_filename(const enum hailo_board_type board_type);

long hailo_pcie_read_firmware_log(struct hailo_pcie_resources *resources, struct hailo_read_log_params *params);
int hailo_pcie_memory_transfer(struct hailo_pcie_resources *resources, struct hailo_memory_transfer_params *params);

bool hailo_pcie_is_device_connected(struct hailo_pcie_resources *resources);

#ifdef __cplusplus
}
#endif

#endif /* _HAILO_COMMON_PCIE_COMMON_H_ */