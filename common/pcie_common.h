// SPDX-License-Identifier: MIT
/**
 * Copyright (c) 2019-2024 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_COMMON_PCIE_COMMON_H_
#define _HAILO_COMMON_PCIE_COMMON_H_

#include "hailo_resource.h"
#include "hailo_ioctl_common.h"
#include "fw_validation.h"
#include "fw_operation.h"
#include "utils.h"
#include "vdma_common.h"
#include "soc_structs.h"

#include <linux/types.h>
#include <linux/firmware.h>


#define BCS_ISTATUS_HOST_FW_IRQ_CONTROL_MASK (0x04000000)
#define BCS_ISTATUS_HOST_FW_IRQ_NOTIFICATION (0x02000000)
#define BCS_ISTATUS_HOST_DRIVER_DOWN         (0x08000000)
#define BCS_ISTATUS_SOC_CONNECT_ACCEPTED     (0x10000000)
#define BCS_ISTATUS_SOC_CLOSED_IRQ           (0x20000000)
#define BCS_ISTATUS_HOST_VDMA_SRC_IRQ_MASK   (0x000000FF)
#define BCS_ISTATUS_HOST_VDMA_DEST_IRQ_MASK  (0x0000FF00)

#define PCIE_HAILO8_BOARD_CFG_MAX_SIZE          (0x500)
#define PCIE_HAILO8_FW_CFG_MAX_SIZE             (0x500)

#define FW_CODE_SECTION_ALIGNMENT (4)

#define HAILO_PCIE_CONFIG_BAR       (0)
#define HAILO_PCIE_VDMA_REGS_BAR    (2)
#define HAILO_PCIE_FW_ACCESS_BAR    (4)

#define HAILO_PCIE_DMA_ENGINES_COUNT (1)

#define DRIVER_NAME		"hailo"

#define PCI_VENDOR_ID_HAILO           0x1e60
#define PCI_DEVICE_ID_HAILO_HAILO8    0x2864
#define PCI_DEVICE_ID_HAILO_HAILO15   0x45C4
#define PCI_DEVICE_ID_HAILO_PLUTO     0x43a2

typedef u64 hailo_ptr_t;

struct hailo_pcie_resources {
    struct hailo_resource config;               // BAR0
    struct hailo_resource vdma_registers;       // BAR2
    struct hailo_resource fw_access;            // BAR4
    enum hailo_board_type board_type;
    enum hailo_accelerator_type accelerator_type;
};

struct hailo_atr_config {
    u32 atr_param;
    u32 atr_src;
    u32 atr_trsl_addr_1;
    u32 atr_trsl_addr_2;
    u32 atr_trsl_param;
};

enum loading_stages {
    FIRST_STAGE = 0,
    SECOND_STAGE = 1,
    SECOND_STAGE_LINUX_IN_EMMC = 2,
    MAX_LOADING_STAGES = 3
};

enum hailo_pcie_interrupt_masks {
    FW_CONTROL = BCS_ISTATUS_HOST_FW_IRQ_CONTROL_MASK,
    FW_NOTIFICATION = BCS_ISTATUS_HOST_FW_IRQ_NOTIFICATION,
    DRIVER_DOWN = BCS_ISTATUS_HOST_DRIVER_DOWN,
    SOC_CONNECT_ACCEPTED = BCS_ISTATUS_SOC_CONNECT_ACCEPTED,
    SOC_CLOSED_IRQ = BCS_ISTATUS_SOC_CLOSED_IRQ,
    VDMA_SRC_IRQ_MASK = BCS_ISTATUS_HOST_VDMA_SRC_IRQ_MASK,
    VDMA_DEST_IRQ_MASK = BCS_ISTATUS_HOST_VDMA_DEST_IRQ_MASK
};

struct hailo_pcie_interrupt_source {
    u32 interrupt_bitmask;
    u32 vdma_channels_bitmap;
};

struct hailo_file_batch {
    const char *filename;
    u32 address;
    size_t max_size;
    bool is_mandatory;
    bool has_header;
    bool has_core;
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

extern struct hailo_vdma_hw hailo_pcie_vdma_hw;

// Reads the interrupt source from BARs, return false if there is no interrupt.
// note - this function clears the interrupt signals.
bool hailo_pcie_read_interrupt(struct hailo_pcie_resources *resources, struct hailo_pcie_interrupt_source *source);
void hailo_pcie_update_channel_interrupts_mask(struct hailo_pcie_resources *resources, u32 channels_bitmap);
void hailo_pcie_enable_interrupts(struct hailo_pcie_resources *resources);
void hailo_pcie_disable_interrupts(struct hailo_pcie_resources *resources);

int hailo_pcie_write_firmware_control(struct hailo_pcie_resources *resources, const struct hailo_fw_control *command);
int hailo_pcie_read_firmware_control(struct hailo_pcie_resources *resources, struct hailo_fw_control *command);

int hailo_pcie_write_firmware_batch(struct device *dev, struct hailo_pcie_resources *resources, u32 stage);
bool hailo_pcie_is_firmware_loaded(struct hailo_pcie_resources *resources);
bool hailo_pcie_wait_for_firmware(struct hailo_pcie_resources *resources);

int hailo_pcie_memory_transfer(struct hailo_pcie_resources *resources, struct hailo_memory_transfer_params *params);

bool hailo_pcie_is_device_connected(struct hailo_pcie_resources *resources);
void hailo_pcie_write_firmware_driver_shutdown(struct hailo_pcie_resources *resources);
void hailo_trigger_firmware_boot(struct hailo_pcie_resources *resources, u32 address);

int hailo_set_device_type(struct hailo_pcie_resources *resources);

u32 hailo_get_boot_status(struct hailo_pcie_resources *resources);

int hailo_pcie_configure_atr_table(struct hailo_resource *bridge_config, u64 trsl_addr, u32 atr_index);
void hailo_pcie_read_atr_table(struct hailo_resource *bridge_config, struct hailo_atr_config *atr, u32 atr_index);

u64 hailo_pcie_encode_desc_dma_address_range(dma_addr_t dma_address_start, dma_addr_t dma_address_end, u32 step, u8 channel_id);

void hailo_pcie_soc_write_request(struct hailo_pcie_resources *resources,
    const struct hailo_pcie_soc_request *request);
void hailo_pcie_soc_read_response(struct hailo_pcie_resources *resources,
    struct hailo_pcie_soc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* _HAILO_COMMON_PCIE_COMMON_H_ */