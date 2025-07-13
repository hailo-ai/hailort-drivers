// SPDX-License-Identifier: MIT
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
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


#define PCIE_HAILO8_BOARD_CFG_MAX_SIZE          (0x500)
#define PCIE_HAILO8_FW_CFG_MAX_SIZE             (0x500)

#define FW_CODE_SECTION_ALIGNMENT (4)

#define HAILO_PCIE_CONFIG_BAR       (0)
#define HAILO_PCIE_VDMA_REGS_BAR    (2)
#define HAILO_PCIE_FW_ACCESS_BAR    (4)

#define HAILO_PCIE_DMA_ENGINES_COUNT (1)
#define PCI_VDMA_ENGINE_INDEX        (0)

#define FW_FILENAME_MAX_LEN (128)
#define MAX_FILES_PER_STAGE (4)

#define HAILO_PCIE_HOST_DMA_DATA_ID    (0)
#define HAILO_PCI_EP_HOST_DMA_DATA_ID  (6)

#define DRIVER_NAME		"hailo"

#define PCI_VENDOR_ID_HAILO           0x1e60
#define PCI_DEVICE_ID_HAILO_HAILO8    0x2864
#define PCI_DEVICE_ID_HAILO_HAILO10H  0x45C4
#define PCI_DEVICE_ID_HAILO_HAILO15L  0x43a2
#define PCI_DEVICE_ID_HAILO_MARS      0x26a2

// On PCIe, masked_channel_id is always 0
#define PCIE_CHANNEL_ID_MASK (0)
#define PCIE_CHANNEL_ID_SHIFT (0)
#define HAILO_SKU_ID_DEFAULT (0xffffffff)

typedef u64 hailo_ptr_t;

struct hailo_pcie_resources {
    struct hailo_resource config;               // BAR0
    struct hailo_resource vdma_registers;       // BAR2
    struct hailo_resource fw_access;            // BAR4
    enum hailo_board_type board_type;
    enum hailo_accelerator_type accelerator_type;
    u32 sku_id;
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
    THIRD_STAGE = 2,
    MAX_LOADING_STAGES = 3
};

enum hailo_pcie_nnc_sw_interrupt_masks {
    HAILO_PCIE_NNC_FW_NOTIFICATION_IRQ  = 0x2,
    HAILO_PCIE_NNC_FW_CONTROL_IRQ       = 0x4,
    HAILO_PCIE_NNC_DRIVER_DOWN_IRQ      = 0x8,
};

enum hailo_pcie_soc_sw_interrupt_masks {
    HAILO_PCIE_SOC_CONTROL_IRQ          = 0x10,
    HAILO_PCIE_SOC_CLOSE_IRQ            = 0x20,
};

enum hailo_pcie_boot_interrupt_masks {
    HAILO_PCIE_BOOT_SOFT_RESET_IRQ      = 0x1,
    HAILO_PCIE_BOOT_IRQ                 = 0x2,
};

struct hailo_pcie_interrupt_source {
    u32 sw_interrupts;
    u32 vdma_channels_bitmap;
};

struct hailo_file_batch {
    char filename[FW_FILENAME_MAX_LEN];
    u32 address;
    size_t max_size;
    bool is_mandatory;
    bool has_header;
    bool has_core;
    bool is_dynamic_filename;
};

struct hailo_pcie_loading_stage {
    const struct hailo_file_batch *batch;
    u32 trigger_address;
    u32 timeout;
    u8 amount_of_files_in_stage;
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

#define TIME_COUNT_FOR_BOOTLOADER_MS (1)

#ifndef HAILO_EMULATOR
#define COUNT_UNTIL_REACH_BOOTLOADER (10)
#define PCI_EP_WAIT_TIMEOUT_MS   (40000)
#define FIRMWARE_WAIT_TIMEOUT_MS (5000)
#else /* ifndef HAILO_EMULATOR */
#define COUNT_UNTIL_REACH_BOOTLOADER (10000)
// PCI EP timeout is defined to 50000000 because on Emulator the boot time + linux init time can be very long (4+ hours)
#define PCI_EP_WAIT_TIMEOUT_MS   (50000000)
#define FIRMWARE_WAIT_TIMEOUT_MS (5000000)
#endif /* ifndef HAILO_EMULATOR */

extern struct hailo_vdma_hw hailo_pcie_vdma_hw;

const struct hailo_pcie_loading_stage* hailo_pcie_get_loading_stage_info(enum hailo_board_type board_type,
    enum loading_stages stage);

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
void hailo_pcie_write_firmware_soft_reset(struct hailo_pcie_resources *resources);
void hailo_pcie_configure_ep_registers_for_dma_transaction(struct hailo_pcie_resources *resources);
void hailo_trigger_firmware_boot(struct hailo_pcie_resources *resources, u32 stage);

int hailo_set_device_type(struct hailo_pcie_resources *resources);
void hailo_read_sku_id(struct hailo_pcie_resources *resources);

void hailo_resolve_dtb_filename(char *filename, u32 sku_id);

u32 hailo_get_boot_status(struct hailo_pcie_resources *resources);

int hailo_pcie_configure_atr_table(struct hailo_resource *bridge_config, u64 trsl_addr, u32 atr_index);
void hailo_pcie_read_atr_table(struct hailo_resource *bridge_config, struct hailo_atr_config *atr, u32 atr_index);

void hailo_pcie_soc_write_request(struct hailo_pcie_resources *resources,
    const struct hailo_pcie_soc_request *request);
void hailo_pcie_soc_read_response(struct hailo_pcie_resources *resources,
    struct hailo_pcie_soc_response *response);
bool hailo_pcie_wait_for_boot(struct hailo_pcie_resources *resources);

#ifdef __cplusplus
}
#endif

#endif /* _HAILO_COMMON_PCIE_COMMON_H_ */
