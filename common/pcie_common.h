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
#include <linux/scatterlist.h>

// Platform-specific includes are now handled in platform layers only

#define HAILO_PCI_OVER_VDMA_MAX_CHANNELS (16) // Maximum number of channels available for boot
#define HAILO_PCI_OVER_VDMA_PAGE_SIZE    (512)

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

#define DRIVER_NAME "hailo1x"

#define PCI_VENDOR_ID_HAILO           0x1e60
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

// File batch flags.
#define HAILO_FILE_F_NONE         (0)
#define HAILO_FILE_F_MANDATORY    (1 << 0)
#define HAILO_FILE_F_HAS_HEADER   (1 << 1)
#define HAILO_FILE_F_HAS_CORE     (1 << 2)
#define HAILO_FILE_F_DYNAMIC_NAME (1 << 3)

struct hailo_file_batch {
    char filename[FW_FILENAME_MAX_LEN];
    u32 address;
    size_t max_size;
    u8 flags;
};

struct hailo_pcie_loading_stage {
    const struct hailo_file_batch *batch;
    u32 trigger_address;
    u32 timeout;
    u8 amount_of_files_in_stage;
};

// Common descriptor programming function - works directly with common structures
struct hailo_pcie_boot_desc_programming_params {
    struct hailo_vdma_descriptors_list *device_desc_list;
    struct hailo_vdma_descriptors_list *host_desc_list;
    u32 desc_program_num;
    u32 max_desc_count;
};

// Common structure definitions for platform-agnostic firmware loading
struct hailo_pcie_boot_dma_channel_state {
    // The sg_table and kernel_address are considered common as linux-port provides
    // compatible types for all platforms. The memory itself is allocated by the platform.
    struct sg_table sg_table;
    void *kernel_address;

    // Pointers to the descriptor lists within the buffers for convenience.
    // The backing memory is allocated and managed by the platform-specific driver code.
    struct hailo_vdma_descriptors_list *host_descriptors_list;
    struct hailo_vdma_descriptors_list *device_descriptors_list;

    // Common channel state
    u32 buffer_size;
    u32 desc_program_num;
};

struct hailo_pcie_boot_dma_state {
    struct hailo_pcie_boot_dma_channel_state channels[HAILO_PCI_OVER_VDMA_MAX_CHANNELS];
    u8 curr_channel_index;          // Runtime pointer: which channel we're currently programming
    u8 allocated_channels;          // Pre-calculated capacity: how many channels we allocated
    // Note: At completion, allocated_channels should equal curr_channel_index + 1 (if all channels used)
    
    // Cache for firmware files to avoid loading them twice (for channel calculation and programming)
    // Files are cached in the same order as they appear in the stage file batch
    const struct firmware *firmware_cache[MAX_FILES_PER_STAGE];
    u8 cached_firmware_count;
};

struct hailo_pcie_fw_boot {
    struct hailo_pcie_boot_dma_state boot_dma_state;
    u16 boot_used_channel_bitmap;
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

#define HAILO_SCU_LOG_MAX_SIZE (0x1000u)

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


bool hailo_pcie_is_device_connected(struct hailo_pcie_resources *resources);
void hailo_pcie_write_firmware_driver_shutdown(struct hailo_pcie_resources *resources);
void hailo_pcie_write_firmware_soft_reset(struct hailo_pcie_resources *resources);
void hailo_pcie_configure_ep_registers_for_dma_transaction(struct hailo_pcie_resources *resources);
void hailo_trigger_firmware_boot(struct hailo_pcie_resources *resources, u32 stage);

int hailo_set_device_type(struct hailo_pcie_resources *resources);
void hailo_read_sku_id(struct hailo_pcie_resources *resources);

void hailo_resolve_dtb_filename(char *filename, u32 sku_id, const char *file_name_template);

u32 hailo_get_boot_status(struct hailo_pcie_resources *resources);
int hailo_pcie_read_scu_log(struct hailo_pcie_resources *resources,
    void *buffer, u32 *size);

int hailo_pcie_configure_atr_table(struct hailo_resource *bridge_config, u64 trsl_addr, u32 atr_index);
void hailo_pcie_read_atr_table(struct hailo_resource *bridge_config, struct hailo_atr_config *atr, u32 atr_index);

/**
 * Program a batch of firmware files over vDMA.
 *
 * This function orchestrates the firmware loading process by iterating through the
 * files for a given stage, preparing DMA transfers, and programming the descriptors
 * using platform-specific data.
 *
 * @fw_boot Pointer to the common firmware boot state structure.
 * @resources Pointer to the PCIe hardware resources.
 * @stage The firmware loading stage to be programmed.
 * @dev Pointer to the device struct for logging and resource management.
 * @return Returns 0 on success, or a negative error code on failure.
 */
long hailo_pcie_program_firmware_batch_common(struct hailo_pcie_fw_boot *fw_boot,
    struct hailo_pcie_resources *resources, u32 stage, struct device *dev);

/**
 * Load and cache firmware files for a stage, then calculate the number of channels
 * required for the transfer based on actual file sizes.
 *
 * @param fw_boot Pointer to the firmware boot state structure.
 * @param resources Pointer to the PCIe hardware resources.
 * @param stage The firmware loading stage to analyze.
 * @param dev Pointer to the device struct for logging.
 * @return Returns 0 on success, or a negative error code on failure.
 *
 * This function loads each firmware file for the given stage, caches the firmware pointers
 * and sums their sizes to determine the number of vDMA channels required for the transfer.
 * The number of channels is based on the total size and the maximum channel capacity,
 * which is calculated using (MAX_SG_DESCS_COUNT - 1) * HAILO_PCI_OVER_VDMA_PAGE_SIZE.
 */
int hailo_pcie_load_and_cache_stage_firmware(struct hailo_pcie_fw_boot *fw_boot,
    struct hailo_pcie_resources *resources, u32 stage, struct device *dev);

/**
 * Release all cached firmware files for a boot DMA state.
 *
 * @param boot_dma_state Pointer to the boot DMA state structure.
 */
void hailo_pcie_release_firmware_cache(struct hailo_pcie_boot_dma_state *boot_dma_state);

void hailo_pcie_soc_write_request(struct hailo_pcie_resources *resources,
    const struct hailo_pcie_soc_request *request);
void hailo_pcie_soc_read_response(struct hailo_pcie_resources *resources,
    struct hailo_pcie_soc_response *response);
bool hailo_pcie_wait_for_boot(struct hailo_pcie_resources *resources);
#ifdef __cplusplus
}
#endif
#endif /* _HAILO_COMMON_PCIE_COMMON_H_ */

