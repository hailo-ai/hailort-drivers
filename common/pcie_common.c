// SPDX-License-Identifier: MIT
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include "pcie_common.h"
#include "fw_operation.h"
#include "soc_structs.h"
#include "logs.h"

#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/device.h>


#define BSC_IMASK_HOST (0x0188)
#define BCS_ISTATUS_HOST (0x018C)
#define BCS_SOURCE_INTERRUPT_PER_CHANNEL (0x400)
#define BCS_DESTINATION_INTERRUPT_PER_CHANNEL (0x500)

#define BCS_ISTATUS_HOST_SW_IRQ_MASK         (0xFF000000)
#define BCS_ISTATUS_HOST_SW_IRQ_SHIFT        (24)
#define BCS_ISTATUS_HOST_VDMA_SRC_IRQ_MASK   (0x000000FF)
#define BCS_ISTATUS_HOST_VDMA_DEST_IRQ_MASK  (0x0000FF00)
#define BSC_ISTATUS_HOST_MASK                (BCS_ISTATUS_HOST_SW_IRQ_MASK | \
                                              BCS_ISTATUS_HOST_VDMA_SRC_IRQ_MASK | \
                                              BCS_ISTATUS_HOST_VDMA_DEST_IRQ_MASK)

#define PO2_ROUND_UP(size, alignment) ((size + alignment-1) & ~(alignment-1))

#define ATR_PARAM               (0x17)
#define ATR_SRC_ADDR            (0x0)
#define ATR_TRSL_PARAM          (6)
#define ATR_TABLE_SIZE          (0x1000u)
#define ATR_TABLE_SIZE_MASK     (0x1000u - 1)

#define ATR0_PCIE_BRIDGE_OFFSET (0x700)

#define ATR_PCIE_BRIDGE_OFFSET(atr_index)    (ATR0_PCIE_BRIDGE_OFFSET + (atr_index * 0x20))

#define MAXIMUM_APP_FIRMWARE_CODE_SIZE (0x40000)
#define MAXIMUM_CORE_FIRMWARE_CODE_SIZE (0x20000)

#define FIRMWARE_LOAD_WAIT_MAX_RETRIES (100)
#define FIRMWARE_LOAD_SLEEP_MS         (50)

#define PCIE_REQUEST_SIZE_OFFSET (0x640)

#define PCIE_CONFIG_VENDOR_OFFSET (0x0098)

#define HAILO_PCIE_DMA_DEVICE_INTERRUPTS_BITMASK    (1 << 4)
#define HAILO_PCIE_DMA_HOST_INTERRUPTS_BITMASK      (1 << 5)
#define HAILO_PCIE_DMA_SRC_CHANNELS_BITMASK         (0x000000000000FFFF)

#define HAILO_PCIE_MAX_ATR_TABLE_INDEX (3)

#define BOOT_STATUS_UNINITIALIZED (0x1)

#define PCIE_CONTROL_SECTION_ADDRESS_H8 (0x60000000)
#define PCIE_BLOCK_ADDRESS_ATR1    (0x200000)

#define PCIE_CONFIG_PCIE_CFG_QM_ROUTING_MODE_SET(reg_offset)\
	(reg_offset) = (((reg_offset) & ~0x00000004L) | ((uint32_t)(1) << 2))

/* Define GPIO bit positions based on the mapping */
#define GPIO_SKU_ID_EN_BIT  0   /* GPIO16 - GPIO_SKU_ID_EN */
#define GPIO_SKU_ID_0_BIT   1   /* GPIO17 - SKU ID[0] */
#define GPIO_SKU_ID_1_BIT   2   /* GPIO18 - SKU ID[1] */
#define GPIO_SKU_ID_2_BIT   3   /* GPIO19 - SKU ID[2] */
#define GPIO_SKU_ID_3_BIT   9   /* GPIO25 - SKU ID[3] */
#define GPIO_SKU_ID_4_BIT   10  /* GPIO26 - SKU ID[4] */
#define GPIO_SKU_ID_5_BIT   11  /* GPIO27 - SKU ID[5] */

// max len of u32 is 10, plus the null terminator
#define SKU_ID_MAX_LEN 11

// Constants for the new common function
#ifndef MAX_SG_DESCS_COUNT
#define MAX_SG_DESCS_COUNT (65536)
#endif

struct hailo_fw_addresses {
    u32 boot_fw_header;
    u32 app_fw_code_ram_base;
    u32 boot_key_cert;
    u32 boot_cont_cert;
    u32 core_code_ram_base;
    u32 core_fw_header;
    u32 raise_ready_offset;
    u32 boot_status;
    u32 sku_id_offset;
    u32 pcie_cfg_regs;
    u32 scu_log_address;
};

struct hailo_board_compatibility {
    struct hailo_fw_addresses fw_addresses;
    const struct hailo_pcie_loading_stage stages[MAX_LOADING_STAGES];
};

static const struct hailo_file_batch hailo10h_files_stg1[] = {
    {
        .filename = "hailo/hailo10h/customer_certificate.bin",
        .address = 0xA0000,
        .max_size = 0x8004,
        .flags = HAILO_FILE_F_MANDATORY
    },
    {
        .filename = "hailo/hailo10h/scu_fw.bin",
        .address = 0x20000,
        .max_size = 0x40000,
        .flags = HAILO_FILE_F_MANDATORY | HAILO_FILE_F_HAS_HEADER
    }
};

static const struct hailo_file_batch hailo10h_files_stg2[] = {
    {
        .filename = "hailo/hailo10h/u-boot-%s.dtb.signed",
        .address = 0xA8004,
        .max_size = 0x20000,
        .flags = HAILO_FILE_F_MANDATORY | HAILO_FILE_F_DYNAMIC_NAME
    }
};

static const struct hailo_file_batch hailo10h_files_stg3[] = {
    {
        .filename = "hailo/hailo10h/u-boot-spl.bin",
        .address = 0x80300000,
        .max_size = 0x2C000,
        .flags = HAILO_FILE_F_MANDATORY,
    },
    {
        .filename = "hailo/hailo10h/u-boot-tfa.itb",
        .address = 0x8032C000,
        .max_size = 0x1d4000,
        .flags = HAILO_FILE_F_NONE,
    },
    {
        .filename = "hailo/hailo10h/fitImage",
        .address = 0x88000000,
        .max_size = 0x8000000,
        .flags = HAILO_FILE_F_MANDATORY
    },
    {
        .filename = "hailo/hailo10h/image-fs",
        .address = 0x90000000,
        .max_size = 0x20000000, // max size 512 MiB
        .flags = HAILO_FILE_F_MANDATORY
    }
};

static const struct hailo_file_batch hailo12l_files_stg1[] = {
    {
        .filename = "hailo/hailo12l/customer_certificate.bin",
        .address = 0x88000,
        .max_size = 0x8004,
        .flags = HAILO_FILE_F_MANDATORY
    },
    {
        .filename = "hailo/hailo12l/scu_fw.bin",
        .address = 0x20000,
        .max_size = 0x40000,
        .flags = HAILO_FILE_F_MANDATORY | HAILO_FILE_F_HAS_HEADER
    }
};

static const struct hailo_file_batch hailo12l_files_stg2[] = {
    {
        .filename = "hailo/hailo12l/u-boot-%s.dtb.signed",
        .address = 0x80004,
        .max_size = 0x20000,
        .flags = HAILO_FILE_F_MANDATORY | HAILO_FILE_F_DYNAMIC_NAME
    }
};

static const struct hailo_file_batch hailo12l_files_stg3[] = {
    {
        .filename = "hailo/hailo12l/u-boot-spl.bin",
        .address = 0x80300000,
        .max_size = 0x2C000,
        .flags = HAILO_FILE_F_MANDATORY
    },
    {
        .filename = "hailo/hailo12l/u-boot-tfa.itb",
        .address = 0x8032C000,
        .max_size = 0x1d4000,
        .flags = HAILO_FILE_F_NONE
    },
    {
        .filename = "hailo/hailo12l/fitImage",
        .address = 0x88000000,
        .max_size = 0x8000000,
        .flags = HAILO_FILE_F_MANDATORY
    },
    {
        .filename = "hailo/hailo12l/image-fs",
        .address = 0x90000000,
        .max_size = 0x20000000, // max size 512 MiB
        .flags = HAILO_FILE_F_MANDATORY
    }
};

static const struct hailo_file_batch hailo15h_accelerator_mode_files_stg1[] = {
    {
        .filename = "hailo/hailo15_fw.bin",
        .address = 0x20000,
        .max_size = 0x100000,
        .flags = HAILO_FILE_F_MANDATORY | HAILO_FILE_F_HAS_HEADER | HAILO_FILE_F_HAS_CORE
    }
};

static const struct hailo_file_batch hailo15l_files_stg1[] = {
    {
        .filename = "hailo/hailo15l_fw.bin",
        .address = 0x20000,
        .max_size = 0x100000,
        .flags = HAILO_FILE_F_MANDATORY | HAILO_FILE_F_HAS_HEADER | HAILO_FILE_F_HAS_CORE
    }
};

static const struct hailo_board_compatibility compat[HAILO_BOARD_TYPE_COUNT] = {
    [HAILO_BOARD_TYPE_HAILO15H_ACCELERATOR_MODE] = {
        .fw_addresses = {
            .boot_fw_header = 0x88000,
            .boot_key_cert = 0x88018,
            .boot_cont_cert = 0x886a8,
            .app_fw_code_ram_base = 0x20000,
            .core_code_ram_base = 0x60000,
            .core_fw_header = 0xC0000,
            .raise_ready_offset = 0x1754,
            .boot_status = 0x80000,
        },
        .stages = {
            {
                .batch = hailo15h_accelerator_mode_files_stg1,
                .trigger_address = 0x88c98,
                .timeout = FIRMWARE_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 1
            },
        },
    },
    [HAILO_BOARD_TYPE_HAILO10H] = {
        .fw_addresses = {
            .boot_fw_header = 0x88000,
            .boot_key_cert = 0x88018,
            .boot_cont_cert = 0x886a8,
            .app_fw_code_ram_base = 0x20000,
            .core_code_ram_base = 0,
            .core_fw_header = 0,
            .raise_ready_offset = 0x1754,
            .boot_status = 0x80000,
            .pcie_cfg_regs = 0x002009dc,
            .sku_id_offset = 0xdeffc,
            .scu_log_address = 0x000df000,
        },
        .stages = {
            {
                .batch = hailo10h_files_stg1,
                .trigger_address = 0x88c98,
                .timeout = FIRMWARE_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 2
            },
            {
                .batch = hailo10h_files_stg2,
                .trigger_address = 0xDEFF8,
                .timeout = FIRMWARE_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 1
            },
            {
                .batch = hailo10h_files_stg3,
                .trigger_address = 0x802FF000,
                .timeout = PCI_EP_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 4
            },
        },
    },
    // HRT-11344 : none of these matter except raise_ready_offset seeing as we load fw seperately - not through driver
    // After implementing bootloader put correct values here
    [HAILO_BOARD_TYPE_HAILO15L] = {
        .fw_addresses = {
            .boot_fw_header = 0x88000,
            .boot_key_cert = 0x88018,
            .boot_cont_cert = 0x886a8,
            .app_fw_code_ram_base = 0x20000,
            .core_code_ram_base = 0x60000,
            .core_fw_header = 0xC0000,
            // NOTE: After they update hw consts - check register fw_access_interrupt_w1s of pcie_config
            .raise_ready_offset = 0x174c,
            .boot_status = 0x80000,
        },
        .stages = {
            {
                .batch = hailo15l_files_stg1,
                .trigger_address = 0x88c98,
                .timeout = FIRMWARE_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 1
            },
        },
    },
    [HAILO_BOARD_TYPE_MARS] = {
        .fw_addresses = {
            .boot_fw_header = 0x98000,
            .boot_key_cert = 0x98018,
            .boot_cont_cert = 0x986a8,
            .app_fw_code_ram_base = 0x20000,
            .core_code_ram_base = 0,
            .core_fw_header = 0,
            .raise_ready_offset = 0x174c,
            .boot_status = 0x90000,
            .sku_id_offset = 0xdeffc,
            .pcie_cfg_regs = 0x002009d4,
            .scu_log_address = 0x000a7000,
        },
        .stages = {
            {
                .batch = hailo12l_files_stg1,
                .trigger_address = 0x98d18,
                .timeout = FIRMWARE_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 2
            },
            {
                .batch = hailo12l_files_stg2,
                .trigger_address = 0xa6ff8,
                .timeout = FIRMWARE_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 1
            },
            {
                .batch = hailo12l_files_stg3,
                .trigger_address = 0x802FF000,
                .timeout = PCI_EP_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 4
            },
        },
    },
};

void hailo_resolve_dtb_filename(char *filename, u32 sku_id, const char *file_name_template)
{
    char sku_id_str[SKU_ID_MAX_LEN];
    if (HAILO_SKU_ID_DEFAULT == sku_id) {
        snprintf(filename, FW_FILENAME_MAX_LEN, file_name_template, "default");
    } else {
        snprintf(sku_id_str, SKU_ID_MAX_LEN, "%u", sku_id);
        snprintf(filename, FW_FILENAME_MAX_LEN, file_name_template, sku_id_str);
    }
}

/**
 * Release all cached firmware files for a boot DMA state.
 */
void hailo_pcie_release_firmware_cache(struct hailo_pcie_boot_dma_state *boot_dma_state)
{
    u8 i = 0;

    if (!boot_dma_state) {
        return;
    }

    for (i = 0; i < boot_dma_state->cached_firmware_count; i++) {
        if (boot_dma_state->firmware_cache[i]) {
            release_firmware(boot_dma_state->firmware_cache[i]);
            boot_dma_state->firmware_cache[i] = NULL;
        }
    }
    boot_dma_state->cached_firmware_count = 0;
}

/**
 * Add firmware to cache at specific index.
 */
static void pcie_cache_firmware(struct hailo_pcie_boot_dma_state *boot_dma_state,
    u8 file_index, const struct firmware *firmware)
{
    boot_dma_state->firmware_cache[file_index] = firmware;

    // Update cached count to be max of current count and file_index + 1
    if (file_index + 1 > boot_dma_state->cached_firmware_count) {
        boot_dma_state->cached_firmware_count = file_index + 1;
    }
}

/**
 * Load and cache firmware files for a stage, then calculate the number of channels
 * required for the transfer based on actual file sizes.
 *
 * @param fw_boot Pointer to the firmware boot state structure (contains boot DMA state).
 * @param resources Pointer to the PCIe resources (contains board type and SKU ID).
 * @param stage The firmware loading stage to analyze.
 * @param dev Pointer to the device for error reporting and logging.
 * @return 0 on success, negative error code on failure.
 */
int hailo_pcie_load_and_cache_stage_firmware(struct hailo_pcie_fw_boot *fw_boot,
    struct hailo_pcie_resources *resources, u32 stage, struct device *dev)
{
    const struct hailo_pcie_loading_stage *stage_info = hailo_pcie_get_loading_stage_info(resources->board_type, stage);
    const struct hailo_file_batch *files_batch = stage_info->batch;
    const u8 amount_of_files = stage_info->amount_of_files_in_stage;
    struct hailo_pcie_boot_dma_state *boot_dma_state = &fw_boot->boot_dma_state;
    u64 total_stage_size = 0;
    u32 max_channel_capacity = 0;
    u8 required_channels = 0;
    u8 file_index = 0;
    int err = 0;

    if (!fw_boot || !resources || !dev) {
        return -EINVAL;
    }

    // Clear any existing firmware cache before starting (defensive programming - ensures clean state)
    hailo_pcie_release_firmware_cache(boot_dma_state);

    // Calculate maximum capacity per channel: (MAX_SG_DESCS_COUNT - 1) * page_size
    // We reserve 1 descriptor per channel for safety
    max_channel_capacity = (MAX_SG_DESCS_COUNT - 1) * HAILO_PCI_OVER_VDMA_PAGE_SIZE;

    // Sum up actual file sizes in the stage by loading each firmware file and caching them
    for (file_index = 0; file_index < amount_of_files; file_index++) {
        const struct hailo_file_batch *file = &files_batch[file_index];
        char filename[FW_FILENAME_MAX_LEN] = {0};
        const struct firmware *firmware = NULL;

        // Handle dynamic filenames (like DTB files based on SKU ID)
        if (file->flags & HAILO_FILE_F_DYNAMIC_NAME) {
            hailo_resolve_dtb_filename(filename, resources->sku_id, file->filename);
        } else {
            strncpy(filename, file->filename, FW_FILENAME_MAX_LEN - 1);
            filename[FW_FILENAME_MAX_LEN - 1] = '\0';
        }

        // Load firmware to get actual size
        hailo_dev_notice(dev, "Reading firmware file %s\n", filename);
        err = request_firmware_direct(&firmware, filename, dev);
        if (err < 0) {
            if (file->flags & HAILO_FILE_F_MANDATORY) {
                hailo_dev_err(dev, "Failed to load mandatory firmware file %s, error: %d\n", filename, err);
                goto cleanup_cache;
            } else {
                hailo_dev_info(dev, "Failed to load optional firmware file %s, error: %d, skipping\n", filename, err);
                continue;
            }
        }

        total_stage_size += firmware->size;
        
        hailo_dev_dbg(dev, "Stage %u file %d: %s, actual_size: %zu bytes\n", 
            stage+1, file_index, filename, firmware->size);

        // Cache the firmware for later use instead of releasing it
        pcie_cache_firmware(boot_dma_state, file_index, firmware);
    }

    // Calculate required channels (DIV_ROUND_UP ensures at least 1 for non-zero size)
    required_channels = (u8)DIV_ROUND_UP(total_stage_size, max_channel_capacity);
    
    // Check if firmware is too large for our maximum channel capacity
    if (required_channels > VDMA_CHANNELS_PER_ENGINE_PER_DIRECTION) {
        u64 max_total_capacity = (u64)VDMA_CHANNELS_PER_ENGINE_PER_DIRECTION * max_channel_capacity;
        hailo_dev_err(dev, "Stage %u firmware image file is too large for this device: %llu bytes > max capacity %llu bytes (%u channels)\n",
            stage+1, total_stage_size, max_total_capacity, VDMA_CHANNELS_PER_ENGINE_PER_DIRECTION);
        err = -EFBIG;   // firmware file too large for this device
        goto cleanup_cache;
    }

    hailo_dev_dbg(dev, "Stage %u: total_actual_size=%llu bytes, max_per_channel=%u bytes, required_channels=%u\n",
        stage+1, total_stage_size, max_channel_capacity, required_channels);

    // Update the boot DMA state with the calculated number of channels
    fw_boot->boot_dma_state.allocated_channels = required_channels;
    
    hailo_dev_dbg(dev, "Calculated %u channels required for stage %u\n", required_channels, stage+1);
    
    return 0;

cleanup_cache:
    hailo_pcie_release_firmware_cache(boot_dma_state);
    return err;
}

const struct hailo_pcie_loading_stage *hailo_pcie_get_loading_stage_info(enum hailo_board_type board_type,
    enum loading_stages stage)
{
    return &compat[board_type].stages[stage];
}

static u32 read_and_clear_reg(struct hailo_resource *resource, u32 offset)
{
    u32 value = hailo_resource_read32(resource, offset);
    if (value != 0) {
        hailo_resource_write32(resource, offset, value);
    }
    return value;
}

bool hailo_pcie_read_interrupt(struct hailo_pcie_resources *resources, struct hailo_pcie_interrupt_source *source)
{
    u32 istatus_host = 0;
    memset(source, 0, sizeof(*source));

    istatus_host = read_and_clear_reg(&resources->config, BCS_ISTATUS_HOST);
    if (0 == istatus_host) {
        return false;
    }

    source->sw_interrupts = (istatus_host >> BCS_ISTATUS_HOST_SW_IRQ_SHIFT);

    if (istatus_host & BCS_ISTATUS_HOST_VDMA_SRC_IRQ_MASK) {
        source->vdma_channels_bitmap |= read_and_clear_reg(&resources->config, BCS_SOURCE_INTERRUPT_PER_CHANNEL);
    }
    if (istatus_host & BCS_ISTATUS_HOST_VDMA_DEST_IRQ_MASK) {
        source->vdma_channels_bitmap |= read_and_clear_reg(&resources->config, BCS_DESTINATION_INTERRUPT_PER_CHANNEL);
    }

    return true;
}

int hailo_pcie_write_firmware_control(struct hailo_pcie_resources *resources, const struct hailo_fw_control *command)
{
    int err = 0;
    u32 request_size = 0;
    u8 fw_access_value = FW_ACCESS_APP_CPU_CONTROL_MASK;
    const struct hailo_fw_addresses *fw_addresses = &(compat[resources->board_type].fw_addresses);

    if (!hailo_pcie_is_firmware_loaded(resources)) {
        return -ENODEV;
    }

    // Copy md5 + buffer_len + buffer
    request_size = sizeof(command->expected_md5) + sizeof(command->buffer_len) + command->buffer_len;
    err = hailo_resource_write_buffer(&resources->fw_access, 0, PO2_ROUND_UP(request_size, FW_CODE_SECTION_ALIGNMENT),
        command);
    if (err < 0) {
        return err;
    }

    // Raise the bit for the CPU that will handle the control
    fw_access_value = (command->cpu_id == HAILO_CPU_ID_CPU1) ? FW_ACCESS_CORE_CPU_CONTROL_MASK :
        FW_ACCESS_APP_CPU_CONTROL_MASK;

    // Raise ready flag to FW
    hailo_resource_write32(&resources->fw_access, fw_addresses->raise_ready_offset, (u32)fw_access_value);
    return 0;
}

int hailo_pcie_read_firmware_control(struct hailo_pcie_resources *resources, struct hailo_fw_control *command)
{
    u32 response_header_size = 0;

    // Copy response md5 + buffer_len
    response_header_size = sizeof(command->expected_md5) + sizeof(command->buffer_len);

    hailo_resource_read_buffer(&resources->fw_access, PCIE_REQUEST_SIZE_OFFSET, response_header_size, command);

    if (sizeof(command->buffer) < command->buffer_len) {
        return -EINVAL;
    }

    // Copy response buffer
    hailo_resource_read_buffer(&resources->fw_access, PCIE_REQUEST_SIZE_OFFSET + (size_t)response_header_size,
        command->buffer_len, &command->buffer);

    return 0;
}

void hailo_pcie_write_firmware_driver_shutdown(struct hailo_pcie_resources *resources)
{
    const struct hailo_fw_addresses *fw_addresses = &(compat[resources->board_type].fw_addresses);
    const u32 fw_access_value = FW_ACCESS_DRIVER_SHUTDOWN_MASK;

    // Write shutdown flag to FW
    hailo_resource_write32(&resources->fw_access, fw_addresses->raise_ready_offset, fw_access_value);
}

void hailo_pcie_write_firmware_soft_reset(struct hailo_pcie_resources *resources)
{
    const struct hailo_fw_addresses *fw_addresses = &(compat[resources->board_type].fw_addresses);
    const u32 fw_access_value = FW_ACCESS_SOFT_RESET_MASK;

    // Write shutdown flag to FW
    hailo_resource_write32(&resources->fw_access, fw_addresses->raise_ready_offset, fw_access_value);
}

int hailo_pcie_configure_atr_table(struct hailo_resource *bridge_config, u64 trsl_addr, u32 atr_index)
{
    size_t offset = 0;
    struct hailo_atr_config atr = {
        .atr_param = (ATR_PARAM | (atr_index << 12)),
        .atr_src = ATR_SRC_ADDR,
        .atr_trsl_addr_1 = (u32)(trsl_addr & 0xFFFFFFFF),
        .atr_trsl_addr_2 = (u32)(trsl_addr >> 32),
        .atr_trsl_param = ATR_TRSL_PARAM
    };

    BUG_ON(HAILO_PCIE_MAX_ATR_TABLE_INDEX < atr_index);
    offset = ATR_PCIE_BRIDGE_OFFSET(atr_index);

    return hailo_resource_write_buffer(bridge_config, offset, sizeof(atr), (void*)&atr);
}

void hailo_pcie_read_atr_table(struct hailo_resource *bridge_config, struct hailo_atr_config *atr, u32 atr_index)
{
    size_t offset = 0;

    BUG_ON(HAILO_PCIE_MAX_ATR_TABLE_INDEX < atr_index);
    offset = ATR_PCIE_BRIDGE_OFFSET(atr_index);

    hailo_resource_read_buffer(bridge_config, offset, sizeof(*atr), (void*)atr);
}

static void write_memory_chunk(struct hailo_pcie_resources *resources,
    hailo_ptr_t dest, u32 dest_offset, const void *src, u32 len)
{
    u32 ATR_INDEX = 0;
    BUG_ON(dest_offset + len > (u32)resources->fw_access.size);

    (void)hailo_pcie_configure_atr_table(&resources->config, dest, ATR_INDEX);
    (void)hailo_resource_write_buffer(&resources->fw_access, dest_offset, len, src);
}

static void read_memory_chunk(
    struct hailo_pcie_resources *resources, hailo_ptr_t src, u32 src_offset, void *dest, u32 len)
{
    u32 ATR_INDEX = 0;
    BUG_ON(src_offset + len > (u32)resources->fw_access.size);

    (void)hailo_pcie_configure_atr_table(&resources->config, src, ATR_INDEX);
    (void)hailo_resource_read_buffer(&resources->fw_access, src_offset, len, dest);
}

// Note: this function modify the device ATR table (that is also used by the firmware for control and vdma).
// Use with caution, and restore the original atr if needed.
static void write_memory(struct hailo_pcie_resources *resources, hailo_ptr_t dest, const void *src, u32 len)
{
    struct hailo_atr_config previous_atr = {0};
    hailo_ptr_t base_address = (dest & ~ATR_TABLE_SIZE_MASK);
    u32 chunk_len = 0;
    u32 offset = 0;
    u32 ATR_INDEX = 0;

    // Store previous ATR (Read/write modify the ATR).
    hailo_pcie_read_atr_table(&resources->config, &previous_atr, ATR_INDEX);

    if (base_address != dest) {
        // Data is not aligned, write the first chunk
        chunk_len = min((u32)(base_address + ATR_TABLE_SIZE - dest), len);
        write_memory_chunk(resources, base_address, (u32)(dest - base_address), src, chunk_len);
        offset += chunk_len;
    }

    while (offset < len) {
        chunk_len = min(len - offset, ATR_TABLE_SIZE);
        write_memory_chunk(resources, dest + offset, 0, (const u8*)src + offset, chunk_len);
        offset += chunk_len;
    }

    (void)hailo_pcie_configure_atr_table(&resources->config,
        (((u64)(previous_atr.atr_trsl_addr_2) << 32) | previous_atr.atr_trsl_addr_1), ATR_INDEX);
}

// Note: this function modify the device ATR table (that is also used by the firmware for control and vdma).
// Use with caution, and restore the original atr if needed.
static void read_memory(struct hailo_pcie_resources *resources, hailo_ptr_t src, void *dest, u32 len)
{
    struct hailo_atr_config previous_atr = {0};
    hailo_ptr_t base_address = (src & ~ATR_TABLE_SIZE_MASK);
    u32 chunk_len = 0;
    u32 offset = 0;
    u32 ATR_INDEX = 0;

    // Store previous ATR (Read/write modify the ATR).
    hailo_pcie_read_atr_table(&resources->config, &previous_atr, ATR_INDEX);

    if (base_address != src) {
        // Data is not aligned, read the first chunk
        chunk_len = min((u32)(base_address + ATR_TABLE_SIZE - src), len);
        read_memory_chunk(resources, base_address, (u32)(src - base_address), dest, chunk_len);
        offset += chunk_len;
    }

    while (offset < len) {
        chunk_len = min(len - offset, ATR_TABLE_SIZE);
        read_memory_chunk(resources, src + offset, 0, (u8*)dest + offset, chunk_len);
        offset += chunk_len;
    }

    (void)hailo_pcie_configure_atr_table(&resources->config,
        (((u64)(previous_atr.atr_trsl_addr_2) << 32) | previous_atr.atr_trsl_addr_1), ATR_INDEX);
}

// Note: This function use for enabling the vDMA transaction host<->device by read modify write of the EP registers in the SOC - for fast boot over vDMA.
void hailo_pcie_configure_ep_registers_for_dma_transaction(struct hailo_pcie_resources *resources)
{
    u32 reg_routing_mercury = 0;

    BUG_ON(compat[resources->board_type].fw_addresses.pcie_cfg_regs == 0);

    read_memory(resources, compat[resources->board_type].fw_addresses.pcie_cfg_regs, &reg_routing_mercury, sizeof(reg_routing_mercury));
    PCIE_CONFIG_PCIE_CFG_QM_ROUTING_MODE_SET(reg_routing_mercury);
    write_memory(resources, compat[resources->board_type].fw_addresses.pcie_cfg_regs, &reg_routing_mercury, sizeof(reg_routing_mercury));
}

static void hailo_write_app_firmware(struct hailo_pcie_resources *resources, firmware_header_t *fw_header,
    secure_boot_certificate_header_t *fw_cert)
{
    const struct hailo_fw_addresses *fw_addresses = &(compat[resources->board_type].fw_addresses);
    u8 *fw_code = ((u8*)fw_header + sizeof(firmware_header_t));
    u8 *key_data = ((u8*)fw_cert + sizeof(secure_boot_certificate_header_t));
    u8 *content_data = key_data + fw_cert->key_size;

    write_memory(resources, fw_addresses->boot_fw_header, fw_header, sizeof(firmware_header_t));

    write_memory(resources, fw_addresses->app_fw_code_ram_base, fw_code, fw_header->code_size);

    write_memory(resources, fw_addresses->boot_key_cert, key_data, fw_cert->key_size);
    write_memory(resources, fw_addresses->boot_cont_cert, content_data, fw_cert->content_size);
}

static void hailo_write_core_firmware(struct hailo_pcie_resources *resources, firmware_header_t *fw_header)
{
    const struct hailo_fw_addresses *fw_addresses = &(compat[resources->board_type].fw_addresses);
    void *fw_code = (void*)((u8*)fw_header + sizeof(firmware_header_t));

    write_memory(resources, fw_addresses->core_code_ram_base, fw_code, fw_header->code_size);
    write_memory(resources, fw_addresses->core_fw_header, fw_header, sizeof(firmware_header_t));
}

void hailo_trigger_firmware_boot(struct hailo_pcie_resources *resources, u32 stage)
{
    u32 pcie_finished = 1;

    write_memory(resources, compat[resources->board_type].stages[stage].trigger_address, (void*)&pcie_finished, sizeof(pcie_finished));
}

u32 hailo_get_boot_status(struct hailo_pcie_resources *resources)
{
    u32 boot_status = 0;
    const struct hailo_fw_addresses *fw_addresses = &(compat[resources->board_type].fw_addresses);

    read_memory(resources, fw_addresses->boot_status, &boot_status, sizeof(boot_status));

    return boot_status;
}

int hailo_pcie_read_scu_log(struct hailo_pcie_resources *resources,
    void *buffer, u32 *size)
{
    const struct hailo_fw_addresses *fw_addresses = &(compat[resources->board_type].fw_addresses);
    if (fw_addresses->scu_log_address == 0) {
        return -EINVAL;
    }
    *size = min(*size, HAILO_SCU_LOG_MAX_SIZE);
    read_memory(resources, fw_addresses->scu_log_address, buffer, *size);
    return 0;
}

/**
* Validates the FW headers.
* @param[in] address                    Address of the firmware.
* @param[in] firmware_size              Size of the firmware.
* @param[out] out_app_firmware_header   (optional) App firmware header
* @param[out] out_core_firmware_header  (optional) Core firmware header
* @param[out] out_firmware_cert         (optional) Firmware certificate header
*/
static int FW_VALIDATION__validate_fw_headers(uintptr_t firmware_base_address, size_t firmware_size,
    firmware_header_t **out_app_firmware_header, firmware_header_t **out_core_firmware_header,
    secure_boot_certificate_header_t **out_firmware_cert, enum hailo_board_type board_type,
    enum hailo_accelerator_type accelerator_type)
{
    firmware_header_t *app_firmware_header = NULL;
    firmware_header_t *core_firmware_header = NULL;
    secure_boot_certificate_header_t *firmware_cert = NULL;
    int err = -EINVAL;
    u32 consumed_firmware_offset = 0;

    err = FW_VALIDATION__validate_fw_header(firmware_base_address, firmware_size, MAXIMUM_APP_FIRMWARE_CODE_SIZE,
        &consumed_firmware_offset, &app_firmware_header, board_type);
    if (0 != err) {
        err = -EINVAL;
        goto exit;
    }

    err = FW_VALIDATION__validate_cert_header(firmware_base_address, firmware_size,
        &consumed_firmware_offset, &firmware_cert);
    if (0 != err) {
        err = -EINVAL;
        goto exit;
    }

    // Only validating with accelerator types of NNC since core firmware doesn't loaded over pcie
    if (HAILO_ACCELERATOR_TYPE_NNC == accelerator_type) {
        err = FW_VALIDATION__validate_fw_header(firmware_base_address, firmware_size, MAXIMUM_CORE_FIRMWARE_CODE_SIZE,
            &consumed_firmware_offset, &core_firmware_header, board_type);
        if (0 != err) {
            err = -EINVAL;
            goto exit;
        }
    }

    if (consumed_firmware_offset != firmware_size) {
        /* it is an error if there is leftover data after the last firmware header */
        err = -EINVAL;
        goto exit;
    }

    /* the out params are all optional */
    if (NULL != out_app_firmware_header) {
        *out_app_firmware_header = app_firmware_header;
    }
    if (NULL != out_firmware_cert) {
        *out_firmware_cert = firmware_cert;
    }
    if (NULL != out_core_firmware_header) {
        *out_core_firmware_header = core_firmware_header;
    }
    err = 0;

exit:
    return err;
}

static int write_single_file(struct hailo_pcie_resources *resources, const struct hailo_file_batch *file_info, const char *filename, struct device *dev)
{
    const struct firmware *firmware = NULL;
    firmware_header_t *app_firmware_header = NULL;
    secure_boot_certificate_header_t *firmware_cert = NULL;
    firmware_header_t *core_firmware_header = NULL;
    int err = 0;

    err = request_firmware_direct(&firmware, filename, dev);
    if (err < 0) {
        return err;
    }

    if (firmware->size > file_info->max_size) {
        release_firmware(firmware);
        return -EFBIG;
    }

    if (file_info->flags & HAILO_FILE_F_HAS_HEADER) {
        err = FW_VALIDATION__validate_fw_headers((uintptr_t)firmware->data, (u32)firmware->size, &app_firmware_header,
            &core_firmware_header, &firmware_cert, resources->board_type, resources->accelerator_type);
        if (err < 0) {
            release_firmware(firmware);
            return err;
        }

        hailo_write_app_firmware(resources, app_firmware_header, firmware_cert);
        if (file_info->flags & HAILO_FILE_F_HAS_CORE) {
            hailo_write_core_firmware(resources, core_firmware_header);
        }
    } else {
        write_memory(resources, file_info->address, (void*)firmware->data, firmware->size);
    }

    release_firmware(firmware);

    return 0;
}

int hailo_pcie_write_firmware_batch(struct device *dev, struct hailo_pcie_resources *resources, u32 stage)
{
    const struct hailo_pcie_loading_stage *stage_info = hailo_pcie_get_loading_stage_info(resources->board_type, stage);
    const struct hailo_file_batch *files_batch = stage_info->batch;
    const u8 amount_of_files = stage_info->amount_of_files_in_stage;
    int file_index = 0;
    int err = 0;

    for (file_index = 0; file_index < amount_of_files; file_index++)
    {
        const struct hailo_file_batch *file = &files_batch[file_index];
        char filename[FW_FILENAME_MAX_LEN] = {0};

        if (file->flags & HAILO_FILE_F_DYNAMIC_NAME) {
            hailo_resolve_dtb_filename(filename, resources->sku_id, file->filename);
        } else {
            memcpy(filename, file->filename, FW_FILENAME_MAX_LEN);
        }

        hailo_dev_notice(dev, "Writing file %s\n", filename);

        err = write_single_file(resources, file, filename, dev);
        if (err < 0) {
            if (file->flags & HAILO_FILE_F_MANDATORY) {
                hailo_dev_err(dev, "Failed with error %d to write file %s\n", err, filename);
                return err;
            }
        }

        hailo_dev_notice(dev, "File %s written successfully\n", filename);
    }

    hailo_trigger_firmware_boot(resources, stage);

    return 0;
}

bool hailo_pcie_is_firmware_loaded(struct hailo_pcie_resources *resources)
{
    u32 offset = ATR_PCIE_BRIDGE_OFFSET(1) + offsetof(struct hailo_atr_config, atr_trsl_addr_1);
    u32 atr_value = hailo_resource_read32(&resources->config, offset);

    return (PCIE_BLOCK_ADDRESS_ATR1 == atr_value);
}

bool hailo_pcie_wait_for_firmware(struct hailo_pcie_resources *resources)
{
    size_t retries;
    for (retries = 0; retries < FIRMWARE_LOAD_WAIT_MAX_RETRIES; retries++) {
        if (hailo_pcie_is_firmware_loaded(resources)) {
            return true;
        }

        msleep(FIRMWARE_LOAD_SLEEP_MS);
    }

    return false;
}

bool hailo_pcie_wait_for_boot(struct hailo_pcie_resources *resources)
{
    int count = COUNT_UNTIL_REACH_BOOTLOADER;
    while (count > 0) {
        if (hailo_get_boot_status(resources) == 1) {
            break;
        }
        msleep(TIME_COUNT_FOR_BOOTLOADER_MS);
        count--;
    }
    return (count > 0);
}

void hailo_pcie_update_channel_interrupts_mask(struct hailo_pcie_resources* resources, u32 channels_bitmap)
{
    // Nothing need to be done here since already enabled in hailo_pcie_enable_interrupts
    // TODO: HRT-16439 remove this
    (void)resources;
    (void)channels_bitmap;
}

void hailo_pcie_enable_interrupts(struct hailo_pcie_resources *resources)
{
    u32 mask = hailo_resource_read32(&resources->config, BSC_IMASK_HOST);
    mask |= BSC_ISTATUS_HOST_MASK;
    hailo_resource_write32(&resources->config, BSC_IMASK_HOST, mask);
    hailo_resource_write32(&resources->config, BCS_ISTATUS_HOST, 0xFFFFFFFF);
    hailo_resource_write32(&resources->config, BCS_DESTINATION_INTERRUPT_PER_CHANNEL, 0xFFFFFFFF);
    hailo_resource_write32(&resources->config, BCS_SOURCE_INTERRUPT_PER_CHANNEL, 0xFFFFFFFF);
}

void hailo_pcie_disable_interrupts(struct hailo_pcie_resources* resources)
{
    hailo_resource_write32(&resources->config, BSC_IMASK_HOST, 0);
}





bool hailo_pcie_is_device_connected(struct hailo_pcie_resources *resources)
{
    return PCI_VENDOR_ID_HAILO == hailo_resource_read16(&resources->config, PCIE_CONFIG_VENDOR_OFFSET);
}

int hailo_set_device_type(struct hailo_pcie_resources *resources)
{
    switch(resources->board_type) {
    case HAILO_BOARD_TYPE_HAILO15H_ACCELERATOR_MODE:
    case HAILO_BOARD_TYPE_HAILO15L:
        resources->accelerator_type = HAILO_ACCELERATOR_TYPE_NNC;
        break;
    case HAILO_BOARD_TYPE_HAILO10H:
    case HAILO_BOARD_TYPE_MARS:
        resources->accelerator_type = HAILO_ACCELERATOR_TYPE_SOC;
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

void hailo_read_sku_id(struct hailo_pcie_resources *resources)
{
    u32 gpio_values = 0;
    read_memory(resources, compat[resources->board_type].fw_addresses.sku_id_offset, &gpio_values, sizeof(u32));
    if (!hailo_test_bit(GPIO_SKU_ID_EN_BIT, &gpio_values)) {
        resources->sku_id = HAILO_SKU_ID_DEFAULT;
    } else {
        /* Extract individual SKU ID bits and combine them */
        resources->sku_id |= hailo_test_bit(GPIO_SKU_ID_0_BIT, &gpio_values) ? (1 << 0) : 0;
        resources->sku_id |= hailo_test_bit(GPIO_SKU_ID_1_BIT, &gpio_values) ? (1 << 1) : 0;
        resources->sku_id |= hailo_test_bit(GPIO_SKU_ID_2_BIT, &gpio_values) ? (1 << 2) : 0;
        resources->sku_id |= hailo_test_bit(GPIO_SKU_ID_3_BIT, &gpio_values) ? (1 << 3) : 0;
        resources->sku_id |= hailo_test_bit(GPIO_SKU_ID_4_BIT, &gpio_values) ? (1 << 4) : 0;
        resources->sku_id |= hailo_test_bit(GPIO_SKU_ID_5_BIT, &gpio_values) ? (1 << 5) : 0;
    }
}

struct hailo_vdma_hw hailo_pcie_vdma_hw = {
    .channel_id_mask = PCIE_CHANNEL_ID_MASK,
    .channel_id_shift = PCIE_CHANNEL_ID_SHIFT,
    .ddr_data_id = HAILO_PCIE_HOST_DMA_DATA_ID,
    .device_interrupts_bitmask = HAILO_PCIE_DMA_DEVICE_INTERRUPTS_BITMASK,
    .host_interrupts_bitmask = HAILO_PCIE_DMA_HOST_INTERRUPTS_BITMASK,
    .src_channels_bitmask = HAILO_PCIE_DMA_SRC_CHANNELS_BITMASK,
    .channels_count = MAX_PCIE_VDMA_CHANNELS_PER_ENGINE,
};

void hailo_pcie_soc_write_request(struct hailo_pcie_resources *resources,
    const struct hailo_pcie_soc_request *request)
{
    const struct hailo_fw_addresses *fw_addresses = &(compat[resources->board_type].fw_addresses);
    BUILD_BUG_ON_MSG((sizeof(*request) % sizeof(u32)) != 0, "Request must be a multiple of 4 bytes");

    hailo_resource_write_buffer(&resources->fw_access, 0, sizeof(*request), (void*)request);
    hailo_resource_write32(&resources->fw_access, fw_addresses->raise_ready_offset, FW_ACCESS_SOC_CONTROL_MASK);
}

void hailo_pcie_soc_read_response(struct hailo_pcie_resources *resources,
    struct hailo_pcie_soc_response *response)
{
    BUILD_BUG_ON_MSG((sizeof(*response) % sizeof(u32)) != 0, "Request must be a multiple of 4 bytes");
    hailo_resource_read_buffer(&resources->fw_access, 0, sizeof(*response), response);
}

/**
 * Program one FW file descriptors to the vDMA engine.
 *
 * @param file_address - the address of the file in the device memory.
 * @param buffer_size - the size of the file to program.
 * @param channel_index - the index of the channel to program.
 * @param raise_int_on_completion - true if this is the last descriptors chunk in the specific channel in the boot flow, false otherwise. If true - will enable
 * an IRQ for the relevant channel when the transfer is finished.
 * @param channel - the channel to program.
 * @param dev - the device to use.
 * @return the amount of descriptors programmed on success, negative error code on failure.
 */
static int hailo_pcie_program_one_file_descriptors(
    u32 file_address,
    u32 buffer_size,
    u8 channel_index,
    bool raise_int_on_completion,
    struct hailo_pcie_boot_dma_channel_state *channel,
    struct device *dev)
{
    enum hailo_vdma_interrupts_domain interrupts_domain = raise_int_on_completion ?
        HAILO_VDMA_INTERRUPTS_DOMAIN_HOST : HAILO_VDMA_INTERRUPTS_DOMAIN_NONE;
    const u64 masked_channel_id_for_encode_addr = HAILO_PCI_EP_HOST_DMA_DATA_ID;

    if (!channel || !channel->device_descriptors_list || !channel->host_descriptors_list) {
        hailo_dev_err(dev, "hailo_pcie_program_one_file_descriptors: Invalid parameters - received NULL pointer\n");
        return -EINVAL;
    }

    // Program device descriptors
    hailo_vdma_program_descriptors_in_chunk(
        file_address | masked_channel_id_for_encode_addr,
        ALIGN(buffer_size, HAILO_PCI_OVER_VDMA_PAGE_SIZE),
        channel->device_descriptors_list,
        channel->desc_program_num,
        buffer_size,
        0);

    // Program host descriptors
    return hailo_vdma_program_descriptors_list(
        &hailo_pcie_vdma_hw,
        channel->host_descriptors_list,
        channel->desc_program_num,
        &channel->sg_table,
        HAILO_PCI_OVER_VDMA_PAGE_SIZE * channel->desc_program_num,
        buffer_size,
        1,
        channel_index,
        interrupts_domain,
        false);
}

/**
 * Program one FW file to the vDMA engine using firmware data.
 *
 * @param fw_boot - pointer to the fw boot struct which includes all of the boot resources.
 * @param file_address - the address of the file in the device memory.
 * @param firmware - pointer to the firmware data to program.
 * @param raise_int_on_completion - true if this is the last file in the boot flow, false otherwise.
 * @param dev - the device to use.
 * @return 0 on success, negative error code on failure.
 */
static int pcie_program_one_file_common(struct hailo_pcie_fw_boot *fw_boot, u32 file_address,
    const struct firmware *firmware, bool raise_int_on_completion, struct device *dev)
{
    int desc_programmed = 0;
    size_t remaining_size = 0, data_offset = 0, desc_num_left = 0, current_desc_to_program = 0;
    struct hailo_pcie_boot_dma_state *boot_dma_state = &fw_boot->boot_dma_state;

    hailo_dev_dbg(dev, "Programming firmware file for DMA transfer\n");

    if (!firmware) {
        hailo_dev_err(dev, "No firmware provided\n");
        return -EINVAL;
    }

    // Set the remaining size as the whole file size to begin with
    remaining_size = firmware->size;

    while (remaining_size > 0) {
        struct hailo_pcie_boot_dma_channel_state *channel = &boot_dma_state->channels[boot_dma_state->curr_channel_index];
        bool is_last_desc_chunk_of_curr_channel = false;
        bool raise_interrupt_on_last_chunk = false;
        u32 channel_buffer_offset = 0;
        u32 size_to_program = 0;

        // Increment the channel index if the current channel is full
        if ((MAX_SG_DESCS_COUNT - 1) == channel->desc_program_num) {
            boot_dma_state->curr_channel_index++;
            
            // Check if we have exceeded the allocated number of channels
            if (boot_dma_state->curr_channel_index >= boot_dma_state->allocated_channels) {
                hailo_dev_err(dev, "Channel index %u exceeded allocated channels %u\n", 
                    boot_dma_state->curr_channel_index, boot_dma_state->allocated_channels);
                return -EINVAL;
            }
            
            channel = &boot_dma_state->channels[boot_dma_state->curr_channel_index];
            fw_boot->boot_used_channel_bitmap |= (1 << boot_dma_state->curr_channel_index);
        }

        // Calculate the number of descriptors left to program and the number of bytes left to program
        desc_num_left = (MAX_SG_DESCS_COUNT - 1) - channel->desc_program_num;

        // prepare the transfer buffer to make sure all the fields are initialized
        size_to_program = (u32)min(remaining_size, (desc_num_left * HAILO_PCI_OVER_VDMA_PAGE_SIZE));
        // no need to check for overflow since the variables are constant and always desc_program_num <= max u16 (65536)
        // & the buffer max size is 256 Mb << 4G (max u32)
        channel_buffer_offset = channel->desc_program_num * HAILO_PCI_OVER_VDMA_PAGE_SIZE;

        // Check if this is the last descriptor chunk to program in the whole boot flow
        current_desc_to_program = (size_to_program / HAILO_PCI_OVER_VDMA_PAGE_SIZE);
        if (channel->desc_program_num + current_desc_to_program > channel->device_descriptors_list->desc_count) {
            hailo_dev_err(dev, "Invalid descriptors range: (desc_index + descs_to_program > max_desc_index + 1) where: desc_index=%u, descs_to_program=%zu, max_desc_index=%u\n",
                channel->desc_program_num, current_desc_to_program, channel->device_descriptors_list->desc_count - 1);
            return -EINVAL;
        }

        // Check if this is the last descriptor chunk to program in the whole boot flow
        is_last_desc_chunk_of_curr_channel = ((MAX_SG_DESCS_COUNT - 1) ==
            (current_desc_to_program + channel->desc_program_num));
        raise_interrupt_on_last_chunk = (is_last_desc_chunk_of_curr_channel || (raise_int_on_completion &&
            (remaining_size == size_to_program)));

        // Copy firmware data to DMA buffer
        if (!channel->kernel_address || !channel->device_descriptors_list || !channel->host_descriptors_list) {
            hailo_dev_err(dev, "kernel_addresses is NULL or descriptor lists are NULL for channel %u\n",
                boot_dma_state->curr_channel_index);
            return -EINVAL;
        }
        memcpy((uint8_t*)channel->kernel_address + channel_buffer_offset,
            &((const uint8_t*)firmware->data)[data_offset], size_to_program);

        // Program the descriptors using common function
        desc_programmed = hailo_pcie_program_one_file_descriptors(
            file_address + (u32)data_offset,
            (u32)size_to_program,
            (u8)boot_dma_state->curr_channel_index,
            raise_interrupt_on_last_chunk,
            channel,
            dev);
        if (desc_programmed < 0) {
            hailo_dev_err(dev, "Failed to program descriptors on channel = %d\n",
                boot_dma_state->curr_channel_index);
            return desc_programmed;
        }
        hailo_dev_dbg(dev, "Programmed %d MB on channel = %d\n", size_to_program / 1024 / 1024,
            boot_dma_state->curr_channel_index);

        // Update remaining size, data_offset and desc_program_num for the next iteration
        remaining_size -= size_to_program;
        data_offset += size_to_program;
        channel->desc_program_num += desc_programmed;
    }

    hailo_dev_notice(dev, "Firmware file programmed successfully\n");
    return desc_programmed;
}

/**
 * Program the entire batch of firmware files to the vDMA engine.
 *
 * @param fw_boot - pointer to the fw boot struct which includes all of the boot resources.
 * @param resources - pointer to the hailo_pcie_resources struct.
 * @param stage - the stage to program.
 * @param dev - the device to use.
 * @return 0 on success, negative error code on failure.
 */
long hailo_pcie_program_firmware_batch_common(struct hailo_pcie_fw_boot *fw_boot,
    struct hailo_pcie_resources *resources, u32 stage, struct device *dev)
{
    long err = 0;
    u8 file_index = 0;
    const struct hailo_pcie_loading_stage *stage_info = hailo_pcie_get_loading_stage_info(resources->board_type, stage);
    const struct hailo_file_batch *files_batch = stage_info->batch;
    const u8 amount_of_files = stage_info->amount_of_files_in_stage;

    if (!fw_boot || !resources || !dev) {
        hailo_dev_err(dev, "Invalid parameters passed to program_firmware_batch_common\n");
        return -EINVAL;
    }

    hailo_dev_dbg(dev, "Programming firmware batch for stage %u (%d files)\n", stage, amount_of_files);

    for (file_index = 0; file_index < amount_of_files; file_index++) {
        const struct hailo_file_batch *file = &files_batch[file_index];
        const struct firmware *firmware = fw_boot->boot_dma_state.firmware_cache[file_index];
        u32 file_address = file->address;
        bool raise_int_on_completion = (file_index == (amount_of_files - 1));

        if (!firmware) {
            // assuming not mandatory, continue to next file
            hailo_dev_dbg(dev, "No cached firmware for file index %d, skipping\n", file_index);
            continue;
        }

        err = pcie_program_one_file_common(fw_boot, file_address, firmware,
            raise_int_on_completion, dev);
        if (err < 0) {
            if (file->flags & HAILO_FILE_F_MANDATORY) {
                hailo_dev_err(dev, "Failed to program mandatory firmware file index %d (error: %ld)\n", file_index, err);
                goto exit;
            }
        } else {
            hailo_dev_notice(dev, "Firmware file index %d programmed successfully\n", file_index);
        }
    }

    hailo_dev_notice(dev, "Firmware batch programming completed for stage %u\n", stage);

exit:
    return err;
}
