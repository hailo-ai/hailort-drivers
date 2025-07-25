// SPDX-License-Identifier: MIT
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include "pcie_common.h"
#include "fw_operation.h"
#include "soc_structs.h"

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
#define GPIO_SKU_ID_EN_BIT  0  /* GPIO16 - GPIO_SKU_ID_EN */
#define GPIO_SKU_ID_0_BIT   1  /* GPIO17 - SKU ID[0] */
#define GPIO_SKU_ID_1_BIT   2  /* GPIO18 - SKU ID[1] */
#define GPIO_SKU_ID_2_BIT   3  /* GPIO19 - SKU ID[2] */
#define GPIO_SKU_ID_3_BIT   12  /* GPIO25 - SKU ID[3] */
#define GPIO_SKU_ID_4_BIT   13  /* GPIO26 - SKU ID[4] */
#define GPIO_SKU_ID_5_BIT   14  /* GPIO27 - SKU ID[5] */

#define DTB_FILENAME_TEMPLATE "hailo/hailo10h/u-boot-%d.dtb.signed"
#define DTB_FILENAME_DEFAULT "hailo/hailo10h/u-boot-default.dtb.signed"

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
        .is_mandatory = true,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = false
    },
    {
        .filename = "hailo/hailo10h/scu_fw.bin",
        .address = 0x20000,
        .max_size = 0x40000,
        .is_mandatory = true,
        .has_header = true,
        .has_core = false,
        .is_dynamic_filename = false
    }
};

static const struct hailo_file_batch hailo10h_files_stg2[] = {
    {
        .filename = "hailo/hailo10h/u-boot.dtb.signed",
        .address = 0xA8004,
        .max_size = 0x20000,
        .is_mandatory = true,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = true
    }
};

static const struct hailo_file_batch hailo10h_files_stg1_legacy_boot[] = {
    {
        .filename = "hailo/hailo10h/customer_certificate.bin",
        .address = 0xA0000,
        .max_size = 0x8004,
        .is_mandatory = true,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = false
    },
    {
        .filename = "hailo/hailo10h/u-boot.dtb.signed",
        .address = 0xA8004,
        .max_size = 0x20000,
        .is_mandatory = true,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = false
    },
    {
        .filename = "hailo/hailo10h/scu_fw.bin",
        .address = 0x20000,
        .max_size = 0x40000,
        .is_mandatory = true,
        .has_header = true,
        .has_core = false,
        .is_dynamic_filename = false
    }
};

static const struct hailo_file_batch hailo10h2_files_stg1[] = {
    {
        .filename = "hailo/hailo10h/customer_certificate.bin",
        .address = 0x88000,
        .max_size = 0x8004,
        .is_mandatory = true,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = false
    },
    {
        .filename = "hailo/hailo10h/scu_fw.bin",
        .address = 0x20000,
        .max_size = 0x40000,
        .is_mandatory = true,
        .has_header = true,
        .has_core = false,
        .is_dynamic_filename = false
    }
};

static const struct hailo_file_batch hailo10h2_files_stg2[] = {
    {
        .filename = "hailo/hailo10h/u-boot.dtb.signed",
        .address = 0x80004,
        .max_size = 0x20000,
        .is_mandatory = true,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = true
    }
};

static const struct hailo_file_batch hailo10h2_files_stg1_legacy_boot[] = {
    {
        .filename = "hailo/hailo10h/customer_certificate.bin",
        .address = 0x88000,
        .max_size = 0x8004,
        .is_mandatory = true,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = false
    },
    {
        .filename = "hailo/hailo10h/u-boot.dtb.signed",
        .address = 0x80004,
        .max_size = 0x20000,
        .is_mandatory = true,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = false
    },
    {
        .filename = "hailo/hailo10h/scu_fw.bin",
        .address = 0x20000,
        .max_size = 0x40000,
        .is_mandatory = true,
        .has_header = true,
        .has_core = false,
        .is_dynamic_filename = false
    }
};

// This second stage supports both hailo10h and hailo10hs (a.k.a hailo10h_family)
static const struct hailo_file_batch hailo10h_family_files_stg3[] = {
    {
        .filename = "hailo/hailo10h/u-boot-spl.bin",
        .address = 0x85000000,
        .max_size = 0x1000000,
        .is_mandatory = true,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = false
    },
    {
        .filename = "hailo/hailo10h/u-boot-tfa.itb",
        .address = 0x86000000,
        .max_size = 0x1000000,
        .is_mandatory = true,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = false
    },
    {
        .filename = "hailo/hailo10h/fitImage",
        .address = 0x87000000,
        .max_size = 0x1000000,
        .is_mandatory = true,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = false
    },
    {
        .filename = "hailo/hailo10h/image-fs",
#ifndef HAILO_EMULATOR
        .address = 0x88000000,
#else
        // TODO : HRT-15692 - merge two cases
        .address = 0x89000000,
#endif /* ifndef HAILO_EMULATOR */
        .max_size = 0x20000000, // Max size 512MB
        .is_mandatory = true,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = false
    }
};

static const struct hailo_file_batch hailo8_files_stg1[] = {
    {
        .filename = "hailo/hailo8_fw.bin",
        .address = 0x20000,
        .max_size = 0x50000,
        .is_mandatory = true,
        .has_header = true,
        .has_core = true,
        .is_dynamic_filename = false
    },
    {
        .filename = "hailo/hailo8_board_cfg.bin",
        .address = 0x60001000,
        .max_size = PCIE_HAILO8_BOARD_CFG_MAX_SIZE,
        .is_mandatory = false,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = false
    },
    {
        .filename = "hailo/hailo8_fw_cfg.bin",
        .address = 0x60001500,
        .max_size = PCIE_HAILO8_FW_CFG_MAX_SIZE,
        .is_mandatory = false,
        .has_header = false,
        .has_core = false,
        .is_dynamic_filename = false
    }
};

static const struct hailo_file_batch hailo15h_accelerator_mode_files_stg1[] = {
    {
        .filename = "hailo/hailo15_fw.bin",
        .address = 0x20000,
        .max_size = 0x100000,
        .is_mandatory = true,
        .has_header = true,
        .has_core = true,
        .is_dynamic_filename = false
    }
};

static const struct hailo_file_batch hailo15l_files_stg1[] = {
    {
        .filename = "hailo/hailo15l_fw.bin",
        .address = 0x20000,
        .max_size = 0x100000,
        .is_mandatory = true,
        .has_header = true,
        .has_core = true,
        .is_dynamic_filename = false
    }
};

static const struct hailo_board_compatibility compat[HAILO_BOARD_TYPE_COUNT] = {
    [HAILO_BOARD_TYPE_HAILO8] = {
        .fw_addresses = {
            .boot_fw_header = 0xE0030,
            .boot_key_cert = 0xE0048,
            .boot_cont_cert = 0xE0390,
            .app_fw_code_ram_base = 0x60000,
            .core_code_ram_base = 0xC0000,
            .core_fw_header = 0xA0000,
            .raise_ready_offset = 0x1684,
            .boot_status = 0xe0000,
        },
        .stages = {
            {
                .batch = hailo8_files_stg1,
                .trigger_address = 0xE0980,
                .timeout = FIRMWARE_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 3
            },
        },
    },
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
                .batch = hailo10h_family_files_stg3,
                .trigger_address = 0x84000000,
                .timeout = PCI_EP_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 4
            },
        },
    },
    [HAILO_BOARD_TYPE_HAILO10H_LEGACY_BOOT] = {
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
        },
        .stages = {
            {
                .batch = hailo10h_files_stg1_legacy_boot,
                .trigger_address = 0x88c98,
                .timeout = FIRMWARE_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 3
            },
            {
                .batch = hailo10h_family_files_stg3,
                .trigger_address = 0x84000000,
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
        },
        .stages = {
            {
                .batch = hailo10h2_files_stg1,
                .trigger_address = 0x98d18,
                .timeout = FIRMWARE_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 2
            },
            {
                .batch = hailo10h2_files_stg2,
                .trigger_address = 0x98d1c,
                .timeout = FIRMWARE_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 1
            },
            {
                .batch = hailo10h_family_files_stg3,
                .trigger_address = 0x84000000,
                .timeout = PCI_EP_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 4
            },
        },
    },
    [HAILO_BOARD_TYPE_MARS_LEGACY_BOOT] = {
        .fw_addresses = {
            .boot_fw_header = 0x98000,
            .boot_key_cert = 0x98018,
            .boot_cont_cert = 0x986a8,
            .app_fw_code_ram_base = 0x20000,
            .core_code_ram_base = 0,
            .core_fw_header = 0,
            .raise_ready_offset = 0x174c,
            .boot_status = 0x90000,
            .pcie_cfg_regs = 0x002009d4,
        },
        .stages = {
            {
                .batch = hailo10h2_files_stg1_legacy_boot,
                .trigger_address = 0x98d18,
                .timeout = FIRMWARE_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 3
            },
            {
                .batch = hailo10h_family_files_stg3,
                .trigger_address = 0x84000000,
                .timeout = PCI_EP_WAIT_TIMEOUT_MS,
                .amount_of_files_in_stage = 4
            },
        },
    },
};

void hailo_resolve_dtb_filename(char *filename, u32 sku_id)
{
    if (HAILO_SKU_ID_DEFAULT == sku_id) {
        snprintf(filename, FW_FILENAME_MAX_LEN, DTB_FILENAME_DEFAULT);
    } else {
        snprintf(filename, FW_FILENAME_MAX_LEN, DTB_FILENAME_TEMPLATE, sku_id);
    }
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

    if (file_info->has_header) {
        err = FW_VALIDATION__validate_fw_headers((uintptr_t)firmware->data, firmware->size, &app_firmware_header,
            &core_firmware_header, &firmware_cert, resources->board_type, resources->accelerator_type);
        if (err < 0) {
            release_firmware(firmware);
            return err;
        }

        hailo_write_app_firmware(resources, app_firmware_header, firmware_cert);
        if (file_info->has_core) {
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

        if (file->is_dynamic_filename) {
            hailo_resolve_dtb_filename(filename, resources->sku_id);
        } else {
            memcpy(filename, file->filename, FW_FILENAME_MAX_LEN);
        }

        dev_notice(dev, "Writing file %s\n", filename);

        err = write_single_file(resources, file, filename, dev);
        if (err < 0) {
            if (file->is_mandatory) {
                pr_err("Failed with error %d to write file %s\n err\n", err, filename);
                return err;
            }
        }

        dev_notice(dev, "File %s written successfully\n", filename);
    }

    hailo_trigger_firmware_boot(resources, stage);

    return 0;
}

bool hailo_pcie_is_firmware_loaded(struct hailo_pcie_resources *resources)
{
    u32 offset;
    u32 atr_value;

    if (HAILO_BOARD_TYPE_HAILO8 == resources->board_type) {
        offset = ATR_PCIE_BRIDGE_OFFSET(0) + offsetof(struct hailo_atr_config, atr_trsl_addr_1);
        atr_value = hailo_resource_read32(&resources->config, offset);

        return (PCIE_CONTROL_SECTION_ADDRESS_H8 == atr_value);
    }
    else {
        offset = ATR_PCIE_BRIDGE_OFFSET(1) + offsetof(struct hailo_atr_config, atr_trsl_addr_1);
        atr_value = hailo_resource_read32(&resources->config, offset);

        return (PCIE_BLOCK_ADDRESS_ATR1 == atr_value);
    }

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

static int direct_memory_transfer(struct hailo_pcie_resources *resources,
    struct hailo_memory_transfer_params *params)
{
    switch (params->transfer_direction) {
    case TRANSFER_READ:
        read_memory(resources, params->address, params->buffer, (u32)params->count);
        break;
    case TRANSFER_WRITE:
        write_memory(resources, params->address, params->buffer, (u32)params->count);
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

int hailo_pcie_memory_transfer(struct hailo_pcie_resources *resources, struct hailo_memory_transfer_params *params)
{
    if (params->count > ARRAY_SIZE(params->buffer)) {
        return -EINVAL;
    }

    switch (params->memory_type) {
    case HAILO_TRANSFER_DEVICE_DIRECT_MEMORY:
        return direct_memory_transfer(resources, params);
    case HAILO_TRANSFER_MEMORY_PCIE_BAR0:
        return hailo_resource_transfer(&resources->config, params);
    case HAILO_TRANSFER_MEMORY_PCIE_BAR2:
    case HAILO_TRANSFER_MEMORY_VDMA0:
        return hailo_resource_transfer(&resources->vdma_registers, params);
    case HAILO_TRANSFER_MEMORY_PCIE_BAR4:
        return hailo_resource_transfer(&resources->fw_access, params);
    default:
        return -EINVAL;
    }
}

bool hailo_pcie_is_device_connected(struct hailo_pcie_resources *resources)
{
    return PCI_VENDOR_ID_HAILO == hailo_resource_read16(&resources->config, PCIE_CONFIG_VENDOR_OFFSET);
}

int hailo_set_device_type(struct hailo_pcie_resources *resources)
{
    switch(resources->board_type) {
    case HAILO_BOARD_TYPE_HAILO8:
    case HAILO_BOARD_TYPE_HAILO15H_ACCELERATOR_MODE:
    case HAILO_BOARD_TYPE_HAILO15L:
        resources->accelerator_type = HAILO_ACCELERATOR_TYPE_NNC;
        break;
    case HAILO_BOARD_TYPE_HAILO10H:
    case HAILO_BOARD_TYPE_HAILO10H_LEGACY_BOOT:
    case HAILO_BOARD_TYPE_MARS:
    case HAILO_BOARD_TYPE_MARS_LEGACY_BOOT:
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
    .hw_ops = {
        .channel_id_mask = PCIE_CHANNEL_ID_MASK,
        .channel_id_shift = PCIE_CHANNEL_ID_SHIFT,
    },
    .ddr_data_id = HAILO_PCIE_HOST_DMA_DATA_ID,
    .device_interrupts_bitmask = HAILO_PCIE_DMA_DEVICE_INTERRUPTS_BITMASK,
    .host_interrupts_bitmask = HAILO_PCIE_DMA_HOST_INTERRUPTS_BITMASK,
    .src_channels_bitmask = HAILO_PCIE_DMA_SRC_CHANNELS_BITMASK,
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
