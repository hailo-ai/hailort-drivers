// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_PCI_PCIE_H_
#define _HAILO_PCI_PCIE_H_

#include "vdma/vdma.h"
#include "hailo_ioctl_common.h"
#include "pcie_common.h"
#include "utils/fw_common.h"

#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/circ_buf.h>
#include <linux/device.h>

#include <linux/scatterlist.h>
#include <linux/ioctl.h>

struct hailo_fw_control_info {
    // protects that only one fw control will be send at a time
    struct semaphore    mutex;
    // called from the interrupt handler to notify that a response is ready
    struct completion   completion;
    // the command we are currently handling
    struct hailo_fw_control command;
};

struct hailo_pcie_driver_down_info {
    // called from the interrupt handler to notify that FW completed reset
    struct completion   reset_completed;
};

struct hailo_pcie_soft_reset {
    // called from the interrupt handler to notify that FW completed reset
    struct completion   reset_completed;
};

struct hailo_pcie_nnc {
    struct hailo_fw_control_info fw_control;
    spinlock_t notification_read_spinlock;
    struct list_head notification_wait_list;
    struct hailo_d2h_notification notification_cache;
    struct hailo_d2h_notification notification_to_user;
};

struct hailo_pcie_soc {
    struct completion control_resp_ready;
    bool driver_compatible;
};

// Context for each open file handle
struct hailo_file_context {
    struct list_head open_files_list;
    struct hailo_pcie_board *board;
    struct file *filp;
    struct hailo_vdma_file_context vdma_context;
    bool is_valid;
    u32 soc_used_channels_bitmap;
};

// Linux-specific extensions to the common hailo_pcie_fw_boot structure
struct hailo_pcie_fw_boot_linux {
    // Common base structure - must be first
    struct hailo_pcie_fw_boot common;
    
    // Linux-specific descriptor buffers - one per channel
    struct hailo_descriptors_list_buffer host_descriptors_buffers[HAILO_PCI_OVER_VDMA_MAX_CHANNELS];
    struct hailo_descriptors_list_buffer device_descriptors_buffers[HAILO_PCI_OVER_VDMA_MAX_CHANNELS];

    // Linux-specific completion events
    struct completion fw_loaded_completion;
    struct completion vdma_boot_completion;
    bool is_in_boot;
};

struct hailo_pcie_board {
    struct list_head board_list;
    struct pci_dev *pdev;
    u32 board_index;
    struct kref kref;
    struct list_head open_files_list;
    struct hailo_pcie_resources pcie_resources;
    struct hailo_pcie_nnc nnc;
    struct hailo_pcie_soc soc;
    struct hailo_pcie_driver_down_info driver_down;
    struct hailo_pcie_soft_reset soft_reset;
    struct semaphore mutex;
    struct hailo_vdma_controller vdma;
    struct hailo_pcie_fw_boot_linux fw_boot;
    u32 desc_max_page_size;
    bool interrupts_enabled;
};

bool power_mode_enabled(void);

struct hailo_pcie_board* hailo_pcie_get_board_by_index(u32 index);
void hailo_pcie_put_board(struct hailo_pcie_board *board);
void hailo_disable_interrupts(struct hailo_pcie_board *board);
int hailo_enable_interrupts(struct hailo_pcie_board *board);

#endif /* _HAILO_PCI_PCIE_H_ */

