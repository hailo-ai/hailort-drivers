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

#include <linux/ioctl.h>

#define HAILO_PCI_OVER_VDMA_NUM_CHANNELS                (8)
#define HAILO_PCI_OVER_VDMA_PAGE_SIZE                   (512)

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

struct hailo_fw_boot {
    // the filp that enabled interrupts for fw boot. the interrupt is enabled if this is not null
    struct file *filp;
    // called from the interrupt handler to notify that an interrupt was raised
    struct completion completion;
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
// TODO: store board and use as actual context
struct hailo_file_context {
    struct list_head open_files_list;
    struct file *filp;
    struct hailo_vdma_file_context vdma_context;
    bool is_valid;
    u32 soc_used_channels_bitmap;
};

struct hailo_pcie_boot_dma_channel_state {
    struct hailo_descriptors_list_buffer host_descriptors_buffer;
    struct hailo_descriptors_list_buffer device_descriptors_buffer;
    struct sg_table sg_table;
    u64 buffer_size;
    void *kernel_addrs;
    u32 desc_program_num;
};

struct hailo_pcie_boot_dma_state {
    struct hailo_pcie_boot_dma_channel_state channels[HAILO_PCI_OVER_VDMA_NUM_CHANNELS];
    u8 curr_channel_index;
};

struct hailo_pcie_fw_boot {
    struct hailo_pcie_boot_dma_state boot_dma_state;
    // is_in_boot is set to true when the board is in boot mode
    bool is_in_boot;
    // boot_used_channel_bitmap is a bitmap of the channels that are used for boot
    u16 boot_used_channel_bitmap;
    // fw_loaded_completion is used to notify that the FW was loaded - SOC & NNC
    struct completion fw_loaded_completion;
    // vdma_boot_completion is used to notify that the vDMA boot data was transferred completely on all used channels for boot
    struct completion vdma_boot_completion;
};

struct hailo_pcie_board {
    struct list_head board_list;
    struct pci_dev *pDev;
    u32 board_index;
    atomic_t ref_count;
    struct list_head open_files_list;
    struct hailo_pcie_resources pcie_resources;
    struct hailo_pcie_nnc nnc;
    struct hailo_pcie_soc soc;
    struct hailo_pcie_driver_down_info driver_down;
    struct hailo_pcie_soft_reset soft_reset;
    struct semaphore mutex;
    struct hailo_vdma_controller vdma;

    struct hailo_pcie_fw_boot fw_boot;
    
    struct hailo_memory_transfer_params memory_transfer_params;
    u32 desc_max_page_size;
    enum hailo_allocation_mode allocation_mode;
    bool interrupts_enabled;
};

bool power_mode_enabled(void);

struct hailo_pcie_board* hailo_pcie_get_board_index(u32 index);
void hailo_disable_interrupts(struct hailo_pcie_board *board);
int hailo_enable_interrupts(struct hailo_pcie_board *board);
#endif /* _HAILO_PCI_PCIE_H_ */

