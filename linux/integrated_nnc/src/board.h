// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _BOARD_H_
#define _BOARD_H_

#include <linux/platform_device.h>
#include <linux/reset.h>
#include <linux/cdev.h>
#include <linux/semaphore.h>
#include <linux/mailbox_client.h>
#include "hailo_ioctl_common.h"
#include "vdma/vdma.h"

enum irq_type {
    IRQ_TYPE_INPUT = 0,
    IRQ_TYPE_OUTPUT = 1,
    IRQ_TYPE_BOTH = 2,
    MAX_IRQ_TYPE = 3
};

struct vdma_interrupt_data
{
    u16 vdma_interrupt_mask_offset;
    u16 vdma_interrupt_status_offset;
    u16 vdma_interrupt_w1c_offset;
    enum irq_type irq_type;
};

// Support up to 2 IRQs for MARS compatability
#define MAX_INTERRUPTS_PER_ENGINE (2)

struct integrated_board_data {
    enum hailo_board_type board_type;
    const struct vdma_interrupt_data *vdma_interrupts_data;
    const char *fw_filename;
};

// TODO: HRT-14781: remove this enum when every integrated uses BKC that has memory region
enum nnc_fw_shared_mem_type {
    NNC_FW_SHARED_MEM_TYPE_MEMORY_REGION = 0,
    NNC_FW_SHARED_MEM_TYPE_CONTINOUS_BUFFER = 1,
    NNC_FW_SHARED_MEM_TYPE_NONE = 2,
};

struct nnc_fw_shared_mem_info {
    enum nnc_fw_shared_mem_type type;
    uintptr_t   dma_address;
    void        *kernel_address;
    size_t      size;
};

struct fw_control
{
    // protects that only one fw control will be send at a time
    struct semaphore mutex;
    // the command we are currently handling
    struct hailo_fw_control command;
    // the mailbox client for sending controls to vpu firmware
    struct mbox_client mbox_client;
    // the mailbox channel for sending controls to vpu firmware
    struct mbox_chan *mbox_channel;
    // hailo resource of the tx shmem buffer
    struct hailo_resource tx_shmem;
    // hailo resource of the rx shmem buffer
    struct hailo_resource rx_shmem;

    struct completion response_ready;
};

struct fw_notification
{
    // the notification we are currently handling
    struct hailo_d2h_notification notification;
    // the mailbox client for receiving notification from vpu firmware
    struct mbox_client mbox_client;
    // the mailbox channel for receiving notification from vpu firmware
    struct mbox_chan *mbox_channel;
    // hailo resource of the rx shmem buffer
    struct hailo_resource rx_shmem;
};

struct driver_down_notification
{
    // the mailbox client for receiving notification from vpu firmware
    struct mbox_client mbox_client;
    // the mailbox channel for receiving notification from vpu firmware
    struct mbox_chan *mbox_channel;
    // Response completion
    struct completion response_ready;
};

struct hailo_integrated_nnc_cpu {
    struct reset_control *reset;
    struct hailo_resource fw_header;
    struct hailo_resource fw_code;
    struct hailo_resource fw_isr_vector;

    // nnc cpu reference count
    atomic_t ref_count;
};

struct irq_info {
    int irq;
    enum irq_type type;
    int engine_index;
    struct device *dev;
};

struct hailo_vdma_engine_resources
{
    struct hailo_resource channel_registers;
    struct hailo_resource engine_registers;
};

struct hailo_board
{
    struct platform_device *pDev;
    struct cdev cdev;
    struct hailo_integrated_nnc_cpu integrated_nnc_cpu;
    struct reset_control *nn_core_reset;
    struct class *class;
    dev_t dev;
    struct semaphore mutex;
    struct fw_control fw_control;
    struct fw_notification fw_notification;
    struct driver_down_notification driver_down_notification;
    struct hailo_d2h_notification notification_cache;
    spinlock_t notification_read_spinlock;
    struct list_head notification_wait_list;
    struct hailo_resource fw_logger;
    struct hailo_vdma_controller vdma;
    struct hailo_vdma_engine_resources vdma_engines_resources[MAX_VDMA_ENGINES];
    // Store transfer params here to avoid stack/dynamic allocation.

    // TODO: HRT-14781: remove this when every integrated uses BKC that has memory region
    struct hailo_vdma_continuous_buffer nnc_fw_shared_memory_continuous_buffer;
    struct nnc_fw_shared_mem_info nnc_fw_shared_mem_info;
    struct integrated_board_data *board_data;
    struct irq_info irqs_info[MAX_VDMA_ENGINES][MAX_INTERRUPTS_PER_ENGINE];
};

#endif //_BOARD_H_