// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
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
};

struct hailo_vdma_engine_resources
{
    int irq;
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
    struct hailo_memory_transfer_params memory_transfer_params;
};

#endif //_BOARD_H_