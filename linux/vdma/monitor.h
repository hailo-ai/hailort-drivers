// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
 **/
/**
 * Hailo vdma monitor definitions
 */

#ifndef _HAILO_VDMA_MONITOR_H_
#define _HAILO_VDMA_MONITOR_H_

#include <linux/timer.h>
#include <linux/spinlock.h>

struct hailo_vdma_monitor {
    spinlock_t lock;
    struct timer_list timer;

    int ongoing_transfers;
    u64 in_use_cnt;
    u64 total_cnt;
};

void hailo_vdma_monitor_init(struct hailo_vdma_monitor *monitor);
long hailo_vdma_monitor_start(struct hailo_vdma_monitor *monitor);
void hailo_vdma_monitor_stop(struct hailo_vdma_monitor *monitor);

static inline void hailo_vdma_monitor_inc_ongoing(struct hailo_vdma_monitor *monitor)
{
    unsigned long flags = 0;

    spin_lock_irqsave(&monitor->lock, flags);
    monitor->ongoing_transfers++;
    spin_unlock_irqrestore(&monitor->lock, flags);
}

static inline void hailo_vdma_monitor_dec_ongoing(struct hailo_vdma_monitor *monitor)
{
    unsigned long flags = 0;

    spin_lock_irqsave(&monitor->lock, flags);
    monitor->ongoing_transfers--;
    spin_unlock_irqrestore(&monitor->lock, flags);
}

ssize_t hailo_vdma_monitor_show(struct hailo_vdma_monitor *monitor, char *buf);

#endif // _HAILO_VDMA_MONITOR_H_
