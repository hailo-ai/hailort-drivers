// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
 **/

#include "logs.h"
#include "vdma.h"
#include "utils/compact.h"

#include "monitor.h"

static void mon_timer_callback(struct timer_list *timer)
{
    struct hailo_vdma_monitor *monitor = container_of(timer, struct hailo_vdma_monitor, timer);
    unsigned long flags = 0;

    spin_lock_irqsave(&monitor->lock, flags);

    if (monitor->ongoing_transfers > 0) {
        monitor->in_use_cnt++;
    }
    monitor->total_cnt++;

    spin_unlock_irqrestore(&monitor->lock, flags);

    // Retrigger the timer next jiffy.
    if (mod_timer(&monitor->timer, jiffies)) {
        struct hailo_vdma_controller *controller = container_of(monitor, struct hailo_vdma_controller, monitor);
        hailo_dev_err(controller->dev, "hailo_vmda_monitor failed to set next timer\n");
    }
}

ssize_t hailo_vdma_monitor_show(struct hailo_vdma_monitor *monitor, char *buf)
{
    return sprintf(buf, "INUSE\tTOTAL\n%llu\t%llu\n", monitor->in_use_cnt, monitor->total_cnt);
}

void hailo_vdma_monitor_init(struct hailo_vdma_monitor *monitor)
{
    monitor->ongoing_transfers = 0;
    monitor->in_use_cnt = 0;
    monitor->total_cnt = 0;
    spin_lock_init(&monitor->lock);
    timer_setup(&monitor->timer, mon_timer_callback, 0);
}

long hailo_vdma_monitor_start(struct hailo_vdma_monitor *monitor)
{
    return mod_timer(&monitor->timer, jiffies);
}

void hailo_vdma_monitor_stop(struct hailo_vdma_monitor *monitor)
{
    timer_delete_sync(&monitor->timer);
}
