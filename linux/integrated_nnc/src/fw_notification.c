// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include "fw_notification.h"
#include "utils/logs.h"
#include "utils/integrated_nnc_utils.h"
#include "utils/fw_common.h"
#include "fw_operation.h"

#include <linux/uaccess.h>
#include <asm/io.h>
#include <linux/of_address.h>
#include <linux/slab.h>

static void notification_rx_callback(struct mbox_client *cl, void *msg)
{
    struct hailo_notification_wait *notif_wait_cursor = NULL;
    unsigned long irq_saved_flags = 0;
    int err = 0;

    struct fw_notification *notification = container_of(cl, struct fw_notification, mbox_client);
    struct hailo_board *board = container_of(notification, struct hailo_board, fw_notification);

    spin_lock_irqsave(&board->notification_read_spinlock, irq_saved_flags);
    err = hailo_read_firmware_notification(&notification->rx_shmem, &board->notification_cache);
    spin_unlock_irqrestore(&board->notification_read_spinlock, irq_saved_flags);

    if (err < 0) {
        hailo_err(board, "Failed reading firmware notification");
    } else {
        rcu_read_lock();
        list_for_each_entry_rcu(notif_wait_cursor, &board->notification_wait_list, notification_wait_list)
        {
            complete(&notif_wait_cursor->notification_completion);
        }
        rcu_read_unlock();
    }
}

long fw_notification_init(struct hailo_board *board)
{
    long err = -EINVAL;
    struct mbox_chan *chan = NULL;
    struct mbox_client *cl = &board->fw_notification.mbox_client;
    const size_t minimum_size = sizeof(board->fw_notification.notification.buffer_len) +
        sizeof(board->fw_notification.notification.buffer);

    cl->dev = &board->pDev->dev;
    cl->rx_callback = notification_rx_callback;

    chan = mbox_request_channel(cl, HAILO15_CORE_NOTIFICATION_MAILBOX_INDEX);
    if (IS_ERR(chan)) {
        err = PTR_ERR(chan);
        hailo_err(board, "fw_notification_init, failed to request mbox. err:%ld\n", err);
        goto l_exit;
    }

    err = hailo_ioremap_shmem(board->pDev, HAILO15_CORE_NOTIFICATION_MAILBOX_RX_SHMEM_INDEX,
        &board->fw_notification.rx_shmem);
    if (err < 0) {
        hailo_err(board, "Failed ioremap notification rx shmem. err %ld\n", err);
        goto l_free_channel;
    }

    if (board->fw_notification.rx_shmem.size < minimum_size) {
        hailo_err(board, "fw notification rx shmem is too small. defined %zu bytes, minimum size is %lu\n", 
            board->fw_notification.rx_shmem.size, minimum_size);
        err = -EADDRNOTAVAIL;
        goto l_free_channel;
    }

    board->fw_notification.mbox_channel = chan;

    INIT_LIST_HEAD(&board->notification_wait_list);

    err = 0;
    goto l_exit;

l_free_channel:
    mbox_free_channel(chan);
l_exit:
    return err;
}

void fw_notification_release(struct hailo_board *board)
{
    mbox_free_channel(board->fw_notification.mbox_channel);
}

int hailo_add_notification_wait(struct hailo_board *board, struct file *filp)
{
    struct hailo_notification_wait *new_notification_wait = NULL;
    if (!(new_notification_wait = kmalloc(sizeof(*new_notification_wait), GFP_KERNEL))) {
        hailo_err(board, "Failed to allocate notification wait structure.\n");
        return -ENOMEM;
    }
    new_notification_wait->tgid = current->tgid;
    new_notification_wait->filp = filp;
    new_notification_wait->is_disabled = false;
    init_completion(&new_notification_wait->notification_completion);
    list_add_rcu(&new_notification_wait->notification_wait_list, &board->notification_wait_list);
    return 0;
}

static long hailo_get_notification_wait_thread(struct hailo_board *board, struct file *filp,
    struct hailo_notification_wait **current_waiting_thread)
{
    struct hailo_notification_wait *cursor = NULL;
    // note: safe to access without rcu because the notification_wait_list is closed only on file release
    list_for_each_entry(cursor, &board->notification_wait_list, notification_wait_list)
    {
        if ((current->tgid == cursor->tgid) && (filp == cursor->filp)) {
            *current_waiting_thread = cursor;
            return 0;
        }
    }

    return -EFAULT;
}

long hailo_read_notification_ioctl(struct hailo_board *board, unsigned long arg, struct file *filp,
    bool *should_up_board_mutex)
{
    long err = 0;
    struct hailo_notification_wait *current_waiting_thread = NULL;
    struct hailo_d2h_notification *notification = &board->fw_notification.notification;
    unsigned long irq_saved_flags = 0;

    err = hailo_get_notification_wait_thread(board, filp, &current_waiting_thread);
    if (0 != err) {
        goto l_exit;
    }
    up(&board->mutex);

    if (0 > (err = wait_for_completion_interruptible(&current_waiting_thread->notification_completion))) {
        hailo_info(board,
            "HAILO_READ_NOTIFICATION - wait_for_completion_interruptible error. err=%ld. tgid=%d (process was interrupted or killed)\n",
            err, current_waiting_thread->tgid);
        *should_up_board_mutex = false;
        goto l_exit;
    }

    if (down_interruptible(&board->mutex)) {
        hailo_info(board, "HAILO_READ_NOTIFICATION - down_interruptible error (process was interrupted or killed)\n");
        *should_up_board_mutex = false;
        err = -ERESTARTSYS;
        goto l_exit;
    }

    // Check if was disabled
    if (current_waiting_thread->is_disabled) {
        hailo_info(board, "HAILO_READ_NOTIFICATION - notification disabled for tgid=%d\n", current->tgid);
        err = -ECANCELED;
        goto l_exit;
    }

    reinit_completion(&current_waiting_thread->notification_completion);
    
    spin_lock_irqsave(&board->notification_read_spinlock, irq_saved_flags);
    notification->buffer_len = board->notification_cache.buffer_len;
    memcpy(notification->buffer, board->notification_cache.buffer, notification->buffer_len);
    spin_unlock_irqrestore(&board->notification_read_spinlock, irq_saved_flags);

    if (copy_to_user((void __user*)arg, notification, sizeof(*notification))) {
        hailo_err(board, "HAILO_READ_NOTIFICATION copy_to_user fail\n");
        err = -ENOMEM;
        goto l_exit;
    }

l_exit:
    return err;
}

long hailo_disable_notification_ioctl(struct hailo_board *board, struct file *filp)
{
    struct hailo_notification_wait *cursor = NULL;

    hailo_info(board, "HAILO_DISABLE_NOTIFICATION: disable notification");
    rcu_read_lock();
    list_for_each_entry_rcu(cursor, &board->notification_wait_list, notification_wait_list) {
        if ((current->tgid == cursor->tgid) && (filp == cursor->filp)) {
            cursor->is_disabled = true;
            complete(&cursor->notification_completion);
            break;
        }
    }
    rcu_read_unlock();

    return 0;
}

void hailo_clear_notification_wait_list(struct hailo_board *board, struct file *filp)
{
    struct hailo_notification_wait *cur = NULL, *next = NULL;
    list_for_each_entry_safe(cur, next, &board->notification_wait_list, notification_wait_list) {
        if (cur->filp == filp) {
            list_del_rcu(&cur->notification_wait_list);
            synchronize_rcu();
            kfree(cur);
        }
    }
}
