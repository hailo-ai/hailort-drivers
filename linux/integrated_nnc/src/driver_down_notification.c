// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include "driver_down_notification.h"
#include "logs.h"
#include "utils/integrated_nnc_utils.h"

#include <linux/uaccess.h>
#include <asm/io.h>
#include <linux/of_address.h>

#if !defined(HAILO_EMULATOR)
#define DEFAULT_SHUTDOWN_TIMEOUT_MS (5)
#else /* !defined(HAILO_EMULATOR) */
#define DEFAULT_SHUTDOWN_TIMEOUT_MS (1000)
#endif /* !defined(HAILO_EMULATOR) */

long hailo_driver_down_notification(struct hailo_board *board)
{
    long err = 0;
    long completion_result = 0;
    // PL320 Mailbox must have non NULL address for TX side.
    // Using FW control shared memory space as valid address. The FW would not do anything with this address.
    void* driver_down_event_address = (void *)(board->fw_control.tx_shmem.address);

    reinit_completion(&board->driver_down_notification.response_ready);

    err = mbox_send_message(board->driver_down_notification.mbox_channel, driver_down_event_address);
    if (err < 0) {
        if (-ETIME == err) {
            hailo_err(board, "hailo_driver_down_notification, mbox_send_message timed out. timeout setting was %d ms\n",
                DEFAULT_SHUTDOWN_TIMEOUT_MS);
        } else {
            hailo_err(board, "hailo_driver_down_notification, mbox_send_message failed with errno: %ld\n", err);
        }
        goto l_exit;
    }

    completion_result =
        wait_for_completion_timeout(&board->driver_down_notification.response_ready, msecs_to_jiffies(DEFAULT_SHUTDOWN_TIMEOUT_MS));
    if (completion_result <= 0) {
        if (0 == completion_result) {
            hailo_err(board, "hailo_driver_down_notification, timeout waiting for control (timeout_ms=%d)\n",
                DEFAULT_SHUTDOWN_TIMEOUT_MS);
            err = -ETIMEDOUT;
        } else {
            hailo_info(board, "hailo_driver_down_notification, wait for completion failed with err=%ld (process was interrupted or killed)\n",
                completion_result);
            err = -EINTR;
        }
        goto l_exit;
    }

l_exit:
    return err;
}

static void driver_down_rx_callback(struct mbox_client *cl, void *mssg)
{
    struct driver_down_notification *driver_down = container_of(cl, struct driver_down_notification, mbox_client);
    complete(&driver_down->response_ready);
}

long driver_down_notification_init(struct hailo_board *board)
{
    long err = -EINVAL;
    struct mbox_chan *chan = NULL;
    struct mbox_client *cl = &board->driver_down_notification.mbox_client;

    cl->dev = &board->pdev->dev;
    cl->tx_block = true;
    cl->rx_callback = driver_down_rx_callback;

    chan = mbox_request_channel(cl, HAILO15_CORE_DRIVER_DOWN_MAILBOX_INDEX);
    if (IS_ERR(chan)) {
        err = PTR_ERR(chan);
        hailo_err(board, "driver_down_notification_init, failed to request mbox. err:%ld\n", err);
        goto l_exit;
    }

    board->driver_down_notification.mbox_channel = chan;
    init_completion(&board->driver_down_notification.response_ready);

    err = 0;
l_exit:
    return err;
}

void driver_down_notification_release(struct hailo_board *board)
{
    mbox_free_channel(board->driver_down_notification.mbox_channel);
}