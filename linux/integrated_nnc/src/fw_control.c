// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include "fw_control.h"
#include "logs.h"
#include "utils/integrated_nnc_utils.h"

#include <linux/uaccess.h>
#include <asm/io.h>
#include <linux/of_address.h>

long hailo_fw_control(struct hailo_board *board, unsigned long arg, bool *should_up_board_mutex)
{
    long err = 0;
    long completion_result = 0;
    u32 request_size = 0;
    u32 response_header_size = 0;
    struct hailo_fw_control *command = &board->fw_control.command;
    struct hailo_resource tx_control = board->fw_control.tx_shmem;
    struct hailo_resource rx_control = board->fw_control.rx_shmem;

    up(&board->mutex);
    *should_up_board_mutex = false;

    if (down_interruptible(&board->fw_control.mutex)) {
        hailo_info(board, "hailo_fw_control down_interruptible fail tgid:%d (process was interrupted or killed)\n", current->tgid);
        return -ERESTARTSYS;
    }

    if (copy_from_user(command, (void __user*)arg, sizeof(*command))) {
        hailo_err(board, "hailo_fw_control, copy_from_user fail\n");
        err = -ENOMEM;
        goto l_exit;
    }

    if (sizeof(command->buffer) < command->buffer_len) {
        hailo_err(board, "hailo_fw_control, control length(%u bytes) is larger than maximum(%lu)\n",
            command->buffer_len, sizeof(command->buffer));
        err = -ENOMEM;
        goto l_exit;
    }

    request_size = sizeof(command->expected_md5) + sizeof(command->buffer_len) + command->buffer_len;
    memcpy_toio((void*)tx_control.address, command, request_size);

    reinit_completion(&board->fw_control.response_ready);

    board->fw_control.mbox_client.tx_tout = command->timeout_ms;
    err = mbox_send_message(board->fw_control.mbox_channel, (void*)tx_control.address);
    if (err < 0) {
        if (-ETIME == err) {
            hailo_err(board, "hailo_fw_control, mbox_send_message timed out. timeout setting was %d ms\n", command->timeout_ms);
        } else {
            hailo_err(board, "hailo_fw_control, mbox_send_message failed with errno: %ld\n", err);
        }
        goto l_exit;
    }

    completion_result = wait_for_completion_interruptible_timeout(&board->fw_control.response_ready,
        msecs_to_jiffies(command->timeout_ms));
    if (completion_result <= 0) {
        if (0 == completion_result) {
            hailo_err(board, "hailo_fw_control, timeout waiting for control (timeout_ms=%d)\n", command->timeout_ms);
            err = -ETIMEDOUT;
        } else {
            hailo_info(board, "hailo_fw_control, wait for completion failed with err=%ld (process was interrupted or killed)\n", completion_result);
            err = -EINTR;
        }
        goto l_exit;
    }

    response_header_size = sizeof(command->expected_md5) + sizeof(command->buffer_len);
    memcpy_fromio(command, (void*)rx_control.address, response_header_size);

    if (sizeof(command->buffer) < command->buffer_len) {
        hailo_err(board, "hailo_fw_control, response length(%u bytes) is larger than maximum(%lu)\n",
            command->buffer_len, sizeof(command->buffer));
        err = -ENOMEM;
        goto l_exit;
    }

    memcpy_fromio(&command->buffer, (void*)rx_control.address + response_header_size, command->buffer_len);

    if (copy_to_user((void __user*)arg, command, sizeof(*command))) {
        hailo_err(board, "hailo_fw_control, copy_to_user fail\n");
        err = -ENOMEM;
        goto l_exit;
    }

l_exit:
    up(&board->fw_control.mutex);
    return err;
}

static void rx_callback(struct mbox_client *cl, void *mssg)
{
    struct fw_control *control = container_of(cl, struct fw_control, mbox_client);
    complete(&control->response_ready);
}

long fw_control_init(struct hailo_board *board)
{
    long err = -EINVAL;
    struct mbox_chan *chan = NULL;
    struct mbox_client *cl = &board->fw_control.mbox_client;
    const size_t minimum_size = sizeof(board->fw_control.command.expected_md5) + sizeof(board->fw_control.command.buffer_len) 
        + sizeof(board->fw_control.command.buffer);

    cl->dev = &board->pdev->dev;
    cl->tx_block = true;
    cl->rx_callback = rx_callback;

    chan = mbox_request_channel(cl, HAILO15_CORE_CONTROL_MAILBOX_INDEX);
    if (IS_ERR(chan)) {
        err = PTR_ERR(chan);
        hailo_err(board, "fw_control_init, failed to request mbox. err:%ld\n", err);
        goto l_exit;
    }

    err = hailo_ioremap_shmem(board->pdev, HAILO15_CORE_CONTROL_MAILBOX_TX_SHMEM_INDEX, &board->fw_control.tx_shmem);
    if (err < 0) {
        hailo_err(board, "Failed ioremap control tx shmem. err %ld\n", err);
        goto l_free_channel;
    }

    err = hailo_ioremap_shmem(board->pdev, HAILO15_CORE_CONTROL_MAILBOX_RX_SHMEM_INDEX, &board->fw_control.rx_shmem);
    if (err < 0) {
        hailo_err(board, "Failed ioremap control rx shmem. err %ld\n", err);
        goto l_free_channel;
    }

    if (board->fw_control.tx_shmem.size < minimum_size || board->fw_control.rx_shmem.size < minimum_size) {
        hailo_err(board, "fw control shmem is too small. tx is %zu bytes, rx is %zu bytes, minimum size\
            is %lu\n", board->fw_control.tx_shmem.size, board->fw_control.rx_shmem.size, minimum_size);
        err = -EADDRNOTAVAIL;
        goto l_free_channel;
    }

    board->fw_control.mbox_channel = chan;
    sema_init(&board->fw_control.mutex, 1);
    init_completion(&board->fw_control.response_ready);

    err = 0;
    goto l_exit;

l_free_channel:
    mbox_free_channel(chan);
l_exit:
    return err;
}

void fw_control_release(struct hailo_board *board)
{
    mbox_free_channel(board->fw_control.mbox_channel);
}