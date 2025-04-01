// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _FW_NOTIFICATION_H_
#define _FW_NOTIFICATION_H_

#include "board.h"

long fw_notification_init(struct hailo_board *board);
void fw_notification_release(struct hailo_board *board);

int hailo_add_notification_wait(struct hailo_board *board, struct file *filp);
long hailo_read_notification_ioctl(struct hailo_board *board, unsigned long arg, struct file *filp,
    bool *should_up_board_mutex);
long hailo_disable_notification_ioctl(struct hailo_board *board, struct file *filp);
void hailo_clear_notification_wait_list(struct hailo_board *board, struct file *filp);

#endif /* _FW_NOTIFICATION_H_ */