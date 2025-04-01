// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _DRIVER_DOWN_H
#define _DRIVER_DOWN_H

#include "board.h"

long driver_down_notification_init(struct hailo_board *board);
void driver_down_notification_release(struct hailo_board *board);
long hailo_driver_down_notification(struct hailo_board *board);

#endif /* _DRIVER_DOWN_H */