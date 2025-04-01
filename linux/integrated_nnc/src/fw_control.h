// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _FW_CONTROL_H_
#define _FW_CONTROL_H_

#include "board.h"

long fw_control_init(struct hailo_board *board);
void fw_control_release(struct hailo_board *board);
long hailo_fw_control(struct hailo_board *board, unsigned long arg, bool *should_up_board_mutex);

#endif /* _FW_CONTROL_H_ */