// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include "fw_logger.h"
#include "utils/logs.h"
#include "utils/integrated_nnc_utils.h"

int fw_logger_init(struct hailo_board *board)
{
    int err = -EINVAL;
    struct hailo_resource fw_logger;

    err = hailo_ioremap_resource(board->pDev, &fw_logger, "core-fw-log");
    if (err < 0) {
        hailo_err(board, "Failed ioremap fw logger. err %d\n", err);
        return err;
    }

    board->fw_logger = fw_logger;

    return 0;
}