// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _INTEGRATED_NNC_UTILS_H_
#define _INTEGRATED_NNC_UTILS_H_

#include "board.h"

#define HAILO15_CORE_CONTROL_MAILBOX_INDEX (0)
#define HAILO15_CORE_NOTIFICATION_MAILBOX_INDEX (1)
#define HAILO15_CORE_DRIVER_DOWN_MAILBOX_INDEX (2)

#define HAILO15_CORE_CONTROL_MAILBOX_TX_SHMEM_INDEX (0)
#define HAILO15_CORE_CONTROL_MAILBOX_RX_SHMEM_INDEX (1)
#define HAILO15_CORE_NOTIFICATION_MAILBOX_RX_SHMEM_INDEX (2)

int hailo_ioremap_resource(struct platform_device *pdev, struct hailo_resource *resource,
    const char *name);

// TODO: HRT-8475 - change to name instead of index
int hailo_ioremap_shmem(struct hailo_board *board, int index, struct hailo_resource *resource);

#endif /* _INTEGRATED_NNC_UTILS_H_ */
