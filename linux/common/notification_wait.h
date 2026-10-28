// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_NOTIFICATION_WAIT_H_
#define _HAILO_NOTIFICATION_WAIT_H_

#include "hailo_ioctl_common.h"

struct hailo_notification_wait {
    struct list_head    notification_wait_list;
    int                 tgid;
    struct file*        filp;
    struct completion 	notification_completion;
    bool                is_disabled;
};

#endif /* _HAILO_NOTIFICATION_WAIT_H_ */
