// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_INTEGRATED_NNC_VERSION_H_
#define _HAILO_INTEGRATED_NNC_VERSION_H_

#include <linux/stringify.h>

#define HAILO_DRV_VER_MAJOR 4
#define HAILO_DRV_VER_MINOR 17
#define HAILO_DRV_VER_REVISION 1

#define HAILO_DRV_VER __stringify(HAILO_DRV_VER_MAJOR) "." __stringify(HAILO_DRV_VER_MINOR) "."  __stringify(HAILO_DRV_VER_REVISION)

#endif /* _HAILO_INTEGRATED_NNC_VERSION_H_ */
