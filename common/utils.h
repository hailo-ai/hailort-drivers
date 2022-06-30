// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_DRIVER_UTILS_H_
#define _HAILO_DRIVER_UTILS_H_

#ifdef __cplusplus
extern "C"
{
#endif

static inline bool is_powerof2(size_t v) {
    // bit trick
    return (v & (v - 1)) == 0;
}

#ifdef __cplusplus
}
#endif

#endif // _HAILO_DRIVER_UTILS_H_