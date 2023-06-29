// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2023 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_LINUX_DELAY_H_
#define _HAILO_LINUX_DELAY_H_

#ifdef _MSC_VER

void FORCEINLINE msleep(ULONG milliseconds)
{
    LARGE_INTEGER li;
    li.QuadPart = -10000LL * milliseconds;
    KeDelayExecutionThread(KernelMode, false, &li);
}

#elif defined(__QNX__)

inline static void msleep(int milliseconds)
{
    usleep(milliseconds * 1000);
}

#else
#error "Unsupported Platform"
#endif

#endif /* _HAILO_LINUX_DELAY_H_ */