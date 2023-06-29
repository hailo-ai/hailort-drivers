// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2023 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_LINUX_TIMEKEEPING_H_
#define _HAILO_LINUX_TIMEKEEPING_H_

#ifdef _MSC_VER

static uint64_t FORCEINLINE ktime_get_ns()
{
    ULONG64 qpcTimeStamp;
    ULONG64 val = KeQueryInterruptTimePrecise(&qpcTimeStamp);
    val *= 100LL;
    return val;
}

#elif defined(__QNX__)

inline static uint64_t ktime_get_ns()
{
    return (ClockCycles() / SYSPAGE_ENTRY(qtime)->cycles_per_sec) * 1000000;
}

#else
#error "Unsupported Platform"
#endif

#endif /* _HAILO_LINUX_TIMEKEEPING_H_ */