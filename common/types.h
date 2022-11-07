// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_COMMON_TYPES_H_
#define _HAILO_COMMON_TYPES_H_

#ifdef _MSC_VER

#include <wdm.h>

typedef ULONG uint32_t;
typedef UCHAR uint8_t;
typedef USHORT uint16_t;
typedef ULONGLONG uint64_t;
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;

#if !defined(U32_MAX)
#define U32_MAX ((u32)~0U)
#endif


#define _CSTDINT_
#define _VCRUNTIME_H

#include <sys/types.h>
#include <cstddef>

#pragma warning(disable:4200)

#if !defined(EIO)
#define EIO         5
#endif

#if !defined(ENOMEM)
#define ENOMEM      12
#endif

#if !defined(EFAULT)
#define EFAULT      14
#endif

#if !defined(ENODEV)
#define ENODEV 19
#endif

#if !defined(EINVAL)
#define EINVAL      22
#endif

#if !defined(ETIMEDOUT)
#define ETIMEDOUT   60
#endif

#if !defined(ENOSYS)
#define ENOSYS 88
#endif

#define KERN_ERR            "x2"
#define KERN_WARNING        "x3"
#define KERN_INFO           "x4"
#define KERN_NOTICE         "x5"

#define BUG_ON(condition)   if (condition) { KeBugCheckEx(0xE4A12000, (ULONG_PTR)__FILE__, __LINE__, 0, 0); } else {}

#define false               FALSE
#define true                TRUE

#define BITS_PER_LONG           32
#define UL(x)                   ((unsigned long)x)
#define BIT_MASK(nr)		    (UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		    ((nr) / BITS_PER_LONG)

#define CIRC_CNT(head,tail,size) (((head) - (tail)) & ((size)-1))
#define CIRC_SPACE(head,tail,size) CIRC_CNT((tail),((head)+1),(size))

#define IS_ALIGNED(p, n) (((ULONG_PTR)(p) & (n - 1)) == 0)

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

// Make device an empty strcut becasue we dont use it in windows - just need it to be defined as a struct to match 
//  Function signatures
typedef struct device
{   
    int : 0;  
} device;

typedef struct firmware
{
    uint32_t        size;
    const uint8_t*  data;
    /* firmware loader private fields */
    void*           priv;
} firmware;

void FORCEINLINE msleep(ULONG milliseconds)
{
    LARGE_INTEGER li;
    li.QuadPart = -10000LL * milliseconds;
    KeDelayExecutionThread(KernelMode, false, &li);
}

static void FORCEINLINE udelay(ULONG microseconds)
{
    LARGE_INTEGER li;
    li.QuadPart = -10LL * microseconds;
    KeDelayExecutionThread(KernelMode, 0, &li);
}

static uint64_t FORCEINLINE ktime_get_ns()
{
    ULONG64 qpcTimeStamp;
    ULONG64 val = KeQueryInterruptTimePrecise(&qpcTimeStamp);
    val *= 100LL;
    return val;
}

BOOLEAN FORCEINLINE copy_to_user(void *dst, void *src, size_t len)
{
    memcpy(dst, src, len);
    return true;
}

#elif defined(__linux__)

#include <linux/version.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/circ_buf.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/uaccess.h>

#elif defined(__QNX__)

#include <stdint.h>
#include <sys/types.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/syspage.h>
#include <sys/neutrino.h>
#include <inttypes.h>

// TODO: HRT-6138
#define IS_ALIGNED(x, a)        (((x) & ((typeof(x))(a) - 1)) == 0)
#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))
#define BUG_ON(condition)   if (condition) { printf("CRITICAL ERROR CAUGHT\n"); exit(0); } else {}
#define BITS_PER_LONG           32
#define UL(x)                   ((unsigned long)x)
#define BIT_MASK(nr)		    (UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		    ((nr) / BITS_PER_LONG)

#define CIRC_CNT(head,tail,size) (((head) - (tail)) & ((size)-1))
#define CIRC_SPACE(head,tail,size) CIRC_CNT((tail),((head)+1),(size))

#define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

// At the moment dont do anything special for QNX
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;

// Define dma_addr_t as physical memory address for QNX
typedef uint64_t dma_addr_t;

#if !defined(INT_MAX)
#define INT_MAX 0x7FFFFFFF
#endif

#if !defined(U32_MAX)
#define U32_MAX ((u32)~0U)
#endif

inline static bool copy_to_user(void *dst, void *src, size_t len)
{
    memcpy(dst, src, len);
    return true;
}

inline static void msleep(int milliseconds)
{
    usleep(milliseconds * 1000);
}

inline static uint64_t ktime_get_ns()
{
    return (ClockCycles() / SYSPAGE_ENTRY(qtime)->cycles_per_sec) * 1000000;
}

struct hailo_bar {
    uintptr_t   mapped_address;
    uintptr_t   phys_address;
    uint64_t    length;
};

#else

#error "Unsupported Platform"

#endif

#include "hailo_ioctl_common.h"

#endif /* _HAILO_COMMON_TYPES_H_ */
