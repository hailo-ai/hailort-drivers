// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_LINUX_TYPES_H_
#define _HAILO_LINUX_TYPES_H_

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

typedef uint64_t  dma_addr_t;

#if !defined(U32_MAX)
#define U32_MAX ((u32)~0U)
#endif

#ifndef UINT_MAX
#define UINT_MAX	(~0U)
#endif

#define _CSTDINT_
#define _VCRUNTIME_H

#include <sys/types.h>
#include <cstddef>


#define false               FALSE
#define true                TRUE

// On msvc, we don't have likely and unlikely - so we just don't this optimization
#define unlikely(x) (x)
#define likely(x) (x)

#elif defined(__QNX__)

#include <stdint.h>
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/syspage.h>
#include <sys/neutrino.h>
#include <inttypes.h>

// TODO: HRT-6138

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

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

#ifndef UINT_MAX
#define UINT_MAX	(~0U)
#endif

#if !defined(U32_MAX)
#define U32_MAX ((u32)~0U)
#endif

#else

#error "Unsupported Platform"

#endif

#include "hailo_ioctl_common.h"

#endif /* _HAILO_LINUX_TYPES_H_ */
