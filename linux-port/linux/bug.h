// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2023 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_LINUX_PORT_BUG_H_
#define _HAILO_LINUX_PORT_BUG_H_

#ifdef _MSC_VER

#define BUG_ON(condition)   if (condition) { KeBugCheckEx(0xE4A12000, (ULONG_PTR)__FILE__, __LINE__, 0, 0); } else {}

#elif defined(__QNX__)

#define BUG_ON(condition)   if (condition) { printf("CRITICAL ERROR CAUGHT\n"); exit(0); } else {}

#else
#error "Unsupported Platform"
#endif

#endif /* _HAILO_LINUX_PORT_BUG_H_ */