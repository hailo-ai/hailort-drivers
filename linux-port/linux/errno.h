// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2023 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_LINUX_PORT_ERRNO_H_
#define _HAILO_LINUX_PORT_ERRNO_H_

#ifdef _MSC_VER

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

#if !defined(ERANGE)
#define ERANGE 34
#endif


#if !defined(ETIMEDOUT)
#define ETIMEDOUT   60
#endif

#if !defined(ENOSYS)
#define ENOSYS 88
#endif


#elif defined(__QNX__)

#include <errno.h>

#else
#error "Unsupported Platform"
#endif

#endif /* _HAILO_LINUX_PORT_ERRNO_H_ */