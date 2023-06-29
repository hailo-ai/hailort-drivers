// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2023 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_LINUX_KERNEL_H_
#define _HAILO_LINUX_KERNEL_H_

#include <linux/types.h>


#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

#define IS_ALIGNED(p, n) (((uintptr_t)(p) & (n - 1)) == 0)
#define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))


#endif /* _HAILO_LINUX_KERNEL_H_ */