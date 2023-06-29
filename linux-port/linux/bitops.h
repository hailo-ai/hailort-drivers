// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2023 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_LINUX_BITOPS_H_
#define _HAILO_LINUX_BITOPS_H_

#define BITS_PER_LONG           32
#define UL(x)                   ((unsigned long)x)
#define BIT_MASK(nr)		    (UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		    ((nr) / BITS_PER_LONG)

#endif /* _HAILO_LINUX_BITOPS_H_ */