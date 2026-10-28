// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
 **/
/**
 * Platform bindings for the shared vDMA layer (common/include/vdma).
 * Picked up by vdma/platform.h via __has_include(<vdma_platform.h>).
 **/

#ifndef _HAILO_DRIVER_VDMA_PLATFORM_H_
#define _HAILO_DRIVER_VDMA_PLATFORM_H_

#include <linux/types.h>
#include <linux/io.h>

#define vdma_iomem __iomem

static inline uint32_t vdma_platform_read32(const uint32_t vdma_iomem *reg)
{
    return ioread32((void vdma_iomem *)reg);
}

static inline void vdma_platform_write32(uint32_t vdma_iomem *reg, uint32_t value)
{
    iowrite32(value, reg);
}

#endif /* _HAILO_DRIVER_VDMA_PLATFORM_H_ */
