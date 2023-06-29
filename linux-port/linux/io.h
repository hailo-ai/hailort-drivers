// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2023 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_LINUX_PORT_IO_H_
#define _HAILO_LINUX_PORT_IO_H_

#include <sys/types.h>

static uint8_t ioread8(volatile void* src)
{
    return *(volatile uint8_t*)src;
}

static uint16_t ioread16(volatile void* src)
{
    return *(volatile uint16_t*)src;
}

static uint32_t ioread32(volatile void* src)
{
    return *(volatile uint32_t*)src;
}

static void iowrite8(uint8_t value, volatile void* dest)
{
    *(volatile uint8_t*)dest = value;
}

static void iowrite16(uint16_t value, volatile void* dest)
{
    *(volatile uint16_t*)dest = value;
}

static void iowrite32(uint32_t value, volatile void* dest)
{
    *(volatile uint32_t *)dest = value;
}

#endif /* _HAILO_LINUX_PORT_IO_H_ */