// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_PLATFORM_RESOURCE_H_
#define _HAILO_PLATFORM_RESOURCE_H_

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>

#include "hailo_resource.h"

static inline int hailo_ioremap_resource(struct platform_device *pdev, struct hailo_resource *resource,
    const char *name)
{
    void __iomem *address = NULL;
    struct resource *platform_resource = platform_get_resource_byname(pdev, IORESOURCE_MEM, name);
    if (NULL == platform_resource) {
        return -ENOENT;
    }

    address = devm_ioremap_resource(&pdev->dev, platform_resource);
    if (IS_ERR(address)) {
        return PTR_ERR(address);
    }

    resource->address = (uintptr_t)address;
    resource->size = resource_size(platform_resource);

    return 0;
}

// TODO: HRT-8475 - change to name instead of index
static inline int hailo_ioremap_shmem(struct platform_device *pdev, int index, struct hailo_resource *resource)
{
    int err = 0;
    struct resource res = {0};
    struct device_node *shmem = NULL;
    void __iomem *remap_ptr = NULL;

    shmem = of_parse_phandle(pdev->dev.of_node, "shmem", index);
    if (NULL == shmem) {
        return -ENODEV;
    }

    err = of_address_to_resource(shmem, 0, &res);
    of_node_put(shmem);
    if (err < 0) {
        return err;
    }

    remap_ptr = devm_ioremap(&pdev->dev, res.start, resource_size(&res));
    if (NULL == remap_ptr) {
        return -EADDRNOTAVAIL;
    }

    resource->address = (uintptr_t)remap_ptr;
    resource->size = resource_size(&res);

    return 0;
}

static inline int hailo_get_resource_physical_addr(struct platform_device *pdev, const char *name, u64 *address)
{
    struct resource *platform_resource = platform_get_resource_byname(pdev, IORESOURCE_MEM, name);
    if (NULL == platform_resource) {
        return -ENOENT;
    }

    *address = (u64)(platform_resource->start);
    return 0;
}

#endif /* _HAILO_PLATFORM_RESOURCE_H_ */
