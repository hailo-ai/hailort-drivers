// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#include "board.h"
#include "integrated_nnc_utils.h"
#include "utils/logs.h"

#include <linux/uaccess.h>
#include <asm/io.h>
#include <linux/of_address.h>

int hailo_ioremap_resource(struct platform_device *pdev, struct hailo_resource *resource,
    const char *name)
{
    void __iomem *address;
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
int hailo_ioremap_shmem(struct hailo_board *board, int index, struct hailo_resource *resource)
{
    int ret;
    struct resource res;
    struct device_node *shmem;
    void __iomem * remap_ptr;

    shmem = of_parse_phandle(board->pDev->dev.of_node, "shmem", index);
    ret = of_address_to_resource(shmem, 0, &res);
    if (ret) {
        hailo_err(board, "hailo_ioremap_shmem, failed to get memory (index: %d)\n", index);
        return ret;
    }
    of_node_put(shmem);

    remap_ptr = devm_ioremap(&board->pDev->dev, res.start, resource_size(&res));
    if (!remap_ptr) {
        hailo_err(board, "hailo_ioremap_shmem, failed to ioremap shmem (index: %d)\n", index);
        return -EADDRNOTAVAIL;
    }

    resource->address = (uintptr_t)remap_ptr;
    resource->size = resource_size(&res);

    return 0;
}