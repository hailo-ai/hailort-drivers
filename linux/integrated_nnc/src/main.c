// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2023 Hailo Technologies Ltd. All rights reserved.
 **/

#include <linux/err.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/reset.h>
#include <linux/slab.h>
#include <asm-generic/errno-base.h>

#include "board.h"
#include "integrated_nnc_cpu.h"
#include "file_operations.h"
#include "fw_control.h"
#include "fw_notification.h"
#include "driver_down_notification.h"
#include "fw_logger.h"
#include "dram_vdma.h"
#include "utils/logs.h"
#include "utils/compact.h"

#define DRIVER_NAME "hailo_integrated_nnc"
#define DEVICE_NODE_NAME "hailo_integrated_nnc"

static ssize_t board_location_show(struct device *dev, struct device_attribute *_attr,
    char *buf)
{
    return sprintf(buf, "%s", "[integrated]");
}
static DEVICE_ATTR_RO(board_location);

static ssize_t accelerator_type_show(struct device *dev, struct device_attribute *_attr,
    char *buf)
{
    return sprintf(buf, "%d", HAILO_ACCELERATOR_TYPE_NNC);
}
static DEVICE_ATTR_RO(accelerator_type);

static struct attribute *hailo_dev_attrs[] = {
    &dev_attr_board_location.attr,
    &dev_attr_accelerator_type.attr,
    NULL
};

ATTRIBUTE_GROUPS(hailo_dev);

static int driver_probe(struct platform_device *pdev)
{
    struct device *device = NULL;
    struct reset_control *nn_core_reset = NULL;
    struct class *class = NULL;
    struct hailo_board *board = NULL;
    int err = -EINVAL;
    dev_t dev = 0;

    dev_notice(&pdev->dev, "Probing module. driver version %s\n", HAILO_DRV_VER);

    /* allocate board */
    board = devm_kzalloc(&pdev->dev, sizeof(*board), GFP_KERNEL);
    if (!board) {
        dev_err(&pdev->dev, "Unable to allocate device internal structure");
        goto l_exit;
    }

    sema_init(&board->mutex, 1);
    board->pDev = pdev;

    err = hailo_integrated_nnc_cpu_struct_init(board);
    if (err < 0) {
        goto l_exit;
    }

    /* Retrieve NN core reset from device-tree */
    nn_core_reset = devm_reset_control_get_exclusive(&pdev->dev, "nn-core");
    if (IS_ERR(nn_core_reset)) {
        err = PTR_ERR(nn_core_reset);
        hailo_err(board, "NN core reset get failed: %d\n", err);
        goto l_exit;
    }
    board->nn_core_reset = nn_core_reset;

    /* Initialize fw_control */
    err = fw_control_init(board);
    if (0 > err) {
        /* error already logged */
        goto l_exit;
    }

    /* Initialize breakpoint params */
    err = fw_notification_init(board);
    if (0 > err) {
        /* error already logged */
        goto l_fw_control_release;
    }

    /* Initialize breakpoint params */
    err = driver_down_notification_init(board);
    if (0 > err) {
        /* error already logged */
        goto l_fw_notification_release;
    }

    err = fw_logger_init(board);
    if (0 > err) {
        /* error already logged */
        goto l_driver_down_notification_release;
    }

    if (hailo_load_firmware(board)) {
        /* error already logged */
        goto l_driver_down_notification_release;
    }

    err = hailo_integrated_nnc_vdma_controller_init(board);
    if (0 > err) {
        hailo_err(board, "Failed init vdma controller. err: %d\n", err);
        goto l_driver_down_notification_release;
    }

    /*Creating cdev structure*/
    cdev_init(&board->cdev, &hailo_integrated_nnc_fops);
    board->cdev.owner = THIS_MODULE;

    /*Allocating Major number*/
    err = alloc_chrdev_region(&dev, /*baseminor: */0, /*count: */1, DRIVER_NAME);
    if(0 > err){
        hailo_err(board, "Cannot allocate major number. err: %d\n", err);
        goto l_driver_down_notification_release;
    }
    board->dev = dev;

    /* Adding character device to the system. The driver is live after this call */
    err = cdev_add(&board->cdev, dev, 1);
    if(0 > err){
        hailo_err(board, "Cannot add the device to the system. err: %d\n", err);
        goto l_chrdev_region;
    }

    /* Creating struct class */
    class = class_create_compat("hailo_chardev");
    if (IS_ERR(class)) {
        err = PTR_ERR(class);
        hailo_err(board, "Failed creating class. err: %d", err);
        goto l_cdev;
    }
    board->class = class;

    /* Creating device */
    device = device_create_with_groups(class, NULL, dev, NULL, hailo_dev_groups,
        DEVICE_NODE_NAME);
    if (IS_ERR(device)) {
        err = PTR_ERR(device);
        hailo_err(board, "Failed creating dynamic device. err: %d\n", err);
        goto l_class;
    }

    platform_set_drvdata(pdev, board);
    return 0;

l_class:
    class_destroy(class);
l_cdev:
    cdev_del(&board->cdev);
l_chrdev_region:
    unregister_chrdev_region(dev, 1);
l_driver_down_notification_release:
    driver_down_notification_release(board);
l_fw_notification_release:
    fw_notification_release(board);
l_fw_control_release:
    fw_control_release(board);
l_exit:
    return err;
}

static int driver_remove(struct platform_device *pdev)
{
    struct hailo_board *board = NULL;
    dev_notice(&pdev->dev, "Exit module.\n");
    board = platform_get_drvdata(pdev);

    if (!board) {
        return 0;
    }

    device_destroy(board->class, board->dev);
    class_destroy(board->class);
    cdev_del(&board->cdev);
    unregister_chrdev_region(board->dev, 1);
    driver_down_notification_release(board);
    fw_notification_release(board);
    fw_control_release(board);
    return 0;
}


static const struct of_device_id driver_match[] = {
    {
        .compatible = "hailo,hailort"
    },
    { }
};
MODULE_DEVICE_TABLE(of, driver_match);


static struct platform_driver hailort_core_driver = {
    .probe = driver_probe,
    .remove = driver_remove,
    .driver = {
        .name = "hailort-core-driver",
        .of_match_table = driver_match,
    },
};
module_platform_driver(hailort_core_driver);

module_param(o_dbg, int, S_IRUGO | S_IWUSR);

MODULE_AUTHOR("Hailo Technologies Ltd.");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Integrated NNC HailoRT");
MODULE_VERSION(HAILO_DRV_VER);