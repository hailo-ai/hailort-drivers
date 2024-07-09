// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#include <linux/err.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/reset.h>
#include <linux/slab.h>
#include <asm-generic/errno-base.h>
#include <linux/uaccess.h>
#include <linux/pagemap.h>
#include <linux/version.h>

#include "file_operations.h"
#include "board.h"
#include "hailo_ioctl_common.h"
#include "fw_control.h"
#include "fw_operation.h"
#include "fw_notification.h"
#include "driver_down_notification.h"
#include "utils/logs.h"
#include "utils/compact.h"
#include "utils/integrated_nnc_utils.h"
#include "vdma/ioctl.h"
#include "vdma/memory.h"


static long hailo_query_device_properties(struct hailo_board *board, unsigned long arg);
static long hailo_query_driver_info(struct hailo_board *board, unsigned long arg);
static long hailo_read_log_ioctl(struct hailo_board *board, unsigned long arg);
static long hailo_reset_nn_core_ioctl(struct hailo_board *board, unsigned long arg);

struct hailo_file_context {
    struct hailo_vdma_file_context vdma_context;
};


inline struct hailo_board* inode_to_board(struct inode *inode) {
    struct cdev *cdev = inode->i_cdev;
    return container_of(cdev, struct hailo_board, cdev);
}

static int hailo_integrated_nnc_fops_open(struct inode *inode, struct file *filp)
{
    struct hailo_board *board = inode_to_board(inode);
    struct hailo_file_context *context = NULL;
    int err = 0;

    hailo_info(board, "hailo_integrated_nnc_fops_open called.\n");

    context = kzalloc(sizeof(*context), GFP_KERNEL);
    if (!context) {
        hailo_err(board, "Failed to alloc file context (required size %zu)\n", sizeof(*context));
        return -ENOMEM;
    }

    hailo_vdma_file_context_init(&context->vdma_context);
    filp->private_data = context;

    if (down_interruptible(&board->mutex)) {
        hailo_err(board, "fops_open down_interruptible fail tgid:%d\n", current->tgid);
        kfree(context);
        return -ERESTARTSYS;
    }

    err = hailo_add_notification_wait(board, filp);
    if (err < 0) {
        hailo_err(board, "Failed to add notification wait with err %d\n", err);
        up(&board->mutex);
        kfree(context);
        return err;
    }

    up(&board->mutex);

    return 0;
}

static int hailo_integrated_nnc_fops_release(struct inode *inode, struct file *filp)
{
    struct hailo_board *board = inode_to_board(inode);
    struct hailo_file_context *context = filp->private_data;
    int ret = 0;

    hailo_info(board, "hailo_integrated_nnc_fops_release called.\n");

    down(&board->mutex);

    hailo_clear_notification_wait_list(board, filp);

    if (filp == board->vdma.used_by_filp) {
        ret = hailo_driver_down_notification(board);
        if (ret < 0) {
            hailo_err(board, "Failed sending FW shutdown event with err %d\n", ret);
        }
    }

    hailo_vdma_file_context_finalize(&context->vdma_context, &board->vdma, filp);
    up(&board->mutex);

    kfree(context);
    return ret;
}

static long hailo_memory_transfer_ioctl(struct hailo_board *board, unsigned long arg)
{
    long err = 0;
    struct hailo_memory_transfer_params* transfer = &board->memory_transfer_params;

    hailo_dbg(board, "Start memory transfer ioctl\n");

    if (copy_from_user(transfer, (void __user*)arg, sizeof(*transfer))) {
        hailo_err(board, "copy_from_user fail\n");
        return -EFAULT;
    }

    if (transfer->count > ARRAY_SIZE(transfer->buffer)) {
        hailo_err(board, "Transfer count too big %zu\n", transfer->count);
        return -EINVAL;
    }

    switch (transfer->memory_type) {
    case HAILO_TRANSFER_DEVICE_DIRECT_MEMORY:
        err = direct_memory_transfer(board->pDev, transfer);
        break;
    case HAILO_TRANSFER_MEMORY_VDMA0:
        err = hailo_resource_transfer(&board->vdma_engines_resources[0].channel_registers, transfer);
        break;
    case HAILO_TRANSFER_MEMORY_VDMA1:
        err = hailo_resource_transfer(&board->vdma_engines_resources[1].channel_registers, transfer);
        break;
    case HAILO_TRANSFER_MEMORY_VDMA2:
        err = hailo_resource_transfer(&board->vdma_engines_resources[2].channel_registers, transfer);
        break;
    case HAILO_TRANSFER_MEMORY_DMA_ENGINE0:
        err = hailo_resource_transfer(&board->vdma_engines_resources[0].engine_registers, transfer);
        break;
    case HAILO_TRANSFER_MEMORY_DMA_ENGINE1:
        err = hailo_resource_transfer(&board->vdma_engines_resources[1].engine_registers, transfer);
        break;
    case HAILO_TRANSFER_MEMORY_DMA_ENGINE2:
        err = hailo_resource_transfer(&board->vdma_engines_resources[2].engine_registers, transfer);
        break;
    default:
        hailo_err(board, "Memory type %d not supported\n", (int)transfer->memory_type);
        err = -EINVAL;
    }
    if (err < 0) {
        return err;
    }

    if (copy_to_user((void __user*)arg, transfer, sizeof(*transfer))) {
        hailo_err(board, "copy_to_user fail\n");
        return -EFAULT;
    }

    return err;
}

static long hailo_general_ioctl(struct hailo_board *board, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case HAILO_MEMORY_TRANSFER:
        return hailo_memory_transfer_ioctl(board, arg);
    case HAILO_QUERY_DEVICE_PROPERTIES:
        return hailo_query_device_properties(board, arg);
    case HAILO_QUERY_DRIVER_INFO:
        return hailo_query_driver_info(board, arg);
    default:
        hailo_err(board, "Invalid general ioctl code 0x%x (nr: %d)\n", cmd, _IOC_NR(cmd));
        return -ENOTTY;
    }
}

static long hailo_nnc_ioctl(struct hailo_board *board, unsigned int cmd, unsigned long arg,
    struct file *filp, bool *should_up_board_mutex)
{
    switch (cmd) {
    case HAILO_FW_CONTROL:
        return hailo_fw_control(board, arg, should_up_board_mutex);
    case HAILO_READ_NOTIFICATION:
        return hailo_read_notification_ioctl(board, arg, filp, should_up_board_mutex);
    case HAILO_DISABLE_NOTIFICATION:
        return hailo_disable_notification_ioctl(board, filp);
    case HAILO_RESET_NN_CORE:
        return hailo_reset_nn_core_ioctl(board, arg);
    case HAILO_READ_LOG:
        return hailo_read_log_ioctl(board, arg);
    default:
        hailo_err(board, "Invalid nnc ioctl code 0x%x (nr: %d)\n", cmd, _IOC_NR(cmd));
        return -ENOTTY;
    }
}

static long hailo_integrated_nnc_fops_unlockedioctl(struct file* filp, unsigned int cmd, unsigned long arg)
{
    long err = 0;
    bool should_up_board_mutex = true;
    struct hailo_board *board = inode_to_board(filp->f_inode);
    struct hailo_file_context *context = filp->private_data;

    hailo_dbg(board, "hailo_integrated_nnc_fops_unlockedioctl called.\n");
    
    if (_IOC_DIR(cmd) & _IOC_READ)
    {
        err = !compatible_access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    }
    else if (_IOC_DIR(cmd) & _IOC_WRITE)
    {
        err =  !compatible_access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    }

    if (err) {
        hailo_err(board, "Invalid ioctl parameter access 0x%x", cmd);
        return -EFAULT;
    }

    if (down_interruptible(&board->mutex)) return -ERESTARTSYS;
    BUG_ON(board->mutex.count != 0);

    switch (_IOC_TYPE(cmd)) {
    case HAILO_GENERAL_IOCTL_MAGIC:
        err = hailo_general_ioctl(board, cmd, arg);
        break;
    case HAILO_VDMA_IOCTL_MAGIC:
        err = hailo_vdma_ioctl(&context->vdma_context, &board->vdma, cmd, arg, filp, &board->mutex,
            &should_up_board_mutex);
        break;
    case HAILO_NNC_IOCTL_MAGIC:
        err = hailo_nnc_ioctl(board, cmd, arg, filp, &should_up_board_mutex);
        break;
    default:
        hailo_err(board, "Invalid ioctl type %d\n", _IOC_TYPE(cmd));
        err = -ENOTTY;
    }

    if (should_up_board_mutex) {
        up(&board->mutex);
    }

    return err;
}

static int hailo_integrated_nnc_fops_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int err = 0;
    uintptr_t vdma_handle = vma->vm_pgoff << PAGE_SHIFT;
    struct hailo_board *board = inode_to_board(filp->f_inode);
    struct hailo_file_context *context = filp->private_data;

    BUILD_BUG_ON_MSG(sizeof(vma->vm_pgoff) < sizeof(vdma_handle),
        "If this expression fails to compile it means the target HW is not compatible with our approach to use "
         "the page offset paramter of 'mmap' to pass the driver the 'handle' of the desired descriptor");

    vma->vm_pgoff = 0; // vm_pgoff contains vdma_handle page offset, the actual offset from the phys addr is 0

    hailo_info(board, "%d fops_mmap\n", current->tgid);

    if (down_interruptible(&board->mutex)) {
        hailo_err(board, "hailo_integrated_nnc_fops_mmap down_interruptible fail tgid:%d\n", current->tgid);
        return -ERESTARTSYS;
    }
    err = hailo_vdma_mmap(&context->vdma_context, &board->vdma, vma, vdma_handle);
    up(&board->mutex);
    return err;
}

static long hailo_query_device_properties(struct hailo_board *board, unsigned long arg)
{
    struct hailo_device_properties props = {
        .desc_max_page_size = 0x1000,
        .allocation_mode    = HAILO_ALLOCATION_MODE_USERSPACE,
        .dma_type           = HAILO_DMA_TYPE_DRAM,
        .dma_engines_count  = board->vdma.vdma_engines_count,
        .is_fw_loaded       = true,     // TODO MSW-422: implement is fw loaded check
    };

    hailo_info(board, "HAILO_QUERY_DEVICE_PROPERTIES: desc_max_page_size=%u\n", props.desc_max_page_size);

    if (copy_to_user((void __user*)arg, &props, sizeof(props))) {
        hailo_err(board, "HAILO_QUERY_DEVICE_PROPERTIES, copy_to_user failed\n");
        return -ENOMEM;
    }

    return 0;
}

static long hailo_query_driver_info(struct hailo_board *board, unsigned long arg)
{
    struct hailo_driver_info info = {
        .major_version = HAILO_DRV_VER_MAJOR,
        .minor_version = HAILO_DRV_VER_MINOR,
        .revision_version = HAILO_DRV_VER_REVISION
    };

    hailo_info(board, "HAILO_QUERY_DRIVER_INFO: major=%u, minor=%u, revision=%u\n",
        info.major_version, info.minor_version, info.revision_version);

    if (copy_to_user((void __user*)arg, &info, sizeof(info))) {
        hailo_err(board, "HAILO_QUERY_DRIVER_INFO, copy_to_user failed\n");
        return -ENOMEM;
    }

    return 0;
}

static long hailo_read_log_ioctl(struct hailo_board *board, unsigned long arg)
{
    long err = 0;
    struct hailo_read_log_params params;

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_err(board, "HAILO_READ_LOG, copy_from_user fail\n");
        return -ENOMEM;
    }

    if ((err = hailo_read_firmware_log(&board->fw_logger, &params) < 0)) {
        hailo_err(board, "HAILO_READ_LOG, reading from log failed with error: %ld \n", err);
        return err;
    }

    if (copy_to_user((void*)arg, &params, sizeof(params))) {
        return -ENOMEM;
    }

    return 0;
}

static long hailo_reset_nn_core_ioctl(struct hailo_board *board, unsigned long arg)
{
    return reset_control_reset(board->nn_core_reset);
}

struct file_operations hailo_integrated_nnc_fops =
{
    owner:              THIS_MODULE,
    unlocked_ioctl:     hailo_integrated_nnc_fops_unlockedioctl,
    open:               hailo_integrated_nnc_fops_open,
    release:            hailo_integrated_nnc_fops_release,
    mmap:               hailo_integrated_nnc_fops_mmap
};