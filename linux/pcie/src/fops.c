// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include <linux/version.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/uaccess.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include <asm/thread_info.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif

#include "fops.h"
#include "vdma_common.h"
#include "logs.h"
#include "vdma/memory.h"
#include "vdma/ioctl.h"
#include "utils/compact.h"
#include "nnc.h"
#include "soc.h"


#if LINUX_VERSION_CODE >= KERNEL_VERSION( 4, 13, 0 )
#define wait_queue_t wait_queue_entry_t
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION( 4, 15, 0 )
#define ACCESS_ONCE READ_ONCE
#endif

#ifndef VM_RESERVED
    #define VMEM_FLAGS (VM_IO | VM_DONTEXPAND | VM_DONTDUMP)
#else
    #define VMEM_FLAGS (VM_IO | VM_RESERVED)
#endif

#define IS_PO2_ALIGNED(size, alignment) (!(size & (alignment-1)))

// On pcie driver there is only one dma engine
#define DEFAULT_VDMA_ENGINE_INDEX       (0)


void hailo_pcie_init_file_context(struct hailo_file_context *context, struct hailo_pcie_board *board, struct file *filp)
{
    context->board = board;
    context->filp = filp;

    hailo_vdma_file_context_init(&context->vdma_context, &board->vdma);

    list_add(&context->open_files_list, &board->open_files_list);
    context->is_valid = true;
}

void hailo_pcie_finalize_file_context(struct hailo_file_context *context)
{
    context->is_valid = false;
    list_del(&context->open_files_list);

    if (context->board->pcie_resources.accelerator_type == HAILO_ACCELERATOR_TYPE_NNC) {
        hailo_nnc_file_context_finalize(context->board, context);
    } else {
        hailo_soc_file_context_finalize(context->board, context);
    }

    hailo_vdma_file_context_finalize(&context->vdma_context, &context->board->vdma, context->filp);
}

int hailo_pcie_fops_open(struct inode *inode, struct file *filp)
{
    u32 major = MAJOR(inode->i_rdev);
    u32 minor = MINOR(inode->i_rdev);
    struct hailo_pcie_board *board;
    int err = 0;
    pci_power_t previous_power_state = PCI_UNKNOWN;
    bool interrupts_enabled_by_filp = false;
    struct hailo_file_context *context = NULL;

    pr_debug(DRIVER_NAME ": (%d: %d-%d): fops_open\n", current->tgid, major, minor);

    board = hailo_pcie_get_board_by_index(minor);
    if (!board) {
        pr_err(DRIVER_NAME ": fops_open: PCIe board not found for /dev/hailo%d node.\n", minor);
        err = -ENODEV;
        goto l_exit;
    }

    context = kzalloc(sizeof(*context), GFP_KERNEL);
    if (!context) {
        pr_err(DRIVER_NAME ": fops_open: Failed to alloc file context (required size %zu)\n", sizeof(*context));
        err =  -ENOMEM;
        goto l_put_board;
    }

    filp->private_data = context;

    if (down_interruptible(&board->mutex)) {
        pr_err(DRIVER_NAME ": fops_open: down_interruptible fail tgid:%d\n", current->tgid);
        err = -ERESTARTSYS;
        goto l_free_context;
    }

    if (!board->pdev) {
        pr_err(DRIVER_NAME ": fops_open: PCIe device not connected for /dev/hailo%d node.\n", minor);
        err = -ENXIO;
        goto l_unlock_board_mutex;
    }

    hailo_pcie_init_file_context(context, board, filp);

    previous_power_state = board->pdev->current_state;
    if (PCI_D0 != previous_power_state) {
        hailo_info(board, "Waking up board change state from %d to PCI_D0\n", previous_power_state);
        err = pci_set_power_state(board->pdev, PCI_D0);
        if (err < 0) {
            hailo_err(board, "Failed waking up board %d", err);
            goto l_finalize_context;
        }
    }

    if (!hailo_pcie_is_device_connected(&board->pcie_resources)) {
        hailo_err(board, "Device disconnected while opening device\n");
        err = -ENXIO;
        goto l_revert_power_state;
    }

    // enable interrupts
    if (!board->interrupts_enabled) {
        err = hailo_enable_interrupts(board);
        if (err < 0) {
            hailo_err(board, "Failed Enabling interrupts %d\n", err);
            goto l_revert_power_state;
        }
        interrupts_enabled_by_filp = true;
    }

    if (board->pcie_resources.accelerator_type == HAILO_ACCELERATOR_TYPE_NNC) {
        err = hailo_nnc_file_context_init(board, context);
    } else {
        err = hailo_soc_file_context_init(board, context);
    }
    if (err < 0) {
        goto l_release_irq;
    }

    hailo_dbg(board, "(%d: %d-%d): fops_open: SUCCESS on /dev/hailo%d\n", current->tgid,
        major, minor, minor);

    up(&board->mutex);
    return 0;

l_release_irq:
    if (interrupts_enabled_by_filp) {
        hailo_disable_interrupts(board);
    }

l_revert_power_state:
    if (board->pdev->current_state != previous_power_state) {
        hailo_info(board, "Power changing state from %d to %d\n", previous_power_state, board->pdev->current_state);
        if (pci_set_power_state(board->pdev, previous_power_state) < 0) {
            hailo_err(board, "Failed setting power state back to %d\n", (int)previous_power_state);
        }
    }
l_finalize_context:
    hailo_pcie_finalize_file_context(context);
l_unlock_board_mutex:
    up(&board->mutex);
l_free_context:
    kfree(context);
l_put_board:
    hailo_pcie_put_board(board);
l_exit:
    return err;
}

int hailo_pcie_fops_release(struct inode *inode, struct file *filp)
{
    struct hailo_file_context *context = (struct hailo_file_context *)filp->private_data;
    struct hailo_pcie_board *board = context->board;

    u32 major = MAJOR(inode->i_rdev);
    u32 minor = MINOR(inode->i_rdev);

    if (!board) {
        return -ENODEV;
    }

    pr_debug(DRIVER_NAME ": (%d: %d-%d): fops_release\n", current->tgid, major, minor);
    down(&board->mutex);

    if (context->is_valid) {
        hailo_pcie_finalize_file_context(context);
    }

    kfree(context);

    // On last released file we can disable interrupts and set power state to D3hot
    if (list_empty(&board->open_files_list)) {
        hailo_disable_interrupts(board);

        if (power_mode_enabled()) {
            hailo_info(board, "Power change state to PCI_D3hot\n");
            if (board->pdev && pci_set_power_state(board->pdev, PCI_D3hot) < 0) {
                hailo_err(board, "Failed setting power state to D3hot");
            }
        }
    }
    hailo_dbg(board, "(%d: %d-%d): fops_release: SUCCESS on /dev/hailo%d\n", current->tgid,
        major, minor, minor);

    up(&board->mutex);

    hailo_pcie_put_board(board);
    return 0;
}

static void firmware_notification_irq_handler(struct hailo_pcie_board *board)
{
    struct hailo_notification_wait *notif_wait_cursor = NULL;
    int err = 0;
    unsigned long irq_saved_flags = 0;

    spin_lock_irqsave(&board->nnc.notification_read_spinlock, irq_saved_flags);
    err = hailo_pcie_read_mailbox_notification(&board->pcie_resources.fw_access, &board->nnc.notification_cache);
    spin_unlock_irqrestore(&board->nnc.notification_read_spinlock, irq_saved_flags);

    if (err < 0) {
        hailo_err(board, "Failed reading firmware notification");
    }
    else {
        // TODO: HRT-14502 move interrupt handling to nnc
        rcu_read_lock();
        list_for_each_entry_rcu(notif_wait_cursor, &board->nnc.notification_wait_list, notification_wait_list)
        {
            complete(&notif_wait_cursor->notification_completion);
        }
        rcu_read_unlock();
    }
}

static void boot_irq_handler(struct hailo_pcie_board *board, struct hailo_pcie_interrupt_source *irq_source)
{
    if (irq_source->sw_interrupts & HAILO_PCIE_BOOT_SOFT_RESET_IRQ) {
        hailo_dbg(board, "soft reset trigger IRQ\n");
        complete(&board->soft_reset.reset_completed);
    }
    if (irq_source->sw_interrupts & HAILO_PCIE_BOOT_IRQ) {
        hailo_dbg(board, "boot trigger IRQ - firmware boot completed\n");
        complete_all(&board->fw_boot.fw_loaded_completion);
    } else {
        board->fw_boot.common.boot_used_channel_bitmap &= ~irq_source->vdma_channels_bitmap;
        hailo_dbg(board, "boot vDMA data IRQ - boot_used_channel_bitmap=0x%x, vdma_channels_bitmap=0x%x\n", 
            board->fw_boot.common.boot_used_channel_bitmap, irq_source->vdma_channels_bitmap);
        if (0 == board->fw_boot.common.boot_used_channel_bitmap) {
            complete_all(&board->fw_boot.vdma_boot_completion);
            hailo_dbg(board, "BOOT_COMPLETION: boot vDMA data trigger IRQ - ALL CHANNELS COMPLETED\n");
        }
    }
}

static void nnc_irq_handler(struct hailo_pcie_board *board, struct hailo_pcie_interrupt_source *irq_source)
{
    if (irq_source->sw_interrupts & HAILO_PCIE_NNC_FW_CONTROL_IRQ) {
        complete(&board->nnc.fw_control.completion);
    }

    if (irq_source->sw_interrupts & HAILO_PCIE_NNC_DRIVER_DOWN_IRQ) {
        complete(&board->driver_down.reset_completed);
    }

    if (irq_source->sw_interrupts & HAILO_PCIE_NNC_FW_NOTIFICATION_IRQ) {
        firmware_notification_irq_handler(board);
    }
}

static void soc_irq_handler(struct hailo_pcie_board *board, struct hailo_pcie_interrupt_source *irq_source)
{
    if (irq_source->sw_interrupts & HAILO_PCIE_SOC_CONTROL_IRQ) {
        complete_all(&board->soc.control_resp_ready);
    }

    if (irq_source->sw_interrupts & HAILO_PCIE_SOC_CLOSE_IRQ) {
        hailo_info(board, "soc_irq_handler - HAILO_PCIE_SOC_CLOSE_IRQ\n");
        // always use bitmap=0xFFFFFFFF - it is ok to wake all interrupts since each handler will check if the stream was aborted or not.
        hailo_vdma_wakeup_interrupts(&board->vdma, DEFAULT_VDMA_ENGINE_INDEX, 0xFFFFFFFF);
    }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
irqreturn_t hailo_irqhandler(int irq, void *dev_id, struct pt_regs *regs)
#else
irqreturn_t hailo_irqhandler(int irq, void *dev_id)
#endif
{
    irqreturn_t return_value = IRQ_NONE;
    struct hailo_pcie_board *board = (struct hailo_pcie_board *)dev_id;
    bool got_interrupt = false;
    struct hailo_pcie_interrupt_source irq_source = {0};

    hailo_dbg(board, "hailo_irqhandler\n");

    while (true) {
        if (!hailo_pcie_is_device_connected(&board->pcie_resources)) {
            hailo_err(board, "Device disconnected while handling irq\n");
            break;
        }

        got_interrupt = hailo_pcie_read_interrupt(&board->pcie_resources, &irq_source);
        if (!got_interrupt) {
            break;
        }

        return_value = IRQ_HANDLED;

        if (board->fw_boot.is_in_boot) {
            boot_irq_handler(board, &irq_source);
        } else {
            if (HAILO_ACCELERATOR_TYPE_NNC == board->pcie_resources.accelerator_type) {
                nnc_irq_handler(board, &irq_source);
            } else if (HAILO_ACCELERATOR_TYPE_SOC == board->pcie_resources.accelerator_type) {
                soc_irq_handler(board, &irq_source);
            } else {
                hailo_err(board, "Invalid accelerator type %d\n", board->pcie_resources.accelerator_type);
            }

            if (0 != irq_source.vdma_channels_bitmap) {
                hailo_vdma_irq_handler(&board->vdma, DEFAULT_VDMA_ENGINE_INDEX,
                    irq_source.vdma_channels_bitmap);
            }
        }
    }

    return return_value;
}

static long hailo_query_device_properties(struct hailo_pcie_board *board, unsigned long arg)
{
    struct hailo_device_properties props = {
        .desc_max_page_size = board->desc_max_page_size,
        .board_type = board->pcie_resources.board_type,
        .dma_type = HAILO_DMA_TYPE_PCIE,
        .dma_engines_count = board->vdma.vdma_engines_count,
        .is_fw_loaded = hailo_pcie_is_firmware_loaded(&board->pcie_resources),
    };

    hailo_info(board, "HAILO_QUERY_DEVICE_PROPERTIES: desc_max_page_size=%u\n", props.desc_max_page_size);

    if (copy_to_user((void __user*)arg, &props, sizeof(props))) {
        hailo_err(board, "HAILO_QUERY_DEVICE_PROPERTIES, copy_to_user failed\n");
        return -EFAULT;
    }

    return 0;
}

static long hailo_query_driver_info(struct hailo_pcie_board *board, unsigned long arg)
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
        return -EFAULT;
    }

    return 0;
}

static long hailo_general_ioctl(struct hailo_pcie_board *board, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case HAILO_QUERY_DEVICE_PROPERTIES:
        return hailo_query_device_properties(board, arg);
    case HAILO_QUERY_DRIVER_INFO:
        return hailo_query_driver_info(board, arg);
    default:
        hailo_err(board, "Invalid general ioctl code 0x%x (nr: %d)\n", cmd, _IOC_NR(cmd));
        return -ENOTTY;
    }
}

long hailo_pcie_fops_unlockedioctl(struct file* filp, unsigned int cmd, unsigned long arg)
{
    long err = 0;
    struct hailo_file_context *context = (struct hailo_file_context *)filp->private_data;
    struct hailo_pcie_board* board = context->board;
    bool should_up_board_mutex = true;


    if (_IOC_DIR(cmd) & _IOC_READ) {
        err = !compatible_access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    } else if (_IOC_DIR(cmd) & _IOC_WRITE) {
        err =  !compatible_access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    }
    if (err) {
        pr_err(DRIVER_NAME ": fops_unlockedioctl: Invalid ioctl parameter access 0x%x", cmd);
        return -EFAULT;
    }

    if (down_interruptible(&board->mutex)) {
        pr_err(DRIVER_NAME ": fops_unlockedioctl down_interruptible failed\n");
        return -ERESTARTSYS;
    }
    BUG_ON(board->mutex.count != 0);

    if (!context->is_valid) {
        pr_err(DRIVER_NAME ": fops_unlockedioctl: Invalid file context\n");
        up(&board->mutex);
        return -ENXIO;
    }

    hailo_dbg(board, "(%d): fops_unlockedioctl. cmd:%d\n", current->tgid, _IOC_NR(cmd));

    switch (_IOC_TYPE(cmd)) {
    case HAILO_GENERAL_IOCTL_MAGIC:
        err = hailo_general_ioctl(board, cmd, arg);
        break;
    case HAILO_VDMA_IOCTL_MAGIC:
        err = hailo_vdma_ioctl(&context->vdma_context, &board->vdma, cmd, arg, filp, &board->mutex,
            &should_up_board_mutex);
        break;
    case HAILO_SOC_IOCTL_MAGIC:
        if (HAILO_ACCELERATOR_TYPE_SOC != board->pcie_resources.accelerator_type) {
            hailo_err(board, "Ioctl %d is not supported on this accelerator type\n", _IOC_TYPE(cmd));
            err = -EINVAL;
        } else {
            err = hailo_soc_ioctl(board, context, &board->vdma, cmd, arg);
        }
        break;
    case HAILO_NNC_IOCTL_MAGIC:
        if (HAILO_ACCELERATOR_TYPE_NNC != board->pcie_resources.accelerator_type) {
            hailo_err(board, "Ioctl %d is not supported on this accelerator type\n", _IOC_TYPE(cmd));
            err = -EINVAL;
        } else {
            err = hailo_nnc_ioctl(board, context, cmd, arg, filp, &should_up_board_mutex);
        }
        break;
    default:
        hailo_err(board, "Invalid ioctl type %d\n", _IOC_TYPE(cmd));
        err = -ENOTTY;
    }

    if (should_up_board_mutex) {
        up(&board->mutex);
    }

    hailo_dbg(board, "(%d): fops_unlockedioct: SUCCESS\n", current->tgid);
    return err;

}

int hailo_pcie_fops_mmap(struct file* filp, struct vm_area_struct *vma)
{
    int err = 0;
    uintptr_t vdma_handle   = vma->vm_pgoff << PAGE_SHIFT;
    struct hailo_file_context *context = (struct hailo_file_context *)filp->private_data;
    struct hailo_pcie_board* board = context->board;

    BUILD_BUG_ON_MSG(sizeof(vma->vm_pgoff) < sizeof(vdma_handle),
        "If this expression fails to compile it means the target HW is not compatible with our approach to use "
         "the page offset paramter of 'mmap' to pass the driver the 'handle' of the desired descriptor");

    vma->vm_pgoff = 0; // vm_pgoff contains vdma_handle page offset, the actual offset from the phys addr is 0

    hailo_info(board, "%d fops_mmap\n", current->tgid);

    if (!board || !board->pdev) {
        return -ENODEV;
    }

    if (down_interruptible(&board->mutex)) {
        pr_err(DRIVER_NAME ": fops_mmap down_interruptible fail tgid:%d\n", current->tgid);
        return -ERESTARTSYS;
    }

    if (!context->is_valid) {
        up(&board->mutex);
        pr_err(DRIVER_NAME ": fops_mmap: Invalid file context\n");
        return -ENXIO;
    }

    err = hailo_vdma_mmap(&context->vdma_context, &board->vdma, vma, vdma_handle);
    up(&board->mutex);
    return err;
}
