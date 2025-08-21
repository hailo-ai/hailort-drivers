// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_PCI_FOPS_H_
#define _HAILO_PCI_FOPS_H_

#include "pcie.h"

int hailo_pcie_fops_open(struct inode* inode, struct file* filp);
int hailo_pcie_fops_release(struct inode* inode, struct file* filp);
long hailo_pcie_fops_unlockedioctl(struct file* filp, unsigned int cmd, unsigned long arg);
int hailo_pcie_fops_mmap(struct file* filp, struct vm_area_struct *vma);

void hailo_pcie_init_file_context(struct hailo_file_context *context, struct hailo_pcie_board *board, struct file *filp);
void hailo_pcie_finalize_file_context(struct hailo_file_context *context);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
irqreturn_t hailo_irqhandler(int irq, void* dev_id, struct pt_regs *regs);
#else
irqreturn_t hailo_irqhandler(int irq, void* dev_id);
#endif

#endif /* _HAILO_PCI_FOPS_H_ */
