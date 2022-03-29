// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_PCI_FOPS_H_
#define _HAILO_PCI_FOPS_H_

int hailo_pcie_fops_open(struct inode* inode, struct file* filp);
int hailo_pcie_fops_release(struct inode* inode, struct file* filp);
long hailo_pcie_fops_unlockedioctl(struct file* filp, unsigned int cmd, unsigned long arg);
int hailo_pcie_fops_mmap(struct file* filp, struct vm_area_struct *vma);

#endif /* _HAILO_PCI_FOPS_H_ */
