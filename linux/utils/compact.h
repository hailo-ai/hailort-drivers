// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_PCI_COMPACT_H_
#define _HAILO_PCI_COMPACT_H_

#include <linux/version.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define class_create_compat class_create
#else
#define class_create_compat(name) class_create(THIS_MODULE, name)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
#define pci_printk(level, pdev, fmt, arg...) \
	dev_printk(level, &(pdev)->dev, fmt, ##arg)
#define pci_emerg(pdev, fmt, arg...)	dev_emerg(&(pdev)->dev, fmt, ##arg)
#define pci_alert(pdev, fmt, arg...)	dev_alert(&(pdev)->dev, fmt, ##arg)
#define pci_crit(pdev, fmt, arg...)	dev_crit(&(pdev)->dev, fmt, ##arg)
#define pci_err(pdev, fmt, arg...)	dev_err(&(pdev)->dev, fmt, ##arg)
#define pci_warn(pdev, fmt, arg...)	dev_warn(&(pdev)->dev, fmt, ##arg)
#define pci_notice(pdev, fmt, arg...)	dev_notice(&(pdev)->dev, fmt, ##arg)
#define pci_info(pdev, fmt, arg...)	dev_info(&(pdev)->dev, fmt, ##arg)
#define pci_dbg(pdev, fmt, arg...)	dev_dbg(&(pdev)->dev, fmt, ##arg)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
#define get_user_pages_compact get_user_pages
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
#define get_user_pages_compact(start, nr_pages, gup_flags, pages) \
    get_user_pages(start, nr_pages, gup_flags, pages, NULL)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 168)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0))
#define get_user_pages_compact(start, nr_pages, gup_flags, pages) \
    get_user_pages(current, current->mm, start, nr_pages, gup_flags, pages, NULL)
#else
static inline long get_user_pages_compact(unsigned long start, unsigned long nr_pages,
    unsigned int gup_flags, struct page **pages)
{
    int write = !!((gup_flags & FOLL_WRITE) == FOLL_WRITE);
    int force = !!((gup_flags & FOLL_FORCE) == FOLL_FORCE);
    return get_user_pages(current, current->mm, start, nr_pages, write, force,
        pages, NULL);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
static inline void dma_sync_sgtable_for_device(struct device *dev,
    struct sg_table *sgt, enum dma_data_direction dir)
{
	dma_sync_sg_for_device(dev, sgt->sgl, sgt->orig_nents, dir);
}
#endif

#ifndef _LINUX_MMAP_LOCK_H
static inline void mmap_read_lock(struct mm_struct *mm)
{
    down_read(&mm->mmap_sem);
}

static inline void mmap_read_unlock(struct mm_struct *mm)
{
    up_read(&mm->mmap_sem);
}
#endif /* _LINUX_MMAP_LOCK_H */

#if LINUX_VERSION_CODE >= KERNEL_VERSION( 5, 0, 0 )
#define compatible_access_ok(a,b,c) access_ok(b, c)
#else
#define compatible_access_ok(a,b,c) access_ok(a, b, c)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
#define PCI_DEVICE_DATA(vend, dev, data) \
	.vendor = PCI_VENDOR_ID_##vend, .device = PCI_DEVICE_ID_##vend##_##dev, \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID, 0, 0, \
	.driver_data = (kernel_ulong_t)(data)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
// On kernels < 4.1.12,  kvmalloc, kvfree is not implemented. For simplicity, instead of implement our own
// kvmalloc/kvfree, just using vmalloc and vfree (It may reduce allocate/access performance, but it worth it).
static inline void *kvmalloc_array(size_t n, size_t size, gfp_t flags)
{
    (void)flags; //ignore
    return vmalloc(n * size);
}

#define kvfree vfree
#endif


#endif /* _HAILO_PCI_COMPACT_H_ */