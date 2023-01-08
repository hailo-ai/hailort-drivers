// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_PCI_COMPACT_H_
#define _HAILO_PCI_COMPACT_H_

#include <linux/version.h>
#include <linux/scatterlist.h>

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


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
#define get_user_pages_compact get_user_pages
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 168)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0))
#define get_user_pages_compact(start, nr_pages, gup_flags, pages, vmas) \
    get_user_pages(current, current->mm, start, nr_pages, gup_flags, pages, vmas)
#else
static inline long get_user_pages_compact(unsigned long start, unsigned long nr_pages,
    unsigned int gup_flags, struct page **pages,
    struct vm_area_struct **vmas)
{
    int write = !!((gup_flags & FOLL_WRITE) == FOLL_WRITE);
    int force = !!((gup_flags & FOLL_FORCE) == FOLL_FORCE);
    return get_user_pages(current, current->mm, start, nr_pages, write, force,
        pages, vmas);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
#define sg_alloc_table_from_pages_segment_compat __sg_alloc_table_from_pages
#else
static inline struct scatterlist *sg_alloc_table_from_pages_segment_compat(struct sg_table *sgt,
    struct page **pages, unsigned int n_pages, unsigned int offset,
    unsigned long size, unsigned int max_segment,
    struct scatterlist *prv, unsigned int left_pages,
    gfp_t gfp_mask)
{
    int res = 0;

    if (NULL != prv) {
        // prv not suported
        return ERR_PTR(-EINVAL);
    }

    if (0 != left_pages) {
        // Left pages not supported
        return ERR_PTR(-EINVAL);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
    res = sg_alloc_table_from_pages_segment(sgt, pages, n_pages, offset, size, max_segment, gfp_mask);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
    res = __sg_alloc_table_from_pages(sgt, pages, n_pages, offset, size, max_segment, gfp_mask);
#else
    res = sg_alloc_table_from_pages(sgt, pages, n_pages, offset, size, gfp_mask);
#endif
    if (res < 0) {
        return ERR_PTR(res);
    }

    return sgt->sgl;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
#define dma_capable_compat(dev, addr, size, is_ram) dma_capable(dev, addr, size, is_ram)
// Case for Rasberry Pie kernel versions 5.4.83 <=> 5.5.0 - do not follow other linux conventions regarding dma_capable
#elif defined(HAILO_RASBERRY_PIE) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 83)
#define dma_capable_compat(dev, addr, size, is_ram) dma_capable(dev, addr, size, is_ram)
#else
#define dma_capable_compat(dev, addr, size, is_ram) dma_capable(dev, addr, size)
#endif

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

#endif /* _HAILO_PCI_COMPACT_H_ */