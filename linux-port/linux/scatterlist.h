// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2023 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_LINUX_SCATTERLIST_H_
#define _HAILO_LINUX_SCATTERLIST_H_

#include <linux/types.h>

struct scatterlist {
    unsigned int    length;
    dma_addr_t  dma_address;
};

struct sg_table {
    struct scatterlist *sgl;    /* the list */
    unsigned int nents;         /* number of mapped entries */
};

/*
 * Loop over each sg element, following the pointer to a new list if necessary
 */
#define for_each_sg(sglist, sg, nr, __i)	\
    for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))

/*
 * Loop over each sg element in the given *DMA mapped* sg_table object.
 * Please use sg_dma_address(sg) and sg_dma_len(sg) to extract DMA addresses
 * of the each element.
 */
#define for_each_sgtable_dma_sg(sgt, sg, i)	\
    for_each_sg((sgt)->sgl, sg, (sgt)->nents, i)

static inline struct scatterlist *sg_next(struct scatterlist *sg)
{
    sg++;
    return sg;
}

#define sg_dma_address(sg)  ((sg)->dma_address)
#define sg_dma_len(sg)      ((sg)->length)

#endif /* _HAILO_LINUX_SCATTERLIST_H_ */