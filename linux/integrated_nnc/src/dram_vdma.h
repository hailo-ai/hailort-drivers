// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _DRAM_VDMA_H_
#define _DRAM_VDMA_H_

#include "board.h"

// Channel DMA address bits are 17:34
#define DMA_CHANNEL_ADDRESS_MASK            (0x7ffff0000)
// Desc DMA address bits are 4:34
#define DMA_DESC_ADDRESS_MASK               (0x7fffffff0)
#define EXTERNAL_DESCRIPTOR_KIND            (2)
#define DESCRIPTOR_KIND_SHIFT               (62)
#define CHANNEL_ID_MASK                     (0xf)
#define CHANNEL_ID_SHIFT                    (57)

#define DDR_AXI_DATA_ID                     (1)
#define DRAM_DMA_HOST_INTERRUPTS_BITMASK    (1 << 4)
#define DRAM_DMA_DEVICE_INTERRUPTS_BITMASK  (1 << 5)

#define OUTPUT_IRQ_NAME                     "output"
#define INPUT_IRQ_NAME                      "input"
#define BOTH_INPUT_AND_OUTPUT_IRQ_NAME      "both"

int hailo_integrated_nnc_vdma_controller_init(struct hailo_board *board);

#endif /* _DRAM_VDMA_H_ */
