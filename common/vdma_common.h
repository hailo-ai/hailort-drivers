// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_COMMON_VDMA_COMMON_H_
#define _HAILO_COMMON_VDMA_COMMON_H_

#include "types.h"
#include "hailo_resource.h"
#include "utils.h"

#define VDMA_DESCRIPTOR_LIST_ALIGN  (1 << 16)
#define INVALID_VDMA_ADDRESS        (0)
#define DWORD_SIZE                  (4)
#define WORD_SIZE                   (2)
#define BYTE_SIZE                   (1)

#ifdef __cplusplus
extern "C"
{
#endif

struct hailo_vdma_descriptor {
    uint32_t    PageSize_DescControl;
    uint32_t    AddrL_rsvd_DataID;
    uint32_t    AddrH;
    uint32_t    RemainingPageSize_Status;
};

struct hailo_channel_interrupt_timestamp_list {
    int head;
    int tail;
    struct hailo_channel_interrupt_timestamp timestamps[CHANNEL_IRQ_TIMESTAMPS_SIZE];
};

// to_device_control_reg, from_device_control_reg - out params
int hailo_vdma_stop_channel(struct hailo_resource *vdma_registers, size_t channel_index,
    u8 *to_device_control_reg, u8 *from_device_control_reg);

void hailo_vdma_program_descriptor(struct hailo_vdma_descriptor *descriptor, uint64_t dma_address, size_t page_size,
    uint8_t data_id);

void hailo_vdma_push_timestamp(struct hailo_channel_interrupt_timestamp_list *timestamp_list, 
    struct hailo_resource *vdma_registers, size_t channel_index, enum hailo_dma_data_direction direction);

// Returns false if there are no items
bool hailo_vdma_pop_timestamp(struct hailo_channel_interrupt_timestamp_list *timestamp_list,
    struct hailo_channel_interrupt_timestamp *out_timestamp);

void hailo_vdma_pop_timestamps_to_response(struct hailo_channel_interrupt_timestamp_list *timestamp_list,
    struct hailo_vdma_channel_wait_params *interrupt_args);

bool hailo_vdma_is_valid_channel(uint8_t channel_index, enum hailo_dma_data_direction direction);

int hailo_vdma_channel_read_register(struct hailo_vdma_channel_read_register_params *params,
    struct hailo_resource *vdma_registers);
int hailo_vdma_channel_write_register(struct hailo_vdma_channel_write_register_params *params,
    struct hailo_resource *vdma_registers);

#ifdef __cplusplus
}
#endif
#endif /* _HAILO_COMMON_VDMA_COMMON_H_ */
