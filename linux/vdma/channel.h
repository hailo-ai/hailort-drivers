// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_VDMA_CHANNEL_H_
#define _HAILO_VDMA_CHANNEL_H_


#include "vdma/vdma.h"
#include <linux/semaphore.h>


long hailo_vdma_channel_enable(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg);
void hailo_vdma_channel_disable_internal(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller, size_t engine_index, size_t channel_index, bool stop_channel);
long hailo_vdma_channel_disable(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg);
long hailo_vdma_channel_wait_interrupts_ioctl(struct hailo_vdma_controller *controller, unsigned long arg,
    struct semaphore *mutex, bool *should_up_board_mutex);
long hailo_vdma_channel_abort(struct hailo_vdma_controller *controller, unsigned long arg);
long hailo_vdma_channel_clear_abort(struct hailo_vdma_controller *controller, unsigned long arg);
long hailo_vdma_channel_read_register_ioctl(struct hailo_vdma_controller *controller, unsigned long arg);
long hailo_vdma_channel_write_register_ioctl(struct hailo_vdma_controller *controller, unsigned long arg);
void hailo_vdma_channel_irq_handler(struct hailo_vdma_controller *controller,
    size_t engine_index, u32 channel_index);

#endif /* _HAILO_VDMA_CHANNEL_H_ */