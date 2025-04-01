// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _INTEGRATED_NNC_CPU_H_
#define _INTEGRATED_NNC_CPU_H_

#include "board.h"

int hailo_integrated_nnc_cpu_struct_init(struct hailo_board *board);

int hailo_load_firmware(struct hailo_board *board);

#endif //_INTEGRATED_NNC_CPU_H_