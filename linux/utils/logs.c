// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/
#include <linux/module.h>
#include "logs.h"

// This is the single definition point for the o_dbg module parameter.
// It is declared as 'extern' in common/logs.h
int o_dbg = LOGLEVEL_NOTICE;
