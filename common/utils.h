// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#ifndef _HAILO_DRIVER_UTILS_H_
#define _HAILO_DRIVER_UTILS_H_

#define hailo_clear_bit(bit, pval)  { *(pval) &= ~(1 << bit); }
#define hailo_test_bit(pos,var_addr)  ((*var_addr) & (1<<(pos)))

#ifdef __cplusplus
extern "C"
{
#endif

static inline bool is_powerof2(size_t v) {
    // bit trick
    return (v & (v - 1)) == 0;
}

static inline void hailo_set_bit(int nr, uint32_t* addr) {
	uint32_t mask = BIT_MASK(nr);
	uint32_t *p = addr + BIT_WORD(nr);

	*p  |= mask;
}

#ifdef __cplusplus
}
#endif

#endif // _HAILO_DRIVER_UTILS_H_