// SPDX-License-Identifier: MIT
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
 **/
/**
 * @file driver_timeouts.h
 * @brief Centralized timeout and retry constants for Hailo drivers.
 **/

#ifndef _HAILO_DRIVER_TIMEOUTS_H_
#define _HAILO_DRIVER_TIMEOUTS_H_

/* Selects between normal and emulator values at compile time */
#ifdef HAILO_EMULATOR
#define HAILO_DRIVER_EMU_SELECT(normal_val, emulator_val) (emulator_val)
#else
#define HAILO_DRIVER_EMU_SELECT(normal_val, emulator_val) (normal_val)
#endif

/* --- PCIe boot timeouts -------------------------------------------------- */
#define COUNT_UNTIL_REACH_BOOTLOADER    HAILO_DRIVER_EMU_SELECT(10, 10000)
/* PCI EP timeout is large for Emulator because boot + linux init can take 4+ hours */
#define PCI_EP_WAIT_TIMEOUT_MS          HAILO_DRIVER_EMU_SELECT(40000, 50000000)
#define FIRMWARE_WAIT_TIMEOUT_MS        HAILO_DRIVER_EMU_SELECT(5000, 5000000)

/* --- VDMA / SoC connect timeouts ----------------------------------------- */
/* 3-way split: Linux vs Windows vs Emulator */
#ifndef HAILO_EMULATOR
#ifdef WINDOWS
// Windows (not emulator)
#define PCI_SOC_CONTROL_CONNECT_TIMEOUT_MS          (10000)
#define PCI_EP_CONTROL_CONNECT_TIMEOUT_MARGIN_MS    (2000)
#else
// Linux (not emulator)
#define PCI_SOC_CONTROL_CONNECT_TIMEOUT_MS          (1000)
#define PCI_EP_CONTROL_CONNECT_TIMEOUT_MARGIN_MS    (200)
#endif
#else
// Emulator
#define PCI_SOC_CONTROL_CONNECT_TIMEOUT_MS          (1000000)
#define PCI_EP_CONTROL_CONNECT_TIMEOUT_MARGIN_MS    (1000)
#endif /* ifndef HAILO_EMULATOR */
#define PCI_EP_CONTROL_CONNECT_TIMEOUT_MS           (PCI_SOC_CONTROL_CONNECT_TIMEOUT_MS - PCI_EP_CONTROL_CONNECT_TIMEOUT_MARGIN_MS)

/* --- Shutdown timeout ---------------------------------------------------- */
#define DEFAULT_SHUTDOWN_TIMEOUT_MS     HAILO_DRIVER_EMU_SELECT(5, 1000)

#endif /* _HAILO_DRIVER_TIMEOUTS_H_ */
