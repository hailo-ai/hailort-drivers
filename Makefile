# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
#
# Makefile for Hailo Linux Drivers.

# If KERNELRELEASE is defined, we've been invoked from the kernel build system and can use its language.
ifneq ($(KERNELRELEASE),)
include Kbuild
else
# Otherwise we were called directly from the command line; invoke the kernel build system.

ifndef kernelver
	kernelver=$(shell uname -r)
endif

MODULES := /lib/modules/${kernelver}/
KERNEL_DIR ?= $(MODULES)/build
DEPMOD ?= depmod

PWD := $(shell pwd)

ifeq ($(DEBUG), 1)
    GDB_FLAG="CONFIG_DEBUG_INFO=y CONFIG_FRAME_POINTER=y"
endif

ifeq ($(EMULATOR), 1)
    USER_FLAGS="EMULATOR=1"
endif

help:
	#
	# Usage: make [target] [options]
	#
	# Target:
	#   pcie           Build the PCIe (host) driver: hailo1x_pci
	#   pci_ep         Build the PCIe-Endpoint dirver: hailo_pci_ep
	#   integrated_nnc Build the Integrated-NNC dirver: hailo_integrated_nnc
	#
	#   clean          Clean all build artifacts
	#
	#   install        Install the built driver
	#   uninstall      Uninstall all Hailo drivers
	#
	#   help           Display this help
	#
	# Options:
	#   KERNEL_DIR=<path> Path to kernel toolchain
	#   DEBUG=1           Compile with debug info
	#   EMULATOR=1        Compile in emulator mode (Internal, PCIe only)
	#

# Same build command for all three drivers:
define build_driver
$(1):
	$$(MAKE) -C $$(KERNEL_DIR) M=$$(PWD) HAILO_DRIVER=$(1) $$(GDB_FLAG) $$(USER_FLAGS) modules
.PHONY: $(1)
endef

$(eval $(call build_driver,pcie))
$(eval $(call build_driver,pci_ep))
$(eval $(call build_driver,integrated_nnc))

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f linux/*/src/*o.ur-safe

install:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) INSTALL_MOD_DIR=kernel/drivers/misc modules_install
	$(DEPMOD) -a

# Uninstall all Hailo drivers
uninstall:
ifneq ($(wildcard $(MODULES)),)
	rm -f $(MODULES)kernel/drivers/misc/hailo1x_pci*
	rm -f $(MODULES)kernel/drivers/misc/hailo_pci_ep*
	rm -f $(MODULES)kernel/drivers/misc/hailo_integrated_nnc*
	$(DEPMOD) -a
endif

endif

.PHONY: help clean install uninstall
