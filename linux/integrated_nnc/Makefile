# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
#

# quiet command
ifeq ($(Q),)
	Q=@
endif

# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq ($(KERNELRELEASE),)
	include KBuild
else
# Otherwise we were called directly from the command
# line; invoke the kernel build system.

BUILD_DIR = build

# default is system arch
ifndef ARCH
    ARCH=$(shell uname -m)
endif

# set output folder ( e.g. release | debug )
# Default is release folder
TARGET_DIR:="$(BUILD_DIR)/release/$(ARCH)"

DRIVER_NAME=hailo_integrated_nnc.ko
DRIVER_NAME_NO_EXT=hailo_integrated_nnc

ifeq ($(DEBUG), 1)
    GDB_FLAG="CONFIG_DEBUG_INFO=y CONFIG_FRAME_POINTER=y"
    TARGET_DIR:="$(BUILD_DIR)/debug/$(ARCH)"
endif

ifndef kernelver
	kernelver=$(shell uname -r)
endif

MODULES := /lib/modules/${kernelver}/
KERNEL_DIR ?= $(MODULES)/build
DEPMOD ?= depmod

PWD  := $(shell pwd)
default: help

help:
	$(Q)echo "******************************************************************************"
	$(Q)echo "*                            core Driver                                      "
	$(Q)echo "* usage: make [options] [target]                                              "
	$(Q)echo "*                                                                             "
	$(Q)echo "* options:                                                                    "
	$(Q)echo "*   DEBUG=1: Activate CONFIG_DEBUG_INFO and CONFIG_FRAME_POINTER flag to      "
	$(Q)echo "*            gdb debugging.                                                   "
	$(Q)echo "*   Q=     : Activate makefile verbose mode                                   "
	$(Q)echo "*                                                                             "
	$(Q)echo "* target:                                                                     " 
	$(Q)echo "*   all          Generate the ko file in $(BUILD_DIR)/[release|debug]/$(ARCH) "
	$(Q)echo "*                                                                             "
	$(Q)echo "*   clean        Delete the generated files                                   "
	$(Q)echo "*                Delete $(BUILD_DIR) directory                                "
	$(Q)echo "*                                                                             "
	$(Q)echo "*   install      Installs the driver, setup auto boot.                        "
	$(Q)echo "*                                                                             "
	$(Q)echo "*   uninstall    Uninstalls the driver                                        "
	$(Q)echo "*                                                                             "
	$(Q)echo "*   help:        Display this help                                            "
	$(Q)echo "******************************************************************************"

all: $(TARGET_DIR)
	$(Q)$(MAKE) -C $(KERNEL_DIR) M=$(PWD) $(GDB_FLAG) modules
	$(Q)cp $(DRIVER_NAME) $(TARGET_DIR)

$(TARGET_DIR):
	$(Q)mkdir -p $@

clean:
	$(Q)$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	$(Q)rm -rf $(BUILD_DIR)
	$(Q)rm -f src/*o.ur-safe

install:
	$(Q)$(MAKE) -C $(KERNEL_DIR) M=$(PWD) INSTALL_MOD_DIR=kernel/drivers/misc modules_install
	$(Q)$(DEPMOD) -a

uninstall: uninstall_all_dkms
ifneq ($(wildcard $(MODULES)),)
	$(Q)rm -f $(MODULES)kernel/drivers/misc/$(DRIVER_NAME)
	$(Q)$(DEPMOD) -a
endif

endif

.PHONY: help
.PHONY: all
.PHONY: clean
.PHONY: install
.PHONY: uninstall
