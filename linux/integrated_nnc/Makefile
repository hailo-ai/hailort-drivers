# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2019-2023 Hailo Technologies Ltd. All rights reserved.
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

VERSION_MAJOR=$(shell grep "\#define HAILO_DRV_VER_MAJOR" include/hailo_integrated_nnc_version.h | sed "s/\#define HAILO_DRV_VER_MAJOR //g")
VERSION_MINOR=$(shell grep "\#define HAILO_DRV_VER_MINOR" include/hailo_integrated_nnc_version.h | sed "s/\#define HAILO_DRV_VER_MINOR //g")
VERSION_RELEASE=$(shell grep "\#define HAILO_DRV_VER_REVISION" include/hailo_integrated_nnc_version.h | sed "s/\#define HAILO_DRV_VER_REVISION //g")

DRIVER_VERSION=$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_RELEASE)
is_driver_version_valid=$(shell echo $(DRIVER_VERSION) | grep '^[[:digit:]]\+\.[[:digit:]]\+\.[[:digit:]]\+$$' > /dev/null; echo $$?)
ifneq ($(is_driver_version_valid),0)
    $(error "DRIVER_VERSION is invalid! Got $(DRIVER_VERSION)")
endif

ifndef kernelver
	kernelver=$(shell uname -r)
endif

MODULES := /lib/modules/${kernelver}/
KERNEL_DIR ?= $(MODULES)/build
DEPMOD ?= depmod

PWD  := $(shell pwd)

PUBLIC_INC_DIR = $(BUILD_DIR)/include
PUBLIC_INC_FILE = $(PUBLIC_INC_DIR)/hailo_integrated_nnc_version.h

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
	$(Q)echo "*                copy the public include files in $(PUBLIC_INC_DIR)           "
	$(Q)echo "*                                                                             "
	$(Q)echo "*   clean        Delete the generated files                                   "
	$(Q)echo "*                Delete $(BUILD_DIR) directory                                "
	$(Q)echo "*                                                                             "
	$(Q)echo "*   install      Installs the driver, setup auto boot.                        "
	$(Q)echo "*                                                                             "
	$(Q)echo "*   install_dkms Installs the driver using DKMS.                              "
	$(Q)echo "*                                                                             "
	$(Q)echo "*   uninstall    Uninstalls the driver                                        "
	$(Q)echo "*                                                                             "
	$(Q)echo "*   help:        Display this help                                            "
	$(Q)echo "******************************************************************************"

all: $(PUBLIC_INC_FILE) $(TARGET_DIR)
	$(Q)$(MAKE) -C $(KERNEL_DIR) M=$(PWD) $(GDB_FLAG) modules
	$(Q)cp $(DRIVER_NAME) $(TARGET_DIR)

$(TARGET_DIR):
	$(Q)mkdir -p $@

$(PUBLIC_INC_DIR):
	$(Q)mkdir -p $@

$(PUBLIC_INC_FILE): $(PUBLIC_INC_DIR)
	$(Q)cp -f $(PWD)/include/* $(PUBLIC_INC_DIR)/

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


install_dkms: uninstall
ifneq ($(shell id -u),0)
	@echo "make install_dkms should run as root"
	exit 1
endif 
ifeq ($(strip $(shell which dkms)),)
	@echo "make install_dkms requires dkms to be installed"
	exit 1
endif 
# build DKMS
	$(Q)cp -r . /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/
	$(Q)sed 's/@PCIE_DRIVER_VERSION@/$(DRIVER_VERSION)/g' dkms.conf.in > /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/dkms.conf
	$(Q)dkms add -m $(DRIVER_NAME_NO_EXT) -v $(DRIVER_VERSION)
	$(Q)dkms build -m $(DRIVER_NAME_NO_EXT) -v $(DRIVER_VERSION) || (cat /var/lib/dkms/$(DRIVER_NAME_NO_EXT)/$(DRIVER_VERSION)/build/make.log; exit 1)

# install DKMS
	$(Q)dkms install -m $(DRIVER_NAME_NO_EXT) -v $(DRIVER_VERSION) --force

uninstall_all_dkms: 
ifneq ($(shell id -u),0)
	@echo "make uninstall_all_dkms should run as root"
	exit 1
endif 
# Uninstall driver from dkms, if dkms is installed
# If the driver wasn't installed with dkms, the following commands won't do anything
ifneq ($(strip $(shell which dkms)),)
	-$(Q)dkms status -m $(DRIVER_NAME_NO_EXT) | grep added | cut -d ' ' -f 2 | sed 's/://' | xargs -I{} dkms remove $(DRIVER_NAME_NO_EXT)/{} --all
	-$(Q)dkms status -m $(DRIVER_NAME_NO_EXT) | cut -d ' ' -f 2 | sed 's/,//' | xargs -I{} dkms remove $(DRIVER_NAME_NO_EXT)/{} --all
	-$(Q)rm -rf /usr/src/$(DRIVER_NAME_NO_EXT)-*
endif

endif

.PHONY: help
.PHONY: all
.PHONY: clean
.PHONY: install
.PHONY: uninstall
