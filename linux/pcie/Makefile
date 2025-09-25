# SPDX-License-Identifier: GPL-2.0

# quiet command
ifeq ($(Q),)
	Q=@
endif

COMMON_SRC_DIRECTORY=../../common
VDMA_SRC_DIRECTORY=../vdma
UTILS_SRC_DIRECTORY=../utils


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

DRIVER_NAME=hailo_pci.ko
DRIVER_NAME_NO_EXT=hailo_pci

VERSION_MAJOR=$(shell grep "\#define HAILO_DRV_VER_MAJOR" ../../common/hailo_ioctl_common.h | sed "s/\#define HAILO_DRV_VER_MAJOR //g")
VERSION_MINOR=$(shell grep "\#define HAILO_DRV_VER_MINOR" ../../common/hailo_ioctl_common.h | sed "s/\#define HAILO_DRV_VER_MINOR //g")
VERSION_RELEASE=$(shell grep "\#define HAILO_DRV_VER_REVISION" ../../common/hailo_ioctl_common.h | sed "s/\#define HAILO_DRV_VER_REVISION //g")
DRIVER_VERSION=$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_RELEASE)
is_driver_version_valid=$(shell echo $(DRIVER_VERSION) | grep '^[[:digit:]]\+\.[[:digit:]]\+\.[[:digit:]]\+$$' > /dev/null; echo $$?)
ifneq ($(is_driver_version_valid),0)
    $(error "DRIVER_VERSION is invalid! Got $(DRIVER_VERSION)")
endif


ifeq ($(DEBUG), 1)
    GDB_FLAG="CONFIG_DEBUG_INFO=y CONFIG_FRAME_POINTER=y"
    TARGET_DIR:="$(BUILD_DIR)/debug/$(ARCH)"
endif

# Internal use only. Compile driver in emulator mode.
ifeq ($(EMULATOR), 1)
    USER_FLAGS="EMULATOR=1"
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
	$(Q)echo "*                            PCIe Driver                                      "
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
	$(Q)echo "*   install_dkms Installs the driver using DKMS.                              "
	$(Q)echo "*                                                                             "
	$(Q)echo "*   uninstall    Uninstalls the driver                                        "
	$(Q)echo "*                                                                             "
	$(Q)echo "*   help:        Display this help                                            "
	$(Q)echo "******************************************************************************"

print-versions:
	$(Q)kernelver="$(make -s -C $(KERNEL_DIR) kernelversion || echo \"unknown\")"
	$(Q)echo "******************************************************************************"
	$(Q)echo "Kernel version: $(kernelver)"
	$(Q)echo "******************************************************************************"

all: $(TARGET_DIR) print-versions
	$(Q)$(MAKE)  -C $(KERNEL_DIR) M=$(PWD) $(GDB_FLAG) $(USER_FLAGS) modules
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
	$(Q)mkdir -p /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/linux
	$(Q)cp -r . /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/linux/pcie
	$(Q)cp -r $(COMMON_SRC_DIRECTORY) /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/
	$(Q)cp -r $(VDMA_SRC_DIRECTORY) /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/linux
	$(Q)cp -r $(UTILS_SRC_DIRECTORY) /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/linux
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
	-$(Q)sh dkms_uninstall.sh
endif

endif

.PHONY: help
.PHONY: all
.PHONY: clean
.PHONY: install
.PHONY: uninstall
