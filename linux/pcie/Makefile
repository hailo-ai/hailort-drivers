# SPDX-License-Identifier: GPL-2.0

# quiet command
ifeq ($(Q),)
	Q=@
endif

COMMON_INCLUDE_DIRECTORY=../../../../common/include
PCIE_SRC_DIRECTORY=../pcie
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
	$(Q)echo "*   uninstall / uninstall_dkms: Remove this DKMS version for kernelver        "
	$(Q)echo "*   uninstall_all_dkms: Remove this DKMS version for all kernels              "
	$(Q)echo "*   uninstall_standalone: Refuse removal without installer ownership records "
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
	$(Q)cp $(DRIVER_NAME_NO_EXT)* $(TARGET_DIR)

$(TARGET_DIR):
	$(Q)mkdir -p $@

clean:
	$(Q)$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	$(Q)rm -rf $(BUILD_DIR)
	$(Q)rm -f src/*o.ur-safe

install:
	$(Q)$(MAKE) -C $(KERNEL_DIR) M=$(PWD) INSTALL_MOD_DIR=kernel/drivers/misc modules_install
	$(Q)$(DEPMOD) -a

# DKMS owns its installed files, backups, restoration and dependency updates.
# Never follow DKMS removal with standalone cleanup: that can erase an original
# module which DKMS has just restored.
uninstall: uninstall_dkms

uninstall_dkms:
	$(Q)if [ "$$(id -u)" -ne 0 ]; then \
		echo "make uninstall / uninstall_dkms should run as root" >&2; exit 1; \
	fi
	$(Q)sh dkms_uninstall.sh "$(DRIVER_VERSION)" --kernel "$(kernelver)"

# Compatibility target: 'all' now means all kernels of this version, never all
# driver versions. Retain the existing helper's one-argument --all interface.
uninstall_all_dkms:
	$(Q)if [ "$$(id -u)" -ne 0 ]; then \
		echo "make uninstall_all_dkms should run as root" >&2; exit 1; \
	fi
	$(Q)sh dkms_uninstall.sh "$(DRIVER_VERSION)"

# Legacy standalone installations have no reliable installer ownership record.
# Version/name/vermagic matching is not proof of ownership. Until provenance is
# tracked by installation, refuse cleanup rather than guess from a pathname.
uninstall_standalone:
	$(Q)if [ "$$(id -u)" -ne 0 ]; then \
		echo "make uninstall_standalone should run as root" >&2; exit 1; \
	fi
	$(Q)echo "Standalone removal is unsupported without installer ownership records; no files were removed." >&2
	$(Q)exit 1

# Installing a version must not run an implicit (and potentially destructive)
# uninstall. Refuse to overwrite a pre-existing DKMS registration or source
# tree; the caller must explicitly decide how to handle that installation.
install_dkms:
	$(Q)if [ "$$(id -u)" -ne 0 ]; then \
		echo "make install_dkms should run as root" >&2; exit 1; \
	fi
	$(Q)if ! command -v dkms >/dev/null 2>&1; then \
		echo "make install_dkms requires dkms to be installed" >&2; exit 1; \
	fi
	$(Q)if [ -e "/usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)" ] || \
		[ -e "/var/lib/dkms/$(DRIVER_NAME_NO_EXT)/$(DRIVER_VERSION)" ]; then \
		echo "$(DRIVER_NAME_NO_EXT)/$(DRIVER_VERSION) already exists; refusing to overwrite" >&2; \
		exit 1; \
	fi

# Copy driver sources
	$(Q)mkdir -p /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/hailort/drivers/linux
	$(Q)cp -r $(PCIE_SRC_DIRECTORY) /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/hailort/drivers/linux
	$(Q)cp -r $(COMMON_SRC_DIRECTORY) /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/hailort/drivers
	$(Q)cp -r $(VDMA_SRC_DIRECTORY) /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/hailort/drivers/linux
	$(Q)cp -r $(UTILS_SRC_DIRECTORY) /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/hailort/drivers/linux

# Copy common headers (standalone layout fix is tracked separately in PR #56).
	$(Q)mkdir -p /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/common
	$(Q)cp -r $(COMMON_INCLUDE_DIRECTORY) /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/common

	$(Q)sed 's/@PCIE_DRIVER_VERSION@/$(DRIVER_VERSION)/g' dkms.conf.in > /usr/src/$(DRIVER_NAME_NO_EXT)-$(DRIVER_VERSION)/dkms.conf
	$(Q)dkms add -m $(DRIVER_NAME_NO_EXT) -v $(DRIVER_VERSION)
	$(Q)dkms build -m $(DRIVER_NAME_NO_EXT) -v $(DRIVER_VERSION) -k "$(kernelver)" || (cat /var/lib/dkms/$(DRIVER_NAME_NO_EXT)/$(DRIVER_VERSION)/build/make.log; exit 1)

# No --force: retain DKMS's normal safety checks and module-signing behavior.
	$(Q)dkms install -m $(DRIVER_NAME_NO_EXT) -v $(DRIVER_VERSION) -k "$(kernelver)"

endif

.PHONY: help
.PHONY: all
.PHONY: clean
.PHONY: install
.PHONY: uninstall
.PHONY: uninstall_dkms
.PHONY: uninstall_all_dkms
.PHONY: uninstall_standalone
.PHONY: install_dkms
