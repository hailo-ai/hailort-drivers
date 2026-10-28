# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
#
# Kbuild for the Hailo Linux kernel drivers.
# The driver to build is selected via the HAILO_DRIVER make variable
# (pcie | pci_ep | integrated_nnc), passed in by the top-level Makefile.

DRIVERS_COMMON_DIR=common
LINUX_COMMON_DIR=linux/common
VDMA_SRC_DIR=linux/vdma

# Objects linked by all three drivers (pcie, pci_ep, integrated_nnc).
COMMON_OBJS := \
	$(DRIVERS_COMMON_DIR)/fw_validation.o \
	$(DRIVERS_COMMON_DIR)/vdma_common.o \
	$(DRIVERS_COMMON_DIR)/hailo_resource.o \
	$(VDMA_SRC_DIR)/vdma.o \
	$(VDMA_SRC_DIR)/memory.o \
	$(VDMA_SRC_DIR)/monitor.o \
	$(VDMA_SRC_DIR)/ioctl.o \
	$(VDMA_SRC_DIR)/channel.o

ccflags-y += -Werror
ccflags-y += -I$(src)/$(DRIVERS_COMMON_DIR)
ccflags-y += -I$(src)/linux
ccflags-y += -I$(src)/$(LINUX_COMMON_DIR)

UNAME_STR=$(shell uname -a)
ifneq (,$(findstring raspi, $(UNAME_STR)))
    ccflags-y += -DHAILO_RASBERRY_PIE
endif

ifeq ($(EMULATOR), 1)
    ccflags-y += -DHAILO_EMULATOR
endif

# MMIO_DMA_MAPPING is not supported on kernels above 6.9 (since follow_pfn was removed).
ifeq ($(shell (test $(VERSION) -gt 6 || (test $(VERSION) -eq 6 && test $(PATCHLEVEL) -ge 9)) && echo 1 || echo 0), 0)
    ccflags-y += -DHAILO_SUPPORT_MMIO_DMA_MAPPING
endif

ifeq ($(HAILO_DRIVER), pcie)
obj-m += hailo1x_pci.o
else ifeq ($(HAILO_DRIVER), pci_ep)
obj-m += hailo_pci_ep.o
else ifeq ($(HAILO_DRIVER), integrated_nnc)
obj-m += hailo_integrated_nnc.o
endif

# PCIe Driver Sources
hailo1x_pci-objs += linux/pcie/src/pcie.o
hailo1x_pci-objs += linux/pcie/src/fops.o
hailo1x_pci-objs += linux/pcie/src/sysfs.o
hailo1x_pci-objs += linux/pcie/src/nnc.o
hailo1x_pci-objs += linux/pcie/src/soc.o
hailo1x_pci-objs += $(COMMON_OBJS)
hailo1x_pci-objs += $(DRIVERS_COMMON_DIR)/fw_operation.o
hailo1x_pci-objs += $(DRIVERS_COMMON_DIR)/pcie_common.o

# PCIe-Endpoint Driver Sources
hailo_pci_ep-objs += linux/pci_ep/src/main.o
hailo_pci_ep-objs += linux/pci_ep/src/pci_ep_common.o
hailo_pci_ep-objs += linux/pci_ep/src/pci_ep_soc_control.o
hailo_pci_ep-objs += linux/pci_ep/src/pci_ep_ioctl.o
hailo_pci_ep-objs += $(COMMON_OBJS)
hailo_pci_ep-objs += $(DRIVERS_COMMON_DIR)/pcie_common.o

# Integrated NNC Driver Sources
hailo_integrated_nnc-objs += linux/integrated_nnc/src/main.o
hailo_integrated_nnc-objs += linux/integrated_nnc/src/dram_vdma.o
hailo_integrated_nnc-objs += linux/integrated_nnc/src/integrated_nnc_cpu.o
hailo_integrated_nnc-objs += linux/integrated_nnc/src/integrated_nnc_fw_validation.o
hailo_integrated_nnc-objs += linux/integrated_nnc/src/file_operations.o
hailo_integrated_nnc-objs += linux/integrated_nnc/src/fw_control.o
hailo_integrated_nnc-objs += linux/integrated_nnc/src/fw_notification.o
hailo_integrated_nnc-objs += linux/integrated_nnc/src/driver_down_notification.o
hailo_integrated_nnc-objs += linux/integrated_nnc/src/fw_logger.o
hailo_integrated_nnc-objs += $(COMMON_OBJS)
hailo_integrated_nnc-objs += $(DRIVERS_COMMON_DIR)/fw_operation.o

clean-files += $(hailo1x_pci-objs)
clean-files += $(hailo_pci_ep-objs)
clean-files += $(hailo_integrated_nnc-objs)
