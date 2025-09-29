// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include <linux/err.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/reset.h>
#include <linux/slab.h>
#include <asm-generic/errno-base.h>

#include "board.h"
#include "integrated_nnc_cpu.h"
#include "file_operations.h"
#include "fw_control.h"
#include "fw_notification.h"
#include "driver_down_notification.h"
#include "fw_logger.h"
#include "dram_vdma.h"
#include "logs.h"
#include "utils/compact.h"
#include "vdma/memory.h"

#define DRIVER_NAME "hailo_integrated_nnc"
#define DEVICE_NODE_NAME "hailo_integrated_nnc"
#define INTEGRATED_DEVICE_TREE_MEMORY_REGION_NAME "memory-region"

#define CONTEXT_SWITCH_DEFS__START_M4_MAPPED_DDR_ADDRESS (0x80000000)
#define CONTEXT_SWITCH_DEFS__END_M4_MAPPED_DDR_ADDRESS (0x90000000)
// 16 MB
#define CMA_FW_SHM_SIZE (0x1000000)

#define MAX_VDMA_CHANNELS_PER_ENGINE_H15 (32)

// Enum that indexes different integrated board types - only used as indexing for the integrated_board_data_arr array
enum integrated_board_type
{
    HAILO_INTEGRATED_BOARD_TYPE_HAILO15H = 0,
    HAILO_INTEGRATED_BOARD_TYPE_HAILO15L = 1,
    HAILO_INTEGRATED_BOARD_TYPE_HAILO12L = 2,
};

static const struct vdma_interrupt_data hailo15h_interrupts_data[] = {
    [IRQ_TYPE_INPUT] = {0},
    [IRQ_TYPE_OUTPUT] = {0},
    [IRQ_TYPE_BOTH] = {
        .vdma_interrupt_mask_offset = 0x990,
        .vdma_interrupt_status_offset = 0x994,
        .vdma_interrupt_w1c_offset = 0x998,
        .irq_type = IRQ_TYPE_BOTH,
    }
};

static const struct vdma_interrupt_data hailo15l_interrupts_data[] = {
    [IRQ_TYPE_INPUT] = {0},
    [IRQ_TYPE_OUTPUT] = {0},
    [IRQ_TYPE_BOTH] = {
        .vdma_interrupt_mask_offset = 0xa00,
        .vdma_interrupt_status_offset = 0xa04,
        .vdma_interrupt_w1c_offset = 0xa08,
        .irq_type = IRQ_TYPE_BOTH,
    }
};

static const struct vdma_interrupt_data hailo12l_interrupts_data[] = {
    [IRQ_TYPE_INPUT] = {
        .vdma_interrupt_mask_offset = 0xda0,
        .vdma_interrupt_status_offset = 0xda4,
        .vdma_interrupt_w1c_offset = 0xda8,
        .irq_type = IRQ_TYPE_INPUT,
    },
    [IRQ_TYPE_OUTPUT] = {
        .vdma_interrupt_mask_offset = 0xdb0,
        .vdma_interrupt_status_offset = 0xdb4,
        .vdma_interrupt_w1c_offset = 0xdb8,
        .irq_type = IRQ_TYPE_OUTPUT,
    },
    [IRQ_TYPE_BOTH] = {0}
};

// TODO: HRT-14933 : chnage name to hailo15h in mercury
static const struct integrated_board_data integrated_board_data_arr[] = {
    [HAILO_INTEGRATED_BOARD_TYPE_HAILO15H] = {
        .board_type = HAILO_BOARD_TYPE_HAILO15,
        .vdma_interrupts_data = hailo15h_interrupts_data,
        .fw_filename          = "hailo/hailo15_nnc_fw.bin",
        // TODO: HRT-17117 : Remove vdma_hw duplications between board types
        .vdma_hw =
        {
            .channel_id_mask = H15X_CHANNEL_ID_MASK,
            .channel_id_shift = CHANNEL_ID_SHIFT,
            .ddr_data_id = DDR_AXI_DATA_ID,
            .device_interrupts_bitmask = DRAM_DMA_DEVICE_INTERRUPTS_BITMASK,
            .host_interrupts_bitmask = DRAM_DMA_HOST_INTERRUPTS_BITMASK,
            .src_channels_bitmask = DRAM_DMA_SRC_CHANNELS_BITMASK_H10H,
            .channels_count = MAX_VDMA_CHANNELS_PER_ENGINE_H15,
        }
    },
    [HAILO_INTEGRATED_BOARD_TYPE_HAILO15L] = {
        .board_type = HAILO_BOARD_TYPE_HAILO15L,
        .vdma_interrupts_data = hailo15l_interrupts_data,
        .fw_filename          = "hailo/hailo15l_nnc_fw.bin",
        .vdma_hw =
        {
            .channel_id_mask = H15X_CHANNEL_ID_MASK,
            .channel_id_shift = CHANNEL_ID_SHIFT,
            .ddr_data_id = DDR_AXI_DATA_ID,
            .device_interrupts_bitmask = DRAM_DMA_DEVICE_INTERRUPTS_BITMASK,
            .host_interrupts_bitmask = DRAM_DMA_HOST_INTERRUPTS_BITMASK,
            .src_channels_bitmask = DRAM_DMA_SRC_CHANNELS_BITMASK_H10H,
            .channels_count = MAX_VDMA_CHANNELS_PER_ENGINE_H15,
        }
    },
    [HAILO_INTEGRATED_BOARD_TYPE_HAILO12L] = {
        .board_type = HAILO_BOARD_TYPE_MARS,
        .vdma_interrupts_data = hailo12l_interrupts_data,
        .fw_filename          = "hailo/mars_nnc_fw.bin",
        .vdma_hw =
        {
            .channel_id_mask = MARS_CHANNEL_ID_MASK,
            .channel_id_shift = CHANNEL_ID_SHIFT,
            .ddr_data_id = DDR_AXI_DATA_ID,
            .device_interrupts_bitmask = DRAM_DMA_DEVICE_INTERRUPTS_BITMASK,
            .host_interrupts_bitmask = DRAM_DMA_HOST_INTERRUPTS_BITMASK,
            .src_channels_bitmask = DRAM_DMA_SRC_CHANNELS_BITMASK_H12L,
            .channels_count = MAX_VDMA_CHANNELS_PER_ENGINE,
        }
    },
};

static ssize_t board_location_show(struct device *dev, struct device_attribute *_attr,
    char *buf)
{
    return sprintf(buf, "%s", "[integrated]");
}
static DEVICE_ATTR_RO(board_location);

static ssize_t accelerator_type_show(struct device *dev, struct device_attribute *_attr,
    char *buf)
{
    return sprintf(buf, "%d", HAILO_ACCELERATOR_TYPE_NNC);
}
static DEVICE_ATTR_RO(accelerator_type);

static ssize_t cma_in_use_show(struct device *dev, struct device_attribute *_attr,
    char *buf)
{
    struct hailo_board *board = (struct hailo_board *)dev_get_drvdata(dev);
    u64 total_cma = atomic64_read(&board->vdma.cma_in_use);
    return sprintf(buf, "%llu\n", total_cma);
}
static DEVICE_ATTR_RO(cma_in_use);

static ssize_t desc_cma_in_use_show(struct device *dev, struct device_attribute *_attr,
    char *buf)
{
    struct hailo_board *board = (struct hailo_board *)dev_get_drvdata(dev);
    u64 total_desc_cma = atomic64_read(&board->vdma.desc_cma_in_use);
    return sprintf(buf, "%llu\n", total_desc_cma);
}
static DEVICE_ATTR_RO(desc_cma_in_use);

static struct attribute *hailo_dev_attrs[] = {
    &dev_attr_board_location.attr,
    &dev_attr_accelerator_type.attr,
    &dev_attr_cma_in_use.attr,
    &dev_attr_desc_cma_in_use.attr,
    NULL
};

ATTRIBUTE_GROUPS(hailo_dev);

static const struct of_device_id driver_match[] = {
    {
        // TODO: HRT-14133 : Fix compatible string when fixed in device tree
        // (currently should always be hailo15h - add "hailo15h" when its added to device tree)
        .compatible = "hailo,hailort",
        .data = &integrated_board_data_arr[HAILO_INTEGRATED_BOARD_TYPE_HAILO15H],
    },
    {
        .compatible = "hailo,integrated-nnc,hailo15l",
        .data = &integrated_board_data_arr[HAILO_INTEGRATED_BOARD_TYPE_HAILO15L],
    },
    {
        .compatible = "hailo,integrated-nnc,hailo12l",
        .data = &integrated_board_data_arr[HAILO_INTEGRATED_BOARD_TYPE_HAILO12L],
    },
    { }
};
MODULE_DEVICE_TABLE(of, driver_match);

static bool verify_dma_addr(struct hailo_vdma_continuous_buffer *buffer)
{
    // verify that buffer starts and ends inside mapped range
    if (buffer->dma_address < CONTEXT_SWITCH_DEFS__START_M4_MAPPED_DDR_ADDRESS ||
        (buffer->dma_address + buffer->size >= CONTEXT_SWITCH_DEFS__END_M4_MAPPED_DDR_ADDRESS)) {
        return false;
    }
    return true;
}

// TODO: HRT-8475 - change function hailo_ioremap_shmem to use name instead of index and then use function here
// Function that searches for memory region in device tree for the nnc fw shared memory - if found uses memory from
// the region
static int hailo_allocate_nnc_fw_shm_from_device_tree_memory_region(struct device *dev, struct hailo_board *board)
{
    struct device_node *node = dev->of_node;
    struct resource res;
    void __iomem *mem_map_ptr;
    int err = 0;

    // Search for memory region node by name - if region not found print info log and fallback to regular
    // continuous buffer allocation
    struct device_node *memory_region_node = of_parse_phandle(node, INTEGRATED_DEVICE_TREE_MEMORY_REGION_NAME, 0);
    if (!memory_region_node) {
        hailo_dev_notice(dev, "Failed to find memory region node in device tree\n");
        return -ENODEV;
    }

    err = of_address_to_resource(memory_region_node, 0, &res);
    if (err) {
        hailo_dev_err(dev, "Failed to get memory of memory region node\n");
        of_node_put(memory_region_node);
        return err;
    }

    // Decrement the refcount of the node
    of_node_put(memory_region_node);

    mem_map_ptr = devm_ioremap(dev, res.start, resource_size(&res));
    if (!mem_map_ptr) {
        hailo_dev_err(dev, "Failed ioremap memory region at start %llx, size %lld (please check device tree)\n",
            res.start, resource_size(&res));
        return -EINVAL;
    }

    board->nnc_fw_shared_mem_info.dma_address = (uintptr_t)res.start;
    board->nnc_fw_shared_mem_info.kernel_address = mem_map_ptr;
    board->nnc_fw_shared_mem_info.size = resource_size(&res);

    return 0;
}

static int hailo_allocate_nnc_fw_shm_continuous_buffer(struct device *dev, struct hailo_board *board)
{
    size_t aligned_buffer_size = PAGE_ALIGN(CMA_FW_SHM_SIZE);

    int err = hailo_vdma_continuous_buffer_alloc(dev, aligned_buffer_size, &board->nnc_fw_shared_memory_continuous_buffer);
    if (err < 0) {
        return err;
    }

    // In case of allocation in wrong region - release allocated memory, disable nnc_fw shared memory and return
    if (!verify_dma_addr(&board->nnc_fw_shared_memory_continuous_buffer)) {
        hailo_dev_notice(dev, "Successfully allocated continous buffer - but not in allowed region - nnc_fw shared memory will be disabled\n");
        hailo_vdma_continuous_buffer_free(dev, &board->nnc_fw_shared_memory_continuous_buffer);
        board->nnc_fw_shared_mem_info.type = NNC_FW_SHARED_MEM_TYPE_NONE;
        return 0;
    }

    board->nnc_fw_shared_mem_info.dma_address = board->nnc_fw_shared_memory_continuous_buffer.dma_address;
    board->nnc_fw_shared_mem_info.kernel_address = board->nnc_fw_shared_memory_continuous_buffer.kernel_address;
    board->nnc_fw_shared_mem_info.size = board->nnc_fw_shared_memory_continuous_buffer.size;
    board->nnc_fw_shared_mem_info.type = NNC_FW_SHARED_MEM_TYPE_CONTINOUS_BUFFER;

    return 0;
}

// Function allocates memory for the nnc fw shared memory - first tries to allocate memory from device tree memory region
// if not found - falls back to continuous buffer allocation and if this buffer is allocated in non allowed region - disables
// nnc fw shared memory
static long hailo_vdma_allocate_nnc_fw_shm(struct device *dev, struct hailo_board *board)
{
    // Try first to allocate memory from device tree memory region
    int err = hailo_allocate_nnc_fw_shm_from_device_tree_memory_region(dev, board);
    if (-ENODEV == err) {
        hailo_dev_notice(dev, "No memory region found in device tree, falling back to continuous buffer allocation\n");
        err = hailo_allocate_nnc_fw_shm_continuous_buffer(dev, board);
        if (err < 0) {
            hailo_dev_err(dev, "Failed to allocate memory from continuous buffer pool\n");
            board->nnc_fw_shared_mem_info.type = NNC_FW_SHARED_MEM_TYPE_NONE;
            return err;
        }
    } else if (0 != err) {
        hailo_dev_err(dev, "Failed to allocate memory from device tree memory region err %d\n", err);
        board->nnc_fw_shared_mem_info.type = NNC_FW_SHARED_MEM_TYPE_NONE;
        return err;
    } else {
        hailo_dev_notice(dev, "Allocated memory from device tree memory region starting physical address: 0x%lx, size: 0x%lx\n",
            board->nnc_fw_shared_mem_info.dma_address, board->nnc_fw_shared_mem_info.size);
        board->nnc_fw_shared_mem_info.type = NNC_FW_SHARED_MEM_TYPE_MEMORY_REGION;
    }

    return 0;
}

static int hailo_set_integrated_board_data(struct platform_device *pdev, struct integrated_board_data **board_data)
{
    const struct of_device_id *match = of_match_device(driver_match, &pdev->dev);
    if ((!match) || (!match->data)) {
        dev_err(&pdev->dev, "Failed to get integrated board data\n");
        return -EINVAL;
    }

    *board_data = (struct integrated_board_data*)match->data;
    return 0;
}

static int driver_probe(struct platform_device *pdev)
{
    struct device *device = NULL;
    struct reset_control *nn_core_reset = NULL;
    struct class *class = NULL;
    struct hailo_board *board = NULL;
    int err = -EINVAL;
    dev_t dev = 0;

    dev_notice(&pdev->dev, "Probing module. driver version %s\n", HAILO_DRV_VER);

    /* allocate board */
    board = devm_kzalloc(&pdev->dev, sizeof(*board), GFP_KERNEL);
    if (!board) {
        dev_err(&pdev->dev, "Unable to allocate device internal structure");
        goto l_exit;
    }

    sema_init(&board->mutex, 1);
    board->pdev = pdev;

    err = hailo_integrated_nnc_cpu_struct_init(board);
    if (err < 0) {
        goto l_exit;
    }

    /* Retrieve NN core reset from device-tree */
    nn_core_reset = devm_reset_control_get_exclusive(&pdev->dev, "nn-core");
    if (IS_ERR(nn_core_reset)) {
        err = PTR_ERR(nn_core_reset);
        hailo_err(board, "NN core reset get failed: %d\n", err);
        goto l_exit;
    }
    board->nn_core_reset = nn_core_reset;

    /* Initialize fw_control */
    err = fw_control_init(board);
    if (0 > err) {
        /* error already logged */
        goto l_exit;
    }

    /* Initialize breakpoint params */
    err = fw_notification_init(board);
    if (0 > err) {
        /* error already logged */
        goto l_fw_control_release;
    }

    /* Initialize breakpoint params */
    err = driver_down_notification_init(board);
    if (0 > err) {
        /* error already logged */
        goto l_fw_notification_release;
    }

    err = fw_logger_init(board);
    if (0 > err) {
        /* error already logged */
        goto l_driver_down_notification_release;
    }

    err = hailo_set_integrated_board_data(pdev, &board->board_data);
    if (err < 0) {
        hailo_err(board, "Failed to get integrated board data\n");
        goto l_driver_down_notification_release;
    }

    if (hailo_load_firmware(board)) {
        /* error already logged */
        goto l_driver_down_notification_release;
    }

    err = hailo_integrated_nnc_vdma_controller_init(board);
    if (0 > err) {
        hailo_err(board, "Failed init vdma controller. err: %d\n", err);
        goto l_driver_down_notification_release;
    }

    /*Creating cdev structure*/
    cdev_init(&board->cdev, &hailo_integrated_nnc_fops);
    board->cdev.owner = THIS_MODULE;

    /*Allocating Major number*/
    err = alloc_chrdev_region(&dev, /*baseminor: */0, /*count: */1, DRIVER_NAME);
    if(0 > err){
        hailo_err(board, "Cannot allocate major number. err: %d\n", err);
        goto l_driver_down_notification_release;
    }
    board->dev = dev;

    /* Adding character device to the system. The driver is live after this call */
    err = cdev_add(&board->cdev, dev, 1);
    if(0 > err){
        hailo_err(board, "Cannot add the device to the system. err: %d\n", err);
        goto l_chrdev_region;
    }

    /* Creating struct class */
    class = class_create_compat("hailo_chardev");
    if (IS_ERR(class)) {
        err = PTR_ERR(class);
        hailo_err(board, "Failed creating class. err: %d", err);
        goto l_cdev;
    }
    board->class = class;

    /* Creating device */
    device = device_create_with_groups(class, &pdev->dev, dev, board, hailo_dev_groups,
        DEVICE_NODE_NAME);
    if (IS_ERR(device)) {
        err = PTR_ERR(device);
        hailo_err(board, "Failed creating dynamic device. err: %d\n", err);
        goto l_class;
    }

    platform_set_drvdata(pdev, board);

    err = hailo_vdma_allocate_nnc_fw_shm(&pdev->dev, board);
    if (err < 0) {
        hailo_err(board, "Failed to allocate continous buffer pool M4 mapped memory region");
        goto l_device_destroy;
    }

    return 0;

l_device_destroy:
    device_destroy(class, dev);
l_class:
    class_destroy(class);
l_cdev:
    cdev_del(&board->cdev);
l_chrdev_region:
    unregister_chrdev_region(dev, 1);
l_driver_down_notification_release:
    driver_down_notification_release(board);
l_fw_notification_release:
    fw_notification_release(board);
l_fw_control_release:
    fw_control_release(board);
l_exit:
    return err;
}

static void driver_remove(struct platform_device *pdev)
{
    struct hailo_board *board = NULL;
    dev_notice(&pdev->dev, "Exit module.\n");
    board = platform_get_drvdata(pdev);

    if (!board) {
        return;
    }

    if (NNC_FW_SHARED_MEM_TYPE_CONTINOUS_BUFFER == board->nnc_fw_shared_mem_info.type) {
        hailo_vdma_continuous_buffer_free(&pdev->dev, &board->nnc_fw_shared_memory_continuous_buffer);
    }
    device_destroy(board->class, board->dev);
    class_destroy(board->class);
    cdev_del(&board->cdev);
    unregister_chrdev_region(board->dev, 1);
    driver_down_notification_release(board);
    fw_notification_release(board);
    fw_control_release(board);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
static int driver_remove_old(struct platform_device *pdev){

	driver_remove(pdev);
	return 0;
}
#endif

static struct platform_driver hailort_core_driver = {
    .probe = driver_probe,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
    .remove = driver_remove,
#else
    .remove = driver_remove_old,
#endif
    .driver = {
        .name = "hailort-core-driver",
        .of_match_table = driver_match,
    },
};
module_platform_driver(hailort_core_driver);

module_param(o_dbg, int, S_IRUGO | S_IWUSR);

MODULE_AUTHOR("Hailo Technologies Ltd.");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Integrated NNC HailoRT");
MODULE_VERSION(HAILO_DRV_VER);
