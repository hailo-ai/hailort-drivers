// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include "board.h"
#include "dram_vdma.h"
#include "utils/integrated_nnc_utils.h"
#include "vdma/vdma.h"
#include "utils/logs.h"

#include <linux/interrupt.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_reserved_mem.h>

#define DRAM_DMA_SRC_CHANNELS_BITMASK   (0x0000FFFF)
#define INVALID_MASK_OFFSET             (0x00)

static void update_channel_interrupts(struct hailo_vdma_controller *controller,
    size_t engine_index, u32 channels_bitmap)
{
    struct hailo_board *board = (struct hailo_board*) dev_get_drvdata(controller->dev);
    struct hailo_resource *engine_registers = NULL;
    int type_idx;

    BUG_ON(engine_index >= board->vdma.vdma_engines_count);
    for (type_idx = 0; type_idx < MAX_IRQ_TYPE; type_idx++) {
        // Updating only on interrupts with valid mask offset
        if (INVALID_MASK_OFFSET != board->board_data->vdma_interrupts_data[type_idx].vdma_interrupt_mask_offset) {
            engine_registers = &board->vdma_engines_resources[engine_index].engine_registers;
            hailo_resource_write32(engine_registers,
                board->board_data->vdma_interrupts_data[type_idx].vdma_interrupt_mask_offset, channels_bitmap);
        }
    }
}

static inline u64 get_masked_channel_id(u8 channel_id)
{
    return ((u64)(channel_id & CHANNEL_ID_MASK) << CHANNEL_ID_SHIFT);
}

static struct hailo_vdma_hw dram_vdma_hw = {
    .hw_ops = {
        .get_masked_channel_id = get_masked_channel_id,
    },
    .ddr_data_id = DDR_AXI_DATA_ID,
    .device_interrupts_bitmask = DRAM_DMA_DEVICE_INTERRUPTS_BITMASK,
    .host_interrupts_bitmask = DRAM_DMA_HOST_INTERRUPTS_BITMASK,
    .src_channels_bitmask = DRAM_DMA_SRC_CHANNELS_BITMASK,
};

static struct hailo_vdma_controller_ops core_vdma_controller_ops = {
    .update_channel_interrupts = update_channel_interrupts,
};

// TODO - HRT-16572: Remove after implementing the correct channel types handling
static void channel_bitmap_adjust(u32 *channels_bitmap, enum irq_type type)
{
    switch (type) {
    case IRQ_TYPE_INPUT:
        // Handling only 16 channels for input (0-15)
        *channels_bitmap = *channels_bitmap & 0x0000FFFF;
        break;
    case IRQ_TYPE_OUTPUT:
        // Move lower 16-bit, channels (0-15), to the upper 16 bits (16-31), clearing the lower part
        *channels_bitmap = (*channels_bitmap & 0x0000FFFF) << 16;
        break;
    case IRQ_TYPE_BOTH:
    default:
        break;
    }
}

static irqreturn_t engine_irqhandler(struct hailo_board *board, size_t engine_index, enum irq_type irq_type)
{
    u32 channels_bitmap = 0;
    irqreturn_t return_value = IRQ_NONE;
    struct hailo_resource *engine_registers =
        &board->vdma_engines_resources[engine_index].engine_registers;

    while (true) {
        channels_bitmap = hailo_resource_read32(engine_registers,
            board->board_data->vdma_interrupts_data[irq_type].vdma_interrupt_status_offset);
        hailo_dbg(board, "Got vDMA interupt %u for engine %zu", channels_bitmap, engine_index);
        hailo_resource_write32(engine_registers,
            board->board_data->vdma_interrupts_data[irq_type].vdma_interrupt_w1c_offset, channels_bitmap);
        channel_bitmap_adjust(&channels_bitmap, irq_type);

        if (0 == channels_bitmap) {
            break;
        }

        return_value = IRQ_HANDLED;
        hailo_vdma_irq_handler(&board->vdma, engine_index, channels_bitmap);
    }

    return return_value;
}

static irqreturn_t vdma_irqhandler(int irq, void *p)
{
    struct irq_info *irq_info = (struct irq_info *)p;
    struct hailo_board *board = dev_get_drvdata((struct device *)irq_info->dev);

    if (irq != irq_info->irq) {
        hailo_err(board, "Invalid irq %d\n", irq);
        return IRQ_NONE;
    }

    return engine_irqhandler(board, irq_info->engine_index, irq_info->type);
}

static int ioremap_vdma_resource(struct device *dev, struct device_node *vdma_node,
    const char *name, struct hailo_resource *resource)
{
    int err = -EFAULT;
    void __iomem *address = NULL;
    struct resource of_resource;

    int num = of_property_match_string(vdma_node, "reg-names", name);
    if (num < 0) {
        dev_err(dev, "Failed match (%pOF/%s) err %d\n", vdma_node, name, num);
        return num;
    }

    err = of_address_to_resource(vdma_node, num, &of_resource);
    if (err < 0) {
        dev_err(dev, "Failed get address (%pOF/%s) err %d\n", vdma_node, name, err);
        return err;
    }

    address = devm_ioremap_resource(dev, &of_resource);
    if (IS_ERR(address)) {
        dev_err(dev, "Failed ioremap %pOF/%s, err %ld\n", vdma_node,
            name, PTR_ERR(address));
        return PTR_ERR(address);
    }

    dev_notice(dev, "Mapped %pR %pOF/%s", &of_resource, vdma_node, name);

    resource->address = (uintptr_t)address;
    resource->size = resource_size(&of_resource);
    return 0;
}

static enum irq_type map_irq_name_to_type(const char *name)
{
    // TODO - HRT-16580: Remove (!name) after updating the device tree and image
    if ((!name) || (0 == strcmp(name, BOTH_INPUT_AND_OUTPUT_IRQ_NAME))) {
        return IRQ_TYPE_BOTH;
    }

    if (0 == strcmp(name, INPUT_IRQ_NAME)) {
        return IRQ_TYPE_INPUT;
    } else if (0 == strcmp(name, OUTPUT_IRQ_NAME)) {
        return IRQ_TYPE_OUTPUT;
    }

    // Default to both
    return IRQ_TYPE_BOTH;
}

static int setup_engine_irq(struct device *dev, struct device_node *vdma_node,
    struct irq_info *irqs_info, int engine_index)
{
    int idx = 0;
    int err = -EINVAL;
    int ret = 0;
    const char *irq_name;
    enum irq_type type;

    for (idx = 0; idx < MAX_INTERRUPTS_PER_ENGINE; idx++) {
        err = of_property_read_string_index(vdma_node, "interrupt-names", idx, &irq_name);
        if (err < 0) {
            hailo_dev_notice(dev, "Did not detect interrupt-names entry for index %d, using default\n", idx);
            irq_name = NULL;
        }

        // Get IRQ by name if available, otherwise by index
        ret = irq_name ? of_irq_get_byname(vdma_node, irq_name) : of_irq_get(vdma_node, idx);
        if (ret < 0) {
            // Making sure atleast one irq is available
            if (idx > 0) {
                break;
            } else {
                dev_err(dev, "Error receiving irq for %pOF. err %d\n", vdma_node, ret);
                return ret;
            }
        }

        type = map_irq_name_to_type(irq_name);
        irqs_info[type].irq = ret;
        irqs_info[type].type = type;
        irqs_info[type].dev = dev;
        irqs_info[type].engine_index = engine_index;

        err = devm_request_irq(dev, ret, vdma_irqhandler, 0, dev_name(dev), (void *)&irqs_info[type]);
        if (err < 0) {
            dev_err(dev, "Failed setting up vDMA interrupts. err %d\n", err);
            return err;
        }
    }

    return 0;
}

static int init_engine(struct device *dev, struct device_node *vdma_node,
    struct hailo_vdma_engine_resources *engine_resources,
    struct irq_info *irqs_info, int engine_index)
{
    int err = -EINVAL;
    struct hailo_resource channel_regs;
    struct hailo_resource engine_regs;

    // Should not happen, just for safety
    if (!irqs_info) {
        dev_err(dev, "Invalid irq info\n");
        return err;
    }

    err = ioremap_vdma_resource(dev, vdma_node, "channel-regs", &channel_regs);
    if (err < 0) {
        return err;
    }

    err = ioremap_vdma_resource(dev, vdma_node, "engine-regs", &engine_regs);
    if (err < 0) {
        return err;
    }

    err = setup_engine_irq(dev, vdma_node, irqs_info, engine_index);
    if (err < 0) {
        return err;
    }

    engine_resources->channel_registers = channel_regs;
    engine_resources->engine_registers = engine_regs;
    return 0;
}

static void init_reserved_mem(struct device *dev)
{
    int err = of_reserved_mem_device_init_by_name(dev, dev->of_node, "nnc-dma-cma");
    if (err < 0) {
        hailo_dev_notice(dev, "Did not detect reserved memory. Using system shared cma\n");
    }
}

int hailo_integrated_nnc_vdma_controller_init(struct hailo_board *board)
{
    struct hailo_vdma_engine_resources engine_resources;
    struct hailo_resource channel_registers[MAX_VDMA_ENGINES];
    struct device_node *dev_node = board->pDev->dev.of_node;
    struct device_node *vdma_node = NULL;
    int err = -EINVAL;
    int engine_idx = 0;
    size_t engines_count = 0;

    hailo_notice(board, "Initializing vDMA controller\n");

    init_reserved_mem(&board->pDev->dev);

    engines_count = of_get_child_count(dev_node);
    if (ARRAY_SIZE(board->vdma_engines_resources) < engines_count) {
        hailo_err(board, "Invalid dma engines count %zu\n", engines_count);
        return -EINVAL;
    }

    for_each_child_of_node(dev_node, vdma_node) {
        err = init_engine(&board->pDev->dev, vdma_node, &engine_resources, &board->irqs_info[engine_idx][0], engine_idx);
        if (err < 0) {
            return err;
        }

        board->vdma_engines_resources[engine_idx] = engine_resources;
        channel_registers[engine_idx] = engine_resources.channel_registers;
        engine_idx++;
    }

    err = hailo_vdma_controller_init(&board->vdma, &board->pDev->dev, &dram_vdma_hw,
        &core_vdma_controller_ops, channel_registers, engines_count);
    if (err < 0) {
        return err;
    }

    hailo_notice(board, "vDMA controller is initialized\n");
    return 0;
}