// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#include "board.h"
#include "dram_vdma.h"
#include "integrated_nnc_utils.h"
#include "vdma/vdma.h"
#include "utils/logs.h"

#include <linux/interrupt.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

#define VDMA_INTERRUPT_MASK_OFFSET      (0x990)
#define VDMA_INTERRUPT_STATUS_OFFSET    (0x994)
#define VDMA_INTERRUPT_W1C_OFFSET       (0x998)
#define VDMA_INTERRUPT_W1S_OFFSET       (0x99C)


// Channel DMA address bits are 17:34
#define DMA_CHANNEL_ADDRESS_MASK        (0x7ffff0000)
// Desc DMA address bits are 4:34
#define DMA_DESC_ADDRESS_MASK           (0x7fffffff0) 
#define EXTERNAL_DESCRIPTOR_KIND        (2)
#define DESCRIPTOR_KIND_SHIFT           (62)
#define CHANNEL_ID_MASK                 (0xf)
#define CHANNEL_ID_SHIFT                (57)

#define DDR_AXI_DATA_ID                 (1)

static void update_channel_interrupts(struct hailo_vdma_controller *controller,
    size_t engine_index, uint32_t channels_bitmap)
{
    struct hailo_board *board = (struct hailo_board*) dev_get_drvdata(controller->dev);
    struct hailo_resource *engine_registers = NULL;

    BUG_ON(engine_index >= board->vdma.vdma_engines_count);
    engine_registers = &board->vdma_engines_resources[engine_index].engine_registers;
    hailo_resource_write32(engine_registers, VDMA_INTERRUPT_MASK_OFFSET, channels_bitmap);
}

static uint64_t encode_dma_address_base(dma_addr_t dma_address, uint8_t channel_id, uint8_t kind)
{
    uint64_t address = INVALID_VDMA_ADDRESS;
    if (0 != (channel_id & ~CHANNEL_ID_MASK)) {
        return INVALID_VDMA_ADDRESS;
    }

    address = (uint64_t)dma_address;
    address |= ((uint64_t)kind) << DESCRIPTOR_KIND_SHIFT;
    address |= ((uint64_t)channel_id) << CHANNEL_ID_SHIFT;

    return address;
}

static uint64_t encode_channel_dma_address(dma_addr_t dma_address, uint8_t channel_id)
{
    if (0 != ((uint64_t)dma_address & ~DMA_CHANNEL_ADDRESS_MASK)) {
        return INVALID_VDMA_ADDRESS;
    }

    return encode_dma_address_base(dma_address, channel_id, EXTERNAL_DESCRIPTOR_KIND);
}

static uint64_t encode_desc_dma_address(dma_addr_t dma_address, uint8_t channel_id)
{
    const uint8_t zero_kind = 0;

    if (0 != ((uint64_t)dma_address & ~DMA_DESC_ADDRESS_MASK)) {
        return INVALID_VDMA_ADDRESS;
    }

    return encode_dma_address_base(dma_address, channel_id, zero_kind);
}

static uint8_t get_dma_data_id(void)
{
    return DDR_AXI_DATA_ID;
}

static struct hailo_vdma_controller_ops core_vdma_controller_ops = {
    .update_channel_interrupts = update_channel_interrupts,
    .encode_channel_dma_address = encode_channel_dma_address,
    .encode_desc_dma_address = encode_desc_dma_address,
    .get_dma_data_id = get_dma_data_id
};

static irqreturn_t engine_irqhandler(struct hailo_board *board, size_t engine_index)
{
    u32 channels_bitmap = 0;
    irqreturn_t return_value = IRQ_NONE;
    struct hailo_resource *engine_registers = 
        &board->vdma_engines_resources[engine_index].engine_registers;

    while (true) {
        channels_bitmap = hailo_resource_read32(engine_registers, VDMA_INTERRUPT_STATUS_OFFSET);
        hailo_dbg(board, "Got vDMA interupt %u for engine %zu", channels_bitmap, engine_index);
        hailo_resource_write32(engine_registers, VDMA_INTERRUPT_W1C_OFFSET, channels_bitmap);

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
    struct hailo_board *board = dev_get_drvdata((struct device *)p);
    size_t engine_index = 0;

    for (engine_index = 0; engine_index < ARRAY_SIZE(board->vdma_engines_resources); engine_index++) {
        if (irq == board->vdma_engines_resources[engine_index].irq) {
            return engine_irqhandler(board, engine_index);
        }
    }

    hailo_dbg(board, "Engine not found for %d\n", irq);
    return IRQ_NONE;
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

static int setup_engine_irq(struct device *dev, struct device_node *vdma_node)
{
    int err = -EINVAL;
    int irq = -1;

    irq = of_irq_get(vdma_node, 0);
    if (irq < 0) {
        dev_err(dev, "Error receiving irq for %pOF. err %d\n", vdma_node, irq);
        return irq;
    }

    err = devm_request_irq(dev, irq, vdma_irqhandler, 0, dev_name(dev), dev);
    if (err < 0) {
        dev_err(dev, "Failed setting up vDMA interrupts. err %d\n", err);
        return err;
    }

    return irq;
}

static int init_engine(struct device *dev, struct device_node *vdma_node,
    struct hailo_vdma_engine_resources *engine_resources)
{
    int err = -EINVAL;
    int irq = -1;
    struct hailo_resource channel_regs;
    struct hailo_resource engine_regs;

    err = ioremap_vdma_resource(dev, vdma_node, "channel-regs", &channel_regs);
    if (err < 0) {
        return err;
    }

    err = ioremap_vdma_resource(dev, vdma_node, "engine-regs", &engine_regs);
    if (err < 0) {
        return err;
    }

    irq = setup_engine_irq(dev, vdma_node);
    if (irq < 0) {
        return irq;
    }

    engine_resources->irq = irq;
    engine_resources->channel_registers = channel_regs;
    engine_resources->engine_registers = engine_regs;
    return 0;
}

int hailo_integrated_nnc_vdma_controller_init(struct hailo_board *board)
{
    struct hailo_vdma_engine_resources engine_resources;
    struct hailo_resource channel_registers[MAX_VDMA_ENGINES];
    struct device_node *dev_node = board->pDev->dev.of_node;
    struct device_node *vdma_node = NULL;
    int err = -EINVAL;
    int i = 0;
    size_t engines_count = 0;

    hailo_notice(board, "initializing vDMA controller\n");

    engines_count = of_get_child_count(dev_node);
    if (ARRAY_SIZE(board->vdma_engines_resources) != engines_count) {
        hailo_err(board, "Invalid dma engines count %zu\n", engines_count);
        return -EINVAL;
    }

    for_each_child_of_node(dev_node, vdma_node) {
        err = init_engine(&board->pDev->dev, vdma_node, &engine_resources);
        if (err < 0) {
            return err;
        }

        board->vdma_engines_resources[i] = engine_resources;
        channel_registers[i] = engine_resources.channel_registers;
        i++;
    }

    err = hailo_vdma_controller_init(&board->vdma, &board->pDev->dev,
        &core_vdma_controller_ops, channel_registers, engines_count);
    if (err < 0) {
        return err;
    }

    hailo_notice(board, "vDMA controller is initialized\n");
    return 0;
}
