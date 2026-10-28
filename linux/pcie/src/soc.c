// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2026 Hailo Technologies Ltd. All rights reserved.
 **/
/**
 * A Hailo PCIe NNC device is a device contains a full SoC over PCIe. The SoC contains NNC (neural network core) and
 * some application processor (pci_ep).
 */

#include "soc.h"

#include "vdma_common.h"
#include "logs.h"
#include "vdma/memory.h"
#include "pcie_common.h"

#include <linux/uaccess.h>

void hailo_soc_init(struct hailo_pcie_soc *soc)
{
    init_completion(&soc->control_resp_ready);
    soc->driver_compatible = true;
}

long hailo_soc_ioctl(struct hailo_pcie_board *board, struct hailo_file_context *context,
    struct hailo_vdma_controller *controller, unsigned int cmd, unsigned long arg)
{
    if (!board->soc.driver_compatible) {
        hailo_err(board, "driver_compatible is false\n");
        return -EINVAL;
    }

    switch (cmd) {
    case HAILO_SOC_CONNECT:
        return hailo_soc_connect_ioctl(board, context, controller, arg);
    case HAILO_SOC_CLOSE:
        return hailo_soc_close_ioctl(board, controller, context, arg);
    case HAILO_SOC_POWER_OFF:
        return hailo_soc_power_off_ioctl(board, arg);
    default:
        hailo_err(board, "Invalid pcie EP ioctl code 0x%x (nr: %d)\n", cmd, _IOC_NR(cmd));
        return -ENOTTY;
    }
}

static int soc_control(struct hailo_pcie_board *board,
    const struct hailo_pcie_soc_request *request,
    struct hailo_pcie_soc_response *response,
    bool killable)
{
    int ret = 0;
    reinit_completion(&board->soc.control_resp_ready);

    hailo_pcie_soc_write_request(&board->pcie_resources, request);

    if (killable) {
        ret = wait_for_completion_killable_timeout(&board->soc.control_resp_ready,
            msecs_to_jiffies(PCI_SOC_CONTROL_CONNECT_TIMEOUT_MS));
    } else {
        ret = wait_for_completion_timeout(&board->soc.control_resp_ready,
            msecs_to_jiffies(PCI_SOC_CONTROL_CONNECT_TIMEOUT_MS));
    }

    if (ret <= 0) {
        if (0 == ret) {
            hailo_err(board, "Timeout waiting for soc control (timeout_ms=%d)\n", PCI_SOC_CONTROL_CONNECT_TIMEOUT_MS);
            return -ETIMEDOUT;
        } else {
            if ((ret != -EAGAIN) && (ret != -EINTR)) {
                hailo_err(board, "soc control failed with err=%d (process was interrupted or killed)\n",
                    ret);
            }
            return ret;
        }
    }

    hailo_pcie_soc_read_response(&board->pcie_resources, response);
    if (response->status < 0) {
        return response->status;
    }

    if (response->control_code != request->control_code) {
        hailo_err(board, "Invalid response control code %d (expected %d)\n",
            response->control_code, request->control_code);
        return -EINVAL;
    }

    return 0;
}

int hailo_soc_get_driver_info(struct hailo_pcie_board *board)
{
    struct hailo_pcie_soc_request request = (struct hailo_pcie_soc_request) {
        .control_code = HAILO_PCIE_SOC_CONTROL_CODE_QUERY_DRIVER_INFO,
    };

    struct hailo_pcie_soc_response response = {0};
    int err;

    err = soc_control(board, &request, &response, true);
    if (err < 0) {
        hailo_err(board, "soc_get_driver_info failed with err=%d\n", err);
        return err;
    }

    if ((response.driver_info.driver_major != HAILO_DRV_VER_MAJOR) || 
        (response.driver_info.driver_minor != HAILO_DRV_VER_MINOR) ||
        (response.driver_info.driver_revision != HAILO_DRV_VER_REVISION)) {
        hailo_err(board, "Mismatch Driver version pcie driver %u:%u:%u pci_ep driver %u:%u:%u\n",
            HAILO_DRV_VER_MAJOR, HAILO_DRV_VER_MINOR, HAILO_DRV_VER_REVISION,
            response.driver_info.driver_major, response.driver_info.driver_minor, response.driver_info.driver_revision);
        board->soc.driver_compatible = false;
        return -EINVAL;
    }

    return 0;
}

long hailo_soc_connect_ioctl(struct hailo_pcie_board *board, struct hailo_file_context *context,
    struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_pcie_soc_request request = {0};
    struct hailo_pcie_soc_response response = {0};
    struct hailo_soc_connect_params params;
    struct hailo_vdma_channel_pair *input_channel = NULL;
    struct hailo_vdma_channel_pair *output_channel = NULL;
    struct hailo_vdma_engine *vdma_engine = &controller->vdma_engines[PCI_VDMA_ENGINE_INDEX];
    struct hailo_vdma_descriptors_list *input_desc_list = NULL;
    struct hailo_vdma_descriptors_list *output_desc_list = NULL;
    int err = 0;

    if (copy_from_user(&params, (void *)arg, sizeof(params))) {
        hailo_err(board, "copy_from_user fail\n");
        return -EFAULT;
    }

    input_desc_list = hailo_vdma_get_desc_list(&context->vdma_context, params.input_desc_handle);
    output_desc_list = hailo_vdma_get_desc_list(&context->vdma_context, params.output_desc_handle);
    if (NULL == input_desc_list || NULL == output_desc_list) {
        hailo_dev_err(&board->pdev->dev, "input / output descriptors buffer not found \n");
        return -EINVAL;
    }

    if (!is_powerof2((size_t)input_desc_list->desc_count) ||
        !is_powerof2((size_t)output_desc_list->desc_count)) {
        hailo_dev_err(&board->pdev->dev, "Invalid desc list size\n");
        return -EINVAL;
    }

    request = (struct hailo_pcie_soc_request) {
        .control_code = HAILO_PCIE_SOC_CONTROL_CODE_CONNECT,
        .connect = {
            .port = params.port_number
        }
    };

    err = soc_control(board, &request, &response, true);
    if (err < 0) {
        if (err != -EAGAIN) {
            hailo_err(board, "soc_connect failed with err=%d\n", err);
        }
        return err;
    }

    params.input_channel_index = response.connect.input_channel_index;
    params.output_channel_index = response.connect.output_channel_index;

    if (vdma_channel_direction_by_idx(controller->hw->variant, params.input_channel_index) != VDMA_H2D) {
        hailo_dev_err(&board->pdev->dev, "Invalid input channel index %u\n", params.input_channel_index);
        return -EINVAL;
    }

    if (vdma_channel_direction_by_idx(controller->hw->variant, params.output_channel_index) != VDMA_D2H) {
        hailo_dev_err(&board->pdev->dev, "Invalid output channel index %u\n", params.output_channel_index);
        return -EINVAL;
    }

    input_channel = &vdma_engine->channels[params.input_channel_index];
    output_channel = &vdma_engine->channels[params.output_channel_index];

    err = hailo_vdma_start_channel(&input_channel->host, input_desc_list->buffer.dma_address,
        input_desc_list->desc_count, VDMA_DESC_LIST_HOST);
    if (err < 0) {
        hailo_err(board, "Failed to start host soc-connect channel: %d", err);
        return err;
    }

    err = hailo_vdma_start_channel(&output_channel->host, output_desc_list->buffer.dma_address,
        output_desc_list->desc_count, VDMA_DESC_LIST_HOST);
    if (err < 0) {
        hailo_err(board, "Failed to start device soc-connect channel: %d", err);
        return err;
    }

    // Store the input channels state in bitmap (open)
    hailo_set_bit(params.input_channel_index, &context->context_channels_in_use_bitmap);
    hailo_set_bit(params.output_channel_index, &context->context_channels_in_use_bitmap);

    if (copy_to_user((void *)arg, &params, sizeof(params))) {
        hailo_dev_err(&board->pdev->dev, "copy_to_user fail\n");
        return -EFAULT;
    }

    return 0;
}

static int close_channels(struct hailo_pcie_board *board, u32 channels_bitmap)
{
    int err = 0;
    struct hailo_pcie_soc_request request = {0};
    struct hailo_pcie_soc_response response = {0};
    struct hailo_vdma_engine *engine = &board->vdma.vdma_engines[PCI_VDMA_ENGINE_INDEX];
    struct hailo_vdma_channel_pair *channel_pair = NULL;
    u8 channel_index = 0;

    hailo_info(board, "Closing channels bitmap 0x%x\n", channels_bitmap);
    for_each_vdma_channel_pair(engine, channel_pair, channel_index) {
        if (hailo_test_bit(channel_index, &channels_bitmap)) {
            hailo_vdma_stop_channel(&channel_pair->host);
        }
    }

    request = (struct hailo_pcie_soc_request) {
        .control_code = HAILO_PCIE_SOC_CONTROL_CODE_CLOSE,
        .close = {
            .channels_bitmap = channels_bitmap
        }
    };
    err = soc_control(board, &request, &response, false);
    if (err < 0) {
        hailo_err(board, "soc_close failed with err=%d\n", err);
        return err;
    }
    return 0;
}

long hailo_soc_close_ioctl(struct hailo_pcie_board *board, struct hailo_vdma_controller *controller,
    struct hailo_file_context *context, unsigned long arg)
{
    struct hailo_soc_close_params params;
    u32 channels_bitmap = 0;
    int err = 0;

    if (copy_from_user(&params, (void *)arg, sizeof(params))) {
        hailo_dev_err(&board->pdev->dev, "copy_from_user fail\n");
        return -EFAULT;
    }

    // TOOD: check channels are connected

    channels_bitmap = (1 << params.input_channel_index) | (1 << params.output_channel_index);

    // check if channels are from this bitmap
    if (!hailo_test_bit(params.input_channel_index, &context->context_channels_in_use_bitmap) ||
        !hailo_test_bit(params.output_channel_index, &context->context_channels_in_use_bitmap)) {
        hailo_dev_err(&board->pdev->dev, "Channels %u and %u are not connected\n",
            params.input_channel_index, params.output_channel_index);
        return -EINVAL;
    }

    hailo_info(board, "soc_close_ioctl: ch %x\n", channels_bitmap);

    err = close_channels(board, channels_bitmap);
    if (0 != err) {
        hailo_dev_err(&board->pdev->dev, "Error closing channels\n");
        return err;
    }

    // Store the channel state in bitmap (closed)
    hailo_clear_bit(params.input_channel_index, &context->context_channels_in_use_bitmap);
    hailo_clear_bit(params.output_channel_index, &context->context_channels_in_use_bitmap);

    return err;
}

int hailo_soc_file_context_init(struct hailo_pcie_board *board, struct hailo_file_context *context)
{
    // Nothing to init yet
    return 0;
}

void hailo_soc_file_context_finalize(struct hailo_pcie_board *board, struct hailo_file_context *context)
{
    // close only channels connected by this (by bitmap)
    if (context->context_channels_in_use_bitmap != 0) {
        hailo_info(board, "close_finalize: %x\n", context->context_channels_in_use_bitmap);
        close_channels(board, context->context_channels_in_use_bitmap);
    }
}

long hailo_soc_power_off_ioctl(struct hailo_pcie_board *board, unsigned long arg)
{
    int err = 0;
    struct hailo_pcie_soc_request request = (struct hailo_pcie_soc_request) {
        .control_code = HAILO_PCIE_SOC_CONTROL_POWER_OFF,
    };
    struct hailo_pcie_soc_response response = {0};

    err = soc_control(board, &request, &response, true);
    if (err < 0) {
        hailo_err(board, "soc_power_off failed with err=%d\n", err);
        return err;
    }

    return 0;
}
