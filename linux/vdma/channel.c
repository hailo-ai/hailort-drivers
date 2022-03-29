// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2022 Hailo Technologies Ltd. All rights reserved.
 **/

#include "channel.h"
#include "memory.h"
#include "types.h"

#include "utils/logs.h"
#include <linux/uaccess.h>

#include <linux/delay.h>


static long hailo_vdma_channel_get(struct hailo_vdma_controller *controller, u32 channel_index, u64 channel_handle,
    struct hailo_vdma_channel **channel)
{
    struct hailo_vdma_channel *local_channel = NULL;

    if (channel_index >= MAX_VDMA_CHANNELS) {
        hailo_dev_err(controller->dev, "Channel index %d is more than maximum channel %d\n",
            channel_index, MAX_VDMA_CHANNELS);
        return -EINVAL;
    }

    if (INVALID_CHANNEL_HANDLE_VALUE == channel_handle) {
        hailo_dev_dbg(controller->dev, "Invalid chanel handle was passed (channel index %d)\n", channel_index);
        return -ECONNRESET;
    }

    local_channel = &controller->channels[channel_index];
    if (channel_handle != local_channel->handle) {
        hailo_dev_dbg(controller->dev, "Operation on channel %u is not allowed, the channel is used by another handle\n",
            channel_index);
        return -ECONNRESET;
    }

    *channel = local_channel;
    return 0;
}

static void hailo_vdma_update_interrupts(struct hailo_vdma_controller *controller)
{
    unsigned long channel_bitmap = 0;
    int i = 0;
    for (i = 0; i < ARRAY_SIZE(controller->channels); ++i) {
        if (INVALID_CHANNEL_HANDLE_VALUE != controller->channels[i].handle) {
            set_bit(i, &channel_bitmap);
        }
    }

    controller->ops->update_channel_interrupts(controller, channel_bitmap);
}

static uint8_t get_channel_depth(size_t decs_count)
{
    uint8_t depth = 0;
    while (decs_count >>= 1) {
        ++depth;
    }
    return depth;
}

static int start_channel(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller,
    struct hailo_vdma_channel_enable_params *enable_params)
{
    struct hailo_descriptors_list *desc_list = NULL;
    uint8_t depth = 0;
    int err = 0;
    uint64_t address = 0;
    uint8_t channel_id = hailo_vdma_get_channel_id(enable_params->channel_index);
    desc_list = hailo_vdma_get_descriptors_buffer(context, enable_params->desc_list_handle);
    if (NULL == desc_list) {
        hailo_dev_err(controller->dev, "Descriptors list %llu not found\n",
            (uint64_t)enable_params->desc_list_handle);
        return -EINVAL;
    }

    address = controller->ops->encode_channel_dma_address(desc_list->dma_addr,
        channel_id);
    if (INVALID_VDMA_ADDRESS == address) {
        hailo_dev_err(controller->dev, "Failed encode dma address %pad\n", &desc_list->dma_addr);
        return -EINVAL;
    }

    depth = get_channel_depth(desc_list->desc_count);
    err = hailo_vdma_start_channel(&controller->registers,
        enable_params->channel_index, enable_params->direction, address,
        depth);
    if (err < 0) {
        hailo_dev_err(controller->dev, "Vdma start channel failed, err %d\n", err);
        return err;
    }

    return 0;
}

static bool is_valid_channel(struct device *dev, uint8_t channel_index,
    enum hailo_dma_data_direction direction)
{
    switch (direction) {
    case HAILO_DMA_TO_DEVICE:
        if (channel_index >= VDMA_DEST_CHANNELS_START) {
            hailo_dev_err(dev, "Invalid input channel index %d\n", channel_index);
            return false;
        }
        return true;
    case HAILO_DMA_FROM_DEVICE:
        if ((channel_index < VDMA_DEST_CHANNELS_START) ||
            (channel_index >= MAX_VDMA_CHANNELS)) {
            hailo_dev_err(dev, "Invalid output channel index %d\n", channel_index);
            return false;
        }
        return true;
    default:
        hailo_dev_err(dev, "not supported direction %d\n", direction);
        return false;
    }
}

long hailo_vdma_channel_enable(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_vdma_channel_enable_params input;
    struct hailo_vdma_channel *channel = NULL;
    long err = 0;

    hailo_dev_info(controller->dev, "HAILO_VDMA_CHANNEL_ENABLE\n");

    if (copy_from_user(&input, (void *)arg, sizeof(input))) {
        hailo_dev_err(controller->dev, "HAILO_VDMA_CHANNEL_ENABLE, copy_from_user fail\n");
        return -ENOMEM;
    }

    if (!is_valid_channel(controller->dev, input.channel_index, input.direction)) {
        return -EINVAL;
    }

    channel = &controller->channels[input.channel_index];

    if (INVALID_CHANNEL_HANDLE_VALUE != controller->channels[input.channel_index].handle) {
        hailo_dev_err(controller->dev, "HAILO_VDMA_CHANNEL_ENABLE channel %u was already enabled\n",
            input.channel_index);
        return -EINVAL;
    }

    if (INVALID_DRIVER_HANDLE_VALUE != input.desc_list_handle) {
        err = start_channel(context, controller, &input);
        if (err < 0) {
            return err;
        }
    }

    if (input.enable_timestamps_measure) {
        channel->timestamp_measure_enabled = true;
        channel->timestamp_list.head = channel->timestamp_list.tail = 0;
    }

    channel->handle = atomic64_inc_return(&controller->last_channel_handle);
    if (INVALID_CHANNEL_HANDLE_VALUE == channel->handle) {
        // We reach invalid handle value, use next one.
        channel->handle = atomic64_inc_return(&controller->last_channel_handle);
    }

    channel->direction = get_dma_direction(input.direction);
    channel->should_abort = false;
    set_bit(input.channel_index, &context->enabled_channels);
    hailo_vdma_update_interrupts(controller);

    input.channel_handle = channel->handle;
    if (copy_to_user((void __user*)arg, &input, sizeof(input))) {
        hailo_dev_err(controller->dev, "HAILO_VDMA_CHANNEL_ENABLE, copy_to_user fail\n");
        hailo_vdma_channel_disable_internal(context, controller, input.channel_index);
        return -ENOMEM;
    }

    hailo_dev_info(controller->dev, "HAILO_VDMA_CHANNEL_ENABLE enabled for channel %d handle %llu\n",
        input.channel_index, channel->handle);
    return 0;
}

void hailo_vdma_channel_disable_internal(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller, size_t channel_index)
{
    unsigned long irq_saved_flags;
    struct hailo_vdma_channel *channel = &controller->channels[channel_index];
    // In case of FLR, the vdma registers will be NULL
    const bool is_device_up = (NULL != controller->dev);
    u8 to_device_control_reg = 0;
    u8 from_device_control_reg = 0;

    channel->handle = INVALID_CHANNEL_HANDLE_VALUE;
    channel->direction = DMA_NONE;
    spin_lock_irqsave(&controller->channels_interrupts.lock, irq_saved_flags);
    __clear_bit(channel_index, (ulong *)&controller->channels_interrupts.channel_data_source);
    __clear_bit(channel_index, (ulong *)&controller->channels_interrupts.channel_data_dest);
    spin_unlock_irqrestore(&controller->channels_interrupts.lock, irq_saved_flags);

    if (is_device_up) {
        hailo_vdma_update_interrupts(controller);
    }

    // Trigger completion to wake-up any thread that might be waiting for interrupts for the channel we are disabling
    complete(&channel->completion);
    channel->timestamp_measure_enabled = false;

    clear_bit(channel_index, &context->enabled_channels);

    if (is_device_up) {
        hailo_dev_info(controller->dev, "Aborting channel %u", (u32)channel_index);
        hailo_vdma_channel_validate_stopped(&controller->registers, channel_index, &to_device_control_reg, &from_device_control_reg);
    }
}

long hailo_vdma_channel_disable(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    struct hailo_vdma_channel_disable_params input;
    struct hailo_vdma_channel *channel = NULL;
    long err = -EINVAL;
    hailo_dev_info(controller->dev, "HAILO_VDMA_CHANNEL_DISABLE\n");

    if (copy_from_user(&input, (void*)arg, sizeof(input))) {
        hailo_dev_err(controller->dev, "HAILO_VDMA_CHANNEL_DISABLE, copy_from_user fail\n");
        return -ENOMEM;
    }

    err = hailo_vdma_channel_get(controller, input.channel_index, input.channel_handle, &channel);
    if (err < 0) {
        hailo_dev_err(controller->dev, "HAILO_VDMA_CHANNEL_DISABLE, channel %u not exists or in use by another handle",
            input.channel_index);
        return err;
    }

    if (!test_bit(input.channel_index, &context->enabled_channels)) {
        hailo_dev_err(controller->dev,
            "HAILO_VDMA_CHANNEL_DISABLE, channel index %d was enabled by a different filp\n",
            input.channel_index);
        return -EINVAL;
    }

    hailo_vdma_channel_disable_internal(context, controller, input.channel_index);

    return 0;
}

static long hailo_vdma_channel_wait_interrupts(struct hailo_vdma_controller *controller,
    u32 channel_index, u64 channel_handle, u64 timeout_ms, struct semaphore *mutex, bool *should_up_board_mutex)
{
    long err = 0;
    unsigned long irq_saved_flags;
    long completion_result = -1;
    bool got_interrupt = false;
    struct hailo_vdma_channel *channel = NULL;

    err = hailo_vdma_channel_get(controller, channel_index, channel_handle, &channel);
    if (err < 0) {
        hailo_dev_info(controller->dev, "HAILO_VDMA_CHANNEL_WAIT_INT, channel %u not exists or in use by another handle",
            channel_index);
        return -ECONNRESET;
    }

    while (true) {
        // break if device removed
        if (!controller->dev) {
            hailo_dev_err(controller->dev, "HAILO_VDMA_CHANNEL_WAIT_INT, device removed\n");
            err = -ENODEV;
            goto l_exit;
        }

        // Channel was disabled or reused by another process
        if (channel->handle != channel_handle) {
            hailo_dev_info(controller->dev, "HAILO_VDMA_CHANNEL_WAIT_INT, channel was closed %u\n", channel_index);
            err = -ECONNRESET;
            goto l_exit;
        }

        if (channel->should_abort) {
            hailo_dev_info(controller->dev, "HAILO_VDMA_CHANNEL_WAIT_INT, aborting channel %u\n", channel_index);
            err = -ECONNABORTED;
            goto l_exit;
        }

        reinit_completion(&channel->completion);

        // Read and zero out the interrupt data
        spin_lock_irqsave(&controller->channels_interrupts.lock, irq_saved_flags);
        got_interrupt =
            __test_and_clear_bit(channel_index, (ulong *)&controller->channels_interrupts.channel_data_source) ||
            __test_and_clear_bit(channel_index, (ulong *)&controller->channels_interrupts.channel_data_dest);
        spin_unlock_irqrestore(&controller->channels_interrupts.lock, irq_saved_flags);

        // data was available
        if (got_interrupt) {
            break;
        }

        up(mutex);

        completion_result = wait_for_completion_interruptible_timeout(&channel->completion, msecs_to_jiffies(timeout_ms));
        if (completion_result <= 0) {
            *should_up_board_mutex = false;
            if (0 == completion_result) {
                hailo_dev_info(controller->dev,
                    "HAILO_VDMA_CHANNEL_WAIT_INT - timedout waiting for interrupt in channel %u (timeout_ms=%llu)\n",
                    channel_index, timeout_ms);
                err = -ETIMEDOUT;
            } else {
                hailo_dev_info(controller->dev,
                    "HAILO_VDMA_CHANNEL_WAIT_INT - wait for completion failed with err=%ld for channel %u"
                    "(process was interrupted or killed)\n",
                    completion_result, channel_index);
                err = -EINTR;
            }
            goto l_exit;
        }

        if (down_interruptible(mutex)) {
            hailo_dev_info(controller->dev,
                "HAILO_VDMA_CHANNEL_WAIT_INT - down_interruptible error (process was interrupted or killed)\n");
            *should_up_board_mutex = false;
            err = -ERESTARTSYS;
            goto l_exit;
        }
    }

l_exit:
    return err;
}

int copy_timestamps_to_user(struct hailo_channel_interrupt_timestamp_list *timestamp_list,
    struct hailo_vdma_channel_wait_params *interrupt_args)
{
    u32 max_timestamps = interrupt_args->timestamps_count;
    u32 i = 0;
    struct hailo_channel_interrupt_timestamp current_timestamp = {0};

    while (hailo_vdma_pop_timestamp(timestamp_list, &current_timestamp) && (i < max_timestamps)) {
        if (copy_to_user((void __user*)&(interrupt_args->timestamps[i]), &current_timestamp,
            sizeof(interrupt_args->timestamps[i]))) {
            return -ENOMEM;
        }

        i++;
    }

    interrupt_args->timestamps_count = i;

    return 0;
}

long hailo_vdma_channel_wait_interrupts_ioctl(struct hailo_vdma_controller *controller, unsigned long arg,
    struct semaphore *mutex, bool *should_up_board_mutex)
{
    long err = 0;
    struct hailo_vdma_channel_wait_params intr_args = {0};

    if (copy_from_user(&intr_args, (void*)arg, sizeof(intr_args))) {
        hailo_dev_err(controller->dev, "HAILO_VDMA_CHANNEL_WAIT_INT, copy_from_user fail\n");
        return -ENOMEM;
    }

    err = hailo_vdma_channel_wait_interrupts(controller, intr_args.channel_index, intr_args.channel_handle,
        intr_args.timeout_ms, mutex, should_up_board_mutex);
    if (err < 0) {
        return err;
    }

    if (unlikely(controller->channels[intr_args.channel_index].timestamp_measure_enabled)) {
        err = copy_timestamps_to_user(&controller->channels[intr_args.channel_index].timestamp_list, &intr_args);
        if (err < 0) {
            hailo_dev_err(controller->dev, "HAILO_VDMA_CHANNEL_WAIT_INT copy timestamps to user failed fail\n");
            return err;
        }
    }

    if (copy_to_user((void __user*)arg, &intr_args, sizeof(intr_args))) {
        hailo_dev_err(controller->dev, "HAILO_VDMA_CHANNEL_WAIT_INT, copy_to_user fail\n");
        return -ENOMEM;
    }

    return 0;
}

long hailo_vdma_channel_abort(struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_channel *channel = NULL;
    struct hailo_vdma_channel_abort_params input;
    long err = -EINVAL;

    if (copy_from_user(&input, (void __user*)arg, sizeof(input))) {
        hailo_dev_err(controller->dev, "HAILO_VDMA_CHANNEL_ABORT, copy_from_user fail\n");
        return -ENOMEM;
    }

    err = hailo_vdma_channel_get(controller, input.channel_index, input.channel_handle, &channel);
    if (err < 0) {
        return err;
    }

    channel->should_abort = true;
    complete(&channel->completion);

    return 0;
}

long hailo_vdma_channel_clear_abort(struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_channel *channel = NULL;
    struct hailo_vdma_channel_clear_abort_params input;
    long err = -EINVAL;

    if (copy_from_user(&input, (void __user*)arg, sizeof(input))) {
        hailo_dev_err(controller->dev, "HAILO_VDMA_CHANNEL_CLEAR_ABORT, copy_from_user fail\n");
        return -ENOMEM;
    }

    err = hailo_vdma_channel_get(controller, input.channel_index, input.channel_handle, &channel);
    if (err < 0) {
        return err;
    }

    channel->should_abort = false;

    return 0;
}

long hailo_vdma_channel_registers_ioctl(struct hailo_vdma_controller *controller, unsigned long arg)
{
    // according to vdma spec the registers size for each channel is 0x20 bytes
    const size_t CHANNEL_REGISTERS_SIZE = 0x20;
    struct hailo_channel_registers_params params;

    hailo_dev_dbg(controller->dev, "HAILO_CHANNEL_REGISTERS\n");

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "HAILO_CHANNEL_REGISTERS, copy_from_user fail\n");
        return -ENOMEM;
    }

    // check for valid input
    if (params.offset >= (MAX_VDMA_CHANNELS * CHANNEL_REGISTERS_SIZE)) {
        hailo_dev_err(controller->dev, "HAILO_CHANNEL_REGISTERS, invalid offset %ld\n", (long)params.offset);
        return -EINVAL;
    }

    switch (params.transfer_direction) {
        case TRANSFER_READ:
            switch (params.size) {
            case 4:
                params.data = hailo_resource_read32(&controller->registers, params.offset);
                break;
            case 2:
                params.data = (uint32_t)hailo_resource_read16(&controller->registers, params.offset);
                break;
            case 1:
                params.data = (uint32_t)hailo_resource_read8(&controller->registers, params.offset);
                break;
            default:
                hailo_dev_err(controller->dev, "HAILO_CHANNEL_REGISTERS, size %zu is invalid (only 4,2,1 is allowed)\n", params.size);
                return -EINVAL;
            }
            if (copy_to_user((void __user *)arg, &params, sizeof(params))) {
                hailo_dev_err(controller->dev, "HAILO_CHANNEL_REGISTERS, copy_to_user fail\n");
                return -ENOMEM;
            }
        break;
    case TRANSFER_WRITE:
        switch (params.size) {
        case 4:
            hailo_resource_write32(&controller->registers, params.offset, params.data);
            break;
        case 2:
            hailo_resource_write16(&controller->registers, params.offset, (uint16_t)params.data);
            break;
        case 1:
            hailo_resource_write8(&controller->registers, params.offset, (uint8_t)params.data);
            break;
        default:
            hailo_dev_err(controller->dev, "HAILO_CHANNEL_REGISTERS, size %zu is invalid (only 4,2,1 is allowed)\n", params.size);
            return -EINVAL;
        }
        break;
    default:
        hailo_dev_err(controller->dev, "HAILO_CHANNEL_REGISTERS, unknown transfer type %d\n", params.transfer_direction);
        return -EINVAL;
    }

    return 0;
}

void hailo_vdma_channel_irq_handler(struct hailo_vdma_controller *controller, u32 channel_index)
{
    struct hailo_vdma_channel *channel = &controller->channels[channel_index];
    if (unlikely(channel->timestamp_measure_enabled)) {
        hailo_vdma_push_timestamp(&channel->timestamp_list,
            &controller->registers, channel_index, channel->direction);
    }
}
