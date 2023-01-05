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


#define GET_CHANNEL(controller, engine_index, channel_index) \
    (&((controller)->vdma_engines[(engine_index)].channels[(channel_index)]))

static long hailo_vdma_channel_get(struct hailo_vdma_controller *controller,
    u8 engine_index, u8 channel_index, u64 channel_handle,
    struct hailo_vdma_channel **channel)
{
    struct hailo_vdma_channel *local_channel = NULL;

    if (engine_index >= controller->vdma_engines_count) {
        hailo_dev_err(controller->dev, "Invalid engine %u", engine_index);
        return -EINVAL;
    }

    if (channel_index >= MAX_VDMA_CHANNELS_PER_ENGINE) {
        hailo_dev_err(controller->dev, "Channel index %u is more than maximum channel %d\n",
            channel_index, MAX_VDMA_CHANNELS_PER_ENGINE);
        return -EINVAL;
    }

    if (INVALID_CHANNEL_HANDLE_VALUE == channel_handle) {
        hailo_dev_dbg(controller->dev, "Invalid chanel handle was passed (channel index %d)\n", channel_index);
        return -ECONNRESET;
    }

    local_channel = GET_CHANNEL(controller, engine_index, channel_index);
    if (channel_handle != local_channel->handle) {
        hailo_dev_dbg(controller->dev, "Channel %u:%u is used by another handle\n",
            engine_index, channel_index);
        return -ECONNRESET;
    }

    *channel = local_channel;
    return 0;
}

static void hailo_vdma_update_interrupts_mask(struct hailo_vdma_controller *controller,
    size_t engine_index)
{
    uint32_t channel_bitmap = 0;
    int i = 0;
    struct hailo_vdma_engine *engine = &controller->vdma_engines[engine_index];
    for (i = 0; i < ARRAY_SIZE(engine->channels); ++i) {
        if (INVALID_CHANNEL_HANDLE_VALUE != engine->channels[i].handle) {
            hailo_set_bit(i, &channel_bitmap);
        }
    }

    controller->ops->update_channel_interrupts(controller, engine_index, channel_bitmap);
}

long hailo_vdma_channel_enable(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    static const bool DONT_STOP_CHANNEL = false;
    struct hailo_vdma_channel_enable_params input;
    struct hailo_vdma_channel *channel = NULL;

    if (copy_from_user(&input, (void *)arg, sizeof(input))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -ENOMEM;
    }

    if (input.engine_index >= controller->vdma_engines_count) {
        hailo_dev_err(controller->dev, "Invalid engine %u", input.engine_index);
        return -EINVAL;
    }

    if (!hailo_vdma_is_valid_channel(input.channel_index, input.direction)) {
        hailo_dev_err(controller->dev, "Invalid channel! index of invalid channel: %d, direction of invalid channel: %d\n",
            input.channel_index, input.direction);
        return -EINVAL;
    }

    channel = GET_CHANNEL(controller, input.engine_index, input.channel_index);

    if (INVALID_CHANNEL_HANDLE_VALUE != channel->handle) {
        hailo_dev_err(controller->dev, "Channel %u:%u was already enabled\n",
            input.engine_index, input.channel_index);
        return -EINVAL;
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
    hailo_set_bit(input.channel_index, &context->enabled_channels_per_engine[input.engine_index]);
    hailo_vdma_update_interrupts_mask(controller, input.engine_index);

    input.channel_handle = channel->handle;
    if (copy_to_user((void __user*)arg, &input, sizeof(input))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        // Channels will be stopped by the fw or in hailo_vdma_file_context_finalize
        // (Also, the channel hasn't been started => no need to stop)
        hailo_vdma_channel_disable_internal(context, controller,
            input.engine_index, input.channel_index, DONT_STOP_CHANNEL);
        return -ENOMEM;
    }

    hailo_dev_info(controller->dev, "Enabled channel %u:%u handle %llu\n",
        input.engine_index, input.channel_index, channel->handle);
    return 0;
}

void hailo_vdma_channel_disable_internal(struct hailo_vdma_file_context *context,
    struct hailo_vdma_controller *controller, const size_t engine_index,
    const size_t channel_index, bool stop_channel)
{
    int err = 0;
    unsigned long irq_saved_flags;
    struct hailo_vdma_engine *engine = &controller->vdma_engines[engine_index];
    struct hailo_vdma_channel *channel = &engine->channels[channel_index];
    // In case of FLR, the vdma registers will be NULL
    const bool is_device_up = (NULL != controller->dev);
    u8 to_device_control_reg = 0;
    u8 from_device_control_reg = 0;

    channel->handle = INVALID_CHANNEL_HANDLE_VALUE;
    channel->direction = DMA_NONE;
    spin_lock_irqsave(&engine->interrupts.lock, irq_saved_flags);
    hailo_clear_bit(channel_index, &engine->interrupts.channel_data_source);
    hailo_clear_bit(channel_index, &engine->interrupts.channel_data_dest);
    spin_unlock_irqrestore(&engine->interrupts.lock, irq_saved_flags);

    if (is_device_up) {
        hailo_vdma_update_interrupts_mask(controller, engine_index);
    }

    // Trigger completion to wake-up any thread that might be waiting for interrupts for the channel we are disabling
    complete_all(&channel->completion);
    channel->timestamp_measure_enabled = false;

    hailo_clear_bit(channel_index, &context->enabled_channels_per_engine[engine_index]);

    if (stop_channel && is_device_up) {
        hailo_dev_info(controller->dev, "Aborting channel %u", (u32)channel_index);
        err = hailo_vdma_stop_channel(
            &controller->vdma_engines[engine_index].channel_registers,
            channel_index, &to_device_control_reg, &from_device_control_reg);
        if (err != 0) {
            hailo_dev_err(controller->dev, "hailo_vdma_stop_channel failed for channel %u with errno %d", (u32)channel_index, err);
        }
    }
}

long hailo_vdma_channel_disable(struct hailo_vdma_file_context *context, struct hailo_vdma_controller *controller,
    unsigned long arg)
{
    static const bool DONT_STOP_CHANNEL = false;
    struct hailo_vdma_channel_disable_params input;
    struct hailo_vdma_channel *channel = NULL;
    long err = -EINVAL;
    uint32_t enabled_channels = 0;

    if (copy_from_user(&input, (void*)arg, sizeof(input))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -ENOMEM;
    }

    err = hailo_vdma_channel_get(controller, input.engine_index,
        input.channel_index, input.channel_handle, &channel);
    if (err < 0) {
        hailo_dev_err(controller->dev, "channel %u:%u not exists or in use by another handle",
            input.engine_index, input.channel_index);
        return err;
    }

    enabled_channels = context->enabled_channels_per_engine[input.engine_index];
    if (!hailo_test_bit(input.channel_index, &enabled_channels)){
        hailo_dev_err(controller->dev, "channel %u:%u not enabled by current process\n",
            input.engine_index, input.channel_index);
        return -EINVAL;
    }

    // Channels will be stopped by the fw or in hailo_vdma_file_context_finalize
    hailo_vdma_channel_disable_internal(context, controller,
        input.engine_index, input.channel_index, DONT_STOP_CHANNEL);

    return 0;
}

static long hailo_vdma_channel_wait_interrupts(struct hailo_vdma_controller *controller,
    u8 engine_index, u8 channel_index, u64 timeout_ms,
    struct semaphore *mutex, bool *should_up_board_mutex)
{
    long err = 0;
    unsigned long irq_saved_flags;
    long completion_result = -1;
    bool got_interrupt = false;
    struct hailo_vdma_engine *engine = &controller->vdma_engines[engine_index];
    struct hailo_vdma_channel *channel = &engine->channels[channel_index];
    const u64 original_handle = channel->handle;

    while (true) {
        // break if device removed
        if (!controller->dev) {
            hailo_dev_err(controller->dev, "Device removed on wait interrupts\n");
            err = -ENODEV;
            goto l_exit;
        }

        // We first check that the channel is enabled, and then we check if it is aborted so if the channel is both
        // disabled and aborted, we return status that it is disabled.
        if (channel->handle != original_handle) {
            hailo_dev_info(controller->dev, "channel %u:%u was closed\n",
                engine_index, channel_index);
            err = -ECONNRESET;
            goto l_exit;
        }

        if (channel->should_abort) {
            hailo_dev_info(controller->dev, "aborting channel %u:%u\n",
                engine_index, channel_index);
            err = -ECONNABORTED;
            goto l_exit;
        }

        reinit_completion(&channel->completion);

        // Read and zero out the interrupt data
        spin_lock_irqsave(&engine->interrupts.lock, irq_saved_flags);
        got_interrupt = hailo_test_bit(channel_index, &engine->interrupts.channel_data_source) || 
            hailo_test_bit(channel_index, &engine->interrupts.channel_data_dest);
        
        hailo_clear_bit(channel_index, &engine->interrupts.channel_data_source);
        hailo_clear_bit(channel_index, &engine->interrupts.channel_data_dest);
        spin_unlock_irqrestore(&engine->interrupts.lock, irq_saved_flags);

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
                    "timedout waiting for interrupt in channel %u:%u (timeout_ms=%llu)\n",
                    engine_index, channel_index, timeout_ms);
                err = -ETIMEDOUT;
            } else {
                hailo_dev_info(controller->dev,
                    "Wait for completion failed with err=%ld for channel %u:%u"
                    "(process was interrupted or killed)\n",
                    completion_result, engine_index, channel_index);
                err = -EINTR;
            }
            goto l_exit;
        }

        if (down_interruptible(mutex)) {
            hailo_dev_info(controller->dev,
                "down_interruptible error (process was interrupted or killed)\n");
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
    struct hailo_vdma_channel *channel = NULL;

    if (copy_from_user(&intr_args, (void*)arg, sizeof(intr_args))) {
        hailo_dev_err(controller->dev, "HAILO_VDMA_CHANNEL_WAIT_INT, copy_from_user fail\n");
        return -ENOMEM;
    }

    err = hailo_vdma_channel_get(controller, intr_args.engine_index,
        intr_args.channel_index, intr_args.channel_handle, &channel);
    if (err < 0) {
        return -ECONNRESET;
    }

    err = hailo_vdma_channel_wait_interrupts(controller, intr_args.engine_index,
        intr_args.channel_index, intr_args.timeout_ms, mutex,
        should_up_board_mutex);
    if (err < 0) {
        return err;
    }

    if (unlikely(channel->timestamp_measure_enabled)) {
        err = copy_timestamps_to_user(&channel->timestamp_list, &intr_args);
        if (err < 0) {
            hailo_dev_err(controller->dev, "copy timestamps to user failed fail\n");
            return err;
        }
    } else {
        intr_args.timestamps_count = 0;
    }

    if (copy_to_user((void __user*)arg, &intr_args, sizeof(intr_args))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
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
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -ENOMEM;
    }

    err = hailo_vdma_channel_get(controller, input.engine_index,
        input.channel_index, input.channel_handle, &channel);
    if (err < 0) {
        return err;
    }

    channel->should_abort = true;
    complete_all(&channel->completion);

    return 0;
}

long hailo_vdma_channel_clear_abort(struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_channel *channel = NULL;
    struct hailo_vdma_channel_clear_abort_params input;
    long err = -EINVAL;

    if (copy_from_user(&input, (void __user*)arg, sizeof(input))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -ENOMEM;
    }

    err = hailo_vdma_channel_get(controller, input.engine_index,
        input.channel_index, input.channel_handle, &channel);
    if (err < 0) {
        return err;
    }

    channel->should_abort = false;

    return 0;
}

long hailo_vdma_channel_read_register_ioctl(struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_channel_read_register_params params;
    int err = 0;
    size_t engine_index = 0;
    struct hailo_resource *channel_registers = NULL;

    hailo_dev_dbg(controller->dev, "Read vdma channel registers\n");

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -ENOMEM;
    }

    if (params.engine_index >= controller->vdma_engines_count) {
        hailo_dev_err(controller->dev, "Invalid engine %u", params.engine_index);
        return -EINVAL;
    }

    engine_index = params.engine_index;
    channel_registers = &controller->vdma_engines[engine_index].channel_registers;
    err = hailo_vdma_channel_read_register(&params, channel_registers);
    if (0 != err) {
        hailo_dev_err(controller->dev, "hailo vdma channel read registers failed with error %d\n", err);
        return -EINVAL;
    }

    if (copy_to_user((void __user *)arg, &params, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy_to_user fail\n");
        return -ENOMEM;
    }

    return 0;
}

long hailo_vdma_channel_write_register_ioctl(struct hailo_vdma_controller *controller, unsigned long arg)
{
    struct hailo_vdma_channel_write_register_params params;
    int err = 0;
    size_t engine_index = 0;
    struct hailo_resource *channel_registers = NULL;

    hailo_dev_dbg(controller->dev, "Write vdma channel registers\n");

    if (copy_from_user(&params, (void __user*)arg, sizeof(params))) {
        hailo_dev_err(controller->dev, "copy_from_user fail\n");
        return -ENOMEM;
    }

    if (params.engine_index >= controller->vdma_engines_count) {
        hailo_dev_err(controller->dev, "Invalid engine %u", params.engine_index);
        return -EINVAL;
    }

    engine_index = params.engine_index;
    channel_registers = &controller->vdma_engines[engine_index].channel_registers;
    err = hailo_vdma_channel_write_register(&params, channel_registers);
    if (0 != err) {
        hailo_dev_err(controller->dev, "hailo vdma channel write registers failed with error %d\n", err);
        return -EINVAL;
    }

    return 0;
}

void hailo_vdma_channel_irq_handler(struct hailo_vdma_controller *controller,
    size_t engine_index, u32 channel_index)
{
    struct hailo_vdma_engine *engine = &controller->vdma_engines[engine_index];
    struct hailo_vdma_channel *channel = &engine->channels[channel_index];
    if (unlikely(channel->timestamp_measure_enabled)) {
        hailo_vdma_push_timestamp(&channel->timestamp_list,
            &engine->channel_registers, channel_index, channel->direction);
    }
}
