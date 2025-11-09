// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (c) 2019-2025 Hailo Technologies Ltd. All rights reserved.
 **/

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/firmware.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
#include <linux/dma-direct.h>
#endif

#include "hailo_ioctl_common.h"
#include "pcie.h"
#include "nnc.h"
#include "soc.h"
#include "fops.h"
#include "sysfs.h"
#include "logs.h"
#include "utils/compact.h"
#include "vdma/vdma.h"
#include "vdma/memory.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION( 5, 4, 0 )
#include <linux/pci-aspm.h>
#endif

// Debug flag
static int force_desc_page_size = 0;
static bool g_is_power_mode_enabled = true;
static bool force_hailo10h_legacy_mode = false;
static bool support_soft_reset = true;

#define DEVICE_NODE_NAME "hailo"
static int char_major = 0;
static struct class *g_chrdev_class = NULL;

static LIST_HEAD(g_hailo_board_list);
static struct semaphore g_hailo_add_board_mutex = __SEMAPHORE_INITIALIZER(g_hailo_add_board_mutex, 1);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22))
#define HAILO_IRQ_FLAGS (SA_SHIRQ | SA_INTERRUPT)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 22) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0))
#define HAILO_IRQ_FLAGS (IRQF_SHARED | IRQF_DISABLED)
#else
#define HAILO_IRQ_FLAGS (IRQF_SHARED)
#endif

#define HAILO_PCI_RESET_POLL_INTERVAL_MS (100)
#define HAILO_PCI_MAX_RESET_POLLS        (10)

 /* ****************************
  ******************************* */
bool power_mode_enabled(void)
{
#if !defined(HAILO_EMULATOR)
    return g_is_power_mode_enabled;
#else /* !defined(HAILO_EMULATOR) */
    return false;
#endif /* !defined(HAILO_EMULATOR) */
}

/**
 * Due to an HW bug, on system with low MaxReadReq ( < 512) we need to use different descriptors size.
 * Returns the max descriptor size or 0 on failure.
 */
static int hailo_get_desc_page_size(struct pci_dev *pdev, u32 *out_page_size)
{
    u16 pcie_device_control = 0;
    int err = 0;
    // The default page size must be smaller/equal to 4096 (due to FW assumptions).
    const u32 default_page_size = min((u32)PAGE_SIZE, 4096u);

    if (force_desc_page_size != 0) {
        // The user given desc_page_size as a module parameter
        if ((force_desc_page_size & (force_desc_page_size - 1)) != 0) {
            pci_err(pdev, "force_desc_page_size must be a power of 2\n");
            return -EINVAL;
        }

        pci_notice(pdev, "Probing: Force setting max_desc_page_size to %d (PAGE_SIZE=%lu)\n",
            force_desc_page_size, PAGE_SIZE);
        *out_page_size = force_desc_page_size;
        return 0;
    }

    err = pcie_capability_read_word(pdev, PCI_EXP_DEVCTL, &pcie_device_control);
    if (err < 0) {
        pci_err(pdev, "Couldn't read DEVCTL capability\n");
        return err;
    }

    switch (pcie_device_control & PCI_EXP_DEVCTL_READRQ) {
    case PCI_EXP_DEVCTL_READRQ_128B:
        *out_page_size = 128;
        break;
    case PCI_EXP_DEVCTL_READRQ_256B:
        *out_page_size = 256;
        break;
    default:
        *out_page_size = default_page_size;
        break;
    };

    pci_notice(pdev, "Probing: Setting max_desc_page_size to %u, (PAGE_SIZE=%lu)\n", *out_page_size, PAGE_SIZE);
    return 0;
}

struct hailo_pcie_board* hailo_pcie_get_board_by_index(u32 index)
{
    struct hailo_pcie_board *board, *ret = NULL;

    down(&g_hailo_add_board_mutex);
    list_for_each_entry(board, &g_hailo_board_list, board_list) {
        if (index == board->board_index) {
            kref_get(&board->kref);
            ret = board;
            break;
        }
    }
    up(&g_hailo_add_board_mutex);

    return ret;
}

static void free_board(struct kref *kref)
{
    struct hailo_pcie_board *board = container_of(kref, struct hailo_pcie_board, kref);
    pr_notice(DRIVER_NAME ": Freeing board struct\n");
    kfree(board);
}

void hailo_pcie_put_board(struct hailo_pcie_board *board)
{
    kref_put(&board->kref, free_board);
}

/**
 * hailo_pcie_disable_aspm - Disable ASPM states
 * @board: pointer to PCI board struct
 * @state: bit-mask of ASPM states to disable
 * @locked: indication if this context holds pci_bus_sem locked.
 *
 * Some devices *must* have certain ASPM states disabled per hardware errata.
 **/
static int hailo_pcie_disable_aspm(struct hailo_pcie_board *board, u16 state, bool locked)
{
    struct pci_dev *pdev = board->pdev;
    struct pci_dev *parent = pdev->bus->self;
    u16 aspm_dis_mask = 0;
    u16 pdev_aspmc = 0;
    u16 parent_aspmc = 0;
    int err = 0;

    switch (state) {
    case PCIE_LINK_STATE_L0S:
        aspm_dis_mask |= PCI_EXP_LNKCTL_ASPM_L0S;
        break;
    case PCIE_LINK_STATE_L1:
        aspm_dis_mask |= PCI_EXP_LNKCTL_ASPM_L1;
        break;
    default:
        break;
    }

    err = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL, &pdev_aspmc);
    if (err < 0) {
        hailo_err(board, "Couldn't read LNKCTL capability\n");
        return err;
    }

    pdev_aspmc &= PCI_EXP_LNKCTL_ASPMC;

    if (parent) {
        err = pcie_capability_read_word(parent, PCI_EXP_LNKCTL, &parent_aspmc);
        if (err < 0) {
            hailo_err(board, "Couldn't read slot LNKCTL capability\n");
            return err;
        }
        parent_aspmc &= PCI_EXP_LNKCTL_ASPMC;
    }

    hailo_notice(board, "Disabling ASPM %s %s\n",
        (aspm_dis_mask & PCI_EXP_LNKCTL_ASPM_L0S) ? "L0s" : "",
        (aspm_dis_mask & PCI_EXP_LNKCTL_ASPM_L1) ? "L1" : "");

    // Disable L0s even if it is currently disabled as ASPM states can be enabled by the kernel when changing power modes
#ifdef CONFIG_PCIEASPM
    if (locked) {
        // Older kernel versions (<5.2.21) don't return value for this functions, so we try manual disabling anyway
        (void)pci_disable_link_state_locked(pdev, state);
    } else {
        (void)pci_disable_link_state(pdev, state);
    }

    /* Double-check ASPM control.  If not disabled by the above, the
     * BIOS is preventing that from happening (or CONFIG_PCIEASPM is
     * not enabled); override by writing PCI config space directly.
     */
    err = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL, &pdev_aspmc);
    if (err < 0) {
        hailo_err(board, "Couldn't read LNKCTL capability\n");
        return err;
    }
    pdev_aspmc &= PCI_EXP_LNKCTL_ASPMC;

    if (!(aspm_dis_mask & pdev_aspmc)) {
        hailo_notice(board, "Successfully disabled ASPM %s %s\n",
            (aspm_dis_mask & PCI_EXP_LNKCTL_ASPM_L0S) ? "L0s" : "",
            (aspm_dis_mask & PCI_EXP_LNKCTL_ASPM_L1) ? "L1" : "");
        return 0;
    }
#endif

    /* Both device and parent should have the same ASPM setting.
     * Disable ASPM in downstream component first and then upstream.
     */
    err = pcie_capability_clear_word(pdev, PCI_EXP_LNKCTL, aspm_dis_mask);
    if (err < 0) {
        hailo_err(board, "Couldn't read LNKCTL capability\n");
        return err;
    }
    if (parent) {
        err = pcie_capability_clear_word(parent, PCI_EXP_LNKCTL, aspm_dis_mask);
        if (err < 0) {
            hailo_err(board, "Couldn't read slot LNKCTL capability\n");
            return err;
        }
    }
    hailo_notice(board, "Manually disabled ASPM %s %s\n",
        (aspm_dis_mask & PCI_EXP_LNKCTL_ASPM_L0S) ? "L0s" : "",
        (aspm_dis_mask & PCI_EXP_LNKCTL_ASPM_L1) ? "L1" : "");

    return 0;
}

static long hailo_pcie_insert_board(struct hailo_pcie_board* board)
{
    u32 index = 0;
    struct hailo_pcie_board *pCurrent, *pNext;

    down(&g_hailo_add_board_mutex);

    if (!g_chrdev_class) {
        g_chrdev_class = class_create_compat("hailo_chardev");
        if (IS_ERR(g_chrdev_class)) {
            hailo_err(board, "Failed to create class for chrdev");
            return PTR_ERR(g_chrdev_class);
        }
    }

    if ( list_empty(&g_hailo_board_list)  ||
            list_first_entry(&g_hailo_board_list, struct hailo_pcie_board, board_list)->board_index > 0)
    {
        board->board_index = 0;
        list_add(&board->board_list, &g_hailo_board_list);

        up(&g_hailo_add_board_mutex);
        return 0;
    }

    list_for_each_entry_safe(pCurrent, pNext, &g_hailo_board_list, board_list)
    {
        index = pCurrent->board_index+1;
        if( list_is_last(&pCurrent->board_list, &g_hailo_board_list) || (index != pNext->board_index))
        {
            break;
        }
    }

    board->board_index = index;
    list_add(&board->board_list, &pCurrent->board_list);

    up(&g_hailo_add_board_mutex);

    return 0;
}

static void hailo_pcie_remove_board(struct hailo_pcie_board* board)
{
    down(&g_hailo_add_board_mutex);
    if (board) {
        list_del(&board->board_list);
    }
    up(&g_hailo_add_board_mutex);
}

/**
 * Wait until the relevant completion is done.
 *
 * @param completion - pointer to the completion struct to wait for.
 * @param msecs - the amount of time to wait in milliseconds.
 * @return false if timed out, true if completed.
 */
static bool wait_for_firmware_completion(struct completion *completion, unsigned int msecs)
{
    return (0 != wait_for_completion_timeout(completion, msecs_to_jiffies(msecs)));
}

/**
 * Release noncontinuous memory (virtual continuous memory). (sg table and kernel_addrs)
 *
 * @param dev - pointer to the device struct we are working on.
 * @param sg_table - the sg table to release.
 * @param kernel_addrs - the kernel address to release.
 */
static void pcie_vdma_release_noncontinuous_memory(struct device *dev, struct sg_table *sg_table, void *kernel_addrs)
{
    dma_unmap_sg(dev, sg_table->sgl, sg_table->orig_nents, DMA_TO_DEVICE);
    sg_free_table(sg_table);
    vfree(kernel_addrs);
}

/**
 * Allocate noncontinuous memory (virtual continuous memory).
 *
 * @param dev - pointer to the device struct we are working on.
 * @param buffer_size - the size of the buffer to allocate.
 * @param kernel_addrs - pointer to the allocated buffer.
 * @param sg_table - pointer to the sg table struct.
 * @return 0 on success, negative error code on failure. on failure all resurces are released. (pages array, sg table, kernel_addrs)
 */
static long pcie_vdma_allocate_noncontinuous_memory(struct device *dev, u64 buffer_size, void **kernel_addrs, struct sg_table *sg_table)
{
    struct page **pages = NULL;
    size_t npages = 0;
    long err = 0;
    size_t i = 0;

    // allocate noncontinuous memory for the kernel address (virtual continuous memory)
    *kernel_addrs = vmalloc(buffer_size);
    if (NULL == *kernel_addrs) {
        hailo_dev_err(dev, "Failed to allocate memory for kernel_addrs\n");
        err = -ENOMEM;
        goto exit;
    }

    // map the memory to pages
    npages = DIV_ROUND_UP(buffer_size, PAGE_SIZE);

    // allocate memory for a virtually contiguous array for the pages
    pages = kvmalloc_array(npages, sizeof(*pages), GFP_KERNEL);
    if (!pages) {
        err = -ENOMEM;
        hailo_dev_err(dev, "Failed to allocate memory for pages\n");
        goto release_user_addrs;
    }

    // walk a vmap address to the struct page it maps
    for (i = 0; i < npages; i++) {
        pages[i] = vmalloc_to_page(*kernel_addrs + (i * PAGE_SIZE));
        if (!pages[i]) {
            err = -ENOMEM;
            hailo_dev_err(dev, "Failed to get page from vmap address\n");
            goto release_array;
        }
    }

    // allocate and initialize the sg table from a list of pages
    err = sg_alloc_table_from_pages(sg_table, pages, npages, 0, buffer_size, GFP_KERNEL);
    if (err < 0) {
        hailo_dev_err(dev, "sg table alloc failed (err %ld)..\n", err);
        goto release_array;
    }

    // map the sg list
    sg_table->nents = dma_map_sg(dev, sg_table->sgl, sg_table->orig_nents, DMA_TO_DEVICE);
    if (0 == sg_table->nents) {
        hailo_dev_err(dev, "failed to map sg list for user buffer\n");
        err = -EFAULT;
        goto release_sg_table;
    }

    // clean exit - just release the pages array & return err = 0
    err = 0;
    kfree(pages);
    goto exit;

release_sg_table:
    dma_unmap_sg(dev, sg_table->sgl, sg_table->orig_nents, DMA_TO_DEVICE);
release_array:
    kfree(pages);
release_user_addrs:
    vfree(*kernel_addrs);
exit:
    return err;
}

/**
 * Release all boot resources.
 *
 * @param fw_boot - pointer to the fw boot struct we are working on.
 * @param engine - pointer to the vdma engine struct.
 * @param dev - pointer to the device struct.
 */
static void pcie_platform_release_boot_resources(struct hailo_pcie_fw_boot_linux *fw_boot, struct hailo_vdma_engine *engine,
    struct device *dev)
{
    u8 channel_index = 0;
    u8 allocated_channels = 0;

    if (!fw_boot) {
        return;
    }

    allocated_channels = fw_boot->common.boot_dma_state.allocated_channels;

    hailo_dev_dbg(dev, "Releasing boot resources for %u channels\n", allocated_channels);

    // Release any cached firmware first
    hailo_pcie_release_firmware_cache(&fw_boot->common.boot_dma_state);

    // Release resources for the allocated number of channels
    for (channel_index = 0; channel_index < allocated_channels; channel_index++) {
        // Direct access to common channels and platform buffers
        struct hailo_pcie_boot_dma_channel_state *channel = &fw_boot->common.boot_dma_state.channels[channel_index];
        struct hailo_descriptors_list_buffer *host_buffer = &fw_boot->host_descriptors_buffers[channel_index];
        struct hailo_descriptors_list_buffer *device_buffer = &fw_boot->device_descriptors_buffers[channel_index];
        
        // Release Linux-specific descriptor buffers
        if (host_buffer->kernel_address != NULL) {
            hailo_desc_list_release(dev, host_buffer);
            host_buffer->kernel_address = NULL;
        }
        if (device_buffer->kernel_address != NULL) {
            hailo_desc_list_release(dev, device_buffer);
            device_buffer->kernel_address = NULL;
        }

        // Clear the pointers in the common structure
        channel->host_descriptors_list = NULL;
        channel->device_descriptors_list = NULL;

        // Stop all boot vDMA channels
        hailo_vdma_stop_channel(engine->channels[channel_index].host_regs);
        hailo_vdma_stop_channel(engine->channels[channel_index].device_regs);

        // Release noncontinuous memory (virtual continuous memory)
        if (channel->kernel_address != NULL) {
            pcie_vdma_release_noncontinuous_memory(dev, &channel->sg_table, channel->kernel_address);
            channel->kernel_address = NULL;
        }
    }

    hailo_dev_dbg(dev, "Boot resources release completed\n");
}

/**
 * Allocate linux specific boot resources for vDMA transfer.
 *
 * @param pcie_fw_boot - pointer to the pcie fw boot struct.
 * @param desc_page_size - the size of the descriptor page.
 * @param num_channels - number of channels to allocate for this stage.
 * @param board - pointer to the board struct.
 * @return 0 on success, negative error code on failure. in case of failure descriptor lists are released,
 *  boot vDMA channels are stopped and memory is released.
 */
static long pcie_platform_allocate_boot_resources(struct hailo_pcie_fw_boot_linux *pcie_fw_boot, u32 desc_page_size, u8 num_channels, struct hailo_pcie_board *board)
{
    struct hailo_vdma_engine *engine = &board->vdma.vdma_engines[PCI_VDMA_ENGINE_INDEX];
    long err = 0;
    uintptr_t device_handle = 0, host_handle = 0;
    u8 channel_index = 0;

    if (!pcie_fw_boot || !board) {
        pr_err("Invalid parameters: fw_boot=%p, board=%p\n", pcie_fw_boot, board);
        return -EINVAL;
    }

    if (num_channels == 0 || num_channels > HAILO_PCI_OVER_VDMA_MAX_CHANNELS) {
        hailo_err(board, "Invalid number of channels: %u (max: %u)\n", num_channels, HAILO_PCI_OVER_VDMA_MAX_CHANNELS);
        return -EINVAL;
    }

    hailo_dbg(board, "Linux: Allocating boot resources for %u channels\n", num_channels);

    // Allocate resources for the calculated number of channels
    for (channel_index = 0; channel_index < num_channels; channel_index++) {
        // Direct access to common channels and platform buffers
        struct hailo_pcie_boot_dma_channel_state *channel = &pcie_fw_boot->common.boot_dma_state.channels[channel_index];
        struct hailo_descriptors_list_buffer *host_buffer = &pcie_fw_boot->host_descriptors_buffers[channel_index];
        struct hailo_descriptors_list_buffer *device_buffer = &pcie_fw_boot->device_descriptors_buffers[channel_index];

        // Create 2 descriptors list - 1 for the host & 1 for the device for each channel
        err = hailo_desc_list_create(&board->pdev->dev, MAX_SG_DESCS_COUNT, desc_page_size, host_handle, false,
            host_buffer);
        if (err < 0) {
            hailo_err(board, "Failed to allocate host descriptors list buffer for channel %u\n", channel_index);
            goto release_all_resources;
        }

        err = hailo_desc_list_create(&board->pdev->dev, MAX_SG_DESCS_COUNT, desc_page_size, device_handle, false,
            device_buffer);
        if (err < 0) {
            hailo_err(board, "Failed to allocate device descriptors list buffer for channel %u\n", channel_index);
            goto release_all_resources;
        }

        // Set up pointers in common structure to platform-allocated descriptors
        channel->host_descriptors_list = &host_buffer->desc_list;
        channel->device_descriptors_list = &device_buffer->desc_list;

        // Start vDMA channels - both sides with descriptors list at the host DDR (AKA ID 0)
        hailo_vdma_start_channel(engine->channels[channel_index].host_regs,
            host_buffer->dma_address,
            host_buffer->desc_list.desc_count, board->vdma.hw->ddr_data_id);
        hailo_vdma_start_channel(engine->channels[channel_index].device_regs,
            device_buffer->dma_address,
            device_buffer->desc_list.desc_count, board->vdma.hw->ddr_data_id);

        // Initialize the buffer size per channel
        channel->buffer_size = (MAX_SG_DESCS_COUNT * desc_page_size);
        channel->desc_program_num = 0;

        // Allocate noncontinuous memory (virtual continuous memory)
        err = pcie_vdma_allocate_noncontinuous_memory(&board->pdev->dev, channel->buffer_size,
            &channel->kernel_address, &channel->sg_table);
        if (err < 0) {
            hailo_err(board, "Failed to allocate noncontinuous memory for channel %u\n", channel_index);
            goto release_all_resources;
        }
    }
    pcie_fw_boot->common.boot_dma_state.curr_channel_index = 0;

    hailo_info(board, "Linux: Boot resources allocation completed for all channels\n");
    return 0;

release_all_resources:
    pcie_platform_release_boot_resources(pcie_fw_boot, engine, &board->pdev->dev);
    return err;
}

/*
 * Write FW boot files over vDMA using multiple channels for timing optimizations.
 * 
 * The function is divided into the following steps:
 * 1) Calculate the required number of channels for this stage.
 * 2) Allocate resources for the boot process.
 * 3) Programs descriptors to point to the memory and start the vDMA.
 * 4) Waits until the vDMA is done and triggers the device to start the boot process.
 * 5) Releases all the resources.
 *
 * @param board - pointer to the board struct.
 * @param stage - the stage of the boot process.
 * @return 0 on success, negative error code on failure. in any case all resurces are released.
 */
static long pcie_write_firmware_batch_over_dma(struct hailo_pcie_board *board, u32 stage)
{
    struct hailo_vdma_engine *engine = &board->vdma.vdma_engines[PCI_VDMA_ENGINE_INDEX];
    long err = 0;
    u8 channel_index = 0;
    u8 required_channels = 0;
    struct hailo_pcie_boot_dma_state *boot_dma_state = &board->fw_boot.common.boot_dma_state;

    hailo_info(board, "Starting common firmware batch loading for stage %u\n", stage);

    // Load firmware and calculate the required number of channels for this stage
    err = hailo_pcie_load_and_cache_stage_firmware(&board->fw_boot.common, &board->pcie_resources, stage, &board->pdev->dev);
    if (err < 0) {
        hailo_err(board, "Failed to load and cache firmware for stage %u: %ld\n", stage, err);
        return err;
    }

    required_channels = boot_dma_state->allocated_channels;
    hailo_dbg(board, "Stage %u requires %u channels\n", stage, required_channels);

    err = pcie_platform_allocate_boot_resources(&board->fw_boot, HAILO_PCI_OVER_VDMA_PAGE_SIZE, required_channels, board);
    if (err) {
        return err;
    }

    // initialize the completion for the vDMA boot data completion
    reinit_completion(&board->fw_boot.vdma_boot_completion);

    // Pass the common structure to the common function
    err = hailo_pcie_program_firmware_batch_common(&board->fw_boot.common, &board->pcie_resources, stage, &board->pdev->dev);
    if (err < 0) {
        hailo_err(board, "Failed to program firmware batch for stage %u: %ld\n", stage, err);
        goto release_all;
    }

    // Sync the sg tables for the device before starting the vDMA
    for (channel_index = 0; channel_index < required_channels; channel_index++) {
        struct hailo_pcie_boot_dma_channel_state *common_channel = &boot_dma_state->channels[channel_index];
        dma_sync_sgtable_for_device(&board->pdev->dev, &common_channel->sg_table, DMA_TO_DEVICE);
    }

    // Start the vDMA transfer on all allocated channels
    for (channel_index = 0; channel_index < required_channels; channel_index++) {
        struct hailo_pcie_boot_dma_channel_state *common_channel = &boot_dma_state->channels[channel_index];
        if (common_channel->desc_program_num > 0) {
            // Trigger the transfers (channels were started during descriptor allocation)
            hailo_vdma_set_num_avail(engine->channels[channel_index].host_regs, common_channel->desc_program_num);
            hailo_vdma_set_num_avail(engine->channels[channel_index].device_regs, common_channel->desc_program_num);
            hailo_dbg(board, "Set num avail to %u, on channel %u\n", common_channel->desc_program_num, channel_index);
        }
    }

    if (!wait_for_firmware_completion(&board->fw_boot.vdma_boot_completion,
        hailo_pcie_get_loading_stage_info(board->pcie_resources.board_type, stage)->timeout)) {
        hailo_err(board, "Timeout waiting for vDMA boot data completion\n");
        err = -ETIMEDOUT;
        goto release_all;
    }

    hailo_notice(board, "vDMA transfer completed, triggering boot\n");
    reinit_completion(&board->fw_boot.fw_loaded_completion);
    hailo_trigger_firmware_boot(&board->pcie_resources, stage);

release_all:
    // Always release boot resources, regardless of success or failure
    pcie_platform_release_boot_resources(&board->fw_boot, engine, &board->pdev->dev);
    return err;
}

#define STRATEGY_PCIE_BARS (0)
#define STRATEGY_DMA       (1)

/**
 * write_firmware_and_wait_completion() - Write firmware to device and wait
 * for completion indicating write done.
 * @hailo_pcie_board: Board to boot.
 * @stage:            Boot stage (FIRST_STAGE, SECOND_STAGE, ...).
 * @strategy:         Firmware write strategy. Can be over PCIE
 *                    or DMA, see above.
 *
 * Important: Assumes board->fw_boot.fw_loaded_completion and
 * board->fw_boot.vdma_boot_completion have already been initialized.
 */
static int write_firmware_and_wait_completion(struct hailo_pcie_board *board, u32 stage, u32 strategy) {
    struct hailo_pcie_resources *resources = &board->pcie_resources;
    struct device *dev = &board->pdev->dev;
    struct completion *fw_load_completion = &board->fw_boot.fw_loaded_completion;
    int err = 0;

    if (STRATEGY_PCIE_BARS == strategy) {
        err = hailo_pcie_write_firmware_batch(dev, resources, stage);
        if (err < 0) {
            hailo_dev_err(dev, "Failed writing firmware files over PCIe bars. err %d\n", err);
            return err;
        }
    } else if (STRATEGY_DMA == strategy) {
        err = (int)pcie_write_firmware_batch_over_dma(board, stage);
        if (err < 0) {
            hailo_dev_err(dev, "Failed writing firmware files over vDMA. err %d\n", err);
            return err;
        }
    } else {
        hailo_dev_err(dev, "Invalid firmware write strategy");
        return -EINVAL;
    }

    if (!wait_for_firmware_completion(fw_load_completion, hailo_pcie_get_loading_stage_info(resources->board_type, stage)->timeout)) {
        hailo_dev_err(dev, "Timeout waiting for firmware file\n");
        return -ETIMEDOUT;
    }

    reinit_completion(fw_load_completion);

    return 0;
}

static void print_scu_log(struct hailo_pcie_board *board)
{
    u32 scu_log_size = HAILO_SCU_LOG_MAX_SIZE;
    u8 *scu_log_buffer = kmalloc(scu_log_size, GFP_KERNEL);
    if (!scu_log_buffer) {
        hailo_err(board, "Failed to allocate SCU log buffer\n");
        return;
    }

    if (hailo_pcie_read_scu_log(&board->pcie_resources, scu_log_buffer, &scu_log_size) >= 0) {
        if (scu_log_size > 0) {
            scu_log_buffer[scu_log_size] = '\0';
            hailo_warn(board, "SCU log:\n");
            hailo_warn(board, "%s\n", scu_log_buffer);
        } else {
            hailo_warn(board, "SCU log is empty\n");
        }
    } else {
        hailo_err(board, "Cannot read SCU log\n");
    }

    kfree(scu_log_buffer);
}

static int load_soc_firmware(struct hailo_pcie_board *board)
{
    struct hailo_pcie_resources *resources = &board->pcie_resources;
    struct device *dev = &board->pdev->dev;
    int err = 0;

    if (hailo_pcie_is_firmware_loaded(resources)) {
        hailo_dev_warn(dev, "SOC Firmware batch was already loaded\n");
        return 0;
    }

    // configure the EP registers for the DMA transaction
    hailo_pcie_configure_ep_registers_for_dma_transaction(resources);

    init_completion(&board->fw_boot.fw_loaded_completion);
    init_completion(&board->fw_boot.vdma_boot_completion);

    // Send certificate and SCU code.
    err = write_firmware_and_wait_completion(board, FIRST_STAGE, STRATEGY_PCIE_BARS);
    if (err < 0) {
        hailo_dev_err(dev, "Failed writing SOC firmware on stage 1. boot_status %x\n", hailo_get_boot_status(resources));
        return err;
    }

    // Read SKU-ID. SCU is responsible for writing SKU-ID to correct address.
    hailo_read_sku_id(resources);
    if (HAILO_SKU_ID_DEFAULT == resources->sku_id) {
        hailo_notice(board, "Board SKU-ID is default");
    } else {
        hailo_notice(board, "Board SKU-ID is: %d", resources->sku_id);
    }

    // Send .dtb file over PCIe bars. Filename is resolved based on SKU-ID from stage 1.
    err = write_firmware_and_wait_completion(board, SECOND_STAGE, STRATEGY_PCIE_BARS);
    if (err < 0) {
        hailo_dev_err(dev, "Failed writing SOC firmware on stage 2\n");
        if (err != -EFBIG) {
            print_scu_log(board);
        }
        return err;
    }

    // Boot linux. Remaining files sent over DMA.
    err = write_firmware_and_wait_completion(board, THIRD_STAGE, STRATEGY_DMA);
    if (err < 0) {
        hailo_dev_err(dev, "Failed writing SOC firmware on stage 3\n");
        if (err != -EFBIG) {
            print_scu_log(board);
        }
        return err;
    }

    hailo_dev_notice(dev, "SOC Firmware Batch loaded successfully\n");
    return 0;
}

static int hailo_pcie_soft_reset(struct hailo_pcie_board *board)
{
    bool completion_result = false;
    int err = 0;

    hailo_pcie_write_firmware_soft_reset(&board->pcie_resources);

    reinit_completion(&board->soft_reset.reset_completed);

    // Wait for response
    completion_result =
        wait_for_firmware_completion(&board->soft_reset.reset_completed, msecs_to_jiffies(FIRMWARE_WAIT_TIMEOUT_MS));
    if (completion_result == false) {
        hailo_warn(board, "hailo reset firmware, timeout waiting for shutdown response (timeout_ms=%d)\n", FIRMWARE_WAIT_TIMEOUT_MS);
        err = -ETIMEDOUT;
        return err;
    }

    if (!hailo_pcie_wait_for_boot(&board->pcie_resources)) {
        hailo_warn(board, "couldn't wait for bootloader\n");
        return -ETIMEDOUT;
    }

    hailo_notice(board, "soft reset finished\n");
    return err;
}

static int load_nnc_firmware(struct hailo_pcie_board *board)
{
    int err = 0;
    struct device *dev = &board->pdev->dev;

    if (hailo_pcie_is_firmware_loaded(&board->pcie_resources)) {
        if (support_soft_reset) {
            err = hailo_pcie_soft_reset(board);
            if (err < 0) {
                hailo_dev_err(dev, "Failed hailo pcie soft reset. err %d\n", err);
                return 0;
            }
            hailo_dev_notice(dev, "Soft reset done\n");
        } else {
            hailo_dev_warn(dev, "NNC Firmware batch was already loaded\n");
            return 0;
        }
    }

    init_completion(&board->fw_boot.fw_loaded_completion);

    err = write_firmware_and_wait_completion(board, FIRST_STAGE, STRATEGY_PCIE_BARS);
    if (err < 0) {
        hailo_dev_err(dev, "Failed loading NNC firmware\n");
        return err;
    }

    hailo_dev_notice(dev, "NNC Firmware loaded successfully\n");
    return 0;
}

static int load_firmware(struct hailo_pcie_board *board)
{
    switch (board->pcie_resources.accelerator_type) {
    case HAILO_ACCELERATOR_TYPE_SOC:
        return load_soc_firmware(board);
    case HAILO_ACCELERATOR_TYPE_NNC:
        return load_nnc_firmware(board);
    default:
        hailo_err(board, "Invalid board type %d\n", board->pcie_resources.accelerator_type);
        return -EINVAL;
    }
}

static int hailo_activate_board(struct hailo_pcie_board *board)
{
    int err = 0;
    ktime_t start_time = 0, end_time = 0;

    (void)hailo_pcie_disable_aspm(board, PCIE_LINK_STATE_L0S, false);

    err = hailo_enable_interrupts(board);
    if (err < 0) {
        hailo_err(board, "Failed enabling interrupts %d\n", err);
        return err;
    }

    // Set is_in_boot for fimware loading for interrupt handler
    board->fw_boot.is_in_boot = true;

    start_time = ktime_get();
    err = load_firmware(board);
    end_time = ktime_get();

    board->fw_boot.is_in_boot = false;

    if (err < 0) {
        hailo_err(board, "Firmware load failed\n");
        hailo_disable_interrupts(board);
        return err;
    }

    hailo_notice(board, "Firmware loaded in %lld ms\n", ktime_to_ms(ktime_sub(end_time, start_time)));

    if (HAILO_ACCELERATOR_TYPE_SOC == board->pcie_resources.accelerator_type) {
        err = hailo_soc_get_driver_info(board);
        if (err < 0) {
            hailo_err(board, "hailo_soc_get_driver_info has failed with err %d\n", err);
        }
    }

    hailo_disable_interrupts(board);
    if (power_mode_enabled()) {
        // Setting the device to low power state, until the user opens the device
        hailo_info(board, "Power change state  to PCI_D3hot\n");
        err = pci_set_power_state(board->pdev, PCI_D3hot);
        if (err < 0) {
            hailo_err(board, "Set power state failed %d\n", err);
            return err;
        }
    }

    return 0;
}

int hailo_enable_interrupts(struct hailo_pcie_board *board)
{
    int err = 0;

    if (board->interrupts_enabled) {
        hailo_crit(board, "Failed enabling interrupts (already enabled)\n");
        return -EINVAL;
    }

    // TODO HRT-2253: use new api for enabling msi: (pci_alloc_irq_vectors)
    if ((err = pci_enable_msi(board->pdev))) {
        hailo_err(board, "Failed to enable MSI %d\n", err);
        return err;
    }
    hailo_info(board, "Enabled MSI interrupt\n");

    err = request_irq(board->pdev->irq, hailo_irqhandler, HAILO_IRQ_FLAGS, DRIVER_NAME, board);
    if (err) {
        hailo_err(board, "request_irq failed %d\n", err);
        pci_disable_msi(board->pdev);
        return err;
    }
    hailo_info(board, "irq enabled %u\n", board->pdev->irq);

    hailo_pcie_enable_interrupts(&board->pcie_resources);

    board->interrupts_enabled = true;
    return 0;
}

void hailo_disable_interrupts(struct hailo_pcie_board *board)
{
    // Sanity Check
    if ((NULL == board) || (NULL == board->pdev)) {
        pr_err("Failed to access board or device\n");
        return;
    }

    if (!board->interrupts_enabled) {
        return;
    }

    board->interrupts_enabled = false;
    hailo_pcie_disable_interrupts(&board->pcie_resources);
    free_irq(board->pdev->irq, board);
    pci_disable_msi(board->pdev);
}

static int hailo_bar_iomap(struct pci_dev *pdev, int bar, struct hailo_resource *resource)
{
    resource->size = pci_resource_len(pdev, bar);
    resource->address = (uintptr_t)(pci_iomap(pdev, bar, resource->size));

    if (!resource->size || !resource->address) {
        pci_err(pdev, "Probing: Invalid PCIe BAR %d", bar);
        return -EINVAL;
    }

    pci_notice(pdev, "Probing: mapped bar %d - %p %zu\n", bar,
        (void*)resource->address, resource->size);
    return 0;
}

static void hailo_bar_iounmap(struct pci_dev *pdev, struct hailo_resource *resource)
{
    if (resource->address) {
        pci_iounmap(pdev, (void*)resource->address);
        resource->address = 0;
        resource->size = 0;
    }
}

static int pcie_resources_init(struct pci_dev *pdev, struct hailo_pcie_resources *resources,
    enum hailo_board_type board_type)
{
    int err = -EINVAL;
    if (board_type >= HAILO_BOARD_TYPE_COUNT) {
        pci_err(pdev, "Probing: Invalid board type %d\n", (int)board_type);
        err = -EINVAL;
        goto failure_exit;
    }

    err = pci_request_regions(pdev, DRIVER_NAME);
    if (err < 0) {
        pci_err(pdev, "Probing: Error allocating bars %d\n", err);
        goto failure_exit;
    }

    err = hailo_bar_iomap(pdev, HAILO_PCIE_CONFIG_BAR, &resources->config);
    if (err < 0) {
        goto failure_release_regions;
    }

    err = hailo_bar_iomap(pdev, HAILO_PCIE_VDMA_REGS_BAR, &resources->vdma_registers);
    if (err < 0) {
        goto failure_release_config;
    }

    err = hailo_bar_iomap(pdev, HAILO_PCIE_FW_ACCESS_BAR, &resources->fw_access);
    if (err < 0) {
        goto failure_release_vdma_regs;
    }

    if (HAILO_BOARD_TYPE_HAILO10H == board_type) {
        if (true == force_hailo10h_legacy_mode) {
            board_type = HAILO_BOARD_TYPE_HAILO15H_ACCELERATOR_MODE;
        }
    }

    resources->board_type = board_type;

    resources->sku_id = 0;

    err = hailo_set_device_type(resources);
    if (err < 0) {
        goto failure_release_fw_access;
    }

    if (!hailo_pcie_is_device_connected(resources)) {
        pci_err(pdev, "Probing: Failed reading device BARs, device may be disconnected\n");
        err = -ENODEV;
        goto failure_release_fw_access;
    }

    return 0;

failure_release_fw_access:
    hailo_bar_iounmap(pdev, &resources->fw_access);
failure_release_vdma_regs:
    hailo_bar_iounmap(pdev, &resources->vdma_registers);
failure_release_config:
    hailo_bar_iounmap(pdev, &resources->config);
failure_release_regions:
    pci_release_regions(pdev);
failure_exit:
    return err;
}

static void pcie_resources_release(struct pci_dev *pdev, struct hailo_pcie_resources *resources)
{
    hailo_bar_iounmap(pdev, &resources->config);
    hailo_bar_iounmap(pdev, &resources->vdma_registers);
    hailo_bar_iounmap(pdev, &resources->fw_access);
    pci_release_regions(pdev);
}

static void update_channel_interrupts(struct hailo_vdma_controller *controller,
    size_t engine_index, u64 channels_bitmap)
{
    u32 channels_bitmap_red = channels_bitmap & 0xFFFFFFFF;
    struct hailo_pcie_board *board = (struct hailo_pcie_board*) dev_get_drvdata(controller->dev);
    if (engine_index >= board->vdma.vdma_engines_count) {
        hailo_err(board, "Invalid engine index %zu", engine_index);
        return;
    }

    hailo_pcie_update_channel_interrupts_mask(&board->pcie_resources, channels_bitmap_red);
}

static struct hailo_vdma_controller_ops pcie_vdma_controller_ops = {
    .update_channel_interrupts = update_channel_interrupts,
};

static int hailo_pcie_vdma_controller_init(struct hailo_vdma_controller *controller,
    struct device *dev, struct hailo_resource *vdma_registers)
{
    const size_t engines_count = 1;
    return hailo_vdma_controller_init(controller, dev, &hailo_pcie_vdma_hw,
        &pcie_vdma_controller_ops, vdma_registers, engines_count);
}

static int hailo_pcie_probe(struct pci_dev* pdev, const struct pci_device_id* id)
{
    struct hailo_pcie_board * board;
    struct device *char_device = NULL;
    int err = -EINVAL;

    pci_notice(pdev, "Probing on: %04x:%04x...\n", pdev->vendor, pdev->device);
#ifdef HAILO_EMULATOR
    pci_notice(pdev, "PCIe driver was compiled in emulator mode\n");
#endif /* HAILO_EMULATOR */
    if (!g_is_power_mode_enabled) {
        pci_notice(pdev, "PCIe driver was compiled with power modes disabled\n");
    }

    /* Initialize device extension for the board*/
    pci_notice(pdev, "Probing: Allocate memory for device extension, %zu\n", sizeof(struct hailo_pcie_board));
    board = (struct hailo_pcie_board*) kzalloc( sizeof(struct hailo_pcie_board), GFP_KERNEL);
    if (board == NULL)
    {
        pci_err(pdev, "Probing: Failed to allocate memory for device extension structure\n");
        err = -ENOMEM;
        goto probe_exit;
    }

    board->pdev = pdev;

    err = pci_enable_device(pdev);
    if (err) {
        pci_err(pdev, "Probing: Failed calling pci_enable_device %d\n", err);
        goto probe_free_board;
    }
    pci_notice(pdev, "Probing: Device enabled\n");

    pci_set_master(pdev);

    err = pcie_resources_init(pdev, &board->pcie_resources, id->driver_data);
    if (err < 0) {
        pci_err(pdev, "Probing: Failed init pcie resources");
        goto probe_disable_device;
    }

    err = hailo_get_desc_page_size(pdev, &board->desc_max_page_size);
    if (err < 0) {
        goto probe_release_pcie_resources;
    }

    // Initialize the boot DMA state
    memset(&board->fw_boot, 0, sizeof(board->fw_boot));

    // Initialize the boot channel bitmap to 1 since channel 0 is always used for boot
    // (we will always use at least 1 channel which is LSB in the bitmap)
    // Additional channels will be added dynamically as they get allocated
    board->fw_boot.common.boot_used_channel_bitmap = (1 << 0);
    board->fw_boot.common.boot_dma_state.curr_channel_index = 0;
    board->fw_boot.common.boot_dma_state.allocated_channels = 0; // Will be calculated per stage
    board->fw_boot.common.boot_dma_state.cached_firmware_count = 0; // Initialize firmware cache
    board->fw_boot.is_in_boot = false;
    init_completion(&board->fw_boot.fw_loaded_completion);

    sema_init(&board->mutex, 1);
    kref_init(&board->kref);
    INIT_LIST_HEAD(&board->open_files_list);

    // Init both soc and nnc, since the interrupts are shared.
    hailo_nnc_init(&board->nnc);
    hailo_soc_init(&board->soc);

    init_completion(&board->driver_down.reset_completed);
    init_completion(&board->soft_reset.reset_completed);

    err = hailo_pcie_vdma_controller_init(&board->vdma, &board->pdev->dev,
        &board->pcie_resources.vdma_registers);
    if (err < 0) {
        hailo_err(board, "Failed init vdma controller %d\n", err);
        goto probe_release_pcie_resources;
    }

    err = hailo_activate_board(board);
    if (err < 0) {
        hailo_err(board, "Failed activating board %d\n", err);
        goto probe_release_pcie_resources;
    }

    /* Keep track on the device, in order, to be able to remove it later */
    pci_set_drvdata(pdev, board);
    err = hailo_pcie_insert_board(board);
    if (err < 0) {
        hailo_err(board, "Failed inserting board %d to list\n", err);
        goto probe_release_pcie_resources;
    }

    /* Create dynamically the device node*/
    char_device = device_create_with_groups(g_chrdev_class, &pdev->dev,
                                            MKDEV(char_major, board->board_index),
                                            board,
                                            g_hailo_dev_groups,
                                            DEVICE_NODE_NAME"%d", board->board_index);
    if (IS_ERR(char_device)) {
        hailo_err(board, "Failed creating dynamic device %d\n", board->board_index);
        err = PTR_ERR(char_device);
        goto probe_remove_board;
    }

    hailo_notice(board, "Probing: Added board %0x-%0x, /dev/hailo%d\n", pdev->vendor, pdev->device, board->board_index);

    return 0;

probe_remove_board:
    hailo_pcie_remove_board(board);

probe_release_pcie_resources:
    pcie_resources_release(board->pdev, &board->pcie_resources);

probe_disable_device:
    pci_disable_device(pdev);

probe_free_board:
    kfree(board);

probe_exit:
    return err;
}

static void hailo_pcie_remove(struct pci_dev* pdev)
{
    struct hailo_pcie_board* board = (struct hailo_pcie_board*) pci_get_drvdata(pdev);
    struct hailo_file_context *cur_file_context = NULL, *next_file_context = NULL;

    pci_notice(pdev, "Remove: Releasing board\n");

    if (!board) {
        return;
    }

    // Lock board to wait for any pending operations and for synchronization with open
    down(&board->mutex);

    list_for_each_entry_safe(cur_file_context, next_file_context, &board->open_files_list, open_files_list) {
        hailo_pcie_finalize_file_context(cur_file_context);
    }

    // Remove board from active boards list
    hailo_pcie_remove_board(board);

    // Delete the device node
    device_destroy(g_chrdev_class, MKDEV(char_major, board->board_index));

    // Disable interrupts - will only disable if they have not been disabled in release already
    hailo_disable_interrupts(board);

    pcie_resources_release(board->pdev, &board->pcie_resources);

    // There may still be an active file context open after finalize them.
    // Each open file should check (under the lock) if the board is still active (by checking the device is alive)
    board->pdev = NULL;
    board->vdma.dev = NULL;

    pci_disable_device(pdev);

    pci_set_drvdata(pdev, NULL);

    if (board->pcie_resources.accelerator_type == HAILO_ACCELERATOR_TYPE_NNC) {
        hailo_nnc_finalize(&board->nnc);
    }

    up(&board->mutex);

    hailo_pcie_put_board(board);
}

#ifdef CONFIG_PM_SLEEP
static int hailo_pcie_suspend(struct device *dev)
{
    struct hailo_pcie_board *board = (struct hailo_pcie_board*) dev_get_drvdata(dev);
    struct hailo_file_context *cur = NULL, *next = NULL;

    // lock board to wait for any pending operations
    down(&board->mutex);

    // Un validate all active file contexts so every new action will return error to the user.
    list_for_each_entry_safe(cur, next, &board->open_files_list, open_files_list) {
        hailo_pcie_finalize_file_context(cur);
    }

    // Disable all interrupts. All interrupts from Hailo chip would be masked.
    hailo_disable_interrupts(board);

    // Release board
    up(&board->mutex);

    dev_notice(dev, "PM's suspend\n");
    // Success Oriented - Continue system suspend even in case of error (otherwise system will not suspend correctly)
    return 0;
}

static int hailo_pcie_resume(struct device *dev)
{
    struct hailo_pcie_board *board = (struct hailo_pcie_board*) dev_get_drvdata(dev);
    int err = 0;

    if ((err = hailo_activate_board(board)) < 0) {
        dev_err(dev, "Failed activating board %d\n", err);
    }

    dev_notice(dev, "PM's resume\n");
    // Success Oriented - Continue system resume even in case of error (otherwise system will not suspend correctly)
    return 0;
}
#endif /* CONFIG_PM_SLEEP */

static SIMPLE_DEV_PM_OPS(hailo_pcie_pm_ops, hailo_pcie_suspend, hailo_pcie_resume);

#if LINUX_VERSION_CODE >= KERNEL_VERSION( 3, 16, 0 )
static void hailo_pci_reset_prepare(struct pci_dev *pdev)
{
    struct hailo_pcie_board* board = (struct hailo_pcie_board*) pci_get_drvdata(pdev);
    struct hailo_file_context *cur = NULL, *next = NULL;

    pci_notice(pdev, "Reset preparation for PCI device\n");

    if (!board) {
       pr_warn("No PCI board found before reset\n");
       return;
    }

    down(&board->mutex);

    list_for_each_entry_safe(cur, next, &board->open_files_list, open_files_list) {
        hailo_pcie_finalize_file_context(cur);
    }

    hailo_disable_interrupts(board);

    up(&board->mutex);
}

static void hailo_pci_reset_done(struct pci_dev *pdev)
{
    struct hailo_pcie_board* board = (struct hailo_pcie_board*) pci_get_drvdata(pdev);
    int err = 0, i = 0;

    pci_notice(pdev, "Reset done for PCI device: reactivating board\n");

    if (!board) {
       pr_warn("No PCI board found after reset\n");
       return;
    }

    // Note: we are safe to operate on an unlocked board since we invalidated all open file-contexts
    // in `hailo_pci_reset_prepare()`.

    for (i = 0; i < HAILO_PCI_MAX_RESET_POLLS; i++) {

        // Wait until baord has reset succesfully.
        if (hailo_pcie_is_firmware_loaded(&board->pcie_resources)) {
            msleep(HAILO_PCI_RESET_POLL_INTERVAL_MS);
            continue;
        }

        // Reset some board fields before reboot.
        board->fw_boot.common.boot_used_channel_bitmap = (1 << 0);
        memset(&board->fw_boot.common.boot_dma_state, 0, sizeof(board->fw_boot.common.boot_dma_state));
        board->fw_boot.common.boot_dma_state.allocated_channels = 0;

        // Reboot the board.
        err = hailo_activate_board(board);
        if (err) {
            pr_err("Failed to activate board after reset");
        }

        return;
    }

    pr_err("Failed PCI reset: board still active after FLR");
}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION( 3, 16, 0 ) */

#if LINUX_VERSION_CODE < KERNEL_VERSION( 4, 13, 0 ) && LINUX_VERSION_CODE >= KERNEL_VERSION( 3, 16, 0 )
/**
 * hailo_pci_reset_notify - called before and after PCI reset.
 * @pdev: PCI device
 * @prepare: Indicates if function was called from "prepare reset" flow.
 *
 * When called before reset, `prepare` will be ture, otherwise `prepare`
 * will be false.
 */
static void hailo_pci_reset_notify(struct pci_dev *pdev, bool prepare)
{
    prepare ? hailo_pci_reset_prepare(pdev) : hailo_pci_reset_done(pdev);
}
#endif

static const struct pci_error_handlers hailo_pcie_err_handlers = {
#if LINUX_VERSION_CODE < KERNEL_VERSION( 3, 16, 0 )
    // FLR not supported.
#elif LINUX_VERSION_CODE < KERNEL_VERSION( 4, 13, 0 )
    .reset_notify   = hailo_pci_reset_notify,
#else
    .reset_prepare = hailo_pci_reset_prepare,
    .reset_done =    hailo_pci_reset_done,
#endif
};

static struct pci_device_id hailo_pcie_id_table[] =
{
    {PCI_DEVICE_DATA(HAILO, HAILO10H, HAILO_BOARD_TYPE_HAILO10H)},
    {PCI_DEVICE_DATA(HAILO, HAILO15L, HAILO_BOARD_TYPE_HAILO15L)},
    {PCI_DEVICE_DATA(HAILO, MARS, HAILO_BOARD_TYPE_MARS)},
    {0,0,0,0,0,0,0 },
};

static struct file_operations hailo_pcie_fops =
{
    .owner =          THIS_MODULE,
    .unlocked_ioctl = hailo_pcie_fops_unlockedioctl,
    .mmap =           hailo_pcie_fops_mmap,
    .open =           hailo_pcie_fops_open,
    .release =        hailo_pcie_fops_release
};

static struct pci_driver hailo_pci_driver =
{
    .name =        DRIVER_NAME,
    .id_table =    hailo_pcie_id_table,
    .probe =       hailo_pcie_probe,
    .remove =      hailo_pcie_remove,
    .err_handler = &hailo_pcie_err_handlers,
    .driver = {
        .pm =         &hailo_pcie_pm_ops,
        .probe_type = PROBE_PREFER_ASYNCHRONOUS,
    }
};

MODULE_DEVICE_TABLE (pci, hailo_pcie_id_table);

static int hailo_pcie_register_chrdev(unsigned int major, const char *name)
{
    int char_major;

    char_major = register_chrdev(major, name, &hailo_pcie_fops);

    return char_major;
}

static void hailo_pcie_unregister_chrdev(unsigned int major, const char *name)
{
    if (!g_chrdev_class) {
        return;
    }
    class_destroy(g_chrdev_class);
    unregister_chrdev(major, name);
}

static int __init hailo_pcie_module_init(void)
{
    int err;

    pr_notice(DRIVER_NAME ": Init module. driver version %s\n", HAILO_DRV_VER);

    if ( 0 > (char_major = hailo_pcie_register_chrdev(0, DRIVER_NAME)) )
    {
        pr_err(DRIVER_NAME ": Init Error, failed to call register_chrdev.\n");

        return char_major;
    }

    if ( 0 != (err = pci_register_driver(&hailo_pci_driver)))
    {
        pr_err(DRIVER_NAME ": Init Error, failed to call pci_register_driver.\n");
        hailo_pcie_unregister_chrdev(char_major, DRIVER_NAME);
        return err;
    }

    return 0;
}

static void __exit hailo_pcie_module_exit(void)
{

    pr_notice(DRIVER_NAME ": Exit module.\n");

    // Unregister the driver from pci bus
    pci_unregister_driver(&hailo_pci_driver);
    hailo_pcie_unregister_chrdev(char_major, DRIVER_NAME);

    pr_notice(DRIVER_NAME ": Hailo PCIe driver unloaded.\n");
}


module_init(hailo_pcie_module_init);
module_exit(hailo_pcie_module_exit);

module_param(o_dbg, int, S_IRUGO | S_IWUSR);

module_param_named(no_power_mode, g_is_power_mode_enabled, invbool, S_IRUGO);
MODULE_PARM_DESC(no_power_mode, "Disables automatic D0->D3 PCIe transactions");

module_param(force_desc_page_size, int, S_IRUGO);
MODULE_PARM_DESC(force_desc_page_size, "Determines the maximum DMA descriptor page size (must be a power of 2)");

module_param(force_hailo10h_legacy_mode, bool, S_IRUGO);
MODULE_PARM_DESC(force_hailo10h_legacy_mode, "Forces work with Hailo10h in legacy mode(relevant for emulators)");

module_param(support_soft_reset, bool, S_IRUGO);
MODULE_PARM_DESC(support_soft_reset, "enables driver reload to reload a new firmware as well");

MODULE_AUTHOR("Hailo Technologies Ltd.");
MODULE_DESCRIPTION("Hailo PCIe driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(HAILO_DRV_VER);
