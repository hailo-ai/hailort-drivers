/* Source-subset regression only; no device, MMIO, driver or kernel execution. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define hailo_dbg(...) ((void)0)
#define hailo_warn(...) ((void)0)
#define hailo_notice(...) ((void)0)
#define FIRMWARE_WAIT_TIMEOUT_MS 5000
#define HZ 250
#define HAILO_PCIE_BOOT_SOFT_RESET_IRQ 0x1
#define HAILO_PCIE_BOOT_IRQ 0x2

struct completion { unsigned int done; };
struct hailo_pcie_resources { int unused; };
struct hailo_pcie_interrupt_source { unsigned int sw_interrupts, vdma_channels_bitmap; };
struct hailo_pcie_board {
    struct hailo_pcie_resources pcie_resources;
    struct { struct completion reset_completed; } soft_reset;
    struct {
        struct completion fw_loaded_completion, vdma_boot_completion;
        unsigned int boot_used_channel_bitmap;
    } fw_boot;
};

static struct hailo_pcie_board *active;
static int timing, boot_ok;
static unsigned int requests, waits, boot_polls, rearms, conversions;
static unsigned long ticks;
static void boot_irq_handler(struct hailo_pcie_board *, struct hailo_pcie_interrupt_source *);
static void complete(struct completion *c) { ++c->done; }
static void complete_all(struct completion *c) { c->done = UINT32_MAX; }
static void reinit_completion(struct completion *c) { c->done = 0; ++rearms; }
static unsigned long msecs_to_jiffies(unsigned int ms)
{
    ++conversions;
    return ((uint64_t)ms * HZ + 999) / 1000;
}
static void acknowledge(void)
{
    struct hailo_pcie_interrupt_source irq = {HAILO_PCIE_BOOT_SOFT_RESET_IRQ, 0};
    boot_irq_handler(active, &irq);
}
static void hailo_pcie_write_firmware_soft_reset(struct hailo_pcie_resources *r)
{
    (void)r;
    ++requests;
    if (timing == 1) acknowledge();
}
static unsigned long wait_for_completion_timeout(struct completion *c, unsigned long timeout)
{
    ++waits;
    ticks = timeout;
    if (timing == 2) acknowledge();
    if (!c->done) return 0;
    --c->done;
    return 1;
}
static bool hailo_pcie_wait_for_boot(struct hailo_pcie_resources *r)
{
    (void)r;
    ++boot_polls;
    return boot_ok;
}

#include "production.inc"

int main(int argc, char **argv)
{
    struct hailo_pcie_board board = {0};
    if (argc != 5) return 2;
    timing = atoi(argv[1]);
    boot_ok = atoi(argv[2]);
    board.soft_reset.reset_completed.done = (unsigned int)atoi(argv[3]);
    unsigned int repeats = (unsigned int)atoi(argv[4]);
    active = &board;
    board.fw_boot.boot_used_channel_bitmap = 1;
    int result = 0;
    for (unsigned int i = 0; i < repeats; ++i) result = hailo_pcie_soft_reset(&board);
    printf("%d %u %u %u %u %u %lu %u\n", result, requests, waits,
        boot_polls, rearms, conversions, ticks, board.soft_reset.reset_completed.done);
    return 0;
}
