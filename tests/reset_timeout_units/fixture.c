#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#define hailo_warn(...) ((void)0)
#define hailo_notice(...) ((void)0)
struct completion {int done;};struct hailo_pcie_resources {int unused;};
struct hailo_pcie_board {struct hailo_pcie_resources pcie_resources;struct {struct completion reset_completed;}soft_reset;};
static unsigned int conversions;static unsigned long waited;
static unsigned long msecs_to_jiffies(unsigned int ms){conversions++;return ((uint64_t)ms*HZ+999)/1000;}
static unsigned long wait_for_completion_timeout(struct completion *c,unsigned long ticks){(void)c;waited=ticks;return 1;}
static void reinit_completion(struct completion *c){c->done=0;}
static void hailo_pcie_write_firmware_soft_reset(struct hailo_pcie_resources *r){(void)r;}
static bool hailo_pcie_wait_for_boot(struct hailo_pcie_resources *r){(void)r;return true;}
#include "wait.inc"
#include "selected.inc"
int main(void){struct hailo_pcie_board board={0};int result=hailo_pcie_soft_reset(&board);printf("%d %u %lu\n",result,conversions,waited);return 0;}
