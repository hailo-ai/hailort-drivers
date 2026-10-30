#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
typedef uint32_t u32;
#define FIRST_STAGE 0
#define hailo_dev_err(...) ((void)0)
#define hailo_dev_notice(...) ((void)0)
#define hailo_dev_warn(...) ((void)0)
struct device { int unused; };
struct pci_dev { struct device dev; };
struct completion { int done; };
struct hailo_pcie_resources { int board_type; };
struct hailo_pcie_board { struct pci_dev *pDev;struct hailo_pcie_resources pcie_resources;struct {struct completion fw_loaded_completion;}fw_boot; };
static int present, support_soft_reset, reset_code, batch_code, ack, resets, batches, waits, inits;
static bool hailo_pcie_is_firmware_loaded(struct hailo_pcie_resources *r){(void)r;return present;}
static int hailo_pcie_soft_reset(struct hailo_pcie_board *b){(void)b;resets++;return reset_code;}
static void init_completion(struct completion *c){c->done=0;inits++;}
static int hailo_pcie_write_firmware_batch(struct device *d,struct hailo_pcie_resources *r,int s){(void)d;(void)r;(void)s;batches++;return batch_code;}
static bool wait_for_firmware_completion(struct completion *c,unsigned int ms){(void)c;(void)ms;waits++;return ack;}
struct stage {unsigned int timeout;};static struct stage stage_info={5000};
static struct stage *hailo_pcie_get_loading_stage_info(int b,int s){(void)b;(void)s;return &stage_info;}
static u32 hailo_get_boot_status(struct hailo_pcie_resources *r){(void)r;return 1;}
#include "selected.inc"
int main(int argc,char **argv){assert(argc==6);reset_code=atoi(argv[1]);present=atoi(argv[2]);support_soft_reset=atoi(argv[3]);batch_code=atoi(argv[4]);ack=atoi(argv[5]);struct pci_dev dev={0};struct hailo_pcie_board board={.pDev=&dev};int result=load_nnc_firmware(&board);printf("%d %d %d %d %d\n",result,resets,batches,waits,inits);return 0;}
