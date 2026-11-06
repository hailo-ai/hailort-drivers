/* Userspace lifecycle regression fixture; never calls the kernel or hardware. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;
#define __init
#define __exit
#define DRIVER_NAME "hailo_pci"
#define HAILO_DRV_VER "4.24.0"
#define pr_notice(...) ((void)0)
#define pr_err(...) ((void)0)
#define hailo_err(...) ((void)0)
#define ERR_PTR(v) ((void *)(intptr_t)(v))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
struct class {int alive;};
struct list_head {struct list_head *next,*prev;};
struct semaphore {int value;};
struct hailo_pcie_board {struct list_head board_list;u32 board_index;int ref_count;};
static void atomic_inc(int *p){(*p)++;}
#define container_of(ptr,type,member) ((type *)((char *)(ptr)-offsetof(type,member)))
#define list_entry(ptr,type,member) container_of(ptr,type,member)
#define list_first_entry(head,type,member) list_entry((head)->next,type,member)
#define list_next_entry(pos,member) list_entry((pos)->member.next,__typeof__(*(pos)),member)
#define list_for_each_entry_safe(pos,n,head,member) \
 for(pos=list_first_entry(head,__typeof__(*pos),member),n=list_next_entry(pos,member);&(pos)->member!=(head);pos=n,n=list_next_entry(n,member))
#define list_for_each_entry(pos,head,member) for(pos=list_first_entry(head,__typeof__(*pos),member);&(pos)->member!=(head);pos=list_next_entry(pos,member))
static bool list_empty(struct list_head *h){return h->next==h;}
static bool list_is_last(struct list_head *n,struct list_head *h){return n->next==h;}
static void list_add(struct list_head *n,struct list_head *h){n->next=h->next;n->prev=h;h->next->prev=n;h->next=n;}
static void list_del(struct list_head *n){n->prev->next=n->next;n->next->prev=n->prev;}
static struct list_head g_hailo_board_list={&g_hailo_board_list,&g_hailo_board_list};
static struct semaphore g_hailo_add_board_mutex={1};
static struct class *g_chrdev_class;
static struct class cls;
static struct hailo_pcie_board boards[5];
static int char_major,pci_driver_token,fops_token;
#define hailo_pci_driver pci_driver_token
#define hailo_pcie_fops fops_token
static int down_calls,up_calls,blocked,bad_unlock,class_calls,destroy_calls,bad_destroy;
static int reg_calls,unreg_calls,bad_unregister,pci_reg_calls,pci_unreg_calls;
static int ignored_class_destroy,post_probe_error;
static int class_error,register_error,pci_error,major_owned,hook;
static jmp_buf escaped;
static void down(struct semaphore *s){down_calls++;if(s->value==0){blocked++;longjmp(escaped,1);}assert(s->value==1);s->value--;}
static void up(struct semaphore *s){up_calls++;if(s->value!=0)bad_unlock++;s->value++;}
static struct class *class_create_compat(const char *name){assert(!strcmp(name,"hailo_chardev"));class_calls++;if(class_error)return ERR_PTR(class_error);cls.alive=1;return &cls;}
static void class_destroy(struct class *c){destroy_calls++;if(c==NULL||IS_ERR(c)){ignored_class_destroy++;return;}if(c!=&cls||!cls.alive){bad_destroy++;return;}cls.alive=0;}
static int register_chrdev(unsigned int major,const char *name,void *fops){assert(major==0&&fops==&fops_token&&!strcmp(name,DRIVER_NAME));reg_calls++;if(register_error)return register_error;assert(!major_owned);major_owned=240;return major_owned;}
static void unregister_chrdev(unsigned int major,const char *name){assert(!strcmp(name,DRIVER_NAME));unreg_calls++;if((int)major!=major_owned||major_owned==0)bad_unregister++;major_owned=0;}
static int pci_register_driver(void *d);
static void pci_unregister_driver(void *d);
