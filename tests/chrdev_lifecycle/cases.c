static struct hailo_pcie_board *safe_lookup(u32 i){if(setjmp(escaped)){return NULL;}return hailo_pcie_get_board_index(i);}
static long safe_insert(unsigned int i){if(setjmp(escaped)){return LONG_MIN;}return hailo_pcie_insert_board(&boards[i]);}
static int pci_register_driver(void *d){assert(d==&pci_driver_token);pci_reg_calls++;if(pci_error&&!post_probe_error)return pci_error;if(hook)(void)safe_insert(0);if(pci_error){if(!list_empty(&g_hailo_board_list))hailo_pcie_remove_board(&boards[0]);return pci_error;}return 0;}
static void pci_unregister_driver(void *d){assert(d==&pci_driver_token);pci_unreg_calls++;if(hook&&!list_empty(&g_hailo_board_list))hailo_pcie_remove_board(&boards[0]);}
static void seed(unsigned int n,u32 index){boards[n].board_index=index;list_add(&boards[n].board_list,g_hailo_board_list.prev);}
int main(int argc,char **argv){
 assert(argc==2);const char *test=argv[1];long ret=0,first=0;bool held=false;int lookup_found=0;
#define IS(s) (!strcmp(test,s))
 if(IS("class-fail")||IS("failure-unwind")||IS("retry-success")||IS("retry-fail")){major_owned=240;class_error=-ENOMEM;first=safe_insert(0);ret=first;
  if(IS("failure-unwind"))hailo_pcie_unregister_chrdev(240,DRIVER_NAME);
  if(IS("retry-success")){class_error=0;ret=safe_insert(1);}
  if(IS("retry-fail"))ret=safe_insert(1);
 }else if(IS("class-fail-einval")){class_error=-EINVAL;ret=safe_insert(0);
 }else if(IS("new-class-empty")){ret=safe_insert(0);
 }else if(IS("existing-empty")){g_chrdev_class=&cls;cls.alive=1;ret=safe_insert(0);
 }else if(IS("existing-first-gap")){g_chrdev_class=&cls;cls.alive=1;seed(0,2);ret=safe_insert(1);
 }else if(IS("existing-middle-gap")){g_chrdev_class=&cls;cls.alive=1;seed(0,0);seed(1,2);ret=safe_insert(2);
 }else if(IS("existing-tail")){g_chrdev_class=&cls;cls.alive=1;seed(0,0);seed(1,1);ret=safe_insert(2);
 }else if(IS("remove-null")){hailo_pcie_remove_board(NULL);
 }else if(IS("insert-remove")){ret=safe_insert(0);if(ret==0)hailo_pcie_remove_board(&boards[0]);
 }else if(IS("unregister-no-class")){major_owned=240;hailo_pcie_unregister_chrdev(240,DRIVER_NAME);
 }else if(IS("unregister-class")){major_owned=240;g_chrdev_class=&cls;cls.alive=1;hailo_pcie_unregister_chrdev(240,DRIVER_NAME);
 }else if(IS("module-register-fail")){register_error=-EBUSY;ret=hailo_pcie_module_init();
 }else if(IS("module-pci-fail")){pci_error=-EIO;ret=hailo_pcie_module_init();
 }else if(IS("module-no-boards")){ret=hailo_pcie_module_init();if(ret==0)hailo_pcie_module_exit();
 }else if(IS("module-with-board")){hook=1;ret=hailo_pcie_module_init();if(ret==0)hailo_pcie_module_exit();
 }else if(IS("module-probe-fail")){hook=1;class_error=-ENOMEM;ret=hailo_pcie_module_init();held=g_hailo_add_board_mutex.value==0;
  /* A leaked lock would block real unregister/remove. Do not simulate a safe teardown past it. */
  if(ret==0&&!held)hailo_pcie_module_exit();
 }else if(IS("two-normal-cycles")){hook=1;ret=hailo_pcie_module_init();if(ret==0)hailo_pcie_module_exit();if(!g_chrdev_class&&major_owned==0){ret=hailo_pcie_module_init();if(ret==0)hailo_pcie_module_exit();}
 }else if(IS("module-pci-fail-after-probe")){hook=1;pci_error=-EIO;post_probe_error=1;ret=hailo_pcie_module_init();
 }else if(IS("module-pci-fail-after-class-error")){hook=1;pci_error=-EIO;class_error=-ENOMEM;post_probe_error=1;ret=hailo_pcie_module_init();
 }else if(IS("probe-unwind-then-insert")){ret=safe_insert(0);if(ret==0){hailo_pcie_remove_board(&boards[0]);ret=safe_insert(1);}
 }else if(IS("lookup-empty")){lookup_found=safe_lookup(7)!=NULL;
 }else if(IS("lookup-found")){seed(0,3);lookup_found=safe_lookup(3)==&boards[0];
 }else if(IS("lookup-no-match")){seed(0,3);lookup_found=safe_lookup(7)!=NULL;
 }else if(IS("lookup-after-failure")){class_error=-ENOMEM;first=safe_insert(0);lookup_found=safe_lookup(7)!=NULL;
 }else{fprintf(stderr,"unknown case\n");return 2;}
 unsigned int count=0,indices[5]={0};struct list_head *it;
 for(it=g_hailo_board_list.next;it!=&g_hailo_board_list;it=it->next){assert(count<5);indices[count++]=list_entry(it,struct hailo_pcie_board,board_list)->board_index;}
 printf("{\"ignored_class_destroy\":%d,\"lookup_found\":%d,\"refs0\":%d,\"ret\":%ld,\"first\":%ld,\"sem\":%d,\"down\":%d,\"up\":%d,\"blocked\":%d,\"bad_unlock\":%d,\"class_null\":%d,\"class_error\":%d,\"class_calls\":%d,\"destroy\":%d,\"bad_destroy\":%d,\"register\":%d,\"unregister\":%d,\"bad_unregister\":%d,\"major_owned\":%d,\"pci_register\":%d,\"pci_unregister\":%d,\"boards\":%u,\"indices\":[%u,%u,%u],\"initial_leaked_lock\":%d}\n",ignored_class_destroy,lookup_found,boards[0].ref_count,ret,first,g_hailo_add_board_mutex.value,down_calls,up_calls,blocked,bad_unlock,g_chrdev_class==NULL,IS_ERR(g_chrdev_class),class_calls,destroy_calls,bad_destroy,reg_calls,unreg_calls,bad_unregister,major_owned,pci_reg_calls,pci_unreg_calls,count,indices[0],indices[1],indices[2],held);return 0;
}
