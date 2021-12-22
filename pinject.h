#ifndef PINJECT_H_
#define PINJECT_H_

#define __KERNEL__

#include <linux/ptrace.h>

#define MONITOR_FILE "monitor/hello"
#define MONITOR_PATH "/mnt/hgfs/Projects/process_inject/"MONITOR_FILE

// kprobe.c
int  kprobe_init(void);
void kprobe_destroy(void);

// hook.c
typedef long (*sys_call_ptr_t)(const struct pt_regs *);
int  hook_init(void);
void hook_destory(void);

// loader.c
#define LOAD_SUCCESS        0
#define LOAD_FAILED         1
#define LOAD_NO_SYSCALL     2 // DO NOT do syscall, goto monitor directly!
#define LOAD_FROM_MONITOR   3


int check_mapping(int (*resolve) (struct vm_area_struct const * const vma, void *arg),
                  void *arg);
int do_load_monitor(const struct pt_regs *reg, 
                      unsigned long *target_entry, 
                      unsigned long *target_sp, 
                      unsigned long *event_id);
int  loader_init(void);
void loader_destory(void);

#endif // PINJECT_H_