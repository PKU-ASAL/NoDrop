#ifndef PINJECT_H_
#define PINJECT_H_

#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/ptrace.h>

#define MONITOR_PATH "/mnt/hgfs/Projects/pinject_dpdk/monitor/monitor"
// #define MONITOR_PATH "/monitor"


// proc.c
int  proc_init(void);
void proc_destroy(void);

// hook.c
void hook_syscall(void);
void restore_syscall(void);
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
                      unsigned long *target_sp);
void adjust_retval(long retval); // adjust syscall return value
int  loader_init(void);
void loader_destory(void);

#endif // PINJECT_H_
