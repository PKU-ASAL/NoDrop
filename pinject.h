#ifndef PINJECT_H_
#define PINJECT_H_

#include <linux/ptrace.h>

#define MONITOR_FILE "monitor/hello"
#define MONITOR_PATH "/mnt/hgfs/Projects/process_inject/"MONITOR_FILE
// #define MONITOR_PATH "hello"


// kprobe.c
int  kprobe_init(void);
void kprobe_destroy(void);

// hook.c
typedef long (*sys_call_ptr_t)(const struct pt_regs *);
int  hook_init(void);
void hook_destory(void);

// loader.c
int check_mapping(const char *filename, 
                  int (*resolve) (struct vm_area_struct const * const vma, void *arg),
                  void *arg);
int do_load_monitor(const struct pt_regs *reg, 
                      unsigned long *target_entry, 
                      unsigned long *target_sp, 
                      unsigned long *event_id);
int  loader_init(void);
void loader_destory(void);

#endif // PINJECT_H_