#ifndef PINJECT_H_
#define PINJECT_H_

#include <linux/ptrace.h>

#define COLLECTOR_FILE "hello/hello"
#define COLLECTOR_PATH "/home/jeshrz/process_inject/"COLLECTOR_FILE

// kprobe.c
int  kprobe_init(void);
void kprobe_destroy(void);

// hock.c
int  hock_init(void);
void hock_destory(void);

// loader.c
int check_mapping(const char *filename, 
                  int (*resolve) (struct vm_area_struct const * const vma, void *arg),
                  void *arg);
int do_load_collector(const struct pt_regs *reg, 
                      unsigned long *target_entry, 
                      unsigned long *target_sp, 
                      char *argv[]);

#endif // PINJECT_H_