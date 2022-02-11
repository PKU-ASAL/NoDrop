#ifndef PINJECT_H_
#define PINJECT_H_

#include <linux/ptrace.h>

#define ASSERT(expr) BUG_ON(!(expr))
#define MONITOR_PATH "/mnt/hgfs/Projects/pinject_dpdk/monitor/monitor"

#define SPR_SUCCESS 0
#define SPR_FAILURE_BUG -1
#define SPR_FAILURE_BUFFER_FULL -2
#define SPR_FAILURE_INVALID_EVENT -3
#define SPR_EVENT_FROM_MONITOR 1
#define SPR_EVENT_FROM_APPLICATION 2

typedef unsigned long syscall_arg_t;

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

DECLARE_PER_CPU(struct spr_kbuffer, buffer);

int loader_init(void);
void loader_destory(void);
int check_mapping(int (*resolve) (struct vm_area_struct const * const vma, void *arg),
                  void *arg);
int load_monitor(const struct spr_kbuffer *buffer);
int event_from_monitor(void);



// event.c
#define NS_TO_SEC(_ns) ((_ns) / 1000000000)
#define SECOND_IN_NS 1000000000 // 1s = 1e9ns

int event_buffer_init(void);
void event_buffer_destory(void);
int record_one_event(enum spr_event_type type, struct spr_event_data *event_datap);
void spr_init_buffer_info(struct spr_buffer_info *info);

// fillers.c

// syscall_table.c
#define SYSCALL_TABLE_ID0 0
extern const enum spr_event_type g_syscall_event_table[];

// filler_table.c
extern const struct spr_event_entry g_spr_events[];

// flags_table.c
extern const struct ppm_name_value socket_families[];
extern const struct ppm_name_value file_flags[];
extern const struct ppm_name_value flock_flags[];
extern const struct ppm_name_value clone_flags[];
extern const struct ppm_name_value futex_operations[];
extern const struct ppm_name_value lseek_whence[];
extern const struct ppm_name_value poll_flags[];
extern const struct ppm_name_value mount_flags[];
extern const struct ppm_name_value umount_flags[];
extern const struct ppm_name_value shutdown_how[];
extern const struct ppm_name_value rlimit_resources[];
extern const struct ppm_name_value fcntl_commands[];
extern const struct ppm_name_value sockopt_levels[];
extern const struct ppm_name_value sockopt_options[];
extern const struct ppm_name_value ptrace_requests[];
extern const struct ppm_name_value prot_flags[];
extern const struct ppm_name_value mmap_flags[];
extern const struct ppm_name_value splice_flags[];
extern const struct ppm_name_value quotactl_cmds[];
extern const struct ppm_name_value quotactl_types[];
extern const struct ppm_name_value quotactl_dqi_flags[];
extern const struct ppm_name_value quotactl_quota_fmts[];
extern const struct ppm_name_value semop_flags[];
extern const struct ppm_name_value semget_flags[];
extern const struct ppm_name_value semctl_commands[];
extern const struct ppm_name_value access_flags[];
extern const struct ppm_name_value pf_flags[];
extern const struct ppm_name_value unlinkat_flags[];
extern const struct ppm_name_value linkat_flags[];
extern const struct ppm_name_value chmod_mode[];
extern const struct ppm_name_value renameat2_flags[];

extern const struct ppm_param_info sockopt_dynamic_param[];
extern const struct ppm_param_info ptrace_dynamic_param[];
extern const struct ppm_param_info bpf_dynamic_param[];


#endif // PINJECT_H_
