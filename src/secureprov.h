#ifndef SECUREPROV_H_
#define SECUREPROV_H_

#include <linux/ptrace.h>
#include <linux/elf.h>

#include "common.h"
#include "events.h"

#define vpr_dbg(fmt, ...)
// #define vpr_dbg(fmt, ...) vpr_log(info, fmt, ##__VA_ARGS__)

#define vpr_err(fmt, ...) vpr_log(err, fmt, ##__VA_ARGS__)
#define vpr_info(fmt, ...) vpr_log(info, fmt, ##__VA_ARGS__)

#define vpr_log(xxx, fmt, ...) pr_##xxx("(%d)%s[%d][%s:%d]: " fmt, smp_processor_id(), current->comm, current->pid, __func__, __LINE__, ##__VA_ARGS__)

#define SPR_TEST(task) if (!(STR_EQU((task)->comm, "a.out")))
// #define SPR_TEST(task) if (!(STR_EQU((task)->comm, "nginx") || STR_EQU((task)->comm, "httpd") || STR_EQU((task)->comm, "redis-server") || STR_EQU((task)->comm, "postmark") || STR_EQU((task)->comm, "openssl") || STR_EQU((task)->comm, "7z")))
#define STR_EQU(s1, s2) (strcmp(s1, s2) == 0)
#define ASSERT(expr) BUG_ON(!(expr))
#define MONITOR_PATH "./monitor/monitor"

#define SPR_SUCCESS 0
#define SPR_SUCCESS_LOAD 1
#define SPR_FAILURE_BUG -1
#define SPR_FAILURE_BUFFER_FULL -2
#define SPR_FAILURE_INVALID_EVENT -3
#define SPR_FAILURE_INVALID_USER_MEMORY -4
#define SPR_EVENT_FROM_MONITOR 1
#define SPR_EVENT_FROM_APPLICATION 2

#define SPR_INIT_INFO  (1 << 1)
#define SPR_INIT_COUNT (1 << 2)
#define SPR_INIT_LOCK  (1 << 3)

typedef unsigned long syscall_arg_t;

// proc.c
int  proc_init(void);
void proc_destroy(void);

// privil.c
unsigned int spr_get_seccomp(void);
void spr_disable_seccomp(void);
int spr_enable_seccomp(unsigned int mode);
void spr_write_gsbase(unsigned long gsbase);
void spr_write_fsbase(unsigned long fsbase);
void spr_cap_raise(void);
void spr_cap_capset(u32 *permitted, u32 *effective);
void spr_prepare_security(void);
int prepare_root_path(char *path);
void prepare_rlimit_data(struct rlimit *rlims);
void prepare_security_data(struct security_data *security);

// hook.c
int hook_syscall(void);
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

nanoseconds spr_nsecs(void);
int event_buffer_init(void);
void event_buffer_destory(void);
int record_one_event(enum spr_event_type type, struct spr_event_data *event_datap);
int init_buffer(struct spr_kbuffer *buffer);
void free_buffer(struct spr_kbuffer *buffer);
void reset_buffer(struct spr_kbuffer *buffer, int flags);

// elf.c
#define BAD_ADDR(x) ((unsigned long)(x) >= TASK_SIZE)

int elf_load_phdrs(struct elfhdr *elf_ex, struct file *elf_file, struct elf_phdr **elf_phdrs);
unsigned long elf_load_binary(struct elfhdr *elf_ex, struct file *binary, uint64_t *map_addr, unsigned long no_base, struct elf_phdr *elf_phdrs);
void elf_reg_init(struct thread_struct *t, struct pt_regs *regs, const u16 ds);

/*
 * fillers.c
 *
 * These are analogous to get_user(), copy_from_user() and strncpy_from_user(),
 * but they can't sleep, barf on page fault or be preempted
 */
#define spr_get_user(x, ptr) (spr_copy_from_user(&x, ptr, sizeof(x)) ? -EFAULT : 0)
unsigned long spr_copy_from_user(void *to, const void __user *from, unsigned long n);
long spr_strncpy_from_user(char *to, const char __user *from, unsigned long n);

// syscall_table.c
#define SYSCALL_TABLE_ID0 0
extern const enum spr_event_type g_syscall_event_table[];

// filler_table.c
extern const struct spr_event_entry g_spr_events[];



// kernel_hacks
#include <linux/version.h>

/* probe_kernel_read() only added in kernel 2.6.26, name changed in 5.8.0 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static inline long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
{
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	pagefault_disable();
	ret = __copy_from_user_inatomic(dst, (__force const void __user *)src, size);
	pagefault_enable();
	set_fs(old_fs);

	return ret ? -EFAULT : 0;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define copy_from_kernel_nofault probe_kernel_read
#endif


/*
 * Linux 5.6 kernels no longer include the old 32-bit timeval
 * structures. But the syscalls (might) still use them.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#include <linux/time64.h>
struct compat_timespec {
	int32_t tv_sec;
	int32_t tv_nsec;
};

struct timespec {
	int32_t tv_sec;
	int32_t tv_nsec;
};

struct timeval {
	int32_t tv_sec;
	int32_t tv_usec;
};
#else
#define timeval64 timeval
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
static inline struct inode *file_inode(struct file *f)
{
	return f->f_path.dentry->d_inode;
}
#endif

/*
 * Linux 5.1 kernels modify the syscall_get_arguments function to always
 * return all arguments rather than allowing the caller to select which
 * arguments are desired. This wrapper replicates the original
 * functionality.
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0))
#define syscall_get_arguments_deprecated syscall_get_arguments
#else
#define syscall_get_arguments_deprecated(_task, _reg, _start, _len, _args) \
	do { \
	    unsigned long _sga_args[6] = {}; \
	    syscall_get_arguments(_task, _reg, _sga_args); \
	    memcpy(_args, &_sga_args[_start], _len * sizeof(unsigned long)); \
	} while(0)
#endif

#endif // SECUREPROV_H_
