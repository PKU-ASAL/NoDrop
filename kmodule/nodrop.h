#ifndef NODROP_H_
#define NODROP

#include <linux/ptrace.h>
#include <linux/elf.h>

#include "common.h"
#include "events.h"
#include "procinfo.h"

#define vpr_log(xxx, fmt, ...) pr_##xxx("(%d)%s[%d][%s:%d]: " fmt, smp_processor_id(), current->comm, current->pid, __func__, __LINE__, ##__VA_ARGS__)
#define vpr_err(fmt, ...) vpr_log(err, fmt, ##__VA_ARGS__)
#define vpr_info(fmt, ...) vpr_log(info, fmt, ##__VA_ARGS__)
#define vpr_warn(fmt, ...) vpr_log(warn, fmt, ##__VA_ARGS__)
#define vpr_dbg(fmt, ...)
// #define vpr_dbg(fmt, ...) vpr_log(info, fmt, ##__VA_ARGS__)

#define NOD_TEST(task) if (!(STR_EQU((task)->comm, "a.out") || STR_EQU((task)->comm, "helloworld")))
// #define NOD_TEST(task) if (!(STR_EQU((task)->comm, "nginx") || STR_EQU((task)->comm, "httpd") || STR_EQU((task)->comm, "redis-server") || STR_EQU((task)->comm, "postmark") || STR_EQU((task)->comm, "openssl") || STR_EQU((task)->comm, "7z")))
#define STR_EQU(s1, s2) (strcmp(s1, s2) == 0)
#define ASSERT(expr) BUG_ON(!(expr))
#define MONITOR_PATH "./monitor/monitor"

#define NOD_SUCCESS 0
#define NOD_SUCCESS_LOAD 1
#define NOD_FAILURE_BUG -1
#define NOD_FAILURE_BUFFER_FULL -2
#define NOD_FAILURE_INVALID_EVENT -3
#define NOD_FAILURE_INVALID_USER_MEMORY -4
#define NOD_EVENT_FROM_MONITOR 1
#define NOD_EVENT_FROM_APPLICATION 2

#define NOD_INIT_INFO  (1 << 1)
#define NOD_INIT_COUNT (1 << 2)
#define NOD_INIT_LOCK  (1 << 3)

#ifdef CONFIG_X86_64
#define FSBASE fsbase
#define GSBASE gsbase
#else
#define FSBASE fs
#define GSBASE gs
#endif

#define MIN(a, b)   ((a) < (b) ? (a) : (b))
#define MAX(a, b)   ((a) < (b) ? (b) : (a))

typedef unsigned long syscall_arg_t;

// exittrace.c
int trace_register_init(void);
void trace_register_destory(void);

// proc.c
int  proc_init(void);
void proc_destroy(void);

// privil.c
unsigned int nod_get_seccomp(void);
void nod_prepare_context(struct nod_proc_info *p, struct pt_regs *regs);
void nod_prepare_security(struct nod_proc_info *p);
void nod_restore_context(struct nod_proc_info *p, struct pt_regs *regs);
void nod_restore_security(struct nod_proc_info *p);

// trace.c
int trace_syscall(void);
void untrace_syscall(void);
int  tracepoint_init(void);
void tracepoint_destory(void);

// procinfo.c
int procinfo_init(void);
void procinfo_destroy(void);
struct nod_proc_info * 
nod_proc_acquire(enum nod_proc_status status, enum nod_proc_status *pre, 
				int ioctl_fd, struct task_struct *task);
enum nod_proc_status nod_proc_release(struct task_struct *task);
void nod_init_procinfo(struct task_struct *task, struct nod_proc_info *p);
int nod_copy_procinfo(struct task_struct *task, struct nod_proc_info *p);
int nod_share_procinfo(struct task_struct *task, struct nod_proc_info *p);
int nod_event_from(struct nod_proc_info **p);
int nod_proc_check_mm(struct nod_proc_info *p, unsigned long addr, unsigned long length);
unsigned long nod_proc_traverse(int (*func)(struct nod_proc_info *, unsigned long *, va_list), ...);

// loader.c
int loader_init(void);
void loader_destory(void);
int nod_load_monitor(struct nod_proc_info *p);
int nod_mmap_check(unsigned long addr, unsigned long length);

// event.c
#define SECOND_IN_NS 1000000000 // 1s = 1e9ns
#define NS_TO_SEC(_ns) ((_ns) / SECOND_IN_NS)

nanoseconds nod_nsecs(void);
int record_one_event(struct nod_proc_info *p, enum nod_event_type type, struct nod_event_data *event_datap);
int init_buffer(struct nod_buffer *buffer);
void free_buffer(struct nod_buffer *buffer);
void reset_buffer(struct nod_buffer *buffer, int flags);

// elf.c
#define BAD_ADDR(x) ((unsigned long)(x) >= TASK_SIZE)

int elf_load_phdrs(struct elfhdr *elf_ex, struct file *elf_file, struct elf_phdr **elf_phdrs);
int elf_load_shdrs(struct elfhdr *elf_ex, struct file *elf_file, struct elf_shdr **elf_shdrs);
int elf_load_shstrtab(struct elfhdr *elf_ex, struct elf_shdr *elf_shdrs, struct file *elf_file, char **elf_shstrtab);
unsigned long elf_load_binary(struct elfhdr *elf_ex, struct file *binary, uint64_t *map_addr, unsigned long no_base, struct elf_phdr *elf_phdrs);
void elf_reg_init(struct thread_struct *t, struct pt_regs *regs, const u16 ds);

/*
 * fillers.c
 *
 * These are analogous to get_user(), copy_from_user() and strncpy_from_user(),
 * but they can't sleep, barf on page fault or be preempted
 */
#define nod_get_user(x, ptr) (nod_copy_from_user(&x, ptr, sizeof(x)) ? -EFAULT : 0)
unsigned long nod_copy_from_user(void *to, const void __user *from, unsigned long n);
long nod_strncpy_from_user(char *to, const char __user *from, unsigned long n);
int nod_filler_callback(struct event_filler_arguments *args);

// syscall_table.c
#define SYSCALL_TABLE_ID0 0
struct syscall_evt_pair {
	int flags;
	enum nod_event_type event_type;
} _packed;
extern const struct syscall_evt_pair g_syscall_event_table[];


// filler_table.c
extern const struct nod_event_entry g_nod_events[];

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

#endif // NODROP_H_

static void __attribute__((unused))
memory_dump(char *p, size_t size)
{
    unsigned int j;
	pr_info("memory dump at 0x%lx (%ld)\n", (unsigned long)p, size);
    for (j = 0; j < size; j += 8)
        pr_info("%*ph\n", 8, &p[j]);
}
