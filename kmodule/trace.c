#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/ftrace.h>
#include <linux/module.h>
#endif
#include <asm/unistd.h>
#include <asm/syscall.h>

#include "nodrop.h"
#include "syscall.h"
#include "common.h"
#include "events.h"
#include "procinfo.h"

#ifndef CONFIG_HAVE_SYSCALL_TRACEPOINTS
 #error The kernel must have HAVE_SYSCALL_TRACEPOINTS in order to be useful
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
    #define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2)
    #define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2)
    #define TRACEPOINT_PROBE(probe, args...) static void probe(args)
#else
    #define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2, NULL)
    #define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2, NULL)
    #define TRACEPOINT_PROBE(probe, args...) static void probe(void *__data, args)
#endif

struct nod_syscall_filter {
    int enable;
    int hooked;
    int (*filter)(struct nod_proc_info *, struct pt_regs *);
    sys_call_ptr_t oldsyscall;
};

static int tracepoint_registered;
static sys_call_ptr_t *syscall_table;
static struct nod_syscall_filter syscall_filters[SYSCALL_TABLE_SIZE];
static uint64_t nod_lookup_name(const char *name);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
typedef long (*nod_x64_sys_call_t)(const struct pt_regs *, unsigned int);

static struct ftrace_ops nod_x64_sys_call_ops;
static nod_x64_sys_call_t nod_old_x64_sys_call;
static unsigned long nod_x64_sys_call_addr;
static int nod_x64_sys_call_hooked;
static bool nod_x64_sys_call_stopping;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#define NOD_FTRACE_REGS_TYPE struct ftrace_regs
static inline struct pt_regs *nod_ftrace_get_regs(struct ftrace_regs *fregs)
{
    return ftrace_get_regs(fregs);
}

static inline void nod_ftrace_set_ip(struct ftrace_regs *fregs, unsigned long ip)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
    ftrace_regs_set_instruction_pointer(fregs, ip);
#else
    ftrace_instruction_pointer_set(fregs, ip);
#endif
}
#else
#define NOD_FTRACE_REGS_TYPE struct pt_regs
static inline struct pt_regs *nod_ftrace_get_regs(struct pt_regs *regs)
{
    return regs;
}

static inline void nod_ftrace_set_ip(struct pt_regs *regs, unsigned long ip)
{
    instruction_pointer_set(regs, ip);
}
#endif
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
static struct tracepoint *tp_sys_exit;
#endif
static struct tracepoint *tp_sched_process_exit;

/* compat tracepoint functions */
static int compat_register_trace(void *func, const char *probename, struct tracepoint *tp)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
	return TRACEPOINT_PROBE_REGISTER(probename, func);
#else
	return tracepoint_probe_register(tp, func, NULL);
#endif
}

static void compat_unregister_trace(void *func, const char *probename, struct tracepoint *tp)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
	TRACEPOINT_PROBE_UNREGISTER(probename, func);
#else
	tracepoint_probe_unregister(tp, func, NULL);
#endif
}

// struct nod_count {
//   nanoseconds total;
//   int count;
//   int once;
// };
//
// DEFINE_PER_CPU(struct nod_count, cct);

static int
syscall_probe(struct nod_proc_info *p, struct pt_regs *regs, long id, int force) {
    int retval;
    long table_index;
    enum nod_event_type type;
    struct nod_event_data event_data;
    // nanoseconds start, end;
    // struct nod_count *cnt;
    // start = nod_nsecs();

    table_index = id - SYSCALL_TABLE_ID0;
    if (likely(table_index >= 0 && table_index < SYSCALL_TABLE_SIZE)) {
        type = g_syscall_event_table[table_index].event_type;

        event_data.category = NODC_SYSCALL;
        event_data.event_info.syscall_data.regs = regs;
        event_data.event_info.syscall_data.id = id;

        event_data.force = force;
        
        retval = record_one_event(p, type, &event_data);
    } else {
        retval = NOD_FAILURE_INVALID_EVENT;
    }

    // end = nod_nsecs();
    // cnt = &get_cpu_var(cct);
    // if (cnt->count < 10000) {
    //   cnt->total += end - start;
    //   cnt->count++;
    // } else {
    //   if (!cnt->once) {
    //     pr_info("%lld %d\n", cnt->total, cnt->count);
    //     cnt->once = 1;
    //   }
    // }
    // put_cpu_var(cct);
    return retval;
}

TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret)
{
    int evt_from, id, retval;
    struct nod_proc_info *p;
    // nanoseconds start, end;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
    if (unlikely(current->flags & PF_KTHREAD))
#else
    if (unlikely(current->flags & PF_BORROWED_MM))
#endif
    {
        // We are not interested in kernel threads
        return;
    }

#ifdef NOD_TEST
    NOD_TEST(current) {
        return;
    }
#endif

    /* 
     * Since some syscalls are not supported yet, those syscalls will be filtered here.
     * These codes will be removed in the release version.
     */ 
    id = syscall_get_nr(current, regs);

    evt_from = nod_event_from(&p);
    switch(evt_from) {
    case NOD_RESTORE_CONTEXT:
        // start = nod_nsecs();
        nod_restore_security(p);
        nod_restore_context(p, regs);
        // end = nod_nsecs();
        // pr_info("post %llu\n", end - start);
        nod_proc_set_out(p);

        break;

    case NOD_RESTORE_SECURITY:
        // start = nod_nsecs();
        nod_restore_security(p);
        // end = nod_nsecs();
        // pr_info("post %llu\n", end - start);

        break;

    case NOD_OUT:
    case NOD_CLONE:
    case NOD_SHARE:
        if (id == __NR_clone && ret == 0) {
            // forked child process
            unsigned long clone_flags;
            syscall_get_arguments_deprecated(current, regs, 1, 1, &clone_flags);
            if (clone_flags & CLONE_VM) {
                if (!nod_proc_acquire(NOD_SHARE, NULL, -1, current))
                    vpr_err("acquire NOD_SHARE for childed process failed\n");
            } else {
                /* 
                 * If the child process has its own address space,
                 * he should inherit parent's procinfo, including buffer, load address and pkey.
                 * We mark it here and do it lazily.
                 */
                if (!nod_proc_acquire(NOD_CLONE, NULL, -1, current))
                    vpr_err("acquire NOD_CLONE for childed process failed\n");
            }
        } else {
            if (id == __NR_execve || id == __NR_execveat) {
                /*
                 * In execve(), the address space will be replaced with the new one.
                 * The original instrumented monitor will no longer exist.
                 */
                if (p) {
                    nod_init_procinfo(current, p);
                } else {
                    p = nod_proc_acquire(evt_from, NULL, -1, current);
                    if (!p) break;
                }
            } else if (!p) {
                p = nod_proc_acquire(evt_from, NULL, -1, current);
                if (!p) break;
            }
            retval = syscall_probe(p, regs, id, 0);
        }

        break;

    default:
        break;
    }
}

TRACEPOINT_PROBE(syscall_procexit_probe, struct task_struct *tsk)
{

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    if (unlikely(tsk->flags & PF_KTHREAD))
#else
    if (unlikely(current->flags & PF_KTHREAD))
#endif
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    if (unlikely(tsk->flags & PF_BORROWED_MM))
#else
    if (unlikely(current->flags & PF_BORROWED_MM))
#endif
#endif
    {
        // We are not interested in kernel threads
        return;
    }

#ifdef NOD_TEST
    NOD_TEST(tsk) {
        return;
    }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    if (nod_proc_release(tsk) == NOD_UNKNOWN) {
        vpr_dbg("proc exit without procinfo entry (pid %d comm %s)\n", tsk->pid, tsk->comm);
    }
#else
    nod_proc_release(tsk);
#endif
}

static int
exit_filter(struct nod_proc_info *p, struct pt_regs *regs)
{
    if (!p) {
        p = nod_proc_acquire(NOD_OUT, NULL, -1, current);
        if (!p) return 0;
    }

    switch(p->status) {
    case NOD_OUT:
    case NOD_CLONE:
    case NOD_SHARE:
        if (likely(syscall_probe(p, regs, syscall_get_nr(current, regs), 1) == NOD_SUCCESS_LOAD))
            return -EAGAIN;
        
        break;
    
    case NOD_IN:
        nod_restore_security(p);

        break;

    default:
        BUG();
    }

    return 0;
}

static int
mm_range_filter(struct nod_proc_info *p, struct pt_regs *regs)
{
    unsigned long addr, length;

    if (!p) {
        return 0;
    }

    switch(p->status) {
    case NOD_IN:
    case NOD_RESTORE_CONTEXT:
    case NOD_RESTORE_SECURITY:
        return 0;

    default:
        syscall_get_arguments_deprecated(current, regs, 0, 1, &addr);
        syscall_get_arguments_deprecated(current, regs, 1, 1, &length);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
        if (nod_mmap_check(p, addr, length)) {
#else
        if (nod_mmap_check(addr, length)) {
#endif
            vpr_warn("is trying to manipulate monitor memory %lx len %ld\n", addr, length);
            return -EINVAL;
        }

        return 0;
    }
}

static long
hook_general(SYSCALL_DEF) {
    int ret, id;
    struct nod_proc_info *p;
    
    id = syscall_get_nr(current, current_pt_regs());

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
    if (unlikely(current->flags & PF_KTHREAD))
#else
    if (unlikely(current->flags & PF_BORROWED_MM))
#endif
    {
        // We are not interested in kernel threads
        return syscall_filters[id].oldsyscall(SYSCALL_ARGS);
    }

#ifdef NOD_TEST
    NOD_TEST(current) {
        return syscall_filters[id].oldsyscall(SYSCALL_ARGS);
    }
#endif

    ASSERT(1 == syscall_filters[id].hooked);
    
    nod_event_from(&p);

    ret = syscall_filters[id].filter(p, current_pt_regs());
    return ret ? ret : syscall_filters[id].oldsyscall(SYSCALL_ARGS);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
inline void nod_write_cr0(unsigned long cr0) {
    unsigned long __force_order;
	asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}
#else
#define nod_write_cr0 write_cr0 
#endif

#define WPOFF do { nod_write_cr0(read_cr0() & (~0x10000)); } while (0);
#define WPON  do { nod_write_cr0(read_cr0() | 0x10000);    } while (0);

static void __maybe_unused
hook_syscall_legacy(int id, int (*filter)(struct nod_proc_info *, struct pt_regs *))
{
    if (id < 0 || id >= SYSCALL_TABLE_SIZE)
        return;
    if (!syscall_table)
        return;

    if (!syscall_filters[id].hooked) {
        syscall_filters[id].hooked = 1;
        WPOFF
        syscall_filters[id].oldsyscall = syscall_table[id];
        syscall_table[id] = (sys_call_ptr_t)hook_general;
        WPON
    }

    syscall_filters[id].filter = filter;
}

static void __maybe_unused
unhook_syscall_legacy(int id)
{
    if (id < 0 || id >= SYSCALL_TABLE_SIZE)
        return;
    if (!syscall_table)
        return;

    if (!syscall_filters[id].hooked)
        return;
    
    WPOFF
    syscall_table[id] = syscall_filters[id].oldsyscall;
    WPON

    syscall_filters[id].hooked = 0;
    syscall_filters[id].oldsyscall = 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
static void
set_syscall_filter(int id, int (*filter)(struct nod_proc_info *, struct pt_regs *))
{
    if (id < 0 || id >= SYSCALL_TABLE_SIZE)
        return;

    syscall_filters[id].filter = filter;
    syscall_filters[id].hooked = 1;
}

static void
clear_syscall_filter(int id)
{
    if (id < 0 || id >= SYSCALL_TABLE_SIZE)
        return;

    syscall_filters[id].hooked = 0;
    syscall_filters[id].filter = NULL;
}

static bool notrace
nod_skip_current_task(void)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
    if (unlikely(current->flags & PF_KTHREAD))
#else
    if (unlikely(current->flags & PF_BORROWED_MM))
#endif
    {
        // We are not interested in kernel threads
        return true;
    }

#ifdef NOD_TEST
    NOD_TEST(current) {
        return true;
    }
#endif

    return false;
}

static long notrace
nod_x64_sys_call_hook(const struct pt_regs *regs, unsigned int nr)
{
    int ret;
    struct nod_proc_info *p;

    if (unlikely(!nod_old_x64_sys_call))
        return -ENOSYS;

    if (unlikely(nr >= SYSCALL_TABLE_SIZE))
        return nod_old_x64_sys_call(regs, nr);
    if (unlikely(!syscall_filters[nr].hooked || !syscall_filters[nr].filter))
        return nod_old_x64_sys_call(regs, nr);

    nod_event_from(&p);
    ret = syscall_filters[nr].filter(p, (struct pt_regs *)regs);
    if (ret)
        return ret;

    return nod_old_x64_sys_call(regs, nr);
}

static void notrace
nod_x64_sys_call_thunk(unsigned long ip, unsigned long parent_ip,
                       struct ftrace_ops *ops, NOD_FTRACE_REGS_TYPE *fregs)
{
    struct pt_regs *regs;
    unsigned int nr;

    (void)ip;
    (void)ops;

    if (within_module(parent_ip, THIS_MODULE))
        return;

    if (unlikely(READ_ONCE(nod_x64_sys_call_stopping)))
        return;

    if (unlikely(nod_skip_current_task()))
        return;

    regs = nod_ftrace_get_regs(fregs);
    if (!regs)
        return;

    nr = (unsigned int)regs->si;
    if (nr >= SYSCALL_TABLE_SIZE || !syscall_filters[nr].hooked)
        return;
    if (!syscall_filters[nr].filter)
        return;

    nod_ftrace_set_ip(fregs, (unsigned long)nod_x64_sys_call_hook);
}

static void
unhook_syscall_dispatch(void)
{
    int ret;

    if (!nod_x64_sys_call_hooked)
        return;

    WRITE_ONCE(nod_x64_sys_call_stopping, true);

    ret = unregister_ftrace_function(&nod_x64_sys_call_ops);
    if (ret)
        vpr_warn("unregister ftrace hook x64_sys_call failed (%d)\n", ret);

    if (nod_x64_sys_call_addr)
        ftrace_set_filter_ip(&nod_x64_sys_call_ops, nod_x64_sys_call_addr, 1, 0);

    memset(&nod_x64_sys_call_ops, 0, sizeof(nod_x64_sys_call_ops));
    nod_x64_sys_call_hooked = 0;
    nod_x64_sys_call_addr = 0;
    nod_old_x64_sys_call = NULL;
}

static int
hook_syscall_dispatch(void)
{
    int ret;

    if (nod_x64_sys_call_hooked)
        return 0;

    nod_x64_sys_call_addr = nod_lookup_name("x64_sys_call");
    if (!nod_x64_sys_call_addr) {
        vpr_err("cannot find syscall dispatch symbol x64_sys_call\n");
        return -ENOENT;
    }

    memset(&nod_x64_sys_call_ops, 0, sizeof(nod_x64_sys_call_ops));
    nod_x64_sys_call_ops.func = nod_x64_sys_call_thunk;
    nod_x64_sys_call_ops.flags = FTRACE_OPS_FL_SAVE_REGS |
                                 FTRACE_OPS_FL_RECURSION |
                                 FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&nod_x64_sys_call_ops, nod_x64_sys_call_addr, 0, 0);
    if (ret) {
        vpr_err("set ftrace filter x64_sys_call failed (%d)\n", ret);
        return ret;
    }

    nod_old_x64_sys_call = (nod_x64_sys_call_t)nod_x64_sys_call_addr;
    WRITE_ONCE(nod_x64_sys_call_stopping, false);

    ret = register_ftrace_function(&nod_x64_sys_call_ops);
    if (ret) {
        vpr_err("register ftrace hook x64_sys_call failed (%d)\n", ret);
        ftrace_set_filter_ip(&nod_x64_sys_call_ops, nod_x64_sys_call_addr, 1, 0);
        memset(&nod_x64_sys_call_ops, 0, sizeof(nod_x64_sys_call_ops));
        nod_x64_sys_call_addr = 0;
        nod_old_x64_sys_call = NULL;
        WRITE_ONCE(nod_x64_sys_call_stopping, true);
        return ret;
    }

    nod_x64_sys_call_hooked = 1;
    return 0;
}
#endif

int trace_syscall(void) {
    int ret;

    if (tracepoint_registered == 1) {
        ret = 0;
        goto out;
    }

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
    ret = compat_register_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
#else
    ret = register_trace_syscall_exit(syscall_exit_probe);
#endif
    if (ret) {
        pr_err("can't create the sys_exit tracepoint\n");
        goto err_syscall_exit;
    }

    ret = compat_register_trace(syscall_procexit_probe, "sched_process_exit", tp_sched_process_exit);
    if (ret) {
        pr_err("can't create the sched_process_exit tracepoint\n");
        goto err_sched_procexit;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    set_syscall_filter(__NR_exit, exit_filter);
    set_syscall_filter(__NR_exit_group, exit_filter);
    set_syscall_filter(__NR_munmap, mm_range_filter);
    set_syscall_filter(__NR_mprotect, mm_range_filter);
    set_syscall_filter(__NR_mremap, mm_range_filter);

    ret = hook_syscall_dispatch();
    if (ret)
        goto err_hook;
#else
    hook_syscall_legacy(__NR_exit, exit_filter);
    hook_syscall_legacy(__NR_exit_group, exit_filter);
    hook_syscall_legacy(__NR_munmap, mm_range_filter);
    hook_syscall_legacy(__NR_mprotect, mm_range_filter);
    hook_syscall_legacy(__NR_mremap, mm_range_filter);
#endif

    tracepoint_registered = 1;
    return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
err_hook:
    clear_syscall_filter(__NR_mremap);
    clear_syscall_filter(__NR_mprotect);
    clear_syscall_filter(__NR_munmap);
    clear_syscall_filter(__NR_exit_group);
    clear_syscall_filter(__NR_exit);
    unhook_syscall_dispatch();
    compat_unregister_trace(syscall_procexit_probe, "sched_process_exit", tp_sched_process_exit);
#endif
err_sched_procexit:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	compat_unregister_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
#else
	unregister_trace_syscall_exit(syscall_exit_probe);
#endif
err_syscall_exit:
out:
    return ret;
}

void untrace_syscall(void) {
    if (tracepoint_registered == 0)
        return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    unhook_syscall_dispatch();
    clear_syscall_filter(__NR_mremap);
    clear_syscall_filter(__NR_mprotect);
    clear_syscall_filter(__NR_munmap);
    clear_syscall_filter(__NR_exit_group);
    clear_syscall_filter(__NR_exit);
#else
    unhook_syscall_legacy(__NR_mremap);
    unhook_syscall_legacy(__NR_mprotect);
    unhook_syscall_legacy(__NR_munmap);
    unhook_syscall_legacy(__NR_exit_group);
    unhook_syscall_legacy(__NR_exit);
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
    compat_unregister_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
#else
    unregister_trace_syscall_exit(syscall_exit_probe);
#endif

    compat_unregister_trace(syscall_procexit_probe, "sched_process_exit", tp_sched_process_exit);

    tracepoint_registered = 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
static void visit_tracepoint(struct tracepoint *tp, void *priv)
{
    if (!strcmp(tp->name, "sys_exit"))
        tp_sys_exit = tp;
    else if (!strcmp(tp->name, "sched_process_exit"))
        tp_sched_process_exit = tp;
}

static int get_tracepoint_handles(void)
{
	for_each_kernel_tracepoint(visit_tracepoint, NULL);
	if (!tp_sys_exit) {
		pr_err("failed to find sys_exit tracepoint\n");
		return -ENOENT;
	}
	return 0;
}
#else
static int get_tracepoint_handles(void)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};
#endif


uint64_t nod_lookup_name(const char *name) {
#ifdef KPROBE_LOOKUP
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	return kallsyms_lookup_name(name);
}

int tracepoint_init(void) {
    int ret;

    tracepoint_registered = 0;

    syscall_table = (sys_call_ptr_t *)nod_lookup_name("sys_call_table");
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    if (syscall_table == 0) {
        ret = -EINVAL;
        goto out;
    }
#endif

    ret = get_tracepoint_handles();
    if (ret)
        goto out;

    ret = trace_syscall();
    if (ret) {
        goto out;
    }

    ret = 0;

out:
    return ret;
}

void tracepoint_destory(void) {
    untrace_syscall();
}
