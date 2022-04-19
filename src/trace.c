#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <linux/mm.h>
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

static int tracepoint_registered;

static int filtered_syscall[] = { 
    __NR_write, __NR_read, __NR_open, __NR_close, __NR_ioctl,
    __NR_execve, 
    __NR_clone, __NR_fork, __NR_vfork, 
    __NR_socket, __NR_bind, __NR_connect, __NR_listen, __NR_accept, __NR_accept4,
    __NR_sendto, __NR_recvfrom, __NR_sendmsg, __NR_recvmsg
};
static sys_call_ptr_t *syscall_table;
static sys_call_ptr_t real_exit, real_exit_group, real_mprotect, real_munmap;

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

static int
syscall_probe(struct pt_regs *regs, long id) {
    int retval;
    long table_index;
    enum nod_event_type type;
    struct nod_event_data event_data;

    table_index = id - SYSCALL_TABLE_ID0;
    if (likely(table_index >= 0 && table_index < SYSCALL_TABLE_SIZE)) {
        type = g_syscall_event_table[table_index];

        event_data.category = NODC_SYSCALL;
        event_data.event_info.syscall_data.regs = regs;
        event_data.event_info.syscall_data.id = id;
        
        retval = record_one_event(type, &event_data);
    } else {
        retval = NOD_FAILURE_INVALID_EVENT;
    }

    return retval;
}

TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret)
{
    int i, evt_from, id;
    struct nod_proc_info *p;

#ifdef NOD_TEST
    NOD_TEST(current) {
        return;
    }
#endif

    id = syscall_get_nr(current, regs);

    for (i = 0; i < sizeof(filtered_syscall) / sizeof(filtered_syscall[0]); ++i)
        if (id == filtered_syscall[i])
            goto start;

    if (id == __NR_ioctl)
        goto start;

    return;

start:
    evt_from = nod_event_from(&p);
    if (evt_from == NOD_OUT || evt_from == NOD_CLONE) {
        if (id == __NR_clone && ret == 0) {
            // forked child process
            unsigned long clone_flags;
            syscall_get_arguments_deprecated(current, regs, 1, 1, &clone_flags);
            if (!(clone_flags & CLONE_VM)) 
                nod_set_status(NOD_CLONE, NULL, -1, NULL, current);
        } else {
            if(p) {
                if (id == __NR_execve || id == __NR_execveat) {
                    p->load_addr = p->stack.fsbase = 0;
                }
            }
            syscall_probe(regs, id);
        }
    } else if (p) {
        if (p->status == NOD_RESTORE_CONTEXT) {
            nod_restore_security(p);
            nod_restore_context(p, regs);
            nod_set_out(current);
        } else if (p->status == NOD_RESTORE_SECURITY) {
            nod_restore_security(p);
        }
    }
}

TRACEPOINT_PROBE(syscall_procexit_probe, struct task_struct *tsk)
{
#ifdef NOD_TEST
    NOD_TEST(tsk) {
        return;
    }
#endif

    nod_free_status(tsk);
}

static long
__real_exit(SYSCALL_DEF)
{
    struct nod_proc_info *p;
#ifdef NOD_TEST
    NOD_TEST(current) {
        return real_exit(SYSCALL_ARGS);
    }
#endif

    if (likely(nod_event_from(&p) == NOD_OUT)) {
        if (unlikely(syscall_probe(current_pt_regs(), __NR_exit) == NOD_SUCCESS_LOAD))
            return -EAGAIN;
    } else if (p) {
        nod_restore_security(p);
    }

    return real_exit(SYSCALL_ARGS);
}

static long
__real_exit_group(SYSCALL_DEF)
{
    struct nod_proc_info *p;
#ifdef NOD_TEST
    NOD_TEST(current) {
        return real_exit_group(SYSCALL_ARGS);
    }
#endif

    if (likely(nod_event_from(&p) == NOD_OUT)) {
        if (unlikely(syscall_probe(current_pt_regs(), __NR_exit_group) == NOD_SUCCESS_LOAD))
            return -EAGAIN;
    } else if (p) {
        nod_restore_security(p);
    }

    return real_exit_group(SYSCALL_ARGS);
}

static long
__real_mprotect(SYSCALL_DEF)
{
    unsigned long addr, length;
    struct nod_proc_info *p;
#ifdef NOD_TEST
    NOD_TEST(current) {
        return real_mprotect(SYSCALL_ARGS);
    }
#endif

    if (nod_event_from(&p) == NOD_OUT) {
        syscall_get_arguments_deprecated(current, current_pt_regs(), 0, 1, &addr);
        syscall_get_arguments_deprecated(current, current_pt_regs(), 1, 1, &length);
        if ((p && nod_proc_check_mm(p, addr, length)) || nod_mmap_check(addr, length)) {
            pr_warn("%s(%d) is trying to change monitor memory protection\n", current->comm, current->pid);
            return -EINVAL;
        }
    }

    return real_mprotect(SYSCALL_ARGS);
}

static long
__real_munmap(SYSCALL_DEF)
{
    unsigned long addr, length;
    struct nod_proc_info *p;
#ifdef NOD_TEST
    NOD_TEST(current) {
        return real_munmap(SYSCALL_ARGS);
    }
#endif

    if (nod_event_from(&p) == NOD_OUT) {
        syscall_get_arguments_deprecated(current, current_pt_regs(), 0, 1, &addr);
        syscall_get_arguments_deprecated(current, current_pt_regs(), 1, 1, &length);
        if ((p && nod_proc_check_mm(p, addr, length)) || nod_mmap_check(addr, length)) {
            pr_warn("%s(%d) is trying to unmap monitor memory\n", current->comm, current->pid);
            return -EINVAL;
        }
    }

    return real_munmap(SYSCALL_ARGS);
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

int trace_syscall(void) {
    int ret;

    if (tracepoint_registered == 0) {
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

    WPOFF
    real_exit = syscall_table[__NR_exit];
    real_exit_group = syscall_table[__NR_exit_group];
    real_munmap = syscall_table[__NR_munmap];
    real_mprotect = syscall_table[__NR_mprotect];

    syscall_table[__NR_exit] = (sys_call_ptr_t)__real_exit;
    syscall_table[__NR_exit_group] = (sys_call_ptr_t)__real_exit_group;
    syscall_table[__NR_munmap] = (sys_call_ptr_t)__real_munmap;
    syscall_table[__NR_mprotect] = (sys_call_ptr_t)__real_mprotect;
    WPON

    tracepoint_registered = 0;
    return 0;

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
    if (tracepoint_registered == 1)
        return;

    WPOFF
    syscall_table[__NR_exit] = real_exit;
    syscall_table[__NR_exit_group] = real_exit_group;
    syscall_table[__NR_munmap] = real_munmap;
    syscall_table[__NR_mprotect] = real_mprotect;
    WPON

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
    compat_unregister_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
#else
    unregister_trace_syscall_exit(syscall_exit_probe);
#endif

    compat_unregister_trace(syscall_procexit_probe, "sched_process_exit", tp_sched_process_exit);

    tracepoint_registered = 1;
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

int tracepoint_init(void) {
    int ret;

    tracepoint_registered = 1;

    syscall_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    if (syscall_table == 0) {
        ret = -EINVAL;
        goto out;
    }

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
