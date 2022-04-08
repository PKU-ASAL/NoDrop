#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/syscall.h>

#include "nodrop.h"
#include "syscall.h"
#include "common.h"
#include "events.h"

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

int released;

static int filtered_syscall[] = { 
    __NR_write, __NR_read, __NR_open, __NR_close,
    __NR_execve, 
    __NR_clone, __NR_fork, __NR_vfork, 
    __NR_socket, __NR_bind, __NR_connect, __NR_listen, __NR_accept, __NR_accept4,
    __NR_sendto, __NR_recvfrom, __NR_sendmsg, __NR_recvmsg
};
static sys_call_ptr_t *syscall_table;
static sys_call_ptr_t real_exit, real_exit_group;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
static struct tracepoint *tp_sys_exit;
#endif

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

        event_data.category = SPRC_SYSCALL;
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

#ifdef NOD_TEST
    NOD_TEST(current) {
        return;
    }
#endif

    id = syscall_get_nr(current, regs);

    for (i = 0; i < sizeof(filtered_syscall) / sizeof(filtered_syscall[0]); ++i)
        if (id == filtered_syscall[i])
            goto start;

    return;

start:
    evt_from = event_from_monitor();
    if (evt_from == NOD_EVENT_FROM_APPLICATION) {
        syscall_probe(regs, id);
    }
}

static long
hook_exit(SYSCALL_DEF)
{
#ifdef NOD_TEST
    NOD_TEST(current) {
        return real_exit(SYSCALL_ARGS);
    }
#endif

    if (likely(event_from_monitor() == NOD_EVENT_FROM_APPLICATION)) {
        if (unlikely(syscall_probe(current_pt_regs(), __NR_exit) == NOD_SUCCESS_LOAD))
            return 0;
    }

    return real_exit(SYSCALL_ARGS);
}

static long
hook_exit_group(SYSCALL_DEF)
{
#ifdef NOD_TEST
    NOD_TEST(current) {
        return real_exit_group(SYSCALL_ARGS);
    }
#endif

    if (likely(event_from_monitor() == NOD_EVENT_FROM_APPLICATION)) {
        if (unlikely(syscall_probe(current_pt_regs(), __NR_exit_group) == NOD_SUCCESS_LOAD))
            return 0;
    }

    return real_exit_group(SYSCALL_ARGS);
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

int hook_syscall(void) {
    int ret;

    if (released == 0)
        return 0;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
    ret = compat_register_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
#else
    ret = register_trace_syscall_exit(syscall_exit_probe);
#endif
    if (ret) {
        pr_err("can't create the sys_exit tracepoint\n");
        return ret;
    }

    WPOFF
    real_exit = syscall_table[__NR_exit];
    real_exit_group = syscall_table[__NR_exit_group];
    syscall_table[__NR_exit] = (sys_call_ptr_t)hook_exit;
    syscall_table[__NR_exit_group] = (sys_call_ptr_t)hook_exit_group;
    WPON

    released = 0;
    return 0;
}

void restore_syscall(void) {
    // int nr, sz, i;

    if (released == 1)
        return;

    WPOFF
    syscall_table[__NR_exit] = real_exit;
    syscall_table[__NR_exit_group] = real_exit_group;
    WPON

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
    compat_unregister_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
#else
    unregister_trace_syscall_exit(syscall_exit_probe);
#endif

    released = 1;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
static void visit_tracepoint(struct tracepoint *tp, void *priv)
{
	if (!strcmp(tp->name, "sys_exit"))
		tp_sys_exit = tp;
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

int hook_init(void) {
    int ret;

    released = 1;

    syscall_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    if (syscall_table == 0) {
        ret = -EINVAL;
        goto out;
    }

    ret = get_tracepoint_handles();
    if (ret)
        goto out;

    ret = hook_syscall();
    if (ret) {
        goto out;
    }

    ret = 0;

out:
    return ret;
}

void hook_destory(void) {
    restore_syscall();
}
