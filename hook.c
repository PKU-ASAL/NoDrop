#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/syscall.h>

#include "pinject.h"
#include "syscall.h"
#include "include/common.h"
#include "include/events.h"


static int filtered_syscall[] = { 
    __NR_write, __NR_read, __NR_open, __NR_close,
    __NR_execve, 
    __NR_clone, __NR_fork, __NR_vfork, 
    __NR_socket, __NR_bind, __NR_connect, __NR_listen, __NR_accept, __NR_accept4,
    __NR_sendto, __NR_recvfrom, __NR_sendmsg, __NR_recvmsg,
    __NR_exit, __NR_exit_group };
static sys_call_ptr_t *syscall_table;
static sys_call_ptr_t syscall_table_bak[NR_syscalls];

static atomic_t insyscall_count;
int released;

static int
syscall_probe(struct pt_regs *regs, long id) {
    int retval;
    long table_index;
    enum spr_event_type type;
    struct spr_event_data event_data;

    table_index = id - SYSCALL_TABLE_ID0;
    if (likely(table_index >= 0 && table_index < SYSCALL_TABLE_SIZE)) {
        type = g_syscall_event_table[table_index];

        event_data.category = SPRC_SYSCALL;
        event_data.event_info.syscall_data.regs = regs;
        event_data.event_info.syscall_data.id = id;

        retval = record_one_event(type, &event_data);
    } else {
        retval = SPR_FAILURE_INVALID_EVENT;
    }

    return retval;
}

static long
__hooked_syscall_entry(SYSCALL_DEF) {
    int evt_from;
    long nr, retval;
    struct pt_regs *regs;
    sys_call_ptr_t __syscall_real_entry;
    struct spr_proc_status_struct *p = NULL;

    atomic_inc(&insyscall_count);

    regs = current_pt_regs();
    nr = syscall_get_nr(current, regs);

    __syscall_real_entry = syscall_table_bak[nr];
    ASSERT(__syscall_real_entry);

#ifdef SPR_TEST
    SPR_TEST(current) {
        goto do_syscall;
    }
#endif

    evt_from = event_from_monitor(&p);
    /* 
     * Record event immidiately if syscall exit() or exit_group() is invoked from application
     * Otherwise we should delay event recording until syscall returned
     */
    // if (SYSCALL_EXIT_FAMILY(nr) && evt_from == SPR_EVENT_FROM_APPLICATION) {
    //     if (syscall_probe(regs, nr) == SPR_SUCCESS) {
    //         syscall_set_return_value(current, regs, 0, 0);
    //         goto out;
    //     }
    // }

#ifdef SPR_TEST
do_syscall:
#endif
    if (SYSCALL_EXIT_FAMILY(nr))
        atomic_dec(&insyscall_count);
    retval = __syscall_real_entry(SYSCALL_ARGS);
    syscall_set_return_value(current, regs, 0, retval);
    ASSERT(!SYSCALL_EXIT_FAMILY(nr));
#ifdef SPR_TEST
    SPR_TEST(current) {
        goto out;
    }
#endif

    vpr_dbg("syscall %ld, retval %ld\n", nr, retval);
    if (p && p->status == SPR_MONITOR_RESTORE) {
        spr_restore_context(p);
        spr_set_status_out(current);
        spr_release_mm(current);
        vpr_dbg("restore context");
        retval = syscall_get_return_value(current, regs);
    } else if (evt_from == SPR_EVENT_FROM_APPLICATION) {
        syscall_probe(regs, nr);
    }

out:
    atomic_dec(&insyscall_count);
    return retval;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
inline void spr_write_cr0(unsigned long cr0) {
    unsigned long __force_order;
	asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}
#else
#define spr_write_cr0 write_cr0 
#endif

#define WPOFF do { spr_write_cr0(read_cr0() & (~0x10000)); } while (0);
#define WPON  do { spr_write_cr0(read_cr0() | 0x10000);    } while (0);

void hook_syscall(void) {
    int sz, nr, i;

    if (released == 0)
        return;

    WPOFF
    for (i = 0, sz = sizeof(filtered_syscall) / sizeof(int); i < sz; ++i) {
        nr = filtered_syscall[i];
        syscall_table_bak[nr] = syscall_table[nr];
        syscall_table[nr] = (sys_call_ptr_t)__hooked_syscall_entry;
        pr_info("hook syscall %d [%lx]\n", nr, (unsigned long)syscall_table_bak[nr]);
    }
    WPON

    released = 0;
}

void restore_syscall(void) {
    int nr, sz, i;

    if (released == 1)
        return;

    WPOFF
    for (i = 0, sz = sizeof(filtered_syscall) / sizeof(int); i < sz; ++i) {
        nr = filtered_syscall[i];
        syscall_table[nr] = syscall_table_bak[nr];
        syscall_table_bak[nr] = 0;
        pr_info("restore syscall %d [%lx]\n", nr, (unsigned long)syscall_table[nr]);
    }
    WPON

    released = 1;
}

int hook_init() {
    int i;

    syscall_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    if (syscall_table == 0)
        return -EINVAL;

    for (i = 0; i < NR_syscalls; ++i)
        syscall_table_bak[i] = 0;

    released = 1;
    hook_syscall();

    atomic_set(&insyscall_count, 0);

    return 0;
}

void hook_destory() {
    int now;
    restore_syscall();

    vpr_info("Wait for processes to leave hook entry\n");
    for(;;) {
        now = atomic_read(&insyscall_count);
        vpr_info("insyscall count %d\n", now);
        if (now <= 0) break;
        msleep(1000);
    }
}
