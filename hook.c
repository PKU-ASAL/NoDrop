#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <asm/unistd.h>
#include <asm/syscall.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/version.h>

#include "pinject.h"
#include "syscall.h"
#include "include/common.h"
#include "include/events.h"


#define ALL_SYSCALL 0
#define TEST if (strcmp(current->comm, "a.out") && strcmp(current->comm, "curl"))

int released;

static int filtered_syscall[] = { 
    __NR_write, __NR_read,
    __NR_execve, __NR_clone, __NR_fork, __NR_vfork, 
    __NR_socket, __NR_bind, __NR_connect, __NR_listen, __NR_accept, __NR_accept4,
    __NR_sendto, __NR_recvfrom, __NR_sendmsg, __NR_recvmsg,
    __NR_exit, __NR_exit_group };
static sys_call_ptr_t *syscall_table;
static sys_call_ptr_t syscall_table_bak[NR_syscalls];

static  DEFINE_RWLOCK(syscall_lock);
#define enter_syscall(garbage) ({read_lock(&syscall_lock); NULL;})
#define leave_syscall(garbage) ({read_unlock(&syscall_lock); NULL;})

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
    struct pt_regs *reg;
    struct syscall_record *rec;
    sys_call_ptr_t __syscall_real_entry;

    rec = enter_syscall();
    reg = current_pt_regs();

    nr = syscall_get_nr(current, reg);
    __syscall_real_entry = syscall_table_bak[nr];
    if (__syscall_real_entry == 0) {
        pr_err("unexpect syscall_nr=%ld\n", nr);
        reg->ax = -ENOSYS;
        goto out;
    }

    TEST {
        goto do_syscall;
    }

    /* 
     * Record event immidiately if syscall exit() or exit_group() is invoked from application
     * Otherwise we should delay event recording until syscall returned
     */
    evt_from = event_from_monitor();
    if (SYSCALL_EXIT_FAMILY(nr) && evt_from == SPR_EVENT_FROM_APPLICATION) {
        /* escape syscall routine */
        ASSERT(nr != __NR_execve && nr != __NR_execveat);
        if (syscall_probe(reg, nr) == SPR_SUCCESS) {
            reg->ax = 0;
            goto out;
        }
    }

#ifdef TEST
do_syscall:
#endif
    if (SYSCALL_EXIT_FAMILY(nr))
        leave_syscall(rec);
    retval = __syscall_real_entry(SYSCALL_ARGS);
    syscall_set_return_value(current, reg, retval, retval);

    TEST {
        goto out;
    }

    if (evt_from == SPR_EVENT_FROM_APPLICATION) {
        syscall_probe(reg, nr);
    }

out:
    leave_syscall(rec);
    return syscall_get_return_value(current, reg);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
inline void spr_write_cr0(unsigned long cr0) {
    unsigned long __force_order;
	asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}
#else
#define spr_write_cr0 write_cr0 
#endif

#define WPOFF do { spr_write_cr0(read_cr0() & (~0x10000)); } while (0)
#define WPON  do { spr_write_cr0(read_cr0() | 0x10000);    } while (0)

void hook_syscall(void) {
    int sz, nr, i;

    if (released == 0)
        return;

    WPOFF;
#if ALL_SYSCALL == 1
    for (i = 0; i < NR_syscalls; ++i) {
        nr = i;
        syscall_table_bak[nr] = syscall_table[nr];
        syscall_table[nr] = (sys_call_ptr_t)__hooked_syscall_entry;
    }
    pr_info("hook all syscalls\n");
#else
    for (i = 0, sz = sizeof(filtered_syscall) / sizeof(int); i < sz; ++i) {
        nr = filtered_syscall[i];
        syscall_table_bak[nr] = syscall_table[nr];
        syscall_table[nr] = (sys_call_ptr_t)__hooked_syscall_entry;
        pr_info("hook syscall %d [%lx]\n", nr, (unsigned long)syscall_table_bak[nr]);
    }
#endif
    WPON;
    released = 0;
}

void restore_syscall(void) {
    int nr, sz, i;
    if (released == 1)
        return;

    WPOFF;
#if ALL_SYSCALL == 1
    for (i = 0; i < NR_syscalls; ++i) {
        nr = i;
        syscall_table[nr] = syscall_table_bak[nr];
        syscall_table_bak[nr] = 0;
    }
    pr_info("restore all syscalls\n");
#else
    for (i = 0, sz = sizeof(filtered_syscall) / sizeof(int); i < sz; ++i) {
        nr = filtered_syscall[i];
        syscall_table[nr] = syscall_table_bak[nr];
        syscall_table_bak[nr] = 0;
        pr_info("restore syscall %d [%lx]\n", nr, (unsigned long)syscall_table[nr]);
    }
#endif
    WPON;
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

    return 0;
}

void hook_destory() {
    restore_syscall();

    pr_info("Wait for processes to leave hook entry\n");
    while(!write_trylock(&syscall_lock)) {
        cond_resched();
    }
}
