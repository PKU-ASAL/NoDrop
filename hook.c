#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/version.h>

#include "pinject.h"
#include "common.h"

#define __NR_syscall_max __NR_statx // may change

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17,0)
#define SYSCALL_DEF   const struct pt_regs * _syscall_regs
#define SYSCALL_ARGS  _syscall_regs
unsigned long __force_order;
#else
#define SYSCALL_DEF  long _di, long _si, long _dx, long _r10, long _r8, long _r9
#define SYSCALL_ARGS _di, _si, _dx, _r10, _r8, _r9
#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17,0)

typedef long (*sys_call_ptr_t)(SYSCALL_DEF);

#define ALL_SYSCALL 0
#define TEST

static int filtered_syscall[] = { __NR_write, __NR_read, __NR_exit, __NR_exit_group };
static sys_call_ptr_t *syscall_table;
static sys_call_ptr_t syscall_table_bak[__NR_syscall_max + 1];

int released;

rwlock_t rwlock;
#define enter_syscall() read_lock(&rwlock)
#define leave_syscall() read_unlock(&rwlock)

static long
__hooked_syscall_entry(SYSCALL_DEF) {
    int nr;
    long syscall_ret;
    long retval = LOAD_SUCCESS;
    unsigned long _ip, _sp;
    sys_call_ptr_t __syscall_real_entry;
    struct pt_regs *reg;

    enter_syscall();

    reg = current_pt_regs();

    nr = reg->orig_ax;
    __syscall_real_entry = syscall_table_bak[nr];
    if (__syscall_real_entry == 0) {
        pr_err("unexpect syscall_nr=%d\n", nr);
        retval = -ENOSYS;
        goto out;
    }

    // 1. other process call exit(): do it normally retval=LOAD_SUCCESS
    // 2. a.out call exit(): DO NOT do syscall, just return, retval = LOAD_NO_SYSCALL
    // 3. monitor call exit(): do it normally retval=LOAD_SUCCESS

#ifdef TEST
    if(strcmp(current->comm, "a.out"))
        goto do_syscall;
#endif

    _ip = reg->ip;
    _sp = reg->sp;

    retval = do_load_monitor(reg, &_ip, &_sp);

    if (retval == LOAD_SUCCESS || retval == LOAD_NO_SYSCALL) {
        reg->ip = _ip;
        reg->sp = _sp;
        reg->cx = _ip;
    }

do_syscall:
    if (retval != LOAD_NO_SYSCALL) {
        if (DO_EXIT(nr)) 
            leave_syscall();
        syscall_ret = __syscall_real_entry(SYSCALL_ARGS);
    }
    else {
        syscall_ret = -ENOSYS;
    }

#ifdef TEST
    if (!strcmp(current->comm, "a.out")) 
#endif
        if (retval == LOAD_SUCCESS)
            adjust_retval(syscall_ret);

out:
    leave_syscall();
    return syscall_ret;
}

static void 
write_cr0_native(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}
static unsigned long 
read_cr0_native(void) {
    unsigned long val;
    asm volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (__force_order));
    return val;
}
static void 
make_rw(void) { write_cr0_native(read_cr0_native() & (~0x10000)); }
static void 
make_ro(void) { write_cr0_native(read_cr0_native() | 0x10000); }

void hook_syscall(void) {
    int sz, nr, i;

    if (released == 0)
        return;

    make_rw();
#if ALL_SYSCALL == 1
    for (i = 0; i <= __NR_syscall_max; ++i) {
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
    make_ro();
    released = 0;
}

void restore_syscall(void) {
    int nr, sz, i;
    if (released == 1)
        return;

    make_rw();
#if ALL_SYSCALL == 1
    for (i = 0; i <= __NR_syscall_max; ++i) {
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
    make_ro();
    released = 1;
}

int hook_init() {
    int i;

    syscall_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    if (syscall_table == 0)
        return -EINVAL;

    released = 1;
    rwlock_init(&rwlock);

    for (i = 0; i <= __NR_syscall_max; ++i)
        syscall_table_bak[i] = 0;

    hook_syscall();

    return 0;
}

void hook_destory() {
    restore_syscall();

    pr_info("Wait for processes to leave hook entry\n");
    while(!write_trylock(&rwlock)) {
        cond_resched();
    }
}
