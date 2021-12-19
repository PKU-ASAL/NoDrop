#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

#include "pinject.h"

#define __NR_syscall_max __NR_statx // may change

typedef long (*sys_call_ptr_t)(const struct pt_regs *);

sys_call_ptr_t *syscall_table;
sys_call_ptr_t syscall_table_bak[__NR_syscall_max + 1];
int filtered_syscall[] = { /*__NR_write, __NR_clone*/ __NR_write, __NR_read };

static unsigned long event_id;
rwlock_t rwlock;

static long
__hooked_syscall_entry(struct pt_regs *reg) {
    read_lock(&rwlock); 

    int nr = reg->orig_ax;
    long retval;
    unsigned long _ip, _sp;

    sys_call_ptr_t __syscall_real_entry = syscall_table_bak[nr];
    if (__syscall_real_entry == 0) {
        printk(KERN_ERR "unexpect syscall_nr=%d\n", nr);
        retval = -ENOSYS;
        goto out;
    }

    // sys_exit would not return to here
    if (nr == __NR_exit) {
        read_unlock(&rwlock);
    }

    retval = __syscall_real_entry(reg);

    // if(!strcmp(current->comm, "users") ||
    //     !strcmp(current->comm, "gnome-terminal-"))
    //     goto out;
    if(strcmp(current->comm, "a.out"))    
        goto out;

    reg->ax = retval;

    _ip = reg->ip;
    _sp = reg->sp;

    if (!do_load_monitor(reg, &_ip, &_sp, &event_id)) {
        event_id++;
        reg->ip = _ip;
        reg->sp = _sp;
        reg->cx = _ip;
    }

out:
    read_unlock(&rwlock);
    return retval;
}

static void
hook_syscall_table(void) {
    int sz, nr, i;

    for (i = 0; i <= __NR_syscall_max; ++i)
        syscall_table_bak[i] = 0;

    for (i = 0, sz = sizeof(filtered_syscall) / sizeof(int); i < sz; ++i) {
        nr = filtered_syscall[i];
        syscall_table_bak[nr] = syscall_table[nr];
        syscall_table[nr] = (sys_call_ptr_t)__hooked_syscall_entry;
        printk(KERN_INFO "hook syscall %d [%lx]\n", nr, syscall_table_bak[nr]);
    }
}

static int 
make_rw(unsigned long _addr) {
    unsigned int level = 0;	
	pte_t *pte = NULL;

	pte = lookup_address(_addr, &level);
	if(pte == NULL) {
		printk(KERN_ERR "%s: get pte failed\n", __func__);
		return -1;
	} 
	
	if(pte->pte & ~_PAGE_RW)
		pte->pte |= _PAGE_RW;

	return 0;
}

static int 
make_ro(unsigned long _addr) {
    unsigned int level = 0;	
	pte_t *pte = NULL;

	pte = lookup_address(_addr, &level);
	if(pte == NULL) {
		printk(KERN_ERR "%s: get pte failed\n", __func__);
		return -1;
	} 
	
    pte->pte &= ~_PAGE_RW;
    return 0;
}

int hook_init() {
    int retval = 0;
    event_id = 0;

    rwlock_init(&rwlock);

    syscall_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    if (syscall_table == 0)
        return -EINVAL;

    retval = make_rw((unsigned long)syscall_table);

    if (!retval) {
        hook_syscall_table();

        if (make_ro((unsigned long)syscall_table)) {
            printk(KERN_ERR "err!! can not make syscall_table read only!!!!");
        }
    }

    return retval;
}

void hook_destory() {
    int i, nr, sz;

    if (make_rw((unsigned long)syscall_table)) {
        panic("err!! can not make syscall_table writable!!!!");
    }

    for (i = 0, sz = sizeof(filtered_syscall) / sizeof(int); i < sz; ++i) {
        nr = filtered_syscall[i];
        syscall_table[nr] = syscall_table_bak[nr];
        printk(KERN_INFO "restore syscall %d [%lx]\n", nr, syscall_table[nr]);
    }

    if (make_ro((unsigned long)syscall_table)) {
        printk(KERN_ERR "err!! can not make syscall_table read only!!!!");
    }

    printk(KERN_INFO "Wait for processes to leave hook entry\n");
    write_lock(&rwlock);

    printk(KERN_INFO "event_id = %lu\n", event_id);
}