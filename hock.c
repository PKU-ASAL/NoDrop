#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <linux/mm.h>

#include "pinject.h"

#define __NR_syscall_max __NR_statx // may change
#define MAX_LOG_LENGTH 128

typedef long (*sys_call_ptr_t)(const struct pt_regs *);

sys_call_ptr_t *syscall_table;
sys_call_ptr_t syscall_table_bak[__NR_syscall_max + 1] = { (sys_call_ptr_t)NULL };
int filtered_syscall[] = { __NR_write };

static unsigned long event_id;

static long
__hocked_syscall_entry(struct pt_regs *reg) {
    int nr = reg->orig_ax;
    long retval;
    // char log_buf[MAX_LOG_LENGTH];
    // char *argv[2] = { log_buf, NULL };
    unsigned long _ip, _sp;

    sys_call_ptr_t __syscall_real_entry = syscall_table_bak[nr];
    if (__syscall_real_entry == NULL) {
        printk(KERN_ERR "unexpect syscall_nr=%d\n", nr);
        retval = -ENOSYS;
        goto out;
    }

    // sprintf(log_buf, "eid=%lu,proc=%s,pid=%d,rax=%lx,rdi=%lx,rsi=%lx,rdx=%lx,r10=%lx,r8=%lx,r9=%lx", event_id++, current->comm, current->pid,
    //             reg->ax, reg->di, reg->si, reg->dx, reg->r10, reg->r8, reg->r9);

    retval = __syscall_real_entry(reg);

    if(strcmp(current->comm, "a.out"))    
        goto out;

    // reg->ax = retval;

    // _ip = reg->ip;
    // _sp = reg->sp;

    // if (!do_load_collector(reg, &_ip, &_sp, argv)) {
    //     reg->ip = _ip;
    //     reg->sp = _sp;
    //     // reg->cx = _ip;
    // }

out:
    return retval;
}

static void
hock_syscall_table(void) {
    int sz, nr, i;

    for (i = 0, sz = sizeof(filtered_syscall) / sizeof(int); i < sz; ++i) {
        nr = filtered_syscall[i];
        syscall_table_bak[nr] = syscall_table[nr];
        syscall_table[nr] = (sys_call_ptr_t)__hocked_syscall_entry;
    }
}

static int 
make_rw(unsigned long _addr) {
    unsigned int level = 0;	
	pte_t *pte = NULL;

	pte = lookup_address(_addr, &level);
	if(pte == NULL) {
		printk("%s: get pte failed\n", __func__);
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
		printk("%s: get pte failed\n", __func__);
		return -1;
	} 
	
    pte->pte &= ~_PAGE_RW;
    return 0;
}

int hock_init() {
    int retval = 0;
    event_id = 0;

    syscall_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    if (syscall_table == 0)
        return -EINVAL;

    retval = make_rw((unsigned long)syscall_table);

    if (retval >= 0)
        hock_syscall_table();

    return retval;
}

void hock_destory() {
    int i;

    for (i = 0; i <= __NR_syscall_max; ++i) {
        if (syscall_table_bak[i])
            syscall_table[i] = syscall_table_bak[i];
    }

    if (make_ro((unsigned long)syscall_table)) {
        printk(KERN_ERR "err!! can not make syscall_table read only!!!!");
    }
}