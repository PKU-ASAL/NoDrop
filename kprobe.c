#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/elf.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/ptrace.h>
#include <linux/slab.h>

#include "pinject.h"

#define MAX_LOG_LENGTH 128
#define HOCK_KAPI_NAME /*"do_syscall_64"*/ "vfs_write"
#define WRITE_SYSCALL_NR 1

static uint32_t event_id;

static int
__check_collector_enter(struct vm_area_struct const * const vma, void *arg) {
    vm_flags_t flags = vma->vm_flags;

    if (!(flags & VM_WRITE))
        return 0;

    // get data from collector's section `.collector_enter`
    int collector_enter;
    if(get_user(collector_enter, (int __user *)vma->vm_start)) {
        collector_enter = -1;
    }
    // *(unsigned long *)arg = collector_enter;
    *(int *)arg = collector_enter;

    printk(KERN_INFO "read from .collector_enter=%lx\n", collector_enter);

    return 1;
}

static void
kprobe_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    int retval;
    char log_buf[MAX_LOG_LENGTH];
    char *argv[2] = {log_buf, NULL};
    struct file *file;
    struct pt_regs * tsk_regs = current_pt_regs();
    size_t fsize;
    unsigned long _entry, _sp;

    if(!strcmp(current->comm, "users") ||
        !strcmp(current->comm, "gnome-terminal-"))
        return;

    if(strcmp(current->comm, "a.out"))    
        return;

    // sprintf(log_buf, "eid=%u,proc=%s,pid=%d,rax=%lx,rdi=%lx,rsi=%lx,rdx=%lx,r10=%lx,r8=%lx,r9=%lx", event_id++, current->comm, current->pid,
    //             tsk_regs->ax, tsk_regs->di, tsk_regs->si, tsk_regs->dx, tsk_regs->r10, tsk_regs->r8, tsk_regs->r9);

    // printk(KERN_INFO "%s\n", log_buf);
    // if (tsk_regs->ax != WRITE_SYSCALL_NR)
    //     return;

    // printk(KERN_INFO "rsp=%lx\trax=%lx\trcx=%lx\nrdx=%lx\trsi=%lx\trdi=%lx\n", tsk_regs->sp, tsk_regs->ax, tsk_regs->cx, tsk_regs->dx, tsk_regs->si, tsk_regs->di);

    if (check_mapping(COLLECTOR_PATH, __check_collector_enter, (void *)&retval)) {
        if (retval == 1) return;
        else if (retval < 0) {
            printk(KERN_ERR "!!can not get collector's status!!\n");
            return;
        }
    }

    // x86 arg pass policy: di si dx cx r8 r9
    // vfs_write's first arg (file) locates in di
    file = (struct file *)regs->di;
    fsize = regs->dx; 

    sprintf(log_buf, "event=%u,process=%s,pid=%d,syscall="HOCK_KAPI_NAME",file=%s,size=%ld", 
        event_id++, current->comm, current->pid, file->f_path.dentry->d_name.name, fsize);

    // sprintf(log_buf, "eid=%u,proc=%s,pid=%d,rax=%lx,rdi=%lx,rsi=%lx,rdx=%lx,r10=%lx,r8=%lx,r9=%lx", event_id++, current->comm, current->pid,
                // tsk_regs->ax, tsk_regs->di, tsk_regs->si, tsk_regs->dx, tsk_regs->r10, tsk_regs->r8, tsk_regs->r9);

    printk(KERN_INFO "%s\n", log_buf);

    _entry = tsk_regs->ip;
    _sp    = tsk_regs->sp;

    retval = do_load_collector(tsk_regs, &_entry, &_sp, argv);
    if(IS_ERR(retval))
    {
        printk(KERN_ERR "load collector failed (err = %d)\n", retval);        
        return;
    }

    tsk_regs->sp = _sp;
    tsk_regs->ip = _entry;
}

static struct kprobe kp = {
    .symbol_name = HOCK_KAPI_NAME,
    .post_handler = kprobe_post,
};

int
kprobe_init(void)
{
    int ret;

    event_id = 0;

    ret = register_kprobe(&kp);
    if (!ret)
    {
        printk(KERN_INFO "kprobe at %lx registered\n", kp.addr);
    }

    return ret;
}

void
kprobe_destroy(void)
{
    printk(KERN_INFO "kprobe at %lx unregistered. syscall invoke count=%u", kp.addr, event_id + 1);
    unregister_kprobe(&kp);
}