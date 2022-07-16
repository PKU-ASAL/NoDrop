#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/ptrace.h>
#include <linux/signal.h>
#include <linux/capability.h>
#include <linux/types.h>
#include <linux/path.h>
#include <linux/fs_struct.h>
#include <asm/fpu/internal.h>

#include "nodrop.h"
#include "common.h"
#include "procinfo.h"


enum which_selector {
	FS,
	GS
};

unsigned int 
nod_get_seccomp(void)
{
    return seccomp_mode(&current->seccomp);
}

static void
nod_disable_seccomp(void)
{
    if (unlikely(seccomp_mode(&current->seccomp) != SECCOMP_MODE_DISABLED)) {
        spin_lock_irq(&current->sighand->siglock);
        current->seccomp.mode = SECCOMP_MODE_DISABLED;
        smp_mb__before_atomic();
        clear_tsk_thread_flag(current, TIF_SECCOMP);
        spin_unlock_irq(&current->sighand->siglock);
    }
}

static int
nod_enable_seccomp(unsigned int mode)
{
    if (mode != SECCOMP_MODE_DISABLED &&
        mode != SECCOMP_MODE_FILTER &&
        mode != SECCOMP_MODE_STRICT) 
    {
        return -EINVAL;
    }
    if (unlikely(mode != seccomp_mode(&current->seccomp))) {
        spin_lock_irq(&current->sighand->siglock);
        current->seccomp.mode = mode;
        smp_mb__before_atomic();
        set_tsk_thread_flag(current, TIF_SECCOMP);
        spin_unlock_irq(&current->sighand->siglock);
    }

    return 0;
}

#define nod_cap_raise() nod_cap_capset(&CAP_FULL_SET, &CAP_FULL_SET)
static void 
nod_cap_capset(kernel_cap_t *permitted, kernel_cap_t *effective)
{
    struct cred *cred = (struct cred *)current_cred();
    cred->cap_effective = *effective;
    cred->cap_permitted = *permitted;
}

static void 
nod_write_fsbase(unsigned long fsbase)
{
    preempt_disable();
    loadsegment(fs, 0);
    wrmsrl(MSR_FS_BASE, fsbase);
    current->thread.FSBASE = fsbase;
    preempt_enable();
}

static void
nod_write_gsbase(unsigned long gsbase)
{
    preempt_disable();
    load_gs_index(0);
    wrmsrl(MSR_KERNEL_GS_BASE, gsbase);
    current->thread.GSBASE = gsbase;
    preempt_enable();
}

static void 
nod_set_fs_root(struct fs_struct *fs, const struct path *path)
{
    struct path old_root;

    path_get(path);
    spin_lock(&fs->lock);
    write_seqcount_begin(&fs->seq);
    old_root = fs->root;
    fs->root = *path;
    write_seqcount_begin(&fs->seq);
    spin_unlock(&fs->lock);
    if (old_root.dentry)
        path_put(&old_root);
}

static void
nod_disable_rlim(void)
{
    struct rlimit *rlim = current->signal->rlim;

    rlim[RLIMIT_FSIZE] = (struct rlimit){RLIM_INFINITY, RLIM_INFINITY};
    rlim[RLIMIT_CPU] = (struct rlimit){RLIM_INFINITY, RLIM_INFINITY};
    rlim[RLIMIT_NOFILE] = (struct rlimit){1024*1024, 1024*1024};
}

static void
nod_enable_rlim(struct rlimit *rlim)
{
    memcpy(current->signal->rlim, rlim, sizeof(current->signal->rlim));
}

static void 
__restore_security(struct nod_proc_security *sec)
{
    if (!sec->available)
        return;

    // Downgrade capability
    nod_cap_capset(&sec->cap_permitted, &sec->cap_effective);

    // Restore seccomp
    nod_enable_seccomp(sec->seccomp_mode);

    // Restore signals
    sigprocmask(SIG_SETMASK, &sec->sigset, 0);

    // Restore root path
    nod_set_fs_root(current->fs, &sec->root_path);

    // Restore resource limit
    nod_enable_rlim(sec->rlim);

    /* Kernel will wake up futex address pointed to `current->clear_child_tid` at do_exit().
     * This address may be modified by monitor so it should be saved and restored when exit the monitor */
    current->clear_child_tid = (int __user *)sec->child_tid;

    sec->available = 0;
}

void
nod_prepare_security(struct nod_proc_info *p)
{
    sigset_t sigset;
    struct path real_path;
    struct nod_proc_security *sec = &p->sec;

    // Raise capability
    sec->cap_effective = current_cred()->cap_effective;
    sec->cap_permitted = current_cred()->cap_permitted;
    nod_cap_raise();

    // Disable seccomp
    sec->seccomp_mode = nod_get_seccomp();
    nod_disable_seccomp();

    // Change root to "/"
    get_fs_root(current->fs, &sec->root_path);
    get_fs_root(init_task.fs, &real_path);
    nod_set_fs_root(current->fs, &real_path);

    // Block all signals except SIGKILL and SIGSTOP
    sigfillset(&sigset);
    sigdelsetmask(&sigset, sigmask(SIGKILL)|sigmask(SIGSTOP));
    sigprocmask(SIG_SETMASK, &sigset, &sec->sigset);

    // Disable resource limit
    memcpy(sec->rlim, current->signal->rlim, sizeof(sec->rlim));
    nod_disable_rlim();

    /* TODO:
     *  - robust_list may be saved too */
    sec->child_tid = (unsigned long)current->clear_child_tid;

    sec->available = 1;
}

void
nod_restore_security(struct nod_proc_info *p)
{
    if (p->ioctl_fd >= 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
        ksys_close(p->ioctl_fd);
#else
        sys_close(p->ioctl_fd);
#endif
        p->ioctl_fd = -1;
    }
    __restore_security(&p->sec);
}

void
nod_restore_context(struct nod_proc_info *p, struct pt_regs *regs)
{
    struct nod_proc_context *ctx = &p->ctx;

    if (!ctx->available)
        return;

    memcpy(regs, &ctx->regs, sizeof(*regs));

    nod_write_gsbase(ctx->gsbase);
    nod_write_fsbase(ctx->fsbase);

    ctx->available = 0;
}

void
nod_prepare_context(struct nod_proc_info *p, struct pt_regs *regs)
{
    struct nod_proc_context *ctx = &p->ctx;

    ctx->fsbase = current->thread.FSBASE;
    ctx->gsbase = current->thread.GSBASE;

    memcpy(&ctx->regs, regs, sizeof(*regs));

    ctx->available = 1;
}