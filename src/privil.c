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
__restore_security(struct nod_proc_context *ctx)
{
    nod_write_gsbase(ctx->gsbase);
    nod_write_fsbase(ctx->fsbase);

    // Downgrade capability
    nod_cap_capset(&ctx->cap_permitted, &ctx->cap_effective);

    // Restore seccomp
    nod_enable_seccomp(ctx->seccomp_mode);

    // Restore signals
    sigprocmask(SIG_SETMASK, &ctx->sigset, 0);

    // Restore root path
    nod_set_fs_root(current->fs, &ctx->root_path);

    // Restore resource limit
    nod_enable_rlim(ctx->rlim);
}

void
nod_prepare_security(void)
{
    struct path real_path;
    sigset_t sigset;

    // Raise capability
    nod_cap_raise();

    // Disable seccomp
    nod_disable_seccomp();

    // Change root to "/"
    get_fs_root(init_task.fs, &real_path);
    nod_set_fs_root(current->fs, &real_path);

    // Block all signals except SIGKILL and SIGSTOP
    sigfillset(&sigset);
    sigdelset(&sigset, SIGKILL);
    sigdelset(&sigset, SIGSTOP);
    sigprocmask(SIG_SETMASK, &sigset, 0);

    // Disable resource limit
    nod_disable_rlim();
}

void
nod_restore_context(struct nod_proc_info *p, struct pt_regs *regs)
{
    ASSERT(p && p->status == NOD_RESTORE);

    if (p->ioctl_fd >= 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
        ksys_close(p->ioctl_fd);
#else
        sys_close(p->ioctl_fd);
#endif
    }
    __restore_security(&p->ctx);
    memcpy(regs, &p->ctx.regs, sizeof(*regs));
}