#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/signal.h>
#include <linux/capability.h>
#include <linux/types.h>
#include <linux/path.h>
#include <linux/fs_struct.h>

#include "pinject.h"
#include "common.h"


unsigned int spr_get_seccomp(void) {
    return seccomp_mode(&current->seccomp);
}

static void spr_disable_seccomp(void) {
    if (unlikely(seccomp_mode(&current->seccomp) != SECCOMP_MODE_DISABLED)) {
        spin_lock_irq(&current->sighand->siglock);
        current->seccomp.mode = SECCOMP_MODE_DISABLED;
        smp_mb__before_atomic();
        clear_tsk_thread_flag(current, TIF_SECCOMP);
        spin_unlock_irq(&current->sighand->siglock);
    }
}

static int spr_enable_seccomp(unsigned int mode) {
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

static void spr_cap_raise(void) {
    struct cred *cred = current_cred();
	cred->cap_permitted = CAP_FULL_SET;
	cred->cap_effective = CAP_FULL_SET;
}

static void spr_cap_capset(kernel_cap_t *permitted, kernel_cap_t *effective)
{
    struct cred *cred = current_cred();
    cred->cap_effective = *effective;
    cred->cap_permitted = *permitted;
}

static void spr_write_fsbase(unsigned long fsbase) {
    preempt_disable();
    loadsegment(fs, 0);
    wrmsrl(MSR_FS_BASE, fsbase);
    current->thread.fsbase = fsbase;
    preempt_enable();
}

static void spr_write_gsbase(unsigned long gsbase) {
    preempt_disable();
    load_gs_index(0);
    wrmsrl(MSR_KERNEL_GS_BASE, gsbase);
    current->thread.gsbase = gsbase;
    preempt_enable();
}

static void spr_set_fs_root(struct fs_struct *fs, const struct path *path) {
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

static void spr_disable_rlim(void) {
    struct rlimit *rlim = current->signal->rlim;

    rlim[RLIMIT_FSIZE] = (struct rlimit){RLIM_INFINITY, RLIM_INFINITY};
    rlim[RLIMIT_CPU] = (struct rlimit){RLIM_INFINITY, RLIM_INFINITY};
    rlim[RLIMIT_NOFILE] = (struct rlimit){1024*1024, 1024*1024};
}

void prepare_rlimit_data(struct rlimit *rlim) {
    int i;
    int resources[] = {RLIMIT_NOFILE, RLIMIT_FSIZE, RLIMIT_CPU};

    for (i = 0; i < sizeof(resources) / sizeof(resources[0]); ++i) {
        rlim[i] = current->signal->rlim[resources[i]];
    }
}


void spr_prepare_security(void)
{
    sigset_t sigset;
    struct path real_path;

    // raise our cap
    spr_cap_raise();

    // disable seccomp
    spr_disable_seccomp();

    // block all signals
    sigfillset(&sigset);
    sigprocmask(SIG_SETMASK, &sigset, 0);

    // change root to "/"
    get_fs_root(init_task.fs, &real_path);
    spr_set_fs_root(current->fs, &real_path);

    // disable resource limit
    spr_disable_rlim();
}

static void restore_security(struct spr_proc_info *info)
{
    spr_write_gsbase(info->gsbase);
    spr_write_fsbase(info->fsbase);
    spr_cap_capset(&info->cap_permitted, &info->cap_effective);
    spr_enable_seccomp(info->seccomp_mode);

    sigprocmask(SIG_SETMASK, &info->sigset, 0);
    spr_set_fs_root(current->fs, &info->root_path);
}


void spr_restore_context(struct spr_proc_status_struct *p) {
    ASSERT(p && p->info);
    ASSERT(p->status == SPR_MONITOR_RESTORE);

    restore_security(p->info);
    if (p->ioctl_fd >= 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
        ksys_close(p->ioctl_fd);
#else
        sys_close(p->ioctl_fd);
#endif
    }
    memcpy(current_pt_regs(), &p->info->regs, sizeof(p->info->regs));
}