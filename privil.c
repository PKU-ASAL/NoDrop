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

#include "common.h"


enum which_selector {
	FS,
	GS
};

unsigned int spr_get_seccomp(void) {
    return seccomp_mode(&current->seccomp);
}

void spr_disable_seccomp(void) {
    if (unlikely(seccomp_mode(&current->seccomp) != SECCOMP_MODE_DISABLED)) {
        spin_lock_irq(&current->sighand->siglock);
        current->seccomp.mode = SECCOMP_MODE_DISABLED;
        smp_mb__before_atomic();
        clear_tsk_thread_flag(current, TIF_SECCOMP);
        spin_unlock_irq(&current->sighand->siglock);
    }
}

int spr_enable_seccomp(unsigned int mode) {
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

void spr_cap_raise(void) {
    struct cred *cred = current_cred();
	cred->cap_permitted = CAP_FULL_SET;
	cred->cap_effective = CAP_FULL_SET;
}

void spr_cap_capset(u32 *permitted, u32 *effective) {
    int i;
    struct cred *cred = current_cred();
    for (i = 0; i < _KERNEL_CAPABILITY_U32S; ++i) {
        cred->cap_permitted.cap[i] = permitted[i];
        cred->cap_effective.cap[i] = effective[i];
    }
}

void spr_write_fsbase(unsigned long fsbase) {
    preempt_disable();
    loadsegment(fs, 0);
    wrmsrl(MSR_FS_BASE, fsbase);
    current->thread.fsbase = fsbase;
    preempt_enable();
}

void spr_write_gsbase(unsigned long gsbase) {
    preempt_disable();
    load_gs_index(0);
    wrmsrl(MSR_KERNEL_GS_BASE, gsbase);
    current->thread.gsbase = gsbase;
    preempt_enable();
}

void prepare_security_data(struct security_data *security) {
    int i;
    struct cred *cred = current_cred();
    sigset_t sigset;

    sigprocmask(-1, 0, &sigset);
    *security = (struct security_data) {
        .fsbase = current->thread.fsbase,
        .gsbase = current->thread.gsbase,
        .seccomp_mode = seccomp_mode(&current->seccomp),
        .sigset = sigset.sig[0],
    };

    for (i = 0; i < _KERNEL_CAPABILITY_U32S; ++i) {
        security->cap_permitted[i] = cred->cap_permitted.cap[i];
        security->cap_effective[i] = cred->cap_effective.cap[i];
    }
}

void prepare_rlimit_data(struct rlimit *rlim) {
    int i;
    int resources[] = {RLIMIT_NOFILE, RLIMIT_FSIZE, RLIMIT_CPU};

    for (i = 0; i < sizeof(resources) / sizeof(resources[0]); ++i) {
        rlim[i] = current->signal->rlim[resources[i]];
    }
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

int prepare_root_path(char *buf) {
    char *pathp;
    struct path real_path, old_path;

    get_fs_root(current->fs, &old_path);

    get_fs_root(init_task.fs, &real_path);
    spr_set_fs_root(current->fs, &real_path);

    path_get(&old_path);
    pathp = d_path(&old_path, buf, PATH_MAX);
    path_put(&old_path);
    if (IS_ERR(pathp)) {
        spr_set_fs_root(current->fs, &old_path);
        return PTR_ERR(pathp);
    }
    sprintf(buf, "%s", pathp);

    spr_set_fs_root(current->fs, &old_path);
    return 0;
}

void spr_disable_rlim(void) {
    struct rlimit *rlim = current->signal->rlim;

    rlim[RLIMIT_FSIZE] = (struct rlimit){RLIM_INFINITY, RLIM_INFINITY};
    rlim[RLIMIT_CPU] = (struct rlimit){RLIM_INFINITY, RLIM_INFINITY};
    rlim[RLIMIT_NOFILE] = (struct rlimit){1024*1024, 1024*1024};
}

void spr_prepare_security(void) {
    struct path real_path;
    sigset_t sigset;

    spr_cap_raise();
    spr_disable_rlim();
    spr_disable_seccomp();

    get_fs_root(init_task.fs, &real_path);
    spr_set_fs_root(current->fs, &real_path);

    sigfillset(&sigset);
    sigprocmask(SIG_SETMASK, &sigset, 0);
}