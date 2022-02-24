#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <asm/prctl.h>
#include <asm/proto.h>

#include "pinject.h"
#include "include/common.h"
#include "include/events.h"
#include "include/ioctl.h"


#define BUFSIZE 30

static struct proc_dir_entry *ent;
typedef struct  {
    int status;
} spr_private_data_t;

static int spr_procopen(struct inode *inode, struct file *filp)
{
    int ret;
    int status = event_from_monitor();
    spr_private_data_t *private;

    if (status == SPR_EVENT_FROM_APPLICATION || status == SPR_EVENT_FROM_MONITOR) {
        private = vmalloc(sizeof(spr_private_data_t));
        if (!private) {
            ret = -ENOMEM;
            pr_err("proc open: No memory for allocating private data");
        } else {
            ret = 0;
            private->status = status;
            filp->private_data = (void *)private;
        }
    } else {
        ret = -ENODEV;
    }

    return ret;
}

static ssize_t
spr_procread(struct file *filp, char __user *buf, size_t count, loff_t *off) {
    int len = 0;
    unsigned int event_id, cpu;
    char kbuf[BUFSIZE];

    if (*off > 0 || count < BUFSIZE)
        return 0;

    event_id = 0;
    for_each_present_cpu(cpu) {
        struct spr_kbuffer *bufp = &per_cpu(buffer, cpu);
        mutex_lock(&bufp->lock);
        event_id += bufp->event_count;
        mutex_unlock(&bufp->lock);
    }

    len += sprintf(kbuf, "%u", event_id);
    if (copy_to_user(buf, kbuf, len))
        return -EFAULT;
    
    *off = len;
    return len;
}

static long 
spr_procioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret;
    uint64_t count;
    unsigned int cpu;
    struct security_data security;
    struct spr_kbuffer *bufp;
    spr_private_data_t *private = filp->private_data;

    switch(cmd) {
    case SPR_IOCTL_CLEAR_BUFFER:
        for_each_possible_cpu(cpu) {
            bufp = &per_cpu(buffer, cpu);
            mutex_lock(&bufp->lock);
            reset_buffer(bufp, 1, 0);
            mutex_unlock(&bufp->lock);
        }

        pr_info("proc: clean buffer");
        break;
    case SPR_IOCTL_RELEASE_SYSCAL_TABLE:
        ret = -EINVAL;
        pr_info("proc: release syscall table (DEPRECATED)");

        goto out;
    case SPR_IOCTL_HOOK_SYSCALL_TABLE:
        ret = -EINVAL;
        pr_info("proc: hook syscall table (DEPRECATED)");

        goto out;
    case SPR_IOCTL_READ_BUFFER_COUNT:
        count = 0;
        for_each_present_cpu(cpu) {
            bufp = &per_cpu(buffer, cpu);
            mutex_lock(&bufp->lock);
            count += bufp->event_count;
            mutex_unlock(&bufp->lock);
        }

        if (put_user(count, (typeof(count) *)arg)) {
            ret = -EINVAL;
            goto out;
        }
        break;
    case SPR_IOCTL_RESTORE_SECURITY:
        if (private->status != SPR_EVENT_FROM_MONITOR) {
            ret = -EINVAL;
            goto out;
        }

        if (copy_from_user(&security, (void __user *)arg, sizeof(security))) {
            ret = -EFAULT;
            goto out;
        }

        if ((ret = spr_enable_seccomp(security.seccomp_mode))) 
            goto out;

        spr_write_gsbase(security.gsbase);
        spr_write_fsbase(security.fsbase);
        spr_cap_capset(security.cap_permitted, security.cap_effective);

        break;
    default:
        ret = -ENOTTY;
        goto out;
    }

    ret = 0;

out:
    return ret;
}

static int spr_procrelease(struct inode *inode, struct file *filp)
{
    vfree(filp->private_data);
    return 0;
}

static const struct file_operations g_spr_fops = {
    .open = spr_procopen,
    .read = spr_procread,
    .unlocked_ioctl = spr_procioctl,
    .release = spr_procrelease,
    .owner = THIS_MODULE
};

int proc_init(void) {
    int ret;

    ent = proc_create(SPR_IOCTL_NAME, 0666, NULL, &g_spr_fops);

    if (!ent) {
        ret = -EFAULT;
        pr_err("proc_init: Cannot create proc file");
    } else {
        ret = 0;
    }

    return ret;
}

void proc_destroy(void) {
    if (ent) {
        proc_remove(ent);
    }
}
