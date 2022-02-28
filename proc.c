#include <linux/version.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/fdtable.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <asm/prctl.h>
#include <asm/proto.h>

#include "pinject.h"
#include "include/common.h"
#include "include/events.h"
#include "include/ioctl.h"



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
#define BUFSIZE 50
    int len;
    unsigned int cpu;
    uint64_t event_count, unflushed_count;
    char kbuf[BUFSIZE];

    if (*off > 0 || count < BUFSIZE)
        return 0;

    event_count = unflushed_count = 0;
    for_each_present_cpu(cpu) {
        struct spr_kbuffer *bufp = &per_cpu(buffer, cpu);
        mutex_lock(&bufp->lock);
        event_count += bufp->event_count;
        unflushed_count += bufp->info->nevents;
        mutex_unlock(&bufp->lock);
    }

    len = sprintf(kbuf, "%llu,%llu", event_count, unflushed_count);
    if (len > BUFSIZE)
        len = BUFSIZE;
    if (copy_to_user(buf, kbuf, len))
        return -EFAULT;
    
    *off = len;
    return len;
}

static long 
spr_procioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret;
    unsigned int cpu;
    uint64_t count;
    char *ptr;
    struct spr_kbuffer *bufp;
    struct security_data security;
    struct buffer_count_info cinfo;
    struct fetch_buffer_struct fetch;
    spr_private_data_t *private = filp->private_data;


    switch(cmd) {
    case SPR_IOCTL_CLEAR_BUFFER:
        for_each_present_cpu(cpu) {
            bufp = &per_cpu(buffer, cpu);
            mutex_lock(&bufp->lock);
            reset_buffer(bufp, SPR_INIT_INFO | SPR_INIT_COUNT);
            mutex_unlock(&bufp->lock);
        }

        pr_info("proc: clean buffer");
        break;

    case SPR_IOCTL_FETCH_BUFFER:
        if (spr_copy_from_user((void *)&fetch, (void *)arg, sizeof(fetch))) {
            ret = -EINVAL;
            goto out;
        }
        count = 0;
        ptr = fetch.buf;
        for_each_present_cpu(cpu) {
            bufp = &per_cpu(buffer, cpu);
            mutex_lock(&bufp->lock);
            if (count + bufp->info->tail <= fetch.len) {
                if (copy_to_user((void *)ptr, (void *)bufp->buffer, bufp->info->tail)) {
                    mutex_unlock(&bufp->lock);
                    ret = -EFAULT;
                    goto out;
                }
                ptr += bufp->info->tail;
                count += bufp->info->tail;
                mutex_unlock(&bufp->lock);
            } else {
                mutex_unlock(&bufp->lock);
                break;
            }
        }

        fetch.len = count;
        if (copy_to_user((void *)ptr, (void *)&fetch, sizeof(fetch))) {
            ret = -EINVAL;
            goto out;
        }

        ret = 0;
        break;
    
    case SPR_IOCTL_READ_BUFFER_COUNT_INFO:
        memset(&cinfo, 0, sizeof(cinfo));
        for_each_present_cpu(cpu) {
            bufp = &per_cpu(buffer, cpu);
            mutex_lock(&bufp->lock);
            cinfo.event_count += bufp->event_count;
            cinfo.unflushed_count += bufp->info->nevents;
            cinfo.unflushed_len += bufp->info->tail;
            mutex_unlock(&bufp->lock);
        }

        if (copy_to_user((void *)arg, (void *)&cinfo, sizeof(cinfo))) {
            ret = -EINVAL;
            goto out;
        }
        break;
    case SPR_IOCTL_STOP_RECORDING:
        restore_syscall();

        pr_info("proc: Stop recording");
        break;
    case SPR_IOCTL_START_RECORDING:
        hook_syscall();

        pr_info("proc: Start recording");
        break;
    case SPR_IOCTL_EXIT_MONITOR:
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
        if (security.fd >= 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
            ksys_close(security.fd);
#else
            sys_close(security.fd);
#endif
            spr_set_status_out(current);
            spr_release_mm(current);
        }

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

void proc_destory(void) {
    if (ent) {
        proc_remove(ent);
    }
}
