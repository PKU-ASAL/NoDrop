#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/signal.h>
#include <asm/prctl.h>
#include <asm/proto.h>

#include "nodrop.h"
#include "common.h"
#include "events.h"
#include "ioctl.h"


#define BUFSIZE 30

static struct proc_dir_entry *ent;
typedef struct  {
    int status;
} nod_private_data_t;

static int nod_procopen(struct inode *inode, struct file *filp)
{
    int ret;
    int status = event_from_monitor();
    nod_private_data_t *private;

    if (status == NOD_EVENT_FROM_APPLICATION || status == NOD_EVENT_FROM_MONITOR) {
        private = vmalloc(sizeof(nod_private_data_t));
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
nod_procread(struct file *filp, char __user *buf, size_t count, loff_t *off) {
    int len = 0;
    unsigned int event_id, cpu;
    char kbuf[BUFSIZE];

    if (*off > 0 || count < BUFSIZE)
        return 0;

    event_id = 0;
    for_each_present_cpu(cpu) {
        struct nod_kbuffer *bufp = &per_cpu(buffer, cpu);
        down_read(&bufp->sem);
        event_id += bufp->event_count;
        up_read(&bufp->sem);
    }

    len += sprintf(kbuf, "%u", event_id);
    if (copy_to_user(buf, kbuf, len))
        return -EFAULT;
    
    *off = len;
    return len;
}

static long 
nod_procioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret;
    uint64_t count;
    unsigned int cpu;
    char *ptr;
    struct security_data security;
    struct nod_kbuffer *bufp;
    struct buffer_count_info cinfo;
    struct fetch_buffer_struct fetch;
    nod_private_data_t *private = filp->private_data;
    sigset_t sigset;


    switch(cmd) {
    case NOD_IOCTL_CLEAR_BUFFER:
        for_each_present_cpu(cpu) {
            bufp = &per_cpu(buffer, cpu);
            down_write(&bufp->sem);
            reset_buffer(bufp, NOD_INIT_INFO | NOD_INIT_COUNT);
            up_write(&bufp->sem);
        }

        pr_info("proc: clean buffer");
        break;
        
    case NOD_IOCTL_FETCH_BUFFER:
        if (nod_copy_from_user((void *)&fetch, (void *)arg, sizeof(fetch))) {
            ret = -EINVAL;
            goto out;
        }
        count = 0;
        ptr = fetch.buf;
        for_each_present_cpu(cpu) {
            bufp = &per_cpu(buffer, cpu);
            down_read(&bufp->sem);
            if (count + bufp->info->tail <= fetch.len) {
                if (copy_to_user((void *)ptr, (void *)bufp->buffer, bufp->info->tail)) {
                    up_read(&bufp->sem);
                    ret = -EFAULT;
                    goto out;
                }
                ptr += bufp->info->tail;
                count += bufp->info->tail;
                up_read(&bufp->sem);
            } else {
                up_read(&bufp->sem);
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
    
    case NOD_IOCTL_READ_BUFFER_COUNT_INFO:
        memset(&cinfo, 0, sizeof(cinfo));
        for_each_present_cpu(cpu) {
            bufp = &per_cpu(buffer, cpu);
            down_read(&bufp->sem);
            cinfo.event_count += bufp->event_count;
            cinfo.unflushed_count += bufp->info->nevents;
            cinfo.unflushed_len += bufp->info->tail;
            up_read(&bufp->sem);
        }

        if (copy_to_user((void *)arg, (void *)&cinfo, sizeof(cinfo))) {
            ret = -EINVAL;
            goto out;
        }
        break;
    case NOD_IOCTL_STOP_RECORDING:
        restore_syscall();

        pr_info("proc: Stop recording");
        break;
    case NOD_IOCTL_START_RECORDING:
        hook_syscall();

        pr_info("proc: Start recording");
        break;
    case NOD_IOCTL_RESTORE_SECURITY:
        if (private->status != NOD_EVENT_FROM_MONITOR) {
            ret = -EINVAL;
            goto out;
        }

        if (copy_from_user(&security, (void __user *)arg, sizeof(security))) {
            ret = -EFAULT;
            goto out;
        }

        if ((ret = nod_enable_seccomp(security.seccomp_mode))) 
            goto out;

        nod_write_gsbase(security.gsbase);
        nod_write_fsbase(security.fsbase);
        nod_cap_capset(security.cap_permitted, security.cap_effective);

        sigset.sig[0] = security.sigset;
        sigprocmask(SIG_SETMASK, &sigset, 0);

        break;
    default:
        ret = -ENOTTY;
        goto out;
    }

    ret = 0;

out:
    return ret;
}

static int nod_procrelease(struct inode *inode, struct file *filp)
{
    vfree(filp->private_data);
    return 0;
}

static const struct file_operations g_nod_fops = {
    .open = nod_procopen,
    .read = nod_procread,
    .unlocked_ioctl = nod_procioctl,
    .release = nod_procrelease,
    .owner = THIS_MODULE
};

int proc_init(void) {
    int ret;

    ent = proc_create(NOD_IOCTL_NAME, 0666, NULL, &g_nod_fops);

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
