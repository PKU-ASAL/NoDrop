#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/mman.h>

#include "nodrop.h"
#include "common.h"
#include "events.h"
#include "ioctl.h"
#include "procinfo.h"


#define BUFSIZE 30

static struct proc_dir_entry *ent;

static int nod_dev_open(struct inode *inode, struct file *filp)
{
    struct nod_proc_info *p;
    
    nod_event_from(&p);
    filp->private_data = (void *)p;
    return 0;

}

static ssize_t
nod_dev_read(struct file *filp, char __user *buf, size_t count, loff_t *off) {
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
nod_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret;
    uint64_t count;
    unsigned int cpu;
    char *ptr;
    struct nod_kbuffer *bufp;
    struct buffer_count_info cinfo;
    struct fetch_buffer_struct fetch;
    struct nod_proc_info *p = filp->private_data;

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
            ret = -EFAULT;
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
            ret = -EFAULT;
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
            ret = -EFAULT;
            goto out;
        }
        break;
    case NOD_IOCTL_STOP_RECORDING:
        untrace_syscall();

        pr_info("proc: Stop recording");
        break;
    case NOD_IOCTL_START_RECORDING:
        trace_syscall();

        pr_info("proc: Start recording");
        break;
    case NOD_IOCTL_RESTORE_SECURITY:
        if (!p || p->status != NOD_IN || p->pid != current->pid) {
            ret = -ENODEV;
            goto out;
        }

        if (nod_copy_from_user(&p->stack, (void __user *)arg, sizeof(p->stack))) {
            ret = -EFAULT;
            goto out;
        }

        p->ioctl_fd = p->stack.ioctl_fd;
        p->status = NOD_RESTORE;

        break;
    default:
        ret = -EINVAL;
        goto out;
    }

    ret = 0;

out:
    return ret;
}

static int nod_dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret;
    struct nod_proc_info *p;

    p = filp->private_data;
    if (!p || p->status != NOD_IN) {
        return -ENODEV;
    }

    if (vma->vm_pgoff != 0) {
        pr_err("invalid pgoff %lu, must be 0\n", vma->vm_pgoff);
        return -EINVAL;
    }

    if (vma->vm_flags & VM_WRITE) {
        pr_err("invalid mmap flags 0x%lx\n", vma->vm_flags);
        return -EINVAL;
    }

    ret = remap_vmalloc_range(vma, p->buffer, 0);
    if (ret < 0) {
        pr_err("remap_vmalloc_range failed (%d)\n", ret);
        return ret;
    }

    return 0;
}

static int nod_dev_release(struct inode *inode, struct file *filp)
{
    filp->private_data = NULL;
    return 0;
}

static const struct file_operations g_nod_fops = {
    .open = nod_dev_open,
    .read = nod_dev_read,
    .unlocked_ioctl = nod_dev_ioctl,
    .release = nod_dev_release,
    .mmap = nod_dev_mmap,
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
