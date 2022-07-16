#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/mman.h>

#include "nodrop.h"
#include "procinfo.h"

#include "config.h"
#include "common.h"
#include "events.h"
#include "ioctl.h"

#define BUFSIZE 30

static struct proc_dir_entry *ent;

static int nod_dev_open(struct inode *inode, struct file *filp)
{
    struct nod_proc_info *p;
    
    nod_event_from(&p);
    filp->private_data = (void *)p;
    return 0;
}

static int
__proc_buf_reset(struct nod_proc_info *this, unsigned long *ret, va_list args)
{
    down_read(&this->buffer.sem);
    reset_buffer(&this->buffer, NOD_INIT_INFO | NOD_INIT_COUNT);
    up_read(&this->buffer.sem);
    return NOD_PROC_TRAVERSE_CONTINUE;
}

static int
__proc_bufcount_read(struct nod_proc_info *this, unsigned long *ret, va_list args)
{
    struct nod_buffer *buf = &this->buffer;
    struct buffer_count_info *info = va_arg(args, struct buffer_count_info *);
    down_read(&buf->sem);
    info->event_count += buf->event_count;
    info->unflushed_count += buf->info->nevents;
    info->unflushed_len += buf->info->tail; 
    up_read(&buf->sem);
    return NOD_PROC_TRAVERSE_CONTINUE;
}

static ssize_t
nod_dev_read(struct file *filp, char __user *buf, size_t count, loff_t *off) {
    int len = 0;
    struct buffer_count_info buf_info;
    char kbuf[BUFSIZE];

    if (*off > 0 || count < BUFSIZE)
        return 0;

    memset(&buf_info, 0, sizeof(buf_info));
    nod_proc_traverse(__proc_bufcount_read, &buf_info);

    len += sprintf(kbuf, "%llu", buf_info.event_count);
    if (copy_to_user(buf, kbuf, len))
        return -EFAULT;
    
    *off = len;
    return len;
}

static int
__proc_buf_copy(struct nod_proc_info *this, unsigned long *ret, va_list args)
{
    struct nod_buffer *buf = &this->buffer;
    char **ptr = va_arg(args, char **);
    uint64_t *count = va_arg(args, uint64_t *);
    uint64_t len = va_arg(args, uint64_t);

    down_read(&buf->sem);
    if (*count + buf->info->tail <= len) {
        if (copy_to_user((void *)*ptr, (void *)buf->buffer, buf->info->tail)) {
            up_read(&buf->sem);
            *ret = -EFAULT;
            return NOD_PROC_TRAVERSE_BREAK;
        }
        *ptr += buf->info->tail;
        *count += buf->info->tail;
        up_read(&buf->sem);
        *ret = 0;
        return NOD_PROC_TRAVERSE_CONTINUE;
    } else {
        up_read(&buf->sem);
        *ret = 0;
        return NOD_PROC_TRAVERSE_BREAK;
    }
}

static long 
nod_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret;
    uint64_t count;
    char *ptr;
    struct buffer_count_info cinfo;
    struct fetch_buffer_struct fetch;
    struct nod_stack_info stack;
    struct nod_proc_info *p = filp->private_data;

    switch(cmd) {
    case NOD_IOCTL_CLEAR_BUFFER:
        nod_proc_traverse(__proc_buf_reset);

        pr_info("proc: clean buffer");
        break;
        
    case NOD_IOCTL_FETCH_BUFFER:
        if (nod_copy_from_user((void *)&fetch, (void *)arg, sizeof(fetch))) {
            ret = -EFAULT;
            goto out;
        }

        count = 0;
        ptr = fetch.buf;
        ret = nod_proc_traverse(__proc_buf_copy, &ptr, &count, fetch.len);
        if (ret) {
            goto out;
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
        nod_proc_traverse(__proc_bufcount_read, &cinfo);

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
    case NOD_IOCTL_RESTORE_CONTEXT:
        if (!p || p->status != NOD_IN || p->pid != current->pid) {
            ret = -ENODEV;
            goto out;
        }

        if (nod_copy_from_user(&stack, (void __user *)arg, sizeof(stack))) {
            ret = -EFAULT;
            goto out;
        }

        if (stack.hash != nod_calc_hash(&stack)) {
            vpr_err("inconsistent stack info hash %lx (dumped)\n", stack.hash);
            memory_dump((char *)&stack, sizeof(stack));
            ret = -EINVAL;
            goto out;
        }

        memcpy(&p->stack, &stack, sizeof(stack));

        if(cmd == NOD_IOCTL_RESTORE_CONTEXT) 
            nod_proc_set_context(p, p->stack.ioctl_fd);
        else
            nod_proc_set_security(p, p->stack.ioctl_fd);
            
        p->stack.ioctl_fd = -1;

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
    long length;
    struct nod_proc_info *p;

    p = filp->private_data;
    if (!p || p->status != NOD_IN) {
        return -ENODEV;
    }

    if (vma->vm_pgoff != 0) {
        vpr_err("invalid pgoff %lu, must be 0\n", vma->vm_pgoff);
        return -EIO;
    }
    
    length = vma->vm_end - vma->vm_start;
    if (length <= PAGE_SIZE) {
        ret = remap_vmalloc_range(vma, p->buffer.info, 0);
        if (ret < 0) {
            vpr_err("remap_vmalloc_range for buffer info failed (%d)\n", ret);
            return ret;
        }
    } else if (length == BUFFER_SIZE) {
        if (vma->vm_flags & VM_WRITE) {
            vpr_err("invalid mmap flags 0x%lx\n", vma->vm_flags);
            return -EINVAL;
        }

        ret = remap_vmalloc_range(vma, p->buffer.buffer, 0);
        if (ret < 0) {
            vpr_err("remap_vmalloc_range for buffer failed (%d)\n", ret);
            return ret;
        }
    } else {
        vpr_err("invalid mmap size %ld\n", length);
        return -EIO;
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
