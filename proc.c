#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "pinject.h"
#include "include/common.h"
#include "include/events.h"

#define BUFSIZE 30

static struct proc_dir_entry *ent;

static ssize_t
pinject_read(struct file *filp, char __user *buf, size_t count, loff_t *off) {
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

static ssize_t
pinject_write(struct file *filp, const char __user *buf, size_t count, loff_t *off) {
    int i;
    unsigned int cpu;
    struct spr_kbuffer *bufp;
    char kbuf[BUFSIZE];

    if (*off > 0 || count > BUFSIZE)
        return -EINVAL;

    if (copy_from_user(kbuf, buf, count))
        return -EINVAL;
    
    for (i = count - 1; i >= 0;) {
        if (kbuf[i] == '\n' || kbuf[i] == '\t' || kbuf[i] == '\r') {
            kbuf[i--] = 0;
            continue;
        }
        break;
    }

    if (!strcmp(kbuf, "clean")) { //clean
        pr_info("proc.c: clean event_id\n");
        for_each_possible_cpu(cpu) {
            bufp = &per_cpu(buffer, cpu);
            mutex_lock(&bufp->lock);
            reset_buffer(bufp, 1, 0);
            mutex_unlock(&bufp->lock);
        }
    } else if (!strcmp(kbuf, "hook")) {
        pr_info("proc.c: hook syscall\n");
        hook_syscall();
    } else if (!strcmp(kbuf, "release")) {
        pr_info("proc.c: release syscall hook\n");
        restore_syscall();
    } else {
        pr_info("proc.c: invalid op \"%s\"\n", kbuf);
        return -EINVAL;
    }

    *off = count;
    return count;
}

static const struct file_operations fops = {
    .read = pinject_read,
    .write = pinject_write,
    .owner = THIS_MODULE
};

int proc_init(void) {
    ent = proc_create("pinject", 0666, NULL, &fops);
    return 0;
}

void proc_destroy(void) {
    proc_remove(ent);
}