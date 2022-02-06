#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "pinject.h"

#define BUFSIZE 30

extern unsigned int event_id;
static struct proc_dir_entry *ent;

static ssize_t
pinject_read(struct file *filp, char __user *buf, size_t count, loff_t *off) {
    int len = 0;
    char kbuf[BUFSIZE];

    if (*off > 0 || count < BUFSIZE)
        return 0;

    len += sprintf(kbuf, "%u", event_id);
    if (copy_to_user(buf, kbuf, len))
        return -EFAULT;
    
    *off = len;
    return len;
}

static ssize_t
pinject_write(struct file *filp, const char __user *buf, size_t count, loff_t *off) {
    char kbuf[BUFSIZE];
    int op;
    if (*off > 0 || count > BUFSIZE)
        return -EFAULT;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    if (sscanf(kbuf, "%d", &op) != 1)
        return -EFAULT;

    if (op == 0) { //clean
        pr_info("proc.c: clean event_id = %d\n", event_id);
        event_id = 0;
    } else if (op == 1) {
        pr_info("proc.c: hook syscall\n");
        hook_syscall();
    } else if (op == 2) {
        pr_info("proc.c: release syscall hook\n");
        restore_syscall();
    } else {
        return -EINVAL;
    }

    count = strlen(kbuf);
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