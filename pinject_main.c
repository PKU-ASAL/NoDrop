#include <linux/init.h>
#include <linux/module.h>

#include "pinject.h"

MODULE_LICENSE("GPL");

static int pinject_init(void)
{
    int err;

    if ((err = loader_init())) {
        printk(KERN_ERR "load monitor failed (%d)\n", err);
        goto out;
    }

    if((err = hook_init())) {
        printk(KERN_ERR "hook syscall_table failed (%d)\n", err);
        goto out_hook;
    }

    if ((err = proc_init())) {
        printk(KERN_ERR "create proc failed (%d)\n", err);
        goto out_proc;
    }

    err = 0;
out:
    return err;

out_proc:
    hook_destory();
out_hook:
    loader_destory();
    goto out;
}

static void pinject_exit(void)
{
    proc_destroy();
    loader_destory();
    hook_destory();
}

module_init(pinject_init);
module_exit(pinject_exit);