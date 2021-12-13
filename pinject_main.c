#include <linux/init.h>
#include <linux/module.h>

#include "pinject.h"

MODULE_LICENSE("GPL");

static int pinject_init(void)
{
    int err;

    // // register kprobe
    // if((err = kprobe_init()))
    // {
    //     printk(KERN_ERR "kprobe init failed (%d)\n", err);
    //     return err;
    // }

    if((err = hock_init())) {
        printk(KERN_ERR "hock syscall_table failed (%d)\n", err);
        goto out;
    }

    err = loader_init();
    if (err) {
        printk(KERN_ERR "load monitor failed (%d)\n", err);
        goto out;
    }

    err = 0;

out:
    return err;
}

static void pinject_exit(void)
{
    // kprobe_destroy();
    loader_destory();
    hock_destory();
}

module_init(pinject_init);
module_exit(pinject_exit);