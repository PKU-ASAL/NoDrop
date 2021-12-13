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
        return err;
    }

    return 0;
}

static void pinject_exit(void)
{
    // kprobe_destroy();
    hock_destory();
}

module_init(pinject_init);
module_exit(pinject_exit);