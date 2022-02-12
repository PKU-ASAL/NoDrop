#include <linux/init.h>
#include <linux/module.h>

#include "pinject.h"

MODULE_LICENSE("GPL");

static int pinject_init(void)
{
    int err;

    if ((err = loader_init())) {
        pr_err("load monitor failed (%d)\n", err);
        goto out_loader;
    }

    if ((err = event_buffer_init())) {
        pr_err("buffer initialization failed (%d)\n", err);
        goto out_buffer;
    }

    if((err = hook_init())) {
        pr_err("hook syscall_table failed (%d)\n", err);
        goto out_hook;
    }

    if ((err = proc_init())) {
        pr_err("create proc failed (%d)\n", err);
        goto out_proc;
    }

    err = 0;
out:
    return err;

out_proc:
    proc_destroy();
out_hook:
    hook_destory();
out_buffer:
    event_buffer_destory();
out_loader:
    loader_destory();
    goto out;
}

static void pinject_exit(void)
{
    loader_destory();
    event_buffer_destory();
    hook_destory();
    proc_destroy();
}

module_init(pinject_init);
module_exit(pinject_exit);