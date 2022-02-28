#include <linux/init.h>
#include <linux/module.h>

#include "pinject.h"

MODULE_LICENSE("GPL");

static int pinject_init(void)
{
    int err;

    if ((err = loader_init())) {
        pr_err("load monitor failed (%d)\n", err);
        goto err;
    }

    if ((err = event_buffer_init())) {
        pr_err("buffer initialization failed (%d)\n", err);
        goto err_loader;
    }

    if ((err = proc_init())) {
        pr_err("create proc failed (%d)\n", err);
        goto err_buffer;
    }

    if ((err = trace_register_init())) {
        pr_err("register trace failed (%d)\n", err);
        goto err_proc;
    }

    if((err = hook_init())) {
        pr_err("hook syscall_table failed (%d)\n", err);
        goto err_trace;
    }

    err = 0;
out:
    return err;

err_trace:
    trace_register_destory();
err_proc:
    proc_destory();
err_buffer:
    event_buffer_destory();
err_loader:
    loader_destory();
err:
    goto out;
}

static void pinject_exit(void)
{
    hook_destory();
    trace_register_destory();
    proc_destory();
    event_buffer_destory();
    loader_destory();
}

module_init(pinject_init);
module_exit(pinject_exit);