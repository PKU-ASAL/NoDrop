#include <linux/init.h>
#include <linux/module.h>

#include "nodrop.h"

MODULE_LICENSE("GPL");

static int nodrop_init(void)
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

    if ((err = trace_register_init())) {
        pr_err("register trace failed (%d)\n", err);
        goto out_trace;
    }

    if ((err = procinfo_init())) {
        pr_err("procinfo initialization failed (%d)\n", err);
        goto out_procinfo;
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
out_procinfo:
    procinfo_destroy();
out_trace:
    trace_register_destory();
out_buffer:
    event_buffer_destory();
out_loader:
    loader_destory();
    goto out;
}

static void nodrop_exit(void)
{
    loader_destory();
    event_buffer_destory();
    trace_register_destory();
    procinfo_destroy();
    hook_destory();
    proc_destroy();
}

module_init(nodrop_init);
module_exit(nodrop_exit);