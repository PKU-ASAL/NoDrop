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

    if ((err = procinfo_init())) {
        pr_err("procinfo initialization failed (%d)\n", err);
        goto out_procinfo;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
    if ((err = nod_daemon_init())) {
        pr_err("daemon initialization failed (%d)\n", err);
        goto out_daemon;
    }
#endif
    if((err = tracepoint_init())) {
        pr_err("hook syscall_table failed (%d)\n", err);
        goto out_trace;
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
out_trace:
    tracepoint_destory();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
    nod_daemon_destroy();
out_daemon:
#endif
out_procinfo:
    procinfo_destroy();
out_loader:
    loader_destory();
    goto out;
}

static void nodrop_exit(void)
{
    proc_destroy();
    tracepoint_destory();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
    nod_daemon_destroy();
#endif
    procinfo_destroy();
    loader_destory();
    pr_info("NoDrop: Uninstalled\n");
}

module_init(nodrop_init);
module_exit(nodrop_exit);