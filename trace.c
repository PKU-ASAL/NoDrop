#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>

#include "pinject.h"


#define KPROBE_REGISTER(kp) register_kprobe(kp)
#define KPROBE_UNREGISTER(kp) unregister_kprobe(kp)
#define KPROBE_PRE_DEFINE(probe, args...) static int probe(struct kprobe *__kp, args)

KPROBE_PRE_DEFINE(procexit_handler_pre, struct pt_regs *regs);
static struct kprobe procexit_kp = {
    .symbol_name = "do_exit",
	.pre_handler = procexit_handler_pre
};

KPROBE_PRE_DEFINE(procexit_handler_pre, struct pt_regs *regs)
{
	struct task_struct *p = current;

#ifdef SPR_TEST
    SPR_TEST(p) {
        return 0;
    }
#endif

	vpr_dbg("procexit %d\n", p->pid);
	if (spr_erase_status(p) == SPR_MONITOR_IN)
        spr_release_mm(p);
    return 0;
}

static int compat_register_kprobe(struct kprobe *kp)
{
	return KPROBE_REGISTER(kp);
}

static void compat_unregister_kprobe(struct kprobe *kp)
{
	KPROBE_UNREGISTER(kp);
}

int trace_register_init(void)
{
    int ret;

	ret = compat_register_kprobe(&procexit_kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
		goto err_procexit;
    }

out:
    return ret;

err_procexit:
    goto out;
}

void trace_register_destory(void)
{
	compat_unregister_kprobe(&procexit_kp);
}
