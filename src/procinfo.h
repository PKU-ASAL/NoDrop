#ifndef PROCINFO_H_
#define PROCINFO_H_

#include <linux/ptrace.h>
#include <linux/limits.h>
#include <linux/signal.h>

#include "events.h"
#include "common.h"

enum nod_proc_status {
    NOD_UNKNOWN = 0,
	NOD_IN = 1,
	NOD_OUT = 2,
	NOD_RESTORE = 3,
};

struct nod_proc_context {
	struct pt_regs regs;
	unsigned long fsbase;
	unsigned long gsbase;

	/* Following item should be switched in kernel */
	unsigned int seccomp_mode;
	sigset_t sigset;
	kernel_cap_t cap_permitted;
	kernel_cap_t cap_effective;
	struct path root_path;
	struct rlimit rlim[RLIM_NLIMITS];
};

struct nod_proc_info {
	struct rb_node node;
	pid_t pid;
	int ioctl_fd;
	enum nod_proc_status status;
	struct nod_proc_context ctx;
	struct nod_kbuffer buffer;
	struct nod_stack_info stack;
};

#define nod_set_in(task, buffer)    nod_set_status(NOD_IN, -1, buffer, task)
#define nod_set_out(task)           nod_set_status(NOD_OUT, -1, NULL, task)
#define nod_set_restore(task, fd)   nod_set_status(NOD_RESTORE, fd, NULL, task)

#endif //PROCINFO_H_