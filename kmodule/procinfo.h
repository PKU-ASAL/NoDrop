#ifndef PROCINFO_H_
#define PROCINFO_H_

#include <linux/ptrace.h>
#include <linux/limits.h>
#include <linux/signal.h>
#include <linux/hashtable.h>

#include "events.h"
#include "common.h"

enum nod_proc_status {
    NOD_UNKNOWN = 0,
	NOD_IN = 1,
	NOD_OUT = 2,
	NOD_CLONE = 3,
	NOD_SHARE = 4,
	NOD_RESTORE_CONTEXT = 5,
	NOD_RESTORE_SECURITY = 6,
};

struct nod_proc_context {
	int available;
	unsigned long fsbase;
	unsigned long gsbase;
	struct pt_regs regs;
};

struct nod_proc_security {
	int available;
	/* Following item should be switched in kernel */
	unsigned long child_tid;
	unsigned int seccomp_mode;
	sigset_t sigset;
	kernel_cap_t cap_permitted;
	kernel_cap_t cap_effective;
	struct path root_path;
	struct rlimit rlim[RLIM_NLIMITS];
};

struct nod_proc_info {
	struct hlist_node rcu;
	pid_t pid;
	struct mm_struct *mm;
	struct nod_buffer buffer;
	int ioctl_fd;
	unsigned long load_addr;
	enum nod_proc_status status;
	struct nod_proc_context ctx;
	struct nod_proc_security sec;
	struct nod_stack_info stack;
};

#define nod_proc_set_in(proc)			nod_proc_set_status(proc, NOD_IN, -1)
#define nod_proc_set_out(proc)			nod_proc_set_status(proc, NOD_OUT, -1)
#define nod_proc_set_security(proc, fd)	nod_proc_set_status(proc, NOD_RESTORE_SECURITY, fd)
#define nod_proc_set_context(proc, fd)	nod_proc_set_status(proc, NOD_RESTORE_CONTEXT, fd)
#define nod_proc_set_status(proc, _status, _fd) \
	do{(proc)->status = (_status); (proc)->ioctl_fd = (_fd);}while(0)

#define NOD_PROC_TRAVERSE_CONTINUE  0
#define NOD_PROC_TRAVERSE_BREAK 	1

#endif //PROCINFO_H_