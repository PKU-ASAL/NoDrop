#ifndef _COMMON_H_
#define _COMMON_H_

#include <linux/ptrace.h>
#include <linux/capability.h>
#include <linux/limits.h>

#include "events.h"

#ifdef __KERNEL__
#include <linux/syscalls.h>
#include <linux/signal.h>
#else
#include <sys/resource.h>
#include <stdint.h>
#endif
 
#define SYSCALL_EXIT_FAMILY(nr)     	((nr) == __NR_exit || (nr) == __NR_exit_group)

#define likely(x) 	__builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

struct nod_stack_info {
	int come;
	long nr;
	long code;
	unsigned long fsbase;
	char *mem;
	struct nod_buffer *buffer;
};

#endif //_COMMON_H_