#ifndef _COMMON_H_
#define _COMMON_H_


#include "events.h"

#ifdef __KERNEL__
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#include <linux/capability.h>
#include <linux/limits.h>
#else
#include <sys/resource.h>
#include <stdint.h>
#endif
 
#define SYSCALL_EXIT_FAMILY(nr)     	((nr) == __NR_exit || (nr) == __NR_exit_group)

#define likely(x) 	__builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define NOD_MEM_RND_MASK 0x7ff
#define NOD_SECTION_NAME ".monitor.info"

struct nod_stack_info {
	int ioctl_fd;
	int nr;
	int pkey;
	long code;
	unsigned long fsbase;
	unsigned long memoff;
	unsigned long memsz;
	char *mem;
	unsigned long hash;
};

struct nod_monitor_info {
	unsigned long fsbase;
};

__attribute__((unused))
static unsigned long 
nod_calc_hash(struct nod_stack_info *stack)
{
	return stack->fsbase ^ (stack->ioctl_fd + 42) ^ 
		(unsigned long)stack->mem ^ stack->memoff ^ stack->memsz;
}

#endif //_COMMON_H_