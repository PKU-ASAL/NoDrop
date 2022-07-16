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

#define weak __attribute__((__weak__))
#define hidden __attribute__((__visibility__("hidden")))
#define weak_alias(old, new) \
	extern __typeof(old) new __attribute__((__weak__, __alias__(#old)))
#endif
 
#define SYSCALL_EXIT_FAMILY(nr)     	((nr) == __NR_exit || (nr) == __NR_exit_group)

#define likely(x) 	__builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define NOD_MEM_RND_MASK 0x7ff
#define NOD_SECTION_NAME ".monitor.info"
#define NOD_MONITOR_MEM_SIZE (4 * 1024)

struct nod_stack_info {
	int ioctl_fd;
	int pkey;
	int nr;
	long code;
	unsigned long fsbase;
	unsigned long hash;
	char *buffer;
	struct nod_buffer_info *buffer_info;
};

struct nod_monitor_info {
	unsigned long fsbase;
};

__attribute__((unused))
static unsigned long 
nod_calc_hash(struct nod_stack_info *stack)
{
	return stack->fsbase ^ (stack->ioctl_fd + 42) ^ (stack->pkey - 42) ^ 
		(unsigned long)stack->buffer ^ (unsigned long)stack->buffer_info;
}

#endif //_COMMON_H_