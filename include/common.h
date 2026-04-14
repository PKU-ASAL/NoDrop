#ifndef _COMMON_H_
#define _COMMON_H_


#include "events.h"

#ifdef __KERNEL__
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#include <linux/capability.h>
#include <linux/limits.h>
#else
#include "config.h"
#include <sys/resource.h>
#include <stdint.h>

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

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
#define NOD_MONITOR_MEM_SIZE (1024 * 1024)

#define SECOND_IN_NS 1000000000 // 1s = 1e9ns
#define SECOND_IN_US 1000000 // 1s=1e6us
#define NS_TO_SEC(_ns) ((_ns) / SECOND_IN_NS)

struct nod_stack_info {
	int ioctl_fd;
	int pkey;
	int syscall_nr;
	long exit_code;
	unsigned long fsbase;
	unsigned long hash;
	uint64_t stack_start;
	uint64_t stack_end;
#ifdef __KERNEL__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	uint64_t stack_addr;
	uint64_t stack_info_addr;
#endif
#else
#if CONFIG_LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	uint64_t stack_addr;
	uint64_t stack_info_addr;
#endif
#endif
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
#ifdef __KERNEL__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	return stack->fsbase ^ (stack->ioctl_fd + 42) ^ (stack->pkey - 42) ^ 
		(unsigned long)stack->buffer ^ (unsigned long)stack->buffer_info ^
		(unsigned long)stack->stack_start ^ (unsigned long)stack->stack_end
		^ (unsigned long)stack->stack_addr ^ (unsigned long)stack->stack_info_addr
		;
#else
	return stack->fsbase ^ (stack->ioctl_fd + 42) ^ (stack->pkey - 42) ^ 
		(unsigned long)stack->buffer ^ (unsigned long)stack->buffer_info;
#endif
#else
#if CONFIG_LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	return stack->fsbase ^ (stack->ioctl_fd + 42) ^ (stack->pkey - 42) ^ 
		(unsigned long)stack->buffer ^ (unsigned long)stack->buffer_info ^
		(unsigned long)stack->stack_start ^ (unsigned long)stack->stack_end
		^ (unsigned long)stack->stack_addr ^ (unsigned long)stack->stack_info_addr
		;
#else
	return stack->fsbase ^ (stack->ioctl_fd + 42) ^ (stack->pkey - 42) ^ 
		(unsigned long)stack->buffer ^ (unsigned long)stack->buffer_info;
#endif
#endif
}

#endif //_COMMON_H_
