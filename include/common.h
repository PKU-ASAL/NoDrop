#ifndef _COMMON_H_
#define _COMMON_H_

#include <linux/ptrace.h>
#include <linux/capability.h>
#include <linux/limits.h>

#include "events.h"

#ifdef __KERNEL__
#include <linux/syscalls.h>
#include <linux/time.h>
#else
#include <sys/resource.h>
#include <stdint.h>
#endif


#define SYSCALL_EXIT_FAMILY(nr)     	((nr) == __NR_exit || (nr) == __NR_exit_group)

#define likely(x) 	__builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)


struct security_data {
	unsigned long fsbase;
	unsigned long gsbase;	
	unsigned long sigset;
	uint32_t cap_permitted[_LINUX_CAPABILITY_U32S_3];
	uint32_t cap_effective[_LINUX_CAPABILITY_U32S_3];
	unsigned int seccomp_mode;
	int fd;
};

struct context_struct {
	struct pt_regs regs;
	struct rlimit rlim[3];
};

typedef struct {
	struct context_struct m_context;
	struct spr_buffer m_buffer;
} m_infopack;

#endif //_COMMON_H_