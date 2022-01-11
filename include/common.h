#ifndef _COMMON_H_
#define _COMMON_H_

#include <linux/ptrace.h>
#ifdef __KERNEL__
#include <linux/syscalls.h>
#else
#include <sys/syscall.h>
#endif

#define MAX_LOG_LENGTH  128
#define MAX_LOG_NR		32
#define MAX_LOG_BUFFER_SIZE (MAX_LOG_LENGTH * MAX_LOG_NR)
 
#define _DO_EXIT(nr)		((nr) == __NR_exit)
#define _DO_EXIT_GROUP(nr) 	((nr) == __NR_exit_group)
#define DO_EXIT(nr)     	(_DO_EXIT(nr) || _DO_EXIT_GROUP(nr))

#define likely(x) 	__builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

struct context_struct {
	struct pt_regs reg;
	unsigned long fsbase;
	unsigned long gsbase;	
};

struct logmsg_block {
	int nr;
	char buf[MAX_LOG_BUFFER_SIZE];
};

typedef struct {
	int m_enter;
	struct context_struct m_context;
	struct logmsg_block m_logmsg;
} m_infopack;

#endif //_COMMON_H_