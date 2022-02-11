#ifndef _COMMON_H_
#define _COMMON_H_


#ifdef __KERNEL__
#include <linux/syscalls.h>
#include <linux/time.h>
#endif

#define MAX_LOG_LENGTH  128
#define MAX_LOG_NR		1024
 
#define SYSCALL_EXIT_FAMILY(nr)     	((nr) == __NR_exit || (nr) == __NR_exit_group)

#define likely(x) 	__builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

struct context_struct {
	struct pt_regs reg;
	unsigned long fsbase;
	unsigned long gsbase;	
};

// typedef struct {
// 	struct pt_regs reg;
// 	struct timeval timestamp;
// 	long who;
// 	unsigned int cpu;
// 	unsigned long id;
// } __attribute__((packed)) event_data_t;


// struct logmsg_block {
// 	event_data_t log_buf[MAX_LOG_NR];
// 	int nr;
// 	unsigned long total;
// };

// #ifdef __KERNEL__
// struct klogmsg_block {
// 	event_data_t *log_buf;
// 	int nr;
// 	unsigned long total;
// };
// #endif //__KERNEL__

typedef struct {
	int m_enter;
	struct context_struct m_context;
	struct spr_buffer m_buffer;
} m_infopack;

#endif //_COMMON_H_