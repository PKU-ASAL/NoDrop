#ifndef _COMMON_H_
#define _COMMON_H_

#define MAX_LOG_LENGTH 128

struct context_struct {
	struct pt_regs reg;
	unsigned long eid;
	unsigned long fsbase;
	unsigned long gsbase;	
};

#endif //_COMMON_H_