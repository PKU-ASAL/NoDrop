#ifndef _COMMON_H_
#define _COMMON_H_

struct context_struct {
	struct pt_regs reg;
	unsigned long fsbase;
	unsigned long gsbase;	
};

#endif //_COMMON_H_