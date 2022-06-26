#include "events.h"

const struct nod_param_info sockopt_dynamic_param[NOD_SOCKOPT_IDX_MAX] = {
	[NOD_SOCKOPT_IDX_UNKNOWN] = {{0}, PT_BYTEBUF, PF_HEX},
	[NOD_SOCKOPT_IDX_ERRNO] = {{0}, PT_ERRNO, PF_DEC},
	[NOD_SOCKOPT_IDX_UINT32] = {{0}, PT_UINT32, PF_DEC},
	[NOD_SOCKOPT_IDX_UINT64] = {{0}, PT_UINT64, PF_DEC},
	[NOD_SOCKOPT_IDX_TIMEVAL] = {{0}, PT_RELTIME, PF_DEC},
};

const struct nod_param_info ptrace_dynamic_param[NOD_PTRACE_IDX_MAX] = {
	[NOD_PTRACE_IDX_UINT64] = {{0}, PT_UINT64, PF_HEX},
	[NOD_PTRACE_IDX_SIGTYPE] = {{0}, PT_SIGTYPE, PF_DEC},
};

const struct nod_param_info bpf_dynamic_param[NOD_BPF_IDX_MAX] = {
	[NOD_BPF_IDX_FD] = {{0}, PT_FD, PF_DEC},
	[NOD_BPF_IDX_RES] = {{0}, PT_ERRNO, PF_DEC},
};