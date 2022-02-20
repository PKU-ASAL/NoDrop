#include "include/events.h"

const struct spr_param_info sockopt_dynamic_param[SPR_SOCKOPT_IDX_MAX] = {
	[SPR_SOCKOPT_IDX_UNKNOWN] = {{0}, PT_BYTEBUF, PF_HEX},
	[SPR_SOCKOPT_IDX_ERRNO] = {{0}, PT_ERRNO, PF_DEC},
	[SPR_SOCKOPT_IDX_UINT32] = {{0}, PT_UINT32, PF_DEC},
	[SPR_SOCKOPT_IDX_UINT64] = {{0}, PT_UINT64, PF_DEC},
	[SPR_SOCKOPT_IDX_TIMEVAL] = {{0}, PT_RELTIME, PF_DEC},
};