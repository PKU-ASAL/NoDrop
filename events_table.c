#include "include/events.h"
#include "pinject.h"

const struct spr_event_info g_event_info[SPRE_EVENT_MAX] = {
	[SPRE_GENERIC] = {"syscall", EC_OTHER, EF_NONE, 1, {{"ID", PT_SYSCALLID, PF_DEC} } },
	[SPRE_SYSCALL_OPEN] = {"open", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"name", PT_FSPATH, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT}, {"dev", PT_UINT32, PF_HEX} } },
	[SPRE_SYSCALL_CLOSE] = {"close", EC_IO_OTHER, EF_DESTROYS_FD | EF_USES_FD | EF_MODIFIES_STATE | EF_DROP_SIMPLE_CONS, 2, {{"fd", PT_FD, PF_DEC}, {"res", PT_ERRNO, PF_DEC} } },
	[SPRE_SYSCALL_READ] = {"read", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	[SPRE_SYSCALL_WRITE] = {"write", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
    [SPRE_SYSCALL_EXIT] = {"exit", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"code", PT_INT32, PF_DEC}}},
    [SPRE_SYSCALL_EXIT_GROUP] = {"exit_group", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"code", PT_INT32, PF_DEC}}},
};
