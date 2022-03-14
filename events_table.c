#ifdef __KERNEL__
#include "pinject.h"
#include "flags.h"
#endif

#include "events.h"

const struct spr_event_info g_event_info[SPRE_EVENT_MAX] = {
	[SPRE_GENERIC] = {"syscall", EC_OTHER, EF_NONE, 1, {{"ID", PT_SYSCALLID, PF_DEC} } },
	[SPRE_SYSCALL_OPEN] = {"open", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"name", PT_FSPATH, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT}, {"dev", PT_UINT32, PF_HEX} } },
	[SPRE_SYSCALL_CLOSE] = {"close", EC_IO_OTHER, EF_DESTROYS_FD | EF_USES_FD | EF_MODIFIES_STATE | EF_DROP_SIMPLE_CONS, 2, {{"fd", PT_FD, PF_DEC}, {"res", PT_ERRNO, PF_DEC} } },
	[SPRE_SYSCALL_READ] = {"read", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	[SPRE_SYSCALL_WRITE] = {"write", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	[SPRE_SYSCALL_IOCTL] = {"ioctl", EC_IO_OTHER, EF_USES_FD, 4, {{"fd", PT_FD, PF_DEC}, {"cmd", PT_UINT64, PF_HEX}, {"argument", PT_UINT64, PF_HEX}, {"res", PT_ERRNO, PF_DEC} } },
    [SPRE_SYSCALL_EXIT] = {"exit", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"code", PT_INT32, PF_DEC}}},
    [SPRE_SYSCALL_EXIT_GROUP] = {"exit_group", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"code", PT_INT32, PF_DEC}}},
	[SPRE_SYSCALL_EXECVE] = {"execve", EC_PROCESS, EF_MODIFIES_STATE, 19, {{"filename", PT_FSPATH, PF_NA}, {"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA}, {"tty", PT_INT32, PF_DEC}, {"pgid", PT_PID, PF_DEC}, {"loginuid", PT_INT32, PF_DEC} } },
	[SPRE_SYSCALL_CLONE] = {"clone", EC_PROCESS, EF_MODIFIES_STATE, 19, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },
	[SPRE_SYSCALL_FORK] = {"fork", EC_PROCESS, EF_MODIFIES_STATE, 19, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },
	[SPRE_SYSCALL_VFORK] = {"vfork", EC_PROCESS, EF_MODIFIES_STATE, 19, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },
	[SPRE_SYSCALL_SOCKET] = {"socket", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 4, {{"domain", PT_FLAGS32, PF_DEC, socket_families}, {"type", PT_UINT32, PF_DEC}, {"proto", PT_UINT32, PF_DEC}, {"fd", PT_FD, PF_DEC}} },
	[SPRE_SYSCALL_BIND] = {"bind", EC_NET, EF_USES_FD | EF_MODIFIES_STATE, 3, {{"fd", PT_FD, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"addr", PT_SOCKADDR, PF_NA} } },
	[SPRE_SYSCALL_CONNECT] = {"connect", EC_NET, EF_USES_FD | EF_MODIFIES_STATE, 3, {{"fd", PT_FD, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA} } },
	[SPRE_SYSCALL_LISTEN] = {"listen", EC_NET, EF_USES_FD, 3, {{"fd", PT_FD, PF_DEC}, {"backlog", PT_UINT32, PF_DEC}, {"res", PT_ERRNO, PF_DEC} } },
	[SPRE_SYSCALL_ACCEPT] = {"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"queuepct", PT_UINT8, PF_DEC}, {"queuelen", PT_UINT32, PF_DEC}, {"queuemax", PT_UINT32, PF_DEC} } },
	[SPRE_SYSCALL_ACCEPT4] = {"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 6, {{"flags", PT_INT32, PF_HEX}, {"fd", PT_FD, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"queuepct", PT_UINT8, PF_DEC}, {"queuelen", PT_UINT32, PF_DEC}, {"queuemax", PT_UINT32, PF_DEC} } },
	[SPRE_SYSCALL_SENDTO] = {"sendto", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	[SPRE_SYSCALL_RECVFROM] = {"recvfrom", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA}, {"tuple", PT_SOCKTUPLE, PF_NA} } },
	[SPRE_SYSCALL_SHUTDOWN] = {"shutdown", EC_NET, EF_USES_FD | EF_MODIFIES_STATE | EF_DROP_SIMPLE_CONS, 3, {{"fd", PT_FD, PF_DEC}, {"how", PT_FLAGS8, PF_HEX, shutdown_how}, {"res", PT_ERRNO, PF_DEC} } },
	[SPRE_SYSCALL_GETSOCKNAME] = {"getsockname", EC_NET, EF_DROP_SIMPLE_CONS, 0},
	[SPRE_SYSCALL_GETPEERNAME] = {"getpeername", EC_NET, EF_DROP_SIMPLE_CONS, 0},
	[SPRE_SYSCALL_SOCKETPAIR] = {"socketpair", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE, 8, {{"domain", PT_FLAGS32, PF_DEC, socket_families}, {"type", PT_UINT32, PF_DEC}, {"proto", PT_UINT32, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"fd1", PT_FD, PF_DEC}, {"fd2", PT_FD, PF_DEC}, {"source", PT_UINT64, PF_HEX}, {"peer", PT_UINT64, PF_HEX} } },
	[SPRE_SYSCALL_SETSOCKOPT] = {"setsockopt", EC_NET, EF_USES_FD, 6, {{"res", PT_ERRNO, PF_DEC}, {"fd", PT_FD, PF_DEC}, {"level", PT_FLAGS8, PF_DEC, sockopt_levels}, {"optname", PT_FLAGS8, PF_DEC, sockopt_options}, {"val", PT_DYN, PF_DEC, sockopt_dynamic_param, SPR_SOCKOPT_IDX_MAX}, {"optlen", PT_UINT32, PF_DEC}}},
	[SPRE_SYSCALL_GETSOCKOPT] = {"getsockopt", EC_NET, EF_USES_FD | EF_MODIFIES_STATE| EF_DROP_SIMPLE_CONS, 6, {{"res", PT_ERRNO, PF_DEC}, {"fd", PT_FD, PF_DEC}, {"level", PT_FLAGS8, PF_DEC, sockopt_levels}, {"optname", PT_FLAGS8, PF_DEC, sockopt_options}, {"val", PT_DYN, PF_DEC, sockopt_dynamic_param, SPR_SOCKOPT_IDX_MAX}, {"optlen", PT_UINT32, PF_DEC}}},
	[SPRE_SYSCALL_SENDMSG] = {"sendmsg", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	[SPRE_SYSCALL_SENDMMSG] = {"sendmmsg", EC_IO_WRITE, EF_DROP_SIMPLE_CONS, 0},
	[SPRE_SYSCALL_RECVMSG] = {"recvmsg", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"data", PT_BYTEBUF, PF_NA}, {"tuple", PT_SOCKTUPLE, PF_NA} } },
	[SPRE_SYSCALL_RECVMMSG] = {"recvmmsg", EC_IO_READ, EF_DROP_SIMPLE_CONS, 0},
};
