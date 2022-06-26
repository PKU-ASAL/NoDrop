#include "events.h"
const struct nod_event_info g_event_info[SPRE_EVENT_MAX] = {
 {"syscall", EC_OTHER, EF_NONE, 1, {{"ID", PT_SYSCALLID, PF_DEC} } },
 {"open", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"name", PT_FSPATH, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT}, {"dev", PT_UINT32, PF_HEX} } },
 {"close", EC_IO_OTHER, EF_DESTROYS_FD | EF_USES_FD | EF_MODIFIES_STATE | EF_DROP_SIMPLE_CONS, 2, {{"fd", PT_FD, PF_DEC}, {"res", PT_ERRNO, PF_DEC} } },
 {"read", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
 {"write", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
    {"brk", EC_MEMORY, EF_OLD_VERSION, 2, {{"size", PT_UINT32, PF_DEC} ,{"res", PT_UINT64, PF_HEX}} },
 {"exit", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"code", PT_INT32, PF_DEC}}},
 {"exit_group", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"code", PT_INT32, PF_DEC}}},
 {"execve", EC_PROCESS, EF_MODIFIES_STATE, 19, {{"filename", PT_FSPATH, PF_NA}, {"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA}, {"tty", PT_INT32, PF_DEC}, {"pgid", PT_PID, PF_DEC}, {"loginuid", PT_INT32, PF_DEC} } },
 {"clone", EC_PROCESS, EF_MODIFIES_STATE, 19, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },
	{"procexit", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"NA1", EC_PROCESS, EF_UNUSED, 0},
	{"socket", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 4, {{"domain", PT_FLAGS32, PF_DEC, socket_families}, {"type", PT_UINT32, PF_DEC}, {"proto", PT_UINT32, PF_DEC} , {"fd", PT_FD, PF_DEC}} },
 {"fork", EC_PROCESS, EF_MODIFIES_STATE, 19, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },
 {"vfork", EC_PROCESS, EF_MODIFIES_STATE, 19, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },
 {"socket", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 4, {{"domain", PT_FLAGS32, PF_DEC, socket_families}, {"type", PT_UINT32, PF_DEC}, {"proto", PT_UINT32, PF_DEC}, {"fd", PT_FD, PF_DEC}} },
 {"bind", EC_NET, EF_USES_FD | EF_MODIFIES_STATE, 3, {{"fd", PT_FD, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"addr", PT_SOCKADDR, PF_NA} } },
 {"connect", EC_NET, EF_USES_FD | EF_MODIFIES_STATE, 3, {{"fd", PT_FD, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA} } },
 {"listen", EC_NET, EF_USES_FD, 3, {{"fd", PT_FD, PF_DEC}, {"backlog", PT_UINT32, PF_DEC}, {"res", PT_ERRNO, PF_DEC} } },
 {"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"queuepct", PT_UINT8, PF_DEC}, {"queuelen", PT_UINT32, PF_DEC}, {"queuemax", PT_UINT32, PF_DEC} } },
 {"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 6, {{"flags", PT_INT32, PF_HEX}, {"fd", PT_FD, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"queuepct", PT_UINT8, PF_DEC}, {"queuelen", PT_UINT32, PF_DEC}, {"queuemax", PT_UINT32, PF_DEC} } },
	{"send", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC},{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
 {"sendto", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"recv", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC},{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
 {"recvfrom", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA}, {"tuple", PT_SOCKTUPLE, PF_NA} } },
 {"shutdown", EC_NET, EF_USES_FD | EF_MODIFIES_STATE | EF_DROP_SIMPLE_CONS, 3, {{"fd", PT_FD, PF_DEC}, {"how", PT_FLAGS8, PF_HEX, shutdown_how}, {"res", PT_ERRNO, PF_DEC} } },
 {"getsockname", EC_NET, EF_DROP_SIMPLE_CONS, 0},
 {"getpeername", EC_NET, EF_DROP_SIMPLE_CONS, 0},
 {"socketpair", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE, 8, {{"domain", PT_FLAGS32, PF_DEC, socket_families}, {"type", PT_UINT32, PF_DEC}, {"proto", PT_UINT32, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"fd1", PT_FD, PF_DEC}, {"fd2", PT_FD, PF_DEC}, {"source", PT_UINT64, PF_HEX}, {"peer", PT_UINT64, PF_HEX} } },
 {"setsockopt", EC_NET, EF_USES_FD, 6, {{"res", PT_ERRNO, PF_DEC}, {"fd", PT_FD, PF_DEC}, {"level", PT_FLAGS8, PF_DEC, sockopt_levels}, {"optname", PT_FLAGS8, PF_DEC, sockopt_options}, {"val", PT_DYN, PF_DEC, sockopt_dynamic_param, NOD_SOCKOPT_IDX_MAX}, {"optlen", PT_UINT32, PF_DEC}}},
 {"getsockopt", EC_NET, EF_USES_FD | EF_MODIFIES_STATE| EF_DROP_SIMPLE_CONS, 6, {{"res", PT_ERRNO, PF_DEC}, {"fd", PT_FD, PF_DEC}, {"level", PT_FLAGS8, PF_DEC, sockopt_levels}, {"optname", PT_FLAGS8, PF_DEC, sockopt_options}, {"val", PT_DYN, PF_DEC, sockopt_dynamic_param, NOD_SOCKOPT_IDX_MAX}, {"optlen", PT_UINT32, PF_DEC}}},
 {"sendmsg", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
 {"sendmmsg", EC_IO_WRITE, EF_DROP_SIMPLE_CONS, 0},
 {"recvmsg", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"data", PT_BYTEBUF, PF_NA}, {"tuple", PT_SOCKTUPLE, PF_NA} } },
 {"recvmmsg", EC_IO_READ, EF_DROP_SIMPLE_CONS, 0},
	{"creat", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 4, {{"fd", PT_FD, PF_DEC}, {"name", PT_FSPATH, PF_NA}, {"mode", PT_UINT32, PF_OCT}, {"dev", PT_UINT32, PF_HEX} } },
	{"pipe", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE, 4, {{"res", PT_ERRNO, PF_DEC}, {"fd1", PT_FD, PF_DEC}, {"fd2", PT_FD, PF_DEC}, {"ino", PT_UINT64, PF_DEC} } },
	{"eventfd", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE | EF_DROP_SIMPLE_CONS, 3, {{"initval", PT_UINT64, PF_DEC}, {"flags", PT_FLAGS32, PF_HEX},{"res", PT_FD, PF_DEC}  } },
	{"futex", EC_IPC, EF_DROP_SIMPLE_CONS, 4, {{"addr", PT_UINT64, PF_HEX}, {"op", PT_FLAGS16, PF_HEX, futex_operations}, {"val", PT_UINT64, PF_DEC} , {"res", PT_ERRNO, PF_DEC}} },
	{"stat", EC_FILE, EF_DROP_SIMPLE_CONS, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	{"lstat", EC_FILE, EF_DROP_SIMPLE_CONS, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	{"fstat", EC_FILE, EF_USES_FD | EF_DROP_SIMPLE_CONS, 2, {{"fd", PT_FD, PF_NA},{"res", PT_ERRNO, PF_DEC} } },
	{"stat64", EC_FILE, EF_DROP_SIMPLE_CONS, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	{"lstat64", EC_FILE, EF_DROP_SIMPLE_CONS, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	{"fstat64", EC_FILE, EF_USES_FD | EF_DROP_SIMPLE_CONS, 2, {{"fd", PT_FD, PF_NA},{"res", PT_ERRNO, PF_DEC} } },
	{"epoll_wait", EC_WAIT, EF_WAITS | EF_DROP_SIMPLE_CONS, 2, {{"maxevents", PT_ERRNO, PF_DEC},{"res", PT_ERRNO, PF_DEC} } },
	{"poll", EC_WAIT, EF_WAITS | EF_DROP_SIMPLE_CONS, 3, {{"fds", PT_FDLIST, PF_DEC}, {"timeout", PT_INT64, PF_DEC},{"res", PT_ERRNO, PF_DEC} } },
	{"select", EC_WAIT, EF_WAITS | EF_DROP_SIMPLE_CONS, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"select", EC_WAIT, EF_WAITS | EF_DROP_SIMPLE_CONS, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"lseek", EC_FILE, EF_USES_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd", PT_FD, PF_DEC}, {"offset", PT_UINT64, PF_DEC}, {"whence", PT_FLAGS8, PF_DEC, lseek_whence} , {"res", PT_ERRNO, PF_DEC}} },
	{"llseek", EC_FILE, EF_USES_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd", PT_FD, PF_DEC}, {"offset", PT_UINT64, PF_DEC}, {"whence", PT_FLAGS8, PF_DEC, lseek_whence} , {"res", PT_ERRNO, PF_DEC}} },
	{"ioctl", EC_IO_OTHER, EF_USES_FD | EF_OLD_VERSION, 3, {{"fd", PT_FD, PF_DEC}, {"request", PT_UINT64, PF_HEX} ,{"res", PT_ERRNO, PF_DEC}} },
	{"getcwd", EC_FILE, EF_DROP_SIMPLE_CONS, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_CHARBUF, PF_NA} } },
	{"chdir", EC_FILE, EF_MODIFIES_STATE, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_CHARBUF, PF_NA} } },
	{"fchdir", EC_FILE, EF_USES_FD | EF_MODIFIES_STATE, 2, {{"fd", PT_FD, PF_NA},{"res", PT_ERRNO, PF_DEC} } },
	{"mkdir", EC_FILE, EF_NONE, 3, {{"path", PT_FSPATH, PF_NA}, {"mode", PT_UINT32, PF_HEX},{"res", PT_ERRNO, PF_DEC} } },
	{"rmdir", EC_FILE, EF_NONE, 2, {{"path", PT_FSPATH, PF_NA},{"res", PT_ERRNO, PF_DEC} } },
	{"openat", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE | EF_OLD_VERSION, 5, {{"dirfd", PT_FD, PF_DEC}, {"name", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT},{"res", PT_ERRNO, PF_DEC} } },
	{"link", EC_FILE, EF_OLD_VERSION, 3, {{"oldpath", PT_FSPATH, PF_NA}, {"newpath", PT_FSPATH, PF_NA},{"res", PT_ERRNO, PF_DEC} } },
	/* PPME_SYSCALL_LINKAT_E */{"linkat", EC_FILE, EF_OLD_VERSION, 5, {{"olddir", PT_FD, PF_DEC}, {"oldpath", PT_CHARBUF, PF_NA}, {"newdir", PT_FD, PF_DEC}, {"newpath", PT_CHARBUF, PF_NA},{"res", PT_ERRNO, PF_DEC} } },
	/* PPME_SYSCALL_UNLINK_E */{"unlink", EC_FILE, EF_OLD_VERSION, 2, {{"path", PT_FSPATH, PF_NA},{"res", PT_ERRNO, PF_DEC} } },
	/* PPME_SYSCALL_UNLINKAT_E */{"unlinkat", EC_FILE, EF_OLD_VERSION, 3, {{"dirfd", PT_FD, PF_DEC}, {"name", PT_CHARBUF, PF_NA},{"res", PT_ERRNO, PF_DEC} } },
	/* PPME_SYSCALL_PREAD_E */{"pread", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_SIMPLE_CONS, 5, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"pos", PT_UINT64, PF_DEC},{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	/* PPME_SYSCALL_PWRITE_E */{"pwrite", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_SIMPLE_CONS, 5, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"pos", PT_UINT64, PF_DEC},{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	/* PPME_SYSCALL_READV_X */{"readv", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd", PT_FD, PF_DEC},{"res", PT_ERRNO, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	/* PPME_SYSCALL_WRITEV_E */{"writev", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC},{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	/* PPME_SYSCALL_PREADV_E */{"preadv", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_SIMPLE_CONS, 5, {{"fd", PT_FD, PF_DEC}, {"pos", PT_UINT64, PF_DEC},{"res", PT_ERRNO, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	/* PPME_SYSCALL_PWRITEV_E */{"pwritev", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_SIMPLE_CONS, 5, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"pos", PT_UINT64, PF_DEC},{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	/* PPME_SYSCALL_DUP_E */{"dup", EC_IO_OTHER, EF_CREATES_FD | EF_USES_FD | EF_MODIFIES_STATE, 2, {{"fd", PT_FD, PF_DEC} ,{"res", PT_FD, PF_DEC}} },
	/* PPME_SYSCALL_SIGNALFD_E */{"signalfd", EC_SIGNAL, EF_CREATES_FD | EF_MODIFIES_STATE, 4, {{"fd", PT_FD, PF_DEC}, {"mask", PT_UINT32, PF_HEX}, {"flags", PT_FLAGS8, PF_HEX},{"res", PT_FD, PF_DEC} } },
	/* PPME_SYSCALL_KILL_E */{"kill", EC_SIGNAL, EF_NONE, 3, {{"pid", PT_PID, PF_DEC}, {"sig", PT_SIGTYPE, PF_DEC},{"res", PT_ERRNO, PF_DEC} } },
	/* PPME_SYSCALL_TKILL_E */{"tkill", EC_SIGNAL, EF_NONE, 3, {{"tid", PT_PID, PF_DEC}, {"sig", PT_SIGTYPE, PF_DEC} ,{"res", PT_ERRNO, PF_DEC}} },
	/* PPME_SYSCALL_TGKILL_E */{"tgkill", EC_SIGNAL, EF_NONE, 4, {{"pid", PT_PID, PF_DEC}, {"tid", PT_PID, PF_DEC}, {"sig", PT_SIGTYPE, PF_DEC},{"res", PT_ERRNO, PF_DEC} } },
	/* PPME_SYSCALL_NANOSLEEP_E */{"nanosleep", EC_SLEEP, EF_WAITS | EF_DROP_SIMPLE_CONS, 2, {{"interval", PT_RELTIME, PF_DEC} ,{"res", PT_ERRNO, PF_DEC}} },
	/* PPME_SYSCALL_TIMERFD_CREATE_E */{"timerfd_create", EC_TIME, EF_CREATES_FD | EF_MODIFIES_STATE | EF_DROP_SIMPLE_CONS, 3, {{"clockid", PT_UINT8, PF_DEC}, {"flags", PT_FLAGS8, PF_HEX}, {"res", PT_FD, PF_DEC} } },
	/* PPME_SYSCALL_INOTIFY_INIT_E */{"inotify_init", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE, 2, {{"flags", PT_FLAGS8, PF_HEX},{"res", PT_FD, PF_DEC} } },
	/* PPME_SYSCALL_GETRLIMIT_X */{"getrlimit", EC_PROCESS, EF_DROP_SIMPLE_CONS, 4, {{"resource", PT_FLAGS8, PF_DEC, rlimit_resources},{"res", PT_ERRNO, PF_DEC}, {"cur", PT_INT64, PF_DEC}, {"max", PT_INT64, PF_DEC} } },
	/* PPME_SYSCALL_SETRLIMIT_X */{"setrlimit", EC_PROCESS, EF_DROP_SIMPLE_CONS, 4, {{"resource", PT_FLAGS8, PF_DEC, rlimit_resources},{"res", PT_ERRNO, PF_DEC}, {"cur", PT_INT64, PF_DEC}, {"max", PT_INT64, PF_DEC} } },
	
	
	

	/* PPME_SYSCALL_PRLIMIT_X */{"prlimit", EC_PROCESS, EF_NONE, 7, {{"pid", PT_PID, PF_DEC}, {"resource", PT_FLAGS8, PF_DEC, rlimit_resources},{"res", PT_ERRNO, PF_DEC}, {"newcur", PT_INT64, PF_DEC}, {"newmax", PT_INT64, PF_DEC}, {"oldcur", PT_INT64, PF_DEC}, {"oldmax", PT_INT64, PF_DEC} } },
	/* PPME_SCHEDSWITCH_1_E */{"switch", EC_SCHEDULER, EF_SKIPPARSERESET | EF_OLD_VERSION | EF_DROP_SIMPLE_CONS, 1, {{"next", PT_PID, PF_DEC} } },
	/* PPME_SCHEDSWITCH_1_X */{"NA2", EC_SCHEDULER, EF_SKIPPARSERESET | EF_UNUSED | EF_OLD_VERSION, 0},
	/* PPME_DROP_X */{"drop", EC_INTERNAL, EF_SKIPPARSERESET, 1, {{"ratio", PT_UINT32, PF_DEC} } },
	/* PPME_SYSCALL_FCNTL_E */{"fcntl", EC_IO_OTHER, EF_USES_FD | EF_MODIFIES_STATE | EF_DROP_SIMPLE_CONS, 2, {{"fd", PT_FD, PF_DEC}, {"cmd", PT_FLAGS8, PF_DEC, fcntl_commands},{"res", PT_FD, PF_DEC} } },
	/* PPME_SCHEDSWITCH_6_E */{"switch", EC_SCHEDULER, EF_DROP_SIMPLE_CONS, 6, {{"next", PT_PID, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC} } },
	/* PPME_SCHEDSWITCH_6_X */{"NA2", EC_SCHEDULER, EF_UNUSED, 0},
	/* PPME_SYSCALL_BRK_4_X */{"brk", EC_MEMORY, EF_DROP_SIMPLE_CONS, 5, {{"addr", PT_UINT64, PF_HEX},{"res", PT_UINT64, PF_HEX}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC} } },
	/* PPME_SYSCALL_MMAP_E */{"mmap", EC_MEMORY, EF_DROP_SIMPLE_CONS, 10, {{"addr", PT_UINT64, PF_HEX}, {"length", PT_UINT64, PF_DEC}, {"prot", PT_FLAGS32, PF_HEX, prot_flags}, {"flags", PT_FLAGS32, PF_HEX, mmap_flags}, {"fd", PT_FD, PF_DEC}, {"offset", PT_UINT64, PF_DEC},{"res", PT_UINT64, PF_HEX}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC} } },
	/* PPME_SYSCALL_MMAP2_E */{"mmap2", EC_MEMORY, EF_DROP_SIMPLE_CONS, 10, {{"addr", PT_UINT64, PF_HEX}, {"length", PT_UINT64, PF_DEC}, {"prot", PT_FLAGS32, PF_HEX, prot_flags}, {"flags", PT_FLAGS32, PF_HEX, mmap_flags}, {"fd", PT_FD, PF_DEC}, {"pgoffset", PT_UINT64, PF_DEC},{"res", PT_UINT64, PF_HEX}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC},{"res", PT_UINT64, PF_HEX}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC} } },

	/* PPME_SYSCALL_MUNMAP_X */{"munmap", EC_MEMORY, EF_DROP_SIMPLE_CONS, 6, {{"addr", PT_UINT64, PF_HEX}, {"length", PT_UINT64, PF_DEC},{"res", PT_ERRNO, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC} } },
	/* PPME_SYSCALL_SPLICE_E */{"splice", EC_IO_OTHER, EF_USES_FD | EF_DROP_SIMPLE_CONS, 4, {{"fd_in", PT_FD, PF_DEC}, {"fd_out", PT_FD, PF_DEC}, {"size", PT_UINT64, PF_DEC}, {"flags", PT_FLAGS32, PF_HEX, splice_flags},{"res", PT_ERRNO, PF_DEC} } },
	/* PPME_SYSCALL_IOCTL_3_E */{"ioctl", EC_IO_OTHER, EF_USES_FD, 3, {{"fd", PT_FD, PF_DEC}, {"request", PT_UINT64, PF_HEX}, {"argument", PT_UINT64, PF_HEX},{"res", PT_ERRNO, PF_DEC} } },

	/* PPME_SYSCALL_EXECVE_14_X */{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 14, {{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"env", PT_BYTEBUF, PF_NA} } },

	/* PPME_SYSCALL_RENAME_X */{"rename", EC_FILE, EF_NONE, 3, {{"res", PT_ERRNO, PF_DEC}, {"oldpath", PT_FSPATH, PF_NA}, {"newpath", PT_FSPATH, PF_NA} } },

	/* PPME_SYSCALL_RENAMEAT_X */{"renameat", EC_FILE, EF_NONE, 5, {{"res", PT_ERRNO, PF_DEC}, {"olddirfd", PT_FD, PF_DEC}, {"oldpath", PT_FSRELPATH, PF_NA, DIRFD_PARAM(1)}, {"newdirfd", PT_FD, PF_DEC}, {"newpath", PT_FSRELPATH, PF_NA, DIRFD_PARAM(3)} } },

	/* PPME_SYSCALL_SYMLINK_X */{"symlink", EC_FILE, EF_NONE, 3, {{"res", PT_ERRNO, PF_DEC}, {"target", PT_CHARBUF, PF_NA}, {"linkpath", PT_FSPATH, PF_NA} } },

	/* PPME_SYSCALL_SYMLINKAT_X */{"symlinkat", EC_FILE, EF_NONE, 4, {{"res", PT_ERRNO, PF_DEC}, {"target", PT_CHARBUF, PF_NA}, {"linkdirfd", PT_FD, PF_DEC}, {"linkpath", PT_FSRELPATH, PF_NA, DIRFD_PARAM(2)} } },
	
	

	/* PPME_PROCEXIT_1_E */{"procexit", EC_PROCESS, EF_MODIFIES_STATE, 4, {{"status", PT_ERRNO, PF_DEC}, {"ret", PT_ERRNO, PF_DEC}, {"sig", PT_SIGTYPE, PF_DEC}, {"core", PT_UINT8, PF_DEC} } },
	/* PPME_NA1 */{"NA1", EC_PROCESS, EF_UNUSED, 0},

	/* PPME_SYSCALL_SENDFILE_X */{"sendfile", EC_IO_WRITE, EF_USES_FD | EF_DROP_SIMPLE_CONS, 6, {{"out_fd", PT_FD, PF_DEC}, {"in_fd", PT_FD, PF_DEC}, {"offset", PT_UINT64, PF_DEC}, {"size", PT_UINT64, PF_DEC},{"res", PT_ERRNO, PF_DEC}, {"offset", PT_UINT64, PF_DEC} } },

	/* PPME_SYSCALL_QUOTACTL_X */{"quotactl", EC_USER, EF_NONE, 18, {{"cmd", PT_FLAGS16, PF_DEC, quotactl_cmds }, {"type", PT_FLAGS8, PF_DEC, quotactl_types}, {"id", PT_UINT32, PF_DEC}, {"quota_fmt", PT_FLAGS8, PF_DEC, quotactl_quota_fmts },{"res", PT_ERRNO, PF_DEC}, {"special", PT_CHARBUF, PF_NA }, {"quotafilepath", PT_CHARBUF, PF_NA}, {"dqb_bhardlimit", PT_UINT64, PF_DEC }, {"dqb_bsoftlimit", PT_UINT64, PF_DEC }, {"dqb_curspace", PT_UINT64, PF_DEC }, {"dqb_ihardlimit", PT_UINT64, PF_DEC }, {"dqb_isoftlimit", PT_UINT64, PF_DEC }, {"dqb_btime", PT_RELTIME, PF_DEC }, {"dqb_itime", PT_RELTIME, PF_DEC }, {"dqi_bgrace", PT_RELTIME, PF_DEC }, {"dqi_igrace", PT_RELTIME, PF_DEC }, {"dqi_flags", PT_FLAGS8, PF_DEC, quotactl_dqi_flags }, {"quota_fmt_out", PT_FLAGS8, PF_DEC, quotactl_quota_fmts } } },
	/* PPME_SYSCALL_SETRESUID_E */ {"setresuid", EC_USER, EF_MODIFIES_STATE, 4, {{"ruid", PT_UID, PF_DEC }, {"euid", PT_UID, PF_DEC }, {"suid", PT_UID, PF_DEC },{"res", PT_ERRNO, PF_DEC} } },
	
	/* PPME_SYSCALL_SETRESGID_E */ {"setresgid", EC_USER, EF_MODIFIES_STATE, 4, {{"rgid", PT_GID, PF_DEC }, {"egid", PT_GID, PF_DEC }, {"sgid", PT_GID, PF_DEC },{"res", PT_ERRNO, PF_DEC} } },

	/* PPME_SYSDIGEVENT_E */{"sysdigevent", EC_INTERNAL, EF_SKIPPARSERESET, 2, {{"event_type", PT_UINT32, PF_DEC}, {"event_data", PT_UINT64, PF_DEC} } },
	/* PPME_NA1 */{"sysdigevent", EC_INTERNAL, EF_UNUSED, 0},

	/* PPME_SYSCALL_SETUID_E */ {"setuid", EC_USER, EF_MODIFIES_STATE, 2, {{"uid", PT_UID, PF_DEC},{"res", PT_ERRNO, PF_DEC} } },

	/* PPME_SYSCALL_SETGID_E */ {"setgid", EC_USER, EF_MODIFIES_STATE, 2, {{"gid", PT_GID, PF_DEC},{"res", PT_ERRNO, PF_DEC} } },

	/* PPME_SYSCALL_GETUID_X */ {"getuid", EC_USER, EF_DROP_SIMPLE_CONS, 2, {{"uid", PT_UID, PF_DEC},{"euid", PT_UID, PF_DEC} } },

	/* PPME_SYSCALL_GETGID_X */ {"getgid", EC_USER, EF_DROP_SIMPLE_CONS, 1, {{"gid", PT_GID, PF_DEC} ,{"egid", PT_GID, PF_DEC}} },


	/* PPME_SYSCALL_GETRESUID_X */ {"getresuid", EC_USER, EF_DROP_SIMPLE_CONS, 4, {{"res", PT_ERRNO, PF_DEC}, {"ruid", PT_UID, PF_DEC }, {"euid", PT_UID, PF_DEC }, {"suid", PT_UID, PF_DEC } } },

	/* PPME_SYSCALL_GETRESGID_X */ {"getresgid", EC_USER, EF_DROP_SIMPLE_CONS, 4, {{"res", PT_ERRNO, PF_DEC}, {"rgid", PT_GID, PF_DEC }, {"egid", PT_GID, PF_DEC }, {"sgid", PT_GID, PF_DEC } } },

	/* PPME_SYSCALL_EXECVE_15_X */{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 15, {{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA} } },

	/* PPME_SYSCALL_CLONE_17_X */{"clone", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 17, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC} } },

	/* PPME_SYSCALL_FORK_17_X */{"fork", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 17, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC} } },

	/* PPME_SYSCALL_VFORK_17_X */{"vfork", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 17, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC} } },

	/* PPME_SYSCALL_CLONE_20_X */{"clone", EC_PROCESS, EF_MODIFIES_STATE, 20, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },

	/* PPME_SYSCALL_FORK_20_X */{"fork", EC_PROCESS, EF_MODIFIES_STATE, 20, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },

	/* PPME_SYSCALL_VFORK_20_X */{"vfork", EC_PROCESS, EF_MODIFIES_STATE, 20, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },
	/* PPME_CONTAINER_E */{"container", EC_INTERNAL, EF_SKIPPARSERESET | EF_MODIFIES_STATE | EF_OLD_VERSION, 4, {{"id", PT_CHARBUF, PF_NA}, {"type", PT_UINT32, PF_DEC}, {"name", PT_CHARBUF, PF_NA}, {"image", PT_CHARBUF, PF_NA} } },

	/* PPME_SYSCALL_EXECVE_16_X */{"execve", EC_PROCESS, EF_MODIFIES_STATE, 16, {{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA} } },
	/* PPME_SIGNALDELIVER_E */ {"signaldeliver", EC_SIGNAL, EF_DROP_SIMPLE_CONS, 3, {{"spid", PT_PID, PF_DEC}, {"dpid", PT_PID, PF_DEC}, {"sig", PT_SIGTYPE, PF_DEC} } },

	/* PPME_PROCINFO_E */{"procinfo", EC_INTERNAL, EF_SKIPPARSERESET | EF_DROP_SIMPLE_CONS, 2, {{"cpu_usr", PT_UINT64, PF_DEC}, {"cpu_sys", PT_UINT64, PF_DEC} } },

	/* PPME_SYSCALL_GETDENTS_E */{"getdents", EC_FILE, EF_USES_FD | EF_DROP_SIMPLE_CONS, 2, {{"fd", PT_FD, PF_NA},{"res", PT_ERRNO, PF_DEC} } },

	/* PPME_SYSCALL_GETDENTS64_E */{"getdents64", EC_FILE, EF_USES_FD | EF_DROP_SIMPLE_CONS, 2, {{"fd", PT_FD, PF_NA} ,{"res", PT_ERRNO, PF_DEC}} },

	/* PPME_SYSCALL_SETNS_E */ {"setns", EC_PROCESS, EF_USES_FD, 3, {{"fd", PT_FD, PF_NA}, {"nstype", PT_FLAGS32, PF_HEX, clone_flags},{"res", PT_ERRNO, PF_DEC} } },
	
	/* PPME_SYSCALL_FLOCK_E */ {"flock", EC_FILE, EF_USES_FD, 3, {{"fd", PT_FD, PF_NA}, {"operation", PT_FLAGS32, PF_HEX, flock_flags},{"res", PT_ERRNO, PF_DEC} } },
	
	/* PPME_CPU_HOTPLUG_E */ {"cpu_hotplug", EC_SYSTEM, EF_SKIPPARSERESET | EF_MODIFIES_STATE, 2, {{"cpu", PT_UINT32, PF_DEC}, {"action", PT_UINT32, PF_DEC} } },


	/* PPME_SOCKET_ACCEPT_5_X */{"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"queuepct", PT_UINT8, PF_DEC}, {"queuelen", PT_UINT32, PF_DEC}, {"queuemax", PT_UINT32, PF_DEC} } },

	/* PPME_SOCKET_ACCEPT4_5_X */{"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 6, {{"flags", PT_INT32, PF_HEX},{"fd", PT_FD, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"queuepct", PT_UINT8, PF_DEC}, {"queuelen", PT_UINT32, PF_DEC}, {"queuemax", PT_UINT32, PF_DEC} } },
	/* PPME_SYSCALL_SEMOP_X */ {"semop", EC_PROCESS, EF_DROP_SIMPLE_CONS, 9, {{"semid", PT_INT32, PF_DEC},{"res", PT_ERRNO, PF_DEC}, {"nsops", PT_UINT32, PF_DEC}, {"sem_num_0", PT_UINT16, PF_DEC}, {"sem_op_0", PT_INT16, PF_DEC}, {"sem_flg_0", PT_FLAGS16, PF_HEX, semop_flags}, {"sem_num_1", PT_UINT16, PF_DEC}, {"sem_op_1", PT_INT16, PF_DEC}, {"sem_flg_1", PT_FLAGS16, PF_HEX, semop_flags} } },
	
	/* PPME_SYSCALL_SEMCTL_E */{"semctl", EC_PROCESS, EF_DROP_SIMPLE_CONS, 5, {{"semid", PT_INT32, PF_DEC}, {"semnum", PT_INT32, PF_DEC}, {"cmd", PT_FLAGS16, PF_HEX, semctl_commands}, {"val", PT_INT32, PF_DEC} ,{"res", PT_ERRNO, PF_DEC}} },

	/* PPME_SYSCALL_PPOLL_E */{"ppoll", EC_WAIT, EF_WAITS | EF_DROP_SIMPLE_CONS, 5, {{"fds", PT_FDLIST, PF_DEC}, {"timeout", PT_RELTIME, PF_DEC}, {"sigmask", PT_SIGSET, PF_DEC} ,{"res", PT_ERRNO, PF_DEC}, {"fds", PT_FDLIST, PF_DEC}} },

	/* PPME_SYSCALL_MOUNT_X */{"mount", EC_FILE, EF_MODIFIES_STATE, 5, {{"flags", PT_FLAGS32, PF_HEX, mount_flags},{"res", PT_ERRNO, PF_DEC}, {"dev", PT_CHARBUF, PF_NA}, {"dir", PT_FSPATH, PF_NA}, {"type", PT_CHARBUF, PF_NA} } },
	

	/* PPME_SYSCALL_UMOUNT_X */{"umount", EC_FILE, EF_MODIFIES_STATE, 3, {{"flags", PT_FLAGS32, PF_HEX, umount_flags} ,{"res", PT_ERRNO, PF_DEC}, {"name", PT_FSPATH, PF_NA} } },

	/* PPME_K8S_E */{"k8s", EC_INTERNAL, EF_SKIPPARSERESET | EF_MODIFIES_STATE, 1, {{"json", PT_CHARBUF, PF_NA} } },

	/* PPME_SYSCALL_SEMGET_E */{"semget", EC_PROCESS, EF_DROP_SIMPLE_CONS, 4, {{"key", PT_INT32, PF_HEX}, {"nsems", PT_INT32, PF_DEC}, {"semflg", PT_FLAGS32, PF_HEX, semget_flags},{"res", PT_ERRNO, PF_DEC}  } },


	/* PPME_SYSCALL_ACCESS_X */{"access", EC_FILE, EF_DROP_SIMPLE_CONS, 3, {{"mode", PT_FLAGS32, PF_HEX, access_flags},{"res", PT_ERRNO, PF_DEC}, {"name", PT_FSPATH, PF_NA} } },
	
	/* PPME_SYSCALL_CHROOT_X */{"chroot", EC_PROCESS, EF_MODIFIES_STATE, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },

	/* PPME_TRACER_X */{"tracer", EC_OTHER, EF_NONE, 3, { { "id", PT_INT64, PF_DEC }, { "tags", PT_CHARBUFARRAY, PF_NA }, { "args", PT_CHARBUF_PAIR_ARRAY, PF_NA } } },
	/* PPME_MESOS_E */{"mesos", EC_INTERNAL, EF_SKIPPARSERESET | EF_MODIFIES_STATE, 1, {{"json", PT_CHARBUF, PF_NA} } },

	/* PPME_CONTAINER_JSON_E */{"container", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"json", PT_CHARBUF, PF_NA} } },


	/* PPME_SYSCALL_SETSID_X */{"setsid", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"res", PT_PID, PF_DEC} } },

	/* PPME_SYSCALL_MKDIR_2_X */{"mkdir", EC_FILE, EF_NONE, 3, {{"mode", PT_UINT32, PF_HEX},{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },

	/* PPME_SYSCALL_RMDIR_2_X */{"rmdir", EC_FILE, EF_NONE, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	/* PPME_NOTIFICATION_E */{"notification", EC_OTHER, EF_SKIPPARSERESET, 2, {{"id", PT_CHARBUF, PF_DEC}, {"desc", PT_CHARBUF, PF_NA}, } },


	/* PPME_SYSCALL_EXECVE_17_X */{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 17, {{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA}, {"tty", PT_INT32, PF_DEC} } },

	/* PPME_SYSCALL_UNSHARE_X */ {"unshare", EC_PROCESS, EF_NONE, 1, {{"flags", PT_FLAGS32, PF_HEX, clone_flags},{"res", PT_ERRNO, PF_DEC} } },
	/* PPME_INFRASTRUCTURE_EVENT_E */{"infra", EC_INTERNAL, EF_SKIPPARSERESET, 4, {{"source", PT_CHARBUF, PF_DEC}, {"name", PT_CHARBUF, PF_NA}, {"description", PT_CHARBUF, PF_NA}, {"scope", PT_CHARBUF, PF_NA} } },


	/* PPME_SYSCALL_EXECVE_18_X */{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 18, {{"filename", PT_FSPATH, PF_NA},{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA}, {"tty", PT_INT32, PF_DEC} } },
	/* PPME_PAGE_FAULT_E */ {"page_fault", EC_OTHER, EF_SKIPPARSERESET | EF_DROP_SIMPLE_CONS, 3, {{"addr", PT_UINT64, PF_HEX}, {"ip", PT_UINT64, PF_HEX}, {"error", PT_FLAGS32, PF_HEX, pf_flags} } },


	/* PPME_SYSCALL_EXECVE_19_X */{"execve", EC_PROCESS, EF_MODIFIES_STATE, 21, {{"filename", PT_FSPATH, PF_NA},{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA}, {"tty", PT_INT32, PF_DEC}, {"pgid", PT_PID, PF_DEC}, {"loginuid", PT_INT32, PF_DEC}, {"flags", PT_FLAGS32, PF_HEX, execve_flags} } },
	/* PPME_SYSCALL_SETPGID_E */{"setpgid", EC_PROCESS, EF_MODIFIES_STATE, 3, {{"pid", PT_PID, PF_DEC}, {"pgid", PT_PID, PF_DEC},{"res", PT_PID, PF_DEC} } },


	/* PPME_SYSCALL_BPF_X */{"bpf", EC_OTHER, EF_CREATES_FD, 2, {{"cmd", PT_INT64, PF_DEC},{"res_or_fd", PT_DYN, PF_DEC, bpf_dynamic_param, PPM_BPF_IDX_MAX} } },
	/* PPME_SYSCALL_SECCOMP_E */{"seccomp", EC_OTHER, EF_NONE, 2, {{"op", PT_UINT64, PF_DEC}, {"flags", PT_UINT64, PF_HEX},{"res", PT_ERRNO, PF_DEC} } },
	/* PPME_SYSCALL_UNLINK_2_X */{"unlink", EC_FILE, EF_NONE, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	/* PPME_SYSCALL_UNLINKAT_2_X */{"unlinkat", EC_FILE, EF_NONE, 4, {{"res", PT_ERRNO, PF_DEC}, {"dirfd", PT_FD, PF_DEC}, {"name", PT_FSRELPATH, PF_NA, DIRFD_PARAM(1)}, {"flags", PT_FLAGS32, PF_HEX, unlinkat_flags} } },

	/* PPME_SYSCALL_MKDIRAT_X */{"mkdirat", EC_FILE, EF_NONE, 4, {{"res", PT_ERRNO, PF_DEC}, {"dirfd", PT_FD, PF_DEC}, {"path", PT_FSRELPATH, PF_NA, DIRFD_PARAM(1)}, {"mode", PT_UINT32, PF_HEX} } },

	/* PPME_SYSCALL_OPENAT_2_X */{"openat", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 6, {{"fd", PT_FD, PF_DEC}, {"dirfd", PT_FD, PF_DEC}, {"name", PT_FSRELPATH, PF_NA, DIRFD_PARAM(1)}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT}, {"dev", PT_UINT32, PF_HEX} } },

	/* PPME_SYSCALL_LINK_2_X */{"link", EC_FILE, EF_NONE, 3, {{"res", PT_ERRNO, PF_DEC}, {"oldpath", PT_FSPATH, PF_NA}, {"newpath", PT_FSPATH, PF_NA} } },

	/* PPME_SYSCALL_LINKAT_2_X */{"linkat", EC_FILE, EF_NONE, 6, {{"res", PT_ERRNO, PF_DEC}, {"olddir", PT_FD, PF_DEC}, {"oldpath", PT_FSRELPATH, PF_NA, DIRFD_PARAM(1)}, {"newdir", PT_FD, PF_DEC}, {"newpath", PT_FSRELPATH, PF_NA, DIRFD_PARAM(3)}, {"flags", PT_FLAGS32, PF_HEX, linkat_flags} } },

	/* PPME_SYSCALL_FCHMODAT_X */{"fchmodat", EC_FILE, EF_NONE, 4, {{"res", PT_ERRNO, PF_DEC}, {"dirfd", PT_FD, PF_DEC}, {"filename", PT_FSRELPATH, PF_NA, DIRFD_PARAM(1)}, {"mode", PT_MODE, PF_OCT, chmod_mode} } },

	/* PPME_SYSCALL_CHMOD_X */{"chmod", EC_FILE, EF_NONE, 3, {{"res", PT_ERRNO, PF_DEC}, {"filename", PT_FSPATH, PF_NA}, {"mode", PT_MODE, PF_OCT, chmod_mode} } },

	/* PPME_SYSCALL_FCHMOD_X */{"fchmod", EC_FILE, EF_NONE, 3, {{"res", PT_ERRNO, PF_DEC}, {"fd", PT_FD, PF_DEC}, {"mode", PT_MODE, PF_OCT, chmod_mode} } },

	/* PPME_SYSCALL_RENAMEAT2_X */{"renameat2", EC_FILE, EF_NONE, 6, {{"res", PT_ERRNO, PF_DEC}, {"olddirfd", PT_FD, PF_DEC}, {"oldpath", PT_FSRELPATH, PF_NA, DIRFD_PARAM(1)}, {"newdirfd", PT_FD, PF_DEC}, {"newpath", PT_FSRELPATH, PF_NA, DIRFD_PARAM(3)}, {"flags", PT_FLAGS32, PF_HEX, renameat2_flags} } },

	/* PPME_SYSCALL_USERFAULTFD_X */{"userfaultfd", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 2, {{"res", PT_ERRNO, PF_DEC}, {"flags", PT_FLAGS32, PF_HEX, file_flags} } },
	/* PPME_PLUGINEVENT_E */{"pluginevent", EC_OTHER, EF_LARGE_PAYLOAD, 2, {{"plugin ID", PT_UINT32, PF_DEC}, {"event_data", PT_BYTEBUF, PF_NA} } },

	/* PPME_CONTAINER_JSON_2_E */{"container", EC_PROCESS, EF_MODIFIES_STATE | EF_LARGE_PAYLOAD, 1, {{"json", PT_CHARBUF, PF_NA} } },


	/* PPME_SYSCALL_OPENAT2_X */{"openat2", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 6, {{"fd", PT_FD, PF_DEC}, {"dirfd", PT_FD, PF_DEC}, {"name", PT_FSRELPATH, PF_NA, DIRFD_PARAM(1)}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT}, {"resolve", PT_FLAGS32, PF_HEX, openat2_flags} } },
	/* PPME_SYSCALL_MPROTECT_E */{"mprotect", EC_MEMORY, EF_DROP_SIMPLE_CONS, 4, {{"addr", PT_UINT64, PF_HEX}, {"length", PT_UINT64, PF_DEC}, {"prot", PT_FLAGS32, PF_HEX, prot_flags},{"res", PT_ERRNO, PF_DEC} } }, 


	/* PPME_SYSCALL_EXECVEAT_X */{"execveat", EC_PROCESS, EF_MODIFIES_STATE, 23, {{"dirfd", PT_FD, PF_DEC}, {"pathname", PT_FSRELPATH, PF_NA, DIRFD_PARAM(0)}, {"flags", PT_FLAGS32, PF_HEX, execveat_flags},{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA}, {"tty", PT_INT32, PF_DEC}, {"pgid", PT_PID, PF_DEC}, {"loginuid", PT_INT32, PF_DEC}, {"flags", PT_FLAGS32, PF_HEX, execve_flags} } },

	/* PPME_SYSCALL_COPY_FILE_RANGE_X */{"copy_file_range", EC_FILE, EF_USES_FD | EF_READS_FROM_FD | EF_WRITES_TO_FD, 6, {{"fdin", PT_FD, PF_DEC}, {"offin", PT_UINT64, PF_DEC}, {"len", PT_UINT64, PF_DEC},{"res", PT_ERRNO, PF_DEC}, {"fdout", PT_FD, PF_DEC}, {"offout", PT_UINT64, PF_DEC} } },
	/* PPME_SYSCALL_CLONE3_X */{"clone3", EC_PROCESS, EF_MODIFIES_STATE, 20, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },
 {"ptrace", EC_PROCESS, EF_NONE, 5, {{"request", PT_FLAGS16, PF_DEC, ptrace_requests}, {"pid", PT_PID, PF_DEC}, {"res", PT_ERRNO, PF_DEC}, {"addr", PT_DYN, PF_HEX, ptrace_dynamic_param, NOD_PTRACE_IDX_MAX}, {"data", PT_DYN, PF_HEX, ptrace_dynamic_param, NOD_PTRACE_IDX_MAX} } },

};
