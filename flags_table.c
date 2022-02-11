/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#include "include/events.h"

const struct spr_name_value socket_families[] = {
	{"AF_NFC", SPR_AF_NFC},
	{"AF_ALG", SPR_AF_ALG},
	{"AF_CAIF", SPR_AF_CAIF},
	{"AF_IEEE802154", SPR_AF_IEEE802154},
	{"AF_PHONET", SPR_AF_PHONET},
	{"AF_ISDN", SPR_AF_ISDN},
	{"AF_RXRPC", SPR_AF_RXRPC},
	{"AF_IUCV", SPR_AF_IUCV},
	{"AF_BLUETOOTH", SPR_AF_BLUETOOTH},
	{"AF_TIPC", SPR_AF_TIPC},
	{"AF_CAN", SPR_AF_CAN},
	{"AF_LLC", SPR_AF_LLC},
	{"AF_WANPIPE", SPR_AF_WANPIPE},
	{"AF_PPPOX", SPR_AF_PPPOX},
	{"AF_IRDA", SPR_AF_IRDA},
	{"AF_SNA", SPR_AF_SNA},
	{"AF_RDS", SPR_AF_RDS},
	{"AF_ATMSVC", SPR_AF_ATMSVC},
	{"AF_ECONET", SPR_AF_ECONET},
	{"AF_ASH", SPR_AF_ASH},
	{"AF_PACKET", SPR_AF_PACKET},
	{"AF_ROUTE", SPR_AF_ROUTE},
	{"AF_NETLINK", SPR_AF_NETLINK},
	{"AF_KEY", SPR_AF_KEY},
	{"AF_SECURITY", SPR_AF_SECURITY},
	{"AF_NETBEUI", SPR_AF_NETBEUI},
	{"AF_DECnet", SPR_AF_DECnet},
	{"AF_ROSE", SPR_AF_ROSE},
	{"AF_INET6", SPR_AF_INET6},
	{"AF_X25", SPR_AF_X25},
	{"AF_ATMPVC", SPR_AF_ATMPVC},
	{"AF_BRIDGE", SPR_AF_BRIDGE},
	{"AF_NETROM", SPR_AF_NETROM},
	{"AF_APPLETALK", SPR_AF_APPLETALK},
	{"AF_IPX", SPR_AF_IPX},
	{"AF_AX25", SPR_AF_AX25},
	{"AF_INET", SPR_AF_INET},
	{"AF_LOCAL", SPR_AF_LOCAL},
	{"AF_UNIX", SPR_AF_UNIX},
	{"AF_UNSPEC", SPR_AF_UNSPEC},
	{0, 0},
};

const struct spr_name_value file_flags[] = {
	{"O_LARGEFILE", SPR_O_LARGEFILE},
	{"O_DIRECTORY", SPR_O_DIRECTORY},
	{"O_DIRECT", SPR_O_DIRECT},
	{"O_TRUNC", SPR_O_TRUNC},
	{"O_SYNC", SPR_O_SYNC},
	{"O_NONBLOCK", SPR_O_NONBLOCK},
	{"O_EXCL", SPR_O_EXCL},
	{"O_DSYNC", SPR_O_DSYNC},
	{"O_APPEND", SPR_O_APPEND},
	{"O_CREAT", SPR_O_CREAT},
	{"O_RDWR", SPR_O_RDWR},
	{"O_WRONLY", SPR_O_WRONLY},
	{"O_RDONLY", SPR_O_RDONLY},
	{"O_CLOEXEC", SPR_O_CLOEXEC},
	{"O_NONE", SPR_O_NONE},
	{"O_TMPFILE", SPR_O_TMPFILE},
	{0, 0},
};

const struct spr_name_value flock_flags[] = {
	{"LOCK_SH", SPR_LOCK_SH},
	{"LOCK_EX", SPR_LOCK_EX},
	{"LOCK_NB", SPR_LOCK_NB},
	{"LOCK_UN", SPR_LOCK_UN},
	{"LOCK_NONE", SPR_LOCK_NONE},
	{0, 0},
};

const struct spr_name_value clone_flags[] = {
	{"CLONE_FILES", SPR_CL_CLONE_FILES},
	{"CLONE_FS", SPR_CL_CLONE_FS},
	{"CLONE_IO", SPR_CL_CLONE_IO},
	{"CLONE_NEWIPC", SPR_CL_CLONE_NEWIPC},
	{"CLONE_NEWNET", SPR_CL_CLONE_NEWNET},
	{"CLONE_NEWNS", SPR_CL_CLONE_NEWNS},
	{"CLONE_NEWPID", SPR_CL_CLONE_NEWPID},
	{"CLONE_NEWUTS", SPR_CL_CLONE_NEWUTS},
	{"CLONE_PARENT", SPR_CL_CLONE_PARENT},
	{"CLONE_PARENT_SETTID", SPR_CL_CLONE_PARENT_SETTID},
	{"CLONE_PTRACE", SPR_CL_CLONE_PTRACE},
	{"CLONE_SIGHAND", SPR_CL_CLONE_SIGHAND},
	{"CLONE_SYSVSEM", SPR_CL_CLONE_SYSVSEM},
	{"CLONE_THREAD", SPR_CL_CLONE_THREAD},
	{"CLONE_UNTRACED", SPR_CL_CLONE_UNTRACED},
	{"CLONE_VM", SPR_CL_CLONE_VM},
	{"CLONE_INVERTED", SPR_CL_CLONE_INVERTED},
	{"NAME_CHANGED", SPR_CL_NAME_CHANGED},
	{"CLOSED", SPR_CL_CLOSED},
	{"CLONE_NEWUSER", SPR_CL_CLONE_NEWUSER},
	{"CLONE_CHILD_CLEARTID", SPR_CL_CLONE_CHILD_CLEARTID},
	{"CLONE_CHILD_SETTID", SPR_CL_CLONE_CHILD_SETTID},
	{"CLONE_SETTLS", SPR_CL_CLONE_SETTLS},
	{"CLONE_STOPPED", SPR_CL_CLONE_STOPPED},
	{"CLONE_VFORK", SPR_CL_CLONE_VFORK},
	{"CLONE_NEWCGROUP", SPR_CL_CLONE_NEWCGROUP},
	{0, 0},
};

const struct spr_name_value futex_operations[] = {
	{"FUTEX_CLOCK_REALTIME", SPR_FU_FUTEX_CLOCK_REALTIME},
	{"FUTEX_PRIVATE_FLAG", SPR_FU_FUTEX_PRIVATE_FLAG},
	{"FUTEX_CMP_REQUEUE_PI", SPR_FU_FUTEX_CMP_REQUEUE_PI},
	{"FUTEX_WAIT_REQUEUE_PI", SPR_FU_FUTEX_WAIT_REQUEUE_PI},
	{"FUTEX_WAKE_BITSET", SPR_FU_FUTEX_WAKE_BITSET},
	{"FUTEX_WAIT_BITSET", SPR_FU_FUTEX_WAIT_BITSET},
	{"FUTEX_TRYLOCK_PI", SPR_FU_FUTEX_TRYLOCK_PI},
	{"FUTEX_UNLOCK_PI", SPR_FU_FUTEX_UNLOCK_PI},
	{"FUTEX_LOCK_PI", SPR_FU_FUTEX_LOCK_PI},
	{"FUTEX_WAKE_OP", SPR_FU_FUTEX_WAKE_OP},
	{"FUTEX_CMP_REQUEUE", SPR_FU_FUTEX_CMP_REQUEUE},
	{"FUTEX_REQUEUE", SPR_FU_FUTEX_REQUEUE},
	{"FUTEX_FD", SPR_FU_FUTEX_FD},
	{"FUTEX_WAKE", SPR_FU_FUTEX_WAKE},
	{"FUTEX_WAIT", SPR_FU_FUTEX_WAIT},
	{0, 0},
};

const struct spr_name_value poll_flags[] = {
	{"POLLIN", SPR_POLLIN},
	{"POLLPRI", SPR_POLLPRI},
	{"POLLOUT", SPR_POLLOUT},
	{"POLLRDHUP", SPR_POLLRDHUP},
	{"POLLERR", SPR_POLLERR},
	{"POLLHUP", SPR_POLLHUP},
	{"POLLNVAL", SPR_POLLNVAL},
	{"POLLRDNORM", SPR_POLLRDNORM},
	{"POLLRDBAND", SPR_POLLRDBAND},
	{"POLLWRNORM", SPR_POLLWRNORM},
	{"POLLWRBAND", SPR_POLLWRBAND},
	{0, 0},
};

/* http://lxr.free-electrons.com/source/include/uapi/linux/fs.h?v=4.2#L65 */
const struct spr_name_value mount_flags[] = {
	{"RDONLY", SPR_MS_RDONLY},
	{"NOSUID", SPR_MS_NOSUID},
	{"NODEV", SPR_MS_NODEV},
	{"NOEXEC", SPR_MS_NOEXEC},
	{"SYNCHRONOUS", SPR_MS_SYNCHRONOUS},
	{"REMOUNT", SPR_MS_REMOUNT},
	{"MANDLOCK", SPR_MS_MANDLOCK},
	{"DIRSYNC", SPR_MS_DIRSYNC},
	{"NOATIME", SPR_MS_NOATIME},
	{"NODIRATIME", SPR_MS_NODIRATIME},
	{"BIND", SPR_MS_BIND},
	{"MOVE", SPR_MS_MOVE},
	{"REC", SPR_MS_REC},
	{"SILENT", SPR_MS_SILENT},
	{"POSIXACL", SPR_MS_POSIXACL},
	{"UNBINDABLE", SPR_MS_UNBINDABLE},
	{"PRIVATE", SPR_MS_PRIVATE},
	{"SLAVE", SPR_MS_SLAVE},
	{"SHARED", SPR_MS_SHARED},
	{"RELATIME", SPR_MS_RELATIME},
	{"KERNMOUNT", SPR_MS_KERNMOUNT},
	{"I_VERSION", SPR_MS_I_VERSION},
	{"STRICTATIME", SPR_MS_STRICTATIME},
	{"LAZYTIME", SPR_MS_LAZYTIME},
	{"NOSEC", SPR_MS_NOSEC},
	{"BORN", SPR_MS_BORN},
	{"ACTIVE", SPR_MS_ACTIVE},
	{"NOUSER", SPR_MS_NOUSER},
	{0, 0},
};

/* http://lxr.free-electrons.com/source/include/linux/fs.h?v=4.2#L1251 */
const struct spr_name_value umount_flags[] = {
	{"FORCE", SPR_MNT_FORCE},
	{"DETACH", SPR_MNT_DETACH},
	{"EXPIRE", SPR_MNT_EXPIRE},
	{"NOFOLLOW", SPR_UMOUNT_NOFOLLOW},
	{0, 0},
};

const struct spr_name_value lseek_whence[] = {
	{"SEEK_END", SPR_SEEK_END},
	{"SEEK_CUR", SPR_SEEK_CUR},
	{"SEEK_SET", SPR_SEEK_SET},
	{0, 0},
};

const struct spr_name_value shutdown_how[] = {
	{"SHUT_RDWR", SPR_SHUT_RDWR},
	{"SHUT_WR", SPR_SHUT_WR},
	{"SHUT_RD", SPR_SHUT_RD},
	{0, 0},
};

const struct spr_name_value rlimit_resources[] = {
	{"RLIMIT_UNKNOWN", SPR_RLIMIT_UNKNOWN},
	{"RLIMIT_RTTIME", SPR_RLIMIT_RTTIME},
	{"RLIMIT_RTPRIO", SPR_RLIMIT_RTPRIO},
	{"RLIMIT_NICE", SPR_RLIMIT_NICE},
	{"RLIMIT_MSGQUEUE", SPR_RLIMIT_MSGQUEUE},
	{"RLIMIT_SIGPENDING", SPR_RLIMIT_SIGPENDING},
	{"RLIMIT_LOCKS", SPR_RLIMIT_LOCKS},
	{"RLIMIT_AS", SPR_RLIMIT_AS},
	{"RLIMIT_MEMLOCK", SPR_RLIMIT_MEMLOCK},
	{"RLIMIT_NOFILE", SPR_RLIMIT_NOFILE},
	{"RLIMIT_NPROC", SPR_RLIMIT_NPROC},
	{"RLIMIT_RSS", SPR_RLIMIT_RSS},
	{"RLIMIT_CORE", SPR_RLIMIT_CORE},
	{"RLIMIT_STACK", SPR_RLIMIT_STACK},
	{"RLIMIT_DATA", SPR_RLIMIT_DATA},
	{"RLIMIT_FSIZE", SPR_RLIMIT_FSIZE},
	{"RLIMIT_CPU", SPR_RLIMIT_CPU},
	{0, 0},
};

const struct spr_name_value fcntl_commands[] = {
	{"F_GETPIPE_SZ", SPR_FCNTL_F_GETPIPE_SZ},
	{"F_SETPIPE_SZ", SPR_FCNTL_F_SETPIPE_SZ},
	{"F_NOTIFY", SPR_FCNTL_F_NOTIFY},
	{"F_DUPFD_CLOEXEC", SPR_FCNTL_F_DUPFD_CLOEXEC},
	{"F_CANCELLK", SPR_FCNTL_F_CANCELLK},
	{"F_GETLEASE", SPR_FCNTL_F_GETLEASE},
	{"F_SETLEASE", SPR_FCNTL_F_SETLEASE},
	{"F_GETOWN_EX", SPR_FCNTL_F_GETOWN_EX},
	{"F_SETOWN_EX", SPR_FCNTL_F_SETOWN_EX},
#ifndef CONFIG_64BIT
	{"F_SETLKW64", SPR_FCNTL_F_SETLKW64},
	{"F_SETLK64", SPR_FCNTL_F_SETLK64},
	{"F_GETLK64", SPR_FCNTL_F_GETLK64},
#endif
	{"F_GETSIG", SPR_FCNTL_F_GETSIG},
	{"F_SETSIG", SPR_FCNTL_F_SETSIG},
	{"F_GETOWN", SPR_FCNTL_F_GETOWN},
	{"F_SETOWN", SPR_FCNTL_F_SETOWN},
	{"F_SETLKW", SPR_FCNTL_F_SETLKW},
	{"F_SETLK", SPR_FCNTL_F_SETLK},
	{"F_GETLK", SPR_FCNTL_F_GETLK},
	{"F_SETFL", SPR_FCNTL_F_SETFL},
	{"F_GETFL", SPR_FCNTL_F_GETFL},
	{"F_SETFD", SPR_FCNTL_F_SETFD},
	{"F_GETFD", SPR_FCNTL_F_GETFD},
	{"F_DUPFD", SPR_FCNTL_F_DUPFD},
	{"F_OFD_GETLK", SPR_FCNTL_F_OFD_GETLK},
	{"F_OFD_SETLK", SPR_FCNTL_F_OFD_SETLK},
	{"F_OFD_SETLKW", SPR_FCNTL_F_OFD_SETLKW},
	{"UNKNOWN", SPR_FCNTL_UNKNOWN},
	{0, 0},
};

const struct spr_name_value sockopt_levels[] = {
	{"SOL_SOCKET", SPR_SOCKOPT_LEVEL_SOL_SOCKET},
	{"SOL_TCP", SPR_SOCKOPT_LEVEL_SOL_TCP},
	{"UNKNOWN", SPR_SOCKOPT_LEVEL_UNKNOWN},
	{0, 0},
};

const struct spr_name_value sockopt_options[] = {
	{"SO_COOKIE", SPR_SOCKOPT_SO_COOKIE},
	{"SO_MEMINFO", SPR_SOCKOPT_SO_MEMINFO},
	{"SO_PEERGROUPS", SPR_SOCKOPT_SO_PEERGROUPS},
	{"SO_ATTACH_BPF", SPR_SOCKOPT_SO_ATTACH_BPF},
	{"SO_INCOMING_CPU", SPR_SOCKOPT_SO_INCOMING_CPU},
	{"SO_BPF_EXTENSIONS", SPR_SOCKOPT_SO_BPF_EXTENSIONS},
	{"SO_MAX_PACING_RATE", SPR_SOCKOPT_SO_MAX_PACING_RATE},
	{"SO_BUSY_POLL", SPR_SOCKOPT_SO_BUSY_POLL},
	{"SO_SELECT_ERR_QUEUE", SPR_SOCKOPT_SO_SELECT_ERR_QUEUE},
	{"SO_LOCK_FILTER", SPR_SOCKOPT_SO_LOCK_FILTER},
	{"SO_NOFCS", SPR_SOCKOPT_SO_NOFCS},
	{"SO_PEEK_OFF", SPR_SOCKOPT_SO_PEEK_OFF},
	{"SO_WIFI_STATUS", SPR_SOCKOPT_SO_WIFI_STATUS},
	{"SO_RXQ_OVFL", SPR_SOCKOPT_SO_RXQ_OVFL},
	{"SO_DOMAIN", SPR_SOCKOPT_SO_DOMAIN},
	{"SO_PROTOCOL", SPR_SOCKOPT_SO_PROTOCOL},
	{"SO_TIMESTAMPING", SPR_SOCKOPT_SO_TIMESTAMPING},
	{"SO_MARK", SPR_SOCKOPT_SO_MARK},
	{"SO_TIMESTAMPNS", SPR_SOCKOPT_SO_TIMESTAMPNS},
	{"SO_PASSSEC", SPR_SOCKOPT_SO_PASSSEC},
	{"SO_PEERSEC", SPR_SOCKOPT_SO_PEERSEC},
	{"SO_ACCEPTCONN", SPR_SOCKOPT_SO_ACCEPTCONN},
	{"SO_TIMESTAMP", SPR_SOCKOPT_SO_TIMESTAMP},
	{"SO_PEERNAME", SPR_SOCKOPT_SO_PEERNAME},
	{"SO_DETACH_FILTER", SPR_SOCKOPT_SO_DETACH_FILTER},
	{"SO_ATTACH_FILTER", SPR_SOCKOPT_SO_ATTACH_FILTER},
	{"SO_BINDTODEVICE", SPR_SOCKOPT_SO_BINDTODEVICE},
	{"SO_SECURITY_ENCRYPTION_NETWORK", SPR_SOCKOPT_SO_SECURITY_ENCRYPTION_NETWORK},
	{"SO_SECURITY_ENCRYPTION_TRANSPORT", SPR_SOCKOPT_SO_SECURITY_ENCRYPTION_TRANSPORT},
	{"SO_SECURITY_AUTHENTICATION", SPR_SOCKOPT_SO_SECURITY_AUTHENTICATION},
	{"SO_SNDTIMEO", SPR_SOCKOPT_SO_SNDTIMEO},
	{"SO_RCVTIMEO", SPR_SOCKOPT_SO_RCVTIMEO},
	{"SO_SNDLOWAT", SPR_SOCKOPT_SO_SNDLOWAT},
	{"SO_RCVLOWAT", SPR_SOCKOPT_SO_RCVLOWAT},
	{"SO_PEERCRED", SPR_SOCKOPT_SO_PEERCRED},
	{"SO_PASSCRED", SPR_SOCKOPT_SO_PASSCRED},
	{"SO_REUSEPORT", SPR_SOCKOPT_SO_REUSEPORT},
	{"SO_BSDCOMPAT", SPR_SOCKOPT_SO_BSDCOMPAT},
	{"SO_LINGER", SPR_SOCKOPT_SO_LINGER},
	{"SO_PRIORITY", SPR_SOCKOPT_SO_PRIORITY},
	{"SO_NO_CHECK", SPR_SOCKOPT_SO_NO_CHECK},
	{"SO_OOBINLINE", SPR_SOCKOPT_SO_OOBINLINE},
	{"SO_KEEPALIVE", SPR_SOCKOPT_SO_KEEPALIVE},
	{"SO_RCVBUFFORCE", SPR_SOCKOPT_SO_RCVBUFFORCE},
	{"SO_SNDBUFFORCE", SPR_SOCKOPT_SO_SNDBUFFORCE},
	{"SO_RCVBUF", SPR_SOCKOPT_SO_RCVBUF},
	{"SO_SNDBUF", SPR_SOCKOPT_SO_SNDBUF},
	{"SO_BROADCAST", SPR_SOCKOPT_SO_BROADCAST},
	{"SO_DONTROUTE", SPR_SOCKOPT_SO_DONTROUTE},
	{"SO_ERROR", SPR_SOCKOPT_SO_ERROR},
	{"SO_TYPE", SPR_SOCKOPT_SO_TYPE},
	{"SO_REUSEADDR", SPR_SOCKOPT_SO_REUSEADDR},
	{"SO_DEBUG", SPR_SOCKOPT_SO_DEBUG},
	{"UNKNOWN", SPR_SOCKOPT_UNKNOWN},
	{0, 0},
};

const struct spr_name_value ptrace_requests[] = {
	{"PTRACE_SINGLEBLOCK", SPR_PTRACE_SINGLEBLOCK},
	{"PTRACE_SYSEMU_SINGLESTEP", SPR_PTRACE_SYSEMU_SINGLESTEP},
	{"PTRACE_SYSEMU", SPR_PTRACE_SYSEMU},
	{"PTRACE_ARCH_PRCTL", SPR_PTRACE_ARCH_PRCTL},
	{"PTRACE_SET_THREAD_AREA", SPR_PTRACE_SET_THREAD_AREA},
	{"PTRACE_GET_THREAD_AREA", SPR_PTRACE_GET_THREAD_AREA},
	{"PTRACE_OLDSETOPTIONS", SPR_PTRACE_OLDSETOPTIONS},
	{"PTRACE_SETFPXREGS", SPR_PTRACE_SETFPXREGS},
	{"PTRACE_GETFPXREGS", SPR_PTRACE_GETFPXREGS},
	{"PTRACE_SETFPREGS", SPR_PTRACE_SETFPREGS},
	{"PTRACE_GETFPREGS", SPR_PTRACE_GETFPREGS},
	{"PTRACE_SETREGS", SPR_PTRACE_SETREGS},
	{"PTRACE_GETREGS", SPR_PTRACE_GETREGS},
	{"PTRACE_SETSIGMASK", SPR_PTRACE_SETSIGMASK},
	{"PTRACE_GETSIGMASK", SPR_PTRACE_GETSIGMASK},
	{"PTRACE_PEEKSIGINFO", SPR_PTRACE_PEEKSIGINFO},
	{"PTRACE_LISTEN", SPR_PTRACE_LISTEN},
	{"PTRACE_INTERRUPT", SPR_PTRACE_INTERRUPT},
	{"PTRACE_SEIZE", SPR_PTRACE_SEIZE},
	{"PTRACE_SETREGSET", SPR_PTRACE_SETREGSET},
	{"PTRACE_GETREGSET", SPR_PTRACE_GETREGSET},
	{"PTRACE_SETSIGINFO", SPR_PTRACE_SETSIGINFO},
	{"PTRACE_GETSIGINFO", SPR_PTRACE_GETSIGINFO},
	{"PTRACE_GETEVENTMSG", SPR_PTRACE_GETEVENTMSG},
	{"PTRACE_SETOPTIONS", SPR_PTRACE_SETOPTIONS},
	{"PTRACE_SYSCALL", SPR_PTRACE_SYSCALL},
	{"PTRACE_DETACH", SPR_PTRACE_DETACH},
	{"PTRACE_ATTACH", SPR_PTRACE_ATTACH},
	{"PTRACE_SINGLESTEP", SPR_PTRACE_SINGLESTEP},
	{"PTRACE_KILL", SPR_PTRACE_KILL},
	{"PTRACE_CONT", SPR_PTRACE_CONT},
	{"PTRACE_POKEUSR", SPR_PTRACE_POKEUSR},
	{"PTRACE_POKEDATA", SPR_PTRACE_POKEDATA},
	{"PTRACE_POKETEXT", SPR_PTRACE_POKETEXT},
	{"PTRACE_PEEKUSR", SPR_PTRACE_PEEKUSR},
	{"PTRACE_PEEKDATA", SPR_PTRACE_PEEKDATA},
	{"PTRACE_PEEKTEXT", SPR_PTRACE_PEEKTEXT},
	{"PTRACE_TRACEME", SPR_PTRACE_TRACEME},
	{"PTRACE_UNKNOWN", SPR_PTRACE_UNKNOWN},
	{0, 0},
};

const struct spr_name_value prot_flags[] = {
	{"PROT_READ", SPR_PROT_READ},
	{"PROT_WRITE", SPR_PROT_WRITE},
	{"PROT_EXEC", SPR_PROT_EXEC},
	{"PROT_SEM", SPR_PROT_SEM},
	{"PROT_GROWSDOWN", SPR_PROT_GROWSDOWN},
	{"PROT_GROWSUP", SPR_PROT_GROWSUP},
	{"PROT_SAO", SPR_PROT_SAO},
	{"PROT_NONE", SPR_PROT_NONE},
	{0, 0},
};

const struct spr_name_value mmap_flags[] = {
	{"MAP_SHARED", SPR_MAP_SHARED},
	{"MAP_PRIVATE", SPR_MAP_PRIVATE},
	{"MAP_FIXED", SPR_MAP_FIXED},
	{"MAP_ANONYMOUS", SPR_MAP_ANONYMOUS},
	{"MAP_32BIT", SPR_MAP_32BIT},
	{"MAP_RENAME", SPR_MAP_RENAME},
	{"MAP_NORESERVE", SPR_MAP_NORESERVE},
	{"MAP_POPULATE", SPR_MAP_POPULATE},
	{"MAP_NONBLOCK", SPR_MAP_NONBLOCK},
	{"MAP_GROWSDOWN", SPR_MAP_GROWSDOWN},
	{"MAP_DENYWRITE", SPR_MAP_DENYWRITE},
	{"MAP_EXECUTABLE", SPR_MAP_EXECUTABLE},
	{"MAP_INHERIT", SPR_MAP_INHERIT},
	{"MAP_FILE", SPR_MAP_FILE},
	{"MAP_LOCKED", SPR_MAP_LOCKED},
	{0, 0},
};

const struct spr_name_value splice_flags[] = {
	{"SPLICE_F_MOVE", SPR_SPLICE_F_MOVE},
	{"SPLICE_F_NONBLOCK", SPR_SPLICE_F_NONBLOCK},
	{"SPLICE_F_MORE", SPR_SPLICE_F_MORE},
	{"SPLICE_F_GIFT", SPR_SPLICE_F_GIFT},
	{0, 0},
};

const struct spr_name_value quotactl_dqi_flags[] = {
	{"DQF_NONE", SPR_DQF_NONE},
	{"V1_DQF_RSQUASH", SPR_V1_DQF_RSQUASH},
	{0, 0},
};

const struct spr_name_value quotactl_cmds[] = {
	{"Q_QUOTAON", SPR_Q_QUOTAON},
	{"Q_QUOTAOFF", SPR_Q_QUOTAOFF},
	{"Q_GETFMT", SPR_Q_GETFMT},
	{"Q_GETINFO", SPR_Q_GETINFO},
	{"Q_SETINFO", SPR_Q_SETINFO},
	{"Q_GETQUOTA", SPR_Q_GETQUOTA},
	{"Q_SETQUOTA", SPR_Q_SETQUOTA},
	{"Q_SYNC", SPR_Q_SYNC},
	{"Q_XQUOTAON", SPR_Q_XQUOTAON},
	{"Q_XQUOTAOFF", SPR_Q_XQUOTAOFF},
	{"Q_XGETQUOTA", SPR_Q_XGETQUOTA},
	{"Q_XSETQLIM", SPR_Q_XSETQLIM},
	{"Q_XGETQSTAT", SPR_Q_XGETQSTAT},
	{"Q_XQUOTARM", SPR_Q_XQUOTARM},
	{"Q_XQUOTASYNC", SPR_Q_XQUOTASYNC},
	{0, 0},
};

const struct spr_name_value quotactl_types[] = {
	{"USRQUOTA", SPR_USRQUOTA},
	{"GRPQUOTA", SPR_GRPQUOTA},
	{0, 0},
};

const struct spr_name_value quotactl_quota_fmts[] = {
	{"QFMT_NOT_USED", SPR_QFMT_NOT_USED},
	{"QFMT_VFS_OLD", SPR_QFMT_VFS_OLD},
	{"QFMT_VFS_V0", SPR_QFMT_VFS_V0},
	{"QFMT_VFS_V1", SPR_QFMT_VFS_V1},
	{0, 0},
};

const struct spr_name_value semop_flags[] = {
	{"IPC_NOWAIT", SPR_IPC_NOWAIT},
	{"SEM_UNDO", SPR_SEM_UNDO},
	{0, 0},
};

const struct spr_name_value semget_flags[] = {
	{"IPC_EXCL", SPR_IPC_EXCL},
	{"IPC_CREAT", SPR_IPC_CREAT},
	{0, 0},
};

const struct spr_name_value semctl_commands[] = {
	{"IPC_STAT", SPR_IPC_STAT},
	{"IPC_SET", SPR_IPC_SET},
	{"IPC_RMID", SPR_IPC_RMID},
	{"IPC_INFO", SPR_IPC_INFO},
	{"SEM_INFO", SPR_SEM_INFO},
	{"SEM_STAT", SPR_SEM_STAT},
	{"GETALL", SPR_GETALL},
	{"GETNCNT", SPR_GETNCNT},
	{"GETPID", SPR_GETPID},
	{"GETVAL", SPR_GETVAL},
	{"GETZCNT", SPR_GETZCNT},
	{"SETALL", SPR_SETALL},
	{"SETVAL", SPR_SETVAL},
	{0, 0},
};

const struct spr_name_value access_flags[] = {
	{"F_OK", SPR_F_OK},
	{"R_OK", SPR_R_OK},
	{"W_OK", SPR_W_OK},
	{"X_OK", SPR_X_OK},
	{0, 0},
};

const struct spr_name_value pf_flags[] = {
	{"PROTECTION_VIOLATION", SPR_PF_PROTECTION_VIOLATION},
	{"PAGE_NOT_PRESENT", SPR_PF_PAGE_NOT_PRESENT},
	{"WRITE_ACCESS", SPR_PF_WRITE_ACCESS},
	{"READ_ACCESS", SPR_PF_READ_ACCESS},
	{"USER_FAULT", SPR_PF_USER_FAULT},
	{"SUPERVISOR_FAULT", SPR_PF_SUPERVISOR_FAULT},
	{"RESERVED_PAGE", SPR_PF_RESERVED_PAGE},
	{"INSTRUCTION_FETCH", SPR_PF_INSTRUCTION_FETCH},
	{0, 0},
};

const struct spr_name_value unlinkat_flags[] = {
	{"AT_REMOVEDIR", SPR_AT_REMOVEDIR},
	{0, 0},
};

const struct spr_name_value linkat_flags[] = {
	{"AT_SYMLINK_FOLLOW", SPR_AT_SYMLINK_FOLLOW},
	{"AT_EMPTY_PATH", SPR_AT_EMPTY_PATH},
	{0, 0},
};

const struct spr_name_value chmod_mode[] = {
    {"S_IXOTH", SPR_S_IXOTH},
    {"S_IWOTH", SPR_S_IWOTH},
    {"S_IROTH", SPR_S_IROTH},
    {"S_IXGRP", SPR_S_IXGRP},
    {"S_IWGRP", SPR_S_IWGRP},
    {"S_IRGRP", SPR_S_IRGRP},
    {"S_IXUSR", SPR_S_IXUSR},
    {"S_IWUSR", SPR_S_IWUSR},
    {"S_IRUSR", SPR_S_IRUSR},
    {"S_ISVTX", SPR_S_ISVTX},
    {"S_ISGID", SPR_S_ISGID},
    {"S_ISUID", SPR_S_ISUID},
    {0, 0},
};

const struct spr_name_value renameat2_flags[] = {
	{"RENAME_NOREPLACE", SPR_RENAME_NOREPLACE},
	{"RENAME_EXCHANGE", SPR_RENAME_EXCHANGE},
	{"RENAME_WHITEOUT", SPR_RENAME_WHITEOUT},
	{0, 0},
};
