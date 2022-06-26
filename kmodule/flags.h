#ifndef NOD_FLAG_HELPERS_H_
#define NOD_FLAG_HELPERS_H_

#include <linux/mman.h>
#include <linux/futex.h>
#include <linux/ptrace.h>

#include "events.h"

#define NOD_MS_MGC_MSK 0xffff0000
#define NOD_MS_MGC_VAL 0xC0ED0000

static __always_inline uint32_t open_flags_to_scap(unsigned long flags)
{
	uint32_t res = 0;

	switch (flags & (O_RDONLY | O_WRONLY | O_RDWR)) {
	case O_WRONLY:
		res |= NOD_O_WRONLY;
		break;
	case O_RDWR:
		res |= NOD_O_RDWR;
		break;
	default:
		res |= NOD_O_RDONLY;
		break;
	}

	if (flags & O_CREAT)
		res |= NOD_O_CREAT;
#ifdef O_TMPFILE
	if (flags & O_TMPFILE)
		res |= NOD_O_TMPFILE;
#endif

	if (flags & O_APPEND)
		res |= NOD_O_APPEND;

#ifdef O_DSYNC
	if (flags & O_DSYNC)
		res |= NOD_O_DSYNC;
#endif

	if (flags & O_EXCL)
		res |= NOD_O_EXCL;

#ifdef O_NONBLOCK
	if (flags & O_NONBLOCK)
		res |= NOD_O_NONBLOCK;
#endif

#ifdef O_SYNC
	if (flags & O_SYNC)
		res |= NOD_O_SYNC;
#endif

	if (flags & O_TRUNC)
		res |= NOD_O_TRUNC;

#ifdef O_DIRECT
	if (flags & O_DIRECT)
		res |= NOD_O_DIRECT;
#endif

#ifdef O_DIRECTORY
	if (flags & O_DIRECTORY)
		res |= NOD_O_DIRECTORY;
#endif

#ifdef O_LARGEFILE
	if (flags & O_LARGEFILE)
		res |= NOD_O_LARGEFILE;
#endif

#ifdef O_CLOEXEC
	if (flags & O_CLOEXEC)
		res |= NOD_O_CLOEXEC;
#endif

	return res;
}

static __always_inline u32 open_modes_to_scap(unsigned long flags,
					      unsigned long modes)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	unsigned long flags_mask = O_CREAT | O_TMPFILE;
#else
	unsigned long flags_mask = O_CREAT;
#endif
	u32 res = 0;

	if ((flags & flags_mask) == 0)
		return res;

	if (modes & S_IRUSR)
		res |= NOD_S_IRUSR;

	if (modes & S_IWUSR)
		res |= NOD_S_IWUSR;

	if (modes & S_IXUSR)
		res |= NOD_S_IXUSR;

	/*
	* NOD_S_IRWXU == S_IRUSR | S_IWUSR | S_IXUSR
	*/

	if (modes & S_IRGRP)
		res |= NOD_S_IRGRP;

	if (modes & S_IWGRP)
		res |= NOD_S_IWGRP;

	if (modes & S_IXGRP)
		res |= NOD_S_IXGRP;

	/*
	* NOD_S_IRWXG == S_IRGRP | S_IWGRP | S_IXGRP
	*/

	if (modes & S_IROTH)
		res |= NOD_S_IROTH;

	if (modes & S_IWOTH)
		res |= NOD_S_IWOTH;

	if (modes & S_IXOTH)
		res |= NOD_S_IXOTH;

	/*
	* NOD_S_IRWXO == S_IROTH | S_IWOTH | S_IXOTH
	*/

	if (modes & S_ISUID)
		res |= NOD_S_ISUID;

	if (modes & S_ISGID)
		res |= NOD_S_ISGID;

	if (modes & S_ISVTX)
		res |= NOD_S_ISVTX;

	return res;
}

static __always_inline u32 clone_flags_to_scap(unsigned long flags)
{
	u32 res = 0;

	if (flags & CLONE_FILES)
		res |= NOD_CL_CLONE_FILES;

	if (flags & CLONE_FS)
		res |= NOD_CL_CLONE_FS;

#ifdef CLONE_IO
	if (flags & CLONE_IO)
		res |= NOD_CL_CLONE_IO;
#endif

#ifdef CLONE_NEWIPC
	if (flags & CLONE_NEWIPC)
		res |= NOD_CL_CLONE_NEWIPC;
#endif

#ifdef CLONE_NEWNET
	if (flags & CLONE_NEWNET)
		res |= NOD_CL_CLONE_NEWNET;
#endif

#ifdef CLONE_NEWNS
	if (flags & CLONE_NEWNS)
		res |= NOD_CL_CLONE_NEWNS;
#endif

#ifdef CLONE_NEWPID
	if (flags & CLONE_NEWPID)
		res |= NOD_CL_CLONE_NEWPID;
#endif

#ifdef CLONE_NEWUTS
	if (flags & CLONE_NEWUTS)
		res |= NOD_CL_CLONE_NEWUTS;
#endif

	if (flags & CLONE_PARENT_SETTID)
		res |= NOD_CL_CLONE_PARENT_SETTID;

	if (flags & CLONE_PARENT)
		res |= NOD_CL_CLONE_PARENT;

	if (flags & CLONE_PTRACE)
		res |= NOD_CL_CLONE_PTRACE;

	if (flags & CLONE_SIGHAND)
		res |= NOD_CL_CLONE_SIGHAND;

	if (flags & CLONE_SYSVSEM)
		res |= NOD_CL_CLONE_SYSVSEM;

	if (flags & CLONE_THREAD)
		res |= NOD_CL_CLONE_THREAD;

	if (flags & CLONE_UNTRACED)
		res |= NOD_CL_CLONE_UNTRACED;

	if (flags & CLONE_VM)
		res |= NOD_CL_CLONE_VM;

#ifdef CLONE_NEWUSER
	if (flags & CLONE_NEWUSER)
		res |= NOD_CL_CLONE_NEWUSER;
#endif

	if (flags & CLONE_CHILD_CLEARTID)
		res |= NOD_CL_CLONE_CHILD_CLEARTID;

	if (flags & CLONE_CHILD_SETTID)
		res |= NOD_CL_CLONE_CHILD_SETTID;

	if (flags & CLONE_SETTLS)
		res |= NOD_CL_CLONE_SETTLS;

#ifdef CLONE_STOPPED
	if (flags & CLONE_STOPPED)
		res |= NOD_CL_CLONE_STOPPED;
#endif

	if (flags & CLONE_VFORK)
		res |= NOD_CL_CLONE_VFORK;

#ifdef CLONE_NEWCGROUP
	if (flags & CLONE_NEWCGROUP)
		res |= 	NOD_CL_CLONE_NEWCGROUP;
#endif

	return res;
}

static __always_inline u8 socket_family_to_scap(u8 family)
{
	if (family == AF_INET)
		return NOD_AF_INET;
	else if (family == AF_INET6)
		return NOD_AF_INET6;
	else if (family == AF_UNIX)
		return NOD_AF_UNIX;
#ifdef AF_NETLINK
	else if (family == AF_NETLINK)
		return NOD_AF_NETLINK;
#endif
#ifdef AF_PACKET
	else if (family == AF_PACKET)
		return NOD_AF_PACKET;
#endif
#ifdef AF_UNSPEC
	else if (family == AF_UNSPEC)
		return NOD_AF_UNSPEC;
#endif
#ifdef AF_AX25
	else if (family == AF_AX25)
		return NOD_AF_AX25;
#endif
#ifdef AF_IPX
	else if (family == AF_IPX)
		return NOD_AF_IPX;
#endif
#ifdef AF_APPLETALK
	else if (family == AF_APPLETALK)
		return NOD_AF_APPLETALK;
#endif
#ifdef AF_NETROM
	else if (family == AF_NETROM)
		return NOD_AF_NETROM;
#endif
#ifdef AF_BRIDGE
	else if (family == AF_BRIDGE)
		return NOD_AF_BRIDGE;
#endif
#ifdef AF_ATMPVC
	else if (family == AF_ATMPVC)
		return NOD_AF_ATMPVC;
#endif
#ifdef AF_X25
	else if (family == AF_X25)
		return NOD_AF_X25;
#endif
#ifdef AF_ROSE
	else if (family == AF_ROSE)
		return NOD_AF_ROSE;
#endif
#ifdef AF_DECnet
	else if (family == AF_DECnet)
		return NOD_AF_DECnet;
#endif
#ifdef AF_NETBEUI
	else if (family == AF_NETBEUI)
		return NOD_AF_NETBEUI;
#endif
#ifdef AF_SECURITY
	else if (family == AF_SECURITY)
		return NOD_AF_SECURITY;
#endif
#ifdef AF_KEY
	else if (family == AF_KEY)
		return NOD_AF_KEY;
#endif
#ifdef AF_ROUTE
	else if (family == AF_ROUTE)
		return NOD_AF_ROUTE;
#endif
#ifdef AF_ASH
	else if (family == AF_ASH)
		return NOD_AF_ASH;
#endif
#ifdef AF_ECONET
	else if (family == AF_ECONET)
		return NOD_AF_ECONET;
#endif
#ifdef AF_ATMSVC
	else if (family == AF_ATMSVC)
		return NOD_AF_ATMSVC;
#endif
#ifdef AF_RDS
	else if (family == AF_RDS)
		return NOD_AF_RDS;
#endif
#ifdef AF_SNA
	else if (family == AF_SNA)
		return NOD_AF_SNA;
#endif
#ifdef AF_IRDA
	else if (family == AF_IRDA)
		return NOD_AF_IRDA;
#endif
#ifdef AF_PPPOX
	else if (family == AF_PPPOX)
		return NOD_AF_PPPOX;
#endif
#ifdef AF_WANPIPE
	else if (family == AF_WANPIPE)
		return NOD_AF_WANPIPE;
#endif
#ifdef AF_LLC
	else if (family == AF_LLC)
		return NOD_AF_LLC;
#endif
#ifdef AF_CAN
	else if (family == AF_CAN)
		return NOD_AF_CAN;
#endif
#ifdef AF_TIPC
	 else if (family == AF_TIPC)
		return NOD_AF_TIPC;
#endif
#ifdef AF_BLUETOOTH
	else if (family == AF_BLUETOOTH)
		return NOD_AF_BLUETOOTH;
#endif
#ifdef AF_IUCV
	else if (family == AF_IUCV)
		return NOD_AF_IUCV;
#endif
#ifdef AF_RXRPC
	else if (family == AF_RXRPC)
		return NOD_AF_RXRPC;
#endif
#ifdef AF_ISDN
	else if (family == AF_ISDN)
		return NOD_AF_ISDN;
#endif
#ifdef AF_PHONET
	else if (family == AF_PHONET)
		return NOD_AF_PHONET;
#endif
#ifdef AF_IEEE802154
	else if (family == AF_IEEE802154)
		return NOD_AF_IEEE802154;
#endif
#ifdef AF_CAIF
	else if (family == AF_CAIF)
		return NOD_AF_CAIF;
#endif
#ifdef AF_ALG
	else if (family == AF_ALG)
		return NOD_AF_ALG;
#endif
#ifdef AF_NFC
	else if (family == AF_NFC)
		return NOD_AF_NFC;
#endif
	else {
		ASSERT(false);
		return NOD_AF_UNSPEC;
	}
}

static __always_inline u32 prot_flags_to_scap(int prot)
{
	u32 res = 0;

	if (prot & PROT_READ)
		res |= NOD_PROT_READ;

	if (prot & PROT_WRITE)
		res |= NOD_PROT_WRITE;

	if (prot & PROT_EXEC)
		res |= NOD_PROT_EXEC;

#ifdef PROT_SEM
	if (prot & PROT_SEM)
		res |= NOD_PROT_SEM;
#endif

	if (prot & PROT_GROWSDOWN)
		res |= NOD_PROT_GROWSDOWN;

	if (prot & PROT_GROWSUP)
		res |= NOD_PROT_GROWSUP;

#ifdef PROT_SAO
	if (prot & PROT_SAO)
		res |= NOD_PROT_SAO;
#endif

	return res;
}

static __always_inline u32 mmap_flags_to_scap(int flags)
{
	u32 res = 0;

	if (flags & MAP_SHARED)
		res |= NOD_MAP_SHARED;

	if (flags & MAP_PRIVATE)
		res |= NOD_MAP_PRIVATE;

	if (flags & MAP_FIXED)
		res |= NOD_MAP_FIXED;

	if (flags & MAP_ANONYMOUS)
		res |= NOD_MAP_ANONYMOUS;

#ifdef MAP_32BIT
	if (flags & MAP_32BIT)
		res |= NOD_MAP_32BIT;
#endif

#ifdef MAP_RENAME
	if (flags & MAP_RENAME)
		res |= NOD_MAP_RENAME;
#endif

	if (flags & MAP_NORESERVE)
		res |= NOD_MAP_NORESERVE;

	if (flags & MAP_POPULATE)
		res |= NOD_MAP_POPULATE;

	if (flags & MAP_NONBLOCK)
		res |= NOD_MAP_NONBLOCK;

	if (flags & MAP_GROWSDOWN)
		res |= NOD_MAP_GROWSDOWN;

	if (flags & MAP_DENYWRITE)
		res |= NOD_MAP_DENYWRITE;

	if (flags & MAP_EXECUTABLE)
		res |= NOD_MAP_EXECUTABLE;

#ifdef MAP_INHERIT
	if (flags & MAP_INHERIT)
		res |= NOD_MAP_INHERIT;
#endif

	if (flags & MAP_FILE)
		res |= NOD_MAP_FILE;

	if (flags & MAP_LOCKED)
		res |= NOD_MAP_LOCKED;

	return res;
}

static __always_inline u8 fcntl_cmd_to_scap(unsigned long cmd)
{
	switch (cmd) {
	case F_DUPFD:
		return NOD_FCNTL_F_DUPFD;
	case F_GETFD:
		return NOD_FCNTL_F_GETFD;
	case F_SETFD:
		return NOD_FCNTL_F_SETFD;
	case F_GETFL:
		return NOD_FCNTL_F_GETFL;
	case F_SETFL:
		return NOD_FCNTL_F_SETFL;
	case F_GETLK:
		return NOD_FCNTL_F_GETLK;
	case F_SETLK:
		return NOD_FCNTL_F_SETLK;
	case F_SETLKW:
		return NOD_FCNTL_F_SETLKW;
	case F_SETOWN:
		return NOD_FCNTL_F_SETOWN;
	case F_GETOWN:
		return NOD_FCNTL_F_GETOWN;
	case F_SETSIG:
		return NOD_FCNTL_F_SETSIG;
	case F_GETSIG:
		return NOD_FCNTL_F_GETSIG;
#ifndef CONFIG_64BIT
	case F_GETLK64:
		return NOD_FCNTL_F_GETLK64;
	case F_SETLK64:
		return NOD_FCNTL_F_SETLK64;
	case F_SETLKW64:
		return NOD_FCNTL_F_SETLKW64;
#endif
#ifdef F_SETOWN_EX
	case F_SETOWN_EX:
		return NOD_FCNTL_F_SETOWN_EX;
#endif
#ifdef F_GETOWN_EX
	case F_GETOWN_EX:
		return NOD_FCNTL_F_GETOWN_EX;
#endif
	case F_SETLEASE:
		return NOD_FCNTL_F_SETLEASE;
	case F_GETLEASE:
		return NOD_FCNTL_F_GETLEASE;
	case F_CANCELLK:
		return NOD_FCNTL_F_CANCELLK;
#ifdef F_DUPFD_CLOEXEC
	case F_DUPFD_CLOEXEC:
		return NOD_FCNTL_F_DUPFD_CLOEXEC;
#endif
	case F_NOTIFY:
		return NOD_FCNTL_F_NOTIFY;
#ifdef F_SETPIPE_SZ
	case F_SETPIPE_SZ:
		return NOD_FCNTL_F_SETPIPE_SZ;
#endif
#ifdef F_GETPIPE_SZ
	case F_GETPIPE_SZ:
		return NOD_FCNTL_F_GETPIPE_SZ;
#endif
#ifdef F_OFD_GETLK
	case F_OFD_GETLK:
		return NOD_FCNTL_F_OFD_GETLK;
#endif
#ifdef F_OFD_SETLK
	case F_OFD_SETLK:
		return NOD_FCNTL_F_OFD_SETLK;
#endif
#ifdef F_OFD_SETLKW
	case F_OFD_SETLKW:
		return NOD_FCNTL_F_OFD_SETLKW;
#endif
	default:
		ASSERT(false);
		return NOD_FCNTL_UNKNOWN;
	}
}

static __always_inline u8 sockopt_level_to_scap(int level)
{
	switch (level) {
		case SOL_SOCKET:
			return NOD_SOCKOPT_LEVEL_SOL_SOCKET;
#ifdef SOL_TCP
		case SOL_TCP:
			return NOD_SOCKOPT_LEVEL_SOL_TCP;
#endif
		default:
			/* no ASSERT as there are legitimate other levels we don't just support yet */
			return NOD_SOCKOPT_LEVEL_UNKNOWN;
	}
}

static __always_inline u8 sockopt_optname_to_scap(int level, int optname)
{
	if (level != SOL_SOCKET)
	{
		/* no ASSERT as there are legitimate other levels we don't just support yet */
		return NOD_SOCKOPT_LEVEL_UNKNOWN;
	}
	switch (optname) {
#ifdef SO_DEBUG
		case SO_DEBUG:
			return NOD_SOCKOPT_SO_DEBUG;
#endif
#ifdef SO_REUSEADDR
		case SO_REUSEADDR:
			return NOD_SOCKOPT_SO_REUSEADDR;
#endif
#ifdef SO_TYPE
		case SO_TYPE:
			return NOD_SOCKOPT_SO_TYPE;
#endif
#ifdef SO_ERROR
		case SO_ERROR:
			return NOD_SOCKOPT_SO_ERROR;
#endif
#ifdef SO_DONTROUTE
		case SO_DONTROUTE:
			return NOD_SOCKOPT_SO_DONTROUTE;
#endif
#ifdef SO_BROADCAST
		case SO_BROADCAST:
			return NOD_SOCKOPT_SO_BROADCAST;
#endif
#ifdef SO_SNDBUF
		case SO_SNDBUF:
			return NOD_SOCKOPT_SO_SNDBUF;
#endif
#ifdef SO_RCVBUF
		case SO_RCVBUF:
			return NOD_SOCKOPT_SO_RCVBUF;
#endif
#ifdef SO_SNDBUFFORCE
		case SO_SNDBUFFORCE:
			return NOD_SOCKOPT_SO_SNDBUFFORCE;
#endif
#ifdef SO_RCVBUFFORCE
		case SO_RCVBUFFORCE:
			return NOD_SOCKOPT_SO_RCVBUFFORCE;
#endif
#ifdef SO_KEEPALIVE
		case SO_KEEPALIVE:
			return NOD_SOCKOPT_SO_KEEPALIVE;
#endif
#ifdef SO_OOBINLINE
		case SO_OOBINLINE:
			return NOD_SOCKOPT_SO_OOBINLINE;
#endif
#ifdef SO_NO_CHECK
		case SO_NO_CHECK:
			return NOD_SOCKOPT_SO_NO_CHECK;
#endif
#ifdef SO_PRIORITY
		case SO_PRIORITY:
			return NOD_SOCKOPT_SO_PRIORITY;
#endif
#ifdef SO_LINGER
		case SO_LINGER:
			return NOD_SOCKOPT_SO_LINGER;
#endif
#ifdef SO_BSDCOMPAT
		case SO_BSDCOMPAT:
			return NOD_SOCKOPT_SO_BSDCOMPAT;
#endif
#ifdef SO_REUSEPORT
		case SO_REUSEPORT:
			return NOD_SOCKOPT_SO_REUSEPORT;
#endif
#ifdef SO_PASSCRED
		case SO_PASSCRED:
			return NOD_SOCKOPT_SO_PASSCRED;
#endif
#ifdef SO_PEERCRED
		case SO_PEERCRED:
			return NOD_SOCKOPT_SO_PEERCRED;
#endif
#ifdef SO_RCVLOWAT
		case SO_RCVLOWAT:
			return NOD_SOCKOPT_SO_RCVLOWAT;
#endif
#ifdef SO_SNDLOWAT
		case SO_SNDLOWAT:
			return NOD_SOCKOPT_SO_SNDLOWAT;
#endif
#ifdef SO_RCVTIMEO
		case SO_RCVTIMEO:
			return NOD_SOCKOPT_SO_RCVTIMEO;
#endif
#ifdef SO_SNDTIMEO
		case SO_SNDTIMEO:
			return NOD_SOCKOPT_SO_SNDTIMEO;
#endif
#ifdef SO_SECURITY_AUTHENTICATION
		case SO_SECURITY_AUTHENTICATION:
			return NOD_SOCKOPT_SO_SECURITY_AUTHENTICATION;
#endif
#ifdef SO_SECURITY_ENCRYPTION_TRANSPORT
		case SO_SECURITY_ENCRYPTION_TRANSPORT:
			return NOD_SOCKOPT_SO_SECURITY_ENCRYPTION_TRANSPORT;
#endif
#ifdef SO_SECURITY_ENCRYPTION_NETWORK
		case SO_SECURITY_ENCRYPTION_NETWORK:
			return NOD_SOCKOPT_SO_SECURITY_ENCRYPTION_NETWORK;
#endif
#ifdef SO_BINDTODEVICE
		case SO_BINDTODEVICE:
			return NOD_SOCKOPT_SO_BINDTODEVICE;
#endif
#ifdef SO_ATTACH_FILTER
		case SO_ATTACH_FILTER:
			return NOD_SOCKOPT_SO_ATTACH_FILTER;
#endif
#ifdef SO_DETACH_FILTER
		case SO_DETACH_FILTER:
			return NOD_SOCKOPT_SO_DETACH_FILTER;
#endif
#ifdef SO_PEERNAME
		case SO_PEERNAME:
			return NOD_SOCKOPT_SO_PEERNAME;
#endif
#ifdef SO_TIMESTAMP
		case SO_TIMESTAMP:
			return NOD_SOCKOPT_SO_TIMESTAMP;
#endif
#ifdef SO_ACCEPTCONN
		case SO_ACCEPTCONN:
			return NOD_SOCKOPT_SO_ACCEPTCONN;
#endif
#ifdef SO_PEERSEC
		case SO_PEERSEC:
			return NOD_SOCKOPT_SO_PEERSEC;
#endif
#ifdef SO_PASSSEC
		case SO_PASSSEC:
			return NOD_SOCKOPT_SO_PASSSEC;
#endif
#ifdef SO_TIMESTAMPNS
		case SO_TIMESTAMPNS:
			return NOD_SOCKOPT_SO_TIMESTAMPNS;
#endif
#ifdef SO_MARK
		case SO_MARK:
			return NOD_SOCKOPT_SO_MARK;
#endif
#ifdef SO_TIMESTAMPING
		case SO_TIMESTAMPING:
			return NOD_SOCKOPT_SO_TIMESTAMPING;
#endif
#ifdef SO_PROTOCOL
		case SO_PROTOCOL:
			return NOD_SOCKOPT_SO_PROTOCOL;
#endif
#ifdef SO_DOMAIN
		case SO_DOMAIN:
			return NOD_SOCKOPT_SO_DOMAIN;
#endif
#ifdef SO_RXQ_OVFL
		case SO_RXQ_OVFL:
			return NOD_SOCKOPT_SO_RXQ_OVFL;
#endif
#ifdef SO_WIFI_STATUS
		case SO_WIFI_STATUS:
			return NOD_SOCKOPT_SO_WIFI_STATUS;
#endif
#ifdef SO_PEEK_OFF
		case SO_PEEK_OFF:
			return NOD_SOCKOPT_SO_PEEK_OFF;
#endif
#ifdef SO_NOFCS
		case SO_NOFCS:
			return NOD_SOCKOPT_SO_NOFCS;
#endif
#ifdef SO_LOCK_FILTER
		case SO_LOCK_FILTER:
			return NOD_SOCKOPT_SO_LOCK_FILTER;
#endif
#ifdef SO_SELECT_ERR_QUEUE
		case SO_SELECT_ERR_QUEUE:
			return NOD_SOCKOPT_SO_SELECT_ERR_QUEUE;
#endif
#ifdef SO_BUSY_POLL
		case SO_BUSY_POLL:
			return NOD_SOCKOPT_SO_BUSY_POLL;
#endif
#ifdef SO_MAX_PACING_RATE
		case SO_MAX_PACING_RATE:
			return NOD_SOCKOPT_SO_MAX_PACING_RATE;
#endif
#ifdef SO_BPF_EXTENSIONS
		case SO_BPF_EXTENSIONS:
			return NOD_SOCKOPT_SO_BPF_EXTENSIONS;
#endif
#ifdef SO_INCOMING_CPU
		case SO_INCOMING_CPU:
			return NOD_SOCKOPT_SO_INCOMING_CPU;
#endif
#ifdef SO_ATTACH_BPF
		case SO_ATTACH_BPF:
			return NOD_SOCKOPT_SO_ATTACH_BPF;
#endif
#ifdef SO_PEERGROUPS
		case SO_PEERGROUPS:
			return NOD_SOCKOPT_SO_PEERGROUPS;
#endif
#ifdef SO_MEMINFO
		case SO_MEMINFO:
			return NOD_SOCKOPT_SO_MEMINFO;
#endif
#ifdef SO_COOKIE
		case SO_COOKIE:
			return NOD_SOCKOPT_SO_COOKIE;
#endif
		default:
			ASSERT(false);
			return NOD_SOCKOPT_UNKNOWN;
	}
}

/* XXX this is very basic for the moment, we'll need to improve it */
static __always_inline u16 poll_events_to_scap(short revents)
{
	u16 res = 0;

	if (revents & POLLIN)
		res |= NOD_POLLIN;

	if (revents & NOD_POLLPRI)
		res |= NOD_POLLPRI;

	if (revents & POLLOUT)
		res |= NOD_POLLOUT;

	if (revents & POLLRDHUP)
		res |= NOD_POLLRDHUP;

	if (revents & POLLERR)
		res |= NOD_POLLERR;

	if (revents & POLLHUP)
		res |= NOD_POLLHUP;

	if (revents & POLLNVAL)
		res |= NOD_POLLNVAL;

	if (revents & POLLRDNORM)
		res |= NOD_POLLRDNORM;

	if (revents & POLLRDBAND)
		res |= NOD_POLLRDBAND;

	if (revents & POLLWRNORM)
		res |= NOD_POLLWRNORM;

	if (revents & POLLWRBAND)
		res |= NOD_POLLWRBAND;

	return res;
}

static __always_inline u16 futex_op_to_scap(unsigned long op)
{
	u16 res = 0;
	unsigned long flt_op = op & 127;

	if (flt_op == FUTEX_WAIT)
		res = NOD_FU_FUTEX_WAIT;
	else if (flt_op == FUTEX_WAKE)
		res = NOD_FU_FUTEX_WAKE;
	else if (flt_op == FUTEX_FD)
		res = NOD_FU_FUTEX_FD;
	else if (flt_op == FUTEX_REQUEUE)
		res = NOD_FU_FUTEX_REQUEUE;
	else if (flt_op == FUTEX_CMP_REQUEUE)
		res = NOD_FU_FUTEX_CMP_REQUEUE;
	else if (flt_op == FUTEX_WAKE_OP)
		res = NOD_FU_FUTEX_WAKE_OP;
	else if (flt_op == FUTEX_LOCK_PI)
		res = NOD_FU_FUTEX_LOCK_PI;
	else if (flt_op == FUTEX_UNLOCK_PI)
		res = NOD_FU_FUTEX_UNLOCK_PI;
	else if (flt_op == FUTEX_TRYLOCK_PI)
		res = NOD_FU_FUTEX_TRYLOCK_PI;
#ifdef FUTEX_WAIT_BITSET
	else if (flt_op == FUTEX_WAIT_BITSET)
		res = NOD_FU_FUTEX_WAIT_BITSET;
#endif
#ifdef FUTEX_WAKE_BITSET
	else if (flt_op == FUTEX_WAKE_BITSET)
		res = NOD_FU_FUTEX_WAKE_BITSET;
#endif
#ifdef FUTEX_WAIT_REQUEUE_PI
	else if (flt_op == FUTEX_WAIT_REQUEUE_PI)
		res = NOD_FU_FUTEX_WAIT_REQUEUE_PI;
#endif
#ifdef FUTEX_CMP_REQUEUE_PI
	else if (flt_op == FUTEX_CMP_REQUEUE_PI)
		res = NOD_FU_FUTEX_CMP_REQUEUE_PI;
#endif

	if (op & FUTEX_PRIVATE_FLAG)
		res |= NOD_FU_FUTEX_PRIVATE_FLAG;

#ifdef FUTEX_CLOCK_REALTIME
	if (op & FUTEX_CLOCK_REALTIME)
		res |= NOD_FU_FUTEX_CLOCK_REALTIME;
#endif
	return res;
}

static __always_inline u32 access_flags_to_scap(unsigned flags)
{
	u32 res = 0;

	if (flags == 0/*F_OK*/) {
		res = NOD_F_OK;
	} else {
		if (flags & MAY_EXEC)
			res |= NOD_X_OK;
		if (flags & MAY_READ)
			res |= NOD_R_OK;
		if (flags & MAY_WRITE)
			res |= NOD_W_OK;
	}

	return res;
}

static __always_inline u8 rlimit_resource_to_scap(unsigned long rresource)
{
	switch (rresource) {
	case RLIMIT_CPU:
		return NOD_RLIMIT_CPU;
	case RLIMIT_FSIZE:
		return NOD_RLIMIT_FSIZE;
	case RLIMIT_DATA:
		return NOD_RLIMIT_DATA;
	case RLIMIT_STACK:
		return NOD_RLIMIT_STACK;
	case RLIMIT_CORE:
		return NOD_RLIMIT_CORE;
	case RLIMIT_RSS:
		return NOD_RLIMIT_RSS;
	case RLIMIT_NPROC:
		return NOD_RLIMIT_NPROC;
	case RLIMIT_NOFILE:
		return NOD_RLIMIT_NOFILE;
	case RLIMIT_MEMLOCK:
		return NOD_RLIMIT_MEMLOCK;
	case RLIMIT_AS:
		return NOD_RLIMIT_AS;
	case RLIMIT_LOCKS:
		return NOD_RLIMIT_LOCKS;
	case RLIMIT_SIGPENDING:
		return NOD_RLIMIT_SIGPENDING;
	case RLIMIT_MSGQUEUE:
		return NOD_RLIMIT_MSGQUEUE;
	case RLIMIT_NICE:
		return NOD_RLIMIT_NICE;
	case RLIMIT_RTPRIO:
		return NOD_RLIMIT_RTPRIO;
#ifdef RLIMIT_RTTIME
	case RLIMIT_RTTIME:
		return NOD_RLIMIT_RTTIME;
#endif
	default:
		return NOD_RLIMIT_UNKNOWN;
	}
}

static __always_inline u16 shutdown_how_to_scap(unsigned long how)
{
#ifdef SHUT_RD
	if (how == SHUT_RD)
		return NOD_SHUT_RD;
	else if (how == SHUT_WR)
		return SHUT_WR;
	else if (how == SHUT_RDWR)
		return SHUT_RDWR;

	ASSERT(false);
#endif
	return (u16)how;
}

static __always_inline uint64_t lseek_whence_to_scap(unsigned long whence)
{
	uint64_t res = 0;

	if (whence == SEEK_SET)
		res = NOD_SEEK_SET;
	else if (whence == SEEK_CUR)
		res = NOD_SEEK_CUR;
	else if (whence == SEEK_END)
		res = NOD_SEEK_END;

	return res;
}

static __always_inline u16 semop_flags_to_scap(short flags)
{
	u16 res = 0;

	if (flags & IPC_NOWAIT)
		res |= NOD_IPC_NOWAIT;

	if (flags & SEM_UNDO)
		res |= NOD_SEM_UNDO;

	return res;
}

static __always_inline u32 pf_flags_to_scap(unsigned long flags)
{
	u32 res = 0;

	/* Page fault error codes don't seem to be clearly defined in header
	 * files throughout the kernel except in some emulation modes (e.g. kvm)
	 * which we can't assume to exist, so I just took the definitions from
	 * the x86 manual. If we end up supporting another arch for page faults,
	 * refactor this.
	 */
	if (flags & 0x1)
		res |= NOD_PF_PROTECTION_VIOLATION;
	else
		res |= NOD_PF_PAGE_NOT_PRESENT;

	if (flags & 0x2)
		res |= NOD_PF_WRITE_ACCESS;
	else
		res |= NOD_PF_READ_ACCESS;

	if (flags & 0x4)
		res |= NOD_PF_USER_FAULT;
	else
		res |= NOD_PF_SUPERVISOR_FAULT;

	if (flags & 0x8)
		res |= NOD_PF_RESERVED_PAGE;

	if (flags & 0x10)
		res |= NOD_PF_INSTRUCTION_FETCH;

	return res;
}

static __always_inline u32 flock_flags_to_scap(unsigned long flags)
{
	u32 res = 0;

	if (flags & LOCK_EX)
		res |= NOD_LOCK_EX;

	if (flags & LOCK_SH)
		res |= NOD_LOCK_SH;

	if (flags & LOCK_UN)
		res |= NOD_LOCK_UN;

	if (flags & LOCK_NB)
		res |= NOD_LOCK_NB;

	return res;
}

static __always_inline uint8_t quotactl_type_to_scap(unsigned long cmd)
{
	switch (cmd & SUBCMDMASK) {
	case USRQUOTA:
		return NOD_USRQUOTA;
	case GRPQUOTA:
		return NOD_GRPQUOTA;
	}
	return 0;
}

static __always_inline uint16_t quotactl_cmd_to_scap(unsigned long cmd)
{
	uint16_t res;

	switch (cmd >> SUBCMDSHIFT) {
	case Q_SYNC:
		res = NOD_Q_SYNC;
		break;
	case Q_QUOTAON:
		res = NOD_Q_QUOTAON;
		break;
	case Q_QUOTAOFF:
		res = NOD_Q_QUOTAOFF;
		break;
	case Q_GETFMT:
		res = NOD_Q_GETFMT;
		break;
	case Q_GETINFO:
		res = NOD_Q_GETINFO;
		break;
	case Q_SETINFO:
		res = NOD_Q_SETINFO;
		break;
	case Q_GETQUOTA:
		res = NOD_Q_GETQUOTA;
		break;
	case Q_SETQUOTA:
		res = NOD_Q_SETQUOTA;
		break;
	/*
	 *  XFS specific
	 */
	case Q_XQUOTAON:
		res = NOD_Q_XQUOTAON;
		break;
	case Q_XQUOTAOFF:
		res = NOD_Q_XQUOTAOFF;
		break;
	case Q_XGETQUOTA:
		res = NOD_Q_XGETQUOTA;
		break;
	case Q_XSETQLIM:
		res = NOD_Q_XSETQLIM;
		break;
	case Q_XGETQSTAT:
		res = NOD_Q_XGETQSTAT;
		break;
	case Q_XQUOTARM:
		res = NOD_Q_XQUOTARM;
		break;
	case Q_XQUOTASYNC:
		res = NOD_Q_XQUOTASYNC;
		break;
	default:
		res = 0;
	}
	return res;
}

static __always_inline uint8_t quotactl_fmt_to_scap(unsigned long fmt)
{
	switch (fmt) {
	case QFMT_VFS_OLD:
		return NOD_QFMT_VFS_OLD;
	case QFMT_VFS_V0:
		return NOD_QFMT_VFS_V0;
#ifdef QFMT_VFS_V1
	case QFMT_VFS_V1:
		return NOD_QFMT_VFS_V1;
#endif
	default:
		return NOD_QFMT_NOT_USED;
	}
}

static __always_inline u32 semget_flags_to_scap(unsigned flags)
{
	u32 res = 0;

	if (flags & IPC_CREAT)
		res |= NOD_IPC_CREAT;

	if (flags & IPC_EXCL)
		res |= NOD_IPC_EXCL;

	return res;
}

static __always_inline u32 semctl_cmd_to_scap(unsigned cmd)
{
	switch (cmd) {
	case IPC_STAT: return NOD_IPC_STAT;
	case IPC_SET: return NOD_IPC_SET;
	case IPC_RMID: return NOD_IPC_RMID;
	case IPC_INFO: return NOD_IPC_INFO;
	case SEM_INFO: return NOD_SEM_INFO;
	case SEM_STAT: return NOD_SEM_STAT;
	case GETALL: return NOD_GETALL;
	case GETNCNT: return NOD_GETNCNT;
	case GETPID: return NOD_GETPID;
	case GETVAL: return NOD_GETVAL;
	case GETZCNT: return NOD_GETZCNT;
	case SETALL: return NOD_SETALL;
	case SETVAL: return NOD_SETVAL;
	}
	return 0;
}

static __always_inline u16 ptrace_requests_to_scap(unsigned long req)
{
	switch (req) {
#ifdef PTRACE_SINGLEBLOCK
	case PTRACE_SINGLEBLOCK:
		return NOD_PTRACE_SINGLEBLOCK;
#endif
#ifdef PTRACE_SYSEMU_SINGLESTEP
	case PTRACE_SYSEMU_SINGLESTEP:
		return NOD_PTRACE_SYSEMU_SINGLESTEP;
#endif

#ifdef PTRACE_SYSEMU
	case PTRACE_SYSEMU:
		return NOD_PTRACE_SYSEMU;
#endif
#ifdef PTRACE_ARCH_PRCTL
	case PTRACE_ARCH_PRCTL:
		return NOD_PTRACE_ARCH_PRCTL;
#endif
#ifdef PTRACE_SET_THREAD_AREA
	case PTRACE_SET_THREAD_AREA:
		return NOD_PTRACE_SET_THREAD_AREA;
#endif
#ifdef PTRACE_GET_THREAD_AREA
	case PTRACE_GET_THREAD_AREA:
		return NOD_PTRACE_GET_THREAD_AREA;
#endif
#ifdef PTRACE_OLDSETOPTIONS
	case PTRACE_OLDSETOPTIONS:
		return NOD_PTRACE_OLDSETOPTIONS;
#endif
#ifdef PTRACE_SETFPXREGS
	case PTRACE_SETFPXREGS:
		return NOD_PTRACE_SETFPXREGS;
#endif
#ifdef PTRACE_GETFPXREGS
	case PTRACE_GETFPXREGS:
		return NOD_PTRACE_GETFPXREGS;
#endif
#ifdef PTRACE_SETFPREGS
	case PTRACE_SETFPREGS:
		return NOD_PTRACE_SETFPREGS;
#endif
#ifdef PTRACE_GETFPREGS
	case PTRACE_GETFPREGS:
		return NOD_PTRACE_GETFPREGS;
#endif
#ifdef PTRACE_SETREGS
	case PTRACE_SETREGS:
		return NOD_PTRACE_SETREGS;
#endif
#ifdef PTRACE_GETREGS
	case PTRACE_GETREGS:
		return NOD_PTRACE_GETREGS;
#endif
#ifdef PTRACE_SETSIGMASK
	case PTRACE_SETSIGMASK:
		return NOD_PTRACE_SETSIGMASK;
#endif
#ifdef PTRACE_GETSIGMASK
	case PTRACE_GETSIGMASK:
		return NOD_PTRACE_GETSIGMASK;
#endif
#ifdef PTRACE_PEEKSIGINFO
	case PTRACE_PEEKSIGINFO:
		return NOD_PTRACE_PEEKSIGINFO;
#endif
#ifdef PTRACE_LISTEN
	case PTRACE_LISTEN:
		return NOD_PTRACE_LISTEN;
#endif
#ifdef PTRACE_INTERRUPT
	case PTRACE_INTERRUPT:
		return NOD_PTRACE_INTERRUPT;
#endif
#ifdef PTRACE_SEIZE
	case PTRACE_SEIZE:
		return NOD_PTRACE_SEIZE;
#endif
#ifdef PTRACE_SETREGSET
	case PTRACE_SETREGSET:
		return NOD_PTRACE_SETREGSET;
#endif
#ifdef PTRACE_GETREGSET
	case PTRACE_GETREGSET:
		return NOD_PTRACE_GETREGSET;
#endif
	case PTRACE_SETSIGINFO:
		return NOD_PTRACE_SETSIGINFO;
	case PTRACE_GETSIGINFO:
		return NOD_PTRACE_GETSIGINFO;
	case PTRACE_GETEVENTMSG:
		return NOD_PTRACE_GETEVENTMSG;
	case PTRACE_SETOPTIONS:
		return NOD_PTRACE_SETOPTIONS;
	case PTRACE_SYSCALL:
		return NOD_PTRACE_SYSCALL;
	case PTRACE_DETACH:
		return NOD_PTRACE_DETACH;
	case PTRACE_ATTACH:
		return NOD_PTRACE_ATTACH;
	case PTRACE_SINGLESTEP:
		return NOD_PTRACE_SINGLESTEP;
	case PTRACE_KILL:
		return NOD_PTRACE_KILL;
	case PTRACE_CONT:
		return NOD_PTRACE_CONT;
#ifdef PTRACE_POKEUSR
	case PTRACE_POKEUSR:
		return NOD_PTRACE_POKEUSR;
#endif		
	case PTRACE_POKEDATA:
		return NOD_PTRACE_POKEDATA;
	case PTRACE_POKETEXT:
		return NOD_PTRACE_POKETEXT;
#ifdef PTRACE_PEEKUSR
	case PTRACE_PEEKUSR:
		return NOD_PTRACE_PEEKUSR;
#endif
	case PTRACE_PEEKDATA:
		return NOD_PTRACE_PEEKDATA;
	case PTRACE_PEEKTEXT:
		return NOD_PTRACE_PEEKTEXT;
	case PTRACE_TRACEME:
		return NOD_PTRACE_TRACEME;
	default:
		return NOD_PTRACE_UNKNOWN;
	}
}

static __always_inline u32 execveat_flags_to_scap(unsigned long flags)
{
	u32 res = 0;

#ifdef AT_EMPTY_PATH
	if (flags & AT_EMPTY_PATH)
		res |= NOD_EXVAT_AT_EMPTY_PATH;
#endif

#ifdef AT_SYMLINK_NOFOLLOW
	if (flags & AT_SYMLINK_NOFOLLOW)
		res |= NOD_EXVAT_AT_SYMLINK_NOFOLLOW;
#endif

	return res;
}


static __always_inline u32 unlinkat_flags_to_scap(unsigned long flags)
{
	u32 res = 0;

	if (flags & AT_REMOVEDIR)
		res |= NOD_AT_REMOVEDIR;

	return res;
}

static __always_inline u32 linkat_flags_to_scap(unsigned long flags)
{
	u32 res = 0;

	if (flags & AT_SYMLINK_FOLLOW)
		res |= NOD_AT_SYMLINK_FOLLOW;

#ifdef AT_EMPTY_PATH
	if (flags & AT_EMPTY_PATH)
		res |= NOD_AT_EMPTY_PATH;
#endif

	return res;
}

static __always_inline u32 chmod_mode_to_scap(unsigned long modes)
{
	u32 res = 0;
	if (modes & S_IRUSR)
		res |= NOD_S_IRUSR;

	if (modes & S_IWUSR)
		res |= NOD_S_IWUSR;

	if (modes & S_IXUSR)
		res |= NOD_S_IXUSR;

	/*
	 * NOD_S_IRWXU == S_IRUSR | S_IWUSR | S_IXUSR
	 */

	if (modes & S_IRGRP)
		res |= NOD_S_IRGRP;

	if (modes & S_IWGRP)
		res |= NOD_S_IWGRP;

	if (modes & S_IXGRP)
		res |= NOD_S_IXGRP;

	/*
	 * NOD_S_IRWXG == S_IRGRP | S_IWGRP | S_IXGRP
	 */

	if (modes & S_IROTH)
		res |= NOD_S_IROTH;

	if (modes & S_IWOTH)
		res |= NOD_S_IWOTH;

	if (modes & S_IXOTH)
		res |= NOD_S_IXOTH;

	/*
	 * NOD_S_IRWXO == S_IROTH | S_IWOTH | S_IXOTH
	 */

	if (modes & S_ISUID)
		res |= NOD_S_ISUID;

	if (modes & S_ISGID)
		res |= NOD_S_ISGID;

	if (modes & S_ISVTX)
		res |= NOD_S_ISVTX;

	return res;
}


#endif /* NOD_FLAG_HELPERS_H_ */
