#ifndef _EVENTS_H_
#define _EVENTS_H_

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include "fillers.h"
#else
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h> 
#endif //__KERNEL__


typedef uint64_t nanoseconds;
#define _packed __attribute__((packed))

#define BUFFER_SIZE   (8 * 1024 * 1024)
#define MAX_EVENT_NUM 8192
#define SYSCALL_TABLE_SIZE 512
#define STR_STORAGE_SIZE PAGE_SIZE
#define DIRFD_PARAM(_param_num) ((void*)_param_num)

/*
 * Limits
 */
#define NOD_MAX_EVENT_PARAMS (1 << 5)	/* Max number of parameters an event can have */
#define NOD_MAX_PATH_SIZE 256	/* Max size that an event parameter can have in the circular buffer, in bytes */
#define NOD_MAX_NAME_LEN  32
#define NOD_MAX_ARG_SIZE 65000

/*
 * Socket families
 */
#define NOD_AF_UNSPEC       0
#define NOD_AF_UNIX         1       /* Unix domain sockets          */
#define NOD_AF_LOCAL        1       /* POSIX name for NOD_AF_UNIX   */
#define NOD_AF_INET         2       /* Internet IP Protocol         */
#define NOD_AF_AX25         3       /* Amateur Radio AX.25          */
#define NOD_AF_IPX          4       /* Novell IPX                   */
#define NOD_AF_APPLETALK    5       /* AppleTalk DDP                */
#define NOD_AF_NETROM       6       /* Amateur Radio NET/ROM        */
#define NOD_AF_BRIDGE       7       /* Multiprotocol bridge         */
#define NOD_AF_ATMPVC       8       /* ATM PVCs                     */
#define NOD_AF_X25          9       /* Reserved for X.25 project    */
#define NOD_AF_INET6        10      /* IP version 6                 */
#define NOD_AF_ROSE         11      /* Amateur Radio X.25 PLP       */
#define NOD_AF_DECnet       12      /* Reserved for DECnet project  */
#define NOD_AF_NETBEUI      13      /* Reserved for 802.2LLC project*/
#define NOD_AF_SECURITY     14      /* Security callback pseudo AF */
#define NOD_AF_KEY          15      /* PF_KEY key management API */
#define NOD_AF_NETLINK      16
#define NOD_AF_ROUTE        NOD_AF_NETLINK /* Alias to emulate 4.4BSD */
#define NOD_AF_PACKET       17      /* Packet family                */
#define NOD_AF_ASH          18      /* Ash                          */
#define NOD_AF_ECONET       19      /* Acorn Econet                 */
#define NOD_AF_ATMSVC       20      /* ATM SVCs                     */
#define NOD_AF_RDS          21      /* RDS sockets                  */
#define NOD_AF_SNA          22      /* Linux SNA Project (nutters!) */
#define NOD_AF_IRDA         23      /* IRDA sockets                 */
#define NOD_AF_PPPOX        24      /* PPPoX sockets                */
#define NOD_AF_WANPIPE      25      /* Wanpipe API Sockets */
#define NOD_AF_LLC          26      /* Linux LLC                    */
#define NOD_AF_CAN          29      /* Controller Area Network      */
#define NOD_AF_TIPC         30      /* TIPC sockets                 */
#define NOD_AF_BLUETOOTH    31      /* Bluetooth sockets            */
#define NOD_AF_IUCV         32      /* IUCV sockets                 */
#define NOD_AF_RXRPC        33      /* RxRPC sockets                */
#define NOD_AF_ISDN         34      /* mISDN sockets                */
#define NOD_AF_PHONET       35      /* Phonet sockets               */
#define NOD_AF_IEEE802154   36      /* IEEE802154 sockets           */
#define NOD_AF_CAIF         37      /* CAIF sockets                 */
#define NOD_AF_ALG          38      /* Algorithm sockets            */
#define NOD_AF_NFC          39      /* NFC sockets                  */

/*
 * File flags
 */
#define NOD_O_NONE	0
#define NOD_O_RDONLY	(1 << 0)	/* Open for reading only */
#define NOD_O_WRONLY	(1 << 1)	/* Open for writing only */
#define NOD_O_RDWR	(NOD_O_RDONLY | NOD_O_WRONLY)	/* Open for reading and writing */
#define NOD_O_CREAT	(1 << 2)	/* Create a new file if it doesn't exist. */
#define NOD_O_APPEND	(1 << 3)	/* If set, the file offset shall be set to the end of the file prior to each write. */
#define NOD_O_DSYNC	(1 << 4)
#define NOD_O_EXCL	(1 << 5)
#define NOD_O_NONBLOCK	(1 << 6)
#define NOD_O_SYNC	(1 << 7)
#define NOD_O_TRUNC	(1 << 8)
#define NOD_O_DIRECT	(1 << 9)
#define NOD_O_DIRECTORY (1 << 10)
#define NOD_O_LARGEFILE (1 << 11)
#define NOD_O_CLOEXEC	(1 << 12)
#define NOD_O_TMPFILE	(1 << 13)

/*
 * File modes
 */
#define NOD_S_NONE  0
#define NOD_S_IXOTH (1 << 0)
#define NOD_S_IWOTH (1 << 1)
#define NOD_S_IROTH (1 << 2)
#define NOD_S_IXGRP (1 << 3)
#define NOD_S_IWGRP (1 << 4)
#define NOD_S_IRGRP (1 << 5)
#define NOD_S_IXUSR (1 << 6)
#define NOD_S_IWUSR (1 << 7)
#define NOD_S_IRUSR (1 << 8)
#define NOD_S_ISVTX (1 << 9)
#define NOD_S_ISGID (1 << 10)
#define NOD_S_ISUID (1 << 11)

/*
 * flock() flags
 */
#define NOD_LOCK_NONE 0
#define NOD_LOCK_SH (1 << 0)
#define NOD_LOCK_EX (1 << 1)
#define NOD_LOCK_NB (1 << 2)
#define NOD_LOCK_UN (1 << 3)

/*
 * Clone flags
 */
#define NOD_CL_NONE 0
#define NOD_CL_CLONE_FILES (1 << 0)
#define NOD_CL_CLONE_FS (1 << 1)
#define NOD_CL_CLONE_IO (1 << 2)
#define NOD_CL_CLONE_NEWIPC (1 << 3)
#define NOD_CL_CLONE_NEWNET (1 << 4)
#define NOD_CL_CLONE_NEWNS (1 << 5)
#define NOD_CL_CLONE_NEWPID (1 << 6)
#define NOD_CL_CLONE_NEWUTS (1 << 7)
#define NOD_CL_CLONE_PARENT (1 << 8)
#define NOD_CL_CLONE_PARENT_SETTID (1 << 9)
#define NOD_CL_CLONE_PTRACE (1 << 10)
#define NOD_CL_CLONE_SIGHAND (1 << 11)
#define NOD_CL_CLONE_SYSVSEM (1 << 12)
#define NOD_CL_CLONE_THREAD (1 << 13)
#define NOD_CL_CLONE_UNTRACED (1 << 14)
#define NOD_CL_CLONE_VM (1 << 15)
#define NOD_CL_CLONE_INVERTED (1 << 16)	/* libsinsp-specific flag. It's set if clone() returned in */
										/* the child process before than in the parent process. */
#define NOD_CL_NAME_CHANGED (1 << 17)	/* libsinsp-specific flag. Set when the thread name changes */
										/* (for example because execve was called) */
#define NOD_CL_CLOSED (1 << 18)			/* thread has been closed. */
#define NOD_CL_ACTIVE (1 << 19)			/* libsinsp-specific flag. Set in the first non-clone event for
										   this thread. */
#define NOD_CL_CLONE_NEWUSER (1 << 20)
#define NOD_CL_PIPE_SRC (1 << 21)			/* libsinsp-specific flag. Set if this thread has been
										       detected to be the source in a shell pipe. */
#define NOD_CL_PIPE_DST (1 << 22)			/* libsinsp-specific flag. Set if this thread has been
										       detected to be the destination in a shell pipe. */
#define NOD_CL_CLONE_CHILD_CLEARTID (1 << 23)
#define NOD_CL_CLONE_CHILD_SETTID (1 << 24)
#define NOD_CL_CLONE_SETTLS (1 << 25)
#define NOD_CL_CLONE_STOPPED (1 << 26)
#define NOD_CL_CLONE_VFORK (1 << 27)
#define NOD_CL_CLONE_NEWCGROUP (1 << 28)
#define NOD_CL_CHILD_IN_PIDNS (1<<29)			/* true if the thread created by clone() is *not*
									in the init pid namespace */
#define NOD_CL_IS_MAIN_THREAD (1 << 30)	/* libsinsp-specific flag. Set if this is the main thread */
										/* in envs where main thread tid != pid.*/

/*
 * Futex Operations
 */
#define NOD_FU_FUTEX_WAIT 0
#define NOD_FU_FUTEX_WAKE 1
#define NOD_FU_FUTEX_FD 2
#define NOD_FU_FUTEX_REQUEUE 3
#define NOD_FU_FUTEX_CMP_REQUEUE 4
#define NOD_FU_FUTEX_WAKE_OP 5
#define NOD_FU_FUTEX_LOCK_PI 6
#define NOD_FU_FUTEX_UNLOCK_PI 7
#define NOD_FU_FUTEX_TRYLOCK_PI 8
#define NOD_FU_FUTEX_WAIT_BITSET 9
#define NOD_FU_FUTEX_WAKE_BITSET 10
#define NOD_FU_FUTEX_WAIT_REQUEUE_PI 11
#define NOD_FU_FUTEX_CMP_REQUEUE_PI 12
#define NOD_FU_FUTEX_PRIVATE_FLAG	128
#define NOD_FU_FUTEX_CLOCK_REALTIME 256

/*
 * lseek() and llseek() whence
 */
#define NOD_SEEK_SET 0
#define NOD_SEEK_CUR 1
#define NOD_SEEK_END 2

/*
 * poll() flags
 */
#define NOD_POLLIN (1 << 0)
#define NOD_POLLPRI (1 << 1)
#define NOD_POLLOUT (1 << 2)
#define NOD_POLLRDHUP (1 << 3)
#define NOD_POLLERR (1 << 4)
#define NOD_POLLHUP (1 << 5)
#define NOD_POLLNVAL (1 << 6)
#define NOD_POLLRDNORM (1 << 7)
#define NOD_POLLRDBAND (1 << 8)
#define NOD_POLLWRNORM (1 << 9)
#define NOD_POLLWRBAND (1 << 10)

/*
 * mount() flags
 */
#define NOD_MS_RDONLY       (1<<0)
#define NOD_MS_NOSUID       (1<<1)
#define NOD_MS_NODEV        (1<<2)
#define NOD_MS_NOEXEC       (1<<3)
#define NOD_MS_SYNCHRONOUS  (1<<4)
#define NOD_MS_REMOUNT      (1<<5)
#define NOD_MS_MANDLOCK     (1<<6)
#define NOD_MS_DIRSYNC      (1<<7)

#define NOD_MS_NOATIME      (1<<10)
#define NOD_MS_NODIRATIME   (1<<11)
#define NOD_MS_BIND         (1<<12)
#define NOD_MS_MOVE         (1<<13)
#define NOD_MS_REC          (1<<14)
#define NOD_MS_SILENT       (1<<15)
#define NOD_MS_POSIXACL     (1<<16)
#define NOD_MS_UNBINDABLE   (1<<17)
#define NOD_MS_PRIVATE      (1<<18)
#define NOD_MS_SLAVE        (1<<19)
#define NOD_MS_SHARED       (1<<20)
#define NOD_MS_RELATIME     (1<<21)
#define NOD_MS_KERNMOUNT    (1<<22)
#define NOD_MS_I_VERSION    (1<<23)
#define NOD_MS_STRICTATIME  (1<<24)
#define NOD_MS_LAZYTIME     (1<<25)

#define NOD_MS_NOSEC        (1<<28)
#define NOD_MS_BORN         (1<<29)
#define NOD_MS_ACTIVE       (1<<30)
#define NOD_MS_NOUSER       (1<<31)

/*
 * umount() flags
 */
#define NOD_MNT_FORCE       1
#define NOD_MNT_DETACH      2
#define NOD_MNT_EXPIRE      4
#define NOD_UMOUNT_NOFOLLOW 8

/*
 * shutdown() how
 */
#define NOD_SHUT_RD 0
#define NOD_SHUT_WR 1
#define NOD_SHUT_RDWR 2

/*
 * fs *at() flags
 */
#define NOD_AT_FDCWD -100

/*
 * unlinkat() flags
 */
#define NOD_AT_REMOVEDIR 0x200

/*
 * linkat() flags
 */
#define NOD_AT_SYMLINK_FOLLOW	0x400
#define NOD_AT_EMPTY_PATH       0x1000

/*
 * rlimit resources
 */
#define NOD_RLIMIT_CPU 0 /* CPU time in sec */
#define NOD_RLIMIT_FSIZE 1 /* Maximum filesize */
#define NOD_RLIMIT_DATA 2 /* max data size */
#define NOD_RLIMIT_STACK 3 /* max stack size */
#define NOD_RLIMIT_CORE 4 /* max core file size */
#define NOD_RLIMIT_RSS 5 /* max resident set size */
#define NOD_RLIMIT_NPROC 6 /* max number of processes */
#define NOD_RLIMIT_NOFILE 7 /* max number of open files */
#define NOD_RLIMIT_MEMLOCK 8 /* max locked-in-memory address space */
#define NOD_RLIMIT_AS 9 /* address space limit */
#define NOD_RLIMIT_LOCKS 10  /* maximum file locks held */
#define NOD_RLIMIT_SIGPENDING 11 /* max number of pending signals */
#define NOD_RLIMIT_MSGQUEUE 12 /* maximum bytes in POSIX mqueues */
#define NOD_RLIMIT_NICE 13 /* max nice prio allowed to raise to 0-39 for nice level 19 .. -20 */
#define NOD_RLIMIT_RTPRIO 14 /* maximum realtime priority */
#define NOD_RLIMIT_RTTIME 15 /* timeout for RT tasks in us */
#define NOD_RLIMIT_UNKNOWN 255 /* CPU time in sec */

/*
 * fcntl commands
 */
#define NOD_FCNTL_UNKNOWN 0
#define NOD_FCNTL_F_DUPFD 1
#define NOD_FCNTL_F_GETFD 2
#define NOD_FCNTL_F_SETFD 3
#define NOD_FCNTL_F_GETFL 4
#define NOD_FCNTL_F_SETFL 5
#define NOD_FCNTL_F_GETLK 6
#define NOD_FCNTL_F_SETLK 8
#define NOD_FCNTL_F_SETLKW 9
#define NOD_FCNTL_F_SETOWN 10
#define NOD_FCNTL_F_GETOWN 12
#define NOD_FCNTL_F_SETSIG 13
#define NOD_FCNTL_F_GETSIG 15
#ifndef CONFIG_64BIT
#define NOD_FCNTL_F_GETLK64 17
#define NOD_FCNTL_F_SETLK64 18
#define NOD_FCNTL_F_SETLKW64 19
#endif
#define NOD_FCNTL_F_SETOWN_EX 21
#define NOD_FCNTL_F_GETOWN_EX 22
#define NOD_FCNTL_F_SETLEASE 23
#define NOD_FCNTL_F_GETLEASE 24
#define NOD_FCNTL_F_CANCELLK 25
#define NOD_FCNTL_F_DUPFD_CLOEXEC 26
#define NOD_FCNTL_F_NOTIFY 27
#define NOD_FCNTL_F_SETPIPE_SZ 28
#define NOD_FCNTL_F_GETPIPE_SZ 29
#define NOD_FCNTL_F_OFD_GETLK 30
#define NOD_FCNTL_F_OFD_SETLK 31
#define NOD_FCNTL_F_OFD_SETLKW 32

/*
 * getsockopt/setsockopt levels
 */
#define NOD_SOCKOPT_LEVEL_UNKNOWN 0
#define NOD_SOCKOPT_LEVEL_SOL_SOCKET 1
#define NOD_SOCKOPT_LEVEL_SOL_TCP 2

/*
 * getsockopt/setsockopt options
 * SOL_SOCKET only currently
 */
#define NOD_SOCKOPT_UNKNOWN	0
#define NOD_SOCKOPT_SO_DEBUG	1
#define NOD_SOCKOPT_SO_REUSEADDR	2
#define NOD_SOCKOPT_SO_TYPE		3
#define NOD_SOCKOPT_SO_ERROR	4
#define NOD_SOCKOPT_SO_DONTROUTE	5
#define NOD_SOCKOPT_SO_BROADCAST	6
#define NOD_SOCKOPT_SO_SNDBUF	7
#define NOD_SOCKOPT_SO_RCVBUF	8
#define NOD_SOCKOPT_SO_SNDBUFFORCE	32
#define NOD_SOCKOPT_SO_RCVBUFFORCE	33
#define NOD_SOCKOPT_SO_KEEPALIVE	9
#define NOD_SOCKOPT_SO_OOBINLINE	10
#define NOD_SOCKOPT_SO_NO_CHECK	11
#define NOD_SOCKOPT_SO_PRIORITY	12
#define NOD_SOCKOPT_SO_LINGER	13
#define NOD_SOCKOPT_SO_BSDCOMPAT	14
#define NOD_SOCKOPT_SO_REUSEPORT	15
#define NOD_SOCKOPT_SO_PASSCRED	16
#define NOD_SOCKOPT_SO_PEERCRED	17
#define NOD_SOCKOPT_SO_RCVLOWAT	18
#define NOD_SOCKOPT_SO_SNDLOWAT	19
#define NOD_SOCKOPT_SO_RCVTIMEO	20
#define NOD_SOCKOPT_SO_SNDTIMEO	21
#define NOD_SOCKOPT_SO_SECURITY_AUTHENTICATION		22
#define NOD_SOCKOPT_SO_SECURITY_ENCRYPTION_TRANSPORT	23
#define NOD_SOCKOPT_SO_SECURITY_ENCRYPTION_NETWORK		24
#define NOD_SOCKOPT_SO_BINDTODEVICE	25
#define NOD_SOCKOPT_SO_ATTACH_FILTER	26
#define NOD_SOCKOPT_SO_DETACH_FILTER	27
#define NOD_SOCKOPT_SO_PEERNAME		28
#define NOD_SOCKOPT_SO_TIMESTAMP		29
#define NOD_SOCKOPT_SO_ACCEPTCONN		30
#define NOD_SOCKOPT_SO_PEERSEC		31
#define NOD_SOCKOPT_SO_PASSSEC		34
#define NOD_SOCKOPT_SO_TIMESTAMPNS		35
#define NOD_SOCKOPT_SO_MARK			36
#define NOD_SOCKOPT_SO_TIMESTAMPING		37
#define NOD_SOCKOPT_SO_PROTOCOL		38
#define NOD_SOCKOPT_SO_DOMAIN		39
#define NOD_SOCKOPT_SO_RXQ_OVFL             40
#define NOD_SOCKOPT_SO_WIFI_STATUS		41
#define NOD_SOCKOPT_SO_PEEK_OFF		42
#define NOD_SOCKOPT_SO_NOFCS		43
#define NOD_SOCKOPT_SO_LOCK_FILTER		44
#define NOD_SOCKOPT_SO_SELECT_ERR_QUEUE	45
#define NOD_SOCKOPT_SO_BUSY_POLL		46
#define NOD_SOCKOPT_SO_MAX_PACING_RATE	47
#define NOD_SOCKOPT_SO_BPF_EXTENSIONS	48
#define NOD_SOCKOPT_SO_INCOMING_CPU		49
#define NOD_SOCKOPT_SO_ATTACH_BPF		50
#define NOD_SOCKOPT_SO_PEERGROUPS		51
#define NOD_SOCKOPT_SO_MEMINFO		52
#define NOD_SOCKOPT_SO_COOKIE		53

/*
 * getsockopt/setsockopt dynamic params
 */
#define NOD_SOCKOPT_IDX_UNKNOWN 0
#define NOD_SOCKOPT_IDX_ERRNO 1
#define NOD_SOCKOPT_IDX_UINT32 2
#define NOD_SOCKOPT_IDX_UINT64 3
#define NOD_SOCKOPT_IDX_TIMEVAL 4
#define NOD_SOCKOPT_IDX_MAX 5

 /*
 * ptrace requests
 */
#define NOD_PTRACE_UNKNOWN 0
#define NOD_PTRACE_TRACEME 1
#define NOD_PTRACE_PEEKTEXT 2
#define NOD_PTRACE_PEEKDATA 3
#define NOD_PTRACE_PEEKUSR 4
#define NOD_PTRACE_POKETEXT 5
#define NOD_PTRACE_POKEDATA 6
#define NOD_PTRACE_POKEUSR 7
#define NOD_PTRACE_CONT 8
#define NOD_PTRACE_KILL 9
#define NOD_PTRACE_SINGLESTEP 10
#define NOD_PTRACE_ATTACH 11
#define NOD_PTRACE_DETACH 12
#define NOD_PTRACE_SYSCALL 13
#define NOD_PTRACE_SETOPTIONS 14
#define NOD_PTRACE_GETEVENTMSG 15
#define NOD_PTRACE_GETSIGINFO 16
#define NOD_PTRACE_SETSIGINFO 17
#define NOD_PTRACE_GETREGSET 18
#define NOD_PTRACE_SETREGSET 19
#define NOD_PTRACE_SEIZE 20
#define NOD_PTRACE_INTERRUPT 21
#define NOD_PTRACE_LISTEN 22
#define NOD_PTRACE_PEEKSIGINFO 23
#define NOD_PTRACE_GETSIGMASK 24
#define NOD_PTRACE_SETSIGMASK 25
#define NOD_PTRACE_GETREGS 26
#define NOD_PTRACE_SETREGS 27
#define NOD_PTRACE_GETFPREGS 28
#define NOD_PTRACE_SETFPREGS 29
#define NOD_PTRACE_GETFPXREGS 30
#define NOD_PTRACE_SETFPXREGS 31
#define NOD_PTRACE_OLDSETOPTIONS 32
#define NOD_PTRACE_GET_THREAD_AREA 33
#define NOD_PTRACE_SET_THREAD_AREA 34
#define NOD_PTRACE_ARCH_PRCTL 35
#define NOD_PTRACE_SYSEMU 36
#define NOD_PTRACE_SYSEMU_SINGLESTEP 37
#define NOD_PTRACE_SINGLEBLOCK 38

/*
 * ptrace dynamic table indexes
 */
#define NOD_PTRACE_IDX_UINT64 0
#define NOD_PTRACE_IDX_SIGTYPE 1

#define NOD_PTRACE_IDX_MAX 2

#define NOD_BPF_IDX_FD 0
#define NOD_BPF_IDX_RES 1

#define NOD_BPF_IDX_MAX 2

/*
 * memory protection flags
 */
#define NOD_PROT_NONE		0
#define NOD_PROT_READ		(1 << 0)
#define NOD_PROT_WRITE		(1 << 1)
#define NOD_PROT_EXEC		(1 << 2)
#define NOD_PROT_SEM		(1 << 3)
#define NOD_PROT_GROWSDOWN	(1 << 4)
#define NOD_PROT_GROWSUP	(1 << 5)
#define NOD_PROT_SAO		(1 << 6)

/*
 * mmap flags
 */
#define NOD_MAP_SHARED		(1 << 0)
#define NOD_MAP_PRIVATE		(1 << 1)
#define NOD_MAP_FIXED		(1 << 2)
#define NOD_MAP_ANONYMOUS	(1 << 3)
#define NOD_MAP_32BIT		(1 << 4)
#define NOD_MAP_RENAME		(1 << 5)
#define NOD_MAP_NORESERVE	(1 << 6)
#define NOD_MAP_POPULATE	(1 << 7)
#define NOD_MAP_NONBLOCK	(1 << 8)
#define NOD_MAP_GROWSDOWN	(1 << 9)
#define NOD_MAP_DENYWRITE	(1 << 10)
#define NOD_MAP_EXECUTABLE	(1 << 11)
#define NOD_MAP_INHERIT		(1 << 12)
#define NOD_MAP_FILE		(1 << 13)
#define NOD_MAP_LOCKED		(1 << 14)

/*
 * splice flags
 */
#define NOD_SPLICE_F_MOVE		(1 << 0)
#define NOD_SPLICE_F_NONBLOCK	(1 << 1)
#define NOD_SPLICE_F_MORE		(1 << 2)
#define NOD_SPLICE_F_GIFT		(1 << 3)

/*
 * quotactl cmds
 */
#define NOD_Q_QUOTAON		(1 << 0)
#define NOD_Q_QUOTAOFF		(1 << 1)
#define NOD_Q_GETFMT		(1 << 2)
#define NOD_Q_GETINFO		(1 << 3)
#define NOD_Q_SETINFO		(1 << 4)
#define NOD_Q_GETQUOTA		(1 << 5)
#define NOD_Q_SETQUOTA		(1 << 6)
#define NOD_Q_SYNC			(1 << 7)
#define NOD_Q_XQUOTAON		(1 << 8)
#define NOD_Q_XQUOTAOFF		(1 << 9)
#define NOD_Q_XGETQUOTA		(1 << 10)
#define NOD_Q_XSETQLIM		(1 << 11)
#define NOD_Q_XGETQSTAT		(1 << 12)
#define NOD_Q_XQUOTARM		(1 << 13)
#define NOD_Q_XQUOTASYNC	(1 << 14)
#define NOD_Q_XGETQSTATV	(1 << 15)

/*
 * quotactl types
 */
#define NOD_USRQUOTA		(1 << 0)
#define NOD_GRPQUOTA		(1 << 1)

/*
 * quotactl dqi_flags
 */
#define NOD_DQF_NONE		(1 << 0)
#define NOD_V1_DQF_RSQUASH	(1 << 1)

/*
 * quotactl quotafmts
 */
#define NOD_QFMT_NOT_USED		(1 << 0)
#define NOD_QFMT_VFS_OLD	(1 << 1)
#define NOD_QFMT_VFS_V0		(1 << 2)
#define NOD_QFMT_VFS_V1		(1 << 3)

/*
 * Semop flags
 */
#define NOD_IPC_NOWAIT		(1 << 0)
#define NOD_SEM_UNDO		(1 << 1)

/*
 * Semget flags
 */
#define NOD_IPC_CREAT  (1 << 13)
#define NOD_IPC_EXCL   (1 << 14)

#define NOD_IPC_STAT		(1 << 0)
#define NOD_IPC_SET		(1 << 1)
#define NOD_IPC_RMID		(1 << 2)
#define NOD_IPC_INFO		(1 << 3)
#define NOD_SEM_INFO		(1 << 4)
#define NOD_SEM_STAT		(1 << 5)
#define NOD_GETALL		(1 << 6)
#define NOD_GETNCNT		(1 << 7)
#define NOD_GETPID		(1 << 8)
#define NOD_GETVAL		(1 << 9)
#define NOD_GETZCNT		(1 << 10)
#define NOD_SETALL		(1 << 11)
#define NOD_SETVAL		(1 << 12)

/*
 * Access flags
 */
#define NOD_F_OK            (0)
#define NOD_X_OK            (1 << 0)
#define NOD_W_OK            (1 << 1)
#define NOD_R_OK            (1 << 2)

/*
 * Page fault flags
 */
#define NOD_PF_PROTECTION_VIOLATION	(1 << 0)
#define NOD_PF_PAGE_NOT_PRESENT		(1 << 1)
#define NOD_PF_WRITE_ACCESS		(1 << 2)
#define NOD_PF_READ_ACCESS		(1 << 3)
#define NOD_PF_USER_FAULT		(1 << 4)
#define NOD_PF_SUPERVISOR_FAULT		(1 << 5)
#define NOD_PF_RESERVED_PAGE		(1 << 6)
#define NOD_PF_INSTRUCTION_FETCH	(1 << 7)


/*
 * Rename flags
 */
#define NOD_RENAME_NOREPLACE	(1 << 0)	/* Don't overwrite target */
#define NOD_RENAME_EXCHANGE		(1 << 1)	/* Exchange source and dest */
#define NOD_RENAME_WHITEOUT		(1 << 2)	/* Whiteout source */

/*
 * Openat2 resolve flags
 */
#define NOD_RESOLVE_BENEATH			(1 << 0)
#define NOD_RESOLVE_IN_ROOT			(1 << 1)
#define NOD_RESOLVE_NO_MAGICLINKS	(1 << 2)
#define NOD_RESOLVE_NO_SYMLINKS		(1 << 3)
#define NOD_RESOLVE_NO_XDEV			(1 << 4)
#define NOD_RESOLVE_CACHED			(1 << 5)

/*
 * Execve family additional flags.
 */
#define NOD_EXE_WRITABLE		(1 << 0)
  
/*
 * Execveat flags
 */
#define NOD_EXVAT_AT_EMPTY_PATH			(1 << 0)	/* If pathname is an empty string, operate on the file referred to by dirfd */
#define NOD_EXVAT_AT_SYMLINK_NOFOLLOW	(1 << 1)	/* If the file is a symbolic link, then the call fails */


/*
 * parse_readv_writev_bufs flags
 */
#define PRB_FLAG_PUSH_SIZE	1
#define PRB_FLAG_PUSH_DATA	2
#define PRB_FLAG_PUSH_ALL	(PRB_FLAG_PUSH_SIZE | PRB_FLAG_PUSH_DATA)
#define PRB_FLAG_IS_WRITE	4

/*
 * Event information enums
 */
enum nod_event_category {
	EC_UNKNOWN = 0,	/* Unknown */
	EC_OTHER = 1,	/* No specific category */
	EC_FILE = 2,	/* File operation (open, close...) or file I/O */
	EC_NET = 3,		/* Network operation (socket, bind...) or network I/O */
	EC_IPC = 4,		/* IPC operation (pipe, futex...) or IPC I/O (e.g. on a pipe) */
	EC_MEMORY = 5,	/* Memory-related operation (e.g. brk) */
	EC_PROCESS = 6,	/* Process-related operation (fork, clone...) */
	EC_SLEEP = 7,	/* Plain sleep */
	EC_SYSTEM = 8,	/* System-related operations (e.g. reboot) */
	EC_SIGNAL = 9,	/* Signal-related operations (e.g. signal) */
	EC_USER = 10,	/* User-related operations (e.g. getuid) */
	EC_TIME = 11,	/* Time-related syscalls (e.g. gettimeofday) */
	EC_PROCESSING = 12,	/* User level processing. Never used for system calls */
	EC_IO_BASE = 32,/* used for masking */
	EC_IO_READ = 32,/* General I/O read (can be file, socket, IPC...) */
	EC_IO_WRITE = 33,/* General I/O write (can be file, socket, IPC...) */
	EC_IO_OTHER = 34,/* General I/O that is neither read not write (can be file, socket, IPC...) */
	EC_WAIT = 64,	/* General wait (can be file, socket, IPC...) */
	EC_SCHEDULER = 128,	/* Scheduler event (e.g. context switch) */
	EC_INTERNAL = 256,	/* Internal event that shouldn't be shown to the user */
};

enum nod_event_flags {
	EF_NONE = 0,
	EF_CREATES_FD = (1 << 0), /* This event creates an FD (e.g. open) */
	EF_DESTROYS_FD = (1 << 1), /* This event destroys an FD (e.g. close) */
	EF_USES_FD = (1 << 2), /* This event operates on an FD. */
	EF_READS_FROM_FD = (1 << 3), /* This event reads data from an FD. */
	EF_WRITES_TO_FD = (1 << 4), /* This event writes data to an FD. */
	EF_MODIFIES_STATE = (1 << 5), /* This event causes the machine state to change and should not be dropped by the filtering engine. */
	EF_UNUSED = (1 << 6), /* This event is not used */
	EF_WAITS = (1 << 7), /* This event reads data from an FD. */
	EF_SKIPPARSERESET = (1 << 8), /* This event shouldn't pollute the parser lastevent state tracker. */
	EF_OLD_VERSION = (1 << 9), /* This event is kept for backward compatibility */
	EF_DROP_SIMPLE_CONS = (1 << 10), /* This event can be skipped by consumers that privilege low overhead to full event capture */
	EF_LARGE_PAYLOAD = (1 << 11), /* This event has a large payload, ie: up to UINT32_MAX bytes. DO NOT USE ON syscalls-driven events!!! */
};

/*
 * types of event parameters
 */
enum nod_param_type {
	PT_NONE = 0,
	PT_INT8 = 1,
	PT_INT16 = 2,
	PT_INT32 = 3,
	PT_INT64 = 4,
	PT_UINT8 = 5,
	PT_UINT16 = 6,
	PT_UINT32 = 7,
	PT_UINT64 = 8,
	PT_CHARBUF = 9,	/* A printable buffer of bytes, NULL terminated */
	PT_BYTEBUF = 10, /* A raw buffer of bytes not suitable for printing */
	PT_ERRNO = 11,	/* this is an INT64, but will be interpreted as an error code */
	PT_SOCKADDR = 12, /* A sockaddr structure, 1byte family + data */
	PT_SOCKTUPLE = 13, /* A sockaddr tuple,1byte family + 12byte data + 12byte data */
	PT_FD = 14, /* An fd, 64bit */
	PT_PID = 15, /* A pid/tid, 64bit */
	PT_FDLIST = 16, /* A list of fds, 16bit count + count * (64bit fd + 16bit flags) */
	PT_FSPATH = 17,	/* A string containing a relative or absolute file system path, null terminated */
	PT_SYSCALLID = 18, /* A 16bit system call ID. Can be used as a key for the g_syscall_info_table table. */
	PT_SIGTYPE = 19, /* An 8bit signal number */
	PT_RELTIME = 20, /* A relative time. Seconds * 10^9  + nanoseconds. 64bit. */
	PT_ABSTIME = 21, /* An absolute time interval. Seconds from epoch * 10^9  + nanoseconds. 64bit. */
	PT_PORT = 22, /* A TCP/UDP prt. 2 bytes. */
	PT_L4PROTO = 23, /* A 1 byte IP protocol type. */
	PT_SOCKFAMILY = 24, /* A 1 byte socket family. */
	PT_BOOL = 25, /* A boolean value, 4 bytes. */
	PT_IPV4ADDR = 26, /* A 4 byte raw IPv4 address. */
	PT_DYN = 27, /* Type can vary depending on the context. Used for filter fields like evt.rawarg. */
	PT_FLAGS8 = 28, /* this is an UINT8, but will be interpreted as 8 bit flags. */
	PT_FLAGS16 = 29, /* this is an UINT16, but will be interpreted as 16 bit flags. */
	PT_FLAGS32 = 30, /* this is an UINT32, but will be interpreted as 32 bit flags. */
	PT_UID = 31, /* this is an UINT32, MAX_UINT32 will be interpreted as no value. */
	PT_GID = 32, /* this is an UINT32, MAX_UINT32 will be interpreted as no value. */
	PT_DOUBLE = 33, /* this is a double precision floating point number. */
	PT_SIGSET = 34, /* sigset_t. I only store the lower UINT32 of it */
	PT_CHARBUFARRAY = 35,	/* Pointer to an array of strings, exported by the user events decoder. 64bit. For internal use only. */
	PT_CHARBUF_PAIR_ARRAY = 36,	/* Pointer to an array of string pairs, exported by the user events decoder. 64bit. For internal use only. */
	PT_IPV4NET = 37, /* An IPv4 network. */
	PT_IPV6ADDR = 38, /* A 16 byte raw IPv6 address. */
	PT_IPV6NET = 39, /* An IPv6 network. */
	PT_IPADDR = 40,  /* Either an IPv4 or IPv6 address. The length indicates which one it is. */
	PT_IPNET = 41,  /* Either an IPv4 or IPv6 network. The length indicates which one it is. */
	PT_MODE = 42, /* a 32 bit bitmask to represent file modes. */
	PT_FSRELPATH = 43, /* A path relative to a dirfd. */
	PT_MAX = 44 /* array size */
};

enum nod_print_format {
	PF_NA = 0,
	PF_DEC = 1,	/* decimal */
	PF_HEX = 2,	/* hexadecimal */
	PF_10_PADDED_DEC = 3, /* decimal padded to 10 digits, useful to print the fractional part of a ns timestamp */
	PF_OCT = 4,	/* octal */
	PF_ID = 5,
	PF_DIR = 6
};

enum nod_capture_category {
    NODC_NONE = 0,
    NODC_SYSCALL = 1
};

enum nod_event_type {
	NODE_GENERIC = 0,
    NODE_SYSCALL_OPEN = 1,
    NODE_SYSCALL_CLOSE = 2,
    NODE_SYSCALL_READ = 3,
    NODE_SYSCALL_WRITE = 4,
    NODE_SYSCALL_BRK_1 = 5,
    NODE_SYSCALL_EXIT = 6,
    NODE_SYSCALL_EXIT_GROUP = 7,
    NODE_SYSCALL_EXECVE_8 = 8,
    NODE_SYSCALL_CLONE_11 = 9,
    NODE_SOCKET_SOCKET = 10,
    NODE_SOCKET_BIND = 11,
    NODE_SOCKET_CONNECT = 12,
    NODE_SOCKET_LISTEN = 13,
    NODE_SOCKET_ACCEPT = 14,
    NODE_SOCKET_SEND = 15,
    NODE_SOCKET_SENDTO = 16,
    NODE_SOCKET_RECV = 17,
    NODE_SOCKET_RECVFROM = 18,
    NODE_SOCKET_SHUTDOWN = 19,
    NODE_SOCKET_GETSOCKNAME = 20,
    NODE_SOCKET_GETPEERNAME = 21,
    NODE_SOCKET_SOCKETPAIR = 22,
    NODE_SOCKET_SETSOCKOPT = 23,
    NODE_SOCKET_GETSOCKOPT = 24,
    NODE_SOCKET_SENDMSG = 25,
    NODE_SOCKET_SENDMMSG = 26,
    NODE_SOCKET_RECVMSG = 27,
    NODE_SOCKET_RECVMMSG = 28,
    NODE_SOCKET_ACCEPT4 = 29,
    NODE_SYSCALL_CREAT = 30,
    NODE_SYSCALL_PIPE = 31,
    NODE_SYSCALL_EVENTFD = 32,
    NODE_SYSCALL_FUTEX = 33,
    NODE_SYSCALL_STAT = 34,
    NODE_SYSCALL_LSTAT = 35,
    NODE_SYSCALL_FSTAT = 36,
    NODE_SYSCALL_STAT64 = 37,
    NODE_SYSCALL_LSTAT64 = 38,
    NODE_SYSCALL_FSTAT64 = 39,
    NODE_SYSCALL_EPOLLWAIT = 40,
    NODE_SYSCALL_POLL = 41,
    NODE_SYSCALL_SELECT = 42,
    NODE_SYSCALL_LSEEK = 43,
    NODE_SYSCALL_LLSEEK = 44,
    NODE_SYSCALL_IOCTL_2 = 45,
    NODE_SYSCALL_GETCWD = 46,
    NODE_SYSCALL_CHDIR = 47,
    NODE_SYSCALL_FCHDIR = 48,
    NODE_SYSCALL_MKDIR = 49,
    NODE_SYSCALL_RMDIR = 50,
    NODE_SYSCALL_OPENAT = 51,
    NODE_SYSCALL_LINK = 52,
    NODE_SYSCALL_LINKAT = 53,
    NODE_SYSCALL_UNLINK = 54,
    NODE_SYSCALL_UNLINKAT = 55,
    NODE_SYSCALL_PREAD = 56,
    NODE_SYSCALL_PWRITE = 57,
    NODE_SYSCALL_READV = 58,
    NODE_SYSCALL_WRITEV = 59,
    NODE_SYSCALL_PREADV = 60,
    NODE_SYSCALL_PWRITEV = 61,
    NODE_SYSCALL_DUP = 62,
    NODE_SYSCALL_SIGNALFD = 63,
    NODE_SYSCALL_KILL = 64,
    NODE_SYSCALL_TKILL = 65,
    NODE_SYSCALL_TGKILL = 66,
    NODE_SYSCALL_NANOSLEEP = 67,
    NODE_SYSCALL_TIMERFD_CREATE = 68,
    NODE_SYSCALL_INOTIFY_INIT = 69,
    NODE_SYSCALL_GETRLIMIT = 70,
    NODE_SYSCALL_SETRLIMIT = 71,
    NODE_SYSCALL_PRLIMIT = 72,
    NODE_SYSCALL_FCNTL = 73,
    NODE_SYSCALL_EXECVE_13 = 74,
    NODE_SYSCALL_CLONE_16 = 75,
    NODE_SYSCALL_BRK_4 = 76,
    NODE_SYSCALL_MMAP = 77,
    NODE_SYSCALL_MMAP2 = 78,
    NODE_SYSCALL_MUNMAP = 79,
    NODE_SYSCALL_SPLICE = 80,
    NODE_SYSCALL_PTRACE = 81,
    NODE_SYSCALL_IOCTL_3 = 82,
    NODE_SYSCALL_EXECVE_14 = 83,
    NODE_SYSCALL_RENAME = 84,
    NODE_SYSCALL_RENAMEAT = 85,
    NODE_SYSCALL_SYMLINK = 86,
    NODE_SYSCALL_SYMLINKAT = 87,
    NODE_SYSCALL_FORK = 88,
    NODE_SYSCALL_VFORK = 89,
    NODE_SYSCALL_SENDFILE = 90,
    NODE_SYSCALL_QUOTACTL = 91,
    NODE_SYSCALL_SETRESUID = 92,
    NODE_SYSCALL_SETRESGID = 93,
    NODE_SYSCALL_SETUID = 94,
    NODE_SYSCALL_SETGID = 95,
    NODE_SYSCALL_GETUID = 96,
    NODE_SYSCALL_GETEUID = 97,
    NODE_SYSCALL_GETGID = 98,
    NODE_SYSCALL_GETEGID = 99,
    NODE_SYSCALL_GETRESUID = 100,
    NODE_SYSCALL_GETRESGID = 101,
    NODE_SYSCALL_EXECVE_15 = 102,
    NODE_SYSCALL_CLONE_17 = 103,
    NODE_SYSCALL_FORK_17 = 104,
    NODE_SYSCALL_VFORK_17 = 105,
    NODE_SYSCALL_CLONE_20 = 106,
    NODE_SYSCALL_FORK_20 = 107,
    NODE_SYSCALL_VFORK_20 = 108,
    NODE_SYSCALL_EXECVE_16 = 109,
    NODE_SYSCALL_GETDENTS = 110,
    NODE_SYSCALL_GETDENTS64 = 111,
    NODE_SYSCALL_SETNS = 112,
    NODE_SYSCALL_FLOCK = 113,
    NODE_SOCKET_ACCEPT_5 = 114,
    NODE_SOCKET_ACCEPT4_5 = 115,
    NODE_SYSCALL_SEMOP = 116,
    NODE_SYSCALL_SEMCTL = 117,
    NODE_SYSCALL_PPOLL = 118,
    NODE_SYSCALL_MOUNT = 119,
    NODE_SYSCALL_UMOUNT = 120,
    NODE_SYSCALL_SEMGET = 121,
    NODE_SYSCALL_ACCESS = 122,
    NODE_SYSCALL_CHROOT = 123,
    NODE_SYSCALL_SETSID = 124,
    NODE_SYSCALL_MKDIR_2 = 125,
    NODE_SYSCALL_RMDIR_2 = 126,
    NODE_SYSCALL_EXECVE_17 = 127,
    NODE_SYSCALL_UNSHARE = 128,
    NODE_SYSCALL_EXECVE_18 = 129,
    NODE_SYSCALL_EXECVE_19 = 130,
    NODE_SYSCALL_SETPGID = 131,
    NODE_SYSCALL_BPF = 132,
    NODE_SYSCALL_SECCOMP = 133,
    NODE_SYSCALL_UNLINK_2 = 134,
    NODE_SYSCALL_UNLINKAT_2 = 135,
    NODE_SYSCALL_MKDIRAT = 136,
    NODE_SYSCALL_OPENAT_2 = 137,
    NODE_SYSCALL_LINK_2 = 138,
    NODE_SYSCALL_LINKAT_2 = 139,
    NODE_SYSCALL_FCHMODAT = 140,
    NODE_SYSCALL_CHMOD = 141,
    NODE_SYSCALL_FCHMOD = 142,
    NODE_SYSCALL_RENAMEAT2 = 143,
    NODE_SYSCALL_USERFAULTFD = 144,
    NODE_SYSCALL_OPENAT2 = 145,
    NODE_SYSCALL_MPROTECT = 146,
    NODE_SYSCALL_EXECVEAT = 147,
    NODE_SYSCALL_COPY_FILE_RANGE = 148,
    NODE_SYSCALL_CLONE3 = 149,
    NODE_EVENT_MAX = 150,
};

struct nod_buffer_info {
    volatile uint64_t nevents;
    volatile uint32_t tail;
};

#ifdef __KERNEL__
struct nod_overflow_page {
    char *addr;
    int filled;
};

struct nod_buffer {
    char *buffer;
	char *str_storage;
    struct nod_buffer_info *info;
	uint64_t event_count;
	struct rw_semaphore sem;
    struct nod_overflow_page overflow;
};
#endif //__KERNEL__

#define NOD_EVENT_HDR_MAGIC 0xCAFEBABE
struct nod_event_hdr {
    nanoseconds ts;
    uint32_t tid;
	uint16_t cpuid;
    uint16_t type;
    uint32_t len;
    uint32_t nargs;
    uint32_t magic;
}_packed;

struct nod_name_value {
    const char *name;
    uint32_t value;
};

struct event_filler_arguments {
    char *buf_ptr;
	char *str_storage;
    enum nod_event_type event_type;
    uint64_t nevents;
    uint32_t buffer_size;
    uint32_t syscall_nr;
    uint32_t curarg;
    uint32_t nargs;
    uint32_t arg_data_offset;
    uint32_t arg_data_size;
    uint32_t snaplen;
    struct pt_regs *regs;
	bool is_socketcall;
	int fd;
	unsigned long socketcall_args[6];
};

struct nod_event_data {
    enum nod_capture_category category;

    union {
        struct {
            struct pt_regs *regs;
            long id;
        } syscall_data;
    } event_info;

	int force;
};

#define NOD_MAX_AUTOFILL_ARGS (1 << 3)

struct nod_autofill_arg {
#define AF_ID_RETVAL -1
#define AF_ID_USEDEFAULT -2
	int16_t id;
	long default_val;
} _packed;

enum autofill_paramtype {
	APT_REG = 0,
	APT_SOCK = 1,
};

#ifdef __KERNEL__
typedef int (*filler_callback_t) (struct event_filler_arguments *args);
struct nod_event_entry {
    filler_callback_t filler_callback;
    enum nod_filler_id filler_id;
	uint16_t n_autofill_args;
	enum autofill_paramtype paramtype;
	struct nod_autofill_arg autofill_args[NOD_MAX_AUTOFILL_ARGS];
} _packed;
#endif

struct nod_param_info {
    char name[NOD_MAX_NAME_LEN];
    enum nod_param_type type;
    enum nod_print_format fmt;
    const void *info;
    uint8_t ninfo;
} _packed;

struct nod_event_info {
    char name[NOD_MAX_NAME_LEN];
    enum nod_event_category category;
    enum nod_event_flags flags;
    uint32_t nparams;
    struct nod_param_info params[NOD_MAX_EVENT_PARAMS];
} _packed;

extern const struct nod_event_info g_event_info[];

extern const struct nod_name_value socket_families[];
extern const struct nod_name_value file_flags[];
extern const struct nod_name_value flock_flags[];
extern const struct nod_name_value clone_flags[];
extern const struct nod_name_value futex_operations[];
extern const struct nod_name_value lseek_whence[];
extern const struct nod_name_value poll_flags[];
extern const struct nod_name_value mount_flags[];
extern const struct nod_name_value umount_flags[];
extern const struct nod_name_value shutdown_how[];
extern const struct nod_name_value rlimit_resources[];
extern const struct nod_name_value fcntl_commands[];
extern const struct nod_name_value sockopt_levels[];
extern const struct nod_name_value sockopt_options[];
extern const struct nod_name_value ptrace_requests[];
extern const struct nod_name_value prot_flags[];
extern const struct nod_name_value mmap_flags[];
extern const struct nod_name_value splice_flags[];
extern const struct nod_name_value quotactl_cmds[];
extern const struct nod_name_value quotactl_types[];
extern const struct nod_name_value quotactl_dqi_flags[];
extern const struct nod_name_value quotactl_quota_fmts[];
extern const struct nod_name_value semop_flags[];
extern const struct nod_name_value semget_flags[];
extern const struct nod_name_value semctl_commands[];
extern const struct nod_name_value access_flags[];
extern const struct nod_name_value pf_flags[];
extern const struct nod_name_value unlinkat_flags[];
extern const struct nod_name_value linkat_flags[];
extern const struct nod_name_value chmod_mode[];
extern const struct nod_name_value renameat2_flags[];
extern const struct nod_name_value openat2_flags[];
extern const struct nod_name_value execve_flags[];
extern const struct nod_name_value execveat_flags[];

extern const struct nod_param_info sockopt_dynamic_param[];
extern const struct nod_param_info ptrace_dynamic_param[];
extern const struct nod_param_info bpf_dynamic_param[];

enum syscall_flags {
	UF_NONE = 0,
	UF_USED = (1 << 0),
	UF_NEVER_DROP = (1 << 1),
	UF_ALWAYS_DROP = (1 << 2),
	UF_SIMPLEDRIVER_KEEP = (1 << 3), ///< Mark a syscall to be kept in simpledriver mode, see scap_enable_simpledriver_mode()
	UF_ATOMIC = (1 << 4), ///< The handler should not block (interrupt context)
	UF_UNINTERESTING = (1 << 5), ///< Marks a syscall as not interesting. Currently only used by BPF probe to avoid tracing uninteresting syscalls.
				     ///< Kmod uses a different logic path as we communicate with it through ioctls
};

#endif //_EVENTS_H_