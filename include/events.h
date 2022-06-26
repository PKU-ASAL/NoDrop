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

// enum nod_event_flags {
// 	EF_NONE = 0,
// 	EF_CREATES_FD = (1 << 0), /* This event creates an FD (e.g. open) */
// 	EF_DESTROYS_FD = (1 << 1), /* This event destroys an FD (e.g. close) */
// 	EF_USES_FD = (1 << 2), /* This event operates on an FD. */
// 	EF_READS_FROM_FD = (1 << 3), /* This event reads data from an FD. */
// 	EF_WRITES_TO_FD = (1 << 4), /* This event writes data to an FD. */
// 	EF_MODIFIES_STATE = (1 << 5), /* This event causes the machine state to change and should not be dropped by the filtering engine. */
// 	EF_UNUSED = (1 << 6), /* This event is not used */
// 	EF_WAITS = (1 << 7), /* This event reads data from an FD. */
// 	EF_SKIPPARSERESET = (1 << 8), /* This event shouldn't pollute the parser lastevent state tracker. */
// 	EF_OLD_VERSION = (1 << 9), /* This event is kept for backward compatibility */
// 	EF_DROP_SIMPLE_CONS = (1 << 10) /* This event can be skipped by consumers that privilege low overhead to full event capture */
// };

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
	SPRE_GENERIC_E = 0,
	SPRE_GENERIC_X = 1,
	SPRE_SYSCALL_OPEN_E = 2,
	SPRE_SYSCALL_OPEN_X = 3,
	SPRE_SYSCALL_CLOSE_E = 4,
	SPRE_SYSCALL_CLOSE_X = 5,
	SPRE_SYSCALL_READ_E = 6,
	SPRE_SYSCALL_READ_X = 7,
	SPRE_SYSCALL_WRITE_E = 8,
	SPRE_SYSCALL_WRITE_X = 9,
	SPRE_SYSCALL_BRK_1_E = 10,
	SPRE_SYSCALL_BRK_1_X = 11,
	SPRE_SYSCALL_EXECVE_8_E = 12,
	SPRE_SYSCALL_EXECVE_8_X = 13,
	SPRE_SYSCALL_CLONE_11_E = 14,
	SPRE_SYSCALL_CLONE_11_X = 15,
	SPRE_PROCEXIT_E = 16,
	SPRE_PROCEXIT_X = 17,	/* This should never be called */
	SPRE_SOCKET_SOCKET_E = 18,
	SPRE_SOCKET_SOCKET_X = 19,
	SPRE_SOCKET_BIND_E = 20,
	SPRE_SOCKET_BIND_X = 21,
	SPRE_SOCKET_CONNECT_E = 22,
	SPRE_SOCKET_CONNECT_X = 23,
	SPRE_SOCKET_LISTEN_E = 24,
	SPRE_SOCKET_LISTEN_X = 25,
	SPRE_SOCKET_ACCEPT_E = 26,
	SPRE_SOCKET_ACCEPT_X = 27,
	SPRE_SOCKET_SEND_E = 28,
	SPRE_SOCKET_SEND_X = 29,
	SPRE_SOCKET_SENDTO_E = 30,
	SPRE_SOCKET_SENDTO_X = 31,
	SPRE_SOCKET_RECV_E = 32,
	SPRE_SOCKET_RECV_X = 33,
	SPRE_SOCKET_RECVFROM_E = 34,
	SPRE_SOCKET_RECVFROM_X = 35,
	SPRE_SOCKET_SHUTDOWN_E = 36,
	SPRE_SOCKET_SHUTDOWN_X = 37,
	SPRE_SOCKET_GETSOCKNAME_E = 38,
	SPRE_SOCKET_GETSOCKNAME_X = 39,
	SPRE_SOCKET_GETPEERNAME_E = 40,
	SPRE_SOCKET_GETPEERNAME_X = 41,
	SPRE_SOCKET_SOCKETPAIR_E = 42,
	SPRE_SOCKET_SOCKETPAIR_X = 43,
	SPRE_SOCKET_SETSOCKOPT_E = 44,
	SPRE_SOCKET_SETSOCKOPT_X = 45,
	SPRE_SOCKET_GETSOCKOPT_E = 46,
	SPRE_SOCKET_GETSOCKOPT_X = 47,
	SPRE_SOCKET_SENDMSG_E = 48,
	SPRE_SOCKET_SENDMSG_X = 49,
	SPRE_SOCKET_SENDMMSG_E = 50,
	SPRE_SOCKET_SENDMMSG_X = 51,
	SPRE_SOCKET_RECVMSG_E = 52,
	SPRE_SOCKET_RECVMSG_X = 53,
	SPRE_SOCKET_RECVMMSG_E = 54,
	SPRE_SOCKET_RECVMMSG_X = 55,
	SPRE_SOCKET_ACCEPT4_E = 56,
	SPRE_SOCKET_ACCEPT4_X = 57,
	SPRE_SYSCALL_CREAT_E = 58,
	SPRE_SYSCALL_CREAT_X = 59,
	SPRE_SYSCALL_PIPE_E = 60,
	SPRE_SYSCALL_PIPE_X = 61,
	SPRE_SYSCALL_EVENTFD_E = 62,
	SPRE_SYSCALL_EVENTFD_X = 63,
	SPRE_SYSCALL_FUTEX_E = 64,
	SPRE_SYSCALL_FUTEX_X = 65,
	SPRE_SYSCALL_STAT_E = 66,
	SPRE_SYSCALL_STAT_X = 67,
	SPRE_SYSCALL_LSTAT_E = 68,
	SPRE_SYSCALL_LSTAT_X = 69,
	SPRE_SYSCALL_FSTAT_E = 70,
	SPRE_SYSCALL_FSTAT_X = 71,
	SPRE_SYSCALL_STAT64_E = 72,
	SPRE_SYSCALL_STAT64_X = 73,
	SPRE_SYSCALL_LSTAT64_E = 74,
	SPRE_SYSCALL_LSTAT64_X = 75,
	SPRE_SYSCALL_FSTAT64_E = 76,
	SPRE_SYSCALL_FSTAT64_X = 77,
	SPRE_SYSCALL_EPOLLWAIT_E = 78,
	SPRE_SYSCALL_EPOLLWAIT_X = 79,
	SPRE_SYSCALL_POLL_E = 80,
	SPRE_SYSCALL_POLL_X = 81,
	SPRE_SYSCALL_SELECT_E = 82,
	SPRE_SYSCALL_SELECT_X = 83,
	SPRE_SYSCALL_NEWSELECT_E = 84,
	SPRE_SYSCALL_NEWSELECT_X = 85,
	SPRE_SYSCALL_LSEEK_E = 86,
	SPRE_SYSCALL_LSEEK_X = 87,
	SPRE_SYSCALL_LLSEEK_E = 88,
	SPRE_SYSCALL_LLSEEK_X = 89,
	SPRE_SYSCALL_IOCTL_2_E = 90,
	SPRE_SYSCALL_IOCTL_2_X = 91,
	SPRE_SYSCALL_GETCWD_E = 92,
	SPRE_SYSCALL_GETCWD_X = 93,
	SPRE_SYSCALL_CHDIR_E = 94,
	SPRE_SYSCALL_CHDIR_X = 95,
	SPRE_SYSCALL_FCHDIR_E = 96,
	SPRE_SYSCALL_FCHDIR_X = 97,
	/* mkdir/rmdir events are not emitted anymore */
	SPRE_SYSCALL_MKDIR_E = 98,
	SPRE_SYSCALL_MKDIR_X = 99,
	SPRE_SYSCALL_RMDIR_E = 100,
	SPRE_SYSCALL_RMDIR_X = 101,
	SPRE_SYSCALL_OPENAT_E = 102,
	SPRE_SYSCALL_OPENAT_X = 103,
	SPRE_SYSCALL_LINK_E = 104,
	SPRE_SYSCALL_LINK_X = 105,
	SPRE_SYSCALL_LINKAT_E = 106,
	SPRE_SYSCALL_LINKAT_X = 107,
	SPRE_SYSCALL_UNLINK_E = 108,
	SPRE_SYSCALL_UNLINK_X = 109,
	SPRE_SYSCALL_UNLINKAT_E = 110,
	SPRE_SYSCALL_UNLINKAT_X = 111,
	SPRE_SYSCALL_PREAD_E = 112,
	SPRE_SYSCALL_PREAD_X = 113,
	SPRE_SYSCALL_PWRITE_E = 114,
	SPRE_SYSCALL_PWRITE_X = 115,
	SPRE_SYSCALL_READV_E = 116,
	SPRE_SYSCALL_READV_X = 117,
	SPRE_SYSCALL_WRITEV_E = 118,
	SPRE_SYSCALL_WRITEV_X = 119,
	SPRE_SYSCALL_PREADV_E = 120,
	SPRE_SYSCALL_PREADV_X = 121,
	SPRE_SYSCALL_PWRITEV_E = 122,
	SPRE_SYSCALL_PWRITEV_X = 123,
	SPRE_SYSCALL_DUP_E = 124,
	SPRE_SYSCALL_DUP_X = 125,
	SPRE_SYSCALL_SIGNALFD_E = 126,
	SPRE_SYSCALL_SIGNALFD_X = 127,
	SPRE_SYSCALL_KILL_E = 128,
	SPRE_SYSCALL_KILL_X = 129,
	SPRE_SYSCALL_TKILL_E = 130,
	SPRE_SYSCALL_TKILL_X = 131,
	SPRE_SYSCALL_TGKILL_E = 132,
	SPRE_SYSCALL_TGKILL_X = 133,
	SPRE_SYSCALL_NANOSLEEP_E = 134,
	SPRE_SYSCALL_NANOSLEEP_X = 135,
	SPRE_SYSCALL_TIMERFD_CREATE_E = 136,
	SPRE_SYSCALL_TIMERFD_CREATE_X = 137,
	SPRE_SYSCALL_INOTIFY_INIT_E = 138,
	SPRE_SYSCALL_INOTIFY_INIT_X = 139,
	SPRE_SYSCALL_GETRLIMIT_E = 140,
	SPRE_SYSCALL_GETRLIMIT_X = 141,
	SPRE_SYSCALL_SETRLIMIT_E = 142,
	SPRE_SYSCALL_SETRLIMIT_X = 143,
	SPRE_SYSCALL_PRLIMIT_E = 144,
	SPRE_SYSCALL_PRLIMIT_X = 145,
	SPRE_SCHEDSWITCH_1_E = 146,
	SPRE_SCHEDSWITCH_1_X = 147,	/* This should never be called */
	SPRE_DROP_E = 148,  /* For internal use */
	SPRE_DROP_X = 149,	/* For internal use */
	SPRE_SYSCALL_FCNTL_E = 150,  /* For internal use */
	SPRE_SYSCALL_FCNTL_X = 151,	/* For internal use */
	SPRE_SCHEDSWITCH_6_E = 152,
	SPRE_SCHEDSWITCH_6_X = 153,	/* This should never be called */
	SPRE_SYSCALL_EXECVE_13_E = 154,
	SPRE_SYSCALL_EXECVE_13_X = 155,
	SPRE_SYSCALL_CLONE_16_E = 156,
	SPRE_SYSCALL_CLONE_16_X = 157,
	SPRE_SYSCALL_BRK_4_E = 158,
	SPRE_SYSCALL_BRK_4_X = 159,
	SPRE_SYSCALL_MMAP_E = 160,
	SPRE_SYSCALL_MMAP_X = 161,
	SPRE_SYSCALL_MMAP2_E = 162,
	SPRE_SYSCALL_MMAP2_X = 163,
	SPRE_SYSCALL_MUNMAP_E = 164,
	SPRE_SYSCALL_MUNMAP_X = 165,
	SPRE_SYSCALL_SPLICE_E = 166,
	SPRE_SYSCALL_SPLICE_X = 167,
	SPRE_SYSCALL_PTRACE_E = 168,
	SPRE_SYSCALL_PTRACE_X = 169,
	SPRE_SYSCALL_IOCTL_3_E = 170,
	SPRE_SYSCALL_IOCTL_3_X = 171,
	SPRE_SYSCALL_EXECVE_14_E = 172,
	SPRE_SYSCALL_EXECVE_14_X = 173,
	SPRE_SYSCALL_RENAME_E = 174,
	SPRE_SYSCALL_RENAME_X = 175,
	SPRE_SYSCALL_RENAMEAT_E = 176,
	SPRE_SYSCALL_RENAMEAT_X = 177,
	SPRE_SYSCALL_SYMLINK_E = 178,
	SPRE_SYSCALL_SYMLINK_X = 179,
	SPRE_SYSCALL_SYMLINKAT_E = 180,
	SPRE_SYSCALL_SYMLINKAT_X = 181,
	SPRE_SYSCALL_FORK_E = 182,
	SPRE_SYSCALL_FORK_X = 183,
	SPRE_SYSCALL_VFORK_E = 184,
	SPRE_SYSCALL_VFORK_X = 185,
	SPRE_PROCEXIT_1_E = 186,
	SPRE_PROCEXIT_1_X = 187,	/* This should never be called */
	SPRE_SYSCALL_SENDFILE_E = 188,
	SPRE_SYSCALL_SENDFILE_X = 189,	/* This should never be called */
	SPRE_SYSCALL_QUOTACTL_E = 190,
	SPRE_SYSCALL_QUOTACTL_X = 191,
	SPRE_SYSCALL_SETRESUID_E = 192,
	SPRE_SYSCALL_SETRESUID_X = 193,
	SPRE_SYSCALL_SETRESGID_E = 194,
	SPRE_SYSCALL_SETRESGID_X = 195,
	SPRE_SYSDIGEVENT_E = 196,
	SPRE_SYSDIGEVENT_X = 197, /* This should never be called */
	SPRE_SYSCALL_SETUID_E = 198,
	SPRE_SYSCALL_SETUID_X = 199,
	SPRE_SYSCALL_SETGID_E = 200,
	SPRE_SYSCALL_SETGID_X = 201,
	SPRE_SYSCALL_GETUID_E = 202,
	SPRE_SYSCALL_GETUID_X = 203,
	SPRE_SYSCALL_GETEUID_E = 204,
	SPRE_SYSCALL_GETEUID_X = 205,
	SPRE_SYSCALL_GETGID_E = 206,
	SPRE_SYSCALL_GETGID_X = 207,
	SPRE_SYSCALL_GETEGID_E = 208,
	SPRE_SYSCALL_GETEGID_X = 209,
	SPRE_SYSCALL_GETRESUID_E = 210,
	SPRE_SYSCALL_GETRESUID_X = 211,
	SPRE_SYSCALL_GETRESGID_E = 212,
	SPRE_SYSCALL_GETRESGID_X = 213,
	SPRE_SYSCALL_EXECVE_15_E = 214,
	SPRE_SYSCALL_EXECVE_15_X = 215,
	SPRE_SYSCALL_CLONE_17_E = 216,
	SPRE_SYSCALL_CLONE_17_X = 217,
	SPRE_SYSCALL_FORK_17_E = 218,
	SPRE_SYSCALL_FORK_17_X = 219,
	SPRE_SYSCALL_VFORK_17_E = 220,
	SPRE_SYSCALL_VFORK_17_X = 221,
	SPRE_SYSCALL_CLONE_20_E = 222,
	SPRE_SYSCALL_CLONE_20_X = 223,
	SPRE_SYSCALL_FORK_20_E = 224,
	SPRE_SYSCALL_FORK_20_X = 225,
	SPRE_SYSCALL_VFORK_20_E = 226,
	SPRE_SYSCALL_VFORK_20_X = 227,
	SPRE_CONTAINER_E = 228,
	SPRE_CONTAINER_X = 229,
	SPRE_SYSCALL_EXECVE_16_E = 230,
	SPRE_SYSCALL_EXECVE_16_X = 231,
	SPRE_SIGNALDELIVER_E = 232,
	SPRE_SIGNALDELIVER_X = 233, /* This should never be called */
	SPRE_PROCINFO_E = 234,
	SPRE_PROCINFO_X = 235,	/* This should never be called */
	SPRE_SYSCALL_GETDENTS_E = 236,
	SPRE_SYSCALL_GETDENTS_X = 237,
	SPRE_SYSCALL_GETDENTS64_E = 238,
	SPRE_SYSCALL_GETDENTS64_X = 239,
	SPRE_SYSCALL_SETNS_E = 240,
	SPRE_SYSCALL_SETNS_X = 241,
	SPRE_SYSCALL_FLOCK_E = 242,
	SPRE_SYSCALL_FLOCK_X = 243,
	SPRE_CPU_HOTPLUG_E = 244,
	SPRE_CPU_HOTPLUG_X = 245, /* This should never be called */
	SPRE_SOCKET_ACCEPT_5_E = 246,
	SPRE_SOCKET_ACCEPT_5_X = 247,
	SPRE_SOCKET_ACCEPT4_5_E = 248,
	SPRE_SOCKET_ACCEPT4_5_X = 249,
	SPRE_SYSCALL_SEMOP_E = 250,
	SPRE_SYSCALL_SEMOP_X = 251,
	SPRE_SYSCALL_SEMCTL_E = 252,
	SPRE_SYSCALL_SEMCTL_X = 253,
	SPRE_SYSCALL_PPOLL_E = 254,
	SPRE_SYSCALL_PPOLL_X = 255,
	SPRE_SYSCALL_MOUNT_E = 256,
	SPRE_SYSCALL_MOUNT_X = 257,
	SPRE_SYSCALL_UMOUNT_E = 258,
	SPRE_SYSCALL_UMOUNT_X = 259,
	SPRE_K8S_E = 260,
	SPRE_K8S_X = 261,
	SPRE_SYSCALL_SEMGET_E = 262,
	SPRE_SYSCALL_SEMGET_X = 263,
	SPRE_SYSCALL_ACCESS_E = 264,
	SPRE_SYSCALL_ACCESS_X = 265,
	SPRE_SYSCALL_CHROOT_E = 266,
	SPRE_SYSCALL_CHROOT_X = 267,
	SPRE_TRACER_E = 268,
	SPRE_TRACER_X = 269,
	SPRE_MESOS_E = 270,
	SPRE_MESOS_X = 271,
	SPRE_CONTAINER_JSON_E = 272,
	SPRE_CONTAINER_JSON_X = 273,
	SPRE_SYSCALL_SETSID_E = 274,
	SPRE_SYSCALL_SETSID_X = 275,
	SPRE_SYSCALL_MKDIR_2_E = 276,
	SPRE_SYSCALL_MKDIR_2_X = 277,
	SPRE_SYSCALL_RMDIR_2_E = 278,
	SPRE_SYSCALL_RMDIR_2_X = 279,
	SPRE_NOTIFICATION_E = 280,
	SPRE_NOTIFICATION_X = 281,
	SPRE_SYSCALL_EXECVE_17_E = 282,
	SPRE_SYSCALL_EXECVE_17_X = 283,
	SPRE_SYSCALL_UNSHARE_E = 284,
	SPRE_SYSCALL_UNSHARE_X = 285,
	SPRE_INFRASTRUCTURE_EVENT_E = 286,
	SPRE_INFRASTRUCTURE_EVENT_X = 287,
	SPRE_SYSCALL_EXECVE_18_E = 288,
	SPRE_SYSCALL_EXECVE_18_X = 289,
	SPRE_PAGE_FAULT_E = 290,
	SPRE_PAGE_FAULT_X = 291,
	SPRE_SYSCALL_EXECVE_19_E = 292,
	SPRE_SYSCALL_EXECVE_19_X = 293,
	SPRE_SYSCALL_SETPGID_E = 294,
	SPRE_SYSCALL_SETPGID_X = 295,
	SPRE_SYSCALL_BPF_E = 296,
	SPRE_SYSCALL_BPF_X = 297,
	SPRE_SYSCALL_SECCOMP_E = 298,
	SPRE_SYSCALL_SECCOMP_X = 299,
	SPRE_SYSCALL_UNLINK_2_E = 300,
	SPRE_SYSCALL_UNLINK_2_X = 301,
	SPRE_SYSCALL_UNLINKAT_2_E = 302,
	SPRE_SYSCALL_UNLINKAT_2_X = 303,
	SPRE_SYSCALL_MKDIRAT_E = 304,
	SPRE_SYSCALL_MKDIRAT_X = 305,
	SPRE_SYSCALL_OPENAT_2_E = 306,
	SPRE_SYSCALL_OPENAT_2_X = 307,
	SPRE_SYSCALL_LINK_2_E = 308,
	SPRE_SYSCALL_LINK_2_X = 309,
	SPRE_SYSCALL_LINKAT_2_E = 310,
	SPRE_SYSCALL_LINKAT_2_X = 311,
	SPRE_SYSCALL_FCHMODAT_E = 312,
	SPRE_SYSCALL_FCHMODAT_X = 313,
	SPRE_SYSCALL_CHMOD_E = 314,
	SPRE_SYSCALL_CHMOD_X = 315,
	SPRE_SYSCALL_FCHMOD_E = 316,
	SPRE_SYSCALL_FCHMOD_X = 317,
	SPRE_SYSCALL_RENAMEAT2_E = 318,
	SPRE_SYSCALL_RENAMEAT2_X = 319,
	SPRE_SYSCALL_USERFAULTFD_E = 320,
	SPRE_SYSCALL_USERFAULTFD_X = 321,
	SPRE_PLUGINEVENT_E = 322,
	SPRE_PLUGINEVENT_X = 323,
	SPRE_CONTAINER_JSON_2_E = 324,
	SPRE_CONTAINER_JSON_2_X = 325,
	SPRE_SYSCALL_OPENAT2_E = 326,
	SPRE_SYSCALL_OPENAT2_X = 327,
	SPRE_SYSCALL_MPROTECT_E = 328,
	SPRE_SYSCALL_MPROTECT_X = 329,
	SPRE_SYSCALL_EXECVEAT_E = 330,
	SPRE_SYSCALL_EXECVEAT_X = 331,
	SPRE_SYSCALL_COPY_FILE_RANGE_E = 332,
	SPRE_SYSCALL_COPY_FILE_RANGE_X = 333,
	SPRE_SYSCALL_CLONE3_E = 334,
	SPRE_SYSCALL_CLONE3_X = 335,
	SPRE_EVENT_MAX = 336
};

// enum nod_event_type {
//     NODE_GENERIC = 0,
//     NODE_SYSCALL_READ = 1,
//     NODE_SYSCALL_WRITE = 2,
//     NODE_SYSCALL_OPEN = 3,
//     NODE_SYSCALL_CLOSE = 4,
//     NODE_SYSCALL_EXIT = 5,
//     NODE_SYSCALL_EXIT_GROUP = 6,
// 	NODE_SYSCALL_EXECVE = 7,
// 	NODE_SYSCALL_CLONE = 8,
// 	NODE_SYSCALL_FORK = 9,
// 	NODE_SYSCALL_VFORK = 10,
// 	NODE_SYSCALL_SOCKET = 11,
// 	NODE_SYSCALL_BIND = 12,
// 	NODE_SYSCALL_CONNECT = 13,
// 	NODE_SYSCALL_LISTEN = 14,
// 	NODE_SYSCALL_ACCEPT = 15,
// 	NODE_SYSCALL_GETSOCKNAME = 16,
// 	NODE_SYSCALL_GETPEERNAME = 17,
// 	NODE_SYSCALL_SOCKETPAIR = 18,
// 	NODE_SYSCALL_SENDTO = 19,
// 	NODE_SYSCALL_RECVFROM = 20,
// 	NODE_SYSCALL_SHUTDOWN = 21,
// 	NODE_SYSCALL_SETSOCKOPT = 22,
// 	NODE_SYSCALL_GETSOCKOPT = 23,
// 	NODE_SYSCALL_ACCEPT4 = 24,
// 	NODE_SYSCALL_SENDMSG = 25,
// 	NODE_SYSCALL_SENDMMSG = 26,
// 	NODE_SYSCALL_RECVMSG = 27,
// 	NODE_SYSCALL_RECVMMSG = 28,
// 	NODE_SYSCALL_IOCTL = 29,
// 	NODE_SYSCALL_GETUID = 30,
//     NODE_EVENT_MAX
// };

/*************/

struct nod_buffer_info {
    volatile uint64_t nevents;
    volatile uint32_t tail;
};

struct nod_buffer {
    char buffer[BUFFER_SIZE];
    struct nod_buffer_info info;
};

#ifdef __KERNEL__
struct nod_kbuffer {
    char *buffer;
	char *str_storage;
    struct nod_buffer_info *info;
	struct rw_semaphore sem;
	uint64_t event_count;
};

static inline void copy_to_user_buffer(const struct nod_kbuffer *kbuf, struct nod_buffer *ubuf)
{
	memcpy(ubuf->buffer, kbuf->buffer, BUFFER_SIZE);
	memcpy(&ubuf->info, kbuf->info, sizeof(struct nod_buffer_info));
}
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

// struct event_filler_arguments {
//     char *buf_ptr;
// 	char *str_storage;
//     enum nod_event_type event_type;
//     uint64_t nevents;
//     uint32_t buffer_size;
//     uint32_t syscall_nr;
//     uint32_t curarg;
//     uint32_t nargs;
//     uint32_t arg_data_offset;
//     uint32_t arg_data_size;
//     uint32_t snaplen;
//     struct pt_regs *regs;
// };

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

// #ifdef __KERNEL__
// typedef int (*filler_callback_t) (struct event_filler_arguments *args);
// struct nod_event_entry {
//     filler_callback_t filler_callback;
//     enum nod_filler_id filler_id;
// } _packed;
// #endif

#define NOD_MAX_AUTOFILL_ARGS (1 << 2)

struct nod_autofill_arg {
#define AF_ID_RETVAL -1
#define AF_ID_USEDEFAULT -2
	int16_t id;
	long default_val;
} _packed;

enum autofill_paramtype {
	APT_REG,
	APT_SOCK,
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

// extern const struct nod_name_value socket_families[];
// extern const struct nod_name_value file_flags[];
// extern const struct nod_name_value flock_flags[];
// extern const struct nod_name_value clone_flags[];
// extern const struct nod_name_value futex_operations[];
// extern const struct nod_name_value lseek_whence[];
// extern const struct nod_name_value poll_flags[];
// extern const struct nod_name_value mount_flags[];
// extern const struct nod_name_value umount_flags[];
// extern const struct nod_name_value shutdown_how[];
// extern const struct nod_name_value rlimit_resources[];
// extern const struct nod_name_value fcntl_commands[];
// extern const struct nod_name_value sockopt_levels[];
// extern const struct nod_name_value sockopt_options[];
// extern const struct nod_name_value ptrace_requests[];
// extern const struct nod_name_value prot_flags[];
// extern const struct nod_name_value mmap_flags[];
// extern const struct nod_name_value splice_flags[];
// extern const struct nod_name_value quotactl_cmds[];
// extern const struct nod_name_value quotactl_types[];
// extern const struct nod_name_value quotactl_dqi_flags[];
// extern const struct nod_name_value quotactl_quota_fmts[];
// extern const struct nod_name_value semop_flags[];
// extern const struct nod_name_value semget_flags[];
// extern const struct nod_name_value semctl_commands[];
// extern const struct nod_name_value access_flags[];
// extern const struct nod_name_value pf_flags[];
// extern const struct nod_name_value unlinkat_flags[];
// extern const struct nod_name_value linkat_flags[];
// extern const struct nod_name_value chmod_mode[];
// extern const struct nod_name_value renameat2_flags[];

// extern const struct nod_param_info sockopt_dynamic_param[];

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