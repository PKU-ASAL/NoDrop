#include <linux/kobject.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <net/sock.h>
#include <asm/unistd.h>
#include <asm/syscall.h>
#include <linux/unistd.h>

#include "nodrop.h"
#include "events.h"


/*
 * SYSCALL TABLE
 */

const struct syscall_evt_pair g_syscall_event_table[SYSCALL_TABLE_SIZE] = {
#ifdef __NR_open
    [__NR_open - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_OPEN},
#endif
#ifdef __NR_creat
    [__NR_creat - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_CREAT},
#endif
    [__NR_close - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SYSCALL_CLOSE},
    [__NR_brk - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_BRK_4},
    [__NR_read - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_READ},
    [__NR_write - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_WRITE},
    [__NR_execve - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SYSCALL_EXECVE_19},
    [__NR_clone - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SYSCALL_CLONE_20},
#ifdef __NR_fork
    [__NR_fork - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SYSCALL_FORK_20},
#endif
#ifdef __NR_vfork
    [__NR_vfork - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SYSCALL_VFORK_20},
#endif
#ifdef __NR_pipe
    [__NR_pipe - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_PIPE},
#endif
    [__NR_pipe2 - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_PIPE},
#ifdef __NR_eventfd
    [__NR_eventfd - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_EVENTFD},
#endif
    [__NR_eventfd2 - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_EVENTFD},
    [__NR_futex - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_FUTEX},
#ifdef __NR_stat
    [__NR_stat - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_STAT},
#endif
#ifdef __NR_lstat
    [__NR_lstat - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_LSTAT},
#endif
    [__NR_fstat - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_FSTAT},
#ifdef __NR_epoll_wait
    [__NR_epoll_wait - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_EPOLLWAIT},
#endif
#ifdef __NR_poll
    [__NR_poll - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_POLL},
#endif
#ifdef __NR_select
    [__NR_select - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_SELECT},
#endif
    [__NR_lseek - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_LSEEK},
    [__NR_ioctl - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_IOCTL_3},
    [__NR_getcwd - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_GETCWD},
    [__NR_chdir - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SYSCALL_CHDIR},
    [__NR_fchdir - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SYSCALL_FCHDIR},
#ifdef __NR_mkdir
    [__NR_mkdir - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_MKDIR_2},
#endif
#ifdef __NR_rmdir
    [__NR_rmdir - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_RMDIR_2},
#endif
    [__NR_openat - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_OPENAT_2},
    [__NR_mkdirat - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_MKDIRAT},
#ifdef __NR_link
    [__NR_link - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_LINK_2},
#endif
    [__NR_linkat - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_LINKAT_2},
#ifdef __NR_unlink
    [__NR_unlink - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_UNLINK_2},
#endif
    [__NR_unlinkat - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_UNLINKAT_2},
    [__NR_pread64 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_PREAD},
    [__NR_pwrite64 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_PWRITE},
    [__NR_readv - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_READV},
    [__NR_writev - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_WRITEV},
    [__NR_preadv - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_PREADV},
    [__NR_pwritev - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_PWRITEV},
    [__NR_dup - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SYSCALL_DUP},
#ifdef __NR_dup2
    [__NR_dup2 - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SYSCALL_DUP},
#endif
    [__NR_dup3 - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SYSCALL_DUP},
#ifdef __NR_signalfd
    [__NR_signalfd - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_SIGNALFD},
#endif
    [__NR_signalfd4 - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_SIGNALFD},
    [__NR_kill - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_KILL},
    [__NR_tkill - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_TKILL},
    [__NR_tgkill - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_TGKILL},
    [__NR_nanosleep - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_NANOSLEEP},
    [__NR_timerfd_create - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_TIMERFD_CREATE},
#ifdef __NR_inotify_init
    [__NR_inotify_init - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_INOTIFY_INIT},
#endif
    [__NR_inotify_init1 - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_INOTIFY_INIT},
    [__NR_fchmodat - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_FCHMODAT},
    [__NR_fchmod - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_FCHMOD},
#ifdef __NR_getrlimit
    [__NR_getrlimit - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_GETRLIMIT},
#endif
    [__NR_setrlimit - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_SETRLIMIT},
#ifdef __NR_prlimit64
    [__NR_prlimit64 - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_PRLIMIT},
#endif
#ifdef __NR_ugetrlimit
    [__NR_ugetrlimit - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_GETRLIMIT},
#endif
    [__NR_fcntl - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_FCNTL},
#ifdef __NR_fcntl64
    [__NR_fcntl64 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_FCNTL},
#endif
    [__NR_pselect6 - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_GENERIC},
#ifdef __NR_epoll_create
    [__NR_epoll_create - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_GENERIC},
#endif
    [__NR_epoll_ctl - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_GENERIC},
#ifdef __NR_uselib
    [__NR_uselib - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_GENERIC},
#endif
    [__NR_sched_setparam - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_GENERIC},
    [__NR_sched_getparam - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_GENERIC},
    [__NR_syslog - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_GENERIC},
#ifdef __NR_chmod
    [__NR_chmod - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_CHMOD},
#endif
#ifdef __NR_lchown
    [__NR_lchown - SYSCALL_TABLE_ID0] = {UF_USED, NODE_GENERIC},
#endif
#ifdef __NR_utime
    [__NR_utime - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_GENERIC},
#endif
    [__NR_mount - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_MOUNT},
    [__NR_umount2 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_UMOUNT},
    [__NR_ptrace - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_PTRACE},
#ifdef __NR_alarm
    [__NR_alarm - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_GENERIC},
#endif
#ifdef __NR_pause
    [__NR_pause - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_GENERIC},
#endif
#ifndef __NR_socketcall
    [__NR_socket - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SOCKET_SOCKET},
    [__NR_bind - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SOCKET_BIND},
    [__NR_connect - SYSCALL_TABLE_ID0] = {UF_USED | UF_SIMPLEDRIVER_KEEP, NODE_SOCKET_CONNECT},
    [__NR_listen - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SOCKET_LISTEN},
    [__NR_accept - SYSCALL_TABLE_ID0] = {UF_USED | UF_SIMPLEDRIVER_KEEP, NODE_SOCKET_ACCEPT_5},
    [__NR_getsockname - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SOCKET_GETSOCKNAME},
    [__NR_getpeername - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SOCKET_GETPEERNAME},
    [__NR_socketpair - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SOCKET_SOCKETPAIR},
    [__NR_sendto - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SOCKET_SENDTO},
    [__NR_recvfrom - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SOCKET_RECVFROM},
    [__NR_shutdown - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SOCKET_SHUTDOWN},
    [__NR_setsockopt - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SOCKET_SETSOCKOPT},
    [__NR_getsockopt - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SOCKET_GETSOCKOPT},
    [__NR_sendmsg - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SOCKET_SENDMSG},
    [__NR_accept4 - SYSCALL_TABLE_ID0] = {UF_USED | UF_SIMPLEDRIVER_KEEP, NODE_SOCKET_ACCEPT4_5},
#endif
#ifdef __NR_sendmmsg
    [__NR_sendmmsg - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SOCKET_SENDMMSG},
#endif
#ifdef __NR_recvmsg
    [__NR_recvmsg - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SOCKET_RECVMSG},
#endif
#ifdef __NR_recvmmsg
    [__NR_recvmmsg - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SOCKET_RECVMMSG},
#endif
#ifdef __NR_stat64
    [__NR_stat64 - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_STAT64},
#endif
#ifdef __NR_fstat64
    [__NR_fstat64 - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_FSTAT64},
#endif
#ifdef __NR__llseek
    [__NR__llseek - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_LLSEEK},
#endif
#ifdef __NR_mmap
    [__NR_mmap - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_MMAP},
#endif
#ifdef __NR_mmap2
    [__NR_mmap2 - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_MMAP2},
#endif
    [__NR_munmap - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_MUNMAP},
    [__NR_splice - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SPLICE},
#ifdef __NR_process_vm_readv
    [__NR_process_vm_readv - SYSCALL_TABLE_ID0] = {UF_USED, NODE_GENERIC},
#endif
#ifdef __NR_process_vm_writev
    [__NR_process_vm_writev - SYSCALL_TABLE_ID0] = {UF_USED, NODE_GENERIC},
#endif
#ifdef __NR_rename
    [__NR_rename - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_RENAME},
#endif
    [__NR_renameat - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_RENAMEAT},
#ifdef __NR_symlink
    [__NR_symlink - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SYMLINK},
#endif
    [__NR_symlinkat - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SYMLINKAT},
    [__NR_sendfile - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SENDFILE},
#ifdef __NR_sendfile64
    [__NR_sendfile64 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SENDFILE},
#endif
#ifdef __NR_quotactl
    [__NR_quotactl - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_QUOTACTL},
#endif
#ifdef __NR_setresuid
    [__NR_setresuid - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SETRESUID},
#endif
#ifdef __NR_setresuid32
    [__NR_setresuid32 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SETRESUID},
#endif
#ifdef __NR_setresgid
    [__NR_setresgid - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SETRESGID},
#endif
#ifdef __NR_setresgid32
    [__NR_setresgid32 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SETRESGID},
#endif
#ifdef __NR_setuid
    [__NR_setuid - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SETUID},
#endif
#ifdef __NR_setuid32
    [__NR_setuid32 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SETUID},
#endif
#ifdef __NR_setgid
    [__NR_setgid - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SETGID},
#endif
#ifdef __NR_setgid32
    [__NR_setgid32 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SETGID},
#endif
#ifdef __NR_getuid
    [__NR_getuid - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_GETUID},
#endif
#ifdef __NR_getuid32
    [__NR_getuid32 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_GETUID},
#endif
#ifdef __NR_geteuid
    [__NR_geteuid - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_GETEUID},
#endif
#ifdef __NR_geteuid32
    [__NR_geteuid32 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_GETEUID},
#endif
#ifdef __NR_getgid
    [__NR_getgid - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_GETGID},
#endif
#ifdef __NR_getgid32
    [__NR_getgid32 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_GETGID},
#endif
#ifdef __NR_getegid
    [__NR_getegid - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_GETEGID},
#endif
#ifdef __NR_getegid32
    [__NR_getegid32 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_GETEGID},
#endif
#ifdef __NR_getresuid
    [__NR_getresuid - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_GETRESUID},
#endif
#ifdef __NR_getresuid32
    [__NR_getresuid32 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_GETRESUID},
#endif
#ifdef __NR_getresgid
    [__NR_getresgid - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_GETRESGID},
#endif
#ifdef __NR_getresgid32
    [__NR_getresgid32 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_GETRESGID},
#endif
#ifdef __NR_getdents
    [__NR_getdents - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_GETDENTS},
#endif
    [__NR_getdents64 - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_GETDENTS64},
#ifdef __NR_setns
    [__NR_setns - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SETNS},
#endif
#ifdef __NR_unshare
    [__NR_unshare - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_UNSHARE},
#endif
    [__NR_flock - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_FLOCK},
#ifdef __NR_semop
    [__NR_semop - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_SEMOP},
#endif
#ifdef __NR_semget
    [__NR_semget - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_SEMGET},
#endif
#ifdef __NR_semctl
    [__NR_semctl - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_SEMCTL},
#endif
    [__NR_ppoll - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_PPOLL},
#ifdef __NR_access
    [__NR_access - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_ACCESS},
#endif
#ifdef __NR_chroot
    [__NR_chroot - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_CHROOT},
#endif
    [__NR_setsid - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_SETSID},
    [__NR_setpgid - SYSCALL_TABLE_ID0] = {UF_USED | UF_ALWAYS_DROP, NODE_SYSCALL_SETPGID},
#ifdef __NR_bpf
    [__NR_bpf - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_BPF},
#endif
#ifdef __NR_seccomp
    [__NR_seccomp - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_SECCOMP},
#endif
#ifdef __NR_renameat2
    [__NR_renameat2 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_RENAMEAT2},
#endif
#ifdef __NR_userfaultfd
    [__NR_userfaultfd - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, NODE_SYSCALL_USERFAULTFD},
#endif
#ifdef __NR_openat2
    [__NR_openat2 - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_OPENAT2},
#endif
#ifdef __NR_clone3
    [__NR_clone3 - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SYSCALL_CLONE3},
#endif
#ifdef __NR_mprotect
    [__NR_mprotect - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_MPROTECT},
#endif
#ifdef __NR_execveat
    [__NR_execveat - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, NODE_SYSCALL_EXECVEAT},
#endif
#ifdef __NR_copy_file_range
    [__NR_copy_file_range - SYSCALL_TABLE_ID0] = {UF_USED, NODE_SYSCALL_COPY_FILE_RANGE},
#endif
};
