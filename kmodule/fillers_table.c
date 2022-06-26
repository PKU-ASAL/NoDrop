#include "fillers.h"
#include "nodrop.h"

#include "events.h"

#define FILLER_REF(x) f_##x, NOD_FILLER_##x

#define f_sys_socket_x f_sys_single_x

// const struct nod_event_entry g_nod_events[SPRE_EVENT_MAX] = {
//     [SPRE_SYSCALL_READ] = {FILLER_REF(sys_read)},
//     [SPRE_SYSCALL_WRITE] = {FILLER_REF(sys_write)},
//     [SPRE_SYSCALL_OPEN] = {FILLER_REF(sys_open)},
//     [SPRE_SYSCALL_CLOSE] = {FILLER_REF(sys_close)},
//     [SPRE_SYSCALL_EXIT] = {FILLER_REF(sys_exit)},
//     [SPRE_SYSCALL_EXIT_GROUP] = {FILLER_REF(sys_exit_group)},
//     [SPRE_SYSCALL_EXECVE] = {FILLER_REF(sys_execve)},
//     [SPRE_SYSCALL_CLONE] = {FILLER_REF(proc_startupdate)},
//     [SPRE_SYSCALL_FORK] = {FILLER_REF(proc_startupdate)},
//     [SPRE_SYSCALL_VFORK] = {FILLER_REF(proc_startupdate)},
//     [SPRE_SYSCALL_SOCKET] = {FILLER_REF(sys_socket)},
//     [SPRE_SYSCALL_BIND] = {FILLER_REF(sys_socket_bind)},
//     [SPRE_SYSCALL_CONNECT] = {FILLER_REF(sys_connect)},
//     [SPRE_SYSCALL_LISTEN] = {FILLER_REF(sys_listen)},
//     [SPRE_SYSCALL_ACCEPT] = {FILLER_REF(sys_accept)},
//     [SPRE_SYSCALL_ACCEPT4] = {FILLER_REF(sys_accept4)},
//     [SPRE_SYSCALL_SENDTO] = {FILLER_REF(sys_sendto)},
//     [SPRE_SYSCALL_RECVFROM] = {FILLER_REF(sys_recvfrom)},
//     [SPRE_SYSCALL_SHUTDOWN] = {FILLER_REF(sys_shutdown)},
//     [SPRE_SYSCALL_GETSOCKNAME] = {FILLER_REF(sys_empty)},
//     [SPRE_SYSCALL_GETPEERNAME] = {FILLER_REF(sys_empty)},
//     [SPRE_SYSCALL_SOCKETPAIR] = {FILLER_REF(sys_socketpair)},
//     [SPRE_SYSCALL_SETSOCKOPT] = {FILLER_REF(sys_setsockopt)},
//     [SPRE_SYSCALL_GETSOCKOPT] = {FILLER_REF(sys_getsockopt)},
//     [SPRE_SYSCALL_SENDMSG] = {FILLER_REF(sys_sendmsg)},
//     [SPRE_SYSCALL_SENDMMSG] = {FILLER_REF(sys_empty)},
//     [SPRE_SYSCALL_RECVMSG] = {FILLER_REF(sys_recvmsg)},
//     [SPRE_SYSCALL_RECVMMSG] = {FILLER_REF(sys_empty)},
//     [SPRE_SYSCALL_IOCTL] = {FILLER_REF(sys_ioctl)},
//     [SPRE_SYSCALL_PTRACE] = {FILLER_REF(sys_ptrace)}
// };


const struct nod_event_entry g_nod_events[SPRE_EVENT_MAX] = {
	[SPRE_GENERIC_E] = {FILLER_REF(sys_generic)},
	[SPRE_GENERIC_X] = {FILLER_REF(sys_generic)},
	[SPRE_SYSCALL_OPEN_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_OPEN_X] = {FILLER_REF(sys_open_x)},
	[SPRE_SYSCALL_CLOSE_E] = {FILLER_REF(sys_single)},
	[SPRE_SYSCALL_CLOSE_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_READ_E] = {FILLER_REF(sys_autofill), 2, APT_REG, {{0}, {2} } },
	[SPRE_SYSCALL_READ_X] = {FILLER_REF(sys_read_x)},
	[SPRE_SYSCALL_WRITE_E] = {FILLER_REF(sys_autofill), 2, APT_REG, {{0}, {2} } },
	[SPRE_SYSCALL_WRITE_X] = {FILLER_REF(sys_write_x)},
	[SPRE_PROCEXIT_1_E] = {FILLER_REF(sys_procexit_e)},
	[SPRE_SOCKET_SOCKET_E] = {FILLER_REF(sys_autofill), 3, APT_SOCK, {{0}, {1}, {2} } },
	[SPRE_SOCKET_SOCKET_X] = {FILLER_REF(sys_socket_x)},
	[SPRE_SOCKET_BIND_E] = {FILLER_REF(sys_autofill), 1, APT_SOCK, {{0} } },
	[SPRE_SOCKET_BIND_X] = {FILLER_REF(sys_socket_bind_x)},
	[SPRE_SOCKET_CONNECT_E] = {FILLER_REF(sys_autofill), 1, APT_SOCK, {{0} } },
	[SPRE_SOCKET_CONNECT_X] = {FILLER_REF(sys_connect_x)},
	[SPRE_SOCKET_LISTEN_E] = {FILLER_REF(sys_autofill), 2, APT_SOCK, {{0}, {1} } },
	[SPRE_SOCKET_LISTEN_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SOCKET_SEND_E] = {FILLER_REF(sys_send_e)},
	[SPRE_SOCKET_SEND_X] = {FILLER_REF(sys_send_x)},
	[SPRE_SOCKET_SENDTO_E] = {FILLER_REF(sys_sendto_e)},
	[SPRE_SOCKET_SENDTO_X] = {FILLER_REF(sys_send_x)},
	[SPRE_SOCKET_RECV_E] = {FILLER_REF(sys_autofill), 2, APT_SOCK, {{0}, {2} } },
	[SPRE_SOCKET_RECV_X] = {FILLER_REF(sys_recv_x)},
	[SPRE_SOCKET_RECVFROM_E] = {FILLER_REF(sys_autofill), 2, APT_SOCK, {{0}, {2} } },
	[SPRE_SOCKET_RECVFROM_X] = {FILLER_REF(sys_recvfrom_x)},
#ifndef WDIG
	[SPRE_SOCKET_SHUTDOWN_E] = {FILLER_REF(sys_shutdown_e)},
	[SPRE_SOCKET_SHUTDOWN_X] = {FILLER_REF(sys_single_x)},
#endif
	[SPRE_SOCKET_GETSOCKNAME_E] = {FILLER_REF(sys_empty)},
	[SPRE_SOCKET_GETSOCKNAME_X] = {FILLER_REF(sys_empty)},
	[SPRE_SOCKET_GETPEERNAME_E] = {FILLER_REF(sys_empty)},
	[SPRE_SOCKET_GETPEERNAME_X] = {FILLER_REF(sys_empty)},
	[SPRE_SOCKET_SOCKETPAIR_E] = {FILLER_REF(sys_autofill), 3, APT_SOCK, {{0}, {1}, {2} } },
	[SPRE_SOCKET_SOCKETPAIR_X] = {FILLER_REF(sys_socketpair_x)},
	[SPRE_SOCKET_SETSOCKOPT_E] = {FILLER_REF(sys_empty)},
	[SPRE_SOCKET_SETSOCKOPT_X] = {FILLER_REF(sys_setsockopt_x)},
	[SPRE_SOCKET_GETSOCKOPT_E] = {FILLER_REF(sys_empty)},
	[SPRE_SOCKET_GETSOCKOPT_X] = {FILLER_REF(sys_getsockopt_x)},
#ifndef WDIG
	[SPRE_SOCKET_SENDMSG_E] = {FILLER_REF(sys_sendmsg_e)},
	[SPRE_SOCKET_SENDMSG_X] = {FILLER_REF(sys_sendmsg_x)},
	[SPRE_SOCKET_SENDMMSG_E] = {FILLER_REF(sys_empty)},
	[SPRE_SOCKET_SENDMMSG_X] = {FILLER_REF(sys_empty)},
	[SPRE_SOCKET_RECVMSG_E] = {FILLER_REF(sys_autofill), 1, APT_SOCK, {{0} } },
	[SPRE_SOCKET_RECVMSG_X] = {FILLER_REF(sys_recvmsg_x)},
	[SPRE_SOCKET_RECVMMSG_E] = {FILLER_REF(sys_empty)},
	[SPRE_SOCKET_RECVMMSG_X] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_CREAT_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_CREAT_X] = {FILLER_REF(sys_creat_x)},
	[SPRE_SYSCALL_PIPE_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_PIPE_X] = {FILLER_REF(sys_pipe_x)},
	[SPRE_SYSCALL_EVENTFD_E] = {FILLER_REF(sys_eventfd_e)},
	[SPRE_SYSCALL_EVENTFD_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_FUTEX_E] = {FILLER_REF(sys_futex_e)},
	[SPRE_SYSCALL_FUTEX_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_STAT_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_STAT_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_LSTAT_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_LSTAT_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_FSTAT_E] = {FILLER_REF(sys_single)},
	[SPRE_SYSCALL_FSTAT_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_STAT64_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_STAT64_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_LSTAT64_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_LSTAT64_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_FSTAT64_E] = {FILLER_REF(sys_single)},
	[SPRE_SYSCALL_FSTAT64_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_EPOLLWAIT_E] = {FILLER_REF(sys_autofill), 1, APT_REG, {{2} } },
	[SPRE_SYSCALL_EPOLLWAIT_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_POLL_E] = {FILLER_REF(sys_poll_e)},
	[SPRE_SYSCALL_POLL_X] = {FILLER_REF(sys_poll_x)},
	[SPRE_SYSCALL_SELECT_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_SELECT_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_NEWSELECT_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_NEWSELECT_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_LSEEK_E] = {FILLER_REF(sys_lseek_e)},
	[SPRE_SYSCALL_LSEEK_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_LLSEEK_E] = {FILLER_REF(sys_llseek_e)},
	[SPRE_SYSCALL_LLSEEK_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_GETCWD_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_GETCWD_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_CHDIR_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_CHDIR_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_FCHDIR_E] = {FILLER_REF(sys_single)},
	[SPRE_SYSCALL_FCHDIR_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_UNLINK_E] = {FILLER_REF(sys_single)},
	[SPRE_SYSCALL_UNLINK_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_UNLINKAT_E] = {FILLER_REF(sys_autofill), 2, APT_REG, {{0}, {1} } },
	[SPRE_SYSCALL_UNLINKAT_X] = {FILLER_REF(sys_single_x)},
#ifdef _64BIT_ARGS_SINGLE_REGISTER
	[SPRE_SYSCALL_PREAD_E] = {FILLER_REF(sys_autofill), 3, APT_REG, {{0}, {2}, {3} } },
#else
	[SPRE_SYSCALL_PREAD_E] = {FILLER_REF(sys_pread64_e)},
#endif
	[SPRE_SYSCALL_PREAD_X] = {FILLER_REF(sys_read_x)},
#ifdef _64BIT_ARGS_SINGLE_REGISTER
	[SPRE_SYSCALL_PWRITE_E] = {FILLER_REF(sys_autofill), 3, APT_REG, {{0}, {2}, {3} } },
#else
	[SPRE_SYSCALL_PWRITE_E] = {FILLER_REF(sys_pwrite64_e)},
 #endif
	[SPRE_SYSCALL_PWRITE_X] = {FILLER_REF(sys_write_x)},
	[SPRE_SYSCALL_READV_E] = {FILLER_REF(sys_single)},
	[SPRE_SYSCALL_READV_X] = {FILLER_REF(sys_readv_preadv_x)},
	[SPRE_SYSCALL_WRITEV_E] = {FILLER_REF(sys_writev_e)},
	[SPRE_SYSCALL_WRITEV_X] = {FILLER_REF(sys_writev_pwritev_x)},
#ifdef _64BIT_ARGS_SINGLE_REGISTER
	[SPRE_SYSCALL_PREADV_E] = {FILLER_REF(sys_autofill), 2, APT_REG, {{0}, {3} } },
#else
	[SPRE_SYSCALL_PREADV_E] = {FILLER_REF(sys_preadv64_e)},
#endif
	[SPRE_SYSCALL_PREADV_X] = {FILLER_REF(sys_readv_preadv_x)},
	[SPRE_SYSCALL_PWRITEV_E] = {FILLER_REF(sys_pwritev_e)},
	[SPRE_SYSCALL_PWRITEV_X] = {FILLER_REF(sys_writev_pwritev_x)},
	[SPRE_SYSCALL_DUP_E] = {FILLER_REF(sys_autofill), 1, APT_REG, {{0} } },
	[SPRE_SYSCALL_DUP_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_SIGNALFD_E] = {FILLER_REF(sys_autofill), 3, APT_REG, {{0}, {AF_ID_USEDEFAULT, 0}, {AF_ID_USEDEFAULT, 0} } },
	[SPRE_SYSCALL_SIGNALFD_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_KILL_E] = {FILLER_REF(sys_autofill), 2, APT_REG, {{0}, {1} } },
	[SPRE_SYSCALL_KILL_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_TKILL_E] = {FILLER_REF(sys_autofill), 2, APT_REG, {{0}, {1} } },
	[SPRE_SYSCALL_TKILL_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_TGKILL_E] = {FILLER_REF(sys_autofill), 3, APT_REG, {{0}, {1}, {2} } },
	[SPRE_SYSCALL_TGKILL_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_NANOSLEEP_E] = {FILLER_REF(sys_nanosleep_e)},
	[SPRE_SYSCALL_NANOSLEEP_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_TIMERFD_CREATE_E] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_USEDEFAULT, 0}, {AF_ID_USEDEFAULT, 0} } },
	[SPRE_SYSCALL_TIMERFD_CREATE_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_INOTIFY_INIT_E] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_USEDEFAULT, 0} } },
	[SPRE_SYSCALL_INOTIFY_INIT_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_GETRLIMIT_E] = {FILLER_REF(sys_getrlimit_setrlimit_e)},
	[SPRE_SYSCALL_GETRLIMIT_X] = {FILLER_REF(sys_getrlimit_setrlrimit_x)},
	[SPRE_SYSCALL_SETRLIMIT_E] = {FILLER_REF(sys_getrlimit_setrlimit_e)},
	[SPRE_SYSCALL_SETRLIMIT_X] = {FILLER_REF(sys_getrlimit_setrlrimit_x)},
	[SPRE_SYSCALL_PRLIMIT_E] = {FILLER_REF(sys_prlimit_e)},
	[SPRE_SYSCALL_PRLIMIT_X] = {FILLER_REF(sys_prlimit_x)},
	[SPRE_DROP_E] = {FILLER_REF(sched_drop)},
	[SPRE_DROP_X] = {FILLER_REF(sched_drop)},
	[SPRE_SYSCALL_FCNTL_E] = {FILLER_REF(sys_fcntl_e)},
	[SPRE_SYSCALL_FCNTL_X] = {FILLER_REF(sys_single_x)},
#ifdef CAPTURE_CONTEXT_SWITCHES
	[SPRE_SCHEDSWITCH_6_E] = {FILLER_REF(sched_switch_e)},
#endif
	[SPRE_SYSCALL_BRK_4_E] = {FILLER_REF(sys_autofill), 1, APT_REG, {{0} } },
	[SPRE_SYSCALL_BRK_4_X] = {FILLER_REF(sys_brk_munmap_mmap_x)},
	[SPRE_SYSCALL_MMAP_E] = {FILLER_REF(sys_mmap_e)},
	[SPRE_SYSCALL_MMAP_X] = {FILLER_REF(sys_brk_munmap_mmap_x)},
	[SPRE_SYSCALL_MMAP2_E] = {FILLER_REF(sys_mmap_e)},
	[SPRE_SYSCALL_MMAP2_X] = {FILLER_REF(sys_brk_munmap_mmap_x)},
	[SPRE_SYSCALL_MUNMAP_E] = {FILLER_REF(sys_autofill), 2, APT_REG, {{0}, {1} } },
	[SPRE_SYSCALL_MUNMAP_X] = {FILLER_REF(sys_brk_munmap_mmap_x)},
	[SPRE_SYSCALL_SPLICE_E] = {FILLER_REF(sys_autofill), 4, APT_REG, {{0}, {2}, {4}, {5} } },
	[SPRE_SYSCALL_SPLICE_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSCALL_PTRACE_E] = {FILLER_REF(sys_ptrace_e)},
	[SPRE_SYSCALL_PTRACE_X] = {FILLER_REF(sys_ptrace_x)},
	[SPRE_SYSCALL_IOCTL_3_E] = {FILLER_REF(sys_autofill), 3, APT_REG, {{0}, {1}, {2} } },
	[SPRE_SYSCALL_IOCTL_3_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_RENAME_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_RENAME_X] = {FILLER_REF(sys_autofill), 3, APT_REG, {{AF_ID_RETVAL}, {0}, {1} } },
	[SPRE_SYSCALL_RENAMEAT_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_RENAMEAT_X] = {FILLER_REF(sys_renameat_x)},
	[SPRE_SYSCALL_SYMLINK_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_SYMLINK_X] = {FILLER_REF(sys_autofill), 3, APT_REG, {{AF_ID_RETVAL}, {0}, {1} } },
	[SPRE_SYSCALL_SYMLINKAT_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_SYMLINKAT_X] = {FILLER_REF(sys_symlinkat_x)},
	[SPRE_SYSCALL_SENDFILE_E] = {FILLER_REF(sys_sendfile_e)},
	[SPRE_SYSCALL_SENDFILE_X] = {FILLER_REF(sys_sendfile_x)},
	[SPRE_SYSCALL_QUOTACTL_E] = {FILLER_REF(sys_quotactl_e)},
	[SPRE_SYSCALL_QUOTACTL_X] = {FILLER_REF(sys_quotactl_x)},
	[SPRE_SYSCALL_SETRESUID_E] = {FILLER_REF(sys_autofill), 3, APT_REG, {{0}, {1}, {2} } },
	[SPRE_SYSCALL_SETRESUID_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSCALL_SETRESGID_E] = {FILLER_REF(sys_autofill), 3, APT_REG, {{0}, {1}, {2} } },
	[SPRE_SYSCALL_SETRESGID_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSDIGEVENT_E] = {FILLER_REF(sys_sysdigevent_e)},
	[SPRE_SYSCALL_SETUID_E] = {FILLER_REF(sys_autofill), 1, APT_REG, {{0} } },
	[SPRE_SYSCALL_SETUID_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSCALL_SETGID_E] = {FILLER_REF(sys_autofill), 1, APT_REG, {{0} } },
	[SPRE_SYSCALL_SETGID_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSCALL_GETUID_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_GETUID_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSCALL_GETEUID_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_GETEUID_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSCALL_GETGID_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_GETGID_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSCALL_GETEGID_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_GETEGID_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSCALL_GETRESUID_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_GETRESUID_X] = {FILLER_REF(sys_getresuid_and_gid_x)},
	[SPRE_SYSCALL_GETRESGID_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_GETRESGID_X] = {FILLER_REF(sys_getresuid_and_gid_x)},
#endif /* WDIG */
	[SPRE_SYSCALL_CLONE_20_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_CLONE_20_X] = {FILLER_REF(proc_startupdate)},
#ifndef WDIG
	[SPRE_SYSCALL_FORK_20_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_FORK_20_X] = {FILLER_REF(proc_startupdate)},
	[SPRE_SYSCALL_VFORK_20_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_VFORK_20_X] = {FILLER_REF(proc_startupdate)},
#ifdef CAPTURE_SIGNAL_DELIVERIES
	[SPRE_SIGNALDELIVER_E] = {FILLER_REF(sys_signaldeliver_e)},
	[SPRE_SIGNALDELIVER_X] = {FILLER_REF(sys_empty)},
#endif
	[SPRE_SYSCALL_GETDENTS_E] = {FILLER_REF(sys_single)},
	[SPRE_SYSCALL_GETDENTS_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_GETDENTS64_E] = {FILLER_REF(sys_single)},
	[SPRE_SYSCALL_GETDENTS64_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_SETNS_E] = {FILLER_REF(sys_setns_e)},
	[SPRE_SYSCALL_SETNS_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSCALL_FLOCK_E] = {FILLER_REF(sys_flock_e)},
	[SPRE_SYSCALL_FLOCK_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_CPU_HOTPLUG_E] = {FILLER_REF(cpu_hotplug_e)},
#endif /* WDIG */
	[SPRE_SOCKET_ACCEPT_5_E] = {FILLER_REF(sys_empty)},
	[SPRE_SOCKET_ACCEPT_5_X] = {FILLER_REF(sys_accept_x)},
#ifndef WDIG
	[SPRE_SOCKET_ACCEPT4_5_E] = {FILLER_REF(sys_accept4_e)},
	[SPRE_SOCKET_ACCEPT4_5_X] = {FILLER_REF(sys_accept_x)},
	[SPRE_SYSCALL_SEMOP_E] = {FILLER_REF(sys_single)},
	[SPRE_SYSCALL_SEMOP_X] = {FILLER_REF(sys_semop_x)},
	[SPRE_SYSCALL_SEMCTL_E] = {FILLER_REF(sys_semctl_e)},
	[SPRE_SYSCALL_SEMCTL_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_PPOLL_E] = {FILLER_REF(sys_ppoll_e)},
	[SPRE_SYSCALL_PPOLL_X] = {FILLER_REF(sys_poll_x)}, /* exit same for poll() and ppoll() */
	[SPRE_SYSCALL_MOUNT_E] = {FILLER_REF(sys_mount_e)},
	[SPRE_SYSCALL_MOUNT_X] = {FILLER_REF(sys_autofill), 4, APT_REG, {{AF_ID_RETVAL}, {0}, {1}, {2} } },
	[SPRE_SYSCALL_UMOUNT_E] = {FILLER_REF(sys_autofill), 1, APT_REG, {{1} } },
	[SPRE_SYSCALL_UMOUNT_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_SEMGET_E] = {FILLER_REF(sys_semget_e)},
	[SPRE_SYSCALL_SEMGET_X] = {FILLER_REF(sys_single_x)},
	[SPRE_SYSCALL_ACCESS_E] = {FILLER_REF(sys_access_e)},
	[SPRE_SYSCALL_ACCESS_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_CHROOT_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_CHROOT_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_SETSID_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_SETSID_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSCALL_SETPGID_E] = {FILLER_REF(sys_autofill), 2, APT_REG, {{0}, {1} } },
	[SPRE_SYSCALL_SETPGID_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSCALL_MKDIR_2_E] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_USEDEFAULT, 0} } },
	[SPRE_SYSCALL_MKDIR_2_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_RMDIR_2_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_RMDIR_2_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_UNSHARE_E] = {FILLER_REF(sys_unshare_e)},
	[SPRE_SYSCALL_UNSHARE_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
#endif /* WDIG */
	[SPRE_SYSCALL_EXECVE_19_E] = {FILLER_REF(sys_execve_e)},
	[SPRE_SYSCALL_EXECVE_19_X] = {FILLER_REF(proc_startupdate)},
#ifndef WDIG
#ifdef CAPTURE_PAGE_FAULTS
	[SPRE_PAGE_FAULT_E] = {FILLER_REF(sys_pagefault_e)},
	[SPRE_PAGE_FAULT_X] = {FILLER_REF(sys_empty)},
#endif
	[SPRE_SYSCALL_BPF_E] = {FILLER_REF(sys_autofill), 1, APT_REG, {{0} } },
	[SPRE_SYSCALL_BPF_X] = {FILLER_REF(sys_bpf_x)},
	[SPRE_SYSCALL_SECCOMP_E] = {FILLER_REF(sys_autofill), 1, APT_REG, {{0}, {1} } },
	[SPRE_SYSCALL_SECCOMP_X] = {FILLER_REF(sys_autofill), 1, APT_REG, {{AF_ID_RETVAL} } },
	[SPRE_SYSCALL_UNLINK_2_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_UNLINK_2_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_UNLINKAT_2_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_UNLINKAT_2_X] = {FILLER_REF(sys_unlinkat_x)},
	[SPRE_SYSCALL_MKDIRAT_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_MKDIRAT_X] = {FILLER_REF(sys_mkdirat_x)},
	[SPRE_SYSCALL_OPENAT_2_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_OPENAT_2_X] = {FILLER_REF(sys_openat_x)},
	[SPRE_SYSCALL_LINK_2_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_LINK_2_X] = {FILLER_REF(sys_autofill), 3, APT_REG, {{AF_ID_RETVAL}, {0}, {1} } },
	[SPRE_SYSCALL_LINKAT_2_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_LINKAT_2_X] = {FILLER_REF(sys_linkat_x)},
	[SPRE_SYSCALL_FCHMODAT_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_FCHMODAT_X] = {FILLER_REF(sys_fchmodat_x)},
	[SPRE_SYSCALL_CHMOD_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_CHMOD_X] = {FILLER_REF(sys_chmod_x)},
	[SPRE_SYSCALL_FCHMOD_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_FCHMOD_X] = {FILLER_REF(sys_fchmod_x)},
	[SPRE_SYSCALL_RENAMEAT2_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_RENAMEAT2_X] = {FILLER_REF(sys_renameat2_x)},
	[SPRE_SYSCALL_USERFAULTFD_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_USERFAULTFD_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[SPRE_SYSCALL_OPENAT2_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_OPENAT2_X] = {FILLER_REF(sys_openat2_x)},
	[SPRE_SYSCALL_MPROTECT_E] = {FILLER_REF(sys_mprotect_e)},
	[SPRE_SYSCALL_MPROTECT_X] = {FILLER_REF(sys_mprotect_x)}, 
	[SPRE_SYSCALL_EXECVEAT_E] = {FILLER_REF(sys_execveat_e)},
	[SPRE_SYSCALL_EXECVEAT_X] = {FILLER_REF(proc_startupdate)},
	[SPRE_SYSCALL_COPY_FILE_RANGE_E] = {FILLER_REF(sys_copy_file_range_e)},
	[SPRE_SYSCALL_COPY_FILE_RANGE_X] = {FILLER_REF(sys_copy_file_range_x)},
	[SPRE_SYSCALL_CLONE3_E] = {FILLER_REF(sys_empty)},
	[SPRE_SYSCALL_CLONE3_X] = {FILLER_REF(proc_startupdate)},
#endif /* WDIG */
};


