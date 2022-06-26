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
// const enum nod_event_type g_syscall_event_table[SYSCALL_TABLE_SIZE] = {
// 	[__NR_read - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_READ,
// 	[__NR_write - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_WRITE,
//     [__NR_open - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_OPEN,
// 	[__NR_close - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_CLOSE,
//     [__NR_exit - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_EXIT,
//     [__NR_exit_group - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_EXIT_GROUP,
//     [__NR_execve - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_EXECVE,
//     [__NR_clone - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_CLONE,
//     [__NR_fork - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_FORK,
//     [__NR_vfork - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_VFORK,
//     [__NR_socket - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SOCKET,
//     [__NR_bind - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_BIND,
//     [__NR_connect - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_CONNECT,
//     [__NR_listen - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_LISTEN,
//     [__NR_accept - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_ACCEPT,
//     [__NR_getsockname - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_GETSOCKNAME,
//     [__NR_getpeername - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_GETPEERNAME,
//     [__NR_socketpair - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SOCKETPAIR,
//     [__NR_sendto - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SENDTO,
//     [__NR_recvfrom - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_RECVFROM,
//     [__NR_shutdown - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SHUTDOWN,
//     [__NR_setsockopt - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SETSOCKOPT,
//     [__NR_getsockopt - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_GETSOCKOPT,
//     [__NR_accept4 - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_ACCEPT4,
//     [__NR_sendmsg - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SENDMSG,
//     [__NR_sendmmsg - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SENDMMSG,
//     [__NR_recvmsg - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_RECVMSG,
//     [__NR_recvmmsg - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_RECVMMSG,
//     [__NR_ptrace - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_PTRACE,
// };

const struct syscall_evt_pair g_syscall_event_table[SYSCALL_TABLE_SIZE] = {
#ifdef __NR_open
	[__NR_open - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_OPEN_E, SPRE_SYSCALL_OPEN_X},
#endif
#ifdef __NR_creat
	[__NR_creat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_CREAT_E, SPRE_SYSCALL_CREAT_X},
#endif
	[__NR_close - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SYSCALL_CLOSE_E, SPRE_SYSCALL_CLOSE_X},
	[__NR_brk - SYSCALL_TABLE_ID0] =                        {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_BRK_4_E, SPRE_SYSCALL_BRK_4_X},
	[__NR_read - SYSCALL_TABLE_ID0] =                       {UF_USED, SPRE_SYSCALL_READ_E, SPRE_SYSCALL_READ_X},
	[__NR_write - SYSCALL_TABLE_ID0] =                      {UF_USED, SPRE_SYSCALL_WRITE_E, SPRE_SYSCALL_WRITE_X},
	[__NR_execve - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SYSCALL_EXECVE_19_E, SPRE_SYSCALL_EXECVE_19_X},
	[__NR_clone - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SYSCALL_CLONE_20_E, SPRE_SYSCALL_CLONE_20_X},
#ifdef __NR_fork
	[__NR_fork - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SYSCALL_FORK_20_E, SPRE_SYSCALL_FORK_20_X},
#endif
#ifdef __NR_vfork
	[__NR_vfork - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SYSCALL_VFORK_20_E, SPRE_SYSCALL_VFORK_20_X},
#endif
#ifdef __NR_pipe
	[__NR_pipe - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_PIPE_E, SPRE_SYSCALL_PIPE_X},
#endif
	[__NR_pipe2 - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_PIPE_E, SPRE_SYSCALL_PIPE_X},
#ifdef __NR_eventfd
	[__NR_eventfd - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_EVENTFD_E, SPRE_SYSCALL_EVENTFD_X},
#endif
	[__NR_eventfd2 - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_EVENTFD_E, SPRE_SYSCALL_EVENTFD_X},
	[__NR_futex - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_FUTEX_E, SPRE_SYSCALL_FUTEX_X},
#ifdef __NR_stat
	[__NR_stat - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_STAT_E, SPRE_SYSCALL_STAT_X},
#endif
#ifdef __NR_lstat
	[__NR_lstat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_LSTAT_E, SPRE_SYSCALL_LSTAT_X},
#endif
	[__NR_fstat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_FSTAT_E, SPRE_SYSCALL_FSTAT_X},
#ifdef __NR_epoll_wait
	[__NR_epoll_wait - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_EPOLLWAIT_E, SPRE_SYSCALL_EPOLLWAIT_X},
#endif
#ifdef __NR_poll
	[__NR_poll - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_POLL_E, SPRE_SYSCALL_POLL_X},
#endif
#ifdef __NR_select
	[__NR_select - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_SELECT_E, SPRE_SYSCALL_SELECT_X},
#endif
	[__NR_lseek - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_LSEEK_E, SPRE_SYSCALL_LSEEK_X},
	[__NR_ioctl - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_IOCTL_3_E, SPRE_SYSCALL_IOCTL_3_X},
	[__NR_getcwd - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_GETCWD_E, SPRE_SYSCALL_GETCWD_X},
	[__NR_chdir - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SYSCALL_CHDIR_E, SPRE_SYSCALL_CHDIR_X},
	[__NR_fchdir - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SYSCALL_FCHDIR_E, SPRE_SYSCALL_FCHDIR_X},
#ifdef __NR_mkdir
	[__NR_mkdir - SYSCALL_TABLE_ID0] =                      {UF_USED, SPRE_SYSCALL_MKDIR_2_E, SPRE_SYSCALL_MKDIR_2_X},
#endif
#ifdef __NR_rmdir
	[__NR_rmdir - SYSCALL_TABLE_ID0] =                      {UF_USED, SPRE_SYSCALL_RMDIR_2_E, SPRE_SYSCALL_RMDIR_2_X},
#endif
	[__NR_openat - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_OPENAT_2_E, SPRE_SYSCALL_OPENAT_2_X},
	[__NR_mkdirat - SYSCALL_TABLE_ID0] =                    {UF_USED, SPRE_SYSCALL_MKDIRAT_E, SPRE_SYSCALL_MKDIRAT_X},
#ifdef __NR_link
	[__NR_link - SYSCALL_TABLE_ID0] =                       {UF_USED, SPRE_SYSCALL_LINK_2_E, SPRE_SYSCALL_LINK_2_X},
#endif
	[__NR_linkat - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_LINKAT_2_E, SPRE_SYSCALL_LINKAT_2_X},
#ifdef __NR_unlink
	[__NR_unlink - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_UNLINK_2_E, SPRE_SYSCALL_UNLINK_2_X},
#endif
	[__NR_unlinkat - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SYSCALL_UNLINKAT_2_E, SPRE_SYSCALL_UNLINKAT_2_X},
	[__NR_pread64 - SYSCALL_TABLE_ID0] =                    {UF_USED, SPRE_SYSCALL_PREAD_E, SPRE_SYSCALL_PREAD_X},
	[__NR_pwrite64 - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SYSCALL_PWRITE_E, SPRE_SYSCALL_PWRITE_X},
	[__NR_readv - SYSCALL_TABLE_ID0] =                      {UF_USED, SPRE_SYSCALL_READV_E, SPRE_SYSCALL_READV_X},
	[__NR_writev - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_WRITEV_E, SPRE_SYSCALL_WRITEV_X},
	[__NR_preadv - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_PREADV_E, SPRE_SYSCALL_PREADV_X},
	[__NR_pwritev - SYSCALL_TABLE_ID0] =                    {UF_USED, SPRE_SYSCALL_PWRITEV_E, SPRE_SYSCALL_PWRITEV_X},
	[__NR_dup - SYSCALL_TABLE_ID0] =                        {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SYSCALL_DUP_E, SPRE_SYSCALL_DUP_X},
#ifdef __NR_dup2
	[__NR_dup2 - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SYSCALL_DUP_E, SPRE_SYSCALL_DUP_X},
#endif
	[__NR_dup3 - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SYSCALL_DUP_E, SPRE_SYSCALL_DUP_X},
#ifdef __NR_signalfd
	[__NR_signalfd - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_SIGNALFD_E, SPRE_SYSCALL_SIGNALFD_X},
#endif
	[__NR_signalfd4 - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_SIGNALFD_E, SPRE_SYSCALL_SIGNALFD_X},
	[__NR_kill - SYSCALL_TABLE_ID0] =                       {UF_USED, SPRE_SYSCALL_KILL_E, SPRE_SYSCALL_KILL_X},
	[__NR_tkill - SYSCALL_TABLE_ID0] =                      {UF_USED, SPRE_SYSCALL_TKILL_E, SPRE_SYSCALL_TKILL_X},
	[__NR_tgkill - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_TGKILL_E, SPRE_SYSCALL_TGKILL_X},
	[__NR_nanosleep - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_NANOSLEEP_E, SPRE_SYSCALL_NANOSLEEP_X},
	[__NR_timerfd_create - SYSCALL_TABLE_ID0] =             {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_TIMERFD_CREATE_E, SPRE_SYSCALL_TIMERFD_CREATE_X},
#ifdef __NR_inotify_init
	[__NR_inotify_init - SYSCALL_TABLE_ID0] =               {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_INOTIFY_INIT_E, SPRE_SYSCALL_INOTIFY_INIT_X},
#endif
	[__NR_inotify_init1 - SYSCALL_TABLE_ID0] =              {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_INOTIFY_INIT_E, SPRE_SYSCALL_INOTIFY_INIT_X},
	[__NR_fchmodat - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SYSCALL_FCHMODAT_E, SPRE_SYSCALL_FCHMODAT_X},
	[__NR_fchmod - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_FCHMOD_E, SPRE_SYSCALL_FCHMOD_X},
#ifdef __NR_getrlimit
	[__NR_getrlimit - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_GETRLIMIT_E, SPRE_SYSCALL_GETRLIMIT_X},
#endif
	[__NR_setrlimit - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_SETRLIMIT_E, SPRE_SYSCALL_SETRLIMIT_X},
#ifdef __NR_prlimit64
	[__NR_prlimit64 - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_PRLIMIT_E, SPRE_SYSCALL_PRLIMIT_X},
#endif
#ifdef __NR_ugetrlimit
	[__NR_ugetrlimit - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_GETRLIMIT_E, SPRE_SYSCALL_GETRLIMIT_X},
#endif
	[__NR_fcntl - SYSCALL_TABLE_ID0] =                      {UF_USED, SPRE_SYSCALL_FCNTL_E, SPRE_SYSCALL_FCNTL_X},
#ifdef __NR_fcntl64
	[__NR_fcntl64 - SYSCALL_TABLE_ID0] =                    {UF_USED, SPRE_SYSCALL_FCNTL_E, SPRE_SYSCALL_FCNTL_X},
#endif
/* [__NR_old_select - SYSCALL_TABLE_ID0] =	{UF_USED, SPRE_GENERIC_E, SPRE_GENERIC_X}, */
	[__NR_pselect6 - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_ALWAYS_DROP, SPRE_GENERIC_E, SPRE_GENERIC_X},
#ifdef __NR_epoll_create
	[__NR_epoll_create - SYSCALL_TABLE_ID0] =               {UF_USED | UF_ALWAYS_DROP, SPRE_GENERIC_E, SPRE_GENERIC_X},
#endif
	[__NR_epoll_ctl - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_ALWAYS_DROP, SPRE_GENERIC_E, SPRE_GENERIC_X},
#ifdef __NR_uselib
	[__NR_uselib - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, SPRE_GENERIC_E, SPRE_GENERIC_X},
#endif
	[__NR_sched_setparam - SYSCALL_TABLE_ID0] =             {UF_USED | UF_ALWAYS_DROP, SPRE_GENERIC_E, SPRE_GENERIC_X},
	[__NR_sched_getparam - SYSCALL_TABLE_ID0] =             {UF_USED | UF_ALWAYS_DROP, SPRE_GENERIC_E, SPRE_GENERIC_X},
	[__NR_syslog - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, SPRE_GENERIC_E, SPRE_GENERIC_X},
#ifdef __NR_chmod
	[__NR_chmod - SYSCALL_TABLE_ID0] =                      {UF_USED, SPRE_SYSCALL_CHMOD_E, SPRE_SYSCALL_CHMOD_X},
#endif
#ifdef __NR_lchown
	[__NR_lchown - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_GENERIC_E, SPRE_GENERIC_X},
#endif
#ifdef __NR_utime
	[__NR_utime - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, SPRE_GENERIC_E, SPRE_GENERIC_X},
#endif
	[__NR_mount - SYSCALL_TABLE_ID0] =                      {UF_USED, SPRE_SYSCALL_MOUNT_E, SPRE_SYSCALL_MOUNT_X},
	[__NR_umount2 - SYSCALL_TABLE_ID0] =                    {UF_USED, SPRE_SYSCALL_UMOUNT_E, SPRE_SYSCALL_UMOUNT_X},
	[__NR_ptrace - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_PTRACE_E, SPRE_SYSCALL_PTRACE_X},
#ifdef __NR_alarm
	[__NR_alarm - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, SPRE_GENERIC_E, SPRE_GENERIC_X},
#endif
#ifdef __NR_pause
	[__NR_pause - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, SPRE_GENERIC_E, SPRE_GENERIC_X},
#endif

#ifndef __NR_socketcall
	[__NR_socket - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SOCKET_SOCKET_E, SPRE_SOCKET_SOCKET_X},
	[__NR_bind - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, SPRE_SOCKET_BIND_E,  SPRE_SOCKET_BIND_X},
	[__NR_connect - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_SIMPLEDRIVER_KEEP, SPRE_SOCKET_CONNECT_E, SPRE_SOCKET_CONNECT_X},
	[__NR_listen - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SOCKET_LISTEN_E, SPRE_SOCKET_LISTEN_X},
	[__NR_accept - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_SIMPLEDRIVER_KEEP, SPRE_SOCKET_ACCEPT_5_E, SPRE_SOCKET_ACCEPT_5_X},
	[__NR_getsockname - SYSCALL_TABLE_ID0] =                {UF_USED | UF_ALWAYS_DROP, SPRE_SOCKET_GETSOCKNAME_E, SPRE_SOCKET_GETSOCKNAME_X},
	[__NR_getpeername - SYSCALL_TABLE_ID0] =                {UF_USED | UF_ALWAYS_DROP, SPRE_SOCKET_GETPEERNAME_E, SPRE_SOCKET_GETPEERNAME_X},
	[__NR_socketpair - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_NEVER_DROP, SPRE_SOCKET_SOCKETPAIR_E, SPRE_SOCKET_SOCKETPAIR_X},
	[__NR_sendto - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SOCKET_SENDTO_E, SPRE_SOCKET_SENDTO_X},
	[__NR_recvfrom - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SOCKET_RECVFROM_E, SPRE_SOCKET_RECVFROM_X},
	[__NR_shutdown - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SOCKET_SHUTDOWN_E, SPRE_SOCKET_SHUTDOWN_X},
	[__NR_setsockopt - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, SPRE_SOCKET_SETSOCKOPT_E, SPRE_SOCKET_SETSOCKOPT_X},
	[__NR_getsockopt - SYSCALL_TABLE_ID0] =                 {UF_USED, SPRE_SOCKET_GETSOCKOPT_E, SPRE_SOCKET_GETSOCKOPT_X},
	[__NR_sendmsg - SYSCALL_TABLE_ID0] =                    {UF_USED, SPRE_SOCKET_SENDMSG_E, SPRE_SOCKET_SENDMSG_X},
	[__NR_accept4 - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_SIMPLEDRIVER_KEEP, SPRE_SOCKET_ACCEPT4_5_E, SPRE_SOCKET_ACCEPT4_5_X},
#endif

#ifdef __NR_sendmmsg
	[__NR_sendmmsg - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SOCKET_SENDMMSG_E, SPRE_SOCKET_SENDMMSG_X},
#endif
#ifdef __NR_recvmsg
	[__NR_recvmsg - SYSCALL_TABLE_ID0] =                    {UF_USED, SPRE_SOCKET_RECVMSG_E, SPRE_SOCKET_RECVMSG_X},
#endif
#ifdef __NR_recvmmsg
	[__NR_recvmmsg - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SOCKET_RECVMMSG_E, SPRE_SOCKET_RECVMMSG_X},
#endif
#ifdef __NR_stat64
	[__NR_stat64 - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_STAT64_E, SPRE_SYSCALL_STAT64_X},
#endif
#ifdef __NR_fstat64
	[__NR_fstat64 - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_FSTAT64_E, SPRE_SYSCALL_FSTAT64_X},
#endif
#ifdef __NR__llseek
	[__NR__llseek - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_LLSEEK_E, SPRE_SYSCALL_LLSEEK_X},
#endif
#ifdef __NR_mmap
	[__NR_mmap - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_MMAP_E, SPRE_SYSCALL_MMAP_X},
#endif
#ifdef __NR_mmap2
	[__NR_mmap2 - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_MMAP2_E, SPRE_SYSCALL_MMAP2_X},
#endif
	[__NR_munmap - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_MUNMAP_E, SPRE_SYSCALL_MUNMAP_X},
	[__NR_splice - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_SPLICE_E, SPRE_SYSCALL_SPLICE_X},
#ifdef __NR_process_vm_readv
	[__NR_process_vm_readv - SYSCALL_TABLE_ID0] =           {UF_USED, SPRE_GENERIC_E, SPRE_GENERIC_X},
#endif
#ifdef __NR_process_vm_writev
	[__NR_process_vm_writev - SYSCALL_TABLE_ID0] =          {UF_USED, SPRE_GENERIC_E, SPRE_GENERIC_X},
#endif

#ifdef __NR_rename
	[__NR_rename - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_RENAME_E, SPRE_SYSCALL_RENAME_X},
#endif
	[__NR_renameat - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SYSCALL_RENAMEAT_E, SPRE_SYSCALL_RENAMEAT_X},
#ifdef __NR_symlink
	[__NR_symlink - SYSCALL_TABLE_ID0] =                    {UF_USED, SPRE_SYSCALL_SYMLINK_E, SPRE_SYSCALL_SYMLINK_X},
#endif
	[__NR_symlinkat - SYSCALL_TABLE_ID0] =                  {UF_USED, SPRE_SYSCALL_SYMLINKAT_E, SPRE_SYSCALL_SYMLINKAT_X},
	[__NR_sendfile - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SYSCALL_SENDFILE_E, SPRE_SYSCALL_SENDFILE_X},
#ifdef __NR_sendfile64
	[__NR_sendfile64 - SYSCALL_TABLE_ID0] =                 {UF_USED, SPRE_SYSCALL_SENDFILE_E, SPRE_SYSCALL_SENDFILE_X},
#endif
#ifdef __NR_quotactl
	[__NR_quotactl - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SYSCALL_QUOTACTL_E, SPRE_SYSCALL_QUOTACTL_X},
#endif
#ifdef __NR_setresuid
	[__NR_setresuid - SYSCALL_TABLE_ID0] =                  {UF_USED, SPRE_SYSCALL_SETRESUID_E, SPRE_SYSCALL_SETRESUID_X },
#endif
#ifdef __NR_setresuid32
	[__NR_setresuid32 - SYSCALL_TABLE_ID0] =                {UF_USED, SPRE_SYSCALL_SETRESUID_E, SPRE_SYSCALL_SETRESUID_X },
#endif
#ifdef __NR_setresgid
	[__NR_setresgid - SYSCALL_TABLE_ID0] =                  {UF_USED, SPRE_SYSCALL_SETRESGID_E, SPRE_SYSCALL_SETRESGID_X },
#endif
#ifdef __NR_setresgid32
	[__NR_setresgid32 - SYSCALL_TABLE_ID0] =                {UF_USED, SPRE_SYSCALL_SETRESGID_E, SPRE_SYSCALL_SETRESGID_X },
#endif
#ifdef __NR_setuid
	[__NR_setuid - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_SETUID_E, SPRE_SYSCALL_SETUID_X },
#endif
#ifdef __NR_setuid32
	[__NR_setuid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SYSCALL_SETUID_E, SPRE_SYSCALL_SETUID_X },
#endif
#ifdef __NR_setgid
	[__NR_setgid - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_SETGID_E, SPRE_SYSCALL_SETGID_X },
#endif
#ifdef __NR_setgid32
	[__NR_setgid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SYSCALL_SETGID_E, SPRE_SYSCALL_SETGID_X },
#endif
#ifdef __NR_getuid
	[__NR_getuid - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_GETUID_E, SPRE_SYSCALL_GETUID_X },
#endif
#ifdef __NR_getuid32
	[__NR_getuid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SYSCALL_GETUID_E, SPRE_SYSCALL_GETUID_X },
#endif
#ifdef __NR_geteuid
	[__NR_geteuid - SYSCALL_TABLE_ID0] =                    {UF_USED, SPRE_SYSCALL_GETEUID_E, SPRE_SYSCALL_GETEUID_X },
#endif
#ifdef __NR_geteuid32
	[__NR_geteuid32 - SYSCALL_TABLE_ID0] =                  {UF_USED, SPRE_SYSCALL_GETEUID_E, SPRE_SYSCALL_GETEUID_X },
#endif
#ifdef __NR_getgid
	[__NR_getgid - SYSCALL_TABLE_ID0] =                     {UF_USED, SPRE_SYSCALL_GETGID_E, SPRE_SYSCALL_GETGID_X },
#endif
#ifdef __NR_getgid32
	[__NR_getgid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SYSCALL_GETGID_E, SPRE_SYSCALL_GETGID_X },
#endif
#ifdef __NR_getegid
	[__NR_getegid - SYSCALL_TABLE_ID0] =                    {UF_USED, SPRE_SYSCALL_GETEGID_E, SPRE_SYSCALL_GETEGID_X },
#endif
#ifdef __NR_getegid32
	[__NR_getegid32 - SYSCALL_TABLE_ID0] =                  {UF_USED, SPRE_SYSCALL_GETEGID_E, SPRE_SYSCALL_GETEGID_X },
#endif
#ifdef __NR_getresuid
	[__NR_getresuid - SYSCALL_TABLE_ID0] =                  {UF_USED, SPRE_SYSCALL_GETRESUID_E, SPRE_SYSCALL_GETRESUID_X },
#endif
#ifdef __NR_getresuid32
	[__NR_getresuid32 - SYSCALL_TABLE_ID0] =                {UF_USED, SPRE_SYSCALL_GETRESUID_E, SPRE_SYSCALL_GETRESUID_X },
#endif
#ifdef __NR_getresgid
	[__NR_getresgid - SYSCALL_TABLE_ID0] =                  {UF_USED, SPRE_SYSCALL_GETRESGID_E, SPRE_SYSCALL_GETRESGID_X },
#endif
#ifdef __NR_getresgid32
	[__NR_getresgid32 - SYSCALL_TABLE_ID0] =                {UF_USED, SPRE_SYSCALL_GETRESGID_E, SPRE_SYSCALL_GETRESGID_X },
#endif
#ifdef __NR_getdents
	[__NR_getdents - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_GETDENTS_E, SPRE_SYSCALL_GETDENTS_X},
#endif
	[__NR_getdents64 - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_GETDENTS64_E, SPRE_SYSCALL_GETDENTS64_X},
#ifdef __NR_setns
	[__NR_setns - SYSCALL_TABLE_ID0] =                      {UF_USED, SPRE_SYSCALL_SETNS_E, SPRE_SYSCALL_SETNS_X},
#endif
#ifdef __NR_unshare
	[__NR_unshare - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_UNSHARE_E, SPRE_SYSCALL_UNSHARE_X},
#endif
	[__NR_flock - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_FLOCK_E, SPRE_SYSCALL_FLOCK_X},
#ifdef __NR_semop
	[__NR_semop - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_SEMOP_E, SPRE_SYSCALL_SEMOP_X},
#endif
#ifdef __NR_semget
	[__NR_semget - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_SEMGET_E, SPRE_SYSCALL_SEMGET_X},
#endif
#ifdef __NR_semctl
	[__NR_semctl - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_SEMCTL_E, SPRE_SYSCALL_SEMCTL_X},
#endif
	[__NR_ppoll - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_PPOLL_E, SPRE_SYSCALL_PPOLL_X},
#ifdef __NR_access
	[__NR_access - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_ACCESS_E, SPRE_SYSCALL_ACCESS_X},
#endif
#ifdef __NR_chroot
	[__NR_chroot - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_CHROOT_E, SPRE_SYSCALL_CHROOT_X},
#endif
	[__NR_setsid - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_SETSID_E, SPRE_SYSCALL_SETSID_X},
	[__NR_setpgid - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, SPRE_SYSCALL_SETPGID_E, SPRE_SYSCALL_SETPGID_X},
#ifdef __NR_bpf
	[__NR_bpf - SYSCALL_TABLE_ID0] =                        {UF_USED, SPRE_SYSCALL_BPF_E, SPRE_SYSCALL_BPF_X},
#endif
#ifdef __NR_seccomp
	[__NR_seccomp - SYSCALL_TABLE_ID0] =                    {UF_USED, SPRE_SYSCALL_SECCOMP_E, SPRE_SYSCALL_SECCOMP_X},
#endif
#ifdef __NR_renameat2
	[__NR_renameat2 - SYSCALL_TABLE_ID0] =                  {UF_USED, SPRE_SYSCALL_RENAMEAT2_E, SPRE_SYSCALL_RENAMEAT2_X},
#endif
#ifdef __NR_userfaultfd
	[__NR_userfaultfd - SYSCALL_TABLE_ID0] =                {UF_USED | UF_NEVER_DROP, SPRE_SYSCALL_USERFAULTFD_E, SPRE_SYSCALL_USERFAULTFD_X},
#endif
#ifdef __NR_openat2
	[__NR_openat2 - SYSCALL_TABLE_ID0] =                    {UF_USED, SPRE_SYSCALL_OPENAT2_E, SPRE_SYSCALL_OPENAT2_X},
#endif	
#ifdef __NR_clone3
	[__NR_clone3 - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SYSCALL_CLONE3_E, SPRE_SYSCALL_CLONE3_X},
#endif
#ifdef __NR_mprotect
	[__NR_mprotect - SYSCALL_TABLE_ID0] =                   {UF_USED, SPRE_SYSCALL_MPROTECT_E, SPRE_SYSCALL_MPROTECT_X},	
#endif					
#ifdef __NR_execveat
	[__NR_execveat - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, SPRE_SYSCALL_EXECVEAT_E, SPRE_SYSCALL_EXECVEAT_X},
#endif
#ifdef __NR_copy_file_range
	[__NR_copy_file_range - SYSCALL_TABLE_ID0] =            {UF_USED, SPRE_SYSCALL_COPY_FILE_RANGE_E, SPRE_SYSCALL_COPY_FILE_RANGE_X},
#endif
};
