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

#include "secureprov.h"
#include "events.h"


/*
 * SYSCALL TABLE
 */
const enum spr_event_type g_syscall_event_table[SYSCALL_TABLE_SIZE] = {
	[__NR_read - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_READ,
	[__NR_write - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_WRITE,
    [__NR_open - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_OPEN,
	[__NR_close - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_CLOSE,
    [__NR_exit - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_EXIT,
    [__NR_exit_group - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_EXIT_GROUP,
    [__NR_execve - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_EXECVE,
    [__NR_clone - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_CLONE,
    [__NR_fork - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_FORK,
    [__NR_vfork - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_VFORK,
    [__NR_socket - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SOCKET,
    [__NR_bind - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_BIND,
    [__NR_connect - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_CONNECT,
    [__NR_listen - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_LISTEN,
    [__NR_accept - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_ACCEPT,
    [__NR_getsockname - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_GETSOCKNAME,
    [__NR_getpeername - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_GETPEERNAME,
    [__NR_socketpair - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SOCKETPAIR,
    [__NR_sendto - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SENDTO,
    [__NR_recvfrom - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_RECVFROM,
    [__NR_shutdown - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SHUTDOWN,
    [__NR_setsockopt - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SETSOCKOPT,
    [__NR_getsockopt - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_GETSOCKOPT,
    [__NR_accept4 - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_ACCEPT4,
    [__NR_sendmsg - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SENDMSG,
    [__NR_sendmmsg - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_SENDMMSG,
    [__NR_recvmsg - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_RECVMSG,
    [__NR_recvmmsg - SYSCALL_TABLE_ID0] = SPRE_SYSCALL_RECVMMSG,
};
