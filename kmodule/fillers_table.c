#include "fillers.h"
#include "nodrop.h"

#include "events.h"

#define FILLER_REF(x) f_##x, NOD_FILLER_##x

const struct nod_event_entry g_nod_events[NODE_EVENT_MAX] = {
    [NODE_SYSCALL_READ] = {FILLER_REF(sys_read)},
    [NODE_SYSCALL_WRITE] = {FILLER_REF(sys_write)},
    [NODE_SYSCALL_OPEN] = {FILLER_REF(sys_open)},
    [NODE_SYSCALL_CLOSE] = {FILLER_REF(sys_close)},
    [NODE_SYSCALL_EXIT] = {FILLER_REF(sys_exit)},
    [NODE_SYSCALL_EXIT_GROUP] = {FILLER_REF(sys_exit_group)},
    [NODE_SYSCALL_EXECVE] = {FILLER_REF(sys_execve)},
    [NODE_SYSCALL_CLONE] = {FILLER_REF(proc_startupdate)},
    [NODE_SYSCALL_FORK] = {FILLER_REF(proc_startupdate)},
    [NODE_SYSCALL_VFORK] = {FILLER_REF(proc_startupdate)},
    [NODE_SYSCALL_SOCKET] = {FILLER_REF(sys_socket)},
    [NODE_SYSCALL_BIND] = {FILLER_REF(sys_socket_bind)},
    [NODE_SYSCALL_CONNECT] = {FILLER_REF(sys_connect)},
    [NODE_SYSCALL_LISTEN] = {FILLER_REF(sys_listen)},
    [NODE_SYSCALL_ACCEPT] = {FILLER_REF(sys_accept)},
    [NODE_SYSCALL_ACCEPT4] = {FILLER_REF(sys_accept4)},
    [NODE_SYSCALL_SENDTO] = {FILLER_REF(sys_sendto)},
    [NODE_SYSCALL_RECVFROM] = {FILLER_REF(sys_recvfrom)},
    [NODE_SYSCALL_SHUTDOWN] = {FILLER_REF(sys_shutdown)},
    [NODE_SYSCALL_GETSOCKNAME] = {FILLER_REF(sys_empty)},
    [NODE_SYSCALL_GETPEERNAME] = {FILLER_REF(sys_empty)},
    [NODE_SYSCALL_SOCKETPAIR] = {FILLER_REF(sys_socketpair)},
    [NODE_SYSCALL_SETSOCKOPT] = {FILLER_REF(sys_setsockopt)},
    [NODE_SYSCALL_GETSOCKOPT] = {FILLER_REF(sys_getsockopt)},
    [NODE_SYSCALL_SENDMSG] = {FILLER_REF(sys_sendmsg)},
    [NODE_SYSCALL_SENDMMSG] = {FILLER_REF(sys_empty)},
    [NODE_SYSCALL_RECVMSG] = {FILLER_REF(sys_recvmsg)},
    [NODE_SYSCALL_RECVMMSG] = {FILLER_REF(sys_empty)},
    [NODE_SYSCALL_IOCTL] = {FILLER_REF(sys_ioctl)},
    [NODE_SYSCALL_GETUID] = {FILLER_REF(sys_getuid)}
};