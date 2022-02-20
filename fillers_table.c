#include "include/events.h"
#include "include/fillers.h"
#include "pinject.h"

#define FILLER_REF(x) f_##x, SPR_FILLER_##x

const struct spr_event_entry g_spr_events[SPRE_EVENT_MAX] = {
    [SPRE_SYSCALL_READ] = {FILLER_REF(sys_read)},
    [SPRE_SYSCALL_WRITE] = {FILLER_REF(sys_write)},
    [SPRE_SYSCALL_OPEN] = {FILLER_REF(sys_open)},
    [SPRE_SYSCALL_CLOSE] = {FILLER_REF(sys_close)},
    [SPRE_SYSCALL_EXIT] = {FILLER_REF(sys_exit)},
    [SPRE_SYSCALL_EXIT_GROUP] = {FILLER_REF(sys_exit_group)},
    [SPRE_SYSCALL_EXECVE] = {FILLER_REF(sys_execve)},
    [SPRE_SYSCALL_CLONE] = {FILLER_REF(proc_startupdate)},
    [SPRE_SYSCALL_FORK] = {FILLER_REF(proc_startupdate)},
    [SPRE_SYSCALL_VFORK] = {FILLER_REF(proc_startupdate)},
    [SPRE_SYSCALL_SOCKET] = {FILLER_REF(sys_socket)},
    [SPRE_SYSCALL_BIND] = {FILLER_REF(sys_socket_bind)},
    [SPRE_SYSCALL_CONNECT] = {FILLER_REF(sys_connect)},
    [SPRE_SYSCALL_LISTEN] = {FILLER_REF(sys_listen)},
    [SPRE_SYSCALL_ACCEPT] = {FILLER_REF(sys_accept)},
    [SPRE_SYSCALL_ACCEPT4] = {FILLER_REF(sys_accept4)},
    [SPRE_SYSCALL_SENDTO] = {FILLER_REF(sys_sendto)},
    [SPRE_SYSCALL_RECVFROM] = {FILLER_REF(sys_recvfrom)},
    [SPRE_SYSCALL_SHUTDOWN] = {FILLER_REF(sys_shutdown)},
    [SPRE_SYSCALL_GETSOCKNAME] = {FILLER_REF(sys_empty)},
    [SPRE_SYSCALL_GETPEERNAME] = {FILLER_REF(sys_empty)},
    [SPRE_SYSCALL_SOCKETPAIR] = {FILLER_REF(sys_socketpair)},
    [SPRE_SYSCALL_SETSOCKOPT] = {FILLER_REF(sys_setsockopt)},
    [SPRE_SYSCALL_GETSOCKOPT] = {FILLER_REF(sys_getsockopt)},
    [SPRE_SYSCALL_SENDMSG] = {FILLER_REF(sys_sendmsg)},
    [SPRE_SYSCALL_SENDMMSG] = {FILLER_REF(sys_empty)},
    [SPRE_SYSCALL_RECVMSG] = {FILLER_REF(sys_recvmsg)},
    [SPRE_SYSCALL_RECVMMSG] = {FILLER_REF(sys_empty)},
};