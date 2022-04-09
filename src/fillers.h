#ifndef NOD_FILLER_H_
#define NOD_FILLER_H_

struct event_filler_arguments;

#define FILLER_LIST_MAPPER(FN) \
    FN(sys_empty)       \
    FN(sys_read)        \
    FN(sys_write)       \
    FN(sys_open)        \
    FN(sys_close)       \
    FN(sys_exit)        \
    FN(sys_exit_group)  \
    FN(proc_startupdate)\
    FN(sys_execve)      \
    FN(sys_socket)      \
    FN(sys_socket_bind) \
    FN(sys_connect)     \
    FN(sys_listen)      \
    FN(sys_accept)      \
    FN(sys_accept4)     \
    FN(sys_sendto)      \
    FN(sys_recvfrom)    \
    FN(sys_shutdown)    \
    FN(sys_socketpair)  \
    FN(sys_setsockopt)  \
    FN(sys_getsockopt)  \
    FN(sys_sendmsg)     \
    FN(sys_recvmsg)     \
    FN(sys_ioctl)       \

#define FILLER_ENUM_FN(x) NOD_FILLER_##x,
enum nod_filler_id {
    FILLER_LIST_MAPPER(FILLER_ENUM_FN)
    NOD_FILLER_MAX
};
#undef FILLER_ENUM_FN

#define FILLER_PROTOTYPE_FN(x) \
    int f_##x(struct event_filler_arguments *args) __attribute__((weak));
FILLER_LIST_MAPPER(FILLER_PROTOTYPE_FN)
#undef FILLER_PROTOTYPE_FN


#endif //NOD_FILLER_H_