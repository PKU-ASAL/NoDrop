#ifndef NOD_FILLER_H_
#define NOD_FILLER_H_

struct event_filler_arguments;

#define FILLER_LIST_MAPPER(FN)			\
        FN(sys_generic)			\
    FN(sys_open)			\
    FN(sys_empty)			\
    FN(sys_read)			\
    FN(sys_write)			\
    FN(sys_execve)			\
    FN(sys_procstart)			\
    FN(sys_socket_bind)			\
    FN(sys_connect)			\
    FN(sys_send)			\
    FN(sys_recv)			\
    FN(sys_recvfrom)			\
    FN(sys_shutdown)			\
    FN(sys_socketpair)			\
    FN(sys_setsockopt)			\
    FN(sys_getsockopt)			\
    FN(sys_sendmsg)			\
    FN(sys_recvmsg)			\
    FN(sys_creat)			\
    FN(sys_pipe)			\
    FN(sys_eventfd)			\
    FN(sys_futex)			\
    FN(sys_poll)			\
    FN(sys_pread)			\
    FN(sys_pwrite)			\
    FN(sys_readv_preadv)			\
    FN(sys_writev)			\
    FN(sys_preadv)			\
    FN(sys_pwritev)			\
    FN(sys_nanosleep)			\
    FN(sys_getrlimit_setrlrimit)			\
    FN(sys_prlimit)			\
    FN(sys_fcntl)			\
    FN(sys_brk_munmap_mmap)			\
    FN(sys_ptrace)			\
    FN(sys_renameat)			\
    FN(sys_symlinkat)			\
    FN(sys_sendfile)			\
    FN(sys_quotactl)			\
    FN(sys_getresuid_and_gid)			\
    FN(proc_startupdate)			\
    FN(sys_setns)			\
    FN(sys_flock)			\
    FN(sys_accept)			\
    FN(sys_accept4)			\
    FN(sys_semop)			\
    FN(sys_semctl)			\
    FN(sys_ppoll)			\
    FN(sys_mount)			\
    FN(sys_semget)			\
    FN(sys_access)			\
    FN(sys_unshare)			\
    FN(sys_bpf)			\
    FN(sys_unlinkat)			\
    FN(sys_mkdirat)			\
    FN(sys_openat)			\
    FN(sys_linkat)			\
    FN(sys_fchmodat)			\
    FN(sys_chmod)			\
    FN(sys_fchmod)			\
    FN(sys_renameat2)			\
    FN(sys_openat2)			\
    FN(sys_mprotect)			\
    FN(sys_execveat)			\
    FN(sys_copy_file_range)			\
	FN(terminate_filler)
 
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