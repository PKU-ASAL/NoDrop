#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <malloc.h>
#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/times.h>

#include "context.h"
#include "ioctl.h"

#define NOREACH __builtin_unreachable();

void __attribute__((weak)) nod_monitor_init(char *mem, int argc, char *argv[], char *env[]) {};
void __attribute__((weak)) nod_monitor_exit(char *mem, long code) {};
void __attribute__((weak)) nod_monitor_enter(char *mem) {};
void __attribute__((weak)) nod_monitor_return(char *mem) {};

static void 
__m_restore_context(int fd, struct nod_stack_info *p) {
    nod_monitor_return(p->mem);
    p->come++;
    if (unlikely(SYSCALL_EXIT_FAMILY(p->nr))) {
        nod_monitor_exit(p->mem, p->nr);
        syscall(p->nr, p->code);
    } else {
        ioctl(fd, NOD_IOCTL_RESTORE_SECURITY, p);
    }
    NOREACH
}

void
__m_start_main(int argc, char *argv[])
{
    int ioctl_fd;
    struct nod_stack_info *p = (struct nod_stack_info *)argv[argc - 1];

    if (unlikely(p->come == 0)) {
        syscall(SYS_arch_prctl, ARCH_GET_FS, (unsigned long)&p->fsbase);
        mallopt(M_MMAP_THRESHOLD, 0);
        p->mem = mmap(NULL, NOD_MONITOR_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (!p->mem) {
            syscall(SYS_exit, -1);
        }
    } else {
        syscall(SYS_arch_prctl, ARCH_SET_FS, p->fsbase);
    }

    ioctl_fd = open(NOD_IOCTL_PATH, O_RDONLY);

    if (unlikely(p->come == 0)) {
        nod_monitor_init(p->mem, argc, argv, (char **)argv[argc + 1]);
    }

    nod_monitor_enter(p->mem);

    main(p->mem);

    __m_restore_context(ioctl_fd, p);
}