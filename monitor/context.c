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

unsigned long __attribute__((section(".monitor.infopack"))) dynamic_linker_ready = 0;

static void 
__m_restore_context(int fd, struct nod_stack_info *p) {
    if (unlikely(SYSCALL_EXIT_FAMILY(p->nr))) {
        nod_monitor_exit(p->mem, p->nr);
        syscall(p->nr, p->code);
    } else {
        if (mprotect(p->mem, NOD_MONITOR_MEM_SIZE, PROT_READ) == -1) {
            syscall(SYS_exit, -1);
        }
        ioctl(fd, NOD_IOCTL_RESTORE_SECURITY, p);
    }
    NOREACH
}

void
__m_start_main(int argc, char *argv[])
{
    int first = 0, ioctl_fd;
    struct nod_buffer *buffer;
    struct nod_stack_info *p = (struct nod_stack_info *)argv[--argc];
    argv[argc] = 0;

    if (unlikely(p->fsbase == 0)) {
        syscall(SYS_arch_prctl, ARCH_GET_FS, (unsigned long)&p->fsbase);
        if (unlikely(dynamic_linker_ready == 0)) {
            dynamic_linker_ready = p->fsbase;
            mprotect(&dynamic_linker_ready, 4096, PROT_READ);
        }
        mallopt(M_MMAP_THRESHOLD, 0);
    } else {
        syscall(SYS_arch_prctl, ARCH_SET_FS, p->fsbase);
    }

    ioctl_fd = open(NOD_IOCTL_PATH, O_RDONLY);
    if (ioctl_fd < 0) {
        perror("Open ioctl failed");
        syscall(SYS_exit, -1);
    }
    if(!p->buffer) {
        p->buffer = (struct nod_buffer *)mmap(NULL, sizeof(struct nod_buffer), 
                                        PROT_READ, MAP_PRIVATE, ioctl_fd, 0);
        if (p->buffer == MAP_FAILED) {
            perror("Cannot get buffer");
            syscall(SYS_exit, -1);
        }
    }

    if (unlikely(p->come++ == 0)) {
        p->mem = mmap(NULL, NOD_MONITOR_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p->mem == MAP_FAILED) {
            perror("Cannot allocate memory\n");
            syscall(SYS_exit, -1);
        }
        nod_monitor_init(p->mem, argc, argv, (char **)argv[argc + 2]);
    } else {
        if (mprotect(p->mem, NOD_MONITOR_MEM_SIZE, PROT_READ | PROT_WRITE) == -1) {
            perror("Cannot make memory writable\n");
            syscall(SYS_exit, -1);
        }
    }

    main(p->mem, p->buffer);

    __m_restore_context(ioctl_fd, p);
}