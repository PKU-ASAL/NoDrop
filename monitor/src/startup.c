#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "events.h"
#include "common.h"
#include "ioctl.h"
#include "mmheap.h"
#include "pkeys.h"

#include "_random.h"

#define NOREACH __builtin_unreachable();
#define ARCH_SET_FS		0x1002
#define ARCH_GET_FS		0x1003

#define NOD_MONITOR_MEM_SIZE (4 * 1024)

#define __ASSERT(eval, str, pre, cmd)\
do {if (!(eval)){pre;perror(str);cmd;}} while(0)

#define ASSERT_EXIT(eval, str, pre)  __ASSERT(eval, str, pre, syscall(SYS_exit, -1))
#define ASSERT_OUT(eval, str, pre)   __ASSERT(eval, str, pre, goto out)


int nod_monitor_main(struct nod_buffer *buffer);
void __attribute__((weak)) nod_monitor_init(int argc, char *argv[], char *env[]) {};
void __attribute__((weak)) nod_monitor_exit(long code) {};

void main(int, char **, char **);
static void __restore_context(struct nod_stack_info *p);

extern unsigned long __bdata;
extern unsigned long __edata;

__attribute__((section(NOD_SECTION_NAME))) 
struct nod_monitor_info __info = { .fsbase = 0 };

static void 
__restore_context(struct nod_stack_info *p)
{
    if (unlikely(SYSCALL_EXIT_FAMILY(p->nr))) {
        nod_monitor_exit(p->nr);
        if(likely(p->mem > 0)) munmap(p->mem, NOD_MONITOR_MEM_SIZE);
        if(likely(p->pkey != -1))  pkey_free(p->pkey);
        syscall(p->nr, p->code);
    } else {
        if(likely(p->pkey != -1)) pkey_set(p->pkey, PKEY_DISABLE_WRITE);
        ioctl(p->ioctl_fd, NOD_IOCTL_RESTORE_CONTEXT, p);
    }
    NOREACH
}

static void
__initialize(struct nod_stack_info *p)
{
    syscall(SYS_arch_prctl, ARCH_GET_FS, (unsigned long)&p->fsbase);
    p->pkey = pkey_alloc();
    if (p->pkey != -1) {
        ASSERT_EXIT(likely(pkey_mprotect(&__bdata, (unsigned long)&__edata - (unsigned long)&__bdata, PROT_READ | PROT_WRITE, p->pkey) != -1),
                "pkey_mprotect for data segenemtn failed",);
    }

    if (unlikely(__info.fsbase == 0)) {
        __info.fsbase = p->fsbase;
        mprotect(&__info, (sizeof(__info) + 4095) / 4096, PROT_READ);
    }
}

void
main(int argc, char **argv, char **env)
{
    struct nod_buffer *buffer;
    struct nod_stack_info *p = (struct nod_stack_info *)argv[--argc];
    argv[argc] = 0;

    if (unlikely(p->fsbase == 0)) {
        __initialize(p);
    } else {
        syscall(SYS_arch_prctl, ARCH_SET_FS, p->fsbase);
        if (p->pkey != -1) {
            pkey_set(p->pkey, 0);
        }
    }

    if (unlikely(p->mem == 0)) {
        p->mem = mmap(NULL, NOD_MONITOR_MEM_SIZE, PROT_READ | PROT_WRITE, 
                    MAP_PRIVATE | MAP_ANON, -1, 0);
        ASSERT_OUT(likely(p->mem != MAP_FAILED), "Cannot allocate memory", p->mem = 0);
        p->memsz = NOD_MONITOR_MEM_SIZE;

        if (p->pkey != -1) {
            ASSERT_OUT(likely(pkey_mprotect(p->mem, p->memsz, PROT_READ | PROT_WRITE, p->pkey) != -1),
                        "pkey_mprotect for heap mem failed",);
        }

        nod_mmheap_init(p->mem + p->memoff, p->memsz - p->memoff);
        nod_monitor_init(argc, argv, env);
    }

    ASSERT_OUT(likely((p->ioctl_fd = open(NOD_IOCTL_PATH, O_RDONLY)) >= 0),
        "Open " NOD_IOCTL_PATH " failed",);

    p->hash = nod_calc_hash(p);

    buffer = (struct nod_buffer *)mmap(NULL, sizeof(struct nod_buffer), 
                                        PROT_READ, MAP_PRIVATE, p->ioctl_fd, 0);
    ASSERT_OUT(likely(buffer != MAP_FAILED), "Cannot allocate buffer", buffer = 0);
    if (p->pkey != -1) {
        ASSERT_OUT(likely(pkey_mprotect(buffer, sizeof(struct nod_buffer), PROT_READ, p->pkey) != -1),
                "pkey_mprotect for buffer failed",);
    }

    nod_monitor_main(buffer);
    if(likely(buffer))  munmap(buffer, sizeof(struct nod_buffer));

out:
    __restore_context(p);

    /* NOT REACHABLE */
    ASSERT_EXIT(unlikely(0), "FATAL: not reachable",);
}