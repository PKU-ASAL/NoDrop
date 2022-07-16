#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "events.h"
#include "common.h"
#include "ioctl.h"
#include "mmheap.h"
#include "pkeys.h"
#include "dynlink.h"

#define START "_start"

#define NOREACH __builtin_unreachable();
#define ARCH_SET_FS        0x1002
#define ARCH_GET_FS        0x1003

#define __ASSERT(eval, str, pre, cmd)\
do {if (!(eval)){pre;perror(str);cmd;}} while(0)
#define ASSERT_EXIT(eval, str, pre)  __ASSERT(eval, str, pre, syscall(SYS_exit, -1))
#define ASSERT_OUT(eval, str, pre)   __ASSERT(eval, str, pre, goto out)

extern unsigned long __bdata;
extern unsigned long __edata;

__attribute__((section(NOD_SECTION_NAME)))
struct nod_monitor_info __info = {.fsbase = 0};

static char mmheap_pool[NOD_MONITOR_MEM_SIZE];

// declarations of processing logic
int nod_monitor_main(char *buffer, struct nod_buffer_info *buffer_info);
weak void nod_monitor_init(int argc, char *argv[], char *env[]) {};
weak void nod_monitor_exit(long code) {};

// declarations of startup
static void nod_start_main(int, char **, char **);
static void nod_restore_context(struct nod_stack_info *p);

weak void init();
weak void _fini();
int __libc_start_main(int (*)(), int, char **,
                      void (*)(), void(*)(), void(*)());

__asm__(
        ".text \n"
        ".global " START " \n"
START ": \n"
"	xor %rbp,%rbp \n"
"	mov %rsp,%rdi \n"
".weak _DYNAMIC \n"
".hidden _DYNAMIC \n"
"	lea _DYNAMIC(%rip),%rsi \n"
"	andq $-16,%rsp \n"
"	call " START "_c \n"
);

static void
nod_restore_context(struct nod_stack_info *p) {
    if (unlikely(SYSCALL_EXIT_FAMILY(p->nr))) {
        nod_monitor_exit(p->nr);
        syscall(p->nr, p->code);
    } else {
#ifdef NOD_PKEY_SUPPORT
        if (likely(p->pkey != -1)) pkey_set(p->pkey, PKEY_DISABLE_WRITE);
#endif
        ioctl(p->ioctl_fd, NOD_IOCTL_RESTORE_CONTEXT, p);
    }
    NOREACH
}

static void
nod_initialize(struct nod_stack_info *p) {
    syscall(SYS_arch_prctl, ARCH_GET_FS, (unsigned long) &p->fsbase);

    if (unlikely(__info.fsbase == 0)) {
        __info.fsbase = p->fsbase;
        mprotect(&__info, (sizeof(__info) + getpagesize() - 1) / getpagesize(), PROT_READ);
#ifdef NOD_PKEY_SUPPORT
        if (p->pkey != -1) {
            pkey_set(p->pkey, 0);
            ASSERT_EXIT(likely(pkey_mprotect(&__bdata, (unsigned long) &__edata - (unsigned long) &__bdata,
                                             PROT_READ | PROT_WRITE, p->pkey) != -1),
                        "pkey_mprotect for data segenemtn failed",);
        }
#endif
    }
    nod_mmheap_init(mmheap_pool, sizeof(mmheap_pool));
}

static void
nod_start_main(int argc, char **argv, char **env) {
    struct nod_stack_info *p = (struct nod_stack_info *) argv[--argc];

    argv[argc] = 0;

    if (unlikely(p->fsbase == 0)) {
        nod_initialize(p);
        nod_monitor_init(argc, argv, env);
    } else {
        syscall(SYS_arch_prctl, ARCH_SET_FS, p->fsbase);
#ifdef NOD_PKEY_SUPPORT
        if (p->pkey != -1) {
            pkey_set(p->pkey, 0);
        }
#endif
    }

    ASSERT_OUT(likely((p->ioctl_fd = open(NOD_IOCTL_PATH, O_RDONLY)) >= 0),
               "Open " NOD_IOCTL_PATH " failed",);

    if (unlikely(p->buffer == NULL)) {
        p->buffer = (char *) mmap(NULL, BUFFER_SIZE,
                                PROT_READ, MAP_PRIVATE, p->ioctl_fd, 0);
        ASSERT_OUT(likely(p->buffer != MAP_FAILED), 
                "Cannot allocate buffer", p->buffer = NULL);
#ifdef NOD_PKEY_SUPPORT
        if (p->pkey != -1) {
            ASSERT_OUT(likely(pkey_mprotect(p->buffer, sizeof(struct nod_buffer), PROT_READ, p->pkey) != -1),
                    "pkey_mprotect for buffer failed",);
        }
#endif
    }
    
    if (unlikely(p->buffer_info == NULL)) {
        p->buffer_info = (struct nod_buffer_info *) mmap(NULL, sizeof(struct nod_buffer_info*),
                                                       PROT_READ | PROT_WRITE, MAP_PRIVATE, p->ioctl_fd, 0);
        ASSERT_OUT(likely(p->buffer_info != MAP_FAILED), 
                "Cannot allocate buffer info", p->buffer_info = NULL);
#ifdef NOD_PKEY_SUPPORT
        if (p->pkey != -1) {
            ASSERT_OUT(likely(pkey_mprotect(p->buffer_info, sizeof(struct nod_buffer_info), PROT_READ | PROT_WRITE, p->pkey) != -1),
                    "pkey_mprotect for buffer info failed",);
        }
#endif
    }

    p->hash = nod_calc_hash(p);
    nod_monitor_main(p->buffer, p->buffer_info);

out:
    nod_restore_context(p);

    /* NOT REACHABLE */
    ASSERT_EXIT(unlikely(0), "FATAL: not reachable",);
}

hidden void _start_c(size_t *sp, size_t *dynv) {
    size_t i, aux[AUX_CNT], dyn[DYN_CNT];
    size_t *rel, rel_size, base;

    int argc = *sp;
    char **argv = (void *) (sp + 1);

    if (likely(__info.fsbase != 0)) {
        nod_start_main(argc, argv, argv + argc + 1);
        return;
    }

    for (i = argc + 1; argv[i]; i++);
    size_t *auxv = (void *) (argv + i + 1);

    for (i = 0; i < AUX_CNT; i++) aux[i] = 0;
    for (i = 0; auxv[i]; i += 2)
        if (auxv[i] < AUX_CNT)
            aux[auxv[i]] = auxv[i + 1];

    for (i = 0; i < DYN_CNT; i++) dyn[i] = 0;
    for (i = 0; dynv[i]; i += 2)
        if (dynv[i] < DYN_CNT)
            dyn[dynv[i]] = dynv[i + 1];

    /* If the dynamic linker is invoked as a command, its load
     * address is not available in the aux vector. Instead, compute
     * the load address as the difference between &_DYNAMIC and the
     * virtual address in the PT_DYNAMIC program header. */
    base = aux[AT_BASE];
    if (!base) {
        size_t phnum = aux[AT_PHNUM];
        size_t phentsize = aux[AT_PHENT];
        Phdr *ph = (void *) aux[AT_PHDR];
        for (i = phnum; i--; ph = (void *) ((char *) ph + phentsize)) {
            if (ph->p_type == PT_DYNAMIC) {
                base = (size_t) dynv - ph->p_vaddr;
                break;
            }
        }
    }

    /* MIPS uses an ugly packed form for GOT relocations. Since we
     * can't make function calls yet and the code is tiny anyway,
     * it's simply inlined here. */

    rel = (void *) (base + dyn[DT_REL]);
    rel_size = dyn[DT_RELSZ];
    for (; rel_size; rel += 2, rel_size -= 2 * sizeof(size_t)) {
        if (!IS_RELATIVE(rel[1], 0)) continue;
        size_t *rel_addr = (void *) (base + rel[0]);
        *rel_addr += base;
    }

    rel = (void *) (base + dyn[DT_RELA]);
    rel_size = dyn[DT_RELASZ];
    for (; rel_size; rel += 3, rel_size -= 3 * sizeof(size_t)) {
        if (!IS_RELATIVE(rel[1], 0)) continue;
        size_t *rel_addr = (void *) (base + rel[0]);
        *rel_addr = base + rel[2];
    }

    __libc_start_main((int (*)()) nod_start_main, *sp, (void *) (sp + 1), init, _fini, 0);
}