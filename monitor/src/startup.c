#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>

#include "events.h"
#include "config.h"
#include "common.h"
#include "ioctl.h"

#include "mmheap.h"
#include "pkeys.h"
#include "dynlink.h"
#include "tsc.h"

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
int nod_monitor_main(char *buffer, struct nod_buffer_info *buffer_info, struct nod_lua_state *global_state, int record_flag);
weak void nod_monitor_init(int argc, char *argv[], char *env[]) {};
weak void nod_monitor_exit(long code) {};

// declarations of startup
static void nod_start_main(int, char **, char **);
static void nod_restore_context(struct nod_stack_info *p);
#if CONFIG_LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
static size_t *nod_prepare_separated_stack(int argc, char **argv, char **env, size_t aux[AUX_CNT], struct nod_stack_info *p);
#endif

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
    // uint64_t start, end, last_solved;
    if (unlikely(SYSCALL_EXIT_FAMILY(p->syscall_nr))) {
        nod_monitor_exit(p->syscall_nr);
        // end = read_time();
        // printf("\n-%llu-%llu-\n", end - start, p->buffer_info->n_solved_evts - last_solved);
        // last_solved = p->buffer_info->n_solved_evts;
        syscall(p->syscall_nr, p->exit_code);
    } else {
#ifdef NOD_PKEY_SUPPORT
        if (likely(p->pkey != -1)) pkey_set(p->pkey, PKEY_DISABLE_WRITE);
#endif
        // end = read_time();
        // printf("\n-%llu-%llu-\n", end - start, p->buffer_info->n_solved_evts - last_solved);
        // last_solved = p->buffer_info->n_solved_evts;
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
            ASSERT_EXIT(likely(pkey_mprotect(p->stack_start, p->stack_end - p->stack_start,
                                             PROT_READ | PROT_WRITE, p->pkey) != -1),
                        "pkey_mprotect for stack segment failed",);
        }
#endif
    }
    nod_mmheap_init(mmheap_pool, sizeof(mmheap_pool));
}

#if CONFIG_LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
static size_t *
nod_prepare_separated_stack(int argc, char **argv, char **env, size_t aux[AUX_CNT], struct nod_stack_info *p)
{
#define STACK_ROUND_USER(sp, items)  ((size_t *)(((size_t)((sp) - (items))) & ~15UL))
#define STACK_ADD_USER(sp, items)    ((size_t *)(sp) - (items))
#define STACK_ALLOC_USER(sp, len)    ({ (sp) -= (len); sp; })
#define INSERT_AUX_ENT_USER(id, val) \
    do { \
        aux_info[aux_idx++] = (id); \
        aux_info[aux_idx++] = (val); \
    } while (0)
    size_t aux_info[11 * 2];
    size_t arg_addrs[8];
    size_t rand_addr, cur, expected_sp;
    size_t i;
    int envc = 0;
    int aux_idx = 0;
    int items;

    if (argc < 1)
        return NULL;

    if (!p->stack_start || !p->stack_end)
        return NULL;

    rand_addr = p->stack_end - sizeof(void *) - 16;
    p->stack_info_addr = rand_addr - sizeof(*p);
    cur = p->stack_info_addr;

    for (i = argc - 1; i-- > 0;) {
        size_t len = strlen(argv[i]) + 1;
        cur = STACK_ALLOC_USER(cur, len);
        arg_addrs[i] = cur;
        memcpy((void *)cur, argv[i], len);
    }

    for (envc = 0; env[envc]; ++envc)
        ;

    items = argc + envc + 3;
    expected_sp = (size_t)STACK_ROUND_USER(STACK_ADD_USER(cur, 11 * 2), items);
    p->stack_addr = expected_sp;

    if (aux[AT_RANDOM])
        memcpy((void *)rand_addr, (void *)aux[AT_RANDOM], 16);

    memcpy((void *)p->stack_info_addr, p, sizeof(*p));

    {
        size_t *new_sp = (size_t *)p->stack_addr;
        *new_sp++ = argc;
        for (i = 0; i < (size_t)argc - 1; ++i)
            *new_sp++ = arg_addrs[i];
        *new_sp++ = p->stack_info_addr;
        *new_sp++ = 0;
        for (i = 0; env[i]; ++i)
            *new_sp++ = (size_t)env[i];
        *new_sp++ = 0;

        INSERT_AUX_ENT_USER(AT_HWCAP, aux[AT_HWCAP]);
        INSERT_AUX_ENT_USER(AT_PAGESZ, aux[AT_PAGESZ]);
        INSERT_AUX_ENT_USER(AT_CLKTCK, aux[AT_CLKTCK]);
        INSERT_AUX_ENT_USER(AT_PHDR, aux[AT_PHDR]);
        INSERT_AUX_ENT_USER(AT_PHENT, aux[AT_PHENT]);
        INSERT_AUX_ENT_USER(AT_PHNUM, aux[AT_PHNUM]);
        INSERT_AUX_ENT_USER(AT_BASE, aux[AT_BASE]);
        INSERT_AUX_ENT_USER(AT_FLAGS, aux[AT_FLAGS]);
        INSERT_AUX_ENT_USER(AT_ENTRY, aux[AT_ENTRY]);
        INSERT_AUX_ENT_USER(AT_RANDOM, rand_addr);
        INSERT_AUX_ENT_USER(AT_NULL, 0);
        memcpy(new_sp, aux_info, aux_idx * sizeof(size_t));
    }

    return (size_t *)p->stack_addr;
}
#endif

static void
nod_start_main(int argc, char **argv, char **env) {
    struct nod_stack_info *p = (struct nod_stack_info *) argv[argc - 1];

    if (unlikely(p->fsbase == 0)) {
        nod_initialize(p);
        nod_monitor_init(argc, argv, env);
    } else {
#ifdef NOD_PKEY_SUPPORT
        if (p->pkey != -1) {
            pkey_set(p->pkey, PKEY_WR);
        }
#endif
    }

    // static char strbuf[256];
    // uint64_t ts = rdtsc();
    ASSERT_OUT(likely((p->ioctl_fd = open(NOD_IOCTL_PATH, O_RDWR)) >= 0),
               "Open " NOD_IOCTL_PATH " failed",);

    if (unlikely(p->buffer_info == NULL)) {
        p->buffer_info = (struct nod_buffer_info *) mmap(NULL, sizeof(struct nod_buffer_info),
                                                       PROT_READ | PROT_WRITE, MAP_SHARED, p->ioctl_fd, 0);
        ASSERT_OUT(likely(p->buffer_info != MAP_FAILED), 
                "Cannot allocate buffer info", p->buffer_info = NULL);
#ifdef NOD_PKEY_SUPPORT
        if (p->pkey != -1) {
            ASSERT_OUT(likely(pkey_mprotect(p->buffer_info, sizeof(struct nod_buffer_info), PROT_READ | PROT_WRITE, p->pkey) != -1),
                    "pkey_mprotect for buffer info failed",
                    {
                       if (p->buffer_info) munmap(p->buffer_info, sizeof(struct nod_buffer_info));
                       p->buffer_info = NULL;
                    });
        }
#endif
    }

    if (unlikely(p->buffer == NULL)) {
        p->buffer = (char *) mmap(NULL, p->buffer_info->buffer_size,
                                PROT_READ, MAP_SHARED, p->ioctl_fd, 0);
        ASSERT_OUT(likely(p->buffer != MAP_FAILED), 
                "Cannot allocate buffer", 
                {
                   p->buffer = NULL;
                   if (p->buffer_info) munmap(p->buffer_info, sizeof(struct nod_buffer_info));
                   p->buffer_info = NULL;
                });
#ifdef NOD_PKEY_SUPPORT
        if (p->pkey != -1) {
            ASSERT_OUT(likely(pkey_mprotect(p->buffer, p->buffer_info->buffer_size, PROT_READ, p->pkey) != -1),
                    "pkey_mprotect for buffer failed", 
                    {
                        if (p->buffer)  munmap(p->buffer, p->buffer_info->buffer_size);
                        p->buffer = NULL;
                        if (p->buffer_info) munmap(p->buffer_info, sizeof(struct nod_buffer_info));
                        p->buffer_info = NULL;
                    });
        }
#endif
    }

    // int len = sprintf(strbuf, "ts:%lu tail:%u\n", ts, p->buffer_info->tail);
    // write(fileno(stdout), strbuf, len);
    struct nod_lua_state kstate;
    if (ioctl(p->ioctl_fd, NOD_IOCTL_GET_LUA_STATE, &kstate)) {

        // get lua state error
        kstate.lua_path[0] = '\0';
        kstate.lua_mtime = 0;
    }
    if (kstate.lua_mtime) {
        struct stat lua_st;
        if (!stat(kstate.lua_path, &lua_st))
        {
            if (lua_st.st_mtime != kstate.lua_mtime)
            {
                kstate.lua_mtime = lua_st.st_mtime;
                if (ioctl(p->ioctl_fd, NOD_IOCTL_SET_LUA_STATE, &kstate) != 0)
                {
                    return;
                }
            }
        }
    }
    int record_flag = 0;
    if (ioctl(p->ioctl_fd, NOD_IOCTL_GET_RECORD_FLAG, &record_flag)) {
        record_flag = 0;
    }
    nod_monitor_main(p->buffer, p->buffer_info, &kstate, record_flag);

out:
    p->hash = nod_calc_hash(p);
    nod_restore_context(p);

    /* NOT REACHABLE */
    ASSERT_EXIT(unlikely(0), "FATAL: not reachable",);
}

hidden void _start_c(size_t *sp, size_t *dynv) {
    size_t i, aux[AUX_CNT], dyn[DYN_CNT];
    size_t *rel, rel_size, base;

    int argc = *sp;
    char **argv = (void *) (sp + 1);

    // start = read_time();

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

#if CONFIG_LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    {
        struct nod_stack_info *stack = (struct nod_stack_info *)argv[argc - 1];
        size_t current_sp = (size_t)sp;

        if (stack && stack->stack_start && stack->stack_end &&
            (current_sp < stack->stack_start || current_sp >= stack->stack_end)) {
            size_t *new_sp = nod_prepare_separated_stack(argc, argv, argv + argc + 1, aux, stack);
            if (new_sp) {
                sp = new_sp;
                argc = *sp;
                argv = (void *)(sp + 1);
            }
        }
    }
#endif

    __libc_start_main((int (*)()) nod_start_main, *sp, (void *) (sp + 1), init, _fini, 0);
}
