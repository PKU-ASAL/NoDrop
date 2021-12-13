#include <string.h>
#include <linux/elf.h>
#include <linux/ptrace.h>
#include <sys/mman.h>
#include <asm/prctl.h>

#include "common.h"

struct context_struct _l_context;

extern int main(int argc, char *argv[], char *env[]);
extern void __restore_registers(struct pt_regs *reg);

int __attribute__((section(".monitor.enter"))) __collector_enter;
int need_prctl = 0;

void __l_restore_context(struct context_struct *context);

void __l_start_main(int argc, char *argv[]) {
    char **env;

    // Because we are first loaded, OS set __collector_enter to be 1.
    // In other case, __collector_enter should always be 0 here.
    // We should make this page writable manually because ld.so call mprotect during initialization.
    if (__collector_enter == 1) {
        mprotect(&__collector_enter, 4096, PROT_READ|PROT_WRITE);
        need_prctl = 1;
    }

    // Mark that we are in collector
    __collector_enter = 1;

    // Save context
    memcpy((char *)&_l_context, argv[argc - 1], sizeof(struct context_struct));

    env = (char **)argv[argc + 1];

    argv[--argc] = 0;

    main(argc, argv, env);

    // Restore the context
    __l_restore_context(&_l_context);
}

void __l_restore_context(struct context_struct *context) {
    if (need_prctl) {
        need_prctl = 0;
        // Restore Thread Local Storage pointer
        arch_prctl(ARCH_SET_FS, context->fsbase);
        arch_prctl(ARCH_SET_GS, context->gsbase);
    }

    // Leaving the collector, clear the mark
    __collector_enter = 0;

    // Restore context registers
    __restore_registers(&context->reg);
}