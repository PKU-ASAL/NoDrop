#include <string.h>
#include <signal.h>
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
sigset_t oldsig;

char buf[MAX_LOG_LENGTH];

void __l_restore_context(struct context_struct *context);

void __l_start_main(int argc, char *argv[]) {
    char **env;
    sigset_t newsig;

    // Save context
    memcpy((char *)&_l_context, argv[argc - 1], sizeof(struct context_struct));

    // Because we are first loaded, OS set __collector_enter to be 1.
    // In other case, __collector_enter should always be 0 here.
    // We should make this page writable manually because ld.so call mprotect during initialization.
    if (__collector_enter == 1) {
        mprotect(&__collector_enter, 4096, PROT_READ|PROT_WRITE);
        need_prctl = 1;
    }

    // Mark that we are in collector
    __collector_enter = 1;

    // clear SIGNAL
    sigemptyset(&newsig);
    sigprocmask(SIG_SETMASK, &newsig, &oldsig);

    // generate log
    sprintf(buf, "eid=%lu,nr=%lx,ret=%lx,rdi=%lx,rsi=%lx,rdx=%lx,r10=%lx,r8=%lx,r9=%lx", _l_context.eid, 
			_l_context.reg.orig_rax, _l_context.reg.rax, _l_context.reg.rdi, _l_context.reg.rsi, _l_context.reg.rdx, _l_context.reg.r10, _l_context.reg.r8, _l_context.reg.r9);

    env = (char **)argv[argc + 1];
    argv[argc - 1] = buf;

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

    sigprocmask(SIG_SETMASK, &oldsig, NULL);

    // Leaving the collector, clear the mark
    __collector_enter = 0;

    // Restore context registers
    __restore_registers(&context->reg);
}