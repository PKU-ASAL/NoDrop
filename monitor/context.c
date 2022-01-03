#include <signal.h>
#include <asm/prctl.h>
#include <sys/mman.h>
#include <linux/ptrace.h>

#include "common.h"

extern int main(int argc, char *argv[], char *env[]);
extern void __restore_registers(struct pt_regs *reg);
static void __m_restore_context(struct context_struct *context);


m_infopack __attribute__((section(".monitor.infopack"))) infopack;

int *__m_enter = &infopack.m_enter;
struct context_struct *__m_context = &infopack.m_context;
struct logmsg_block *__m_log = &infopack.m_logmsg;

unsigned long orig_fsbase;
unsigned long orig_gsbase;

int first_come_in = 0;
sigset_t oldsig;

void __m_start_main(int argc, char *argv[]) {
    sigset_t newsig;

    // Because we are first loaded, OS set __collector_enter to be 1.
    // In other case, __collector_enter should always be 0 here.
    // We should make this page writable manually because ld.so call mprotect during initialization.
    if (unlikely(*__m_enter == 1)) {
        mprotect(&infopack, sizeof(infopack), PROT_READ|PROT_WRITE);
        arch_prctl(ARCH_GET_FS, &orig_fsbase);
        arch_prctl(ARCH_GET_GS, &orig_gsbase);
        first_come_in = 1;
    }

    // Mark that we are in collector
    *__m_enter = 1;

    if (!first_come_in) {
        arch_prctl(ARCH_SET_FS, orig_fsbase);
        arch_prctl(ARCH_SET_GS, orig_gsbase);
    }

    // clear SIGNAL
    sigemptyset(&newsig);
    sigprocmask(SIG_SETMASK, &newsig, &oldsig);

    main(argc, argv, (char **)argv[argc + 1]);

    // Restore the context
    __m_restore_context(__m_context);
}

static void 
__m_restore_context(struct context_struct *context) {
    if (unlikely(DO_EXIT(infopack.m_context.reg.orig_rax))) {
        exit(infopack.m_context.reg.rdx);
        return;
    }

    if (unlikely(first_come_in)) {
        first_come_in = 0;
    }
    
    // Restore Thread Local Storage pointer
    arch_prctl(ARCH_SET_FS, context->fsbase);
    arch_prctl(ARCH_SET_GS, context->gsbase);

    sigprocmask(SIG_SETMASK, &oldsig, 0);

    // Leaving the collector, clear the mark
    *__m_enter = 0;

    // Restore context registers
    __restore_registers(&context->reg);
}