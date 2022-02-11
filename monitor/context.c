#include <signal.h>
#include <unistd.h>
#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/ptrace.h>

#include "../include/events.h"
#include "../include/common.h"

extern int main(int argc, char *argv[], char *env[]);
extern void __restore_registers(struct pt_regs *reg);
static void __m_restore_context(struct context_struct *context);
static void __m_real_exit(void);

void __attribute__((weak)) on_init() {};
void __attribute__((weak)) on_exit() {};

m_infopack __attribute__((section(".monitor.infopack"))) infopack;
int *enterp = &infopack.m_enter;
struct spr_buffer *bufp = &infopack.m_buffer;

sigset_t oldsig;
unsigned long my_fsbase;
int first_come_in = 0;

void *__dso_handle = 0;

void __m_start_main(int argc, char *argv[], void (*rtld_fini) (void)) {
    sigset_t newsig;

    // Because we are first loaded, OS sets __m_enter to be 1.
    // In other case, __m_enter should always be 0 here.
    // We should make this page writable manually because ld.so call mprotect during initialization.
    if (unlikely(*enterp == 1)) {
        mprotect(&infopack, sizeof(infopack), PROT_READ|PROT_WRITE);
        arch_prctl(ARCH_GET_FS, &my_fsbase);
        first_come_in = 1;
    }

    // Mark that we are in collector
    *enterp = 1;

    // block all SIGNALs
    sigfillset(&newsig);
    sigprocmask(SIG_SETMASK, &newsig, &oldsig);

    if (first_come_in) {
        atexit(__m_real_exit);
        if (rtld_fini) {
            atexit(rtld_fini);
        }
        on_init();
    } else {
        arch_prctl(ARCH_SET_FS, my_fsbase);
    }

    main(argc, argv, (char **)argv[argc + 1]);

    // Restore the context
    __m_restore_context(&infopack.m_context);
}

static void
__m_real_exit(void) {
    unsigned long nr = infopack.m_context.reg.orig_rax;
    unsigned long status = infopack.m_context.reg.rdi;
    while(1) {
        syscall(nr, status);
    }
}

static void 
__m_restore_context(struct context_struct *context) {
    if (unlikely(SYSCALL_EXIT_FAMILT(infopack.m_context.reg.orig_rax))) {
        on_exit();
        exit(infopack.m_context.reg.rdi);
        /* !!!NOT REACHABLE!!! */
        __m_real_exit();
    }

    if (unlikely(first_come_in)) {
        first_come_in = 0;
    }

    // Restore Thread Local Storage pointer
    arch_prctl(ARCH_SET_FS, context->fsbase);

    // Restore SIGNALs
    sigprocmask(SIG_SETMASK, &oldsig, 0);

    // Leaving the collector, clear the mark
    *enterp = 0;

    // Restore context registers
    __restore_registers(&context->reg);
}