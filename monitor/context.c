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


int g_first_come_in = 1;

m_infopack __attribute__((section(".monitor.infopack"))) g_infopack;
struct spr_buffer *g_bufp = &g_infopack.m_buffer;

static unsigned long g_monitor_fsbase;
static unsigned int g_old_uid, g_old_gid;

static int g_ioctl_proc_fd;
static struct {
    int resource;
    struct rlimit limit;
} g_rlimits[] = {
    {RLIMIT_NOFILE}, // MUST put this at the first position
    {RLIMIT_FSIZE},
    {RLIMIT_CPU}
};

static inline int arch_prctl(int code, unsigned long addr) {
    return syscall(SYS_arch_prctl, code, addr);
}

void __attribute__((weak)) spr_monitor_init(int argc, char *argv[], char *env[]) {};
void __attribute__((weak)) spr_monitor_exit(int code) {};

extern void __restore_registers(struct pt_regs *reg, int fd, int cmd, unsigned long arg);
static void __m_restore_context(struct context_struct *ctx);
static void __m_upgrade_cred(struct context_struct *ctx);
static void __m_downgrade_cred(struct context_struct *ctx);

void __m_start_main(int argc, char *argv[], void (*rtld_fini) (void)) {
    // Because we are first loaded, OS sets __m_enter to be 1.
    // In other case, __m_enter should always be 0 here.
    // We should make this page writable manually because ld.so call mprotect during initialization.
    if (g_first_come_in == 1) {
        mallopt(M_MMAP_THRESHOLD, 0);
        arch_prctl(ARCH_GET_FS, (unsigned long)&g_monitor_fsbase);
    } else {
        arch_prctl(ARCH_SET_FS, g_monitor_fsbase);
    }
    
    __m_upgrade_cred(&g_infopack.m_context);
    g_ioctl_proc_fd = open(SPR_IOCTL_PATH, O_RDONLY);

    if (g_first_come_in == 1) {
        spr_monitor_init(argc, argv, (char **)argv[argc + 1]);
        g_first_come_in = 0;
    }

    main();

out:
    // Restore the context
    __m_restore_context(&g_infopack.m_context);
}

static void 
__m_restore_context(struct context_struct *ctx) {
    if (unlikely(SYSCALL_EXIT_FAMILY(ctx->regs.orig_rax))) {
        spr_monitor_exit(ctx->regs.rdi);
        syscall(ctx->regs.orig_rax, ctx->regs.rdi);
    } else {
        /*
        * Restore Thread Local Storage pointer
        * Enable SECCOMP
        * Restore Capability
        * Close fd
        */
        __m_downgrade_cred(ctx);
        ioctl(g_ioctl_proc_fd, SPR_IOCTL_EXIT_MONITOR, g_ioctl_proc_fd);
    }
    /* !!!NOT REACHABLE!!! */
}

static void __m_upgrade_cred(struct context_struct *ctx) {
    int i;
    struct rlimit rlim;
    
    g_old_uid = getuid();
    g_old_gid = getgid();

    setuid(0);
    setgid(0);

    for (i = 0; i < 3; ++i) {
        g_rlimits[i].limit = ctx->rlim[i];
    }
}

static void __m_downgrade_cred(struct context_struct *ctx) {
    int i;

    for (i = 0; i < sizeof(g_rlimits) / sizeof(g_rlimits[0]); ++i) {
        setrlimit(g_rlimits[i].resource, &g_rlimits[i].limit);
    }

    setgid(g_old_gid);
    setuid(g_old_uid);
}