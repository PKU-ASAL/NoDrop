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
struct nod_buffer *g_bufp = &g_infopack.m_buffer;
static int *enterp = &g_infopack.m_enter;

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

void __attribute__((weak)) nod_monitor_init(int argc, char *argv[], char *env[]) {};
void __attribute__((weak)) nod_monitor_exit(int code) {};
void __attribute__((weak)) nod_monitor_enter() {};
void __attribute__((weak)) nod_monitor_return() {};

extern void __restore_registers(struct pt_regs *reg);
static void __m_restore_context(struct context_struct *context);
static void __m_real_exit(void);
static void __m_upgrade_cred(void);
static void __m_downgrade_cred(void);

void __m_start_main(int argc, char *argv[], void (*rtld_fini) (void)) {
    int i;
    
    *enterp = 1;

    // Because we are first loaded, OS sets __m_enter to be 1.
    // In other case, __m_enter should always be 0 here.
    // We should make this page writable manually because ld.so call mprotect during initialization.
    if (unlikely(g_first_come_in == 1)) {
        mallopt(M_MMAP_THRESHOLD, 0);
        arch_prctl(ARCH_GET_FS, (unsigned long)&g_monitor_fsbase);
    } else {
        arch_prctl(ARCH_SET_FS, g_monitor_fsbase);
    }

    __m_upgrade_cred();

    nod_monitor_enter();

    g_ioctl_proc_fd = open(NOD_IOCTL_PATH, O_RDONLY);

    if (unlikely(g_first_come_in == 1)) {
        nod_monitor_init(argc, argv, (char **)argv[argc + 1]);
        g_first_come_in = 0;
    }

    main();

out:
    // Restore the context
    __m_restore_context(&g_infopack.m_context);
}

static void
__m_real_exit(void) {
    unsigned long nr = g_infopack.m_context.regs.orig_rax;
    unsigned long status = g_infopack.m_context.regs.rdi;
    struct security_data *securities = &g_infopack.m_context.securities;

    __m_downgrade_cred();

    /*
     * Restore Thread Local Storage pointer
     * Enable SECCOMP
     * Restore Capability
     */
    ioctl(g_ioctl_proc_fd, NOD_IOCTL_RESTORE_SECURITY, securities);
    close(g_ioctl_proc_fd);


    while(1) {
        syscall(nr, status);
    }
}

static void 
__m_restore_context(struct context_struct *context) {
    int code;
    struct nod_sigwait *sig, *signext;

    nod_monitor_return();

    if (unlikely(SYSCALL_EXIT_FAMILY(g_infopack.m_context.regs.orig_rax))) {
        code = g_infopack.m_context.regs.rdi;
        nod_monitor_exit(code);
        __m_real_exit();
        /* !!!NOT REACHABLE!!! */
    }

    // Restore SIGNALs
    __m_downgrade_cred();

    /*
     * Restore Thread Local Storage pointer
     * Enable SECCOMP
     * Restore Capability
     */
    ioctl(g_ioctl_proc_fd, NOD_IOCTL_RESTORE_SECURITY, &context->securities);
    close(g_ioctl_proc_fd);

    // Leaving the collector, clear the mark
    *enterp = 0;

    // Restore context registers
    __restore_registers(&context->regs);
}

static void __m_upgrade_cred(void) {
    int i;
    struct rlimit rlim;
    
    g_old_uid = getuid();
    g_old_gid = getgid();

    setuid(0);
    setgid(0);

    for (i = 0; i < 3; ++i) {
        g_rlimits[i].limit = g_infopack.m_context.rlim[i];
    }
}

static void __m_downgrade_cred(void) {
    int i;

    for (i = 0; i < sizeof(g_rlimits) / sizeof(g_rlimits[0]); ++i) {
        setrlimit(g_rlimits[i].resource, &g_rlimits[i].limit);
    }

    chroot(g_infopack.m_context.root_path);

    setgid(g_old_gid);
    setuid(g_old_uid);
}