#include <stdlib.h>
#include <sys/mman.h>
#include <linux/elf.h>
#include <linux/ptrace.h>

struct pt_regs _l_context;

extern int main(int argc, char *argv[], char *env[]);
extern void __l_restore_context(struct pt_regs *context);

int __attribute__((section(".collector_enter"))) __collector_enter;
Elf64_Ehdr __attribute__((section(".collector_ehdr"))) __collector_Ehdr;

void __l_start_main(int argc, char *argv[]) {
    char **env;

    // OS modify __collector_enter when it first load the program into memory
    // so we are first here, we should make this page writable
    // after that we should modify __collector_enter by ourselves
    if (__collector_enter == 1)
        mprotect(&__collector_enter, 4096, PROT_READ|PROT_WRITE);

    // mark that we are in collector
    __collector_enter = 1;

    // save context
    memcpy((char *)&_l_context, argv[argc - 1], sizeof(struct pt_regs));

    env = (char **)argv[argc + 1];

    argv[--argc] = 0;

    main(argc, argv, env);

    // we now leave the collector, clear the mark
    __collector_enter = 0;

    // restore the context
    __l_restore_context(&_l_context);

    // we will never reach here
}