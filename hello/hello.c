#include <stdio.h>
#include <stdlib.h>
// #include <linux/ptrace.h>

#define __NR_write 1
#define __NR_exit  60

const char interp_section[] __attribute__((section(".interp"))) = "/lib64/ld-linux-x86-64.so.2";
int global_var = 100;

ssize_t l_write(int fd, const void *buf, size_t size)
{
    ssize_t ret;
    asm volatile
    (
        "syscall"
        : "=a" (ret)
        //                 EDI      RSI       RDX
        : "0"(__NR_write), "D"(fd), "S"(buf), "d"(size)
        : "rcx", "r11", "memory"
    );
    return ret;
}

// int my_exit(int code)
// {
//     ssize_t ret;
//     asm volatile
//     (
//         "syscall"
//         : "=a" (ret)
//         : "0"(__NR_exit), "D"(code)
//         : "rcx", "r11", "memory"
//     );
//     return ret;
// }

int main(int argc, char *argv[], char *env[])
{
    if (argc > 0)
        printf("collector: %s\n", argv[0]);
    // exit(0);
    // int ret;
    // printf("hello\n");
    // l_write(1, "hello\n", 6);
    // while(1);
    // my_exit(0);
    // asm volatile
    // (
    //     "syscall"
    //     : "=a" (ret)
    //     //                 EDI      RSI       RDX
    //     : "0"(__NR_write), "D"(1), "S"("hello\n"), "d"(6)
    //     : "rcx", "r11", "memory"
    // );

    // asm volatile
    // (
    //     "syscall"
    //     : "=a" (ret)
    //     : "0"(__NR_exit), "D"(0)
    //     : "rcx", "r11", "memory"
    // );
    return 0;
}