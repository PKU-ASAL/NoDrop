// #include <stdio.h>
//#include <stdlib.h>
// const char interp_section[] __attribute__((section(".interp"))) = "/home/jeshrz/process_inject/hello/hello";
//const char interp_section[] __attribute__((section(".interp"))) = "/home/jeshrz/glibc-2.27/build/elf/ld.so";
// const char interp_section[] __attribute__((section(".interp"))) = "/lib/x86_64-linux-gnu/ld-2.27.so";
#include <unistd.h>
#include <fcntl.h>

#define __NR_write 1
ssize_t my_write(int fd, const void *buf, size_t size)
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

// #define __NR_exit 60
// ssize_t my_exit(int code)
// {
//     ssize_t ret;
//     asm volatile
//     (
//         "syscall"
//         : "=a" (ret)
//         //                 EDI      RSI       RDX
//         : "0"(__NR_exit), "D"(code)
//         : "rcx", "r11", "memory"
//     );
//     return ret;
// }

// int xxx() {
//     unsigned long rsp;
//     asm("movq %%rsp, %0":"=r"(rsp));
//     printf("%lx\n", rsp);
//     exit(0);
// }

int main() { 
    // int fd = open("/mnt/hgfs/Projects/process_inject/StressTesting/test_r.txt", O_RDONLY);
    // // fork();
    // int pid;
    // int i;
    // for (i = 0; i < 1000; ++i) {
    //     printf("hello, world%d\n", i);
    // }
    // while(1) {
    // // for(i = 0; i < 1000; ++i) {
    //     pid = fork();
    //     if (pid < 0) continue;
    //     if (pid == 0) {
    //         // printf("%d\n", getpid());
    //         exit(0);
    //     }
    // }
    // printf("hello, world1\n");
    // printf("hello, world2\n");
    // printf("hello, world3\n");
    // printf("hello, world4\n");
    // printf("hello, world5\n");
    my_write(1, "a.out1\n", 7);
    my_write(1, "a.out2\n", 7);
    my_write(1, "a.out3\n", 7);
    my_write(1, "a.out4\n", 7);
    my_write(1, "a.out5\n", 7);
    my_write(1, "a.out6\n", 7);
    my_write(1, "a.out7\n", 7);
    my_write(1, "a.out8\n", 7);
    // my_write(1, "")
    // _exit(0);
    // puts("hello");
    // my_write(1, "a.out\n", 6);
    // while(1);
    return 0; 
}
