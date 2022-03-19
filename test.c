#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <linux/elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

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

int main() { 
    my_write(1, "a.out2\n", 7);
    // my_write(1, "a.out3\n", 7);
    // my_write(1, "a.out4\n", 7);
    // my_write(1, "a.out5\n", 7);
    // my_write(1, "a.out6\n", 7);
    // my_write(1, "a.out7\n", 7);
    // my_write(1, "a.out8\n", 7);
    return 0; 
}
