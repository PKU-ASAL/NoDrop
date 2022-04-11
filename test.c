#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define N 50

void *xxx(void *arg) {
    char line[128];
    int i;
    for (i = 0; i < 10000; ++i) {
        int fd = open("StressTesting/1.txt", O_RDONLY);

        read(fd, line, 50);
        read(fd, line, 50);
        read(fd, line, 50);
        read(fd, line, 50);
        read(fd, line, 50);
        read(fd, line, 50);
        read(fd, line, 50);
        read(fd, line, 50);
        read(fd, line, 50);
        read(fd, line, 50);

        close(fd);
    }
    printf("child\n");
    return NULL;
}


int main() { 
    int i;
    pthread_t tids[N];
    for (i = 0; i < N; ++i) {
        if (pthread_create(&tids[i], NULL, xxx, NULL)) {
            printf("%d: failed\n", i);
            tids[i] = -1;
        }
    }
    int pid = getpid();
    printf("ok\n");
    for (i = 0; i < N; ++i) {
        if (tids[i] != -1) {
            pthread_join(tids[i], NULL);
        }
        printf("hello, world%d %d\n",i, pid);
    }
    return 0; 
}
