#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <sys/types.h>
#define N 10
#define M 500

// total events: N * (2 + M * 11) + N * 2 + 9
void *f1(void *arg) {
    char line[128];
    int i;
    for (i = 0; i < M; ++i) {
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

void *f2(void *arg) {
    printf("%ld: child\n", syscall(SYS_gettid));
    return NULL;
}

int main() { 
    int i;
    pthread_t tids[N];

    for (i = 0; i < N; ++i) {
        if (pthread_create(&tids[i], NULL, f1, NULL)) {
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
    printf("bye\n");

    printf("ok\n");
    if(fork() == 0) {
        printf("%d: child\n", getpid());
        syscall(SYS_exit, 0);
    } else {
        printf("%d: parent\n", getpid());
    }
    wait(0);

    pthread_t tid;
    printf("ok\n");
    pthread_create(&tid, 0, f2, 0);
    printf("%d: parent\n", getpid());
    pthread_join(tid, 0);
    return 0; 
}
