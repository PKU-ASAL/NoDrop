#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
int i;
time_t starttime;

void
signal_callback_handler(int signum)
{
//    printf("Caught signal %d\n",signum);
   // Cleanup and close up stuff here
//    printf("number of iteration %d\n",i);
    time_t endtime=time(NULL);
    // printf("number of seconds eplapsed %ld\n",endtime-starttime);
    // printf("average iterations per second %d\n",i/(endtime-starttime));
    printf(" %d,%d,%d\n",i,endtime-starttime,i/(endtime-starttime));
   // Terminate program
   exit(signum);
}
int main() { 
    char line[128];
    char msg[] = "c";
    signal(SIGINT, signal_callback_handler);
    starttime = time(NULL);
    for(i=0;i<100000000;i++)
    //for(i=0;i<10;i++)
    {
        // int fd = open("./test.txt", O_WRONLY| O_CREAT);
        // write(fd, msg, sizeof(msg));
        // close(fd);
        int fd = open("/mnt/hgfs/Projects/process_inject/StressTesting/test_r.txt", O_RDONLY);

        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        read(fd, line, 10);
        close(fd);


    }
    printf("%d\n", i);
    return 0;
}
//./sysdig "proc.name=a.out and evt.type in (close, open, write)"