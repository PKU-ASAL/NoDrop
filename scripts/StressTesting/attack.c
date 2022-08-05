#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int i;
time_t starttime;

void
signal_callback_handler(int signum)
{
   printf("Caught signal %d\n",signum);
   // Cleanup and close up stuff here
   printf("number of iteration %d\n",i);
    time_t endtime=time(NULL);
    printf("number of seconds eplapsed %ld\n",endtime-starttime);
    printf("average iterations per second %ld\n",i/(endtime-starttime));

   // Terminate program
   exit(signum);
}
int main() { 
    char msg[] = "c";
    signal(SIGINT, signal_callback_handler);
    starttime = time(NULL);
    for(i=0;i<1;i++)
    //for(i=0;i<10;i++)
    {
        int fd = open("StressTesting/attack.txt", O_WRONLY| O_CREAT, 0777);
        write(fd, msg, sizeof(msg));
        close(fd);
    }
    return 0;
}
//./sysdig "proc.name=a.out and evt.type in (close, open, write)"
