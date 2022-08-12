#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/syscall.h>

int n, m;
int fd;
uint64_t nevts;
struct timeval begin, end;

void do_exit(int sig) {
  gettimeofday(&end, 0);
  close(fd);
  printf("%lu/%ld\n", nevts, ((end.tv_sec - begin.tv_sec) * 1000000 + (end.tv_usec - begin.tv_usec)) / 1000);
  exit(0);
}

long invoke() {
  long ret;

  ret = write(fd,"1", 1);
  nevts++;

  return ret;
}

#pragma GCC push_options
#pragma GCC optimize("O0")
void thread_worker(int id) {
  int i;
  uint64_t count = 0;
  char path[100];
  sprintf(path, "/tmp/count/%d", id);
  freopen(path, "w", stdout);

  fd = open("/dev/null", O_WRONLY);

  signal(SIGINT, do_exit);

  gettimeofday(&begin, 0);
  while(1) {
    for(i = 0; i < n; ++i) {
      invoke();
    }
    for(i = 0; i < m; ++i) {
      count++;
    }
  }
}
#pragma GCC pop_options

int main(int argc, char *argv[]) {
  int i;
  if (argc < 3) {
    printf("Usage: %s <n - getuid> <m - count> <id>\n", argv[0]);
    exit(1);
  }

  n = atoi(argv[1]);
  m = atoi(argv[2]);
  thread_worker(atoi(argv[3]));
  main_exit(0);
  return 0;
}
