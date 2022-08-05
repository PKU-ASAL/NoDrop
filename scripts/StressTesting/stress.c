#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define TOTAL_TIME 30

int nr_thread;
int interval;
int loop;
int b_exit;
pthread_t tids[100];
struct timespec req, rem;
struct timeval begin, end;

void do_exit(int sig) {
  int i;
  uint64_t each = 0;
  uint64_t total = 0;
  b_exit = 1;
  gettimeofday(&end, 0);
  for(i = 0; i < nr_thread; ++i) {
    pthread_join(tids[i], (void *)&each);
    total += each;
  }
  printf("%lu/%ld\n", total, ((end.tv_sec - begin.tv_sec) * 1000000 + (end.tv_usec - begin.tv_usec)) / 1000);
  exit(0);
}

long invoke(uint64_t *nevts) {
  long ret;
  int i, a;

  ret = syscall(SYS_getuid);
  (*nevts)++;

  return ret;
}

uint64_t thread_worker() {
  int i;
  uint64_t nevts = 0;
  signal(SIGINT, SIG_IGN);
  while(!b_exit) {
    for(i = 0; i < loop && !b_exit; ++i) {
      invoke(&nevts);
    }
    if (!b_exit)
      nanosleep(&req, &rem);
  }
  return nevts;
}

int main(int argc, char *argv[]) {
  int i;
  if (argc < 3) {
    printf("Usage: %s <interval - in ns> <loop> <# thread>\n", argv[0]);
    exit(1);
  }

  interval = atoi(argv[1]);
  loop = atoi(argv[2]);
  nr_thread = argc > 3 ? atoi(argv[3]) : 1;
  if (nr_thread >= 100) {
    printf("# thread is larger than 100\n");
    exit(1);
  }

  req.tv_nsec = interval;
  signal(SIGINT, do_exit);

  b_exit = 0;
  for(i = 0; i < nr_thread; ++i) {
    pthread_create(&tids[i], 0, (void *(*)(void *))thread_worker, 0);
  }
  gettimeofday(&begin, 0);
  sleep(30);
  do_exit(0);
  return 0;
}
//./sysdig "proc.name=a.out and evt.type in (close, open, write)"
