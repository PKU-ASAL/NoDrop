#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
// #include <time.h>
// #include <sys/time.h>

#include "context.h"
#include "events.h"

#define PATH_FMT "/tmp/pinject/%u-%ld.buf"
#define SECOND_IN_US 1000000000

char path[100];
struct spr_buffer_info *info;
struct timeval tv;
unsigned int tid;
// uint64_t total_ts;
// struct timespec start, end;

// void spr_monitor_enter() {
//     clock_gettime(CLOCK_MONOTONIC, &start);
//     // printf("start: %lld %lld\n", start.tv_sec, start.tv_nsec);
// }

// void spr_monitor_return() {
//     FILE *file;
//     clock_gettime(CLOCK_MONOTONIC, &end);
//     uint64_t diff = (end.tv_sec - start.tv_sec) * SECOND_IN_US + (end.tv_nsec - start.tv_nsec);
//     total_ts += diff;

//     if (!(file = fopen(path2, "aw+"))) {
//         printf("%d: %ld\n", tid, diff);
//     } else {
//         fprintf(file, "%ld\n", diff);
//         fclose(file);
//     }

//     // printf("end: %lld %lld\n", end.tv_sec, end.tv_nsec);
//     // printf("%d: %lld\n", tid, diff);
// }

// void spr_monitor_exit(int code) {
//     FILE *file;
//     if(!(file = fopen(path, "aw+"))) {
//         perror("Cannot open log file");
//         return;
//     }
//     fprintf(file, "%ld", total_ts);
//     fclose(file);
// }

void spr_monitor_init(int argc, char *argv[], char *env[]) {
    info = &g_bufp->info;
    gettimeofday(&tv, NULL);
    tid = (unsigned int)syscall(SYS_gettid);
    sprintf(path, PATH_FMT, tid, tv.tv_sec * SECOND_IN_US + tv.tv_usec);
    // total_ts = 0;
    // sprintf(path2, "%d.txt", tid);
}

int main() {
    FILE *file;
    char *ptr, *end;
    struct spr_event_hdr *hdr;
    if(!(file = fopen(path, "ab+"))) {
        perror("Cannot open log file");
        return 0;
    }

    ptr = g_bufp->buffer;
    end = g_bufp->buffer + info->tail;
    while (ptr < end) {
        hdr = (struct spr_event_hdr *)ptr; 
        fwrite(ptr, hdr->len, 1, file);
        ptr += hdr->len;
    }

    fclose(file); 

    return 0;
}