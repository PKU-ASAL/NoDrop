#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include "context.h"

#define PATH_FMT "/tmp/pinject/%u-%ld.buf"
#define SECOND_IN_US 1000000

char path[100];
struct spr_buffer_info *info;
struct timeval tv;

void spr_monitor_init(int argc, char *argv[], char *env[], struct spr_buffer *buffer) {
    info = &buffer->info;
    gettimeofday(&tv, NULL);
}

int main(struct spr_buffer *buffer) {
    FILE *file;
    unsigned int tid = (unsigned int)syscall(SYS_gettid);
    sprintf(path, PATH_FMT, tid, tv.tv_sec * SECOND_IN_US + tv.tv_usec);
    if(!(file = fopen(path, "ab+"))) {
        perror("Cannot open log file");
        return 0;
    }

    fwrite(buffer->buffer, info->tail, 1, file);
    fclose(file); 

    return 0;
}