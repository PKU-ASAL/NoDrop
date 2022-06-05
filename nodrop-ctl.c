#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>

#include "include/ioctl.h"

int main(int argc, char *argv[]) {
    int fd;
    int ret;
    FILE *file;
    struct buffer_count_info cinfo;
    struct fetch_buffer_struct fetch;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [clean|fetch|start|stop|count]\n", argv[0]);
        return 0;
    }

    fd = open(NOD_IOCTL_PATH, O_RDWR);
    if (fd < 0) {
        perror("Cannot open " NOD_IOCTL_PATH);
        return 127;
    }

    if (!strcmp(argv[1], "clean")) {
        if (!ioctl(fd, NOD_IOCTL_CLEAR_BUFFER, 0))
            fprintf(stderr, "Success\n");
    } else if (!strcmp(argv[1], "fetch")) {
        if ((ret = ioctl(fd, NOD_IOCTL_READ_BUFFER_COUNT_INFO, &cinfo))) {
            fprintf(stderr, "Get Buffer Count Info failed, reason %d\n", ret);
            return -1;
        }

        fetch.len = cinfo.unflushed_len;
        fetch.buf = malloc(fetch.len);
        if (!fetch.buf) {
            fprintf(stderr, "Allocate memory failed\n");
            return -1;
        }

        if ((ret = ioctl(fd, NOD_IOCTL_FETCH_BUFFER, &fetch))) {
            fprintf(stderr, "Fetch Buffer failed, reason %d\n", ret);
            return -1;
        }

        if (argc <= 2) file = stdout;
        else file = fopen(argv[2], "wb");
        if (!file) {
            fprintf(stderr, "Cannot open file\n");
            return -1;
        }

        if (fwrite(fetch.buf, fetch.len, 1, file) == 1) {
            fprintf(stderr, "Write %lu bytes to file %s\n", fetch.len, argc <= 2 ? "stdout" : argv[2]);
        } else {
            fprintf(stderr, "Write to file %s failed\n", argc <= 2 ? "stdout" : argv[2]);
        }

        if (file != stdout)
            fclose(file);

    } else if (!strcmp(argv[1], "count")) {
        if (!ioctl(fd, NOD_IOCTL_READ_BUFFER_COUNT_INFO, &cinfo)) {
            printf("event_count=%lu,unflushed_count=%lu,unflushed_len=%lu\n", cinfo.event_count, cinfo.unflushed_count, cinfo.unflushed_len);
        }
    } else if (!strcmp(argv[1], "stop")) {
        if (!ioctl(fd, NOD_IOCTL_STOP_RECORDING, 0))
            fprintf(stderr, "Stopped\n");

    } else if (!strcmp(argv[1], "start")) {
        if (!ioctl(fd, NOD_IOCTL_START_RECORDING, 0))
            fprintf(stderr, "Start\n");

    } else {
        fprintf(stderr, "Unknown cmd %s\n", argv[1]);
    }

    return 0;
}