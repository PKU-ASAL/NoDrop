#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>

#include "include/ioctl.h"

int main(int argc, char *argv[]) {
    unsigned long long count;
    int fd;

    if (argc < 2) {
        printf("Usage: sprctl <cmd>\n");
        return 0;
    }

    fd = open("/proc/pinject", O_RDWR);
    if (fd < 0) {
        printf("Cannot open /proc/pinject\n");
        return 127;
    }

    if (!strcmp(argv[1], "clean")) {
        if (!ioctl(fd, SPR_IOCTL_CLEAR_BUFFER, 0))
            printf("Success\n");
    } else if (!strcmp(argv[1], "count")) {
        if (!ioctl(fd, SPR_IOCTL_READ_BUFFER_COUNT, &count)) {
            printf("%lld\n", count);
        }
    } else if (!strcmp(argv[1], "stop")) {
        if (!ioctl(fd, SPR_IOCTL_STOP_RECORDING, 0))
            printf("Stopped\n");

    } else if (!strcmp(argv[1], "start")) {
        if (!ioctl(fd, SPR_IOCTL_START_RECORDING, 0))
            printf("Start\n");

    } else {
        printf("Unknown cmd %s\n", argv[1]);
    }

    return 0;
}