#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "tsc.h"

int main(int argc, char *argv[]) {
    int loop;
    uint64_t ts;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <number of iterations>\n", argv[0]);
        return -1;
    }

    loop = atoi(argv[1]);
    ts = -rdtsc();
    for (int i = 0; i < loop; i++) {
        (void volatile)getpid();
    }
    ts += rdtsc();
    printf("getpid() called %d times, total ts: %lu ms\n", loop, tsc_to_nsec(ts) / 1000000);

    return 0;
}
