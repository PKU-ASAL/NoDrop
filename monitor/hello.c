#include <stdio.h>
#include <unistd.h>

#include "common.h"

extern struct logmsg_block *__m_log;
int main(int argc, char *argv[], char *env[]) {
    int i;
    FILE *file;
    char path[10], *p;

    sprintf(path, "%d.txt", getpid());
    if(!(file = fopen(path, "a")))
        return 0;

    for (i = 0, p = __m_log->buf; i < __m_log->nr; i++) {
        fprintf(file, "monitor: %s\n", p);
        p += MAX_LOG_LENGTH;
    }

    fclose(file); 
    return 0;
}