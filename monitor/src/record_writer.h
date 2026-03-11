#ifndef NODROP_RECORD_WRITER_H
#define NODROP_RECORD_WRITER_H
#include <stdio.h>
#include <sys/time.h>
#include "zlib.h"

struct record_writer {
    int mode;
    FILE *file;
    gzFile gzfile;
};

void new_record_writer(struct record_writer* rw, int mode);
void write_record_writer(struct record_writer* rw, char * ptr);
void close_record_writer(struct record_writer* rw);
void set_record_path(struct timeval tv, unsigned int tid);

#endif // NODROP_LUA_RUNTIME_H
