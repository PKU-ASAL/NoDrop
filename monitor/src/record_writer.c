#include "record_writer.h"
#include "config.h"
#include "ioctl.h"
#include "common.h"

#ifndef PATH_FMT
#define PATH_FMT CONFIG_STORE_PATH "/%u-%ld.buf"
#endif

static char record_path[100];
static char gz_record_path[100];
void set_record_path(struct timeval tv, unsigned int tid) {
    sprintf((char *)record_path, PATH_FMT, tid, tv.tv_sec * SECOND_IN_US + tv.tv_usec);
    sprintf((char *)gz_record_path, PATH_FMT".gz", tid, tv.tv_sec * SECOND_IN_US + tv.tv_usec);
}

void new_record_writer(struct record_writer* rw, int mode) {
    if (rw->mode == -1) {
        // only update at the first time
        rw->mode = mode;
    }
    switch (mode)
    {
    case NOD_RECORD_MODE_START:
        rw->file = fopen((const char *)record_path, "ab");
        if(!rw->file) { // TEMP
            perror("Cannot open log file");
            return;
        }
        break;
    case NOD_RECORD_MODE_STOP:
        rw->file = NULL;
        break;
    case NOD_RECORD_MODE_COMPRESS:
        rw->gzfile = gzopen((const char *)gz_record_path, "ab");
        if (!rw->gzfile) {
            perror("Cannot open log file");
            return;
        }
        break;
    default:
        break;
    }
}
void write_record_writer(struct record_writer* rw, char * ptr){
    struct nod_event_hdr *hdr;
    switch (rw->mode)
    {
    case NOD_RECORD_MODE_START:
        hdr = (struct nod_event_hdr *)ptr;
        fwrite(ptr, hdr->len, 1, rw->file);
        break;
    case NOD_RECORD_MODE_STOP:
        break;
    case NOD_RECORD_MODE_COMPRESS:
        hdr = (struct nod_event_hdr *)ptr;
        gzwrite(rw->gzfile, ptr, hdr->len);
        break;
    default:
        break;
    }
}
void close_record_writer(struct record_writer* rw) {
    switch (rw->mode)
    {
    case NOD_RECORD_MODE_START:
        fclose(rw->file);
        break;
    case NOD_RECORD_MODE_STOP:
        break;
    case NOD_RECORD_MODE_COMPRESS:
        gzclose(rw->gzfile);
        break;
    default:
        break;
    }
}
