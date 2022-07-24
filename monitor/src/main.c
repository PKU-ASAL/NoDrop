#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include "config.h"
#include "events.h"
#include "common.h"

#ifndef PATH_FMT
#define PATH_FMT STORE_PATH "/%u-%ld.buf"
#endif

static char path[100];
static struct timeval tv;
static unsigned int tid;
uint64_t g_nevts;

static const char *__print_format[PT_UINT64 + 1][PF_OCT + 1] = {
    [PT_NONE] = {"", "", "", "", ""},/*empty*/
    [PT_INT8] = {"", "%"PRId8, "0x%"PRIx8, "%010" PRId8, "0%"PRIo8},/*PT_INT8*/
    [PT_INT16] = {"", "%"PRId16, "0x%"PRIx16, "%010" PRId16, "0%"PRIo16},/*PT_INT16*/
    [PT_INT32] = {"", "%"PRId32, "0x%"PRIx32, "%010" PRId32, "0%"PRIo32},/*PT_INT32*/
    [PT_INT64] = {"", "%"PRId64, "0x%"PRIx64, "%010" PRId64, "0%"PRIo64},/*PT_INT64*/
    [PT_UINT8] = {"", "%"PRIu8, "0x%"PRIx8, "%010" PRId8, "0%"PRIo8},/*PT_UINT8*/
    [PT_UINT16] = {"", "%"PRIu16, "0x%"PRIx16, "%010" PRIu16, "0%"PRIo16},/*PT_UINT16*/
    [PT_UINT32] = {"", "%"PRIu32, "0x%"PRIx32, "%010" PRIu32, "0%"PRIo32},/*PT_UINT32*/
    [PT_UINT64] = {"", "%"PRIu64, "0x%"PRIx64, "%010" PRIu64, "0%"PRIo64}/*PT_UINT64*/
};

static int _parse(FILE *out, struct nod_event_hdr *hdr, char *buffer, void *__data)
{
    size_t i;
    const struct nod_event_info *info;
    const struct nod_param_info *param;
    uint16_t *args;
    char *data;

    if (hdr->type < 0 || hdr->type >= NODE_EVENT_MAX)
        return -1;

    info = &g_event_info[hdr->type];
    args = (uint16_t *)buffer;
    data = (char *)(args + info->nparams);
    
    fprintf(out, "%lu %u (%u): %s(", hdr->ts, hdr->tid, hdr->cpuid, info->name);

    for (i = 0; i < info->nparams; ++i) {
        param = &info->params[i];
        if (i > 0)  fprintf(out, ", ");
        fprintf(out, "%s=", param->name);
        switch(param->type) {
        case PT_CHARBUF:
        case PT_FSPATH:
        case PT_FSRELPATH:
        case PT_BYTEBUF:
            fwrite(data, args[i], 1, out);
            break;

        case PT_FLAGS8:
        case PT_UINT8:
        case PT_SIGTYPE:
            fprintf(out, __print_format[PT_UINT8][param->fmt], *(uint8_t *)data);
            break;
        
        case PT_FLAGS16:
        case PT_UINT16:
        case PT_SYSCALLID:
            fprintf(out, __print_format[PT_UINT16][param->fmt], *(uint16_t *)data);
            break;
        
        case PT_FLAGS32:
        case PT_UINT32:
        case PT_MODE:
        case PT_UID:
        case PT_GID:
        case PT_SIGSET:
            fprintf(out, __print_format[PT_UINT32][param->fmt], *(uint32_t *)data);
            break;
        
        case PT_RELTIME:
        case PT_ABSTIME:
        case PT_UINT64:
            fprintf(out, __print_format[PT_UINT64][param->fmt], *(uint64_t *)data);
            break;

        case PT_INT8:
            fprintf(out, __print_format[PT_INT8][param->fmt], *(int8_t *)data);
            break;

        case PT_INT16:
            fprintf(out, __print_format[PT_INT16][param->fmt], *(int16_t *)data);
            break;
        
        case PT_INT32:
            fprintf(out, __print_format[PT_INT32][param->fmt], *(int32_t *)data);
            break;

        case PT_INT64:
        case PT_ERRNO:
        case PT_FD:
        case PT_PID:
            fprintf(out, __print_format[PT_INT64][param->fmt], *(int64_t *)data);
            break;

        default:
            fprintf(out, "<unknown>");
            break;
        }

        // move to the next argument
        data += args[i];
    }
    fprintf(out, ")\n");
    return 0;
}

void nod_monitor_init(int argc, char *argv[], char *env[]) {
    gettimeofday(&tv, NULL);
    tid = (unsigned int)syscall(SYS_gettid);
    sprintf((char *)path, PATH_FMT, tid, tv.tv_sec * SECOND_IN_US + tv.tv_usec);
}

int nod_monitor_main(char *buffer, struct nod_buffer_info *buffer_info) {
    char *ptr, *buffer_end;
    struct nod_event_hdr *hdr;
    // FILE *file;

    // if(!(file = fopen((const char *)path, "ab+"))) {
    //     perror("Cannot open log file");
    //     return 0;
    // }

    ptr = buffer;
    buffer_end = ptr + buffer_info->tail;
    while (ptr < buffer_end) {
        hdr = (struct nod_event_hdr *)ptr;
        g_nevts++;
        // _parse(file, hdr, (char *)(hdr + 1), 0);
        // fwrite(ptr, hdr->len, 1, file);
        ptr += hdr->len;
    }

    // fclose(file);
    buffer_info->nevents = buffer_info->tail = 0;

    return 0;
}
