#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/syscall.h>

#include "context.h"
#include "events.h"

#define PATH_FMT "/tmp/secureprov/%u-%ld.buf"
#define SECOND_IN_US 1000000000

char path[100];
struct spr_buffer_info *info;
struct timeval tv;
unsigned int tid;

void spr_monitor_init(int argc, char *argv[], char *env[]) {
    info = &g_bufp->info;
    gettimeofday(&tv, NULL);
    tid = (unsigned int)syscall(SYS_gettid);
    sprintf(path, PATH_FMT, tid, tv.tv_sec * SECOND_IN_US + tv.tv_usec);
}

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

static int _parse(struct spr_event_hdr *hdr, char *buffer, void *__data)
{
    size_t i;
    const struct spr_event_info *info;
    const struct spr_param_info *param;
    uint16_t *args;
    char *data;

    if (hdr->type < 0 || hdr->type >= SPRE_EVENT_MAX)
        return -1;

    info = &g_event_info[hdr->type];
    args = (uint16_t *)buffer;
    data = (char *)(args + info->nparams);
    
    printf("%lu %u (%u): %s(", hdr->ts, hdr->tid, hdr->cpuid, info->name);

    for (i = 0; i < info->nparams; ++i) {
        param = &info->params[i];
        if (i > 0)  printf(", ");
        printf("%s=", param->name);
        switch(param->type) {
        case PT_CHARBUF:
        case PT_FSPATH:
        case PT_FSRELPATH:
        case PT_BYTEBUF:
            fwrite(data, args[i], 1, stdout);
            break;

        case PT_FLAGS8:
        case PT_UINT8:
        case PT_SIGTYPE:
            printf(__print_format[PT_UINT8][param->fmt], *(uint8_t *)data);
            break;
        case PT_FLAGS16:
        case PT_UINT16:
        case PT_SYSCALLID:
            printf(__print_format[PT_UINT16][param->fmt], *(uint16_t *)data);
            break;
        
        case PT_FLAGS32:
        case PT_UINT32:
        case PT_MODE:
        case PT_UID:
        case PT_GID:
        case PT_SIGSET:
            printf(__print_format[PT_UINT32][param->fmt], *(uint32_t *)data);
            break;
        
        case PT_RELTIME:
        case PT_ABSTIME:
        case PT_UINT64:
            printf(__print_format[PT_UINT64][param->fmt], *(uint64_t *)data);
            break;

        case PT_INT8:
            printf(__print_format[PT_INT8][param->fmt], *(int8_t *)data);
            break;

        case PT_INT16:
            printf(__print_format[PT_INT16][param->fmt], *(int16_t *)data);
            break;
        
        case PT_INT32:
            printf(__print_format[PT_INT32][param->fmt], *(int32_t *)data);
            break;

        case PT_INT64:
        case PT_ERRNO:
        case PT_FD:
        case PT_PID:
            printf(__print_format[PT_INT64][param->fmt], *(int64_t *)data);
            break;

        default:
            printf("<unknown>");
            break;
        }

        data += args[i];
    }
    printf(")\n");
    return 0;
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
        // _parse(hdr, (char *)(hdr + 1), 0);
        fwrite(ptr, hdr->len, 1, file);
        ptr += hdr->len;
    }

    fclose(file); 

    return 0;
}