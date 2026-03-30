#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <string.h>
#include <limits.h>

#include "config.h"
#include "common.h"
#include "events.h"

#define FIFO_PATH "/tmp/nodrop.fifo"

static FILE *g_log_file = NULL;
struct timeval tv;
static unsigned int tid;

static void print_json_string(FILE *out, const char *data, uint16_t len) {
    const unsigned char *u_data = (const unsigned char *)data;
    fputc('"', out);
    for (uint16_t i = 0; i < len; i++) {
        unsigned char c = u_data[i];
        switch (c) {
            case '"':  fprintf(out, "\\\""); break;
            case '\\': fprintf(out, "\\\\"); break;
            case '\b': fprintf(out, "\\b");  break;
            case '\f': fprintf(out, "\\f");  break;
            case '\n': fprintf(out, "\\n");  break;
            case '\r': fprintf(out, "\\r");  break;
            case '\t': fprintf(out, "\\t");  break;
            default:
                if (c >= 32 && c <= 126) fputc(c, out);
                else fprintf(out, "\\u%04x", c);
                break;
        }
    }
    fputc('"', out);
}

static int _parse(FILE *out, struct nod_event_hdr *hdr, char *buffer) {
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

    fprintf(out, "{\"ts\":%" PRIu64 ",\"tid\":%u,\"cpuid\":%u,\"event\":\"%s\",\"params\":{", 
            hdr->ts, hdr->tid, hdr->cpuid, info->name);

    for (i = 0; i < info->nparams; ++i) {
        param = &info->params[i];
        if (i > 0)
            fprintf(out, ", ");
        fprintf(out, "\"%s\":", param->name);
        switch (param->type)
        {
        case PT_CHARBUF:
        case PT_FSPATH:
        case PT_FSRELPATH:
        case PT_BYTEBUF:
            print_json_string(out, data, args[i]);
            break;

        case PT_FLAGS8:
        case PT_UINT8:
        case PT_SIGTYPE:
            fprintf(out, "%" PRIu8, *(uint8_t *)data);
            break;

        case PT_FLAGS16:
        case PT_UINT16:
        case PT_SYSCALLID:
            fprintf(out, "%" PRIu16, *(uint16_t *)data);
            break;

        case PT_FLAGS32:
        case PT_UINT32:
        case PT_MODE:
        case PT_UID:
        case PT_GID:
        case PT_SIGSET:
            fprintf(out, "%" PRIu32, *(uint32_t *)data);
            break;

        case PT_RELTIME:
        case PT_ABSTIME:
        case PT_UINT64:
            fprintf(out, "%" PRIu64, *(uint64_t *)data);
            break;

        case PT_INT8:
            fprintf(out, "%" PRId8, *(int8_t *)data);
            break;

        case PT_INT16:
            fprintf(out,"%" PRId16, *(int16_t *)data);
            break;

        case PT_INT32:
            fprintf(out, "%" PRId32, *(int32_t *)data);
            break;

        case PT_INT64:
        case PT_ERRNO:
        case PT_FD:
        case PT_PID:
            fprintf(out, "%" PRId64, *(int64_t *)data);
            break;

        default:
            fprintf(out, "null");
            break;
        }

        // move to the next argument
        data += args[i];
    }
    fprintf(out, "}}\n");
    return 0;
}

void nod_monitor_init(int argc, char *argv[], char *env[])
{
    gettimeofday(&tv, NULL);
    tid = (unsigned int)syscall(SYS_gettid);
    // snprintf(g_path, sizeof(g_path), PATH_FILENAME, tid, (long)(tv.tv_sec * SECOND_IN_US + tv.tv_usec));

    g_log_file = fopen(FIFO_PATH, "w");
    if (!g_log_file) {
        perror("Failed to open FIFO");
    }
}

int nod_monitor_main(char *buffer, struct nod_buffer_info *buffer_info)
{
    if (!g_log_file)
        return -1;

    char *ptr, *buffer_end;
    struct nod_event_hdr *hdr;

    ptr = buffer;
    buffer_end = ptr + buffer_info->tail;
    while (ptr < buffer_end)
    {
        hdr = (struct nod_event_hdr *)ptr;
        buffer_info->n_solved_evts++;
        _parse(g_log_file, hdr, (char *)(hdr + 1));
        ptr += hdr->len;
    }

    fflush(g_log_file);
    buffer_info->nevents = buffer_info->tail = 0;
    return 0;
}
