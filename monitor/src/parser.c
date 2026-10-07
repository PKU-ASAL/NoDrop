#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parser.h"
static const char *__print_format[PT_UINT64 + 1][PF_OCT + 1] = {
    [PT_NONE] = {"", "", "", "", ""},                                         /*empty*/
    [PT_INT8] = {"", "%" PRId8, "0x%" PRIx8, "%010" PRId8, "0%" PRIo8},       /*PT_INT8*/
    [PT_INT16] = {"", "%" PRId16, "0x%" PRIx16, "%010" PRId16, "0%" PRIo16},  /*PT_INT16*/
    [PT_INT32] = {"", "%" PRId32, "0x%" PRIx32, "%010" PRId32, "0%" PRIo32},  /*PT_INT32*/
    [PT_INT64] = {"", "%" PRId64, "0x%" PRIx64, "%010" PRId64, "0%" PRIo64},  /*PT_INT64*/
    [PT_UINT8] = {"", "%" PRIu8, "0x%" PRIx8, "%010" PRId8, "0%" PRIo8},      /*PT_UINT8*/
    [PT_UINT16] = {"", "%" PRIu16, "0x%" PRIx16, "%010" PRIu16, "0%" PRIo16}, /*PT_UINT16*/
    [PT_UINT32] = {"", "%" PRIu32, "0x%" PRIx32, "%010" PRIu32, "0%" PRIo32}, /*PT_UINT32*/
    [PT_UINT64] = {"", "%" PRIu64, "0x%" PRIx64, "%010" PRIu64, "0%" PRIo64}  /*PT_UINT64*/
};

int evt_arg_to_string(const struct nod_param_info *param, const void *data, uint16_t len,
                      char *buf, size_t bufsz) {
    if (!param || !buf || bufsz == 0)
        return -1;

    switch (param->type)
    {
    case PT_FSPATH:
    case PT_FSRELPATH:
    case PT_CHARBUF:
    case PT_BYTEBUF:
    {
        size_t n = len < bufsz - 1 ? len : bufsz - 1;
        memcpy(buf, data, n);
        buf[n] = '\0';
        return (int)n;
    }
    /*
    case PT_BYTEBUF:
        // TO-DO raw buffer is not suitable for printing, may transfer into hex code
        return snprintf(buf, bufsz, "<binary:%u>", len);
    */
    case PT_FLAGS8:
    case PT_UINT8:
    case PT_SIGTYPE:
        return snprintf(buf, bufsz,
                        __print_format[PT_UINT8][param->fmt],
                        *(uint8_t *)data);

    case PT_FLAGS16:
    case PT_UINT16:
    case PT_SYSCALLID:
        return snprintf(buf, bufsz,
                        __print_format[PT_UINT16][param->fmt],
                        *(uint16_t *)data);

    case PT_FLAGS32:
    case PT_UINT32:
    case PT_MODE:
    case PT_UID:
    case PT_GID:
    case PT_SIGSET:
        return snprintf(buf, bufsz,
                        __print_format[PT_UINT32][param->fmt],
                        *(uint32_t *)data);

    case PT_RELTIME:
    case PT_ABSTIME:
    case PT_UINT64:
        return snprintf(buf, bufsz,
                        __print_format[PT_UINT64][param->fmt],
                        *(uint64_t *)data);

    case PT_INT8:
        return snprintf(buf, bufsz,
                        __print_format[PT_INT8][param->fmt],
                        *(int8_t *)data);

    case PT_INT16:
        return snprintf(buf, bufsz,
                        __print_format[PT_INT16][param->fmt],
                        *(int16_t *)data);

    case PT_INT32:
        return snprintf(buf, bufsz,
                        __print_format[PT_INT32][param->fmt],
                        *(int32_t *)data);

    case PT_INT64:
    case PT_ERRNO:
    case PT_FD:
    case PT_PID:
        return snprintf(buf, bufsz,
                        __print_format[PT_INT64][param->fmt],
                        *(int64_t *)data);

    default:
        return snprintf(buf, bufsz, "<unknown>");
    }
}

static int nod_left(int mx_size, int off)
{
    return off < mx_size ? mx_size - off : 0;
}

static void nod_append(char *out, int mx_size, int *off, const char *fmt, ...)
{
    va_list ap;
    int left = nod_left(mx_size, *off);
    int n;

    if (left <= 0)
        return;

    va_start(ap, fmt);
    n = vsnprintf(out + *off, (size_t)left, fmt, ap);
    va_end(ap);

    if (n > 0)
        *off += n;
    if (*off > mx_size)
        *off = mx_size;
}

static size_t nod_param_min_size(int type)
{
    switch (type)
    {
    case PT_FLAGS8:
    case PT_UINT8:
    case PT_SIGTYPE:
    case PT_INT8:
        return 1;
    case PT_FLAGS16:
    case PT_UINT16:
    case PT_SYSCALLID:
    case PT_INT16:
        return 2;
    case PT_FLAGS32:
    case PT_UINT32:
    case PT_MODE:
    case PT_UID:
    case PT_GID:
    case PT_SIGSET:
    case PT_INT32:
        return 4;
    case PT_RELTIME:
    case PT_ABSTIME:
    case PT_UINT64:
    case PT_INT64:
    case PT_ERRNO:
    case PT_FD:
    case PT_PID:
        return 8;
    default:
        return 0;
    }
}

int get_whole_event(const struct nod_event_hdr *hdr, char *out, int mx_size) {
    int off = 0;
    const struct nod_event_info *info;
    const struct nod_param_info *param;
    const uint16_t *args;
    const char *data, *ev_end;
    char tmp[256];

    if (mx_size <= 0)
        return 0;
    out[0] = '\0';

    if (!hdr || hdr->type >= NODE_EVENT_MAX)
        return 0;

    info = &g_event_info[hdr->type];

    args = (const uint16_t *)(hdr + 1);
    data = (const char *)(args + info->nparams);
    ev_end = (const char *)hdr + hdr->len;
    if (hdr->len < sizeof(*hdr) + info->nparams * sizeof(uint16_t) ||
        data > ev_end)
        return 0;

    nod_append(out, mx_size, &off,
               "%lu %u (%u): %s(",
               hdr->ts,
               hdr->tid,
               hdr->cpuid,
               info->name);

    for (size_t i = 0; i < info->nparams; ++i)
    {
        size_t avail, need;
        uint16_t alen;

        if (nod_left(mx_size, off) <= 0)
            break;

        param = &info->params[i];
        avail = (size_t)(ev_end - data);

        if (i > 0)
            nod_append(out, mx_size, &off, ", ");

        /* param name */
        nod_append(out, mx_size, &off, "%s=", param->name);

        alen = args[i];
        if ((size_t)alen > avail)
            alen = (uint16_t)avail;
        need = nod_param_min_size(param->type);
        if (need > avail || (need == 0 && (size_t)args[i] > avail)) {
            nod_append(out, mx_size, &off, "<oob>");
            break;
        }

        evt_arg_to_string(param, data, alen, tmp, sizeof(tmp));
        nod_append(out, mx_size, &off, "%s", tmp);

        data += alen;
    }

    nod_append(out, mx_size, &off, ")\n");
    return off;
}

int parse_buf_to_log(const char *buf_file, const char *log_file) {
    FILE *fin = NULL;
    FILE *fout = NULL;
    struct nod_event_hdr hdr;
    char out[MAX_EVENT_STR];

    fin = fopen(buf_file, "rb");
    if (!fin){
        perror("fopen buf_file");
        return -1;
    }

    fout = fopen(log_file, "w");
    if (!fout) {
        perror("fopen log_file");
        fclose(fin);
        return -1;
    }

    while (1) {
        void *event_buf = NULL;
        size_t remain_len;
        int ret;

        ret = fread(&hdr, 1, sizeof(hdr), fin);
        if (ret == 0) {
            break;
        }
        if (ret != sizeof(hdr)) {
            fprintf(stderr, "failed to read event header completely\n");
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (hdr.len < sizeof(struct nod_event_hdr)) {
            fprintf(stderr, "invalid event length: %u\n", hdr.len);
            fclose(fin);
            fclose(fout);
            return -1;
        }

        remain_len = hdr.len - sizeof(struct nod_event_hdr);
        event_buf = malloc(hdr.len);
        if (!event_buf) {
            fprintf(stderr, "malloc failed, len=%u\n", hdr.len);
            fclose(fin);
            fclose(fout);
            return -1;
        }

        memcpy(event_buf, &hdr, sizeof(hdr));

        if (remain_len > 0) {
            ret = fread((char *)event_buf + sizeof(struct nod_event_hdr), 1, remain_len, fin);
            if ((size_t)ret != remain_len)
            {
                fprintf(stderr, "failed to read event data completely\n");
                free(event_buf);
                fclose(fin);
                fclose(fout);
                return -1;
            }
        }

        memset(out, 0, sizeof(out));
        ret = get_whole_event((const struct nod_event_hdr *)event_buf, out, sizeof(out));
        if (ret > 0) {
            fprintf(fout, "%s\n", out);
        }
        free(event_buf);
    }

    fclose(fin);
    fclose(fout);
    return 0;
}

int build_default_log_name(const char *buf_file, char *log_file, size_t log_file_sz) {
    const char *dot;

    if (!buf_file || !log_file || log_file_sz == 0) {
        return -1;
    }

    dot = strrchr(buf_file, '.');
    if (dot && strcmp(dot, ".buf") == 0) {
        size_t prefix_len = (size_t)(dot - buf_file);

        if (prefix_len + 4 + 1 > log_file_sz) { /* ".log" + '\0' */
            return -1;
        }

        memcpy(log_file, buf_file, prefix_len);
        log_file[prefix_len] = '\0';
        strcat(log_file, ".log");
    }
    else {
        if (snprintf(log_file, log_file_sz, "%s.log", buf_file) >= (int)log_file_sz) {
            return -1;
        }
    }

    return 0;
}

int parse_buf_file(const char *buf_file, const char *log_file_opt) {
    char default_log[1024];
    const char *final_log;

    if (!buf_file) {
        fprintf(stderr, "buf_file is NULL\n");
        return -1;
    }

    if (log_file_opt && log_file_opt[0] != '\0') {
        final_log = log_file_opt;
    }
    else {
        if (build_default_log_name(buf_file, default_log, sizeof(default_log)) != 0) {
            fprintf(stderr, "failed to build default log filename\n");
            return -1;
        }
        final_log = default_log;
    }

    return parse_buf_to_log(buf_file, final_log);
}