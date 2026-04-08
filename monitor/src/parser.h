
#ifndef NODROP_PARSER_H
#define NODROP_PARSER_H

#include "common.h"


#define MAX_EVENT_STR 2048

int evt_arg_to_string(const struct nod_param_info *param, const void *data, uint16_t len,
                      char *buf, size_t bufsz);

int get_whole_event(const struct nod_event_hdr *hdr, char *out, int mx_size);

int parse_buf_file(const char *buf_file, const char *log_file_opt);
#endif // NODROP_PARSER_H
