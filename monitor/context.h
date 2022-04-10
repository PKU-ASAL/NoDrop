#ifndef NOD_MONITOR_CONTEXT_H_
#define NOD_MONITOR_CONTEXT_H_

#include "events.h"
#include "common.h"

#define NOD_MONITOR_MEM_SIZE (4 * 1024)

int main(char *mem, struct nod_buffer *buffer);
void nod_monitor_init(char *mem, int argc, char *argv[], char *env[]);
void nod_monitor_exit(char *mem, long code);

#endif //NOD_MONITOR_CONTEXT_H_