#ifndef NOD_MONITOR_CONTEXT_H_
#define NOD_MONITOR_CONTEXT_H_

#include "events.h"
#include "common.h"

int main();
void nod_monitor_init(int argc, char *argv[], char *env[]);
void nod_monitor_exit(int code);

extern int g_first_come_in;
extern struct nod_buffer * g_bufp;

#endif //NOD_MONITOR_CONTEXT_H_