#ifndef NOD_MONITOR_CONTEXT_H_
#define NOD_MONITOR_CONTEXT_H_

#include "events.h"
#include "common.h"

#define NOD_MONITOR_MEM_SIZE (4 * 1024)

int main();
void nod_monitor_init(char *mem, int argc, char *argv[], char *env[]);
void nod_monitor_exit(char *mem, long code);
void nod_monitor_enter(char *mem);
void nod_monitor_return(char *mem);

#endif //NOD_MONITOR_CONTEXT_H_