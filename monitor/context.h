#ifndef SPR_MONITOR_CONTEXT_H_
#define SPR_MONITOR_CONTEXT_H_

#include "events.h"
#include "common.h"

int main();
void spr_monitor_init(int argc, char *argv[], char *env[]);
void spr_monitor_exit(int code);

extern int g_first_come_in;
extern struct spr_buffer * g_bufp;

#endif //SPR_MONITOR_CONTEXT_H_