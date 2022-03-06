#ifndef SPR_MONITOR_CONTEXT_H_
#define SPR_MONITOR_CONTEXT_H_

#include "events.h"
#include "common.h"

int main(struct spr_buffer *buffer);
void spr_monitor_init(int argc, char *argv[], char *env[], struct spr_buffer *buffer);
void spr_monitor_exit(int code);

#endif //SPR_MONITOR_CONTEXT_H_