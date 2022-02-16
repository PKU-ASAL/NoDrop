#include "include/events.h"
#include "include/fillers.h"
#include "pinject.h"

#define FILLER_REF(x) f_##x, SPR_FILLER_##x

const struct spr_event_entry g_spr_events[SPRE_EVENT_MAX] = {
    [SPRE_SYSCALL_READ] = {FILLER_REF(sys_read)},
    [SPRE_SYSCALL_WRITE] = {FILLER_REF(sys_write)},
    [SPRE_SYSCALL_OPEN] = {FILLER_REF(sys_open)},
    [SPRE_SYSCALL_CLOSE] = {FILLER_REF(sys_single)},
    [SPRE_SYSCALL_EXIT] = {FILLER_REF(sys_exit)},
    [SPRE_SYSCALL_EXIT_GROUP] = {FILLER_REF(sys_exit_group)}
};