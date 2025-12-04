#ifndef NODROP_LUA_RUNTIME_H
#define NODROP_LUA_RUNTIME_H

#include <stddef.h>
#include "events.h"

#define LUA_SET_STR(L, k, v)  \
    do { lua_pushstring(L, v); lua_setfield(L, -2, k); } while(0)

#define LUA_SET_INT(L, k, v)  \
    do { lua_pushinteger(L, v); lua_setfield(L, -2, k); } while(0)

struct lua_event {
    const char *type;
    uint32_t tid;
};

void decode_event(const struct nod_event_hdr *hdr, struct lua_event *evt);

int lua_load_script(const char *path);
void lua_runtime_init(void);


void lua_on_event(const struct lua_event *evt);
int lua_run_script(const char *path);


#endif  // NODROP_LUA_RUNTIME_H
