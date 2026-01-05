#ifndef NODROP_LUA_RUNTIME_H
#define NODROP_LUA_RUNTIME_H

#include <stddef.h>

#include "lua_field.h"
#include "ioctl.h"

void lua_on_event(struct lua_event *evt);
void lua_on_init();

void lua_runtime_init(void);

/*
load xxx.lua , save code into g_script_buf and run code
*/
int lua_run_script(struct nod_lua_state *global_state);

#endif // NODROP_LUA_RUNTIME_H
