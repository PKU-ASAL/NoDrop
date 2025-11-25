#ifndef NODROP_LUA_RUNTIME_H
#define NODROP_LUA_RUNTIME_H

#include <stddef.h>


int lua_run_script(const char *path);

long long lua_get_return_value(void);
int lua_get_exec_status(void);

#endif  // NODROP_LUA_RUNTIME_H
