#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "lua_runtime.h"

static lua_State *g_L = NULL;
static char g_script_buf[8192];
static volatile long long g_lua_return_value = 0;
static volatile int g_lua_exec_status = 0;

static int lua_load_script(const char *path, char *buf, size_t max) {
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    size_t total = 0;
    while (total < max) {
        size_t n = fread(buf + total, 1, max - total, fp);
        total += n;
        if (n == 0) break; // EOF
    }

    fclose(fp);
    return (int)total;
}

void lua_runtime_init(void) {
    if (g_L != NULL)
        return;

    g_L = luaL_newstate();
    if (!g_L) {
        g_lua_exec_status = -100;
        return;
    }

    luaL_openlibs(g_L);
}

static int lua_run_code(const char *code){
    printf("in lua run code\n");
    g_lua_return_value = 0;

    if (!g_L)
        lua_runtime_init();
    if (!g_L)
        return -101;
    printf("lua init success\n");
    
    if (luaL_loadbuffer(g_L, code, strlen(code), "script") != LUA_OK) {
        lua_pop(g_L, 1);
        g_lua_exec_status = -1;  // compile error
        return -1;
    }
    printf("lua compile success\n");

    if (lua_pcall(g_L, 0, 1, 0) != LUA_OK) {
        lua_pop(g_L, 1);
        g_lua_exec_status = -2;  // runtime error
        return -2;
    }

    printf("lua run success\n");


    if (lua_isinteger(g_L, -1)) {
        g_lua_return_value = lua_tointeger(g_L, -1);
    }

    lua_pop(g_L, 1);
    g_lua_exec_status = 0;
    printf("return value = %lld\n", g_lua_return_value);
    return 0;
}

int lua_run_script(const char *path)
{

    int sz = lua_load_script(path, g_script_buf, sizeof(g_script_buf) - 1);
    if (sz < 0) {
        g_lua_exec_status = -10;  // read fail
        return -10;
    }

    g_script_buf[sz] = '\0';
    return lua_run_code(g_script_buf);
}

long long lua_get_return_value(void)
{
    return g_lua_return_value;
}

int lua_get_exec_status(void)
{
    return g_lua_exec_status;
}
