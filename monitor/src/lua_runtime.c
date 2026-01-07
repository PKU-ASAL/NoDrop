#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "lua_runtime.h"

static lua_State *g_L = NULL;
static char g_script_buf[8192];
static struct nod_lua_state run_state;

int lua_load_script(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    size_t size = 0, mx_size = sizeof(g_script_buf) - 1;
    while (size < mx_size)
    {
        size_t n = fread(g_script_buf + size, 1, mx_size - size, fp);
        size += n;
        if (n == 0)
            break; // EOF
    }

    fclose(fp);
    g_script_buf[size] = '\0';
    return 0;
}

void lua_runtime_init(void)
{
    if (g_L != NULL)
        return;

    g_L = luaL_newstate();
    if (!g_L)
    {
        printf("lua runtime init error");
        return;
    }

    luaL_openlibs(g_L);
    lua_field_register_api(g_L);

    run_state.lua_path[0] = '\0';
    run_state.lua_mtime = 0;
}

void lua_on_event(struct lua_event *evt)
{
    if (!g_L)
        return;
    lua_field_set_current_event(evt);

    lua_getglobal(g_L, "on_event");

    if (!lua_isfunction(g_L, -1))
    {
        lua_pop(g_L, 1);
        printf("can not find on_event\n");
        return;
    }

    if (lua_pcall(g_L, 0, 0, 0) != LUA_OK)
    {
        printf("[lua] on_event error: %s\n", lua_tostring(g_L, -1));
        lua_pop(g_L, 1);
    }
}

void lua_on_init()
{
    if (!g_L)
        return;

    lua_getglobal(g_L, "on_init");
    if (!lua_isfunction(g_L, -1))
    {
        lua_pop(g_L, 1);
        printf("can not find on_init\n");
        return;
    }

    if (lua_pcall(g_L, 0, 0, 0) != LUA_OK)
    {
        printf("[lua] on_init error: %s\n", lua_tostring(g_L, -1));
        lua_pop(g_L, 1);
    }
}



static int lua_run_code(const char *code)
{

    if (luaL_loadbuffer(g_L, code, strlen(code), "script") != LUA_OK)
    {
        lua_pop(g_L, 1);
        return -1;
    }

    if (lua_pcall(g_L, 0, 1, 0) != LUA_OK)
    {
        lua_pop(g_L, 1);
        return -2;
    }

    lua_pop(g_L, 1);
    return 0;
}

int lua_run_script(struct nod_lua_state *global_state)
{
    if (strcmp(global_state->lua_path, run_state.lua_path) == 0 &&
        global_state->lua_mtime == run_state.lua_mtime && run_state.lua_mtime != 0)
    {
        return 0;
    }
    strcpy(run_state.lua_path, global_state->lua_path);
    run_state.lua_mtime = global_state->lua_mtime; 
    if (lua_load_script(run_state.lua_path) < 0)
        return -1;
    int ret = lua_run_code(g_script_buf);
    lua_on_init();
    return ret;
}
