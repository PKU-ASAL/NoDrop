#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "lua_runtime.h"

static lua_State *g_L = NULL;
static char g_script_buf[8192];

int lua_load_script(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    size_t size = 0, mx_size = sizeof(g_script_buf) - 1;
    while (size < mx_size) {
        size_t n = fread(g_script_buf + size, 1, mx_size - size, fp);
        size += n;
        if (n == 0) break; // EOF
    }

    fclose(fp);
    g_script_buf[size] = '\0';
}

void lua_runtime_init(void) {
    if (g_L != NULL) return;

    g_L = luaL_newstate();
    if (!g_L) {
        printf("lua runtime init error");
        return;
    }

    luaL_openlibs(g_L);
}

void decode_event(const struct nod_event_hdr *hdr, struct lua_event *evt) {
    evt->type = g_event_info[hdr->type].name;
    evt->tid = hdr->tid;
}

void push_event_to_lua(lua_State *L, const struct lua_event *evt)
{
    // evt table
    lua_newtable(L);

    LUA_SET_STR(L, "type", evt->type);
    LUA_SET_INT(L, "tid", evt->tid);
    // TODO: other evt. 
}


void lua_on_event(const struct lua_event *evt){
    if (!g_L) return;

    lua_getglobal(g_L, "on_event");
    if (!lua_isfunction(g_L, -1)) {
        lua_pop(g_L, 1);
        printf("can not find on_event\n");
        return;
    }

    push_event_to_lua(g_L, evt);

    if (lua_pcall(g_L, 1, 0, 0) != LUA_OK) {
        printf("[lua] on_event error: %s\n", lua_tostring(g_L, -1));
        lua_pop(g_L, 1);
    }
}




static int lua_run_code(const char *code){
    
    if (luaL_loadbuffer(g_L, code, strlen(code), "script") != LUA_OK) {
        lua_pop(g_L, 1);
        return -1;
    }

    if (lua_pcall(g_L, 0, 1, 0) != LUA_OK) {
        lua_pop(g_L, 1);
        return -2;
    }

    long long return_value = 0;
    if (lua_isinteger(g_L, -1)) {
        return_value = lua_tointeger(g_L, -1);
    }

    lua_pop(g_L, 1);
    return 0;
}

int lua_run_script(const char *path)
{
    lua_load_script(path);
    return lua_run_code(g_script_buf);
}