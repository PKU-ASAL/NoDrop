#include "lua_runtime.h"

#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static lua_State *g_L = NULL;
static char g_script_buf[8192];

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
}

void decode_event(const struct nod_event_hdr *hdr, struct lua_event *evt)
{
    const struct nod_event_info *info;
    const struct nod_param_info *param;
    struct lua_event_param *dst;
    uint16_t *args;
    char *data;
    memset(evt, 0, sizeof(*evt));
    if (hdr->type < 0 || hdr->type >= NODE_EVENT_MAX)
        return;

    info = &g_event_info[hdr->type];
    evt->type = info->name;
    evt->tid = hdr->tid;
    evt->cpu = hdr->cpuid;
    evt->time = hdr->ts;
    evt->dir = '?'; // TODO

    evt->nparams = info->nparams;
    args = (uint16_t *)(hdr + 1);
    data = (char *)(args + info->nparams);
    for (int i = 0; i < evt->nparams; i++)
    {
        param = &info->params[i];
        dst = &evt->params[i];
        dst->name = param->name;
        switch (param->type)
        {
        case PT_CHARBUF:
        case PT_FSPATH:
        case PT_FSRELPATH:
        case PT_BYTEBUF:
            dst->type = LUA_ARG_STR;
            dst->v.str.ptr = data;
            dst->v.str.len = args[i];
            break;

        case PT_FLAGS8:
        case PT_UINT8:
        case PT_SIGTYPE:
            dst->type = LUA_ARG_UINT;
            dst->v.u64 = *(uint8_t *)data;
            break;

        case PT_FLAGS16:
        case PT_UINT16:
        case PT_SYSCALLID:
            dst->type = LUA_ARG_UINT;
            dst->v.u64 = *(uint16_t *)data;
            break;

        case PT_FLAGS32:
        case PT_UINT32:
        case PT_MODE:
        case PT_UID:
        case PT_GID:
        case PT_SIGSET:
            dst->type = LUA_ARG_UINT;
            dst->v.u64 = *(uint32_t *)data;
            break;

        case PT_RELTIME:
        case PT_ABSTIME:
        case PT_UINT64:
            dst->type = LUA_ARG_UINT;
            dst->v.u64 = *(uint64_t *)data;
            break;

        case PT_INT8:
            dst->type = LUA_ARG_INT;
            dst->v.i64 = *(int8_t *)data;
            break;

        case PT_INT16:
            dst->type = LUA_ARG_INT;
            dst->v.i64 = *(int16_t *)data;
            break;

        case PT_INT32:
            dst->type = LUA_ARG_INT;
            dst->v.i64 = *(int32_t *)data;
            break;

        case PT_INT64:
        case PT_ERRNO:
        case PT_FD:
        case PT_PID:
            dst->type = LUA_ARG_INT;
            dst->v.i64 = *(int64_t *)data;
            break;

        default:
            dst->type = LUA_ARG_NONE;
            break;
        }
        data += args[i];
    }
}

void update_global_evt(lua_State *L, const struct lua_event *evt)
{
    lua_getglobal(L, "evt");
    if (!lua_istable(L, -1))
    {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_setglobal(L, "evt");
        lua_getglobal(L, "evt");
    }

    for (size_t i = 0; i < g_evt_fields_count; i++)
    {
        const evt_field_descriptor *fd = &g_evt_fields[i];
        const void *field_ptr = (const char *)evt + fd->offset;

        switch (fd->type)
        {

        case EVT_FLD_STRING:
        {
            const char *s = *(const char **)field_ptr;
            if (s)
                lua_pushstring(L, s);
            else
                lua_pushnil(L);
            break;
        }

        case EVT_FLD_UINT32:
            lua_pushinteger(L, (lua_Integer)(*(const uint32_t *)field_ptr));
            break;

        case EVT_FLD_UINT64:
            lua_pushinteger(L, (lua_Integer)(*(const uint64_t *)field_ptr));
            break;

        case EVT_FLD_CHAR:
        {
            char c = *(const char *)field_ptr;
            char buf[2] = {c, '\0'};
            lua_pushstring(L, buf);
            break;
        }

        default:
            lua_pushnil(L);
            break;
        }

        lua_setfield(L, -2, fd->name); // evt[field_name] = value
    }

    lua_newtable(L); // evt.args
    for (uint32_t i = 0; i < evt->nparams; i++)
    {
        const struct lua_event_param *p = &evt->params[i];
        if (!p->name)
            continue;

        lua_pushstring(L, p->name); // key

        switch (p->type)
        {
        case LUA_ARG_INT:
            lua_pushinteger(L, p->v.i64);
            break;

        case LUA_ARG_UINT:
            lua_pushinteger(L, (lua_Integer)p->v.u64);
            break;

        case LUA_ARG_STR:
            lua_pushlstring(L, p->v.str.ptr ? p->v.str.ptr : "", p->v.str.len);
            break;

        default:
            lua_pushnil(L);
            break;
        }
        lua_settable(L, -3); // args[name] = value
    }
    lua_setfield(L, -2, "args");

    lua_pop(L, 1);
}

void lua_on_event(const struct lua_event *evt)
{
    if (!g_L)
        return;

    update_global_evt(g_L, evt);

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

int lua_run_script(const char *path)
{
    if (lua_load_script(path) < 0)
        return -1;
    int ret = lua_run_code(g_script_buf);
    lua_on_init();
    return ret;
}

int lua_is_inited()
{
    return g_L != NULL;
}
