#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "lua_field.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static struct nod_field_desc g_fields[NOD_MAX_FIELDS];
static int g_nr_fields = 0;

static struct lua_event *g_current_evt = NULL;

void lua_field_set_current_event(struct lua_event *evt)
{
    g_current_evt = evt;
}

static void push_string(lua_State *L, const char *s)
{
    if (s)
        lua_pushstring(L, s);
    else
        lua_pushnil(L);
}

static void push_u64_as_string(lua_State *L, uint64_t v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%lu", (unsigned long)v);
    lua_pushstring(L, buf);
}

/* ============================================================
 * Lua API: chisel.request_field("evt.xxx" / "evt.arg.xxx")
 * ============================================================ */

static int lua_request_field(lua_State *L)
{
    const char *s = luaL_checkstring(L, 1);

    if (g_nr_fields >= NOD_MAX_FIELDS) {
        return luaL_error(
            L, "too many fields requested (max %d)",
            NOD_MAX_FIELDS);
    }

    struct nod_field_desc *f = &g_fields[g_nr_fields];
    memset(f, 0, sizeof(*f));

    /* fixed evt fields */
    if (strcmp(s, "evt.time") == 0) {
        f->kind = NOD_FLD_EVT_TIME;
    }
    else if (strcmp(s, "evt.type") == 0) {
        f->kind = NOD_FLD_EVT_TYPE;
    }
    else if (strcmp(s, "evt.tid") == 0) {
        f->kind = NOD_FLD_EVT_TID;
    }
    else if (strncmp(s, "evt.arg.", 8) == 0) {
        f->kind = NOD_FLD_EVT_ARG;
        strncpy(f->arg_name, s + 8, NOD_MAX_ARG_NAME - 1);
        f->arg_name[NOD_MAX_ARG_NAME - 1] = '\0';
    }
    else {
        return luaL_error(L, "unknown field: %s", s);
    }

    lua_pushinteger(L, g_nr_fields);
    g_nr_fields++;
    return 1;
}

/* ============================================================
 * Helper: extract evt.arg by name 
 * ============================================================ */

static const char *__print_format[PT_UINT64 + 1][PF_OCT + 1] = {
    [PT_NONE] = {"", "", "", "", ""},                                         /*empty*/
    [PT_INT8] = {"", "%" PRId8, "0x%" PRIx8, "%010" PRId8, "0%" PRIo8},       /*PT_INT8*/
    [PT_INT16] = {"", "%" PRId16, "0x%" PRIx16, "%010" PRId16, "0%" PRIo16},  /*PT_INT16*/
    [PT_INT32] = {"", "%" PRId32, "0x%" PRIx32, "%010" PRId32, "0%" PRIo32},  /*PT_INT32*/
    [PT_INT64] = {"", "%" PRId64, "0x%" PRIx64, "%010" PRId64, "0%" PRIo64},  /*PT_INT64*/
    [PT_UINT8] = {"", "%" PRIu8, "0x%" PRIx8, "%010" PRId8, "0%" PRIo8},      /*PT_UINT8*/
    [PT_UINT16] = {"", "%" PRIu16, "0x%" PRIx16, "%010" PRIu16, "0%" PRIo16}, /*PT_UINT16*/
    [PT_UINT32] = {"", "%" PRIu32, "0x%" PRIx32, "%010" PRIu32, "0%" PRIo32}, /*PT_UINT32*/
    [PT_UINT64] = {"", "%" PRIu64, "0x%" PRIx64, "%010" PRIu64, "0%" PRIo64}  /*PT_UINT64*/
};

void push_arg_as_string(lua_State *L, const struct nod_event_hdr *hdr, const char *arg_name)
{
    static char buf[256];

    size_t i;
    const struct nod_event_info *info;
    const struct nod_param_info *param;
    uint16_t *args;
    char *data;
    int n;

    if (!hdr || !arg_name) {
        lua_pushnil(L);
        return;
    }

    if (hdr->type < 0 || hdr->type >= NODE_EVENT_MAX) {
        lua_pushnil(L);
        return;
    }

    info = &g_event_info[hdr->type];
    if (!info) {
        lua_pushnil(L);
        return;
    }

    args = (uint16_t *)(hdr + 1);
    data = (char *)(args + info->nparams);

    for (i = 0; i < info->nparams; ++i)
    {
        param = &info->params[i];

        if (strcmp(param->name, arg_name) == 0)
        {
            switch (param->type)
            {
            case PT_CHARBUF:
            case PT_FSPATH:
            case PT_FSRELPATH:
            case PT_BYTEBUF:
                n = args[i];
                if (n >= (int)sizeof(buf))
                    n = sizeof(buf) - 1;
                memcpy(buf, data, n);
                buf[n] = '\0';
                lua_pushstring(L, buf);
                return;

            case PT_FLAGS8:
            case PT_UINT8:
            case PT_SIGTYPE:
                snprintf(buf, sizeof(buf),
                         __print_format[PT_UINT8][param->fmt],
                         *(uint8_t *)data);
                lua_pushstring(L, buf);
                return;

            case PT_FLAGS16:
            case PT_UINT16:
            case PT_SYSCALLID:
                snprintf(buf, sizeof(buf),
                         __print_format[PT_UINT16][param->fmt],
                         *(uint16_t *)data);
                lua_pushstring(L, buf);
                return;

            case PT_FLAGS32:
            case PT_UINT32:
            case PT_MODE:
            case PT_UID:
            case PT_GID:
            case PT_SIGSET:
                snprintf(buf, sizeof(buf),
                         __print_format[PT_UINT32][param->fmt],
                         *(uint32_t *)data);
                lua_pushstring(L, buf);
                return;

            case PT_RELTIME:
            case PT_ABSTIME:
            case PT_UINT64:
                snprintf(buf, sizeof(buf),
                         __print_format[PT_UINT64][param->fmt],
                         *(uint64_t *)data);
                lua_pushstring(L, buf);
                return;

            case PT_INT8:
                snprintf(buf, sizeof(buf),
                         __print_format[PT_INT8][param->fmt],
                         *(int8_t *)data);
                lua_pushstring(L, buf);
                return;

            case PT_INT16:
                snprintf(buf, sizeof(buf),
                         __print_format[PT_INT16][param->fmt],
                         *(int16_t *)data);
                lua_pushstring(L, buf);
                return;

            case PT_INT32:
                snprintf(buf, sizeof(buf),
                         __print_format[PT_INT32][param->fmt],
                         *(int32_t *)data);
                lua_pushstring(L, buf);
                return;

            case PT_INT64:
            case PT_ERRNO:
            case PT_FD:
            case PT_PID:
                snprintf(buf, sizeof(buf),
                         __print_format[PT_INT64][param->fmt],
                         *(int64_t *)data);
                lua_pushstring(L, buf);
                return;

            default:
                lua_pushstring(L, "<unknown>");
                return;
            }
        }

        /* move to next argument */
        data += args[i];
    }

    /* arg not found */
    lua_pushnil(L);
    return;
}


/* ============================================================
 * Lua API: evt.field(index)
 * ============================================================ */

static int lua_evt_field(lua_State *L)
{
    const struct nod_event_info *info;
    int idx = luaL_checkinteger(L, 1);

    if (!g_current_evt) {
        return luaL_error(L, "evt.field() called with no current event");
    }

    if (idx < 0 || idx >= g_nr_fields) {
        return luaL_error(L, "invalid field index %d", idx);
    }

    const struct nod_field_desc *f = &g_fields[idx];
    const struct nod_event_hdr *hdr = g_current_evt->raw;

    switch (f->kind) {

    case NOD_FLD_EVT_TIME:
        push_u64_as_string(L, hdr->ts);
        return 1;

    case NOD_FLD_EVT_TYPE:
        info = &g_event_info[hdr->type];
        push_string(L, info->name);
        return 1;

    case NOD_FLD_EVT_TID:
        push_u64_as_string(L, hdr->tid);
        return 1;

    case NOD_FLD_EVT_ARG:
        push_arg_as_string(L, hdr, f->arg_name);
        return 1;

    default:
        lua_pushnil(L);
        return 1;
    }
}

/* ============================================================
 * Lua registration
 * ============================================================ */

void lua_field_register_api(struct lua_State *L)
{
    /* chisel table */
    lua_newtable(L);
    lua_pushcfunction(L, lua_request_field);
    lua_setfield(L, -2, "request_field");
    lua_setglobal(L, "chisel");

    /* evt table (sysdig-style) */
    lua_newtable(L);
    lua_pushcfunction(L, lua_evt_field);
    lua_setfield(L, -2, "field");
    lua_setglobal(L, "evt");
}
