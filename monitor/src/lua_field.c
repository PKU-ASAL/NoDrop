#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "lua_field.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "config.h"
#include "parser.h"
#include "common.h"

static struct nod_field_desc g_fields[NOD_MAX_FIELDS];
static int g_nr_fields = 0;

static struct lua_event *g_current_evt = NULL;

static char save_log_path[100];
void set_log_path(struct timeval tv, unsigned int tid) {
    sprintf((char *)save_log_path, CONFIG_STORE_PATH"/%u-%ld.log", tid, tv.tv_sec * SECOND_IN_US + tv.tv_usec);
}

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

void push_arg_as_string(lua_State *L, const struct nod_event_hdr *hdr, const char *arg_name)
{
    static char buf[256];

    size_t i;
    const struct nod_event_info *info;
    const struct nod_param_info *param;
    uint16_t *args;
    char *data;

    if (!hdr || !arg_name) {
        lua_pushnil(L);
        return;
    }

    if (hdr->type < 0 || hdr->type >= NODE_EVENT_MAX) {
        lua_pushnil(L);
        return;
    }

    info = &g_event_info[hdr->type];
    args = (uint16_t *)(hdr + 1);
    data = (char *)(args + info->nparams);

    for (i = 0; i < info->nparams; ++i) {
        param = &info->params[i];

        if (strcmp(param->name, arg_name) == 0) {
            evt_arg_to_string(param, data, args[i],
                              buf, sizeof(buf));
            lua_pushstring(L, buf);
            return;
        }
        data += args[i];
    }

    lua_pushnil(L);
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
 * Lua API: evt.send(ip, port)
 * ============================================================ */
static int lua_evt_send(lua_State *L)
{
    const char *ip;
    int port;

    const struct nod_event_hdr *hdr;

    char out[2048];
    int off = 0;

    int fd;
    struct sockaddr_in addr;

    ip   = luaL_checkstring(L, 1);
    port = luaL_checkinteger(L, 2);

    if (!g_current_evt || !g_current_evt->raw)
        return 0;

    hdr = g_current_evt->raw;

    if (hdr->type < 0 || hdr->type >= NODE_EVENT_MAX)
        return 0;

    off = get_whole_event(hdr, out, sizeof(out));
    
    /* ----------------------------
     * UDP send
     * ---------------------------- */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;

    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    sendto(fd, out, off, 0,
           (struct sockaddr *)&addr,
           sizeof(addr));

    close(fd);

    return 0;  /* Lua: no return value */
}

/* ============================================================
 * Lua API: evt.save()
 * ============================================================ */
static int lua_evt_save(lua_State *L)
{

    const struct nod_event_hdr *hdr;

    char out[MAX_EVENT_STR];
    int off = 0;

    FILE *fp;

    if (!g_current_evt || !g_current_evt->raw)
        return 0;

    hdr = g_current_evt->raw;

    if (hdr->type < 0 || hdr->type >= NODE_EVENT_MAX)
        return 0;

    off = get_whole_event(hdr, out, sizeof(out));
    
    fp = fopen(save_log_path, "a");
    
    if (!fp) {
        return 0;
    }

    fwrite(out, 1, (size_t)off, fp);
    fclose(fp);

    return 0;
}
/* ============================================================
 * Lua registration
 * ============================================================ */

void lua_field_register_api(lua_State *L)
{
    /* chisel table */
    lua_newtable(L);
    lua_pushcfunction(L, lua_request_field);
    lua_setfield(L, -2, "request_field");
    lua_setglobal(L, "chisel");

    /* evt table*/
    lua_newtable(L);
    /* evt.field(index) */
    lua_pushcfunction(L, lua_evt_field);
    lua_setfield(L, -2, "field");
    /* evt.send(ip, port)*/
    lua_pushcfunction(L, lua_evt_send);
    lua_setfield(L, -2, "send");
    /* evt.save()*/
    lua_pushcfunction(L, lua_evt_save);
    lua_setfield(L, -2, "save");
    lua_setglobal(L, "evt");
    
}
