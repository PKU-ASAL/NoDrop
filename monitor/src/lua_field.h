#ifndef __NODROP_LUA_FIELD_H__
#define __NODROP_LUA_FIELD_H__

#include <stdint.h>
#include "events.h"

struct lua_State;

struct lua_event {
    const struct nod_event_hdr *raw;
};

/* ===============================
 * Field descriptor
 * =============================== */

#define NOD_MAX_FIELDS     16
#define NOD_MAX_ARG_NAME   32

enum nod_field_kind {
    NOD_FLD_EVT_TIME = 0,
    NOD_FLD_EVT_TYPE,
    NOD_FLD_EVT_TID,
    NOD_FLD_EVT_ARG,      /* evt.arg.xxx */
};

struct nod_field_desc {
    enum nod_field_kind kind;

    /* only valid when kind == NOD_FLD_EVT_ARG */
    char arg_name[NOD_MAX_ARG_NAME];
};

/* ===============================
 * API exposed to runtime
 * =============================== */

/* set current event before calling Lua on_event() */
void lua_field_set_current_event(struct lua_event *evt);

/* register Lua APIs:
 *   - chisel.request_field()
 *   - evt.field()
 */
void lua_field_register_api(struct lua_State *L);

#endif /* __NODROP_LUA_FIELD_H__ */
