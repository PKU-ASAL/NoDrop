#ifndef NODROP_LUA_RUNTIME_H
#define NODROP_LUA_RUNTIME_H

#include <stddef.h>
#include "events.h"

#define LUA_MAX_EVENT_PARAMS NOD_MAX_EVENT_PARAMS

enum lua_arg_type {
    LUA_ARG_NONE = 0,
    LUA_ARG_INT,
    LUA_ARG_UINT,
    LUA_ARG_STR,
};
struct lua_event_param {
    const char *name;         // 参数名，比如 "fd", "size", "filename"
    enum lua_arg_type type;   // 简化后的类型
    union {
        int64_t  i64;
        uint64_t u64;
        const char *str;
    } v;
};

struct lua_event {
    const char *type;      // e.g. "open", "read"
    uint32_t tid;    // thread id
    uint32_t cpu;    // cpu id
    char dir;        // direction: '>' or '<' (TODO)
    uint64_t time;     // timestamp in ns

    uint32_t nparams;
    struct lua_event_param params[LUA_MAX_EVENT_PARAMS];
};

typedef enum {
    EVT_FLD_STRING,
    EVT_FLD_UINT32,
    EVT_FLD_UINT64,
    EVT_FLD_CHAR
} evt_field_type;

typedef struct {
    const char *name;
    evt_field_type type;
    size_t offset;
} evt_field_descriptor;

static const evt_field_descriptor g_evt_fields[] = {
    { "type", EVT_FLD_STRING, offsetof(struct lua_event, type) },
    { "tid",  EVT_FLD_UINT32, offsetof(struct lua_event, tid)  },
    { "cpu",  EVT_FLD_UINT32, offsetof(struct lua_event, cpu)  },
    { "dir",  EVT_FLD_CHAR,   offsetof(struct lua_event, dir)  },
    { "time",   EVT_FLD_UINT64, offsetof(struct lua_event, time)   },
};
static const size_t g_evt_fields_count = sizeof(g_evt_fields) / sizeof(g_evt_fields[0]);

void decode_event(const struct nod_event_hdr *hdr, struct lua_event *evt);

int lua_load_script(const char *path);
void lua_runtime_init(void);


void lua_on_event(const struct lua_event *evt);
void lua_on_init();
int lua_run_script(const char *path);


#endif  // NODROP_LUA_RUNTIME_H
