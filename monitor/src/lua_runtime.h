#ifndef NODROP_LUA_RUNTIME_H
#define NODROP_LUA_RUNTIME_H

#include <stddef.h>
#include "events.h"

struct lua_event {
    const char *type;      // e.g. "open", "read"
    uint32_t tid;    // thread id
    uint32_t pid;    // process id
    char dir;        // direction: '>' or '<'
    uint64_t ts;     // timestamp in ns
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
    { "pid",  EVT_FLD_UINT32, offsetof(struct lua_event, pid)  },
    { "dir",  EVT_FLD_CHAR,   offsetof(struct lua_event, dir)  },
    { "ts",   EVT_FLD_UINT64, offsetof(struct lua_event, ts)   },
};
static const size_t g_evt_fields_count = sizeof(g_evt_fields) / sizeof(g_evt_fields[0]);

void decode_event(const struct nod_event_hdr *hdr, struct lua_event *evt);

int lua_load_script(const char *path);
void lua_runtime_init(void);


void lua_on_event(const struct lua_event *evt);
void lua_on_init();
int lua_run_script(const char *path);


#endif  // NODROP_LUA_RUNTIME_H
