#ifndef SPR_FILLER_H_
#define SPR_FILLER_H_

struct event_filler_arguments;

#define FILLER_LIST_MAPPER(FN) \
    FN(sys_open)        \
    FN(sys_close)       \
    FN(sys_read)        \
    FN(sys_write)       \
    FN(sys_exit)        \
    FN(sys_exit_group) 

#define FILLER_ENUM_FN(x) SPR_FILLER_##x,
enum spr_filler_id {
    FILLER_LIST_MAPPER(FILLER_ENUM_FN)
    SPR_FILLER_MAX
};
#undef FILLER_ENUM_FN

#define FILLER_PROTOTYPE_FN(x) \
    int f_##x(struct event_filler_arguments *args) __attribute__((weak));
FILLER_LIST_MAPPER(FILLER_PROTOTYPE_FN)
#undef FILLER_PROTOTYPE_FN


#endif //SPR_FILLER_H_