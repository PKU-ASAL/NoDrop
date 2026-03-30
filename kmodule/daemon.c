#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/timekeeping.h>
#include <linux/slab.h>

#include "nodrop.h"
#include "config.h"

#define NOD_DAEMON_NAME "nodrop-daemon"
#define NOD_PATH_LEN 128

static struct task_struct *daemon_task;
static LIST_HEAD(pending_list);
static DEFINE_SPINLOCK(pending_lock);
static DECLARE_WAIT_QUEUE_HEAD(pending_wq);

static inline bool nod_has_pending_locked(void)
{
    return !list_empty(&pending_list);
}

static inline bool nod_has_pending(void)
{
    bool has_pending;
    unsigned long flags;

    spin_lock_irqsave(&pending_lock, flags);
    has_pending = nod_has_pending_locked();
    spin_unlock_irqrestore(&pending_lock, flags);

    return has_pending;
}

static struct nod_proc_info *nod_pop_pending_proc(void)
{
    struct nod_proc_info *p = NULL;
    unsigned long flags;

    spin_lock_irqsave(&pending_lock, flags);
    if (!list_empty(&pending_list)) {
        p = list_first_entry(&pending_list, struct nod_proc_info, daemon_node);
        list_del_init(&p->daemon_node);
    }
    spin_unlock_irqrestore(&pending_lock, flags);

    return p;
}

static int
nod_write_all(struct file *file, const void *buf, size_t len, loff_t *pos)
{
    const char *ptr = buf;
    ssize_t n;

    while (len > 0) {
        n = kernel_write(file, ptr, len, pos);
        if (n <= 0)
            return n ? (int)n : -EIO;
        ptr += n;
        len -= n;
    }

    return 0;
}

static int
nod_write_str(struct file *file, loff_t *pos, const char *s)
{
    return nod_write_all(file, s, strlen(s), pos);
}

static int
nod_write_fmt(struct file *file, loff_t *pos, const char *fmt, ...)
{
    int len;
    va_list ap;
    char tmp[256];

    va_start(ap, fmt);
    len = vscnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);

    if (len <= 0)
        return 0;

    return nod_write_all(file, tmp, len, pos);
}

static int
nod_write_param_scalar(struct file *file,
                       loff_t *pos,
                       enum nod_param_type type,
                       enum nod_print_format fmt,
                       const char *data)
{
    switch (type) {
    case PT_FLAGS8:
    case PT_UINT8:
    case PT_SIGTYPE:
        switch (fmt) {
        case PF_HEX:
            return nod_write_fmt(file, pos, "0x%x", *(const uint8_t *)data);
        case PF_10_PADDED_DEC:
            return nod_write_fmt(file, pos, "%010d", (int8_t)(*(const uint8_t *)data));
        case PF_OCT:
            return nod_write_fmt(file, pos, "0%o", *(const uint8_t *)data);
        case PF_DEC:
        default:
            return nod_write_fmt(file, pos, "%u", *(const uint8_t *)data);
        }

    case PT_FLAGS16:
    case PT_UINT16:
    case PT_SYSCALLID:
        switch (fmt) {
        case PF_HEX:
            return nod_write_fmt(file, pos, "0x%x", *(const uint16_t *)data);
        case PF_10_PADDED_DEC:
            return nod_write_fmt(file, pos, "%010u", *(const uint16_t *)data);
        case PF_OCT:
            return nod_write_fmt(file, pos, "0%o", *(const uint16_t *)data);
        case PF_DEC:
        default:
            return nod_write_fmt(file, pos, "%u", *(const uint16_t *)data);
        }

    case PT_FLAGS32:
    case PT_UINT32:
    case PT_MODE:
    case PT_UID:
    case PT_GID:
    case PT_SIGSET:
        switch (fmt) {
        case PF_HEX:
            return nod_write_fmt(file, pos, "0x%x", *(const uint32_t *)data);
        case PF_10_PADDED_DEC:
            return nod_write_fmt(file, pos, "%010u", *(const uint32_t *)data);
        case PF_OCT:
            return nod_write_fmt(file, pos, "0%o", *(const uint32_t *)data);
        case PF_DEC:
        default:
            return nod_write_fmt(file, pos, "%u", *(const uint32_t *)data);
        }

    case PT_RELTIME:
    case PT_ABSTIME:
    case PT_UINT64:
        switch (fmt) {
        case PF_HEX:
            return nod_write_fmt(file, pos, "0x%llx", *(const uint64_t *)data);
        case PF_10_PADDED_DEC:
            return nod_write_fmt(file, pos, "%010llu", *(const uint64_t *)data);
        case PF_OCT:
            return nod_write_fmt(file, pos, "0%llo", *(const uint64_t *)data);
        case PF_DEC:
        default:
            return nod_write_fmt(file, pos, "%llu", *(const uint64_t *)data);
        }

    case PT_INT8:
        switch (fmt) {
        case PF_HEX:
            return nod_write_fmt(file, pos, "0x%x", *(const int8_t *)data);
        case PF_10_PADDED_DEC:
            return nod_write_fmt(file, pos, "%010d", *(const int8_t *)data);
        case PF_OCT:
            return nod_write_fmt(file, pos, "0%o", *(const int8_t *)data);
        case PF_DEC:
        default:
            return nod_write_fmt(file, pos, "%d", *(const int8_t *)data);
        }

    case PT_INT16:
        switch (fmt) {
        case PF_HEX:
            return nod_write_fmt(file, pos, "0x%x", *(const int16_t *)data);
        case PF_10_PADDED_DEC:
            return nod_write_fmt(file, pos, "%010d", *(const int16_t *)data);
        case PF_OCT:
            return nod_write_fmt(file, pos, "0%o", *(const int16_t *)data);
        case PF_DEC:
        default:
            return nod_write_fmt(file, pos, "%d", *(const int16_t *)data);
        }

    case PT_INT32:
        switch (fmt) {
        case PF_HEX:
            return nod_write_fmt(file, pos, "0x%x", *(const int32_t *)data);
        case PF_10_PADDED_DEC:
            return nod_write_fmt(file, pos, "%010d", *(const int32_t *)data);
        case PF_OCT:
            return nod_write_fmt(file, pos, "0%o", *(const int32_t *)data);
        case PF_DEC:
        default:
            return nod_write_fmt(file, pos, "%d", *(const int32_t *)data);
        }

    case PT_INT64:
    case PT_ERRNO:
    case PT_FD:
    case PT_PID:
        switch (fmt) {
        case PF_HEX:
            return nod_write_fmt(file, pos, "0x%llx", *(const int64_t *)data);
        case PF_10_PADDED_DEC:
            return nod_write_fmt(file, pos, "%010lld", *(const int64_t *)data);
        case PF_OCT:
            return nod_write_fmt(file, pos, "0%llo", *(const int64_t *)data);
        case PF_DEC:
        default:
            return nod_write_fmt(file, pos, "%lld", *(const int64_t *)data);
        }

    default:
        return nod_write_str(file, pos, "<unknown>");
    }
}

static int
nod_dump_event(struct file *file,
               loff_t *pos,
               struct nod_event_hdr *hdr,
               char *payload)
{
    uint32_t i;
    int retval;
    const struct nod_event_info *info;
    const struct nod_param_info *param;
    uint16_t *args;
    char *data;

    if (hdr->type >= NODE_EVENT_MAX)
        return -EINVAL;

    info = &g_event_info[hdr->type];
    args = (uint16_t *)payload;
    data = (char *)(args + info->nparams);

    retval = nod_write_fmt(file, pos, "%llu %u (%u): %s(",
                           hdr->ts, hdr->tid, hdr->cpuid, info->name);
    if (retval)
        return retval;

    for (i = 0; i < info->nparams; ++i) {
        param = &info->params[i];
        if (i > 0) {
            retval = nod_write_str(file, pos, ", ");
            if (retval)
                return retval;
        }

        retval = nod_write_fmt(file, pos, "%s=", param->name);
        if (retval)
            return retval;

        switch (param->type) {
        case PT_CHARBUF:
        case PT_FSPATH:
        case PT_FSRELPATH:
        case PT_BYTEBUF:
            retval = nod_write_all(file, data, args[i], pos);
            break;
        default:
            retval = nod_write_param_scalar(file, pos, param->type, param->fmt, data);
            break;
        }

        if (retval)
            return retval;

        data += args[i];
    }

    return nod_write_str(file, pos, ")\n");
}

static void
nod_flush_proc_buffer(struct nod_proc_info *p)
{
    loff_t pos = 0;
    int retval;
    char path[NOD_PATH_LEN];
    struct file *file;
    char *ptr;
    char *buf_end;
    struct nod_event_hdr *hdr;
    uint64_t ts_us;

    if (!p || !p->buffer.info)
        return;

    if (p->buffer.info->tail == 0 || !p->buffer.buffer)
        return;

    ts_us = div_u64(ktime_get_real_ns(), 1000);
    scnprintf(path, sizeof(path), CONFIG_STORE_PATH "/%u-%llu.buf", p->pid, ts_us);

    file = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(file)) {
        vpr_err("daemon open %s failed (%ld)\n", path, PTR_ERR(file));
        return;
    }

    ptr = p->buffer.buffer;
    buf_end = ptr + p->buffer.info->tail;

    while (ptr + sizeof(struct nod_event_hdr) <= buf_end) {
        hdr = (struct nod_event_hdr *)ptr;
        if (hdr->len < sizeof(struct nod_event_hdr) ||
            ptr + hdr->len > buf_end)
            break;
        retval = nod_dump_event(file, &pos, hdr, (char *)(hdr + 1));
        if (retval)
            break;
        p->buffer.info->n_solved_evts++;
        ptr += hdr->len;
    }

    filp_close(file, NULL);
    p->buffer.info->nevents = 0;
    p->buffer.info->tail = 0;
}

static int
nod_daemon_loop(void *unused)
{
    struct nod_proc_info *p;

    while (!kthread_should_stop()) {
        wait_event_interruptible(pending_wq,
                                 kthread_should_stop() || nod_has_pending());

        while ((p = nod_pop_pending_proc()) != NULL) {
            nod_flush_proc_buffer(p);
            nod_free_procinfo(p);
        }
    }

    while ((p = nod_pop_pending_proc()) != NULL) {
        nod_flush_proc_buffer(p);
        nod_free_procinfo(p);
    }

    return 0;
}

int
nod_daemon_submit_proc(struct nod_proc_info *p)
{
    unsigned long flags;

    if (!p)
        return -EINVAL;

    if (!daemon_task)
        return -ENODEV;

    spin_lock_irqsave(&pending_lock, flags);
    if (list_empty(&p->daemon_node))
        list_add_tail(&p->daemon_node, &pending_list);
    spin_unlock_irqrestore(&pending_lock, flags);

    wake_up_interruptible(&pending_wq);
    return 0;
}

int
nod_daemon_init(void)
{
    int retval;

    daemon_task = kthread_run(nod_daemon_loop, NULL, NOD_DAEMON_NAME);
    if (IS_ERR(daemon_task)) {
        retval = PTR_ERR(daemon_task);
        daemon_task = NULL;
        return retval;
    }

    return 0;
}

void
nod_daemon_destroy(void)
{
    if (daemon_task) {
        kthread_stop(daemon_task);
        daemon_task = NULL;
    }
}