#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/semaphore.h>
#include <linux/vmalloc.h>


#include "nodrop.h"
#include "syscall.h"
#include "events.h"
#include "common.h"

static int 
do_record_one_event(struct nod_proc_info *p,
        enum nod_event_type event_type,
        nanoseconds ts,
        struct nod_event_data *event_datap)
{
    int cbret, restart;
    size_t event_size;
    uint32_t freespace; 
    struct event_filler_arguments args;
    struct nod_buffer_info *info;
    struct nod_event_hdr *hdr;
    struct nod_kbuffer *buffer;

    buffer = &p->buffer;
    info = buffer->info;

    down_write(&buffer->sem);

start:
    freespace = BUFFER_SIZE - info->tail;

    args.nargs = g_event_info[event_type].nparams;
    args.arg_data_offset = args.nargs * sizeof(uint16_t);

    if (freespace < args.arg_data_offset + sizeof(struct nod_event_hdr)) {
        restart = 1;
        goto loading;
    }

    hdr = (struct nod_event_hdr *)(buffer->buffer + info->tail);
    hdr->ts = ts;
    hdr->tid = current->pid;
    hdr->type = event_type;
    hdr->cpuid = smp_processor_id();
    hdr->nargs = args.nargs;
    hdr->magic = NOD_EVENT_HDR_MAGIC & 0xFFFFFFFF;

    args.buf_ptr = buffer->buffer + info->tail + sizeof(struct nod_event_hdr);
    args.buffer_size = freespace - sizeof(struct nod_event_hdr);
    args.event_type = event_type;
    args.str_storage = buffer->str_storage;

    if (event_datap->category == NODC_SYSCALL) {
        args.regs = event_datap->event_info.syscall_data.regs;
        args.syscall_nr = event_datap->event_info.syscall_data.id;
    } else {
        args.regs = NULL;
        args.syscall_nr = -1;
    }

    args.curarg = 0;
    args.arg_data_size = args.buffer_size - args.arg_data_offset;
    args.nevents = info->nevents;
    args.snaplen = 80; // temporary MAGIC number

    if (g_nod_events[event_type].filler_callback) {
        cbret = g_nod_events[event_type].filler_callback(&args);
    } else {
        pr_err("corrupted filler for event type %d: NULL callback\n", event_type);
        cbret = NOD_FAILURE_BUG;
        goto out;
    }

    if (cbret == NOD_SUCCESS) {
        if (likely(args.curarg == args.nargs)) {
            event_size = sizeof(struct nod_event_hdr) + args.arg_data_offset;

            hdr->len = event_size;
            info->tail += event_size;

            ++info->nevents;
            ++buffer->event_count;
        } else {
            pr_err("corrupted filler for event type %d (added %u args, should have added %u args)\n",
                    event_type,
                    args.curarg,
                    args.nargs);
        }
    } else if (cbret == NOD_FAILURE_BUFFER_FULL) {
        restart = 1;
        goto loading;
    }

out:
    up_write(&buffer->sem);
    return cbret; 

loading:
    if (nod_load_monitor(p) == NOD_SUCCESS) {
        reset_buffer(buffer, NOD_INIT_INFO);
        if (restart)
            goto start;
        else {
            cbret = NOD_SUCCESS_LOAD;
            goto out;
        }
    }

    cbret = NOD_FAILURE_BUG;
    goto out;
}

inline nanoseconds nod_nsecs(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
	return ktime_get_real_ns();
#else
	/* Don't have ktime_get_real functions */
	struct timespec ts;
	getnstimeofday(&ts);
	return SECOND_IN_NS * ts.tv_sec + ts.tv_nsec;
#endif
}

int
init_buffer(struct nod_kbuffer *buffer)
{
    int ret;
    unsigned int j;

    if (BUFFER_SIZE / PAGE_SIZE * PAGE_SIZE != BUFFER_SIZE) {
        ret = -EINVAL;
        pr_err("Buffer size is not a multiple of the page size\n");
        goto init_buffer_err;
    }

    buffer->str_storage = (char *)__get_free_page(GFP_USER);
    if (!buffer->str_storage) {
        ret = -ENOMEM;
		pr_err("Error allocating the string storage\n");
        goto init_buffer_err;
    }

    buffer->info = vmalloc(sizeof(struct nod_buffer_info));
    if (!buffer->info) {
        ret = -ENOMEM;
        pr_err("Error allocating buffer memory\n");
        goto init_buffer_err;
    }

    buffer->buffer = vmalloc(BUFFER_SIZE);
    if (!buffer->buffer) {
        ret = -ENOMEM;
        pr_err("Error allocating buffer memory\n");
        goto init_buffer_err;
    }

    for (j = 0; j < BUFFER_SIZE; ++j) {
        buffer->buffer[j] = 0;
    }

    reset_buffer(buffer, NOD_INIT_INFO | NOD_INIT_COUNT | NOD_INIT_LOCK);

    return 0;

init_buffer_err:
    free_buffer(buffer);
    return ret;
}

void
free_buffer(struct nod_kbuffer *buffer)
{
    if (buffer->info) {
        vfree(buffer->info);
        buffer->info = NULL;
    }

    if (buffer->buffer) {
        vfree(buffer->buffer);
        buffer->buffer = NULL;
    }

    if (buffer->str_storage) {
        free_page((unsigned long)buffer->str_storage);
        buffer->str_storage = NULL;
    }
}

void
reset_buffer(struct nod_kbuffer *buffer, int flags) 
{
    if (flags & NOD_INIT_INFO) {
        buffer->info->nevents = 0;
        buffer->info->tail = 0;
    }

    if (flags & NOD_INIT_COUNT)
        buffer->event_count = 0;

    if (flags & NOD_INIT_LOCK)
        init_rwsem(&buffer->sem);
}

int 
record_one_event(struct nod_proc_info *p, enum nod_event_type type, struct nod_event_data *event_datap) 
{
    int retval;
    nanoseconds ts = nod_nsecs();

    retval = do_record_one_event(p, type, ts, event_datap);
    if (retval < 0) {
        pr_warn("record_one_event: one event log dropped, reason=%d\nnevents=%lld tail=0x%x\n",
                retval,
                p->buffer.info->nevents, p->buffer.info->tail);
    }

    return retval;
}
