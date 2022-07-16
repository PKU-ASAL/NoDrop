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
    int cbret, restart, force;
    size_t event_size;
    uint32_t freespace; 
    struct event_filler_arguments args;
    struct nod_buffer_info *info;
    struct nod_event_hdr *hdr;
    struct nod_buffer *buffer;

    buffer = &p->buffer;
    info = buffer->info;

    down_write(&buffer->sem);
    
    if (unlikely(buffer->overflow.filled == 1)) {
        info->tail = ((struct nod_event_hdr *)buffer->overflow.addr)->len;
        ++info->nevents;
        ++buffer->event_count;

        memmove(buffer->buffer, buffer->overflow.addr, info->tail);
        buffer->overflow.filled = 0;
    }

    freespace = BUFFER_SIZE - info->tail;

    args.nargs = g_event_info[event_type].nparams;
    args.arg_data_offset = args.nargs * sizeof(uint16_t);

    force = event_datap->force;
    restart = 0;

restart:
    if (freespace < args.arg_data_offset + sizeof(struct nod_event_hdr) || restart) {
        // When the buffer is full, the next event log will temporarily write to the overflow page
        // The content of this page will be writen to buffer in the next syscall enter.
        hdr = (struct nod_event_hdr *)buffer->overflow.addr;
        args.buf_ptr = buffer->overflow.addr + sizeof(struct nod_event_hdr);
        args.buffer_size = PAGE_SIZE - sizeof(struct nod_event_hdr);
        
        force = 1;
        buffer->overflow.filled = 1;
    } else {
        hdr = (struct nod_event_hdr *)(buffer->buffer + info->tail);
        args.buf_ptr = buffer->buffer + info->tail + sizeof(struct nod_event_hdr);
        args.buffer_size = freespace - sizeof(struct nod_event_hdr);
    }

    if (!restart) {
        args.event_type = event_type;
        args.str_storage = buffer->str_storage;
        args.nevents = info->nevents;
        args.snaplen = 80; // temporary MAGIC number
        args.is_socketcall = false;

        if (event_datap->category == NODC_SYSCALL) {
            args.regs = event_datap->event_info.syscall_data.regs;
            args.syscall_nr = event_datap->event_info.syscall_data.id;
        } else {
            args.regs = NULL;
            args.syscall_nr = -1;
        }

    }

    args.curarg = 0;
    args.arg_data_size = args.buffer_size - args.arg_data_offset;

    hdr->ts = ts;
    hdr->tid = current->pid;
    hdr->type = event_type;
    hdr->cpuid = smp_processor_id();
    hdr->nargs = args.nargs;
    hdr->magic = NOD_EVENT_HDR_MAGIC & 0xFFFFFFFF;

    cbret = nod_filler_callback(&args);

    if (cbret == NOD_SUCCESS) {
        if (likely(args.curarg == args.nargs)) {
            event_size = sizeof(struct nod_event_hdr) + args.arg_data_offset;
            hdr->len = event_size;

            if (likely(buffer->overflow.filled == 0)) {
                info->tail += event_size;
                ++info->nevents;
                ++buffer->event_count;
            }
        } else {
            pr_err("corrupted filler for event type %d (added %u args, should have added %u args)\n",
                    event_type,
                    args.curarg,
                    args.nargs);
            force = 0;
        }
    } else if (cbret == NOD_FAILURE_BUFFER_FULL) {
        restart = 1;
        goto restart;
    }

    if (force) {
        cbret = nod_load_monitor(p);
    }

    up_write(&buffer->sem);
    return cbret; 
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
init_buffer(struct nod_buffer *buffer)
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
    
    buffer->overflow.addr = (char *)__get_free_page(GFP_KERNEL);
    if (!buffer->overflow.addr) {
        ret = -ENOMEM;
        pr_err("Error allocating the overflow page\n");
        goto init_buffer_err;
    }
    buffer->overflow.filled = 0;

    buffer->info = vmalloc_user(sizeof(struct nod_buffer_info));
    if (!buffer->info) {
        ret = -ENOMEM;
        pr_err("Error allocating buffer memory\n");
        goto init_buffer_err;
    }

    buffer->buffer = vmalloc_user(BUFFER_SIZE);
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
free_buffer(struct nod_buffer *buffer)
{
    if (buffer->info) {
        vfree(buffer->info);
        buffer->info = NULL;
    }

    if (buffer->buffer) {
        vfree(buffer->buffer);
        buffer->buffer = NULL;
    }
    
    if (buffer->overflow.addr) {
        free_page((unsigned long)buffer->overflow.addr);
        buffer->overflow.addr = 0;
        buffer->overflow.filled = 0;
    }

    if (buffer->str_storage) {
        free_page((unsigned long)buffer->str_storage);
        buffer->str_storage = NULL;
    }
}

void
reset_buffer(struct nod_buffer *buffer, int flags) 
{
    if (flags & NOD_INIT_INFO) {
        buffer->info->nevents = 0;
        buffer->info->tail = 0;
        buffer->overflow.filled = 0;
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
        pr_warn("(%u)record_one_event: event #%llu droopped, type=%u, reason=%d\n",
            smp_processor_id(), p->buffer.info->nevents, type, retval);
    }

    return retval;
}
