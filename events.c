#include <linux/version.h>
#include <linux/kernel.h>


#include "pinject.h"
#include "syscall.h"
#include "include/events.h"
#include "include/common.h"

static int 
do_record_one_event(struct spr_kbuffer *buffer,
        enum spr_event_type event_type,
        nanoseconds ts,
        struct spr_event_data *event_datap)
{
    int cbret, restart;
    int do_exit_syscall = 0;
    size_t event_size;
    uint32_t freespace; 
    struct event_filler_arguments args;
    struct spr_buffer_info *info;
    struct spr_event_hdr *hdr;

    info = buffer->info;
start:
    freespace = BUFFER_SIZE - info->tail;

    args.nargs = g_event_info[event_type].nparams;
    args.arg_data_offset = args.nargs * sizeof(uint16_t);

    if (freespace < args.arg_data_offset + sizeof(struct spr_event_hdr)) {
        restart = 1;
        goto loading;
    }

    hdr = (struct spr_event_hdr *)(buffer->buffer + info->tail);
    hdr->ts = ts;
    hdr->tid = current->pid;
    hdr->type = event_type;
    hdr->cpuid = smp_processor_id();
    hdr->nargs = args.nargs;
    hdr->magic = SPR_EVENT_HDR_MAGIC & 0xFFFFFFFF;

    args.buf_ptr = buffer->buffer + info->tail + sizeof(struct spr_event_hdr);
    args.buffer_size = freespace - sizeof(struct spr_event_hdr);
    args.event_type = event_type;
    args.str_storage = buffer->str_storage;

    if (event_datap->category == SPRC_SYSCALL) {
        args.regs = event_datap->event_info.syscall_data.regs;
        args.syscall_nr = event_datap->event_info.syscall_data.id;
        do_exit_syscall = SYSCALL_EXIT_FAMILY(syscall_get_nr(current, args.regs));
    } else {
        args.regs = NULL;
        args.syscall_nr = -1;
    }

    args.curarg = 0;
    args.arg_data_size = args.buffer_size - args.arg_data_offset;
    args.nevents = info->nevents;
    args.snaplen = 16; // temporary MAGIC number

    for(cbret = 0; cbret < args.nargs; ++cbret) {
        *(((uint16_t *)args.buf_ptr) + cbret) = 0;
    }

    if (g_spr_events[event_type].filler_callback) {
        cbret = g_spr_events[event_type].filler_callback(&args);
    } else {
        pr_err("corrupted filler for event type %d: NULL callback\n", event_type);
        ASSERT(0);
    }

    if (cbret == SPR_SUCCESS) {
        if (likely(args.curarg == args.nargs)) {
            event_size = sizeof(struct spr_event_hdr) + args.arg_data_offset;
            hdr->len = event_size;
            /*
            * Make sure all the memory has been written in real memory before
            * we update the tail and the user space process (on another CPU)
            * can access the buffer.
            */
            smp_wmb();
            info->tail += event_size;
            ++info->nevents;
            ++buffer->event_count;

            if (do_exit_syscall) {
                restart = 0;
                goto loading;
            }
        } else {
            pr_err("corrupted filler for event type %d (added %u args, should have added %u args)\n",
                    event_type,
                    args.curarg,
                    args.nargs);
        }
    } else if (cbret == SPR_FAILURE_BUFFER_FULL) {
        restart = 1;
        goto loading;
    }

    return cbret; 

loading:
    if (load_monitor(buffer) == LOAD_SUCCESS) {
        reset_buffer(buffer, SPR_INIT_INFO);
        if (restart)
            goto start;
        return SPR_SUCCESS;
    } else {
        return SPR_FAILURE_BUG;
    }
}

static inline nanoseconds spr_nsecs(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
	return ktime_get_real_ns();
#else
	/* Don't have ktime_get_real functions */
	struct timespec ts;
	getnstimeofday(&ts);
	return SECOND_IN_NS * ts.tv_sec + ts.tv_nsec;
#endif
}

int init_buffer(struct spr_kbuffer *buffer) {
    int ret;
    unsigned int j;

    buffer->str_storage = (char *)__get_free_page(GFP_USER);
    if (!buffer->str_storage) {
        ret = -ENOMEM;
		pr_err("Error allocating the string storage\n");
        goto init_buffer_err;
    }

    buffer->info = vmalloc(sizeof(struct spr_buffer_info));
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

    reset_buffer(buffer, SPR_INIT_INFO | SPR_INIT_COUNT | SPR_INIT_LOCK);

    pr_info("CPU buffer initialized, size = %d\n", BUFFER_SIZE);
    return 0;

init_buffer_err:
    free_buffer(buffer);
    return ret;
}

void free_buffer(struct spr_kbuffer *buffer) {
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

void reset_buffer(struct spr_kbuffer *buffer, int flags) {
    if (flags & SPR_INIT_INFO) {
        buffer->info->nevents = 0;
        buffer->info->tail = 0;
    }

    if (flags & SPR_INIT_COUNT)
        buffer->event_count = 0;

    if (flags & SPR_INIT_LOCK)
        mutex_init(&buffer->lock);
}

int event_buffer_init(void) {
    int cpu;
    int ret;
    for_each_present_cpu(cpu) {
        struct spr_kbuffer *bufp = &per_cpu(buffer, cpu);
        ret = init_buffer(bufp);
        if (ret != 0)
            return ret;
    }
    return 0;
}

void event_buffer_destory(void) {
    int cpu;
    for_each_present_cpu(cpu) {
        struct spr_kbuffer *bufp = &per_cpu(buffer, cpu);
        free_buffer(bufp);
    }
}

int record_one_event(enum spr_event_type type, struct spr_event_data *event_datap) {
    int cpu, retval;
    struct spr_kbuffer *bufp;
    nanoseconds ts = spr_nsecs();

    cpu = get_cpu();
    bufp = &per_cpu(buffer, cpu);
    mutex_lock(&bufp->lock);

    retval = do_record_one_event(bufp, type, ts, event_datap);
    if (retval != SPR_SUCCESS) {
        pr_warn("record_one_event: one event log dropped, reason=%d\nnevents=%lld tail=0x%x\n",
                retval,
                bufp->info->nevents, bufp->info->tail);
    }

    mutex_unlock(&bufp->lock);
    put_cpu();
    return retval;
}
