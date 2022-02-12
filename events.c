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
    struct spr_buffer_info *buffer_info;
    struct spr_event_hdr *hdr;

    buffer_info = &buffer->info;
start:
    freespace = BUFFER_SIZE - buffer_info->tail;

    args.nargs = g_event_info[event_type].nparams;
    args.arg_data_offset = args.nargs * sizeof(uint16_t);

    if (freespace < args.arg_data_offset + sizeof(struct spr_event_hdr)) {
        restart = 1;
        goto loading;
    }

    hdr = (struct spr_event_hdr *)(buffer->buffer + buffer_info->tail);
    hdr->ts = ts;
    hdr->tid = current->pid;
    hdr->type = event_type;
    hdr->nargs = args.nargs;
    hdr->magic = SPR_EVENT_HDR_MAGIC & 0xFFFFFFFF;

    args.buf_ptr = buffer->buffer + buffer_info->tail + sizeof(struct spr_event_hdr);
    args.buffer_size = freespace - sizeof(struct spr_event_hdr);
    args.event_type = event_type;

    if (event_datap->category == SPRC_SYSCALL) {
        args.reg = event_datap->event_info.syscall_data.reg;
        args.syscall_nr = event_datap->event_info.syscall_data.id;
        do_exit_syscall = SYSCALL_EXIT_FAMILY(syscall_get_nr(current, args.reg));
    } else {
        args.reg = NULL;
        args.syscall_nr = -1;
    }

    args.curarg = 0;
    args.arg_data_size = args.buffer_size - args.arg_data_offset;
    args.nevents = buffer_info->nevents;
    args.snaplen = 16; // temporary MAGIC number

    for(cbret = 0; cbret < args.nargs; ++cbret) {
        *(((uint16_t *)args.buf_ptr) + cbret) = 0;
    }

    cbret = g_spr_events[event_type].filler_callback(&args);
    if (cbret == SPR_SUCCESS) {
        if (likely(args.curarg == args.nargs)) {
            event_size = sizeof(struct spr_event_hdr) + args.arg_data_offset;
            hdr->len = event_size;
            /*
            * Make sure all the memory has been written in real memory before
            * we update the head and the user space process (on another CPU)
            * can access the buffer.
            */
            smp_wmb();
            buffer_info->tail += event_size;
            ++buffer_info->nevents;
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
        spr_init_buffer_info(buffer_info);
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

int event_buffer_init(void) {
    int cpu;
    for_each_present_cpu(cpu) {
        struct spr_kbuffer *bufp = &per_cpu(buffer, cpu);
        bufp->buffer = vmalloc(BUFFER_SIZE);
        if (bufp->buffer == NULL) {
            pr_err("event_buffer: cannot allocate buffer for cpu %d (size 0x%xB)\n", cpu, BUFFER_SIZE);
            return -ENOMEM;
        }
        spr_init_buffer_info(&bufp->info);
        bufp->event_count = 0;
        spin_lock_init(&bufp->lock);
    }
    return 0;
}

void event_buffer_destory(void) {
    int cpu;
    for_each_present_cpu(cpu) {
        struct spr_kbuffer *bufp = &per_cpu(buffer, cpu);
        if (bufp->buffer)
            vfree(bufp->buffer);
    }
}

int record_one_event(enum spr_event_type type, struct spr_event_data *event_datap) {
    int cpu, retval;
    struct spr_kbuffer *bufp;
    nanoseconds ts = spr_nsecs();

    cpu = get_cpu();
    bufp = &per_cpu(buffer, cpu);
    spin_lock(&bufp->lock);
    // pr_info("(%d) %d get buffer\n", smp_processor_id(), current->pid);

    // spin_lock(&lock);
    retval = do_record_one_event(bufp, type, ts, event_datap);
    if (retval != SPR_SUCCESS) {
        pr_warn("record_one_event: one event log dropped, reason=%d\nnevents=%lld tail=0x%x\n",
                retval,
                bufp->info.nevents, bufp->info.tail);
    }
    // spin_unlock(&lock);

    // pr_info("(%d) %d put buffer\n", smp_processor_id(), current->pid);
    spin_unlock(&bufp->lock);
    put_cpu();
    return retval;
}


void spr_init_buffer_info(struct spr_buffer_info *info) {
    info->nevents = 0;
    info->tail = 0;
    smp_wmb();
}