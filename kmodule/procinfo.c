#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/signal.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/hashtable.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#include <linux/pid.h>
#include <linux/sched/signal.h>
#endif
#include <linux/pkeys.h>

#include "nodrop.h"
#include "procinfo.h"
#include "ioctl.h"

static struct kmem_cache *proc_info_cachep = NULL;

static DEFINE_READ_MOSTLY_HASHTABLE(proc_info_hl_head, 10);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
static DEFINE_MUTEX(nod_proc_info_mutex);
#endif

static void nod_proc_merge_overflow(struct nod_proc_info *p)
{
    struct nod_buffer *buf;
    struct nod_buffer_info *info;
    struct nod_event_hdr *hdr;
    uint32_t ev_len;

    if (!p)
        return;

    buf = &p->buffer;
    info = buf->info;
    if (!info || !buf->buffer || !buf->overflow.addr || !buf->overflow.filled)
        return;

    hdr = (struct nod_event_hdr *)buf->overflow.addr;
    ev_len = hdr->len;
    if (ev_len < sizeof(*hdr) || ev_len > PAGE_SIZE) {
        vpr_warn("invalid overflow event length %u for pid %d\n", ev_len, p->pid);
        buf->overflow.filled = 0;
        return;
    }

    if (info->tail == 0) {
        if (ev_len <= info->buffer_size) {
            memmove(buf->buffer, buf->overflow.addr, ev_len);
            info->tail = ev_len;
            info->nevents++;
        } else {
            vpr_warn("overflow event too large for buffer (%u > %lu), pid %d\n",
                     ev_len, info->buffer_size, p->pid);
        }
    } else if (info->tail + ev_len <= info->buffer_size) {
        memmove(buf->buffer + info->tail, buf->overflow.addr, ev_len);
        info->tail += ev_len;
        info->nevents++;
    } else {
        vpr_warn("buffer has no room for overflow event, pid %d tail=%u len=%u\n",
                 p->pid, info->tail, ev_len);
    }

    buf->overflow.filled = 0;
}

static inline struct nod_proc_info *
__find_proc_info(struct task_struct *task)
{
    struct nod_proc_info *p;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    mutex_lock(&nod_proc_info_mutex);
    hash_for_each_possible(proc_info_hl_head, p, rcu, task->pid) {
        if (p->pid == task->pid) {
            mutex_unlock(&nod_proc_info_mutex);
            return p;
        }
    }
    mutex_unlock(&nod_proc_info_mutex);
#else
    rcu_read_lock();
    hash_for_each_possible_rcu(proc_info_hl_head, p, rcu, task->pid) {
        if (p->pid == task->pid) {
            rcu_read_unlock();
            return p;
        }
    }
    rcu_read_unlock();
#endif

    return NULL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
static bool
__pid_alive(pid_t pid)
{
    struct task_struct *task;
    bool alive;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    alive = task && !(task->flags & PF_EXITING);
    rcu_read_unlock();

    return alive;
}
#endif

static inline int
__insert_proc_info(struct nod_proc_info *p)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    mutex_lock(&nod_proc_info_mutex);
    hash_add(proc_info_hl_head, &p->rcu, p->pid);
    mutex_unlock(&nod_proc_info_mutex);
#else
    hash_add_rcu(proc_info_hl_head, &p->rcu, p->pid);
#endif

    return true;
}

static void
__remove_proc_info(struct nod_proc_info *p)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    mutex_lock(&nod_proc_info_mutex);
    hash_del(&p->rcu);
    mutex_unlock(&nod_proc_info_mutex);
#else
    hash_del_rcu(&p->rcu);
    synchronize_rcu();
#endif
}

void
nod_init_procinfo(struct task_struct *task, struct nod_proc_info *p)
{
    p->pid = task->pid;
    p->mm = task->mm;

    p->ioctl_fd = -1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    p->load_addr = 0;
    p->interp_load_addr = 0;
#endif
    p->entry_addr = 0;

    if (p->stack_info.pkey > 0) mm_pkey_free(p->mm, p->stack_info.pkey);

    memset(&p->ctx, 0, sizeof(p->ctx));
    memset(&p->sec, 0, sizeof(p->sec));
    memset(&p->stack_info, 0, sizeof(p->stack_info));

    p->stack_info.pkey = mm_pkey_alloc(p->mm);
}

struct nod_proc_info *
nod_alloc_procinfo(void)
{
    struct nod_proc_info *p;

    p = kmem_cache_alloc(proc_info_cachep, GFP_KERNEL);
    if (!p) {
        vpr_err("allocate nod_proc_info failed\n");
        goto out;
    }

    memset(p, 0, sizeof(struct nod_proc_info));
    INIT_LIST_HEAD(&p->daemon_node);

    if(init_buffer(&p->buffer)) {
        vpr_err("allocate kernel buffer for nod_proc_info failed\n");
        goto out_free_cache;
    }

    return p;

out_free_cache:
    kmem_cache_free(proc_info_cachep, p);
out:
    return NULL;
}

void
nod_free_procinfo(struct nod_proc_info *p)
{
    free_buffer(&p->buffer);
    kmem_cache_free(proc_info_cachep, p);
}

struct nod_proc_info *
nod_proc_acquire(enum nod_proc_status status,
                 enum nod_proc_status *pre,
                 int ioctl_fd,
                 struct task_struct *task)
{
    struct nod_proc_info *p;
    // nanoseconds start, end;

    p = __find_proc_info(task);
    if (p) {
        goto success;
    }

    // start = nod_nsecs();
    p = nod_alloc_procinfo();
    if (!p) {
        if (pre) *pre = NOD_UNKNOWN;
        goto out;
    }

    nod_init_procinfo(task, p);
    // end = nod_nsecs();
    // pr_info("%llu\n", end - start);

    ASSERT(__insert_proc_info(p) == true);

success:
    if (pre)    *pre = p->status;
    nod_proc_set_status(p, status, ioctl_fd);
out:
    return p;
}

enum nod_proc_status
nod_proc_release(struct task_struct *task)
{
    int retval, ret;
    struct nod_proc_info *p;

    p = __find_proc_info(task);
    if (!p) {
        return NOD_UNKNOWN;
    }

    retval = p->status;
    nod_proc_merge_overflow(p);
    per_cpu(g_stat, smp_processor_id()).n_drop_evts_unsolved += p->buffer.info->nevents;

    __remove_proc_info(p);

    if (p->buffer.info->tail > 0) {
        ret = nod_daemon_submit_proc(p);
        if (!ret) {
            return retval;
        }
        vpr_warn("daemon queue failed (%d), drop residual logs for pid %d\n", ret, p->pid);
    }
    nod_free_procinfo(p);

    return retval;
}

int
nod_copy_procinfo(struct task_struct *task, struct nod_proc_info *p)
{
    struct nod_proc_info *parent;

    if (!task->real_parent)
        return NOD_SUCCESS;

    parent = __find_proc_info(task->group_leader);

    if (parent) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
        p->load_addr = parent->load_addr;
        p->interp_load_addr = parent->interp_load_addr;
#endif
        p->entry_addr = parent->entry_addr;
        memcpy(&p->stack_info, &parent->stack_info, sizeof(struct nod_stack_info));
    }

    return NOD_SUCCESS;
}

int
nod_share_procinfo(struct task_struct *task, struct nod_proc_info *p)
{
    struct nod_proc_info *parent;

    if (!task->real_parent)
        return NOD_SUCCESS;

    parent = __find_proc_info(task->group_leader);
    if (parent) {
        /*
         * Pkey is previously allocated when acquiring nod_proc_info
         * Now the process is inherited from parent, including pkey
         * Free the original pkey here.
         */
        if (p->stack_info.pkey != parent->stack_info.pkey) {
            if (p->stack_info.pkey > 0) mm_pkey_free(p->mm, p->stack_info.pkey);
            p->stack_info.pkey = parent->stack_info.pkey;
        }
    }

    return NOD_SUCCESS;
}

int
nod_event_from(struct nod_proc_info **p)
{
    struct nod_proc_info *n = NULL;

    n = __find_proc_info(current);

    if (p)  *p = n;
    return n ? n->status : NOD_OUT;
}

unsigned long
nod_proc_traverse(int (*func)(struct nod_proc_info *, unsigned long *, va_list), ...)
{
    int fb, bkt;
    unsigned long ret;
    va_list args;
    struct nod_proc_info *p;
    ret = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    mutex_lock(&nod_proc_info_mutex);
    hash_for_each(proc_info_hl_head, bkt, p, rcu) {
        va_start(args, func);
        fb = func(p, &ret, args);
        va_end(args);
        switch (fb) {
        case NOD_PROC_TRAVERSE_BREAK:
            goto out_unlock;
        default:
            break;
        }
    }

out_unlock:
    mutex_unlock(&nod_proc_info_mutex);
#else
    rcu_read_lock();
    hash_for_each_rcu(proc_info_hl_head, bkt, p, rcu) {
        va_start(args, func);
        fb = func(p, &ret, args);
        va_end(args);
        switch(fb) {
        case NOD_PROC_TRAVERSE_BREAK:
            goto out_rcu;
        default:
            break;
        }
    }

out_rcu:
    rcu_read_unlock();
#endif

    return ret;
}

int
procinfo_init(void)
{
    int retval;

    proc_info_cachep = kmem_cache_create("nod_proc_info_cache", sizeof(struct nod_proc_info), 0, 0, NULL);
    if (proc_info_cachep == NULL) {
        retval = -ENOMEM;
        goto out;
    }

    retval = 0;
out:
    return retval;
}

void
procinfo_destroy(void)
{
    int bkt;
    struct nod_proc_info *this;
    struct hlist_node *tmp;

    if (!proc_info_cachep) return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    mutex_lock(&nod_proc_info_mutex);
    hash_for_each_safe(proc_info_hl_head, bkt, tmp, this, rcu) {
        while(this->status == NOD_IN) {
            if (!__pid_alive(this->pid)) {
                pr_warn("force release stale procinfo (pid %d status %d)\n",
                        this->pid, this->status);
                break;
            }
            pr_info("wait for exiting monitor (pid %d status %d)\n",
                    this->pid, this->status);
            msleep(5);
        }
        hash_del(&this->rcu);
        nod_free_procinfo(this);
    }
    mutex_unlock(&nod_proc_info_mutex);
#else
    rcu_read_lock();
    hash_for_each_safe(proc_info_hl_head, bkt, tmp, this, rcu) {
        while(this->status == NOD_IN) {
            pr_info("wait for exiting monitor (pid %d status %d)\n",
                    this->pid, this->status);
            msleep(5);
        }
        hash_del_rcu(&this->rcu);
        nod_free_procinfo(this);
    }
    rcu_read_unlock();
#endif

    kmem_cache_destroy(proc_info_cachep);
}
