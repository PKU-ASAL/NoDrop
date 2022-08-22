#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/signal.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/hashtable.h>
#include <linux/pkeys.h>


#include "nodrop.h"
#include "procinfo.h"
#include "ioctl.h"

static struct kmem_cache *proc_info_cachep = NULL;

static DEFINE_READ_MOSTLY_HASHTABLE(proc_info_hl_head, 10);

static inline struct nod_proc_info *
__find_proc_info(struct task_struct *task)
{
    struct nod_proc_info *p;

    rcu_read_lock();
    hash_for_each_possible_rcu(proc_info_hl_head, p, rcu, task->pid) {
        if (p->pid == task->pid) {
            rcu_read_unlock();
            return p;
        }
    }
    rcu_read_unlock();
    return NULL;
}

static inline int
__insert_proc_info(struct nod_proc_info *p)
{
    hash_add_rcu(proc_info_hl_head, &p->rcu, p->pid);

    return true;
}

static void
__remove_proc_info(struct nod_proc_info *p)
{
    hash_del_rcu(&p->rcu);
    synchronize_rcu();
}

void
nod_init_procinfo(struct task_struct *task, struct nod_proc_info *p)
{
    p->pid = task->pid;
    p->mm = task->mm;

    p->ioctl_fd = -1;
    p->load_addr = 0;

    if (p->stack.pkey > 0) mm_pkey_free(p->mm, p->stack.pkey);

    memset(&p->ctx, 0, sizeof(p->ctx));
    memset(&p->sec, 0, sizeof(p->sec));
    memset(&p->stack, 0, sizeof(p->stack));

    p->stack.pkey = mm_pkey_alloc(p->mm);
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

    p = __find_proc_info(task);
    if (p) {
        goto success;
    }

    p = nod_alloc_procinfo();
    if (!p) {
        if (pre) *pre = NOD_UNKNOWN;
        goto out;
    }

    nod_init_procinfo(task, p);

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
    int retval;
    struct nod_proc_info *p;

    p = __find_proc_info(task);
    if (!p) {
        return NOD_UNKNOWN;
    }

    retval = p->status;
    per_cpu(g_stat, smp_processor_id()).n_drop_evts_unsolved += p->buffer.info->nevents;

    __remove_proc_info(p);
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
        p->load_addr = parent->load_addr;
        memcpy(&p->stack, &parent->stack, sizeof(struct nod_stack_info));
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
        if (p->stack.pkey != parent->stack.pkey) {
            if (p->stack.pkey > 0) mm_pkey_free(p->mm, p->stack.pkey);
            p->stack.pkey = parent->stack.pkey;
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
    
    rcu_read_lock();
    hash_for_each_rcu(proc_info_hl_head, bkt, p, rcu) {
        va_start(args, func);
        fb = func(p, &ret, args);
        va_end(args);
        switch(fb) {
        case NOD_PROC_TRAVERSE_BREAK:
            goto out;
            break;
        default:
            break;
        }
    }

out:
    rcu_read_unlock();
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
    if(proc_info_cachep) {
        rcu_read_lock();
        hash_for_each_safe(proc_info_hl_head, bkt, tmp, this, rcu) {
            while(this->status == NOD_IN) {
                pr_info("wait for exiting monitor (pid %d status %d)\n", this->pid, this->status);
                msleep(5);
            }
            nod_free_procinfo(this);
        }
        rcu_read_unlock();
        kmem_cache_destroy(proc_info_cachep);
    }
}
