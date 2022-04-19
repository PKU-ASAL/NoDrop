#include <linux/rbtree.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/signal.h>
#include <linux/random.h>

#include "nodrop.h"
#include "procinfo.h"


static struct kmem_cache *proc_info_cachep = NULL;

struct {
    struct rb_root root;
    struct rw_semaphore sem;
} proc_info_rt;

static inline struct nod_proc_info *
__find_proc_info(struct rb_root *rt, struct task_struct *task)
{
    struct rb_node *n;
    struct nod_proc_info *p;

    for (n = rt->rb_node; n; ) {
        p = rb_entry(n, struct nod_proc_info, node);
        if (task->pid < p->pid)
            n = n->rb_left;
        else if (task->pid > p->pid)
            n = n->rb_right;
        else {
            return p;
        }
    }
    return NULL;
}

static inline int
__insert_proc_info(struct rb_root *rt, struct nod_proc_info *p)
{
    struct nod_proc_info *n;
    struct rb_node **new = &rt->rb_node, *parent = NULL;
    while (*new) {
        parent = *new;
        n = rb_entry(parent, struct nod_proc_info, node);
        if (p->pid < n->pid)
            new = &(*new)->rb_left;
        else if (p->pid > n->pid)
            new = &(*new)->rb_right;
        else
            return false;
    }

    rb_link_node(&p->node, parent, new);
    rb_insert_color(&p->node, rt);
    smp_mb();
    return true;
}

struct nod_proc_info *
nod_set_status(enum nod_proc_status status, 
            enum nod_proc_status *pre,
            int ioctl_fd, 
            const struct nod_kbuffer *buffer,
            struct task_struct *task)
{
    struct nod_proc_info *p;

    down_read(&proc_info_rt.sem);
    p = __find_proc_info(&proc_info_rt.root, task);
    up_read(&proc_info_rt.sem);
    if (p) {
        goto success;
    }

    p = kmem_cache_alloc(proc_info_cachep, GFP_KERNEL);
    if (!p) {
        if (pre)    *pre = NOD_UNKNOWN;
        goto out;
    }
    memset(p, 0, sizeof(struct nod_proc_info));

    /* TODO: lazy allocation
     *  - Only allocate buffer when it is needed */
    p->buffer = vmalloc_user(sizeof(struct nod_buffer));
    if (!p->buffer) {
        kmem_cache_free(proc_info_cachep, p);
        p = NULL;
        if (pre)    *pre = NOD_UNKNOWN;
        goto out;
    }

    p->pid = task->pid;
    p->mm = task->mm;
    p->stack.memoff = (unsigned long)get_random_int();
    p->stack.memoff &= NOD_MEM_RND_MASK;

    down_write(&proc_info_rt.sem);
    ASSERT(__insert_proc_info(&proc_info_rt.root, p) == true);
    up_write(&proc_info_rt.sem);

success:
    p->ioctl_fd = ioctl_fd;
    if (pre)    *pre = p->status;
    p->status = status;
    if (buffer && p->buffer) {
        copy_to_user_buffer(buffer, p->buffer);
    }

out:
    return p;
}

enum nod_proc_status
nod_free_status(struct task_struct *task)
{
    int retval;
    struct nod_proc_info *p;

    down_read(&proc_info_rt.sem);
    p = __find_proc_info(&proc_info_rt.root, task);
    up_read(&proc_info_rt.sem);
    if (!p) {
        return NOD_UNKNOWN;
    }

    down_write(&proc_info_rt.sem);
    rb_erase(&p->node, &proc_info_rt.root);
    smp_mb();
    up_write(&proc_info_rt.sem);

    retval = p->status;
    p->ctx.available = p->sec.available = 0;

    if(p->buffer) vfree(p->buffer);
    kmem_cache_free(proc_info_cachep, p);

    return retval;
}

int
nod_copy_procinfo(struct task_struct *task, struct nod_proc_info *p)
{
    struct nod_proc_info *parent;

    if (!task->real_parent) 
        return NOD_SUCCESS;

    down_read(&proc_info_rt.sem);
    parent = __find_proc_info(&proc_info_rt.root, task->real_parent);
    up_read(&proc_info_rt.sem);

    if (parent) {
        p->load_addr = parent->load_addr;
        memcpy(&p->stack, &parent->stack, sizeof(struct nod_stack_info));
    }
    
    return NOD_SUCCESS;    
}

int
nod_event_from(struct nod_proc_info **p)
{
    struct nod_proc_info *n = NULL;

    down_read(&proc_info_rt.sem);
    n = __find_proc_info(&proc_info_rt.root, current);
    up_read(&proc_info_rt.sem);

    if (p)  *p = n;    
    return n ? n->status : NOD_OUT;
}

/* traverse RBTree to find procs with the same address
 * and check (addr, length) */
int
nod_proc_check_mm(struct nod_proc_info *p, unsigned long addr, unsigned long length)
{
    unsigned long end = addr + length;
    struct nod_proc_info *this;
    struct rb_node *n = rb_first(&proc_info_rt.root);
    while(n) {
        this = rb_entry(n, struct nod_proc_info, node);
        n = rb_next(n);
        if (this->stack.mem == 0 || this->stack.memsz == 0)
            continue;
        if (this->mm == p->mm) {
            if ((unsigned long)this->stack.mem <= addr && addr < (unsigned long)this->stack.mem + this->stack.memsz)   return 1;
            if ((unsigned long)this->stack.mem <= end && end < (unsigned long)this->stack.mem + this->stack.memsz)   return 1;
        }
    }
    return 0;
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

    proc_info_rt.root = RB_ROOT;
    init_rwsem(&proc_info_rt.sem);

    retval = 0;
out:
    return retval;
}

void
procinfo_destroy(void)
{
    if(proc_info_cachep) {
        kmem_cache_destroy(proc_info_cachep);
    }
}