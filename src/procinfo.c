#include <linux/rbtree.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/signal.h>
#include <linux/random.h>
#include <linux/delay.h>


#include "nodrop.h"
#include "procinfo.h"


static struct kmem_cache *proc_info_cachep = NULL;

struct {
    struct rb_root root;
    struct list_head list;
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
__insert_proc_info(struct nod_proc_info *p)
{
    struct nod_proc_info *n;
    struct rb_node **new, *parent = NULL;
    down_write(&proc_info_rt.sem);

    new = &proc_info_rt.root.rb_node;
    while (*new) {
        parent = *new;
        n = rb_entry(parent, struct nod_proc_info, node);
        if (p->pid < n->pid)
            new = &(*new)->rb_left;
        else if (p->pid > n->pid)
            new = &(*new)->rb_right;
        else {
            up_write(&proc_info_rt.sem);
            return false;
        }
    }

    list_add(&p->list, &proc_info_rt.list);

    rb_link_node(&p->node, parent, new);
    rb_insert_color(&p->node, &proc_info_rt.root);
    smp_mb();

    up_write(&proc_info_rt.sem);
    return true;
}

static void
__remove_proc_info(struct nod_proc_info *p)
{
    down_write(&proc_info_rt.sem);

    list_del(&p->list);
    rb_erase(&p->node, &proc_info_rt.root);
    smp_mb();

    up_write(&proc_info_rt.sem);
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

    p->ubuffer = vmalloc_user(sizeof(struct nod_buffer));
    if (!p->ubuffer) {
        vpr_err("allocate user buffer for nod_proc_info failed\n");
        goto out_free_cache;
    }

    if(init_buffer(&p->buffer)) {
        vpr_err("allocate kernel buffer for nod_proc_info failed\n");
        goto out_free_buffer;
    }

    return p;

out_free_buffer:
    vfree(p->ubuffer);
out_free_cache:
    kmem_cache_free(proc_info_cachep, p);
out:
    return NULL;
}

void
nod_free_procinfo(struct nod_proc_info *p)
{
    free_buffer(&p->buffer);
    vfree(p->ubuffer);
    kmem_cache_free(proc_info_cachep, p);
}

struct nod_proc_info *
nod_proc_acquire(enum nod_proc_status status, 
            enum nod_proc_status *pre,
            int ioctl_fd, 
            struct task_struct *task)
{
    struct nod_proc_info *p;

    down_read(&proc_info_rt.sem);
    p = __find_proc_info(&proc_info_rt.root, task);
    up_read(&proc_info_rt.sem);
    if (p) {
        goto success;
    }

    p = nod_alloc_procinfo();
    if (!p) {
        if (pre) *pre = NOD_UNKNOWN;
        goto out;
    }

    p->pid = task->pid;
    p->mm = task->mm;
    p->stack.memoff = (unsigned long)get_random_int();
    p->stack.memoff &= NOD_MEM_RND_MASK;

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

    down_read(&proc_info_rt.sem);
    p = __find_proc_info(&proc_info_rt.root, task);
    up_read(&proc_info_rt.sem);
    if (!p) {
        return NOD_UNKNOWN;
    }

    retval = p->status;

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

static int
__proc_check_mm(struct nod_proc_info *this, unsigned long *ret, va_list args)
{
    struct nod_proc_info *p = va_arg(args, struct nod_proc_info *);
    unsigned long addr = va_arg(args, unsigned long);
    unsigned long end = va_arg(args, unsigned long);
    if (this != p && 
        this->stack.mem && 
        this->stack.memsz && 
        this->mm == p->mm) {
        *ret = MAX((unsigned long)this->stack.mem, addr) <= 
            MIN((unsigned long)this->stack.mem + this->stack.memsz, end) ? 1L : 0L;
        return NOD_PROC_TRAVERSE_BREAK;
    }

    *ret = 0;
    return NOD_PROC_TRAVERSE_CONTINUE;
}

/* traverse RBTree to find procs with the same address
 * and check (addr, addr+length) */
int
nod_proc_check_mm(struct nod_proc_info *p, unsigned long addr, unsigned long length)
{
    unsigned long end = addr + length;
    return (int)nod_proc_traverse(__proc_check_mm, p, addr, end);
}

unsigned long
nod_proc_traverse(int (*func)(struct nod_proc_info *, unsigned long *, va_list), ...)
{
    int fb;
    unsigned long ret;
    va_list args;
    struct rb_node *n;

    down_write(&proc_info_rt.sem);
    for (n = rb_first(&proc_info_rt.root); n; n = rb_next(n)) {
        va_start(args, func);
        fb = func(rb_entry(n, struct nod_proc_info, node), &ret, args);
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
    up_write(&proc_info_rt.sem);
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

    INIT_LIST_HEAD(&proc_info_rt.list);
    proc_info_rt.root = RB_ROOT;
    init_rwsem(&proc_info_rt.sem);

    retval = 0;
out:
    return retval;
}

void
procinfo_destroy(void)
{
    struct list_head *pos, *npos;
    struct nod_proc_info *this;
    if(proc_info_cachep) {
        down_write(&proc_info_rt.sem);
        list_for_each_safe(pos, npos, &proc_info_rt.list) {
            this = list_entry(pos, struct nod_proc_info, list);
            while(this->status == NOD_IN || 
                this->status == NOD_RESTORE_CONTEXT || 
                this->status == NOD_RESTORE_SECURITY) {
                vpr_info("wait for exiting monitor (pid %d status %d)\n", this->pid, this->status);
                msleep(5);
            }
            nod_free_procinfo(this);
        }
        up_write(&proc_info_rt.sem);
        kmem_cache_destroy(proc_info_cachep);
    }
}