#include <linux/rbtree.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/signal.h>
#include <linux/fs_struct.h>

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
        n = rb_entry(*new, struct nod_proc_info, node);
        parent = *new;
        if (p->pid < n->pid)
            new = &parent->rb_left;
        else if (p->pid > n->pid)
            new = &parent->rb_right;
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

    ASSERT(status == NOD_IN);

    p = kmem_cache_alloc(proc_info_cachep, GFP_KERNEL);
    if (!p) {
        goto out;
    }

    down_write(&proc_info_rt.sem);
    ASSERT(__insert_proc_info(&proc_info_rt.root, p) == true);
    up_write(&proc_info_rt.sem);

    p->pid = task->pid;
    memset(&p->stack, 0, sizeof(p->stack));

success:
    p->ioctl_fd = ioctl_fd;
    p->status = status;
    if (buffer) {
        memcpy(&p->buffer, buffer, sizeof(p->buffer));
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
    kmem_cache_free(proc_info_cachep, p);
    return retval;
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

void
nod_copy_context(const struct pt_regs *regs)
{
    struct nod_proc_info *p;
    struct nod_proc_context *ctxp;

    down_read(&proc_info_rt.sem);
    p = __find_proc_info(&proc_info_rt.root, current);
    up_read(&proc_info_rt.sem);

    ASSERT(p != NULL);
    ctxp = &p->ctx;

    // no one will delete our rbnode
    ctxp->fsbase = current->thread.FSBASE;
    ctxp->gsbase = current->thread.GSBASE;
    ctxp->seccomp_mode = nod_get_seccomp();
    ctxp->cap_effective = current_cred()->cap_effective;
    ctxp->cap_permitted = current_cred()->cap_permitted;
    get_fs_root(current->fs, &ctxp->root_path);
    sigprocmask(-1, 0, &ctxp->sigset);
    memcpy(ctxp->rlim, current->signal->rlim, sizeof(ctxp->rlim));
    memcpy(&ctxp->regs, regs, sizeof(*regs));

    p->stack.nr = regs->orig_ax;
    p->stack.code = regs->di;
    
    pr_info("%d %d\n", regs->orig_ax, regs->di);
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