#include <linux/elf.h>
#include <linux/file.h>
#include <linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/random.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/semaphore.h>
#include <linux/wait.h>

#include "pinject.h"
#include "include/common.h"
#include "include/events.h"


DEFINE_PER_CPU(struct spr_kbuffer, buffer);
EXPORT_PER_CPU_SYMBOL(buffer);

static struct elf_phdr *monitor_elf_phdata, *interp_elf_phdata;
static struct elfhdr   monitor_elf_ex, interp_elf_ex;
static struct file *monitor, *interpreter;

static struct kmem_cache *proc_status_cachep = NULL;
static struct kmem_cache *mm_wait_struct_cachep = NULL;

static struct spr_proc_status_root proc_root;

static struct spr_mm_wait_struct_root {
    struct rb_root root;
    struct rw_semaphore sem;
} mm_wait_root;
static struct spr_mm_wait_struct {
    struct mm_struct *mm;
    struct rb_node node;
    struct semaphore lock;
    wait_queue_head_t waitq;
    atomic_t count;
    int claimed;
};


static int
__check_mapping(struct vm_area_struct const * const vma, void *arg) {
    vm_flags_t flags = vma->vm_flags;
    if (flags & VM_EXEC) {
        *(unsigned long*)arg = vma->vm_start;
        return 1;
    }

    return 0;
}

static int
__put_monitor_info(struct vm_area_struct const * const vma, void *arg) {
    void **arr = (void **)arg;
    m_infopack __user *infopack;
    struct spr_kbuffer *buffer;

    if (vma->vm_flags & VM_EXEC)
        return 0;

    infopack = (m_infopack __user *)vma->vm_start;
    buffer = (struct spr_kbuffer *)arr[1];

    if (copy_to_user((void __user *)&infopack->m_context, (void *)arr[0], sizeof(infopack->m_context))) {
        vpr_err("cannot write __monitor_context @ %lx\n", &infopack->m_context);
        return 0;
    }

    if (copy_to_user((void __user *)&infopack->m_buffer.buffer, (void *)buffer->buffer, BUFFER_SIZE) ||
        copy_to_user((void __user *)&infopack->m_buffer.info, (void *)buffer->info, sizeof(struct spr_buffer_info))) {
        vpr_err("cannot write __monitor_logmsg @ %lx\n", &infopack->m_buffer);
        return 0;
    }
    
    vpr_info("transfer %lld logs of %u bytes\n", buffer->info->nevents, buffer->info->tail);

    return 1;
}

int
check_mapping(int (*resolve) (struct vm_area_struct const * const vma, void *arg),
              void *arg) {
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct file *file;

    mm = current->mm;

    down_read(&mm->mmap_sem);
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        file = vma->vm_file;
        if (file == monitor) {
            if ((*resolve)((struct vm_area_struct const * const)vma, arg)) {
                up_read(&mm->mmap_sem);
                return 0;
            }
        }
    }
    up_read(&mm->mmap_sem);

    return -1;
}

#define rb_traverse(root, ptr, type, member, cmd) \
do { \
    int count = 0; \
    struct rb_node *node = (root)->rb_node; \
    if (node) while (count < 100 && node->rb_left) { ptr = rb_entry(node, type, member); cmd; vpr_info("node %lx\n", node); node = node->rb_left; count++;} \
    vpr_info("---------------");\
    while(node) { \
        ptr = rb_entry(node, type, member); \
        cmd; \
        node = rb_next(node); \
    } \
} while(0)

#define __down_write(sem) \
do { vpr_dbg("down_write\n"); down_write(sem); vpr_dbg("get write\n"); } while(0)
#define __up_write(sem) \
do { up_write(sem);vpr_dbg("up_write\n"); } while(0)
#define __down(sem) \
do { vpr_dbg("down\n"); down(sem); vpr_dbg("get\n"); } while(0)
#define __up(sem) \
do { up(sem); vpr_dbg("up\n"); } while(0)
#define __down_read(sem) \
do { vpr_dbg("down_read\n"); down_read(sem); vpr_dbg("get read\n"); } while(0)
#define __up_read(sem) \
do { up_read(sem); vpr_dbg("up_read\n"); } while(0)
#define __down_write_trylock(sem) \
({ vpr_dbg("down_trywrite\n"); down_write_trylock(sem); })
#define __down_trylock(sem) \
({ vpr_dbg("down_trywrite\n"); down_trylock(sem); })

enum {
    UNLOCK,
    LOCKED
};

static inline int __claim_mm_try(struct spr_mm_wait_struct *wait_mm)
{
    int locked;
    vpr_dbg("try claim mm_wait mm=%llx\n", wait_mm->mm);
    locked = (down_trylock(&wait_mm->lock) == 0) ? LOCKED : UNLOCK;
    if (locked) {
        vpr_dbg("get mm_wait mm=%llx\n", wait_mm->mm);
        wait_mm->claimed = 1;
    }
    return locked;
}
static inline void __claim_mm(struct spr_mm_wait_struct *wait_mm)
{
    vpr_dbg("claim mm_wait mm=%llx\n", wait_mm->mm);
    down(&wait_mm->lock);
    vpr_dbg("get mm_wait mm=%llx\n", wait_mm->mm);
    wait_mm->claimed = 1;
}
static inline void __release_mm(struct spr_mm_wait_struct *wait_mm)
{
    wait_mm->claimed = 0;
    up(&wait_mm->lock);
    vpr_dbg("release mm_wait mm%llx\n", wait_mm->mm);
}
static inline int __wait_mm(struct spr_mm_wait_struct *wait_mm)
{
    return atomic_read(&wait_mm->count);
}

static inline int get_mm_wait_struct(struct spr_mm_wait_struct_root *rt, struct mm_struct *mm) 
{
    int retval, locked;
    struct spr_mm_wait_struct *p;
    struct rb_node **new, *parent;

    might_sleep();

restart:
    parent = NULL;
    __down_write(&rt->sem);
    new = &rt->root.rb_node;
    while (*new) {
        parent = *new;
        p = rb_entry(parent, struct spr_mm_wait_struct, node);
        if ((u64)mm < (u64)p->mm)
            new = &parent->rb_left;
        else if ((u64)mm > (u64)p->mm)
            new = &parent->rb_right;
        else {
            vpr_dbg("find rbnode %lx mm=%lx\n", p, p->mm);
            atomic_inc(&p->count);
            locked = __claim_mm_try(p);
            if (locked == UNLOCK) {
                // If we cannot claim it, we should give up the rbtree semaphore
                // Whis problem is same as Dining philosophers problem
                __up_write(&rt->sem);
                // Wait someone release mm and we can restart
                wait_event(p->waitq, p->claimed == 0);
                atomic_dec(&p->count);
                goto restart;
            } else {
                atomic_dec(&p->count);
                __up_write(&rt->sem);
                return SPR_SUCCESS;
            }
        }
    }

    p = kmem_cache_alloc(mm_wait_struct_cachep, GFP_KERNEL);
    if (!p) {
        retval = -ENOMEM;
        goto out_writer;
    } 

    p->mm = mm;
    atomic_set(&p->count, 0);
    init_waitqueue_head(&p->waitq);
    // Nobody can see this mm_wait in rbtree
    // So we can directly and safely claim it
    p->claimed = 1;
    sema_init(&p->lock, 0);

    rb_link_node(&p->node, parent, new);
    rb_insert_color(&p->node, &rt->root);
    smp_wmb();

    vpr_dbg("allocate %lx for mm %lx\nparent %lx, rb_left %lx, rb_right %lx\n", &p->node, mm, rb_parent(&p->node), &p->node.rb_left, &p->node.rb_right);
    retval = SPR_SUCCESS;

out_writer:
    // atomic_dec(&rt->nwriter);
    __up_write(&rt->sem);
    return retval;
}

static inline void put_mm_wait_struct(struct spr_mm_wait_struct_root *rt, struct mm_struct *mm) 
{
    struct spr_mm_wait_struct *p;
    struct rb_node *node;

    __down_write(&rt->sem);
    node = rt->root.rb_node;
    while (node) {
        p = rb_entry(node, struct spr_mm_wait_struct, node); 
        if ((u64)mm < (u64)p->mm)
            node = node->rb_left;
        else if ((u64)mm > (u64)p->mm)
            node = node->rb_right;
        else {
            vpr_dbg("put rbnode %lx mm=%lx\n", p, p->mm);

            // we should check if there is another process walking throught the RBTree.
            // If so, we should give up deleting the node
            if (__wait_mm(p) > 0) {
                __release_mm(p);
                wake_up(&p->waitq);
            } else {
                // Since we will free p and we dont need to release the semaphore
                rb_erase(&p->node, &rt->root);
                kmem_cache_free(mm_wait_struct_cachep, p);
                smp_mb();
            }
            break;
        }
    }
    __up_write(&rt->sem);
}

int spr_claim_mm(struct task_struct *task) 
{
    return get_mm_wait_struct(&mm_wait_root, task->mm);
}

void spr_release_mm(struct task_struct *task) 
{
    put_mm_wait_struct(&mm_wait_root, task->mm);
}

static inline struct spr_proc_status_struct *
__find_proc_status(struct rb_root *rt, struct task_struct *task)
{
    struct rb_node *n;
    struct spr_proc_status_struct *p;

    n = rt->rb_node;
    while (n) {
        p = rb_entry(n, struct spr_proc_status_struct, node); 
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
__insert_proc_status(struct rb_root *rt, struct spr_proc_status_struct *p)
{
    struct spr_proc_status_struct *this;
    struct rb_node **new = &rt->rb_node, *parent = NULL;
    while (*new) {
        this = rb_entry(*new, struct spr_proc_status_struct, node);
        parent = *new;
        if (p->pid < this->pid)
            new = &parent->rb_left;
        else if (p->pid > this->pid)
            new = &parent->rb_right;
        else
            return false;
    }

    rb_link_node(&p->node, parent, new);
    rb_insert_color(&p->node, rt);
    smp_wmb();
    return true;
}


static int __set_status(struct spr_proc_status_root *rt, 
                    struct task_struct *task, 
                    enum spr_proc_status status, int fd) 
{
    int retval;
    struct spr_proc_status_struct *p;

    vpr_dbg("find pid %d\n", task->pid);

    __down_read(&rt->sem);
    p = __find_proc_status(&rt->root, task);
    __up_read(&rt->sem);
    if (p) {
        p->status = status;
        p->ioctl_fd = fd;
        vpr_dbg("got pid %d at %lx\n", p->pid, &p->node);
        goto success;
    }

    ASSERT(status == SPR_MONITOR_IN);

    __down_write(&rt->sem);
    p = kmem_cache_alloc(proc_status_cachep, GFP_KERNEL);
    if (!p) {
        __up_write(&rt->sem);
        retval = -ENOMEM;
        goto out;
    }
    p->info = vmalloc(sizeof(struct spr_proc_info));
    if (!p->info) {
        kmem_cache_free(proc_status_cachep, p);
        __up_write(&rt->sem);
        retval = -ENOMEM;
        goto out;
    }
    p->pid = task->pid;
    p->ioctl_fd = fd;
    p->status = status;

    ASSERT(__insert_proc_status(&rt->root, p) == true);
    vpr_dbg("allocate %lx pid %d status %d\n", &p->node, p->pid, p->status);

    __up_write(&rt->sem);

success:
    vpr_dbg("set status %d\n", p->status);
    retval = SPR_SUCCESS;

out:
    return retval;
}

int spr_set_status_in(struct task_struct *task) 
{
    return __set_status(&proc_root, task, SPR_MONITOR_IN, -1);
}

int spr_set_status_out(struct task_struct *task) {
    return __set_status(&proc_root, task, SPR_MONITOR_OUT, -1);
}

int spr_set_status_restore(struct task_struct *task, int fd) {
    return __set_status(&proc_root, task, SPR_MONITOR_RESTORE, fd);
}

int spr_erase_status(struct task_struct *task) {
    int retval;
    struct spr_proc_status_struct *p;
    struct spr_proc_info *info;

    __down_write(&proc_root.sem);
    p = __find_proc_status(&proc_root.root, current);
    if (!p) {
        __up_write(&proc_root.sem);
        vpr_dbg("erase_monitor_status: not found %d\n", task->pid);
        return SPR_MONITOR_OUT;
    }

    vpr_dbg("erase_monitor_status: pid %d\n", task->pid, p->status);

    retval = p->status;
    info = p->info;

    rb_erase(&p->node, &proc_root.root);
    kmem_cache_free(proc_status_cachep, p);
    smp_mb();

    __up_write(&proc_root.sem);

    vfree(info);
    return retval;
}


int event_from_monitor(struct spr_proc_status_struct **proc) {
    int retval, status;
    struct spr_proc_status_struct *p;

    __down_read(&proc_root.sem);
    p = __find_proc_status(&proc_root.root, current);
    __up_read(&proc_root.sem);

    if (!p) {
        vpr_dbg("event_from_monitor: not find pid %d\n", current->pid);
        retval = SPR_EVENT_FROM_APPLICATION;
        goto out;
    }

    status = p->status;
    vpr_dbg("event_from_monitor: find pid %d, status %d\n", current->pid, status);
    
    switch(status) {
    case SPR_MONITOR_OUT:
        retval = SPR_EVENT_FROM_APPLICATION;
        break;
    case SPR_MONITOR_RESTORE:
    case SPR_MONITOR_IN:
        retval = SPR_EVENT_FROM_MONITOR;
        break;
    default:
        ASSERT(false);
        break;
    }

out:
    if (proc)   *proc = p;
    return retval;
}

static inline void 
__prepare_context(struct context_struct *ctx, const struct pt_regs *regs) {
    struct spr_proc_info *info;
    struct spr_proc_status_struct *p;

    __down_read(&proc_root.sem);
    p = __find_proc_status(&proc_root.root, current);
    __up_read(&proc_root.sem);

    ASSERT(p != NULL);
    info = p->info;

    // no one will delete our rbnode
    info->fsbase = current->thread.fsbase;
    info->gsbase = current->thread.gsbase;
    info->seccomp_mode = spr_get_seccomp();
    info->cap_effective = current_cred()->cap_effective;
    info->cap_permitted = current_cred()->cap_permitted;
    get_fs_root(current->fs, &info->root_path);
    sigprocmask(-1, 0, &info->sigset);
    memcpy(&info->regs, regs, sizeof(*regs));

    prepare_rlimit_data(ctx->rlim);
    memcpy(&ctx->regs, regs, sizeof(struct pt_regs));
}

static int
create_elf_tbls(struct elfhdr *exec,
                uint64_t load_addr,
                uint64_t interp_load_addr,
                uint64_t *target_sp,
                const struct pt_regs *regs,
                const struct spr_kbuffer *log,
                char *argv[]) {

#define STACK_ROUND(sp, items) 	(((uint64_t) (sp - (items))) &~ 15UL)
#define STACK_ADD(sp, items) ((elf_addr_t __user *)(sp) - (items))
#define STACK_ALLOC(sp, len) ({sp -= (len); sp;})

    int i, argc, envc;
    int elf_info_idx;
    int items;
    uint64_t p;
    uint64_t arg_start, env_start, original_rsp;

    elf_addr_t __user *sp;
    elf_addr_t __user *u_rand_bytes;
    elf_addr_t *elf_info = NULL;
    struct context_struct *context = NULL;

    unsigned char k_rand_bytes[16];


    p = original_rsp = regs->sp;

    // get the number of arg vector and env vector
    for (argc = 0; argv[argc]; argc++);

    for(i = argc - 1; i >= 0; --i) {
        int len = strlen(argv[i]) + 1;
        p = STACK_ALLOC(p, len);
        if (copy_to_user((char __user *)p, argv[i], len))
            goto err;
    }
    arg_start = p;
    /*
     * Generate 16 random bytes for userspace PRNG seeding.
     */
    get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes));
    u_rand_bytes = (elf_addr_t __user *)
               STACK_ALLOC(p, sizeof(k_rand_bytes));
    if (copy_to_user(u_rand_bytes, k_rand_bytes, sizeof(k_rand_bytes)))
        goto err;

#define INSERT_AUX_ENT(id, val) \
    do { \
        elf_info[elf_info_idx++] = id; \
        elf_info[elf_info_idx++] = val; \
    } while (0)

    /*
    * If we have mapped the collector before,
    * we do not need to create auxv for interpreter
    * so the arugment `load_addr`, `interp_load_addr` and `exec` is not required
    * we only need to put the argc, argv and env onto the stack
    */
    elf_info_idx = 0;
    if (exec && interpreter) {
        elf_info = vmalloc(sizeof(elf_addr_t) * 12 * 2);
        if (!elf_info)
            goto err;
        INSERT_AUX_ENT(AT_HWCAP, ELF_HWCAP);
        INSERT_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
        INSERT_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
        INSERT_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
        INSERT_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr));
        INSERT_AUX_ENT(AT_PHNUM, exec->e_phnum);
        INSERT_AUX_ENT(AT_BASE, interp_load_addr);
        INSERT_AUX_ENT(AT_FLAGS, 0);
        INSERT_AUX_ENT(AT_ENTRY, load_addr + exec->e_entry);
        INSERT_AUX_ENT(AT_EXECFN, original_rsp);
        INSERT_AUX_ENT(AT_RANDOM, (elf_addr_t)(unsigned long)u_rand_bytes);
        INSERT_AUX_ENT(AT_NULL, 0);
    }

#define INSERT_ENV_ENT(start, sp) \
    ({\
        size_t len; \
        if (put_user((elf_addr_t)start, (elf_addr_t *)sp++)) \
            goto err; \
        len = strnlen_user((void __user *)start, MAX_ARG_STRLEN); \
        if (!len || len > MAX_ARG_STRLEN) \
            goto err; \
        len; \
    })

#define TRAVERSE_ENV_ENT(start) \
    ({\
        size_t len; \
        len = strnlen_user((void __user *)start, MAX_ARG_STRLEN); \
        if (!len || len > MAX_ARG_STRLEN) \
            goto err; \
        len; \
    })

    // count that how many envs
    envc = 0;
    env_start = current->mm->env_start;
    while (env_start < current->mm->env_end) {
        env_start += TRAVERSE_ENV_ENT(env_start);
        envc++;
    }

    // make stack 16-byte aligned
    items = (argc + 1) + (envc + 1) + 1;
    sp = STACK_ADD(p, elf_info_idx);
    sp = STACK_ROUND(sp, items);
    *target_sp = (unsigned long)sp;

    // put argc
    if (__put_user(argc, sp++))
        goto err;

    // put argv
    for (i = 0; i < argc; ++i) {
        if(put_user((elf_addr_t)arg_start, sp++))
            goto err;
        arg_start += strlen(argv[i]) + 1;
    }

    // put NULL to mark the end of argv
    if (put_user(0, sp++))
        goto err;

    // put env
    env_start = current->mm->env_start;
    while (env_start < current->mm->env_end) {
        env_start += INSERT_ENV_ENT(env_start, sp);
    }

    // put NULL to mark the end of env
    if (__put_user(0, sp++))
        goto err;

    // put AUXV
    if (exec && interpreter && copy_to_user(sp, elf_info, elf_info_idx * sizeof(elf_addr_t))) {
        goto err;
    }


    context = vmalloc(sizeof(struct context_struct));
    if (!context) 
        goto err;

    __prepare_context(context, regs);
    void *arg[] = {
        (void *)context,
        (void *)log
    };
    if (check_mapping(__put_monitor_info, (void *)arg)) {
        goto err;
    }

    vfree(context);
    vpr_dbg("prepare stack and context\n");
    return 0;
err:
    *target_sp = original_rsp;
    if (elf_info)
        vfree(elf_info);
    if (context)
        vfree(context);
    return -EFAULT;
}

static int
do_load_monitor(const struct pt_regs *reg,
               uint64_t *entry,
               uint64_t *load,
               uint64_t *interp_load) {
    int retval;
    uint64_t load_addr = 0;
    uint64_t interp_load_addr = 0;
    uint64_t interp_map_addr = 0;
    uint64_t load_entry;
    uint64_t monitor_map_addr;
    

    if (interpreter) {
        interp_load_addr = elf_load_binary(&interp_elf_ex,
                        interpreter,
                        &interp_map_addr,
                        ELF_ET_DYN_BASE, interp_elf_phdata);
        vpr_dbg("load interp %llx", interp_load_addr);
        if (BAD_ADDR(interp_load_addr)) {
            retval = IS_ERR((void *)interp_load_addr) ?	
                     (int)interp_load_addr : -EINVAL;
            goto out;
        }
    }

    load_addr = elf_load_binary(&monitor_elf_ex,
                    monitor,
                    &monitor_map_addr,
                    ELF_ET_DYN_BASE, monitor_elf_phdata);
    vpr_dbg("load monitor %llx", load_addr);
    if (BAD_ADDR(load_addr)) {
        retval = IS_ERR((void *)load_addr) ?
                (int)load_addr : -EINVAL;
        goto out;
    }

    load_entry = interpreter ? 
                interp_load_addr + interp_elf_ex.e_entry : 
                load_addr + monitor_elf_ex.e_entry;

    vpr_info("load monitor at %llx\nload interp at %llx\nentry = %llx\n", load_addr, interp_load_addr, load_entry);

    if (entry)  *entry = load_entry;
    if (load)   *load = load_addr;
    if (interp_load) *interp_load = interp_load_addr;

    retval = LOAD_SUCCESS;

out:
    return retval;
}

int
load_monitor(const struct spr_kbuffer *buffer) {
    int retval;
    int no_erase = 0;
    struct pt_regs *regs;
    uint64_t entry, sp, load_addr, interp_load_addr;
    struct task_struct *task = current;
    char *argv[] = { MONITOR_PATH, NULL };

    regs = current_pt_regs();

    retval = spr_claim_mm(task);
    if (retval != SPR_SUCCESS) {
        goto out;
    }

    if(check_mapping(__check_mapping, (void *)&entry) == 0) {
        no_erase = 1;
        vpr_dbg("already mapped at %llx\n", entry);
        entry += monitor_elf_ex.e_entry;
    } else {
        retval = do_load_monitor(regs, &entry, &load_addr, &interp_load_addr);
        if (retval != LOAD_SUCCESS) {
            goto out_claim;
        }
    }

    retval = spr_set_status_in(task);
    if (retval != SPR_SUCCESS) {
        goto out_claim;
    }

    retval = create_elf_tbls(&monitor_elf_ex, load_addr, interp_load_addr, &sp, regs, buffer, argv);
    if(retval != LOAD_SUCCESS) {
        goto out_set_monitor_out;
    }

    spr_prepare_security();

    elf_reg_init(&task->thread, regs, 0);
    regs->sp = sp;
    regs->cx = regs->ip = entry;
    vpr_dbg("monitor is ready to run ip %llx sp %llx\n", entry, sp);

    retval = LOAD_SUCCESS;
    return retval;

out_set_monitor_out:
    if (no_erase)
        spr_set_status_out(task);
    else
        spr_erase_status(task);
out_claim:
    spr_release_mm(task);
out:
    vpr_err("(%d)load_monitor: cannot transfer logging buffer (%d)\n", smp_processor_id(), retval);
    return retval;
}

int loader_init(void) {
    int i, retval;
    char *elf_interpreter = NULL;
    struct elf_phdr *elf_ppnt = NULL;

    loff_t pos;
    monitor = NULL;
    interpreter = NULL;

    monitor = open_exec(MONITOR_PATH);
    retval = PTR_ERR(monitor);
    if (IS_ERR(monitor))
        goto out;

    pos = 0;
    retval = kernel_read(monitor, &monitor_elf_ex, sizeof(monitor_elf_ex), &pos);
    if (retval != sizeof(monitor_elf_ex)) {
        if (retval >= 0)
            retval = -EIO;
        goto out_free_monitor;
    }

    retval = -ENOEXEC;
    /* First of all, some simple consistency checks */
    if (memcmp(monitor_elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
        goto out_free_monitor;
    if (monitor_elf_ex.e_type != ET_DYN && monitor_elf_ex.e_type != ET_EXEC)
        goto out_free_monitor;
    if (!elf_check_arch(&monitor_elf_ex))
        goto out_free_monitor;
    if (!monitor->f_op->mmap)
        goto out_free_monitor;
    if (elf_load_phdrs(&monitor_elf_ex, monitor, &monitor_elf_phdata))
        goto out_free_monitor;

    if (monitor_elf_ex.e_type == ET_EXEC)
        goto success;

    elf_ppnt = monitor_elf_phdata;
    // find INTERP segment
    for (i = 0; i < monitor_elf_ex.e_phnum; i++) {
        if (elf_ppnt->p_type == PT_INTERP) {
            retval = 0;
            if (elf_ppnt->p_filesz > PATH_MAX ||
                elf_ppnt->p_filesz < 2)
                goto out_free_monitor;

            retval = -ENOMEM;
            elf_interpreter = kmalloc(elf_ppnt->p_filesz, GFP_KERNEL);
            if (!elf_interpreter)
                goto out_free_monitor;

            pos = elf_ppnt->p_offset;
            retval = kernel_read(monitor, elf_interpreter, elf_ppnt->p_filesz, &pos);
            if (retval != elf_ppnt->p_filesz) {
                if (retval >= 0)
                    retval = -EIO;
                goto out_free_interp;
            }

            /* make sure path is NULL terminated */
            retval = -ENOEXEC;
            if (elf_interpreter[elf_ppnt->p_filesz - 1] != '\0')
                goto out_free_interp;

            interpreter = open_exec(elf_interpreter);
            retval = PTR_ERR(interpreter);
            if (IS_ERR(interpreter))
                goto out_free_interp;

            /* Get the exec headers */
            pos = 0;
            retval = kernel_read(interpreter, &interp_elf_ex, sizeof(interp_elf_ex), &pos);
            if (retval != sizeof(interp_elf_ex)) {
                if (retval >= 0)
                    retval = -EIO;
                goto out_free_dentry;
            }

            break;
        }
        elf_ppnt++;
    }

    if (!elf_interpreter) {
        retval = -ENOEXEC;
        goto out_free_interp;
    }

    kfree(elf_interpreter);
    elf_interpreter = NULL;

    retval = -ELIBBAD;
    /* Not an ELF interpreter */
    if (memcmp(interp_elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
        goto out_free_dentry;
    /* Verify the interpreter has a valid arch */
    if (!elf_check_arch(&interp_elf_ex))
        goto out_free_dentry;

    /* Load the interpreter program headers */
    if (elf_load_phdrs(&interp_elf_ex, interpreter, &interp_elf_phdata))
        goto out_free_dentry;

    proc_status_cachep = kmem_cache_create("spr_proc_status_cache", sizeof(struct spr_proc_status_struct), 0, SLAB_ACCOUNT, NULL);
    if (!proc_status_cachep) {
        retval = -ENOMEM;
        goto out_free_mem_cache;
    }

    mm_wait_struct_cachep = kmem_cache_create("spr_mm_wait_struct_cache", sizeof(struct spr_mm_wait_struct), 0, SLAB_ACCOUNT, NULL);
    if (!mm_wait_struct_cachep) {
        retval = -ENOMEM;
        goto out_free_mem_cache;
    }

    proc_root.root = RB_ROOT;
    init_rwsem(&proc_root.sem);

    mm_wait_root.root = RB_ROOT;
    init_rwsem(&mm_wait_root.sem);

success:
    retval = 0;

out:
    return retval;

out_free_mem_cache:
    if (mm_wait_struct_cachep)
        kmem_cache_destroy(mm_wait_struct_cachep);
    if (proc_status_cachep)
        kmem_cache_destroy(proc_status_cachep);
out_free_dentry:
    allow_write_access(interpreter);
    if (interpreter)
        fput(interpreter);
    interpreter = NULL;
out_free_interp:
    kfree(elf_interpreter);
    elf_interpreter = NULL;
out_free_monitor:
    allow_write_access(monitor);
    if (monitor)
        fput(monitor);
    monitor = NULL;
    goto out;
}

void loader_destory(void) {
    if (interpreter) {
        allow_write_access(interpreter);
        fput(interpreter);
    }

    if (monitor) {
        allow_write_access(monitor);
        fput(monitor);
    }

    if (monitor_elf_phdata)
        kfree(monitor_elf_phdata);
    if (interp_elf_phdata)
        kfree(interp_elf_phdata);

    if (mm_wait_struct_cachep)
        kmem_cache_destroy(mm_wait_struct_cachep);
    if (proc_status_cachep)
        kmem_cache_destroy(proc_status_cachep);
}