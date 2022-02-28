#include <linux/elf.h>
#include <linux/file.h>
#include <linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/random.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/mm.h>

#include "pinject.h"
#include "include/common.h"
#include "include/events.h"


DEFINE_PER_CPU(struct spr_kbuffer, buffer);
EXPORT_PER_CPU_SYMBOL(buffer);

static struct elf_phdr *monitor_elf_phdata, *interp_elf_phdata;
static struct elfhdr   monitor_elf_ex, interp_elf_ex;
static struct file *monitor, *interpreter;

enum spr_monitor_status {
    SPR_MONITOR_IN = 1,
    SPR_MONITOR_OUT = 2,
};
static struct kmem_cache *inject_proc_cachep = NULL;
static struct rb_root proc_root = RB_ROOT;
static struct spr_inject_proc {
    struct task_struct *task;
    struct rb_node node;
    enum spr_monitor_status status;
};

static struct kmem_cache *mm_wait_struct_cachep = NULL;
static struct rb_root mm_wait_struct_root = RB_ROOT;
static struct spr_mm_wait_struct {
    struct mm_struct *mm;
    struct rb_node node;
    wait_queue_head_t wait_tasks;
    atomic_t claimed;
    atomic_t nwaits;
};


static int
__check_mapping(struct vm_area_struct const * const vma, void *arg) {
    vm_flags_t flags = vma->vm_flags;
    vpr_debug("vm_start %lx flags %lx", vma->vm_start, flags);
    if (flags & VM_EXEC) {
        *(unsigned long*)arg = vma->vm_start;
        vpr_debug("find monitor\n");
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

static inline void 
prepare_context(struct context_struct *ctx, const struct pt_regs *regs) {
    if (prepare_root_path(ctx->root_path)) {
        sprintf(ctx->root_path, "/");
    }

    prepare_rlimit_data(ctx->rlim);
    prepare_security_data(&ctx->securities);
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

    prepare_context(context, regs);
    void *arg[] = {
        (void *)context,
        (void *)log
    };
    if (check_mapping(__put_monitor_info, (void *)arg)) {
        goto err;
    }

    vfree(context);
    vpr_debug("prepare stack and context\n");
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
        vpr_debug("load interp %lx", interp_load_addr);
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
    vpr_debug("load monitor %lx", load_addr);
    if (BAD_ADDR(load_addr)) {
        retval = IS_ERR((void *)load_addr) ?
                (int)load_addr : -EINVAL;
        goto out;
    }

    load_entry = interpreter ? 
                interp_load_addr + interp_elf_ex.e_entry : 
                load_addr + monitor_elf_ex.e_entry;

    vpr_debug("load monitor at %llx\nload interp at %llx\nentry = %llx\n", load_addr, interp_load_addr, load_entry);

    if (entry)  *entry = load_entry;
    if (load)   *load = load_addr;
    if (interp_load) *interp_load = interp_load_addr;

    retval = LOAD_SUCCESS;

out:
    return retval;
}

static struct spr_mm_wait_struct *__find_mm_wait_struct(struct rb_root *root, struct mm_struct *mm) 
{
    struct spr_mm_wait_struct *p;
    struct rb_node *node = root->rb_node;
    while (node) {
        p = rb_entry(node, struct spr_mm_wait_struct, node); 
        if ((u64)mm < (u64)p->mm)
            node = node->rb_left;
        else if ((u64)mm > (u64)p->mm)
            node = node->rb_right;
        else {
            return p;
        }
    }
    return NULL; 
}

static inline struct spr_mm_wait_struct *get_mm_wait_struct(struct mm_struct *mm) 
{
    struct spr_mm_wait_struct *p, *cur;
    struct rb_node **new, *parent;

    parent = NULL;
    new = &mm_wait_struct_root.rb_node;
    while (*new) {
        parent = *new;
        cur = rb_entry(*new, struct spr_mm_wait_struct, node);
        if ((u64)mm < (u64)cur->mm)
            new = &(*new)->rb_left;
        else if ((u64)mm > (u64)cur->mm)
            new = &(*new)->rb_right;
        else {
            p = cur;
            goto out;
        }
    }

    p = kmem_cache_alloc(mm_wait_struct_cachep, GFP_KERNEL);
    if (p) {
        p->mm = mm;
        p->wait_tasks = (wait_queue_head_t)__WAIT_QUEUE_HEAD_INITIALIZER(p->wait_tasks);
        atomic_set(&p->claimed, 0);
        atomic_set(&p->nwaits, 0);
        rb_link_node(&p->node, parent, new);
        rb_insert_color(&p->node, &mm_wait_struct_root);
        vpr_debug("allocate mm_wait mm=%lx\n", mm);
    }

out:
    if (p) {
        atomic_inc(&p->nwaits);
        vpr_debug("get mm_wait\n");
    }
    return p;
}

static inline void put_mm_wait_struct(struct spr_mm_wait_struct *wait_mm) 
{
    if (wait_mm && atomic_dec_and_test(&wait_mm->nwaits)) {
        vpr_debug("put mm_wait mm=%lx\n", wait_mm->mm);
        rb_erase(&wait_mm->node, &mm_wait_struct_root);
        kmem_cache_free(mm_wait_struct_cachep, wait_mm);
    }
}

static inline void __claim_mm(struct spr_mm_wait_struct *wait_mm)
{
    atomic_set(&wait_mm->claimed, 1);
    vpr_debug("claim mm_wait\n");
}
static inline void __release_mm(struct spr_mm_wait_struct *wait_mm)
{
    atomic_set(&wait_mm->claimed, 0);
    vpr_debug("release mm_wait\n");
}

int spr_claim_mm(struct task_struct *task) 
{
    int retval;
    struct spr_mm_wait_struct *wait_mm;

    retval = -ENOMEM;
    wait_mm = get_mm_wait_struct(task->mm);
    if (!wait_mm) {
        goto out;
    }

    retval = SPR_SUCCESS;
    wait_event(wait_mm->wait_tasks, atomic_read(&wait_mm->claimed) == 0);
    vpr_debug("wait_event return %d\n", retval);
    __claim_mm(wait_mm);
        
out:
    return retval;
}

void spr_release_mm(struct task_struct *task) 
{
    struct spr_mm_wait_struct *wait_mm = __find_mm_wait_struct(&mm_wait_struct_root, task->mm);
    if (wait_mm) {
        __release_mm(wait_mm);
        wake_up(&wait_mm->wait_tasks);
        put_mm_wait_struct(wait_mm);
    } else {
        vpr_debug("corruption NULL wait_mm mm=%lx\n", task->mm);
    }
}

static struct spr_inject_proc * __find_inject_proc(struct rb_root *root, struct task_struct *task) 
{
    struct spr_inject_proc *p;
    struct rb_node *node = root->rb_node;
    while (node) {
        p = rb_entry(node, struct spr_inject_proc, node); 
        if (task->pid < p->task->pid)
            node = node->rb_left;
        else if (task->pid > p->task->pid)
            node = node->rb_right;
        else {
            return p;
        }
    }
    return NULL;
}

static int __set_status(struct task_struct *task, enum spr_monitor_status status) 
{
    int retval;
    struct spr_inject_proc *p, *cur;
    struct rb_node **new, *parent;

    parent = NULL;

    vpr_debug("find pid %d\n", task->pid);
    new = &proc_root.rb_node;
    while (*new) {
        parent = *new;
        cur = rb_entry(*new, struct spr_inject_proc, node);
        if (task->pid < cur->task->pid)
            new = &(*new)->rb_left;
        else if (task->pid > cur->task->pid)
            new = &(*new)->rb_right;
        else {
            cur->status = status;
            vpr_debug("got pid\n");
            goto success;
        }
    }

    p = kmem_cache_alloc(inject_proc_cachep, GFP_KERNEL);
    if (!p) {
        retval = -ENOMEM;
        goto out;
    }
    p->task = task;
    p->status = status;
    rb_link_node(&p->node, parent, new);
    rb_insert_color(&p->node, &proc_root);

success:
    vpr_debug("set monitor info %d\n", status);
    retval = SPR_SUCCESS;

out:
    return retval;
}

int spr_set_status_in(struct task_struct *task) 
{
    return __set_status(task, SPR_MONITOR_IN);
}

int spr_set_status_out(struct task_struct *task) {
    return __set_status(task, SPR_MONITOR_OUT);
}

void spr_erase_status(struct task_struct *task) {
    struct spr_inject_proc *p = __find_inject_proc(&proc_root, task);
    if (p) {
        vpr_debug("erase_monitor_status: pid %d\n", task->pid, p->status);
        rb_erase(&p->node, &proc_root);
        kmem_cache_free(inject_proc_cachep, p);
    }
}

int event_from_monitor(void) {
    int retval = SPR_FAILURE_BUG;
    struct spr_inject_proc *p = __find_inject_proc(&proc_root, current);
    if (!p) {
        vpr_debug("event_from_monitor: not find pid %d\n", current->pid);
        return SPR_EVENT_FROM_APPLICATION;
    }
    
    vpr_debug("event_from_monitor: find pid %d, status %d\n", current->pid, p->status);
    switch(p->status) {
    case SPR_MONITOR_OUT:
        retval = SPR_EVENT_FROM_APPLICATION;
        break;
    case SPR_MONITOR_IN:
        retval = SPR_EVENT_FROM_MONITOR;
        break;
    default:
        ASSERT(false);
        break;
    }

    return retval;
}

int
load_monitor(const struct spr_kbuffer *buffer) {
    int retval;
    int no_erase = 0;
    uint64_t entry, sp, load_addr, interp_load_addr;
    struct pt_regs *regs;
    struct task_struct *task = current;
    char *argv[] = { MONITOR_PATH, NULL };

    regs = current_pt_regs();

    retval = spr_claim_mm(task);
    if (retval != SPR_SUCCESS) {
        goto out;
    }

    if(check_mapping(__check_mapping, (void *)&entry) == 0) {
        no_erase = 1;
        vpr_debug("already mapped at %lx\n", entry);
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

success:
    spr_prepare_security();

    elf_reg_init(&task->thread, regs, 0);
    regs->sp = sp;
    regs->cx = regs->ip = entry;
    vpr_debug("monitor is ready to run ip %lx sp %lx\n", entry, sp);

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

    inject_proc_cachep = kmem_cache_create("spr_inject_proc_cache", sizeof(struct spr_inject_proc), 0, SLAB_ACCOUNT, NULL);
    if (!inject_proc_cachep) {
        retval = -ENOMEM;
        goto out_free_mem_cache;
    }

    mm_wait_struct_cachep = kmem_cache_create("spr_mm_wait_struct_cache", sizeof(struct spr_mm_wait_struct), 0, SLAB_ACCOUNT, NULL);
    if (!mm_wait_struct_cachep) {
        retval = -ENOMEM;
        goto out_free_mem_cache;
    }

success:
    retval = 0;

out:
    return retval;

out_free_mem_cache:
    if (mm_wait_struct_cachep)
        kmem_cache_destroy(mm_wait_struct_cachep);
    if (inject_proc_cachep)
        kmem_cache_destroy(inject_proc_cachep);
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
    if (inject_proc_cachep)
        kmem_cache_destroy(inject_proc_cachep);
}