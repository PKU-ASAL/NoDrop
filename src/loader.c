#include <linux/elf.h>
#include <linux/file.h>
#include <linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/fs_struct.h>
#include <linux/delay.h>


#include "nodrop.h"
#include "common.h"
#include "events.h"
#include "syscall.h"
#include "procinfo.h"


DEFINE_PER_CPU(struct nod_kbuffer, buffer);
EXPORT_PER_CPU_SYMBOL(buffer);

static struct elf_phdr *monitor_elf_phdata, *interp_elf_phdata;
static struct elfhdr   monitor_elf_ex, interp_elf_ex;
static struct file *monitor, *interpreter;

#define MAPPING_OK          0 
#define MAPPING_NEXT        1
#define MAPPING_FINISH      2
#define MAPPING_NOTFOUND    3

#define MAPPING_FIND

static int
__check_mapping(struct vm_area_struct const * const vma, void *arg)
{
    vm_flags_t flags = vma->vm_flags;
    if (flags & VM_EXEC) {
        *(unsigned long*)arg = vma->vm_start;
        return MAPPING_OK;
    }

    return MAPPING_NEXT;
}

static int
wait_dynamic_linker_ready(struct vm_area_struct const * const vma, void *arg)
{
    int count = 0;
    vm_flags_t flags = vma->vm_flags;
    if (flags & VM_EXEC) {
        return MAPPING_NEXT;
    }

    /* 
     * Since the monitor may be loaded but not initialized yet, 
     * we should wait here until it is initialized.
     * When the monitor is initialized, the flag in .monitor.info will be set to tls.
     */
    while (count++ < 100 && !nod_copy_from_user(arg, (const void *)vma->vm_start, sizeof(unsigned long))) {
        if (*(unsigned long *)arg != 0) {
            return MAPPING_OK;
        }
        msleep(1);
    }
    return MAPPING_FINISH;
}

int
check_mapping(int (*resolve) (struct vm_area_struct const * const vma, void *arg),
              void *arg)
{
    int retval;
    struct mm_struct *mm;
    struct vm_area_struct *vma;

    mm = current->mm;

    down_read(&mm->mmap_sem);
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_file == monitor) {
            retval = (*resolve)((struct vm_area_struct const * const)vma, arg);
            switch(retval) {
            case MAPPING_OK:
            case MAPPING_FINISH:
                goto out;
            case MAPPING_NEXT:
                break;
            default:
                up_read(&mm->mmap_sem);
                ASSERT(false);
            }
        }
    }

    retval = MAPPING_NOTFOUND;

out:
    up_read(&mm->mmap_sem);
    return retval;
}

static int
create_elf_tbls(struct elfhdr *exec,
                uint64_t load_addr,
                uint64_t interp_load_addr,
                const struct pt_regs *regs,
                const struct nod_stack_info *stack,
                uint64_t *target_sp,
                char *argv[]) {

#define STACK_ROUND(sp, items) 	((elf_addr_t __user *)(((uint64_t) (sp - (items))) &~ 15UL))
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
    unsigned char k_rand_bytes[16];

    p = original_rsp = regs->sp;

    // get the number of arg vector and env vector
    for (argc = 0; argv[argc]; argc++);

    // put nod_stack_info into Runtime stack
    p = STACK_ALLOC(p, sizeof(*stack));
    copy_to_user((char __user *)p, stack, sizeof(*stack));
    argv[argc] = (char *)p;

    for(i = argc - 1; i >= 0; --i) {
        int len = strlen(argv[i]) + 1;
        p = STACK_ALLOC(p, len);
        copy_to_user((char __user *)p, argv[i], len);
    }
    arg_start = p;
    /*
     * Generate 16 random bytes for userspace PRNG seeding.
     */
    get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes));
    u_rand_bytes = (elf_addr_t __user *)
               STACK_ALLOC(p, sizeof(k_rand_bytes));
    if (__copy_to_user(u_rand_bytes, k_rand_bytes, sizeof(k_rand_bytes)))
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
    if (exec) {
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
    items = (argc + 1) + (envc + 1) + 1 + 1; /* argc + argv + addr of nod_stack_info + 0 + envc + 0 */
    sp = STACK_ADD(p, elf_info_idx);
    sp = STACK_ROUND(sp, items);
    *target_sp = (unsigned long)sp;

    /* argc
     * argv[0]
     * argv[1]
     * ...
     * argv[argc - 1]
     * address of nod_stack_info
     * 0
     * env[0]
     * env[1]
     * ...
     * env[envc - 1]
     * 0
     * Aux
     */


    // put argc
    // We put argc + 1 here because the additional value of address of nod_stack_info
    if (__put_user(argc + 1, sp++))
        goto err;

    // put argv
    for (i = 0; i < argc; ++i) {
        if(put_user((elf_addr_t)arg_start, sp++))
            goto err;
        arg_start += strlen(argv[i]) + 1;
    }

    // put address of nod_stack_info
    if(put_user((elf_addr_t)argv[argc], sp++))
        goto err;
    
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
    if (exec && copy_to_user(sp, elf_info, elf_info_idx * sizeof(elf_addr_t))) {
        goto err;
    }

    return NOD_SUCCESS;
err:
    *target_sp = original_rsp;
    if (elf_info)
        vfree(elf_info);
    return -EFAULT;
}

static int
do_load_monitor(const struct pt_regs *regs, uint64_t *entry, uint64_t *load, uint64_t *interp_load)
{
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

    if (BAD_ADDR(load_addr)) {
        retval = IS_ERR((void *)load_addr) ?
                (int)load_addr : -EINVAL;
        goto out;
    }


    load_entry = interpreter ? 
                interp_load_addr + interp_elf_ex.e_entry : 
                load_addr + monitor_elf_ex.e_entry;

    vpr_dbg("load monitor at %llx\nload interp at %llx\nentry = %llx", load_addr, interp_load_addr, load_entry);

    if (entry)  *entry = load_entry;
    if (load)   *load = load_addr;
    if (interp_load) *interp_load = interp_load_addr;

    retval = NOD_SUCCESS;

out:
    return retval;
}

static void
copy_context(struct nod_proc_info *p, const struct pt_regs *regs)
{
    struct nod_proc_context *ctxp;

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
    syscall_get_arguments_deprecated(current, regs, 0, 1, &p->stack.code);
}

int
load_monitor(const struct nod_kbuffer *buffer) {
    int retval, free = 1;
    uint64_t entry, sp;
    struct pt_regs *regs;
    struct nod_proc_info *p;
    struct elf64_hdr *cur_elf_ex = &monitor_elf_ex;
    uint64_t load_addr = 0, interp_load_addr = 0;

    char *argv[] = { MONITOR_PATH, NULL };

    regs = current_pt_regs();

    p = nod_set_in(current, buffer);
    if (!p) {
        retval = -ENOMEM;
        goto out;
    }

    copy_context(p, regs);

    if (!p->load_addr) {
        if(check_mapping(__check_mapping, (void *)&load_addr) == MAPPING_OK &&
            check_mapping(wait_dynamic_linker_ready, (void *)&p->stack.fsbase) == MAPPING_OK) {
            free = 0;
            cur_elf_ex = NULL;
            entry = load_addr + monitor_elf_ex.e_entry;
        } else {
            retval = do_load_monitor(regs, &entry, &load_addr, &interp_load_addr);
            if (retval != NOD_SUCCESS) {
                goto out;
            }
        }
        p->load_addr = load_addr;
    } else {
        entry = p->load_addr + monitor_elf_ex.e_entry;
    }

    retval = create_elf_tbls(cur_elf_ex, load_addr, interp_load_addr, regs, &p->stack, &sp, argv);
    if (retval != NOD_SUCCESS) {
        goto out;
    }

    nod_prepare_security();

    elf_reg_init(&current->thread, regs, 0);
    regs->sp = sp;
    regs->cx = regs->ip = entry;

    return NOD_SUCCESS;

out:
    pr_err("(%d)load_monitor: cannot transfer logging buffer", smp_processor_id());
    if (free == 0) {
        nod_set_out(current);
    } else {
        nod_free_status(current);
    }
    return retval;
}

int loader_init(void)
{
    int i, retval;
    loff_t pos;
    char *elf_interpreter = NULL;
    struct elf_phdr *elf_ppnt = NULL;

    monitor = NULL;
    interpreter = NULL;
    monitor_elf_phdata = NULL;
    interp_elf_phdata = NULL;

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
        pr_warn("No dynamic linker, consider static linked\n");
        goto success;
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

success:

    retval = 0;

out:
    return retval;

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
}