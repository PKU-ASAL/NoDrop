#include <linux/sched/task_stack.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/elf.h>
#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/namei.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>

#include "pinject.h"
#include "include/common.h"
#include "include/events.h"


#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#define BAD_ADDR(x) ((unsigned long)(x) >= TASK_SIZE)

static struct elf_phdr *monitor_elf_phdata, *interp_elf_phdata;
static struct elfhdr   monitor_elf_ex, interp_elf_ex;
static struct file *monitor, *interpreter;

DEFINE_PER_CPU(struct spr_kbuffer, buffer);
EXPORT_PER_CPU_SYMBOL(buffer);
DEFINE_SPINLOCK(mutex);

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
    m_infopack *infopack = (m_infopack *)vma->vm_start;
    vm_flags_t flags = vma->vm_flags;

    if (flags & VM_EXEC)
        return 0;

    if (put_user((int)arr[0], (int __user *)&infopack->m_enter)) {
        pr_err("cannot write __monitor_enter @ %lx\n", &infopack->m_enter);
        return 0;
    }

    if (copy_to_user((void __user *)&infopack->m_context, (void *)arr[1], sizeof(infopack->m_context))) {
        pr_err("cannot write __monitor_context @ %lx\n", &infopack->m_context);
        return 0;
    }

    if (copy_to_user((void __user *)&infopack->m_buffer.buffer, (void *)((struct spr_kbuffer *)arr[2])->buffer, sizeof(infopack->m_buffer.buffer)) ||
        copy_to_user((void __user *)&infopack->m_buffer.info, (void *)&((struct spr_kbuffer *)arr[2])->info, sizeof(struct spr_buffer_info))) {
        pr_err("cannot write __monitor_logmsg @ %lx\n", &infopack->m_buffer);
        return 0;
    }

    return 1;
}

static int
__check_monitor_enter(struct vm_area_struct const * const vma, void *arg) {
    int monitor_enter;
    vm_flags_t flags = vma->vm_flags;

    if (flags & VM_EXEC)
        return 0;

    // get data from monitor's section `.monitor`
    if(get_user(monitor_enter, (int __user *)vma->vm_start)) {
        monitor_enter = -1;
    }
    *(int *)arg = monitor_enter;

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

/* We need to explicitly zero any fractional pages
   after the data section (i.e. bss).  This would
   contain the junk from the file that should not
   be in memory
 */
static int
padzero(unsigned long elf_bss) {
    unsigned long nbyte;

    nbyte = ELF_PAGEOFFSET(elf_bss);
    if (nbyte) {
        nbyte = ELF_MIN_ALIGN - nbyte;
        if (clear_user((void __user *) elf_bss, nbyte)) {
            return -EFAULT;
        }
    }
    return 0;
}

static unsigned long
total_mapping_size(struct elf_phdr *cmds, int nr) {
    int i, first_idx = -1, last_idx = -1;

    for (i = 0; i < nr; i++) {
        if (cmds[i].p_type == PT_LOAD) {
            last_idx = i;
            if (first_idx == -1)
                first_idx = i;
        }
    }
    if (first_idx == -1)
        return 0;

    return cmds[last_idx].p_vaddr + cmds[last_idx].p_memsz -
                ELF_PAGESTART(cmds[first_idx].p_vaddr);
}

static unsigned long
elf_map(struct file *filep, unsigned long addr,
        struct elf_phdr *eppnt, int prot, int type,
        unsigned long total_size) {
    unsigned long map_addr;
    unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
    unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);
    addr = ELF_PAGESTART(addr);
    size = ELF_PAGEALIGN(size);

    /* mmap() will return -EINVAL if given a zero size, but a
     * segment with zero filesize is perfectly valid */
    if (!size)
        return addr;

    /*
    * total_size is the size of the ELF (interpreter) image.
    * The _first_ mmap needs to know the full size, otherwise
    * randomization might put this image into an overlapping
    * position with the ELF binary image. (since size < total_size)
    * So we first map the 'big' image - and unmap the remainder at
    * the end. (which unmap is needed for ELF images with holes.)
    */
    if (total_size) {
        total_size = ELF_PAGEALIGN(total_size);
        map_addr = vm_mmap(filep, addr, total_size, prot, type, off);
        if (!BAD_ADDR(map_addr))
            vm_munmap(map_addr+size, total_size-size);
    } else {
        map_addr = vm_mmap(filep, addr, size, prot, type, off);
    }

    return(map_addr);
}

static int
load_elf_phdrs(struct elfhdr *elf_ex,
               struct file *elf_file,
               struct elf_phdr **elf_phdrs) {
    struct elf_phdr *elf_phdata;
    int retval, size, err = -1;
    loff_t pos = elf_ex->e_phoff;

    /*
     * If the size of this structure has changed, then punt, since
     * we will be doing the wrong thing.
     */
    if (elf_ex->e_phentsize != sizeof(struct elf_phdr))
        goto out;

    /* Sanity check the number of program headers... */
    if (elf_ex->e_phnum < 1 ||
        elf_ex->e_phnum > 65536U / sizeof(struct elf_phdr))
        goto out;

    /* ...and their total size. */
    size = sizeof(struct elf_phdr) * elf_ex->e_phnum;
    if (size > ELF_MIN_ALIGN)
        goto out;

    elf_phdata = kmalloc(size, GFP_KERNEL);
    if (!elf_phdata)
        goto out;

    /* Read in the program headers */
    retval = kernel_read(elf_file, elf_phdata, size, &pos);
    if (retval != size) {
        err = (retval < 0) ? retval : -EIO;
        goto out;
    }

    /* Success! */
    err = 0;
out:
    if (err) {
        kfree(elf_phdata);
        elf_phdata = NULL;
    }
    *elf_phdrs = elf_phdata;
    return err;
}

static unsigned long
load_elf_binary(struct elfhdr *elf_ex,
        struct file *binary, uint64_t *map_addr,
        unsigned long no_base, struct elf_phdr *elf_phdrs) {
    int i;
    int load_addr_set = 0;
    int bss_prot = 0;
    struct elf_phdr *eppnt;
    uint64_t load_addr = 0;
    uint64_t last_bss = 0, elf_bss = 0;
    unsigned long error = ~0UL;
    unsigned long total_size;

    /* First of all, some simple consistency checks */
    if (elf_ex->e_type != ET_EXEC &&
        elf_ex->e_type != ET_DYN)
        goto out;

    total_size = total_mapping_size(elf_phdrs, elf_ex->e_phnum);
    if (!total_size) {
        error = -EINVAL;
        goto out;
    }

    eppnt = elf_phdrs;
    for (i = 0; i < elf_ex->e_phnum; i++, eppnt++) {
        if (eppnt->p_type == PT_LOAD) {
            int elf_type = MAP_PRIVATE /*| MAP_DENYWRITE*/;
            int elf_prot = 0;
            unsigned long vaddr = 0;
            unsigned long k, _addr;

            if (eppnt->p_flags & PF_R)
                elf_prot = PROT_READ;
            if (eppnt->p_flags & PF_W)
                elf_prot |= PROT_WRITE;
            if (eppnt->p_flags & PF_X)
                elf_prot |= PROT_EXEC;
            vaddr = eppnt->p_vaddr;
            if (elf_ex->e_type == ET_EXEC || load_addr_set)
                elf_type |= MAP_FIXED;
            else if (no_base && elf_ex->e_type == ET_DYN)
                load_addr = -vaddr;

            _addr = elf_map(binary, load_addr + vaddr,
                    eppnt, elf_prot, elf_type, total_size);
            total_size = 0;
            if (!*map_addr)
                *map_addr = _addr;
            error = _addr;
            if (BAD_ADDR(_addr))
                goto out;

            if (!load_addr_set &&
                elf_ex->e_type == ET_DYN) {
                load_addr = _addr - ELF_PAGESTART(vaddr);
                load_addr_set = 1;
            }

            /*
             * Check to see if the section's size will overflow the
             * allowed task size. Note that p_filesz must always be
             * <= p_memsize so it's only necessary to check p_memsz.
             */
            k = load_addr + eppnt->p_vaddr;
            if (BAD_ADDR(k) ||
                eppnt->p_filesz > eppnt->p_memsz ||
                eppnt->p_memsz > TASK_SIZE ||
                TASK_SIZE - eppnt->p_memsz < k) {
                error = -ENOMEM;
                goto out;
            }

            /*
             * Find the end of the file mapping for this phdr, and
             * keep track of the largest address we see for this.
             */
            k = load_addr + eppnt->p_vaddr + eppnt->p_filesz;
            if (k > elf_bss)
                elf_bss = k;

            /*
             * Do the same thing for the memory mapping - between
             * elf_bss and last_bss is the bss section.
             */
            k = load_addr + eppnt->p_vaddr + eppnt->p_memsz;
            if (k > last_bss) {
                last_bss = k;
                bss_prot = elf_prot;
            }
        }
    }
    /*
     * Now fill out the bss section: first pad the last page from
     * the file up to the page boundary, and zero it from elf_bss
     * up to the end of the page.
     */
    if (padzero(elf_bss)) {
        error = -EFAULT;
        goto out;
    }
    /*
     * Next, align both the file and mem bss up to the page size,
     * since this is where elf_bss was just zeroed up to, and where
     * last_bss will end after the vm_brk_flags() below.
     */
    elf_bss = ELF_PAGEALIGN(elf_bss);
    last_bss = ELF_PAGEALIGN(last_bss);
    /* Finally, if there is still more bss to allocate, do it. */
    if (last_bss > elf_bss) {
        error = vm_brk_flags(elf_bss, last_bss - elf_bss,
                bss_prot & PROT_EXEC ? VM_EXEC : 0);
        if (error)
            goto out;
    }

    error = load_addr;
out:
    return error;
}

static int
create_elf_tbls(struct elfhdr *exec,
                uint64_t load_addr,
                uint64_t interp_load_addr,
                uint64_t *target_sp,
                const struct pt_regs *reg,
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
    unsigned char k_rand_bytes[16];

    struct context_struct context = {
        .fsbase = current->thread.fsbase,
        .gsbase = current->thread.gsbase,
    };
    memcpy(&context.reg, reg, sizeof(struct pt_regs));

    p = original_rsp = reg->sp;

    // get the number of arg vector and env vector
    for (argc = 0; argv[argc]; argc++);

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
        elf_info = kmalloc(sizeof(elf_addr_t) * 12 * 2, GFP_KERNEL);
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
    if (exec && copy_to_user(sp, elf_info, elf_info_idx * sizeof(elf_addr_t))) {
        goto err;
    }

    void *arg[] = {
        (void *)((exec != NULL) ? (int)1 : (int)0),
        (void *)&context,
        (void *)log
    };
    if (check_mapping(__put_monitor_info, (void *)arg)) {
        goto err;
    }

    return 0;
err:
    *target_sp = original_rsp;
    if (elf_info)
        kfree(elf_info);
    return -EFAULT;
}

static int
do_load_monitor(const struct pt_regs *reg,
               uint64_t *entry,
               uint64_t *load,
               uint64_t *interp_load) {
    int retval;
    uint64_t load_addr = 0;
    uint64_t interp_entry;
    uint64_t interp_load_addr = 0;
    uint64_t interp_map_addr = 0;
    uint64_t monitor_map_addr;
    

    interp_entry = load_elf_binary(&interp_elf_ex,
                    interpreter,
                    &interp_map_addr,
                    ELF_ET_DYN_BASE, interp_elf_phdata);

    if (!IS_ERR((void *)interp_entry)) {
        /* load_elf_interp() returns relocation adjustment */
        interp_load_addr = interp_entry;
        interp_entry += interp_elf_ex.e_entry;
    }
    if (BAD_ADDR(interp_entry)) {
        retval = IS_ERR((void *)interp_entry) ?	(int)interp_entry : -EINVAL;
        goto out;
    }

    load_addr = load_elf_binary(&monitor_elf_ex,
                    monitor,
                    &monitor_map_addr,
                    ELF_ET_DYN_BASE, monitor_elf_phdata);
    if (BAD_ADDR(load_addr)) {
        retval = IS_ERR((void *)load_addr) ?
                (int)load_addr : -EINVAL;
        goto out;
    }

    pr_info("[%d] load monitor at %llx\nload interp at %llx\nentry = %llx", current->pid, load_addr, interp_load_addr, interp_entry);

    if (entry)  *entry = interp_entry;
    if (load)   *load = load_addr;
    if (interp_load) *interp_load = interp_load_addr;

    retval = LOAD_SUCCESS;

out:
    return retval;
}

int event_from_monitor(void) {
    int enter = 0;
    int retval = SPR_EVENT_FROM_APPLICATION; // syscall from application
    // Monitor called syscall
    if (check_mapping(__check_monitor_enter, (void *)&enter) == 0) {
        if (enter == 1) {
            retval = SPR_EVENT_FROM_MONITOR; // syscall from monitor
        } else {
            pr_err("corrupted: cannot get monitor status!!\n");
            ASSERT(false);
            retval = SPR_FAILURE_BUG;
        }
    }
    return retval;
}

int
load_monitor(const struct spr_kbuffer *buffer) {
    int retval;
    uint64_t entry, sp, load_addr, interp_load_addr;
    struct pt_regs *reg;
    char *argv[] = { MONITOR_PATH, "--proc-type=secondary", "--log-level=1", NULL };

    reg = current_pt_regs();

    if(check_mapping(__check_mapping, (void *)&entry) == 0) {
        retval = create_elf_tbls(NULL, 0, 0, &sp, reg, buffer, argv);
        if (retval == LOAD_SUCCESS) {
            entry += monitor_elf_ex.e_entry;
            goto success;
        } else {
            goto out;
        }
    }

    retval = do_load_monitor(reg, &entry, &load_addr, &interp_load_addr);
    if (retval != LOAD_SUCCESS) {
        goto out;
    }

    retval = create_elf_tbls(&monitor_elf_ex, load_addr, interp_load_addr, &sp, reg, buffer, argv);
    if(retval != LOAD_SUCCESS) {
        goto out;
    }

success:
    reg->sp = sp;
    reg->cx = reg->ip = entry;
    retval = LOAD_SUCCESS;

out:
    if (retval != LOAD_SUCCESS) {
        pr_err("(%d)load_monitor: cannot transfer logging buffer", smp_processor_id());
    }
    return retval;
}

int loader_init(void) {
    int i, retval;
    char *elf_interpreter = NULL;
    struct elf_phdr *elf_ppnt = NULL;

    loff_t pos;

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
    if (monitor_elf_ex.e_type != ET_DYN)
        goto out_free_monitor;
    if (!elf_check_arch(&monitor_elf_ex))
        goto out_free_monitor;
    if (!monitor->f_op->mmap)
        goto out_free_monitor;
    if (load_elf_phdrs(&monitor_elf_ex, monitor, &monitor_elf_phdata))
        goto out_free_monitor;

    elf_ppnt = monitor_elf_phdata;

    // find INTERP segment
    for (i = 0; i < monitor_elf_ex.e_phnum; i++) {
        if (elf_ppnt->p_type == PT_INTERP) {
            retval = -ENOEXEC;
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
    if (load_elf_phdrs(&interp_elf_ex, interpreter, &interp_elf_phdata))
        goto out_free_dentry;

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