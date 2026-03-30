#include <linux/elf.h>
#include <linux/file.h>
#include <linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/fs_struct.h>
#include <linux/delay.h>
#include <linux/mman.h>
#include <linux/vmalloc.h>
#include <linux/version.h>

#include "nodrop.h"
#include "syscall.h"
#include "procinfo.h"

#include "common.h"
#include "config.h"

static struct elf_phdr *monitor_elf_phdata, *interp_elf_phdata;
static struct elf_shdr *monitor_elf_shdata;
static struct elfhdr   monitor_elf_ex, interp_elf_ex;
static struct file *filp_monitor, *filp_interpreter;

static unsigned long monitor_info_off;

static uint64_t
calc_phdr_addr(const struct elfhdr *exec,
               const struct elf_phdr *phdrs,
               uint64_t load_addr)
{
    int i;

    for (i = 0; i < exec->e_phnum; i++) {
        const struct elf_phdr *p = &phdrs[i];

        if (p->p_type != PT_LOAD)
            continue;

        if (p->p_offset <= exec->e_phoff &&
            exec->e_phoff < p->p_offset + p->p_filesz) {
            return load_addr + (exec->e_phoff - p->p_offset + p->p_vaddr);
        }
    }

    /* Fallback for malformed binaries: keep historical behavior. */
    return load_addr + exec->e_phoff;
}

#define MAPPING_OK          0 
#define MAPPING_NEXT        1
#define MAPPING_FINISH      2
#define MAPPING_NOTFOUND    3

static int
get_monitor_addr(struct vm_area_struct const * const vma, void *arg)
{
    unsigned long addr = ((unsigned long *)arg)[0];
    unsigned long end = addr + ((unsigned long *)arg)[1];

    if (end < vma->vm_start)
        return MAPPING_FINISH;
    else if (MAX(vma->vm_start, addr) < MIN(vma->vm_end, end))
        return MAPPING_OK;
    return MAPPING_NEXT;
}

static int
check_mapping(int (*resolve) (struct vm_area_struct const * const vma, void *arg),
              void *arg)
{
    int retval;
    struct mm_struct *mm;
    struct vm_area_struct *vma;

    mm = current->mm;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    VMA_ITERATOR(vmi, mm, 0);
    for_each_vma(vmi, vma) {
    // for (vma = mm->mmap; vma; vma = vma->vm_next) {
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        if (vma->vm_file == filp_monitor) {
            retval = (*resolve)((struct vm_area_struct const * const)vma, arg);
            switch(retval) {
            case MAPPING_OK:
            case MAPPING_FINISH:
                goto out;
            case MAPPING_NEXT:
                break;
            default:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
                    mmap_read_unlock(mm);
#else
                    up_read(&mm->mmap_sem);
#endif
                ASSERT(false);
            }
        }
    }

    retval = MAPPING_NOTFOUND;

out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif
    return retval;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
int
nod_mmap_check(struct nod_proc_info *p, unsigned long addr, unsigned long length)
{
    unsigned long end = addr + length;
    unsigned long arg[2] = {addr, length};

    if (end < addr) {
        end = ~0UL;
    }

    if (p && p->stack_info.stack_start && p->stack_info.stack_end) {
        if (MAX(addr, (unsigned long)p->stack_info.stack_start) <
            MIN(end, (unsigned long)p->stack_info.stack_end)) {
            return 1;
        }
    }

    return check_mapping(get_monitor_addr, (void *)arg) == MAPPING_OK ? 1 : 0;
}

#else

int
nod_mmap_check(unsigned long addr, unsigned long length) 
{
    unsigned long arg[2] = {addr, length};
    return check_mapping(get_monitor_addr, (void *)arg) == MAPPING_OK ? 1 : 0;
}

#endif


static unsigned long
create_stack_with_red_zone(unsigned long addr, unsigned long size)
{
    unsigned long stack_begin;
    unsigned long prefer_addr = addr;
    if (prefer_addr > PAGE_SIZE) {
        prefer_addr -= PAGE_SIZE;
    }
    stack_begin = vm_mmap(NULL, prefer_addr, size + PAGE_SIZE + PAGE_SIZE, 0, MAP_PRIVATE | MAP_ANONYMOUS, 0);
    if (BAD_ADDR(stack_begin)) {
        return stack_begin;
    }

    addr = stack_begin + PAGE_SIZE;
    vm_munmap(addr, size);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
    addr = vm_mmap(NULL, addr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0);
#else
    addr = vm_mmap(NULL, addr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_FIXED, 0);
#endif
    return addr;
}


static int
create_elf_tbls(struct elfhdr *exec,
                uint64_t load_addr,
                uint64_t phdr_addr,
                uint64_t interp_load_addr,
                struct nod_stack_info *stack_info,
                uint64_t *stack_info_addr,
                uint64_t *target_sp,
                int argc,
                const char *argv[]) {

#define STACK_ROUND(sp, items)  ((elf_addr_t __user *)(((uint64_t) ((sp) - (items))) &~ 15UL))
#define STACK_ADD(sp, items)    ((elf_addr_t __user *)(sp) - (items))
#define STACK_ALLOC(sp, len)    ({(sp) -= (len); sp;})

    int i, envc, elf_info_idx, items;
    unsigned long prefault_addr;
    unsigned long prefault_size;
    unsigned long prefault_ret;
    uint64_t p, arg_start, env_start;
    unsigned char k_rand_bytes[16];

    elf_addr_t __user *sp;
    elf_addr_t __user *u_rand_bytes;
    elf_addr_t *elf_info = NULL;

    // allocate a dedicate stack for the consumer
    p = create_stack_with_red_zone(0, CONFIG_MONITOR_STACK_SIZE);
    if (BAD_ADDR(p))
        goto err;
    stack_info->stack_start = p;
    stack_info->stack_end = p + CONFIG_MONITOR_STACK_SIZE;
    p = stack_info->stack_end - sizeof(void *);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    /*
     * In some trace/hook contexts, copy_to_user cannot fault in missing pages.
     * Populate only a small stack-top window that we are about to write.
     */
    prefault_size = PAGE_SIZE * 16;
    if (prefault_size > CONFIG_MONITOR_STACK_SIZE)
        prefault_size = CONFIG_MONITOR_STACK_SIZE;
    prefault_addr = stack_info->stack_end - prefault_size;
    prefault_ret = vm_mmap(NULL, prefault_addr, prefault_size,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK |
                           MAP_FIXED | MAP_POPULATE,
                           0);
    if (prefault_ret != prefault_addr)
        goto err;
#endif

    // generate random bytes
    get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes));
    u_rand_bytes = (elf_addr_t __user *)STACK_ALLOC(p, sizeof(k_rand_bytes));
    if (copy_to_user(u_rand_bytes, k_rand_bytes, sizeof(k_rand_bytes)))
        goto err;

    // put nod_stack_info into Runtime stack
    *stack_info_addr = p = STACK_ALLOC(p, sizeof(*stack_info));
    if (copy_to_user((char __user *)p, stack_info, sizeof(*stack_info)))
        goto err;

    for(i = argc - 1; i >= 0; --i) {
        int len = strlen(argv[i]) + 1;
        p = STACK_ALLOC(p, len);
        if (copy_to_user((char __user *)p, argv[i], len))
            goto err;
    }
    arg_start = p;

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
    elf_info = vmalloc(sizeof(elf_addr_t) * 12 * 2);
    if (!elf_info) goto err;
    INSERT_AUX_ENT(AT_HWCAP, ELF_HWCAP);
    INSERT_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
    INSERT_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
    INSERT_AUX_ENT(AT_PHDR, phdr_addr);
    INSERT_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr));
    INSERT_AUX_ENT(AT_PHNUM, exec->e_phnum);
    INSERT_AUX_ENT(AT_BASE, interp_load_addr);
    INSERT_AUX_ENT(AT_FLAGS, 0);
    INSERT_AUX_ENT(AT_ENTRY, load_addr + exec->e_entry);
    // INSERT_AUX_ENT(AT_EXECFN, original_rsp);
    INSERT_AUX_ENT(AT_RANDOM, (elf_addr_t)(unsigned long)u_rand_bytes);
    INSERT_AUX_ENT(AT_NULL, 0);

    #define INSERT_ENV_ENT(start, sp) \
    ({\
        size_t len; \
        if (put_user((elf_addr_t)start, (elf_addr_t *)sp++)) \
            goto err; \
        len = strnlen_user((void __user *)(start), MAX_ARG_STRLEN); \
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

    // . <- stacktop
    /* argc + 1
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
     * ...
     * Contents of argv <--- arg_start
     * ...
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
    if(put_user((elf_addr_t)*stack_info_addr, sp++))
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
    if (copy_to_user(sp, elf_info, elf_info_idx * sizeof(elf_addr_t))) {
        goto err;
    }

    vfree(elf_info);
    return NOD_SUCCESS;

err:
    vfree(elf_info);
    return -EFAULT;
}

static int
update_stack_info(const struct nod_stack_info *stack_info, uint64_t stack_info_addr)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
    return copy_to_user((char __user *)stack_info_addr, stack_info, sizeof(*stack_info));
#else
    return copy_to_user((char __user *)stack_info_addr, stack_info, sizeof(*stack_info)) ? -EFAULT : 0;
#endif
}

static int
do_load_monitor(struct nod_proc_info *p, int argc, const char *argv[])
{
    int retval;
    uint64_t load_addr = 0;
    uint64_t interp_load_addr = 0;
    uint64_t interp_map_addr = 0;
    uint64_t load_entry;
    uint64_t monitor_map_addr;
    uint64_t phdr_addr;

    if (filp_interpreter) {
        interp_load_addr = elf_load_binary(&interp_elf_ex, filp_interpreter, &interp_map_addr,
                        ELF_ET_DYN_BASE, interp_elf_phdata);
        if (BAD_ADDR(interp_load_addr)) {
            retval = IS_ERR((void *)interp_load_addr) ?	
                     (int)interp_load_addr : -EINVAL;
            goto out;
        }
    }

    load_addr = elf_load_binary(&monitor_elf_ex, filp_monitor, &monitor_map_addr,
                    ELF_ET_DYN_BASE, monitor_elf_phdata);

    if (BAD_ADDR(load_addr)) {
        retval = IS_ERR((void *)load_addr) ?
                (int)load_addr : -EINVAL;
        goto out;
    }

    phdr_addr = calc_phdr_addr(&monitor_elf_ex, monitor_elf_phdata, load_addr);

    retval = create_elf_tbls(&monitor_elf_ex, load_addr, phdr_addr,
                             interp_load_addr,
                             &p->stack_info, &p->stack_info_addr, &p->stack_addr, argc, argv);
    if (retval) {
        goto out;
    }

    load_entry = filp_interpreter ? 
                interp_load_addr + interp_elf_ex.e_entry : 
                load_addr + monitor_elf_ex.e_entry;

    vpr_dbg("load monitor at %llx\n"
            "load interp at %llx\n"
            "entry = %llx\n", load_addr, interp_load_addr, load_entry);

    p->entry_addr = load_entry;
    retval = NOD_SUCCESS;

out:
    return retval;
}

int
nod_load_monitor(struct nod_proc_info *p)
{
    int retval;
    int retried = 0;
    struct pt_regs *regs;

    const int argc = 1;
    const char *argv[] = { CONFIG_MONITOR_PATH, NULL };

    regs = current_pt_regs();

    switch(p->status) {
    case NOD_CLONE:
        nod_copy_procinfo(current, p);
        break;
    case NOD_SHARE:
        nod_share_procinfo(current, p);
        break;
    default:
        break;
    }

retry_load:

    if (!p->entry_addr) {
        retval = do_load_monitor(p, argc, argv);
        if (retval != NOD_SUCCESS) {
            if (!retried && (retval == -EEXIST || retval == -EFAULT)) {
                retried = 1;
                goto retry_load;
            }
            goto out;
        }
        vpr_dbg("monitor: entry 0x%llx stack [0x%llx-0x%llx] stack_info_addr 0x%llx\n", 
                 p->entry_addr, p->stack_info.stack_start,
                 p->stack_info.stack_end, p->stack_info_addr);
    }

    p->stack_info.syscall_nr = syscall_get_nr(current, regs);
    // store exit_code from the rdi register for exit-family syscalls
    syscall_get_arguments_deprecated(current, regs, 0, 1, &p->stack_info.exit_code);
    retval = update_stack_info(&p->stack_info, p->stack_info_addr);
    if (retval != 0) {
        if (!retried && retval == -EFAULT) {
            retried = 1;
            p->entry_addr = 0;
            p->stack_info_addr = 0;
            goto retry_load;
        }
        goto out;
    }

    nod_proc_set_in(p);

    nod_prepare_security(p);
    nod_prepare_context(p, regs);

    elf_reg_init(&current->thread, regs, 0);
    regs->sp = p->stack_addr;
    regs->cx = regs->ip = p->entry_addr;

    return NOD_SUCCESS_LOAD;

out:
    vpr_err("cannot transfer logging buffer (%d)\n", retval);
    return retval;
}

int loader_init(void)
{
    int i, retval;
    loff_t pos;
    char *elf_shstrtab = NULL;
    char *elf_interpreter = NULL;
    struct elf_phdr *elf_ppnt = NULL;
    struct elf_shdr *elf_spnt = NULL;

    filp_monitor = NULL;
    filp_interpreter = NULL;

    monitor_elf_shdata = NULL;
    monitor_elf_phdata = NULL;
    interp_elf_phdata = NULL;

    monitor_info_off = 0;

    filp_monitor = open_exec(CONFIG_MONITOR_PATH);
    retval = PTR_ERR(filp_monitor);
    if (IS_ERR(filp_monitor)) {
        filp_monitor = NULL;
        goto out;
    }

    pos = 0;
    retval = kernel_read(filp_monitor, &monitor_elf_ex, sizeof(monitor_elf_ex), &pos);
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
    if (!filp_monitor->f_op->mmap)
        goto out_free_monitor;
    /* Load Program Header Table */
    if (elf_load_phdrs(&monitor_elf_ex, filp_monitor, &monitor_elf_phdata))
        goto out_free_monitor;
    /* Load Section Header Table */
    if (elf_load_shdrs(&monitor_elf_ex, filp_monitor, &monitor_elf_shdata))
        goto out_free_monitor;
    /* Load section str table */
    if (elf_load_shstrtab(&monitor_elf_ex, monitor_elf_shdata, filp_monitor, &elf_shstrtab))
        goto out_free_monitor;

    // Find .monitor.info Section
    elf_spnt = monitor_elf_shdata;
    for (i = 0; i < monitor_elf_ex.e_shnum; i++) {
        if (!strcmp(&elf_shstrtab[elf_spnt->sh_name], NOD_SECTION_NAME)) {
            monitor_info_off = elf_spnt->sh_addr;      
            break;
        }
        elf_spnt++;
    }

    if (monitor_info_off == 0) {
        retval = -EINVAL;
        pr_err("Can nod find " NOD_SECTION_NAME "\n");
        goto out_free_monitor;
    }

    // find INTERP segment
    elf_ppnt = monitor_elf_phdata;
    for (i = 0; i < monitor_elf_ex.e_phnum; i++) {
        if (elf_ppnt->p_type == PT_INTERP) {
            retval = 0;
            if (elf_ppnt->p_filesz > PATH_MAX ||
                elf_ppnt->p_filesz < 2)
                goto out_free_monitor;

            retval = -ENOMEM;
            elf_interpreter = vmalloc(elf_ppnt->p_filesz);
            if (!elf_interpreter)
                goto out_free_monitor;

            pos = elf_ppnt->p_offset;
            retval = kernel_read(filp_monitor, elf_interpreter, elf_ppnt->p_filesz, &pos);
            if (retval != elf_ppnt->p_filesz) {
                if (retval >= 0)
                    retval = -EIO;
                goto out_free_interp;
            }

            /* make sure path is NULL terminated */
            retval = -ENOEXEC;
            if (elf_interpreter[elf_ppnt->p_filesz - 1] != '\0')
                goto out_free_interp;

            filp_interpreter = open_exec(elf_interpreter);
            retval = PTR_ERR(filp_interpreter);
            if (IS_ERR(filp_interpreter)) {
                filp_interpreter = NULL;
                goto out_free_interp;
            }

            /* Get the exec headers */
            pos = 0;
            retval = kernel_read(filp_interpreter, &interp_elf_ex, sizeof(interp_elf_ex), &pos);
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

    vfree(elf_interpreter);
    elf_interpreter = NULL;

    retval = -ELIBBAD;
    /* Not an ELF interpreter */
    if (memcmp(interp_elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
        goto out_free_dentry;
    /* Verify the interpreter has a valid arch */
    if (!elf_check_arch(&interp_elf_ex))
        goto out_free_dentry;

    /* Load the interpreter program headers */
    if (elf_load_phdrs(&interp_elf_ex, filp_interpreter, &interp_elf_phdata))
        goto out_free_dentry;

success:

    retval = 0;

out:
    return retval;

out_free_dentry:
    if (filp_interpreter) {
        allow_write_access(filp_interpreter);
        fput(filp_interpreter);
        filp_interpreter = NULL;
    }
out_free_interp:
    if (elf_interpreter) {
        vfree(elf_interpreter);
        elf_interpreter = NULL;
    }
out_free_monitor:
    if (filp_monitor) {
        allow_write_access(filp_monitor);
        fput(filp_monitor);
        filp_monitor = NULL;
    }
    if (elf_shstrtab) {
        vfree(elf_shstrtab);
        elf_shstrtab = NULL;
    }
    goto out;
}

void loader_destory(void) {
    if (filp_interpreter) {
        allow_write_access(filp_interpreter);
        fput(filp_interpreter);
        filp_interpreter = NULL;
    }

    if (filp_monitor) {
        allow_write_access(filp_monitor);
        fput(filp_monitor);
        filp_monitor = NULL;
    }

    if (monitor_elf_phdata) {
        vfree(monitor_elf_phdata);
        monitor_elf_phdata = NULL;
    }
    if (monitor_elf_shdata) {
        vfree(monitor_elf_shdata);
        monitor_elf_shdata = NULL;
    }
    if (interp_elf_phdata) {
        vfree(interp_elf_phdata);
        interp_elf_phdata = NULL;
    }
}
