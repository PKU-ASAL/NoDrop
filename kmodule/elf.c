#include <linux/kernel.h>
#include <linux/elf.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/namei.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/version.h>

#include "nodrop.h"


#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

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
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
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
#else
    int i;
    elf_addr_t min_addr = -1;
    elf_addr_t max_addr = 0;
    bool pt_load = false;

    for (i = 0; i < nr; i++) {
        if (cmds[i].p_type == PT_LOAD) {
            min_addr = min(min_addr, (elf_addr_t)ELF_PAGESTART(cmds[i].p_vaddr));
            max_addr = max(max_addr, (elf_addr_t)(cmds[i].p_vaddr + cmds[i].p_memsz));
            pt_load = true;
        }
    }

    return pt_load ? (max_addr - min_addr) : 0;
#endif
}

static unsigned long
elf_map(struct file *filep, unsigned long addr,
        struct elf_phdr *eppnt, int prot, int type,
        unsigned long total_size) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
    unsigned long map_addr;
    unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
    unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);
    addr = ELF_PAGESTART(addr);
    size = ELF_PAGEALIGN(size);

    /* mmap() will return -EINVAL if given a zero size, but a
     * segment with zero filesize is perfectly valid */
    if (!size)
        return addr;

    if (total_size) {
        total_size = ELF_PAGEALIGN(total_size);
        map_addr = vm_mmap(filep, addr, total_size, prot, type, off);
        if (!BAD_ADDR(map_addr))
            vm_munmap(map_addr+size, total_size-size);
    } else {
        map_addr = vm_mmap(filep, addr, size, prot, type, off);
    }

    return map_addr;
#else
    unsigned long map_addr;
    unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
    unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);
    addr = ELF_PAGESTART(addr);
    size = ELF_PAGEALIGN(size);

    /* mmap() may reject size=0 but zero-sized PT_LOAD filesz is valid. */
    if (!size)
        return addr;

    if (total_size) {
        total_size = ELF_PAGEALIGN(total_size);
        map_addr = vm_mmap(filep, addr, total_size, prot, type, off);
        if (!BAD_ADDR(map_addr))
            vm_munmap(map_addr+size, total_size-size);
    } else {
        map_addr = vm_mmap(filep, addr, size, prot, type, off);
    }

    return map_addr;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
/*
 * Load one PT_LOAD segment and materialize trailing zero pages/bss in the
 * same way as Linux 6.8 binfmt_elf does.
 */
static unsigned long
elf_load(struct file *filep, unsigned long addr,
         struct elf_phdr *eppnt, int prot, int type,
         unsigned long total_size)
{
    unsigned long map_addr;
    unsigned long zero_start, zero_end;

    if (eppnt->p_filesz) {
        map_addr = elf_map(filep, addr, eppnt, prot, type, total_size);
        if (BAD_ADDR(map_addr))
            return map_addr;

        if (eppnt->p_memsz > eppnt->p_filesz) {
            zero_start = map_addr + ELF_PAGEOFFSET(eppnt->p_vaddr) + eppnt->p_filesz;
            zero_end = map_addr + ELF_PAGEOFFSET(eppnt->p_vaddr) + eppnt->p_memsz;

            /*
             * Zero the end of the last file-backed page. Keep compatibility
             * with non-writable segments where this may legitimately fail.
             */
            if (padzero(zero_start) && (prot & PROT_WRITE))
                return -EFAULT;
        }
    } else {
        map_addr = zero_start = ELF_PAGESTART(addr);
        zero_end = zero_start + ELF_PAGEOFFSET(eppnt->p_vaddr) + eppnt->p_memsz;
    }

    if (eppnt->p_memsz > eppnt->p_filesz) {
        int err;

        zero_start = ELF_PAGEALIGN(zero_start);
        zero_end = ELF_PAGEALIGN(zero_end);

        err = vm_brk_flags(zero_start, zero_end - zero_start,
                prot & PROT_EXEC ? VM_EXEC : 0);
        if (err)
            map_addr = err;
    }

    return map_addr;
}
#endif

int
elf_load_phdrs(struct elfhdr *elf_ex,
               struct file *elf_file,
               struct elf_phdr **elf_phdrs)
{
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

    elf_phdata = vmalloc(size);
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
        vfree(elf_phdata);
        elf_phdata = NULL;
    }
    *elf_phdrs = elf_phdata;
    return err;
}

int
elf_load_shdrs(struct elfhdr *elf_ex,
               struct file *elf_file,
               struct elf_shdr **elf_shdrs)
{
    struct elf_shdr *elf_shdata;
    int retval, size, err = -1;
    loff_t pos = elf_ex->e_shoff;

    /*
     * If the size of this structure has changed, then punt, since
     * we will be doing the wrong thing.
     */
    if (elf_ex->e_shentsize != sizeof(struct elf_shdr))
        goto out;

    /* Sanity check the number of section headers... */
    if (elf_ex->e_shnum < 1 ||
        elf_ex->e_shnum > 65536U / sizeof(struct elf_shdr))
        goto out;

    /* ...and their total size. */
    size = sizeof(struct elf_shdr) * elf_ex->e_shnum;
    if (size > ELF_MIN_ALIGN)
        goto out;

    elf_shdata = vmalloc(size);
    if (!elf_shdata)
        goto out;
    /* Read in the section headers */
    retval = kernel_read(elf_file, elf_shdata, size, &pos);
    if (retval != size) {
        err = (retval < 0) ? retval : -EIO;
        goto out;
    }

    /* Success! */
    err = 0;
out:
    if (err) {
        vfree(elf_shdata);
        elf_shdata = NULL;
    }
    *elf_shdrs = elf_shdata;
    return err;
}

int
elf_load_shstrtab(struct elfhdr *elf_ex,
                  struct elf_shdr *elf_shdrs,
                  struct file *elf_file,
                  char **elf_shstrtab)
{
    int retval, size, err = -1;
    char *elf_shstrdata;
    loff_t pos;
    struct elf_shdr *str_shdr = &elf_shdrs[elf_ex->e_shstrndx];

    if (elf_ex->e_shstrndx < 1 || elf_ex->e_shstrndx >= elf_ex->e_shnum)
        goto out;

    size = str_shdr->sh_size;
    pos = str_shdr->sh_offset;

    elf_shstrdata = vmalloc(size);
    if (!elf_shstrdata)
        goto out;

    retval = kernel_read(elf_file, elf_shstrdata, size, &pos);
    if (retval != size) {
        err = (retval < 0) ? retval : -EIO;
        goto out;
    }

    err = 0;

out:
    if (err) {
        vfree(elf_shstrdata);
        elf_shstrdata = NULL;
    }
    *elf_shstrtab = elf_shstrdata;
    return err;
}

unsigned long
elf_load_binary(struct elfhdr *elf_ex,
        struct file *binary, uint64_t *map_addr,
        unsigned long no_base, struct elf_phdr *elf_phdrs) {
    int i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    int first_pt_load = 1;
#else
    int load_addr_set = 0;
    int bss_prot = 0;
#endif
    struct elf_phdr *eppnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    uint64_t load_bias = 0;
#else
    uint64_t load_addr = 0;
    uint64_t last_bss = 0, elf_bss = 0;
#endif
    unsigned long error = ~0UL;
    unsigned long total_size = 0;

    /* First of all, some simple consistency checks */
    if (elf_ex->e_type != ET_EXEC &&
        elf_ex->e_type != ET_DYN)
        goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
    total_size = total_mapping_size(elf_phdrs, elf_ex->e_phnum);
    if (!total_size)
#else
    if (!total_mapping_size(elf_phdrs, elf_ex->e_phnum))
#endif
    {
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
            if (!first_pt_load) {
                elf_type |= MAP_FIXED;
            } else if (elf_ex->e_type == ET_EXEC) {
                elf_type |= MAP_FIXED_NOREPLACE;
            } else if (elf_ex->e_type == ET_DYN) {
                total_size = total_mapping_size(elf_phdrs, elf_ex->e_phnum);
                if (!total_size) {
                    error = -EINVAL;
                    goto out;
                }

                /*
                 * The monitor is injected into an already-populated mm, not
                 * created through execve(). For ET_DYN on 6.8+, letting the
                 * first mapping choose a free area avoids -EEXIST collisions
                 * against existing VMAs when a fixed ELF_ET_DYN_BASE is busy.
                 */
                load_bias = 0;
            }

            _addr = elf_load(binary, load_bias + vaddr,
                             eppnt, elf_prot, elf_type,
                             first_pt_load ? total_size : 0);
            total_size = 0;
            error = _addr;
            if (!*map_addr)
                *map_addr = _addr;
            if (BAD_ADDR(_addr)) {
                vpr_dbg("map segment at %llx failed (%ld)\n", load_bias + vaddr, _addr);
                goto out;
            }

            if (first_pt_load) {
                first_pt_load = 0;
                if (elf_ex->e_type == ET_DYN) {
                    load_bias += _addr - ELF_PAGESTART(load_bias + vaddr);
                }
            }

            k = load_bias + eppnt->p_vaddr;
            if (BAD_ADDR(k) ||
                eppnt->p_filesz > eppnt->p_memsz ||
                eppnt->p_memsz > TASK_SIZE ||
                TASK_SIZE - eppnt->p_memsz < k) {
                error = -EINVAL;
                goto out;
            }
#else
            if (load_addr_set)
                elf_type |= MAP_FIXED;
            else if (elf_ex->e_type == ET_DYN || elf_ex->e_type == ET_EXEC) 
                load_addr = -vaddr;
            
            _addr = elf_map(binary, load_addr + vaddr,
                    eppnt, elf_prot, elf_type, total_size);
            total_size = 0;
            if (!*map_addr)
                *map_addr = _addr;
            error = _addr;
            if (BAD_ADDR(_addr)) {
                vpr_dbg("map segment at %llx failed (%d)\n", load_addr + vaddr, _addr);
                goto out;
            }

            if (!load_addr_set) {
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

            k = load_addr + eppnt->p_vaddr + eppnt->p_filesz;
            if (k > elf_bss)
                elf_bss = k;

            k = load_addr + eppnt->p_vaddr + eppnt->p_memsz;
            if (k > last_bss) {
                last_bss = k;
                bss_prot = elf_prot;
            }
#endif
        }
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
    if (padzero(elf_bss)) {
        error = -EFAULT;
        goto out;
    }

    elf_bss = ELF_PAGEALIGN(elf_bss);
    last_bss = ELF_PAGEALIGN(last_bss);
    if (last_bss > elf_bss) {
        error = vm_brk_flags(elf_bss, last_bss - elf_bss,
                bss_prot & PROT_EXEC ? VM_EXEC : 0);
        if (error)
            goto out;
    }
#endif

    error =
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
        load_bias;
#else
        load_addr;
#endif
out:
    return error;
}

void elf_reg_init(struct thread_struct *t,
				   struct pt_regs *regs, const u16 ds)
{
	/* ax gets execve's return value. */
	/*regs->ax = */ regs->bx = regs->cx = regs->dx = 0;
	regs->si = regs->di = regs->bp = 0;
	regs->r8 = regs->r9 = regs->r10 = regs->r11 = 0;
	regs->r12 = regs->r13 = regs->r14 = regs->r15 = 0;
	t->fsbase = t->gsbase = 0;
	t->fsindex = t->gsindex = 0;
	t->ds = t->es = ds;
}
