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

#include "secureprov.h"


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

int
elf_load_phdrs(struct elfhdr *elf_ex,
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

unsigned long
elf_load_binary(struct elfhdr *elf_ex,
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
            if (load_addr_set)
                elf_type |= MAP_FIXED;
            else if (elf_ex->e_type == ET_DYN)
                load_addr = -vaddr;
            
            _addr = elf_map(binary, load_addr + vaddr,
                    eppnt, elf_prot, elf_type, total_size);
            total_size = 0;
            if (!*map_addr)
                *map_addr = _addr;
            error = _addr;
            if (BAD_ADDR(_addr))
                goto out;

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