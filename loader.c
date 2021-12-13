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

#include "pinject.h"
#include "common.h"


#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#define BAD_ADDR(x) ((unsigned long)(x) >= TASK_SIZE)

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
__put_ehdr(struct vm_area_struct const * const vma, void *arg) {
	vm_flags_t flags = vma->vm_flags;

    if (flags & VM_EXEC)
        return 0;

	if(put_user(1, (int __user *)vma->vm_start)) {
		printk(KERN_ERR "cannot write __collector_enter @ %lx\n", vma->vm_start);
		return 0;
	}
	copy_to_user((char __user *)(vma->vm_start + 0x10), (char *)arg, sizeof(Elf64_Ehdr));
	return 1;
}

int
check_mapping(const char *filename, 
			  int (*resolve) (struct vm_area_struct const * const vma, void *arg),
			  void *arg)
{
#define PATH_BUF_SIZE 128

    static char buf[PATH_BUF_SIZE];
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct file *file;
	int find;

    mm = current->mm;
    vma = mm->mmap;

    down_read(&mm->mmap_sem);
    for (vma = mm->mmap; vma; vma = vma->vm_next)
    {
        file = vma->vm_file;
        if (file)
        {
            char *p = d_path(&file->f_path, buf, sizeof(buf));
            if (!IS_ERR(p)) 
            {
                char *end = mangle_path(buf, p, "\n");
                *end = '\0';

                if(!strcmp(filename, buf) && (*resolve)((struct vm_area_struct const * const)vma, arg))
                {
					up_read(&mm->mmap_sem);
					return 1;
                }
            }
        }
    }

    up_read(&mm->mmap_sem);
    return 0;
}

/* We need to explicitly zero any fractional pages
   after the data section (i.e. bss).  This would
   contain the junk from the file that should not
   be in memory
 */
static int padzero(unsigned long elf_bss)
{
	unsigned long nbyte;

	nbyte = ELF_PAGEOFFSET(elf_bss);
	if (nbyte)
	{
		nbyte = ELF_MIN_ALIGN - nbyte;
		if (clear_user((void __user *) elf_bss, nbyte))
		{
			return -EFAULT;
		}
	}
	return 0;
}

static unsigned long total_mapping_size(struct elf_phdr *cmds, int nr)
{
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

static unsigned long elf_map(struct file *filep, unsigned long addr,
		struct elf_phdr *eppnt, int prot, int type,
		unsigned long total_size)
{
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

static struct elf_phdr *load_elf_phdrs(struct elfhdr *elf_ex,
				       struct file *elf_file)
{
	struct elf_phdr *elf_phdata = NULL;
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
	return elf_phdata;
}

static unsigned long load_elf_interp(struct elfhdr *interp_elf_ex,
		struct file *interpreter, unsigned long *interp_map_addr,
		unsigned long no_base, struct elf_phdr *interp_elf_phdata)
{
	struct elf_phdr *eppnt;
	unsigned long load_addr = 0;
	int load_addr_set = 0;
	unsigned long last_bss = 0, elf_bss = 0;
	int bss_prot = 0;
	unsigned long error = ~0UL;
	unsigned long total_size;
	int i;

	/* First of all, some simple consistency checks */
	if (interp_elf_ex->e_type != ET_EXEC &&
	    interp_elf_ex->e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(interp_elf_ex))
		goto out;
	if (!interpreter->f_op->mmap)
		goto out;

	total_size = total_mapping_size(interp_elf_phdata,
					interp_elf_ex->e_phnum);
	if (!total_size) {
		error = -EINVAL;
		goto out;
	}

	eppnt = interp_elf_phdata;
	for (i = 0; i < interp_elf_ex->e_phnum; i++, eppnt++) {
		if (eppnt->p_type == PT_LOAD) {
			int elf_type = MAP_PRIVATE /*| MAP_DENYWRITE*/;
			int elf_prot = 0;
			unsigned long vaddr = 0;
			unsigned long k, map_addr;

			if (eppnt->p_flags & PF_R)
				elf_prot = PROT_READ;
			if (eppnt->p_flags & PF_W)
				elf_prot |= PROT_WRITE;
			if (eppnt->p_flags & PF_X)
				elf_prot |= PROT_EXEC;
			vaddr = eppnt->p_vaddr;
			if (interp_elf_ex->e_type == ET_EXEC || load_addr_set)
				elf_type |= MAP_FIXED;
			else if (no_base && interp_elf_ex->e_type == ET_DYN)
				load_addr = -vaddr;

			map_addr = elf_map(interpreter, load_addr + vaddr,
					eppnt, elf_prot, elf_type, total_size);
			total_size = 0;
			if (!*interp_map_addr)
				*interp_map_addr = map_addr;
			error = map_addr;
			if (BAD_ADDR(map_addr))
				goto out;

			if (!load_addr_set &&
			    interp_elf_ex->e_type == ET_DYN) {
				load_addr = map_addr - ELF_PAGESTART(vaddr);
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
	if (padzero(elf_bss)) 
	{
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
	if (last_bss > elf_bss) 
	{
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
				unsigned long load_addr, 
				unsigned long interp_load_addr, 
				unsigned long *target_sp,
				const struct pt_regs *reg,
				int load_auxv,
				char *argv[]) {
#define elf_addr_t unsigned long
#define STACK_ADD(sp, items) ((elf_addr_t __user *)(sp) - (items))
#define STACK_ALLOC(sp, len) ({sp -= (len); sp;})

	int i, argc;
	unsigned long p;
	unsigned long arg_start, env_start, original_rsp;
	elf_addr_t context_addr;

	elf_addr_t __user *sp;
	elf_addr_t __user *u_rand_bytes;
	unsigned char k_rand_bytes[16];
	unsigned char tmp[sizeof(elf_addr_t) + 1];

	struct context_struct context = {
		.fsbase = current->thread.fsbase,
		.gsbase = current->thread.gsbase,
	};
	memcpy(&context.reg, reg, sizeof(struct pt_regs));
	

	original_rsp = *target_sp;
	p = *target_sp & ~0xf;

	// get the number of arg vector and env vector
	for (argc = 0; argv[argc]; argc++);

	// save user context to user stack
	context_addr = p = STACK_ALLOC(p, sizeof(struct context_struct));
	copy_to_user((char __user *)p, (char *)&context, sizeof(struct context_struct));

	for(i = argc - 1; i >= 0; --i) {
		int len = strlen(argv[i]);
		p = STACK_ALLOC(p, len + 1);
		copy_to_user((char __user *)p, argv[i], len + 1);
	}
	arg_start = p;
	argc += 1;

	/*
	 * Generate 16 random bytes for userspace PRNG seeding.
	 */
	get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes));
	u_rand_bytes = (elf_addr_t __user *)
		       STACK_ALLOC(p, sizeof(k_rand_bytes));
	if (__copy_to_user(u_rand_bytes, k_rand_bytes, sizeof(k_rand_bytes)))
		goto err;


#define INSERT_AUX_ENT(id, val, p) \
	({\
		p = STACK_ALLOC(p, sizeof(unsigned long) + sizeof(unsigned long)); \	
		if(put_user((unsigned long)val, (elf_addr_t *)(p) + 1)) \
			goto err; \
		if(put_user((unsigned long)id, (elf_addr_t *)(p))) \
			goto err; \
		p; \
	})

	/*
	* Note that ld.so may be invoke movaps instruction
	* this instruction need 16-byte aligned
	*/
	p &= ~0xf;
	// p = STACK_ALLOC(p, 8);

	/*
	* If we have mapped the collector before,
	* we do not need to create auxv for interpreter
	* so the arugment `load_addr`, `interp_load_addr` and `exec` is not required
	* we only need to put the argc, argv and env onto the stack
	*/
	if (load_auxv) {
		p = INSERT_AUX_ENT(AT_NULL, 0, p);
		p = INSERT_AUX_ENT(AT_RANDOM, (elf_addr_t)(unsigned long)u_rand_bytes, p);
		p = INSERT_AUX_ENT(AT_EXECFN, original_rsp, p);
		p = INSERT_AUX_ENT(AT_ENTRY, load_addr + exec->e_entry, p);
		p = INSERT_AUX_ENT(AT_FLAGS, 0, p);
		p = INSERT_AUX_ENT(AT_BASE, interp_load_addr, p);
		p = INSERT_AUX_ENT(AT_PHNUM, exec->e_phnum, p);
		p = INSERT_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr), p);
		p = INSERT_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff, p);
		p = INSERT_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC, p);
		p = INSERT_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE, p);
		p = INSERT_AUX_ENT(AT_HWCAP, ELF_HWCAP, p);
	}

#define INSERT_ENV_ENT(start, p) \
	({\
		size_t len; \
		p = STACK_ALLOC(p, sizeof(elf_addr_t));\
		if (put_user((elf_addr_t)start, (elf_addr_t *)p)) \
			goto err; \
		len = strnlen_user((void __user *)start, MAX_ARG_STRLEN); \
		if (!len || len > MAX_ARG_STRLEN) \
			goto err; \
		len; \
	})

	// fill NULL as end of env
	p = STACK_ALLOC(p, sizeof(elf_addr_t));
	if (put_user((elf_addr_t)0, (elf_addr_t *)p))
		goto err;

	env_start = current->mm->env_start;
	while (env_start < current->mm->env_end) {
		env_start += INSERT_ENV_ENT(env_start, p);
	}

	sp = STACK_ADD(p, argc + 1);
	*target_sp = (unsigned long)sp;

	if (__put_user(argc, sp++))
		goto err;

	for (i = 0; i < argc - 1; ++i) {
		size_t len = strlen(argv[i]);
		if(put_user((elf_addr_t)arg_start, sp++))
			goto err;
		arg_start += len + 1;
	}

	if (put_user(context_addr, sp++))
		goto err;

	if (put_user(0, sp++))
		goto err;

	return 0;
err:
	*target_sp = original_rsp;
	return -EFAULT;
}

static int
load_elf_collector(const char *filename, 
					const struct pt_regs *reg,
					unsigned long *target_entry, 
					unsigned long *target_sp, char *argv[])
{
	struct file *collector = NULL;
    struct file *interpreter = NULL; /* to shut gcc up */
 	unsigned long load_addr = 0, load_bias = ELF_ET_DYN_BASE;
	char * elf_interpreter = NULL;
	struct elf_phdr *elf_ppnt, *elf_phdata, *interp_elf_phdata = NULL;
	int retval, i;
	unsigned long interp_entry;
	unsigned long interp_load_addr = 0;
	struct 
	{
		struct elfhdr elf_ex;
		struct elfhdr interp_elf_ex;
	} *loc;
	loff_t pos;
    

	loc = kmalloc(sizeof(*loc), GFP_KERNEL);
	if (!loc) 
	{
		retval = -ENOMEM;
		goto out_ret;
	}



	collector = open_exec(filename);
	retval = PTR_ERR(collector);
	if(IS_ERR(collector))
		goto out_ret;

	pos = 0;
	retval = kernel_read(collector, &loc->elf_ex,
				sizeof(loc->elf_ex), &pos);
	if (retval != sizeof(loc->elf_ex))
	{
		if (retval >= 0)
			retval = -EIO;
		goto out_free_collector;
	}

	if(check_mapping(filename, __check_mapping, (void *)target_entry))
    {
		// TODO: create elf table 
		retval = create_elf_tbls(NULL, 0, 0, target_sp, reg, 0, argv);
		if (!retval) {
			*target_entry += loc->elf_ex.e_entry;
			printk(KERN_INFO "%s alread mapped at %08lx\n", filename, *target_entry);
		}
		goto out_free_collector;
    }

	retval = -ENOEXEC;
	/* First of all, some simple consistency checks */
	if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out_free_collector;

	if (loc->elf_ex.e_type != ET_DYN)
		goto out_free_collector;
	if (!elf_check_arch(&loc->elf_ex))
		goto out_free_collector;
	if (!collector->f_op->mmap)
		goto out_free_collector;

	elf_phdata = load_elf_phdrs(&loc->elf_ex, collector);
	if (!elf_phdata)
		goto out_free_collector;

	elf_ppnt = elf_phdata;

    for(i = 0; i < loc->elf_ex.e_phnum; i++)
    {
        if(elf_ppnt->p_type == PT_INTERP)
        {
            /* This is the program interpreter used for
            * shared libraries - for now assume that this
            * is an a.out format binary
            */
            retval = -ENOEXEC;
            if (elf_ppnt->p_filesz > PATH_MAX || 
                elf_ppnt->p_filesz < 2)
                goto out_free_ph;

            retval = -ENOMEM;
            elf_interpreter = kmalloc(elf_ppnt->p_filesz,
                        GFP_KERNEL);
            if (!elf_interpreter)
                goto out_free_ph;

            pos = elf_ppnt->p_offset;
            retval = kernel_read(collector, elf_interpreter,
                        elf_ppnt->p_filesz, &pos);
            if (retval != elf_ppnt->p_filesz)
			{
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
            retval = kernel_read(interpreter, &loc->interp_elf_ex,
                        sizeof(loc->interp_elf_ex), &pos);
            if (retval != sizeof(loc->interp_elf_ex))
			{
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

	unsigned long interp_map_addr = 0;

	retval = -ELIBBAD;
	/* Not an ELF interpreter */
	if (memcmp(loc->interp_elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out_free_dentry;
	/* Verify the interpreter has a valid arch */
	if (!elf_check_arch(&loc->interp_elf_ex))
		goto out_free_dentry;

	/* Load the interpreter program headers */
	interp_elf_phdata = load_elf_phdrs(&loc->interp_elf_ex,
						interpreter);
	if (!interp_elf_phdata)
		goto out_free_dentry;

	interp_entry = load_elf_interp(&loc->interp_elf_ex,
					interpreter,
					&interp_map_addr,
					load_bias, interp_elf_phdata);
	if (!IS_ERR((void *)interp_entry)) 
	{
		/*
			* load_elf_interp() returns relocation
			* adjustment
			*/
		interp_load_addr = interp_entry;
		*target_entry = interp_entry + loc->interp_elf_ex.e_entry;
	}
	if (BAD_ADDR(interp_entry))
	{
		retval = IS_ERR((void *)interp_entry) ?	(int)interp_entry : -EINVAL;
		goto out_free_dentry;
	}

	allow_write_access(interpreter);
	fput(interpreter);
	kfree(elf_interpreter);
	kfree(interp_elf_phdata);

    unsigned long collector_map_addr = 0;
    /* Record that we treat the collector as same as interpreter, so we can reuse `load_elf_interp` to load the collector */
    load_addr = load_elf_interp(&loc->elf_ex,
                    collector,
                    &collector_map_addr,
                    load_bias, elf_phdata);
    if (BAD_ADDR(load_addr)) 
	{
        retval = IS_ERR((void *)load_addr) ?
                (int)load_addr : -EINVAL;
        goto out_free_ph;
    }

	printk(KERN_INFO "load collector at %lx, entry=%lx\ninterp at %lx\n", load_addr, *target_entry, interp_load_addr);

    allow_write_access(collector);
	fput(collector);
    kfree(elf_phdata);

	retval = create_elf_tbls(&loc->elf_ex, load_addr, interp_load_addr, target_sp, reg, 1, argv);
	if(retval < 0)
		// TODO: if create_elf_tbls failed, we need to unmap collector and its interp
		goto out;

	check_mapping(filename, __put_ehdr, &loc->elf_ex);	

    retval = 0;

out:
	kfree(loc);
out_ret:
	return retval;

	/* error cleanup */
out_free_dentry:
	kfree(interp_elf_phdata);
	allow_write_access(interpreter);
	if (interpreter)
		fput(interpreter);
out_free_interp:
	kfree(elf_interpreter);
out_free_ph:
	kfree(elf_phdata);
out_free_collector:
	allow_write_access(collector);
	if (collector)
		fput(collector);

	goto out;
}

static int
__check_collector_enter(struct vm_area_struct const * const vma, void *arg) {
    vm_flags_t flags = vma->vm_flags;

    if (!(flags & VM_WRITE))
        return 0;

    // get data from collector's section `.collector_enter`
    int collector_enter;
    if(get_user(collector_enter, (int __user *)vma->vm_start)) {
        collector_enter = -1;
    }
    // *(unsigned long *)arg = collector_enter;
    *(int *)arg = collector_enter;

    printk(KERN_INFO "read from .collector_enter=%lx\n", collector_enter);

    return 1;
}

int
do_load_collector(const struct pt_regs *reg, unsigned long *target_entry, unsigned long *target_sp, char *argv[])
{
	int retval;
	// we call syscall in collector
    if (check_mapping(COLLECTOR_PATH, __check_collector_enter, (void *)&retval)) {
        if (retval == 1) return 0;
        else if (retval < 0) {
            printk(KERN_ERR "!!can not get collector's status!!\n");
            return retval;
        }
    }

	// otherwise it is the first time
	// we need to load the collector
	retval = load_elf_collector(COLLECTOR_PATH, reg, target_entry, target_sp, argv);
	return retval;
}
