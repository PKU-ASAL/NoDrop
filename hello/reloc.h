#ifndef _RELOC_H_
#define _RELOC_H_

#include <elf.h>

#define DT_IA_64_NUM   1
#define DT_THISPROCNUM DT_IA_64_NUM

#define __used 	 __attribute__((used))
#define __inline __attribute__((always_inline))
#define __hidden __attribute__ ((visibility ("hidden")))

struct reloc_struct {
	ElfW(Dyn) * l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
		      + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
	ElfW(Addr)  l_addr;  // load address
	ElfW(Dyn) * l_ld;    // dynamic section start
};

// copy from glibc/elf/dynamic-link.h
#define Rel							Rela
#define elf_dynamic_do_Rel			elf_dynamic_do_Rela
#define elf_machine_rel				elf_machine_rela
#define elf_machine_rel_relative	elf_machine_rela_relative
#define D_PTR(map, i) 				(map)->i->d_un.d_ptr
#define ELF_DYNAMIC_DO_REL(map, lazy, skip_ifunc) \
  _ELF_DYNAMIC_DO_RELOC (REL, Rel, map, lazy, skip_ifunc)

#define ELF_DYNAMIC_DO_RELA(map, lazy, skip_ifunc) \
  _ELF_DYNAMIC_DO_RELOC (RELA, Rela, map, lazy, skip_ifunc)

#define ELF_DYNAMIC_RELOCATE(map, lazy, consider_profile, skip_ifunc) \
  do {\
    ELF_DYNAMIC_DO_REL ((map), edr_lazy, skip_ifunc);			      \
    ELF_DYNAMIC_DO_RELA ((map), edr_lazy, skip_ifunc);			      \
  } while (0)

#define _ELF_DYNAMIC_DO_RELOC(RELOC, reloc, map, do_lazy, skip_ifunc) \
  do { \
    struct { ElfW(Addr) start, size; __typeof (((ElfW(Dyn) *) 0)->d_un.d_val) nrelative; int lazy; } \
      ranges[2] = { { 0, 0, 0, 0 }, { 0, 0, 0, 0 } }; \
    if ((map)->l_info[DT_##RELOC]) { \
        ranges[0].start = D_PTR ((map), l_info[DT_##RELOC]); \
        ranges[0].size = (map)->l_info[DT_##RELOC##SZ]->d_un.d_val; \
        if (map->l_info[VERSYMIDX (DT_##RELOC##COUNT)] != NULL) \
            ranges[0].nrelative = map->l_info[VERSYMIDX (DT_##RELOC##COUNT)]->d_un.d_val; \
    }									      \
    if ((map)->l_info[DT_PLTREL] && (map)->l_info[DT_PLTREL]->d_un.d_val == DT_##RELOC) { \
        ElfW(Addr) start = D_PTR ((map), l_info[DT_JMPREL]);		      \
        ElfW(Addr) size = (map)->l_info[DT_PLTRELSZ]->d_un.d_val;	      \
        if (ranges[0].start + ranges[0].size == (start + size))		      \
            ranges[0].size -= size;					      \
        ranges[0].size += size;					      \
    }									      \
    elf_dynamic_do_##reloc ((map), ranges[0].start, ranges[0].size, ranges[0].nrelative, 0, skip_ifunc);	      \
  } while (0)

#define VERSYMIDX(sym)	(DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX (sym))
#define VALIDX(tag)	(DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM \
			 + DT_EXTRANUM + DT_VALTAGIDX (tag))
#define ADDRIDX(tag)	(DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM \
			 + DT_EXTRANUM + DT_VALNUM + DT_ADDRTAGIDX (tag))
///////////////////////////////////////

#define START_ENTRY asm ("\
.text\n\
	.p2align 4\n\
.globl _start\n\
_start:\n\
	movl %esp, %edi\n\
	call _reloc_start\n\
	# Save the user entry point address in %r12.\n\
	jmp *%rax\n\
.previous\n\
");

#endif // _RELOC_H_