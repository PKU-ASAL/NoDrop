#ifndef _INTERNAL_RELOC_H
#define _INTERNAL_RELOC_H

#include <features.h>
#include <elf.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#if UINTPTR_MAX == 0xffffffff
typedef Elf32_Ehdr Ehdr;
typedef Elf32_Phdr Phdr;
typedef Elf32_Sym Sym;
#define R_TYPE(x) ((x)&255)
#define R_SYM(x) ((x)>>8)
#define R_INFO ELF32_R_INFO
#else
typedef Elf64_Ehdr Ehdr;
typedef Elf64_Phdr Phdr;
typedef Elf64_Sym Sym;
#define R_TYPE(x) ((x)&0x7fffffff)
#define R_SYM(x) ((x)>>32)
#define R_INFO ELF64_R_INFO
#endif

/* These enum constants provide unmatchable default values for
 * any relocation type the arch does not use. */
enum {
	REL_NONE = 0,
	REL_SYMBOLIC = -100,
	REL_USYMBOLIC,
	REL_GOT,
	REL_PLT,
	REL_RELATIVE,
	REL_OFFSET,
	REL_OFFSET32,
	REL_COPY,
	REL_SYM_OR_REL,
	REL_DTPMOD,
	REL_DTPOFF,
	REL_TPOFF,
	REL_TPOFF_NEG,
	REL_TLSDESC,
	REL_FUNCDESC,
	REL_FUNCDESC_VAL,
};

struct fdpic_loadseg {
	uintptr_t addr, p_vaddr, p_memsz;
};

struct fdpic_loadmap {
	unsigned short version, nsegs;
	struct fdpic_loadseg segs[];
};

struct fdpic_dummy_loadmap {
	unsigned short version, nsegs;
	struct fdpic_loadseg segs[1];
};

#define LDSO_ARCH "x86_64"

#define REL_SYMBOLIC    R_X86_64_64
#define REL_OFFSET32    R_X86_64_PC32
#define REL_GOT         R_X86_64_GLOB_DAT
#define REL_PLT         R_X86_64_JUMP_SLOT
#define REL_RELATIVE    R_X86_64_RELATIVE
#define REL_COPY        R_X86_64_COPY
#define REL_DTPMOD      R_X86_64_DTPMOD64
#define REL_DTPOFF      R_X86_64_DTPOFF64
#define REL_TPOFF       R_X86_64_TPOFF64
#define REL_TLSDESC     R_X86_64_TLSDESC

#define CRTJMP(pc,sp) __asm__ __volatile__( \
	"mov %1,%%rsp ; jmp *%0" : : "r"(pc), "r"(sp) : "memory" )

#define GETFUNCSYM(fp, sym, got) __asm__ ( \
	".hidden " #sym "\n" \
	"	lea " #sym "(%%rip),%0\n" \
	: "=r"(*fp) : : "memory" )

#ifndef FDPIC_CONSTDISP_FLAG
#define FDPIC_CONSTDISP_FLAG 0
#endif

#ifndef DL_FDPIC
#define DL_FDPIC 0
#endif

#ifndef DL_NOMMU_SUPPORT
#define DL_NOMMU_SUPPORT 0
#endif

#if !DL_FDPIC
#define IS_RELATIVE(x,s) ( \
	(R_TYPE(x) == REL_RELATIVE) || \
	(R_TYPE(x) == REL_SYM_OR_REL && !R_SYM(x)) )
#else
#define IS_RELATIVE(x,s) ( ( \
	(R_TYPE(x) == REL_FUNCDESC_VAL) || \
	(R_TYPE(x) == REL_SYMBOLIC) ) \
	&& (((s)[R_SYM(x)].st_info & 0xf) == STT_SECTION) )
#endif

#ifndef NEED_MIPS_GOT_RELOCS
#define NEED_MIPS_GOT_RELOCS 0
#endif

#ifndef DT_DEBUG_INDIRECT
#define DT_DEBUG_INDIRECT 0
#endif

#define AUX_CNT 32
#define DYN_CNT 32

typedef void (*stage2_func)(unsigned char *, size_t *);

#endif
