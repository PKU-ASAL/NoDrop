#ifndef _SYSDEP_H_
#define _SYSDEP_H_

/* Syntactic details of assembler.  */

/* ELF uses byte-counts for .align, most others use log2 of count of bytes.  */
#define ALIGNARG(log2) 1<<log2
#define ASM_SIZE_DIRECTIVE(name) .size name,.-name;

/* Define an entry point visible from C.  */
#define ENTRY(name) \
    .global name; \
    .type name,@function; \
    .align ALIGNARG(4);\
name:

#define END(name) \
    ASM_SIZE_DIRECTIVE(name)


/* Define register offset in struct pt_regs */
#define oR15 0x00
#define oR14 0x08
#define oR13 0x10
#define oR12 0x18
#define oRbp 0x20
#define oRbx 0x28
#define oR11 0x30
#define oR10 0x38
#define oR9  0x40
#define oR8  0x48
#define oRax 0x50
#define oRcx 0x58
#define oRdx 0x60
#define oRsi 0x68
#define oRdi 0x70
#define oRip 0x80
#define oCs  0x88
#define oFlg 0x90
#define oRsp 0x98
#define oSs  0xa0

#define RESTORE_REG(e, Reg, reg) \
    movq o##Reg##(%##e), %##reg

#endif // _SYSDEP_H_