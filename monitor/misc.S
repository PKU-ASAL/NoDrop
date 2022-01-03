#include "sysdep.h"

ENTRY (_start)
    /* clear the frame pointer */
    xorq %rbp, %rbp

    /* %rdi is argc, the first argument */
    popq %rdi

    /* %rsi is argv */
    movq %rsp, %rsi

    /* make the stack 16-byte aligned */
    andq $~0x0f, %rsp
    
	/* Push garbage because we push 8 more bytes.  */
    pushq %rax

    /* Provide the highest stack address to the user code (for stacks
	   which grow downwards).  */
    pushq %rsp

    call __m_start_main

    hlt /* Crash if somehow we do not return to the original address.	 */
END (_start)
    

ENTRY (__restore_registers)
    /* restore normal registers */
    RESTORE_REG(rdi, R15, r15)
    RESTORE_REG(rdi, R14, r14)
    RESTORE_REG(rdi, R13, r13)
    RESTORE_REG(rdi, R12, r12)
    RESTORE_REG(rdi, Rbp, rbp)
    RESTORE_REG(rdi, Rbx, rbx)
    RESTORE_REG(rdi, R11, r11)
    RESTORE_REG(rdi, R10, r10)
    RESTORE_REG(rdi, R9, r9)
    RESTORE_REG(rdi, R8, r8)
    RESTORE_REG(rdi, Rax, rax)
    RESTORE_REG(rdi, Rcx, rcx)
    RESTORE_REG(rdi, Rdx, rdx)

    /* restore %rsp */
    RESTORE_REG(rdi, Rsp, rsp)

    /* restore eflags */
    RESTORE_REG(rdi, Flg, rsi)
    pushq %rsi
    popfq

    /* push return address to orignal stack top */
    RESTORE_REG(rdi, Rip, rsi)
    pushq %rsi

    /* restore %rsi and %rdi */
    RESTORE_REG(rdi, Rsi, rsi)
    RESTORE_REG(rdi, Rdi, rdi)

    /* return address is put on the stack top */
    retq
END (__restore_registers)