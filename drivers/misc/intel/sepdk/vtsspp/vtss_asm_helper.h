#     Copyright (C) 2002-2014 Intel Corporation.  All Rights Reserved.
# 
#     This file is part of SEP Development Kit
# 
#     SEP Development Kit is free software; you can redistribute it
#     and/or modify it under the terms of the GNU General Public License
#     version 2 as published by the Free Software Foundation.
# 
#     SEP Development Kit is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
# 
#     You should have received a copy of the GNU General Public License
#     along with SEP Development Kit; if not, write to the Free Software
#     Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
# 
#     As a special exception, you may use this file as part of a free software
#     library without restriction.  Specifically, if other files instantiate
#     templates or use macros or inline functions from this file, or you compile
#     this file and link it with other files to produce an executable, this
#     file does not by itself cause the resulting executable to be covered by
#     the GNU General Public License.  This exception does not however
#     invalidate any other reasons why the executable file might be covered by
#     the GNU General Public License.


#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
    #include <asm/dwarf2.h>
    #include <asm/calling.h>
#else
#ifdef CONFIG_AS_CFI
    #define CFI_STARTPROC .cfi_startproc
    #define CFI_ENDPROC .cfi_endproc
    #define CFI_ADJUST_CFA_OFFSET .cfi_adjust_cfa_offset
#else
    .macro cfi_ignore a=0, b=0, c=0, d=0
    .endm
    #define CFI_STARTPROC           cfi_ignore
    #define CFI_ENDPROC             cfi_ignore
    #define CFI_ADJUST_CFA_OFFSET   cfi_ignore
#endif
    #ifdef CONFIG_X86_64
    .macro ALLOC_PT_GPREGS_ON_STACK addskip=0
    subq    $15*8+\addskip, %rsp
    CFI_ADJUST_CFA_OFFSET 15*8+\addskip
    .endm

    .macro SAVE_C_REGS_HELPER offset=0 rax=1 rcx=1 r8910=1 r11=1
    .if \r11
    movq %r11, 6*8+\offset(%rsp)
    .endif
    .if \r8910
    movq %r10, 7*8+\offset(%rsp)
    movq %r9,  8*8+\offset(%rsp)
    movq %r8,  9*8+\offset(%rsp)
    .endif
    .if \rax
    movq %rax, 10*8+\offset(%rsp)
    .endif
    .if \rcx
    movq %rcx, 11*8+\offset(%rsp)
    .endif
    movq %rdx, 12*8+\offset(%rsp)
    movq %rsi, 13*8+\offset(%rsp)
    movq %rdi, 14*8+\offset(%rsp)
    .endm
    .macro SAVE_C_REGS offset=0
    SAVE_C_REGS_HELPER \offset, 1, 1, 1, 1
    .endm
    .macro SAVE_EXTRA_REGS offset=0
    movq %r15, 0*8+\offset(%rsp)
    movq %r14, 1*8+\offset(%rsp)
    movq %r13, 2*8+\offset(%rsp)
    movq %r12, 3*8+\offset(%rsp)
    movq %rbp, 4*8+\offset(%rsp)
    movq %rbx, 5*8+\offset(%rsp)
    .endm

    .macro SAVE_EXTRA_REGS_RBP offset=0
    movq %rbp, 4*8+\offset(%rsp)
    .endm

    .macro RESTORE_EXTRA_REGS offset=0
    movq 0*8+\offset(%rsp), %r15
    movq 1*8+\offset(%rsp), %r14
    movq 2*8+\offset(%rsp), %r13
    movq 3*8+\offset(%rsp), %r12
    movq 4*8+\offset(%rsp), %rbp
    movq 5*8+\offset(%rsp), %rbx
    .endm
    .macro RESTORE_C_REGS_HELPER rstor_rax=1, rstor_rcx=1, rstor_r11=1, rstor_r8910=1, rstor_rdx=1
    .if \rstor_r11
    movq 6*8(%rsp), %r11
    .endif
    .if \rstor_r8910
    movq 7*8(%rsp), %r10
    movq 8*8(%rsp), %r9
    movq 9*8(%rsp), %r8
    .endif
    .if \rstor_rax
    movq 10*8(%rsp), %rax
    .endif
    .if \rstor_rcx
    movq 11*8(%rsp), %rcx
    .endif
    .if \rstor_rdx
    movq 12*8(%rsp), %rdx
    .endif
    movq 13*8(%rsp), %rsi
    movq 14*8(%rsp), %rdi
    .endm
    .macro RESTORE_C_REGS
    RESTORE_C_REGS_HELPER 1,1,1,1,1
    .endm

    .macro REMOVE_PT_GPREGS_FROM_STACK addskip=0
    addq $15*8+\addskip, %rsp
    CFI_ADJUST_CFA_OFFSET -(15*8+\addskip)
    .endm
#else //CONFIG_X86_64

    .macro SAVE_ALL
    pushl %eax
    pushl %ebp
    pushl %edi
    pushl %esi
    pushl %edx
    pushl %ecx
    pushl %ebx
    .endm

    .macro RESTORE_ALL
    popl %ebx
    popl %ecx
    popl %edx
    popl %esi
    popl %edi
    popl %ebp
    popl %eax
    .endm
#endif //CONFIG_X86_64

#endif
