/*
  Copyright (C) 2010-2015 Intel Corporation.  All Rights Reserved.

  This file is part of SEP Development Kit

  SEP Development Kit is free software; you can redistribute it
  and/or modify it under the terms of the GNU General Public License
  version 2 as published by the Free Software Foundation.

  SEP Development Kit is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with SEP Development Kit; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

  As a special exception, you may use this file as part of a free software
  library without restriction.  Specifically, if other files instantiate
  templates or use macros or inline functions from this file, or you compile
  this file and link it with other files to produce an executable, this
  file does not by itself cause the resulting executable to be covered by
  the GNU General Public License.  This exception does not however
  invalidate any other reasons why the executable file might be covered by
  the GNU General Public License.
*/
#include "vtss_config.h"
#include "stack.h"
#include "regs.h"
#include "globals.h"
#include "record.h"
#include "user_vm.h"
#include "time.h"
#include "lbr.h"

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>      /* for kmap()/kunmap() */
#include <linux/pagemap.h>      /* for page_cache_release() */
#include <asm/page.h>
#include <asm/processor.h>
#include <linux/nmi.h>
#include <linux/module.h>
#include "unwind.c"

#define VTSS_STK_LOG(fmt, ...) do {\
    int nb = snprintf(stk->dbgmsg, sizeof(stk->dbgmsg)-1, "%s: " fmt, __FUNCTION__, ##__VA_ARGS__);\
    if (nb > 0 && nb < sizeof(stk->dbgmsg)-1) {\
        stk->dbgmsg[nb] = '\0';\
        vtss_record_debug_info(trnd, stk->dbgmsg, 0);\
    }\
} while(0)

static int vtss_stack_store_ip(unsigned long addr, unsigned long *prev_addr, char *callchain, int *callchain_pos, int callchain_size)
{
    unsigned long addr_diff;
    int sign;
    char prefix = 0;
    int j;

    addr_diff = addr - (*prev_addr);
    sign = (addr_diff & (((size_t)1) << ((sizeof(size_t) << 3) - 1))) ? 0xff : 0;
    for (j = sizeof(void*) - 1; j >= 0; j--)
    {
        if(((addr_diff >> (j << 3)) & 0xff) != sign)
        {
           break;
        }
    }
    prefix |= sign ? 0x40 : 0;
    prefix |= j + 1;

    if (callchain_size <= (*callchain_pos)+1+j+1) {
        return -1;
    }

    callchain[*callchain_pos] = prefix;
    (*callchain_pos)++;

    *(unsigned long*)&(callchain[*callchain_pos]) = addr_diff;
    (*callchain_pos) += j + 1;
    *prev_addr = addr;
    return 0;
}

#ifdef VTSS_AUTOCONF_STACKTRACE_OPS

#include <asm/stacktrace.h>

#ifdef VTSS_AUTOCONF_STACKTRACE_OPS_WARNING
static void vtss_warning(void *data, char *msg)
{
}

static void vtss_warning_symbol(void *data, char *msg, unsigned long symbol)
{
}
#endif

typedef struct kernel_stack_control_t
{
    unsigned long bp;
    unsigned char* kernel_callchain;
    int* kernel_callchain_size;
    int* kernel_callchain_pos;
    unsigned long prev_addr;
    int done;
} kernel_stack_control_t;

static int vtss_stack_stack(void *data, char *name)
{
    kernel_stack_control_t* stk = (kernel_stack_control_t*)data;
    if (!stk) return -1;
    if (stk->done){
        ERROR("Error happens during stack processing");
        return -1;
    }
    return 0;
}

static void vtss_stack_address(void *data, unsigned long addr, int reliable)
{
    kernel_stack_control_t* stk = (kernel_stack_control_t*)data;
    TRACE("%s%pB %d", reliable ? "" : "? ", (void*)addr, *stk->kernel_callchain_pos);
    touch_nmi_watchdog();
    if (!reliable){
        return;
    }
    if (!stk || !stk->kernel_callchain_size || !stk->kernel_callchain_pos){
        return;
    }
    if ((*stk->kernel_callchain_size) <= (*stk->kernel_callchain_pos)) {
        return;
    }
#ifndef CONFIG_FRAME_POINTER
    if (addr < VTSS_KOFFSET) return;
#endif
    if (stk->done) return;
    
    if(vtss_stack_store_ip(addr, &stk->prev_addr, stk->kernel_callchain,
        stk->kernel_callchain_pos, *stk->kernel_callchain_size) == -1) {
        stk->done = 1;
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
static int vtss_stack_address_int(void *data, unsigned long addr, int reliable)
{
    vtss_stack_address(data, addr, reliable);
    return 0;
}
#endif

#if defined(VTSS_AUTOCONF_STACKTRACE_OPS_WALK_STACK)
static unsigned long vtss_stack_walk(
#if defined(VTSS_AUTOCONF_WALK_STACK_TASK_ARG)
    struct task_struct *t,
#else
    struct thread_info *t,
#endif
    unsigned long *stack,
    unsigned long bp,
    const struct stacktrace_ops *ops,
    void *data,
    unsigned long *end,
    int *graph)
{
    kernel_stack_control_t* stk = (kernel_stack_control_t*)data;
    if (!stk){
        ERROR("Internal error!");
        return bp;
    }
    if (!stack){
        ERROR("Broken stack pointer!");
        stk->done=1;
        return bp;
    }
    if (stack <= (unsigned long*)VTSS_MAX_USER_SPACE){
        TRACE("Stack pointer belongs user space. We will not process it. stack_ptr=%p", stack);
        if (stk->kernel_callchain_pos && *stk->kernel_callchain_pos == 0){
            TRACE("Most probably stack pointer intitialization is wrong. No one stack address is resolved.");
        }
        stk->done=1;
        return bp;
    }
/*    if ((bp <= vtss_max_user_space) && (bp != 0)){
        TRACE("Frame pointer belongs user space. We will not process it. bp=%lx", bp);
        stk->done=1;
        return bp;
    }
*/
    if (stk->bp==0){
        TRACE("bp=0x%p, stack=0x%p, end=0x%p", (void*)stk->bp, stack, end);
        stk->bp = bp;
    }
    if (stk->done){
        return bp;
    }
    bp = print_context_stack(t, stack, stk->bp, ops, data, end, graph);
    if (stk != NULL && bp < VTSS_KSTART) {
        TRACE("user bp=0x%p", (void*)bp);
        stk->bp = bp;
    }
#if (!defined(CONFIG_X86_64)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0))
    {
        struct thread_info* context = (struct thread_info *)((unsigned long)stack & (~(THREAD_SIZE - 1)));
        unsigned long* next_stack = NULL;
        if (context && (unsigned long)context > VTSS_MAX_USER_SPACE) next_stack = (unsigned long *)context->previous_esp;
        if ((!next_stack) || (!((void*)next_stack >(void*)context && (void*)next_stack < (void*)context + THREAD_SIZE - sizeof(unsigned long)))) stk->done=1;
    }
#endif
    return bp;
}
#endif

static const struct stacktrace_ops vtss_stack_ops = {
#ifdef VTSS_AUTOCONF_STACKTRACE_OPS_WARNING
    .warning        = vtss_warning,
    .warning_symbol = vtss_warning_symbol,
#endif
    .stack          = vtss_stack_stack,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
    .address        = vtss_stack_address,
#else
    .address        = vtss_stack_address_int,
#endif
#if defined(VTSS_AUTOCONF_STACKTRACE_OPS_WALK_STACK)
    .walk_stack     = vtss_stack_walk,
#endif
};

static void *vtss_stack_unwind_kernel(struct vtss_transport_data* trnd, stack_control_t* stk, struct task_struct* task, struct pt_regs* regs_in, void *reg_fp)
{
    kernel_stack_control_t k_stk;

    k_stk.bp = (unsigned long)reg_fp;
    k_stk.kernel_callchain = stk->kernel_callchain;
    k_stk.prev_addr = 0;
    k_stk.kernel_callchain_size = &stk->kernel_callchain_size;
    k_stk.kernel_callchain_pos =  &stk->kernel_callchain_pos;
    *k_stk.kernel_callchain_pos = 0;
    k_stk.done = 0;
#ifdef VTSS_AUTOCONF_DUMP_TRACE_HAVE_BP
    dump_trace(task, regs_in , NULL, 0, &vtss_stack_ops, &k_stk);
#else
    dump_trace(task, regs_in, NULL, &vtss_stack_ops, &k_stk);
#endif
    if(k_stk.bp) reg_fp = (void *)k_stk.bp;
    return reg_fp;
}

#else /* VTSS_AUTOCONF_STACKTRACE_OPS */

#include <asm/unwind.h>

static void *vtss_stack_unwind_kernel(struct vtss_transport_data* trnd, stack_control_t* stk, struct task_struct* task, struct pt_regs* regs_in, void *reg_fp)
{
    struct unwind_state state;
    unsigned long addr, prev_addr = 0;

    stk->kernel_callchain_pos = 0;
    for (unwind_start(&state, task, regs_in, NULL); !unwind_done(&state);
            unwind_next_frame(&state)) {
        addr = unwind_get_return_address(&state);
        if (!addr) {
            break;
        }
        if (vtss_stack_store_ip(addr, &prev_addr, stk->kernel_callchain, 
                    &stk->kernel_callchain_pos, stk->kernel_callchain_size) == -1) {
            break;
        }
    }
    return reg_fp;
}
#endif

static int vtss_check_user_fp(struct task_struct* task, stack_control_t* stk, char* fp)
{
    struct vm_area_struct* vma;
    //allow fp from segments differ than stack
    //if(fp < stk->user_sp.chp) return -1;
    //if(fp > stk->bp.chp) return -1;
    if((unsigned long)fp & (stk->wow64 ? 3 : sizeof(void*) - 1)) return -1;
    vma = find_vma(task->mm, (unsigned long)fp);
    if(vma == NULL) return -1;
    if((unsigned long)fp < vma->vm_start) return -1;
    if((unsigned long)fp > vma->vm_end) return -1;
    return 0;
}

static int vtss_check_user_ip(struct task_struct* task, stack_control_t* stk, char* ip)
{
    struct vm_area_struct* vma;
    vma = find_vma(task->mm, (unsigned long)ip);
    if(vma == NULL) return -1;
    if(!(vma->vm_flags & VM_EXEC) && !(vma->vm_flags & VM_MAYEXEC)) return -1;
    if((unsigned long)ip < vma->vm_start) return -1;
    if((unsigned long)ip > vma->vm_end) return -1;
    return 0;
}

static int vtss_read_user_frame(stack_control_t* stk, char *curr_sp, char **fp, char** ip)
{
    char vals[2*sizeof(void*)]; /* fp + ip */
    int stride = stk->wow64 ? 4 : sizeof(void*);

    if (stk->acc->read(stk->acc, curr_sp, vals, 2*stride) != 2*stride) {
        return -1;
    }
    *fp = (char*)(size_t)(stk->wow64 ? *(u32*)(&vals[0]) : *(u64*)(&vals[0]));
    *ip = (char*)(size_t)(stk->wow64 ? *(u32*)(&vals[stride]) : *(u64*)(&vals[stride]));
    return 0;
}

static int vtss_stack_unwind_user(struct vtss_transport_data* trnd, stack_control_t* stk, struct task_struct* task)
{
    char* fp = stk->user_fp.chp;
    char* ip = stk->user_ip.chp;
    char* curr_fp = fp;
    char *prev_ip = 0;
    void **buffer;
    
    stk->user_callchain_pos = 0;
    if(stk->user_callchain == NULL) {
        return 0;
    }
    buffer = (void**)stk->user_callchain;

    TRACE("fp=%p, sp=%p, stack_base=%p, ip=%p", fp, sp, stk->bp.chp, ip);

    if(vtss_check_user_fp(task, stk, fp) == -1) {
        return VTSS_ERR_NOTFOUND; // no frames
#if 0
        /* try to find the first frame inside stack */
        char* stack_base = stk->bp.chp;
        char* sp = stk->user_sp.chp;
        char *curr_sp = sp;
        int stride = stk->wow64 ? 4 : sizeof(void*);

        curr_fp = NULL;
        for(curr_sp = sp; curr_sp < stack_base; curr_sp += stride) {
        
            if(read_frame(stk, curr_sp, &fp, &ip) == -1) {
                return 0;
            }
            //find frames from stack only
            //if(fp < sp) continue;
            //if(fp > stack_base) continue;
            if(vtss_check_user_fp(task, stk, fp) == -1) continue;
            if((sp <= ip) && (ip <= stack_base)) continue;
            if(vtss_check_user_ip(task, stk, ip) == -1) continue;

            // save found frame
            curr_fp = fp;
            vtss_stack_store_ip((unsigned long)ip, (unsigned long*)&prev_ip, 
                stk->user_callchain, &stk->user_callchain_pos, stk->user_callchain_size);
            break;
        }
        if(curr_fp == NULL) return 0;
        TRACE("found the frame in stack: fp=%p, ip=%p", fp, ip);
#endif
    }

    while(curr_fp) {

        if(vtss_read_user_frame(stk, curr_fp, &fp, &ip) == -1) {
            break;
        }
        if(vtss_check_user_fp(task, stk, fp) == -1) break;
        if(vtss_check_user_ip(task, stk, ip) == -1) break;

        curr_fp = fp;
        if(vtss_stack_store_ip((unsigned long)ip, (unsigned long*)&prev_ip, 
            stk->user_callchain, &stk->user_callchain_pos, stk->user_callchain_size) == -1) {
            return 0;
        }
    }
    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
#ifndef this_cpu_ptr
#define this_cpu_ptr(ptr) SHIFT_PERCPU_PTR(ptr, my_cpu_offset)
#endif
#endif

#if 0 && defined(VTSS_CONFIG_KPTI)
#include <asm/cpu_entry_area.h>
static unsigned long vtss_get_cea_user_sp(void)
{
    int cpu;
    char *entry_stack;

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable_no_resched();
    entry_stack = (char*)cpu_entry_stack(cpu);
    if (entry_stack) {
        return *(unsigned long*)(entry_stack + sizeof(struct entry_stack) - 8);
    }
    return 0;
}
#endif

#if defined(CONFIG_X86_64) && !defined(VTSS_USE_NMI)
static int vtss_in_syscall(void)
{
    if (current->audit_context) {
        if (((int*)current->audit_context)[1]) { /* audit_context->in_syscall */
            return 1;
        }
    }
    return 0;
}
#endif

static unsigned long vtss_get_user_sp(struct task_struct* task, struct pt_regs* regs)
{
#if defined(CONFIG_X86_64) && !defined(VTSS_USE_NMI)
    if (vtss_in_syscall() && !test_tsk_thread_flag(task, TIF_IA32))
    {
        if (vtss_syscall_rsp_ptr)
        {
            /* inside syscall */
            unsigned long old_rsp = *this_cpu_ptr((unsigned long*)vtss_syscall_rsp_ptr);
            if (old_rsp) return old_rsp;
        }
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
        /* fast system call or could not get old_rsp */
        if (task->thread.usersp) return task->thread.usersp;
#endif
    }
#endif
    return REG(sp, regs);
}

int vtss_stack_dump(struct vtss_transport_data* trnd, stack_control_t* stk, struct task_struct* task, struct pt_regs* regs_in, void* reg_fp, void* user_sp, int in_irq)
{
    int rc = 0;
    void* stack_base = stk->bp.vdp;
    void *reg_ip, *reg_sp;
    int kernel_stack = 0;
    struct pt_regs* regs = regs_in;
    int user_mode_regs = 0;

#ifdef VTSS_USE_NMI
    // skip kernel threads
    if (current->mm == NULL) {
        return -EFAULT;
    }
#endif
    if ((!regs && reg_fp > (void*)VTSS_MAX_USER_SPACE) || (regs && (!vtss_user_mode(regs))) || (!reg_fp)) {
        kernel_stack = 1;
    }
#ifndef CONFIG_FRAME_POINTER
    if (!regs) {
        kernel_stack = 0;
        TRACE("kernel stack 0 when no frame pointers");
    }
#endif
    if (regs && vtss_user_mode(regs)) {
        user_mode_regs = 1;
    }

    /* Unwind kernel stack */
    if (kernel_stack && stk->kernel_callchain) {
        if ((unsigned long)reg_fp < 0x1000 || (unsigned long)reg_fp == (unsigned long)-1) reg_fp = 0; //error instead of bp;
        reg_fp = vtss_stack_unwind_kernel(trnd, stk, task, regs_in, reg_fp);
    } else {
        stk->kernel_callchain_pos = 0;
    }
    if (current != task) {
       // we will get crash during user space access while unwiding
       return rc; 
    }
    if (regs == NULL || !vtss_user_mode(regs)) {
        /* kernel mode regs, so get a user mode regs */
#if !defined(CONFIG_HIGHMEM)
        if (current->mm) {
            regs = task_pt_regs(task); /* get user mode regs */
        }
        else {
            regs = NULL;
        }
        if (regs == NULL || !vtss_user_mode(regs))
#endif
        {
            // we might be in kernel thread
            VTSS_STK_LOG("Cannot get user mode registers");
            return rc;
        }
    }

    /* Get IP and SP registers from user space */
    reg_ip = (void*)REG(ip, regs);
    reg_sp = user_mode_regs ? (void*)REG(sp, regs) : (void*)vtss_get_user_sp(task, regs);
    if (reg_fp > (void*)VTSS_MAX_USER_SPACE || reg_fp < (void*)0x1000)
        reg_fp = (void*)REG(bp, regs);

    { /* Check for correct stack range in task->mm */
        struct vm_area_struct* vma;

#ifdef VTSS_CHECK_IP_IN_MAP
        /* Check IP in module map */
        vma = find_vma(task->mm, (unsigned long)reg_ip);
        if (likely(vma != NULL)) {
            unsigned long vm_start = vma->vm_start;
            unsigned long vm_end   = vma->vm_end;

            if ((unsigned long)reg_ip < vm_start ||
                (!((vma->vm_flags & (VM_EXEC | VM_WRITE)) == VM_EXEC &&
                    vma->vm_file && vma->vm_file->f_path.dentry) &&
                 !(vma->vm_mm && vma->vm_start == (long)vma->vm_mm->context.vdso)))
            {
                VTSS_STK_LOG("ip=%p not in valid vma", reg_ip);
                return -EFAULT;
            }
        } 
        else {
            VTSS_STK_LOG("no vma on ip=%p", reg_ip);
            return -EFAULT;
        }
#endif /* VTSS_CHECK_IP_IN_MAP */

        /* Check SP in module map */
        vma = find_vma(task->mm, (unsigned long)reg_sp);
        if (likely(vma != NULL)) {
            unsigned long vm_start = vma->vm_start + ((vma->vm_flags & VM_GROWSDOWN) ? PAGE_SIZE : 0UL);
            unsigned long vm_end   = vma->vm_end;

            if ((unsigned long)reg_sp < vm_start ||
                (vma->vm_flags & (VM_READ | VM_WRITE)) != (VM_READ | VM_WRITE))
            {
                VTSS_STK_LOG("sp=%p not in valid vma", reg_sp);
                return -EFAULT;
            }
            if (!((unsigned long)stack_base >= vm_start &&
                  (unsigned long)stack_base <= vm_end)  ||
                 ((unsigned long)stack_base <= (unsigned long)reg_sp))
            {
                if ((unsigned long)stack_base != 0UL) {
                    TRACE("Fixup stack base to 0x%lx instead of 0x%lx", vm_end, (unsigned long)stack_base);
                }
                stack_base = (void*)vm_end;
                stk->clear(stk);
            }
            stk->hugetlb = (vma->vm_flags & VM_HUGETLB);

            if (!stk->hugetlb) {
                if ((unsigned long)(stack_base - reg_sp) > 0x100000) {
                    // workaround on the problem with huge stack on HSW/BDW/SKL EP machines
                    stk->hugetlb = 1;
                }
            }
            
            if ((unsigned long)stack_base - (unsigned long)reg_sp > reqcfg.stk_sz[vtss_stk_user]){
                unsigned long stack_base_calc = min((unsigned long)stack_base, ((unsigned long)reg_sp + reqcfg.stk_sz[vtss_stk_user])&(~(reqcfg.stk_pg_sz[vtss_stk_user]-1)));
                if (stack_base_calc < (unsigned long)stack_base){
                    TRACE("Limiting stack base to 0x%lx instead of 0x%lx, drop 0x%lx bytes", stack_base_calc, (unsigned long)stack_base, ((unsigned long)stack_base - stack_base_calc));
                    stack_base = (void*)stack_base_calc;
                }
            }
            else if(stk->hugetlb) {
                /* scan no more than 32 pages */
                unsigned long stack_base_calc = ((unsigned long)reg_sp + 32*PAGE_SIZE)&(~(PAGE_SIZE-1));
                if (stack_base_calc < (unsigned long)stack_base) {
                    stack_base = (void*)stack_base_calc;
                }
            }
        } else {
            VTSS_STK_LOG("no vma on sp=%p", reg_sp);
            return -EFAULT;
        }
    }

#if 0
    if (stk->user_ip.vdp == reg_ip &&
        stk->user_sp.vdp == reg_sp &&
        stk->bp.vdp == stack_base &&
        stk->user_fp.vdp == reg_fp)
    {
        VTSS_STK_LOG("The same context");
        return 0; /* Assume that nothing was changed */
    }
#endif

    /* Try to lock vm accessor */
    if (unlikely((stk->acc == NULL) || stk->acc->trylock(stk->acc, task))) {
        VTSS_STK_LOG("Unable to lock vm accessor");
        return -EBUSY;
    }

    stk->user_ip.vdp = reg_ip;
    stk->user_sp.vdp = reg_sp;
    stk->bp.vdp = stack_base;
    stk->user_fp.vdp = reg_fp;

    /* Unwind using FP */
    if (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_CLRSTK) {
        rc = vtss_stack_unwind_user(trnd, stk, task);
        if(stk->user_callchain_pos != 0) {
            stk->acc->unlock(stk->acc);
            return rc;
        }
    }

    VTSS_PROFILE(unw, rc = stk->unwind(stk));
    /* Check unwind result */
    if (unlikely(rc == VTSS_ERR_NOMEMORY)) {
        /* Try again with realloced buffer */
        while (rc == VTSS_ERR_NOMEMORY) {
            int err = stk->realloc(stk); /* realloc_stack */
            if (err == VTSS_ERR_NOMEMORY) {
                /* dump truncated stacks */
                if(stk->hugetlb && stk->buffer) rc = 0;
                break;
            }
            VTSS_PROFILE(unw, rc = stk->unwind(stk)); /* unwind_stack_fwd */
        }
        if (rc == VTSS_ERR_NOMEMORY) {
            VTSS_STK_LOG("Not enough memory for stack buffer");
        }
    }
    stk->acc->unlock(stk->acc);
    if (unlikely(rc)) {
        stk->clear(stk);
        if(rc != VTSS_ERR_NOMEMORY) VTSS_STK_LOG("unwind error: %d", rc);
    }
    TRACE("end, rc = %d", rc);
    return rc;
}

int vtss_stack_record_kernel(struct vtss_transport_data* trnd, stack_control_t* stk, pid_t tid, int cpu, unsigned long long stitch_id, int is_safe)
{
    int rc = -EFAULT;
    int stklen = stk->kernel_callchain_pos;
#ifdef VTSS_USE_UEC
    stk_trace_kernel_record_t stkrec;
    if (stklen == 0)
    {
        // kernel is empty
        VTSS_STK_LOG("Kernel stack is empty");
        return 0;
    }
    TRACE("ip=0x%p, sp=0x%p, fp=0x%p: Trace %d bytes", stk->ip.vdp, stk->sp.vdp, stk->fp.vdp, stklen);
    //implementation is done for UEC NOT USED
    /// save current alt. stack:
    /// [flagword - 4b][residx]
    /// ...[sampled address - 8b][systrace{sts}]
    ///                       [length - 2b][type - 2b]...
    stkrec.flagword = UEC_LEAF1 | UECL1_VRESIDX | UECL1_SYSTRACE;
    stkrec.residx   = tid;
    stkrec.size     = sizeof(stkrec.size) + sizeof(stkrec.type);
    stkrec.type     = (sizeof(void*) == 8) ? UECSYSTRACE_CLEAR_STACK64 : UECSYSTRACE_CLEAR_STACK32;
    stkrec.size += sizeof(unsigned int);
    stkrec.idx   = -1;
    /// correct the size of systrace
    stkrec.size += (unsigned short)stklen;
    if (vtss_transport_record_write(trnd, &stkrec, sizeof(stkrec), stk->kernel_callchain, stklen, is_safe)) {
        TRACE("STACK_record_write() FAIL");
        VTSS_STK_LOG("Unable to write the record");
        rc = -EFAULT;
    }

#else
    void* entry;
    stk_trace_kernel_record_t* stkrec;

    if (stklen == 0)
    {
        // kernel is empty
        VTSS_STK_LOG("Kernel stack is empty");
        return 0;
    }
    TRACE("ip=0x%p, sp=0x%p, fp=0x%p: Trace %d bytes", stk->ip.vdp, stk->sp.vdp, stk->fp.vdp, stklen);
    //implementation is done for UEC NOT USED
    stkrec = (stk_trace_kernel_record_t*)vtss_transport_record_reserve(trnd, &entry, sizeof(stk_trace_kernel_record_t) + stklen);
    if (likely(stkrec)) {
    /// save current alt. stack:
    /// [flagword - 4b][residx]
    /// ...[sampled address - 8b][systrace{sts}]
    ///                       [length - 2b][type - 2b]...
    stkrec->flagword = UEC_LEAF1 | UECL1_VRESIDX | UECL1_SYSTRACE;
    stkrec->residx   = tid;
    stkrec->size     = (unsigned short)stklen + sizeof(stkrec->size) + sizeof(stkrec->type);
    stkrec->type     = (sizeof(void*) == 8) ? UECSYSTRACE_CLEAR_STACK64 : UECSYSTRACE_CLEAR_STACK32;
    stkrec->size += sizeof(unsigned int);
    stkrec->idx   = -1;
    memcpy((char*)stkrec+sizeof(stk_trace_kernel_record_t), stk->kernel_callchain, stklen);
    rc = vtss_transport_record_commit(trnd, entry, is_safe);
    }
#endif
    return rc;
}

int vtss_stack_record_user(struct vtss_transport_data* trnd, stack_control_t* stk, pid_t tid, int cpu, int is_safe)
{
    int rc = 0;
    int stklen = stk->user_callchain_pos;
    
#ifdef VTSS_USE_UEC

    clrstk_trace_record_t stkrec;
 
    if(stklen == 0)
    {
        // user clean stack is empty
        return 0;
    }
    /// save current alt. stack in UEC: [flagword - 4b][residx][cpuidx - 4b][tsc - 8b]
    ///                                 ...[sampled address - 8b][systrace{sts}]
    ///                                                          [length - 2b][type - 2b]...
    stkrec.flagword = UEC_LEAF1 | UECL1_VRESIDX | UECL1_CPUIDX | UECL1_CPUTSC | UECL1_EXECADDR | UECL1_SYSTRACE;
    stkrec.residx = tid;
    stkrec.cpuidx = cpu;
    stkrec.cputsc = vtss_time_cpu();
    stkrec.execaddr = (unsigned long long)stk->user_ip.szt;

    stkrec.size = sizeof(stkrec.size) + sizeof(stkrec.type) + sizeof(stkrec.merge_node) + (unsigned short)stklen;
    stkrec.type = (sizeof(void*) == 8) ? UECSYSTRACE_CLEAR_STACK64 : UECSYSTRACE_CLEAR_STACK32;
    stkrec.merge_node = 0xffffffff;

    if (vtss_transport_record_write(trnd, &stkrec, sizeof(stkrec), stk->user_callchain, stklen, is_safe))
    {
        TRACE("STACK_record_write() FAIL");
        rc = -EFAULT;
    }

#else  // VTSS_USE_UEC 

    void* entry;
    clrstk_trace_record_t* stkrec = (clrstk_trace_record_t*)vtss_transport_record_reserve(trnd, &entry, sizeof(clrstk_trace_record_t) + stklen);

    if(stklen == 0)
    {
        // user clean stack is empty
        return 0;
    }
    if(likely(stkrec))
    {
        /// save current alt. stack in UEC: [flagword - 4b][residx][cpuidx - 4b][tsc - 8b]
        ///                                 ...[sampled address - 8b][systrace{sts}]
        ///                                                          [length - 2b][type - 2b]...
        stkrec->flagword = UEC_LEAF1 | UECL1_VRESIDX | UECL1_CPUIDX | UECL1_CPUTSC | UECL1_EXECADDR | UECL1_SYSTRACE;
        stkrec->residx   = tid;
        stkrec->cpuidx   = cpu;
        stkrec->cputsc   = vtss_time_cpu();
        stkrec->execaddr = (unsigned long long)stk->user_ip.szt;

        stkrec->size = sizeof(stkrec->size) + sizeof(stkrec->type) + sizeof(stkrec->merge_node) + (unsigned short)stklen;
        stkrec->type = (sizeof(void*) == 8) ? UECSYSTRACE_CLEAR_STACK64 : UECSYSTRACE_CLEAR_STACK32;
        stkrec->merge_node = 0xffffffff;
        memcpy((char*)stkrec + sizeof(clrstk_trace_record_t), stk->user_callchain, stklen);
        rc = vtss_transport_record_commit(trnd, entry, is_safe);
    }
    else
    {
        TRACE("STACK_record_write() FAIL");
        rc = -EFAULT;
    }
#endif //  VTSS_USE_UEC
    return rc;
}

int vtss_stack_record(struct vtss_transport_data* trnd, stack_control_t* stk, pid_t tid, int cpu, int is_safe, unsigned long* recid)
{
    int rc = -EFAULT;
    unsigned short sample_type;
    int sktlen = 0;

    /// collect LBR call stacks if so requested
    if (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_LBRCSTK)
    {
        return vtss_stack_record_lbr(trnd, stk, tid, cpu, is_safe);
    }
    /// skip compress dirty stack if clean is present
    if (stk->user_callchain_pos == 0)
    {
        sktlen = stk->compress(stk);
    }

    if (stk->kernel_callchain_pos!=0)
    {
        rc = vtss_stack_record_kernel(trnd, stk, tid, cpu, 0, is_safe);
    }
    else
    {
        TRACE("kernel stack is empty");
    }
    /// record clean stack
    if (stk->user_callchain_pos != 0) {
        return vtss_stack_record_user(trnd, stk, tid, cpu, is_safe);
    }

    if (unlikely(sktlen == 0)) {
        VTSS_STK_LOG("User stack is empty");
        VTSS_STK_LOG("tid=0x%08x, cpu=0x%08x, ip=0x%p, sp=[0x%p,0x%p], fp=0x%p",
                tid, raw_smp_processor_id(), stk->user_ip.vdp, stk->user_sp.vdp, stk->bp.vdp, stk->user_fp.vdp);
        return 0;
    }

    if (stk->is_full(stk)) { /* full stack */
        sample_type = (sizeof(void*) == 8 && !stk->wow64) ? UECSYSTRACE_STACK_CTX64_V0 : UECSYSTRACE_STACK_CTX32_V0;
    } else { /* incremental stack */
        sample_type = (sizeof(void*) == 8 && !stk->wow64) ? UECSYSTRACE_STACK_CTXINC64_V0 : UECSYSTRACE_STACK_CTXINC32_V0;
    }

#ifdef VTSS_USE_UEC
    {
        stk_trace_record_t stkrec;
        /// save current alt. stack:
        /// [flagword - 4b][residx][cpuidx - 4b][tsc - 8b]
        /// ...[sampled address - 8b][systrace{sts}]
        ///                       [length - 2b][type - 2b]...
        stkrec.flagword = UEC_LEAF1 | UECL1_VRESIDX | UECL1_CPUIDX | UECL1_CPUTSC | UECL1_EXECADDR | UECL1_SYSTRACE;
        stkrec.residx   = tid;
        stkrec.cpuidx   = cpu;
        stkrec.cputsc   = vtss_time_cpu();
        stkrec.execaddr = (unsigned long long)stk->user_ip.szt;
        stkrec.type     = sample_type;

        if (!stk->wow64) {
            stkrec.size = 4 + sizeof(void*) + sizeof(void*);
            stkrec.sp   = stk->user_sp.szt;
            stkrec.fp   = stk->user_fp.szt;
        } else { /// a 32-bit stack in a 32-bit process on a 64-bit system
            stkrec.size = 4 + sizeof(unsigned int) + sizeof(unsigned int);
            stkrec.sp32 = (unsigned int)stk->user_sp.szt;
            stkrec.fp32 = (unsigned int)stk->user_fp.szt;
        }
        rc = 0;
        if (sktlen > 0xfffb) {
            lstk_trace_record_t lstkrec;

            TRACE("ip=0x%p, sp=0x%p, fp=0x%p: Large Trace %d bytes", stk->user_ip.vdp, stk->user_sp.vdp, stk->user_fp.vdp, sktlen);
            lstkrec.size = (unsigned int)(stkrec.size + sktlen + 2); /* 2 = sizeof(int) - sizeof(short) */
            lstkrec.flagword = UEC_LEAF1 | UECL1_VRESIDX | UECL1_CPUIDX | UECL1_CPUTSC | UECL1_EXECADDR | UECL1_LARGETRACE;
            lstkrec.residx   = stkrec.residx;
            lstkrec.cpuidx   = stkrec.cpuidx;
            lstkrec.cputsc   = stkrec.cputsc;
            lstkrec.execaddr = stkrec.execaddr;
            lstkrec.type     = stkrec.type;
            lstkrec.sp       = stkrec.sp;
            lstkrec.fp       = stkrec.fp;
            if (vtss_transport_record_write(trnd, &lstkrec, sizeof(lstkrec) - (stk->wow64*8), stk->data(stk), sktlen, is_safe)) {
                VTSS_STK_LOG("Record was not written");
                TRACE("STACK_record_write() FAIL");
                rc = -EFAULT;
            }
        } else {
            /// correct the size of systrace
            stkrec.size += (unsigned short)sktlen;
            if (vtss_transport_record_write(trnd, &stkrec, sizeof(stkrec) - (stk->wow64*8), stk->data(stk), sktlen, is_safe)) {
                TRACE("STACK_record_write() FAIL");
                VTSS_STK_LOG("Record was not written");
                rc = -EFAULT;
            }
        }
    }
#else  /* VTSS_USE_UEC */
    if (unlikely(sktlen > 0xfffb)) {
        VTSS_STK_LOG("Too big stack len (%d bytes)", sktlen);
        return -EFAULT;
    } else {
        void* entry;
        stk_trace_record_t* stkrec = (stk_trace_record_t*)vtss_transport_record_reserve(trnd, &entry, sizeof(stk_trace_record_t) - (stk->wow64*8) + sktlen);
        if (likely(stkrec)) {
            /// save current alt. stack:
            /// [flagword - 4b][residx][cpuidx - 4b][tsc - 8b]
            /// ...[sampled address - 8b][systrace{sts}]
            ///                       [length - 2b][type - 2b]...
            stkrec->flagword = UEC_LEAF1 | UECL1_VRESIDX | UECL1_CPUIDX | UECL1_CPUTSC | UECL1_EXECADDR | UECL1_SYSTRACE;
            stkrec->residx   = tid;
            stkrec->cpuidx   = cpu;
            stkrec->cputsc   = vtss_time_cpu();
            stkrec->execaddr = (unsigned long long)stk->user_ip.szt;
            stkrec->size     = (unsigned short)sktlen + sizeof(stkrec->size) + sizeof(stkrec->type);
            stkrec->type     = sample_type;
            if (!stk->wow64) {
                stkrec->size += sizeof(void*) + sizeof(void*);
                stkrec->sp   = stk->user_sp.szt;
                stkrec->fp   = stk->user_fp.szt;
            } else { /* a 32-bit stack in a 32-bit process on a 64-bit system */
                stkrec->size += sizeof(unsigned int) + sizeof(unsigned int);
                stkrec->sp32 = (unsigned int)stk->user_sp.szt;
                stkrec->fp32 = (unsigned int)stk->user_fp.szt;
            }
            memcpy((char*)stkrec+sizeof(stk_trace_record_t)-(stk->wow64*8), stk->compressed, sktlen);
            rc = vtss_transport_record_commit(trnd, entry, is_safe);
            if (rc != 0){
               VTSS_STK_LOG("Cannot write the record");
            }
        }
    }
#endif /* VTSS_USE_UEC */
    return rc;
}

