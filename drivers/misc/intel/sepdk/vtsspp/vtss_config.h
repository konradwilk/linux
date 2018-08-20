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
#ifndef _VTSS_CONFIG_H_
#define _VTSS_CONFIG_H_

#include "vtss_autoconf.h"

#include <linux/kernel.h>
#include <linux/version.h>      /* for KERNEL_VERSION() */
#include <linux/compiler.h>     /* for inline */
#include <linux/types.h>        /* for size_t, pid_t */
#include <linux/stddef.h>       /* for NULL   */
#include <linux/smp.h>          /* for smp_processor_id() */
#include <linux/cpumask.h>
#include <linux/percpu.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/timex.h>
#endif
#include <asm/cpufeature.h>

#if defined(X86_FEATURE_KAISER) || defined(CONFIG_KAISER) || defined(VTSS_AUTOCONF_KAISER)
#define VTSS_CONFIG_KAISER 1
#elif defined(X86_FEATURE_PTI)
#define VTSS_CONFIG_KPTI 1
#endif

#if defined(VTSS_CONFIG_KPTI) || defined(VTSS_CONFIG_KAISER)
#define VTSS_USE_NMI 1
#define VTSS_USE_UEC 1
#endif

#ifdef CONFIG_X86_64
#define VTSS_KOFFSET ((unsigned long)__START_KERNEL_map)
#define VTSS_MAX_USER_SPACE 0x7fffffffffff
#else
#define VTSS_KOFFSET ((unsigned long)PAGE_OFFSET)
#define VTSS_MAX_USER_SPACE 0x7fffffff
#endif

#define VTSS_KSTART (VTSS_KOFFSET + ((CONFIG_PHYSICAL_START + (CONFIG_PHYSICAL_ALIGN - 1)) & ~(CONFIG_PHYSICAL_ALIGN - 1)))
#define VTSS_KSIZE  ((unsigned long)KERNEL_IMAGE_SIZE - ((CONFIG_PHYSICAL_START + (CONFIG_PHYSICAL_ALIGN - 1)) & ~(CONFIG_PHYSICAL_ALIGN - 1)) - 1)

#define VTSS_TO_STR_AUX(x) #x
#define VTSS_TO_STR(x)     VTSS_TO_STR_AUX(x)

#ifdef VTSS_AUTOCONF_SMP_CALL_FUNCTION_RETRY
#define SMP_CALL_FUNCTION_ARGS 0,1
#else /* VTSS_AUTOCONF_SMP_CALL_FUNCTION_RETRY */
#define SMP_CALL_FUNCTION_ARGS 1
#endif /* VTSS_AUTOCONF_SMP_CALL_FUNCTION_RETRY */

#ifdef VTSS_AUTOCONF_TRACE_SCHED_RQ
#define VTSS_TP_RQ struct rq* rq,
#else  /* VTSS_AUTOCONF_TRACE_SCHED_RQ */
#define VTSS_TP_RQ
#endif /* VTSS_AUTOCONF_TRACE_SCHED_RQ */

#if defined(VTSS_AUTOCONF_TRACE_SCHED_RQ) || defined(VTSS_AUTOCONF_TRACE_SCHED_NO_RQ) || defined(VTSS_AUTOCONF_TRACE_SCHED_PREEMPT)

#define VTSS_TRACE_EVENTS_SCHED 1

#endif

/* Macro for printk */
#ifdef VTSS_DEBUG_TRACE
extern int vtss_check_trace(const char* func_name, int* flag);
#define TRACE(FMT, ...) do {   \
    static int trace_flag = 0; \
    if (unlikely(!trace_flag))  trace_flag = vtss_check_trace(__FUNCTION__, &trace_flag); \
    if (unlikely(trace_flag>0)) printk(KERN_DEBUG "%s[cpu%d]: "FMT"\n", __FUNCTION__, raw_smp_processor_id(), ##__VA_ARGS__); \
  } while(0)
#else  /* VTSS_DEBUG_TRACE */
#define TRACE(FMT, ...) /* empty */
#endif /* VTSS_DEBUG_TRACE */
#define ERROR(FMT, ...) do { printk(KERN_ERR  "%s[cpu%d]: "FMT"\n", __FUNCTION__, raw_smp_processor_id(), ##__VA_ARGS__); } while(0)
#define INFO(FMT, ...)  do { printk(KERN_INFO "%s[cpu%d]: "FMT"\n", __FUNCTION__, raw_smp_processor_id(), ##__VA_ARGS__); } while(0)

extern int vtss_time_source; /* 0 - raw clock monotinic (default), 1 - TSC */
extern cycles_t vtss_time_limit;

#ifdef VTSS_DEBUG_PROFILE
extern cycles_t vtss_profile_cnt_stk;
extern cycles_t vtss_profile_clk_stk;
extern cycles_t vtss_profile_cnt_ctx;
extern cycles_t vtss_profile_clk_ctx;
extern cycles_t vtss_profile_cnt_pmi;
extern cycles_t vtss_profile_clk_pmi;
extern cycles_t vtss_profile_cnt_pmu;
extern cycles_t vtss_profile_clk_pmu;
extern cycles_t vtss_profile_cnt_sys;
extern cycles_t vtss_profile_clk_sys;
extern cycles_t vtss_profile_cnt_bts;
extern cycles_t vtss_profile_clk_bts;
extern cycles_t vtss_profile_cnt_vma;
extern cycles_t vtss_profile_clk_vma;
extern cycles_t vtss_profile_cnt_pgp;
extern cycles_t vtss_profile_clk_pgp;
extern cycles_t vtss_profile_cnt_cpy;
extern cycles_t vtss_profile_clk_cpy;
extern cycles_t vtss_profile_cnt_vld;
extern cycles_t vtss_profile_clk_vld;
extern cycles_t vtss_profile_cnt_unw;
extern cycles_t vtss_profile_clk_unw;

#define VTSS_PROFILE(name, expr) do {   \
    cycles_t start_time = get_cycles(); \
    (expr);                             \
    vtss_profile_cnt_##name++;          \
    vtss_profile_clk_##name += get_cycles() - start_time; \
  } while (0)

#define VTSS_PROFILE_PRINT(func, ...) do { \
    func(__VA_ARGS__ "#ctx=%15lld n=%9lld\n", \
        vtss_profile_clk_ctx, vtss_profile_cnt_ctx); \
    func(__VA_ARGS__ "#pmi=%15lld n=%9lld\n", \
        vtss_profile_clk_pmi, vtss_profile_cnt_pmi/2); \
    func(__VA_ARGS__ "*pmu=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile_clk_pmu, vtss_profile_cnt_pmu, \
        (vtss_profile_clk_pmu*10000/(vtss_profile_clk_ctx+vtss_profile_clk_pmi+1))/100, \
        (vtss_profile_clk_pmu*10000/(vtss_profile_clk_ctx+vtss_profile_clk_pmi+1))%100); \
    func(__VA_ARGS__ "*sys=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile_clk_sys, vtss_profile_cnt_sys, \
        (vtss_profile_clk_sys*10000/(vtss_profile_clk_ctx+vtss_profile_clk_pmi+1))/100, \
        (vtss_profile_clk_sys*10000/(vtss_profile_clk_ctx+vtss_profile_clk_pmi+1))%100); \
    func(__VA_ARGS__ "*bts=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile_clk_bts, vtss_profile_cnt_bts, \
        (vtss_profile_clk_bts*10000/(vtss_profile_clk_ctx+vtss_profile_clk_pmi+1))/100, \
        (vtss_profile_clk_bts*10000/(vtss_profile_clk_ctx+vtss_profile_clk_pmi+1))%100); \
    func(__VA_ARGS__ "*stk=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile_clk_stk, vtss_profile_cnt_stk, \
        (vtss_profile_clk_stk*10000/(vtss_profile_clk_ctx+vtss_profile_clk_pmi+1))/100, \
        (vtss_profile_clk_stk*10000/(vtss_profile_clk_ctx+vtss_profile_clk_pmi+1))%100); \
    func(__VA_ARGS__ ".unw=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile_clk_unw, vtss_profile_cnt_unw, \
        (vtss_profile_clk_unw*10000/(vtss_profile_clk_stk+1))/100, \
        (vtss_profile_clk_unw*10000/(vtss_profile_clk_stk+1))%100); \
    func(__VA_ARGS__ "..vl=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile_clk_vld, vtss_profile_cnt_vld, \
        (vtss_profile_clk_vld*10000/(vtss_profile_clk_unw+1))/100, \
        (vtss_profile_clk_vld*10000/(vtss_profile_clk_unw+1))%100); \
    func(__VA_ARGS__ "..vm=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile_clk_vma, vtss_profile_cnt_vma, \
        (vtss_profile_clk_vma*10000/(vtss_profile_clk_unw+1))/100, \
        (vtss_profile_clk_vma*10000/(vtss_profile_clk_unw+1))%100); \
    func(__VA_ARGS__ "...c=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile_clk_cpy, vtss_profile_cnt_cpy, \
        (vtss_profile_clk_cpy*10000/(vtss_profile_clk_vma+1))/100, \
        (vtss_profile_clk_cpy*10000/(vtss_profile_clk_vma+1))%100); \
    func(__VA_ARGS__ "...p=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile_clk_pgp, vtss_profile_cnt_pgp, \
        (vtss_profile_clk_pgp*10000/(vtss_profile_clk_vma+1))/100, \
        (vtss_profile_clk_pgp*10000/(vtss_profile_clk_vma+1))%100); \
  } while(0)

#else  /* VTSS_DEBUG_PROFILE */
#define VTSS_PROFILE(name, expr) (expr)
#define VTSS_PROFILE_PRINT(func, ...)
#endif /* VTSS_DEBUG_PROFILE */

#if defined(CONFIG_PREEMPT_NOTIFIERS) && (!defined(CONFIG_TRACEPOINTS))
#define VTSS_USE_PREEMPT_NOTIFIERS 1 /* Use backup scheme */
#endif
#define VTSS_GET_TASK_STRUCT 1 /* Prevent task struct early destruction */

#ifdef VTSS_AUTOCONF_USER_COPY_WITHOUT_CHECK
#define vtss_copy_from_user _copy_from_user
#else
#define vtss_copy_from_user copy_from_user
#endif

#ifndef preempt_enable_no_resched
#define preempt_enable_no_resched() preempt_enable()
#endif

#if defined(CONFIG_PREEMPT_RT) || defined(CONFIG_PREEMPT_RT_FULL)
#define VTSS_CONFIG_REALTIME
#ifndef VTSS_CONFIG_INTERNAL_MEMORY_POOL
#define VTSS_CONFIG_INTERNAL_MEMORY_POOL 1
#endif
#endif

#ifdef VTSS_CONFIG_REALTIME
#define vtss_spin_lock_init(lock)                raw_spin_lock_init(lock)
#define vtss_spin_trylock(lock)                  raw_spin_trylock(lock)
#define vtss_spin_lock(lock)                     raw_spin_lock(lock)
#define vtss_spin_unlock(lock)                   raw_spin_unlock(lock)
#define vtss_spin_lock_irqsave(lock, flags)      raw_spin_lock_irqsave(lock, flags)
#define vtss_spin_trylock_irqsave(lock, flags)   raw_spin_trylock_irqsave(lock, flags)
#define vtss_spin_unlock_irqrestore(lock, flags) raw_spin_unlock_irqrestore(lock, flags)
#else
#define vtss_spin_lock_init(lock)                spin_lock_init(lock)
#define vtss_spin_trylock(lock)                  spin_trylock(lock)
#define vtss_spin_lock(lock)                     spin_lock(lock)
#define vtss_spin_unlock(lock)                   spin_unlock(lock)
#define vtss_spin_lock_irqsave(lock, flags)      spin_lock_irqsave(lock, flags)
#define vtss_spin_trylock_irqsave(lock, flags)   spin_trylock_irqsave(lock, flags)
#define vtss_spin_unlock_irqrestore(lock, flags) spin_unlock_irqrestore(lock, flags)
#endif

#ifdef VTSS_CONFIG_INTERNAL_MEMORY_POOL
#define vtss_get_free_pages(gfp_mask, order) vtss_get_free_pages_internal(gfp_mask, order)
#define vtss_free_pages(addr, order)         vtss_free_pages_internal(addr, order)
#define vtss_get_free_page(gfp_mask)         vtss_get_free_page_internal(gfp_mask)
#define vtss_free_page(addr)                 vtss_free_page_internal(addr)
#define vtss_kmalloc(size, gfp_mask)         vtss_kmalloc_internal(size, gfp_mask)
#define vtss_kfree(item)                     vtss_kfree_internal(item)
#else
#define vtss_get_free_pages(gfp_mask, order) __get_free_pages((gfp_mask) | ((gfp_mask) == GFP_NOWAIT ? __GFP_NORETRY : 0) | __GFP_NOWARN, order)
#define vtss_free_pages(addr, order)         free_pages(addr, order)
#define vtss_get_free_page(gfp_mask)         __get_free_page((gfp_mask) | ((gfp_mask) == GFP_NOWAIT ? __GFP_NORETRY : 0) | __GFP_NOWARN)
#define vtss_free_page(addr)                 free_page(addr)
#define vtss_kmalloc(size, gfp_mask)         kmalloc(size, gfp_mask)
#define vtss_kfree(item)                     kfree(item)
#endif

#define vtss_spin_lock_irqsave_timeout(lock, flags, times)\
({\
    int rc = 0;\
    int cnt = 0;\
    while(!(rc = vtss_spin_trylock_irqsave(lock, flags)))\
    {\
        if(++cnt >= (times)) {\
            TRACE("Cannot acquire lock");\
            break;\
        }\
    }\
    rc;\
})\

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
#define vtss_user_mode(regs) user_mode(regs)
#else
#define vtss_user_mode(regs) user_mode_vm(regs)
#endif

#endif /* _VTSS_CONFIG_H_ */
