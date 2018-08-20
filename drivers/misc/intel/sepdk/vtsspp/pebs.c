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
#include "pebs.h"
#include "dsa.h"
#include "globals.h"

#include <linux/percpu.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#define PEBS_ENABLE_MSR         0x03f1
#define PERF_CAPABILITIES_MSR   0x0345
#define PEBS_TRAP_MASK          0x40
#define PEBS_COUNT              2

size_t vtss_pebs_record_size = 0;
static unsigned long long vtss_pebs_enable_mask = 0ULL;
static DEFINE_PER_CPU_SHARED_ALIGNED(vtss_pebs_t*, vtss_pebs_per_cpu);

vtss_pebs_t* vtss_pebs_get(int cpu)
{
    vtss_dsa_t* dsa = vtss_dsa_get(cpu);

    if (IS_DSA_64ON32) {
        if (dsa->v32.pebs_index != dsa->v32.pebs_base) {
            TRACE("base=0x%p, index=0x%p", dsa->v32.pebs_base, dsa->v32.pebs_index);
            return (vtss_pebs_t*)dsa->v32.pebs_base;
        }
    } else {
        if (dsa->v64.pebs_index != dsa->v64.pebs_base) {
            TRACE("base=0x%p, index=0x%p", dsa->v64.pebs_base, dsa->v64.pebs_index);
            return (vtss_pebs_t*)dsa->v64.pebs_base;
        }
    }
    return NULL;
}

int vtss_pebs_is_trap(void)
{
    unsigned long long msr_val = 0ULL;

    if (hardcfg.family == 0x06 && hardcfg.model >= 0x0f) {
        rdmsrl(PERF_CAPABILITIES_MSR, msr_val);
    }
    return (msr_val & PEBS_TRAP_MASK);
}

#ifdef VTSS_CONFIG_KPTI
#include <asm/cpu_entry_area.h>

#define PEBS_BUFFER_SIZE (PAGE_SIZE << 4)

static DEFINE_PER_CPU(void*, vtss_pebs_vaddr);

static int vtss_pebs_alloc_buffer(int cpu)
{
    void *cea;
    void *buffer;

    per_cpu(vtss_pebs_vaddr, cpu) = NULL;
    per_cpu(vtss_pebs_per_cpu, cpu) = NULL;
    cea = &get_cpu_entry_area(cpu)->cpu_debug_buffers.pebs_buffer;
    buffer = vtss_cea_alloc_pages(PEBS_BUFFER_SIZE, GFP_KERNEL, cpu);
    if (unlikely(!buffer)) {
        ERROR("Cannot allocate PEBS buffer");
        return VTSS_ERR_NOMEMORY;
    }
    per_cpu(vtss_pebs_vaddr, cpu) = buffer;
    vtss_cea_update(cea, buffer, PEBS_BUFFER_SIZE, PAGE_KERNEL);
    per_cpu(vtss_pebs_per_cpu, cpu) = (vtss_pebs_t*)cea;
    TRACE("allocated buffer for %d cpu cea=%p, vaddr=%p", cpu, cea, buffer);
    return 0;
}

static void vtss_pebs_release_buffer(int cpu)
{
    void *cea;
    void *buffer;

    cea = per_cpu(vtss_pebs_per_cpu, cpu);
    vtss_cea_clear(cea, PEBS_BUFFER_SIZE);
    buffer = per_cpu(vtss_pebs_vaddr, cpu);
    vtss_cea_free_pages(buffer, PEBS_BUFFER_SIZE);
    TRACE("released buffer for %d cpu cea=%p, vaddr=%p", cpu, cea, buffer);
}

#elif defined(VTSS_CONFIG_KAISER)

static int vtss_pebs_alloc_buffer(int cpu)
{
    void *buffer;

    per_cpu(vtss_pebs_per_cpu, cpu) = NULL;
    buffer = vtss_kaiser_alloc_pages(PEBS_COUNT*sizeof(vtss_pebs_t), GFP_KERNEL, cpu);
    if (unlikely(!buffer)) {
        ERROR("Cannot allocate PEBS buffer");
        return VTSS_ERR_NOMEMORY;
    }
    per_cpu(vtss_pebs_per_cpu, cpu) = buffer;
    TRACE("allocated buffer for %d cpu, buffer=%p", cpu, buffer);
    return 0;
}

static void vtss_pebs_release_buffer(int cpu)
{
    void *buffer;

    buffer = per_cpu(vtss_pebs_per_cpu, cpu);
    vtss_kaiser_free_pages(buffer, PEBS_COUNT*sizeof(vtss_pebs_t));
    TRACE("released buffer for %d cpu, buffer=%p", cpu, buffer);
}

#else

static int vtss_pebs_alloc_buffer(int cpu)
{
    per_cpu(vtss_pebs_per_cpu, cpu) = NULL;
    if ((per_cpu(vtss_pebs_per_cpu, cpu) = (vtss_pebs_t*)kmalloc_node(
            PEBS_COUNT*sizeof(vtss_pebs_t), (GFP_KERNEL | __GFP_ZERO), cpu_to_node(cpu))) == NULL)
    {
        ERROR("Cannot allocate PEBS buffer");
        return VTSS_ERR_NOMEMORY;
    }
    return 0;
}

static void vtss_pebs_release_buffer(int cpu)
{
    if (per_cpu(vtss_pebs_per_cpu, cpu) != NULL)
        kfree(per_cpu(vtss_pebs_per_cpu, cpu));
}
#endif

/* initialize PEBS in DSA for the processor */
void vtss_pebs_init_dsa(void)
{
    int cpu;
    vtss_dsa_t* dsa;
    vtss_pebs_t* pebs;

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable_no_resched();
    dsa = vtss_dsa_get(cpu);
    pebs = per_cpu(vtss_pebs_per_cpu, cpu);

    if (IS_DSA_64ON32) {
        dsa->v32.pebs_base   = (void*)pebs;
        dsa->v32.pebs_pad0   = NULL;
        dsa->v32.pebs_index  = (void*)pebs;
        dsa->v32.pebs_pad1   = NULL;
        dsa->v32.pebs_absmax = (void*)((size_t)pebs + PEBS_COUNT*vtss_pebs_record_size);
        dsa->v32.pebs_pad2   = NULL;
        if (vtss_pebs_enable_mask == PEBS_ENABLE_MASK_NHM) {
            dsa->v32.pebs_threshold = (void*)((size_t)pebs + vtss_pebs_record_size);
        } else {
            dsa->v32.pebs_threshold = (void*)pebs;
        }
        dsa->v32.pebs_pad3 = NULL;
        dsa->v32.pebs_reset[0] = dsa->v32.pebs_reset[1] = NULL;
        dsa->v32.pebs_reset[2] = dsa->v32.pebs_reset[3] = NULL;
    } else {
        dsa->v64.pebs_base   = (void*)pebs;
        dsa->v64.pebs_index  = (void*)pebs;
        dsa->v64.pebs_absmax = (void*)((size_t)pebs + PEBS_COUNT*vtss_pebs_record_size);
        if (vtss_pebs_enable_mask == PEBS_ENABLE_MASK_NHM) {
            dsa->v64.pebs_threshold = (void*)((size_t)pebs + vtss_pebs_record_size);
        } else {
            dsa->v64.pebs_threshold = (void*)pebs;
        }
        dsa->v64.pebs_reset[0] = dsa->v64.pebs_reset[1] = NULL;
    }
    /* invalidate the first PEBS record */
    pebs->v1.ip = 0ULL;
}

void vtss_pebs_enable(void)
{
    if (hardcfg.family == 0x06 && hardcfg.model >= 0x0f && vtss_pebs_record_size) {
        wrmsrl(PEBS_ENABLE_MSR, vtss_pebs_enable_mask);
    }
}

void vtss_pebs_disable(void)
{
/**
 * NOTE: Disabled as there're CPUs which reboot if
 * a PEBS-PMI is encountered when PEBS is disabled.
 * PEBS is effectively disabled when disabling BTS and PMU counters.
 */
#if 0
    if (hardcfg.family == 0x06 && hardcfg.model >= 0x0f) {
        wrmsrl(PEBS_ENABLE_MSR, 0ULL);
    }
#endif
}

static void vtss_pebs_on_each_cpu_func(void* ctx)
{
    if (hardcfg.family == 0x06 && hardcfg.model >= 0x0f) {
        wrmsrl(PEBS_ENABLE_MSR, 0ULL);
    }
}

int vtss_pebs_init(void)
{
    int cpu;
    vtss_pebs_t pebs;

    if (hardcfg.family == 0x06 && hardcfg.model >= 0x0f) {
        switch (hardcfg.model) {
            /// SLM(KNL)
            case VTSS_CPU_KNL:
                vtss_pebs_enable_mask = PEBS_ENABLE_MASK_MRM;
                vtss_pebs_record_size = sizeof(pebs.v3);
                break;
            /* HSW/SLK/BDW/KBL */
            case VTSS_CPU_HSW:
            case VTSS_CPU_HSW_X:
            case VTSS_CPU_HSW_ULT:
            case VTSS_CPU_HSW_GT3:
            case VTSS_CPU_BDW:
            case VTSS_CPU_BDW_GT3:
            case VTSS_CPU_BDW_X:
            case VTSS_CPU_BDW_XD:
            case VTSS_CPU_SKL:
            case VTSS_CPU_SKL_M:
            case VTSS_CPU_SKL_X:
            case VTSS_CPU_KBL:
            case VTSS_CPU_KBL_M:
            case VTSS_CPU_CNL:
            case VTSS_CPU_CNL_M:
                vtss_pebs_record_size = sizeof(pebs.v3);
                vtss_pebs_enable_mask = PEBS_ENABLE_MASK_NHM;
                break;
            /* NHM/SNB/IVB */
            case VTSS_CPU_NHM:
            case VTSS_CPU_NHM_G:
            case VTSS_CPU_NHM_EP:
            case VTSS_CPU_NHM_EX:
            case VTSS_CPU_WMR:
            case VTSS_CPU_WMR_EP:
            case VTSS_CPU_WMR_EX:
            case VTSS_CPU_SNB:
            case VTSS_CPU_SNB_X:
            case VTSS_CPU_IVB:
            case VTSS_CPU_IVB_X:
                vtss_pebs_record_size = sizeof(pebs.v2);
                vtss_pebs_enable_mask = PEBS_ENABLE_MASK_NHM;
                break;
                /* Core2/Atom */
            default:
                vtss_pebs_record_size = sizeof(pebs.v1);
                vtss_pebs_enable_mask = PEBS_ENABLE_MASK_MRM;
                break;
        }
    }
    for_each_possible_cpu(cpu) {
        if (vtss_pebs_alloc_buffer(cpu)) goto fail;
    }
    on_each_cpu(vtss_pebs_on_each_cpu_func, NULL, SMP_CALL_FUNCTION_ARGS);

    INFO("PEBSv%d: record size: 0x%02lx, mask: 0x%02llx", vtss_pebs_record_size == sizeof(pebs.v3) ? 3 : 1,
            vtss_pebs_record_size, vtss_pebs_enable_mask);

    return 0;
fail:
    for_each_possible_cpu(cpu) {
        vtss_pebs_release_buffer(cpu);
    }
    return VTSS_ERR_NOMEMORY;
}

void vtss_pebs_fini(void)
{
    int cpu;
    on_each_cpu(vtss_pebs_on_each_cpu_func, NULL, SMP_CALL_FUNCTION_ARGS);
    for_each_possible_cpu(cpu) {
        vtss_pebs_release_buffer(cpu);
    }
    vtss_pebs_record_size = 0;
}
