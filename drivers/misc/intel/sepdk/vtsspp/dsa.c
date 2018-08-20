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
#include "dsa.h"
#include "globals.h"

#include <linux/percpu.h>
#include <linux/slab.h>
#ifdef VTSS_CONFIG_KPTI
#include <asm/cpu_entry_area.h>
#endif

#define DS_AREA_MSR 0x0600

static DEFINE_PER_CPU_SHARED_ALIGNED(unsigned long long, vtss_dsa_cpu_msr);
static DEFINE_PER_CPU_SHARED_ALIGNED(vtss_dsa_t*, vtss_dsa_per_cpu);

vtss_dsa_t* vtss_dsa_get(int cpu)
{
    return per_cpu(vtss_dsa_per_cpu, cpu);
}

void vtss_dsa_init_cpu(void)
{
    if (hardcfg.family == 0x06 || hardcfg.family == 0x0f) {

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
        vtss_dsa_t *dsa = __get_cpu_var(vtss_dsa_per_cpu);
#else
        vtss_dsa_t *dsa = *this_cpu_ptr(&vtss_dsa_per_cpu);
#endif
        if (IS_DSA_64ON32) {
            dsa->v32.reserved[0] = dsa->v32.reserved[1] = NULL;
            dsa->v32.reserved[2] = dsa->v32.reserved[3] = NULL;
        } else {
            dsa->v64.reserved[0] = dsa->v64.reserved[1] = NULL;
        }
        wrmsrl(DS_AREA_MSR, (size_t)dsa);
    }
}

#ifdef VTSS_CONFIG_KPTI

static int vtss_dsa_alloc_buffer(int cpu)
{
    per_cpu(vtss_dsa_per_cpu, cpu) = (vtss_dsa_t*)&get_cpu_entry_area(cpu)->cpu_debug_store;
    return 0;
}

static void vtss_dsa_release_buffer(int cpu)
{
    per_cpu(vtss_dsa_per_cpu, cpu) = NULL;
}

#elif defined(VTSS_CONFIG_KAISER)

static int vtss_dsa_alloc_buffer(int cpu)
{
    void *buffer;

    per_cpu(vtss_dsa_per_cpu, cpu) = NULL;
    buffer = vtss_kaiser_alloc_pages(sizeof(vtss_dsa_t), GFP_KERNEL, cpu);
    if (unlikely(!buffer)) {
        ERROR("Cannot allocate DSA buffer");
        return VTSS_ERR_NOMEMORY;
    }
    per_cpu(vtss_dsa_per_cpu, cpu) = buffer;
    TRACE("allocated buffer for %d cpu, buffer=%p", cpu, buffer);
    return 0;
}

static void vtss_dsa_release_buffer(int cpu)
{
    void *buffer;

    buffer = per_cpu(vtss_dsa_per_cpu, cpu);
    vtss_kaiser_free_pages(buffer, sizeof(vtss_dsa_t));
    TRACE("released buffer for %d cpu, buffer=%p", cpu, buffer);
}

#else

static int vtss_dsa_alloc_buffer(int cpu)
{
    per_cpu(vtss_dsa_per_cpu, cpu) = NULL;
    if ((per_cpu(vtss_dsa_per_cpu, cpu) = (vtss_dsa_t*)kmalloc_node(
            sizeof(vtss_dsa_t), (GFP_KERNEL | __GFP_ZERO), cpu_to_node(cpu))) == NULL)
    {
        ERROR("Cannot allocate DSA buffer");
        return VTSS_ERR_NOMEMORY;
    }
    return 0;
}

static void vtss_dsa_release_buffer(int cpu)
{
    if (per_cpu(vtss_dsa_per_cpu, cpu) != NULL)
        kfree(per_cpu(vtss_dsa_per_cpu, cpu));
}

#endif

static void vtss_dsa_on_each_cpu_init(void* ctx)
{
    if (hardcfg.family == 0x06 || hardcfg.family == 0x0f) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
        rdmsrl(DS_AREA_MSR, __get_cpu_var(vtss_dsa_cpu_msr));
#else
        rdmsrl(DS_AREA_MSR, *this_cpu_ptr(&vtss_dsa_cpu_msr));
#endif
    }
}

static void vtss_dsa_on_each_cpu_fini(void* ctx)
{
    if (hardcfg.family == 0x06 || hardcfg.family == 0x0f) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
        wrmsrl(DS_AREA_MSR, __get_cpu_var(vtss_dsa_cpu_msr));
#else
        wrmsrl(DS_AREA_MSR, *this_cpu_ptr(&vtss_dsa_cpu_msr));
#endif
    }
}

int vtss_dsa_init(void)
{
    int cpu;

    on_each_cpu(vtss_dsa_on_each_cpu_init, NULL, SMP_CALL_FUNCTION_ARGS);
    for_each_possible_cpu(cpu) {
        if (vtss_dsa_alloc_buffer(cpu)) goto fail;
    }
    return 0;
fail:
    for_each_possible_cpu(cpu) {
        vtss_dsa_release_buffer(cpu);
    }
    return VTSS_ERR_NOMEMORY;
}

void vtss_dsa_fini(void)
{
    int cpu;

    on_each_cpu(vtss_dsa_on_each_cpu_fini, NULL, SMP_CALL_FUNCTION_ARGS);
    for_each_possible_cpu(cpu) {
        vtss_dsa_release_buffer(cpu);
    }
}

#ifdef VTSS_CONFIG_KPTI
#include <asm/tlbflush.h>
#include <linux/kallsyms.h>

static void (*vtss_cea_set_pte)(void *cea_vaddr, phys_addr_t pa, pgprot_t flags) = NULL;
static void (*vtss_do_kernel_range_flush)(void *info) = NULL;

int vtss_cea_init(void)
{
    if (vtss_cea_set_pte == NULL) {
        vtss_cea_set_pte = (void*)vtss_kallsyms_lookup_name("cea_set_pte");
        if (vtss_cea_set_pte == NULL) {
            ERROR("Cannot find 'cea_set_pte' symbol");
            return VTSS_ERR_INTERNAL;
        }
    }
    if (vtss_do_kernel_range_flush == NULL) {
        vtss_do_kernel_range_flush = (void*)vtss_kallsyms_lookup_name("do_kernel_range_flush");
        if (vtss_do_kernel_range_flush == NULL) {
            ERROR("Cannot find 'do_kernel_range_flush' symbol");
            return VTSS_ERR_INTERNAL;
        }
    }
    INFO("KPTI: enabled");
    return 0;
}

void vtss_cea_update(void *cea, void *addr, size_t size, pgprot_t prot)
{
    unsigned long start = (unsigned long)cea;
    struct flush_tlb_info info;
    phys_addr_t pa;
    size_t msz = 0;

    pa = virt_to_phys(addr);

    preempt_disable();
    for (; msz < size; msz += PAGE_SIZE, pa += PAGE_SIZE, cea += PAGE_SIZE)
        vtss_cea_set_pte(cea, pa, prot);

    info.start = start;
    info.end = start + size;
    vtss_do_kernel_range_flush(&info);
    preempt_enable();
}

void vtss_cea_clear(void *cea, size_t size)
{
    unsigned long start = (unsigned long)cea;
    struct flush_tlb_info info;
    size_t msz = 0;

    preempt_disable();
    for (; msz < size; msz += PAGE_SIZE, cea += PAGE_SIZE)
        vtss_cea_set_pte(cea, 0, PAGE_NONE);

    info.start = start;
    info.end = start + size;
    vtss_do_kernel_range_flush(&info);
    preempt_enable();
}

void *vtss_cea_alloc_pages(size_t size, gfp_t flags, int cpu)
{
    unsigned int order = get_order(size);
    int node = cpu_to_node(cpu);
    struct page *page;

    page = alloc_pages_node(node, flags | __GFP_ZERO, order);
    return page ? page_address(page) : NULL;
}

void vtss_cea_free_pages(const void *buffer, size_t size)
{
    if (buffer)
        free_pages((unsigned long)buffer, get_order(size));
}
#endif

#ifdef VTSS_CONFIG_KAISER
#include <linux/kaiser.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>

static int (*vtss_kaiser_add_mapping)(unsigned long addr, unsigned long size, pteval_t flags) = NULL;
static void (*vtss_kaiser_remove_mapping)(unsigned long start, unsigned long size) = NULL;
static int *vtss_kaiser_enabled_ptr = NULL;

int vtss_kaiser_init(void)
{
    vtss_kaiser_enabled_ptr = (int*)vtss_kallsyms_lookup_name("kaiser_enabled");

    if (vtss_kaiser_enabled_ptr && *vtss_kaiser_enabled_ptr) {
        if (vtss_kaiser_add_mapping == NULL) {
            vtss_kaiser_add_mapping = (void*)vtss_kallsyms_lookup_name("kaiser_add_mapping");
            if (vtss_kaiser_add_mapping == NULL) {
                ERROR("Cannot find 'kaiser_add_mapping' symbol");
                return VTSS_ERR_INTERNAL;
            }
        }
        if (vtss_kaiser_remove_mapping == NULL) {
            vtss_kaiser_remove_mapping = (void*)vtss_kallsyms_lookup_name("kaiser_remove_mapping");
            if (vtss_kaiser_remove_mapping == NULL) {
                ERROR("Cannot find 'kaiser_remove_mapping' symbol");
                return VTSS_ERR_INTERNAL;
            }
        }
        INFO("KAISER: enabled");
    }
    else {
        INFO("KAISER: disabled");
    }
    return 0;
}

void *vtss_kaiser_alloc_pages(size_t size, gfp_t flags, int cpu)
{
    unsigned int order = get_order(size);
    int node = cpu_to_node(cpu);
    struct page *page;
    unsigned long addr;

    page = alloc_pages_node(node, flags | __GFP_ZERO, order);
    if (!page)
        return NULL;
    addr = (unsigned long)page_address(page);
    if (vtss_kaiser_enabled_ptr && *vtss_kaiser_enabled_ptr) {
        if (vtss_kaiser_add_mapping(addr, size, __PAGE_KERNEL | _PAGE_GLOBAL) < 0) {
            __free_pages(page, order);
            addr = 0;
        }
    }
    return (void *)addr;
}

void vtss_kaiser_free_pages(const void *buffer, size_t size)
{
    if (!buffer)
        return;
    if (vtss_kaiser_enabled_ptr && *vtss_kaiser_enabled_ptr) {
        vtss_kaiser_remove_mapping((unsigned long)buffer, size);
    }
    free_pages((unsigned long)buffer, get_order(size));
}

#endif
