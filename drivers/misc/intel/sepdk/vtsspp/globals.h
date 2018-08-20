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
#ifndef _VTSS_GLOBALS_H_
#define _VTSS_GLOBALS_H_

#include "vtss_autoconf.h"
#include "vtss_config.h"

/**
 * The size of global structures
 */
//#define VTSS_PROCESSORS_SUPPORTED   0x100
//#define VTSS_PROCESSES_SUPPORTED    0x40000
//#define VTSS_THREADS_SUPPORTED      0x40000

#define VTSS_DYNSIZE_SCRATCH    0x10000
#define VTSS_DYNSIZE_STACKS     0x1000
//#define VTSS_DYNSIZE_UECBUF     0x100000
//#define VTSS_DYNSIZE_BRANCH     0x3000

#define VTSS_MAX_NAME_LEN 130

#include "vtsserr.h"
#include "vtsscfg.h"
#include "vtsstypes.h"
#include "vtsstrace.h"
#include "vtssevids.h"
#include "cpuevents.h"

#include <linux/types.h>        /* for size_t    */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/workqueue.h>
#endif
#include <asm/desc.h>           /* for gate_desc */

#pragma pack(push, 1)

#define VTSS_DEBUGCTL_MSR             0x1d9
#define IPT_BUF_NO       16

typedef struct
{
    int version;

    short type;
    short major;
    short minor;
    short extra;
    short spack;

    short len;
    union
    {
        char host_name[1];
        char brand_name[1];
        char sysid_string[1];
        char system_root_dir[1];
        char placeholder[VTSS_CFG_SPACE_SIZE];
    };
    int record_size;

} vtss_syscfg_t;

typedef struct
{
    int version;

    short int cpu_chain_len;
    cpuevent_cfg_v1_t cpu_chain[1];

    short int exectx_chain_len;
    exectx_cfg_t exectx_chain[1];

    short int chip_chain_len;
    chipevent_cfg_t chip_chain[1];

    short int os_chain_len;
    osevent_cfg_t os_chain[1];

} vtss_softcfg_t;

#define VTSS_CPU_NHM     0x1e
#define VTSS_CPU_NHM_G   0x1f
#define VTSS_CPU_NHM_EP  0x1a
#define VTSS_CPU_NHM_EX  0x2e

#define VTSS_CPU_WMR     0x25
#define VTSS_CPU_WMR_EP  0x2c
#define VTSS_CPU_WMR_EX  0x2f

#define VTSS_CPU_SNB     0x2a
#define VTSS_CPU_SNB_X   0x2d
#define VTSS_CPU_IVB     0x3a
#define VTSS_CPU_IVB_X   0x3e

#define VTSS_CPU_HSW     0x3c
#define VTSS_CPU_HSW_X   0x3f
#define VTSS_CPU_HSW_ULT 0x45
#define VTSS_CPU_HSW_GT3 0x46

#define VTSS_CPU_BDW     0x3d
#define VTSS_CPU_BDW_GT3 0x47
#define VTSS_CPU_BDW_X   0x4f
#define VTSS_CPU_BDW_XD  0x56

#define VTSS_CPU_SKL    0x5e
#define VTSS_CPU_SKL_M  0x4e
#define VTSS_CPU_SKL_X  0x55

#define VTSS_CPU_KBL    0x9e
#define VTSS_CPU_KBL_M  0x8e

#define VTSS_CPU_CNL    0x42
#define VTSS_CPU_CNL_M  0x66

#define VTSS_CPU_KNL    0x57
#define VTSS_CPU_KNM    0x85

#define VTSS_CPU_ATOM_GLM   0x5C
#define VTSS_CPU_ATOM_DNV   0x5F
#define VTSS_CPU_ATOM_GLP   0x7a

typedef struct
{
    int version;

    long long cpu_freq;                     /// Hz
    long long timer_freq;                   /// realtsc, Hz
    long long maxusr_address;
    unsigned char os_sp;
    unsigned char os_minor;
    unsigned char os_major;
    unsigned char os_type;

    unsigned char mode;                     /// 32- or 64-bit
    unsigned char family;
    unsigned char model;
    unsigned char stepping;

    int cpu_no;

    struct
    {
        unsigned char node;
        unsigned char pack;
        unsigned char core;
        unsigned char thread;

    } cpu_map[NR_CPUS];   /// stored truncated to cpu_no elements

} vtss_hardcfg_t;

typedef struct
{
    int version;
    
    unsigned int fratio;    /// MSR_PLATFORM_INFO[15:8]; max non-turbo ratio
    unsigned int ctcnom;    /// RATIO_P = CPUID[21].EBX / CPUID[21].EAX; ratio of ART/CTC to TSC
    unsigned int tscdenom;
    unsigned int mtcfreq;   /// IA32_RTIT_CTL.MTCFreq
} vtss_iptcfg_t;
/**
 * per-task control structures and declarations
 */
typedef struct task_control_block
{
    /// syscall metrics
    long long syscall_count;
    long long syscall_duration;

} vtss_tcb_t;

/**
 * per-processor control structures and declarations
 */
typedef struct processor_control_block
{
    /// current task data
    vtss_tcb_t *tcb_ptr;

    /// idle metrics
    long long idle_duration;
    long long idle_c1_residency;
    long long idle_c3_residency;
    long long idle_c6_residency;
    long long idle_c7_residency;

    /// save area
    int   apic_id;              /// local APIC ID (processor ID)
    void *apic_linear_addr;     /// linear address of local APIC
    void *apic_physical_addr;   /// physical address of local APIC
    gate_desc *idt_base;        /// IDT base address
    gate_desc saved_perfvector; /// saved PMI vector contents
    long long saved_msr_ovf;    /// saved value of MSR_PERF_GLOBAL_OVF_CTRL
    long long saved_msr_perf;   /// saved value of MSR_PERF_GLOBAL_CTRL
    long long saved_msr_debug;  /// saved value of DEBUGCTL_MSR

    /// operating state
    void *bts_ptr;              /// Branch Trace Store pointer
    void *scratch_ptr;          /// Scratch-pad memory pointer

    /// IPT memory
    void* topa_virt;                /// virtual address of IPT ToPA
    void* iptbuf_virt;              /// virtual address of IPT output buffer
    unsigned long long topa_phys;   /// physical address of IPT ToPA
    unsigned long long iptbuf_phys[IPT_BUF_NO]; /// physical address of IPT output buffer
#ifdef VTSS_USE_NMI
    unsigned long saved_apic_lvtpc;
#endif
} vtss_pcb_t;
struct vtss_work
{
    struct work_struct work; /* !!! SHOULD BE THE FIRST !!! */
    char data[0];            /*     placeholder for data    */
};
#pragma pack(pop)

#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
typedef void (vtss_work_func_t) (struct work_struct *work);
#else
typedef void (vtss_work_func_t) (void *work);
#endif



#ifdef DECLARE_PER_CPU_SHARED_ALIGNED
DECLARE_PER_CPU_SHARED_ALIGNED(vtss_pcb_t, vtss_pcb);
#else
DECLARE_PER_CPU(vtss_pcb_t, vtss_pcb);
#endif
#define pcb(cpu) per_cpu(vtss_pcb, cpu)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
#define pcb_cpu __get_cpu_var(vtss_pcb)
#else
#define pcb_cpu  (*this_cpu_ptr(&(vtss_pcb)))
#endif

extern vtss_syscfg_t  syscfg;
extern vtss_hardcfg_t hardcfg;
extern vtss_iptcfg_t iptcfg;
extern fmtcfg_t       fmtcfg[2];
extern process_cfg_t  reqcfg;
extern unsigned long vtss_syscall_rsp_ptr;

//#define VTSS_PT_FLUSH_MODE (reqcfg.ipt_cfg.mode == vtss_iptmode_full && reqcfg.ipt_cfg.size)
//TODO: rename it to VTSS_FLUSH_MODE everywhere
#define VTSS_PT_FLUSH_MODE (reqcfg.ipt_cfg.size)

void vtss_globals_fini(void);
int  vtss_globals_init(void);

int vtss_queue_work(int cpu, vtss_work_func_t* func, void* data, size_t size);

unsigned long vtss_kallsyms_lookup_name(char *name);

#endif /* _VTSS_GLOBALS_H_ */
