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
//#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <asm/io.h>
#include "vtss_config.h"
#include "globals.h"
#include "time.h"
#include "ipt.h"
#include "iptdec.h"
/**
// Intel Processor Trace functionality
*/
#if 0
int vtss_ipt_init(void)
{
    int i;
    int res = 0;
    dma_addr_t dma_addr;
    /// for each CPU:
    ///   allocate ToPA page
    ///   allocate output buffer
    ///   free all buffers in case of error
    for(i = 0; i < hardcfg.cpu_no; i++)
    {
        if((pcb(i).topa_virt = dma_alloc_coherent(NULL, IPT_BUF_SIZE, &dma_addr, GFP_KERNEL)))
        {
            pcb(i).topa_phys = (unsigned long long)dma_addr;
        }
        else
        {
            res = VTSS_ERR_NOMEMORY;
        }
        if((pcb(i).iptbuf_virt = dma_alloc_coherent(NULL, IPT_BUF_SIZE, &dma_addr, GFP_KERNEL)))
        {
            pcb(i).iptbuf_phys = (unsigned long long)dma_addr;
        }
        else
        {
            res = VTSS_ERR_NOMEMORY;
        }
    }
    /// check for errors and free all buffers if any
    return res;
}
#endif
int vtss_ipt_init(void)
{
    int i, j;
    int res = 0;
    /// for each CPU:
    ///   allocate ToPA page
    ///   allocate output buffer
    ///   free all buffers in case of error
    for(i = 0; i < hardcfg.cpu_no; i++)
    {
        if((pcb(i).topa_virt = kmalloc((size_t)IPT_BUF_SIZE, GFP_KERNEL)))
        {
            pcb(i).topa_phys = (unsigned long long)virt_to_phys(pcb(i).topa_virt);
        }
        else
        {
            ERROR("Cannot allocate IPT ToPA buffer");
            res = VTSS_ERR_NOMEMORY;
        }
        if((pcb(i).iptbuf_virt = kmalloc(IPT_BUF_SIZE*IPT_BUF_NO, GFP_KERNEL)))
        {
            for (j = 0; j < IPT_BUF_NO; j++)
            {
                pcb(i).iptbuf_phys[j] = (unsigned long long)virt_to_phys(pcb(i).iptbuf_virt+ j * IPT_BUF_SIZE);
            }
        }
        else
        {
            ERROR("Cannot allocate IPT output buffer");
            res = VTSS_ERR_NOMEMORY;
        }
    }
    if (res == 0) INFO("IPT: enabled");
    /// check for errors and free all buffers if any
    return res;
}

static inline long long read_msr(int idx)
{
    long long val;
    rdmsrl(idx, val);
    return val;
}
static void vtss_init_ipt(void)
{
    long long tmp = read_msr(IPT_CONTROL_MSR);

    wrmsrl(IPT_CONTROL_MSR, tmp & ~1L);

    wrmsrl(IPT_CONTROL_MSR, 0);
    wrmsrl(IPT_STATUS_MSR, 0);
    wrmsrl(IPT_OUT_BASE_MSR, 0);
    wrmsrl(IPT_OUT_MASK_MSR, 0);
}

#if 0
void vtss_ipt_fini(void)
{
    int i;

    for(i = 0; i < hardcfg.cpu_no; i++)
    {
        if(pcb(i).topa_virt)
        {
//            MmFreeNonCachedMemory(pcb(i).topa_virt, IPT_BUF_SIZE);
            dma_free_coherent(NULL, IPT_BUF_SIZE, pcb(i).topa_virt, (dma_addr_t)pcb(i).topa_phys);
            pcb(i).topa_virt = 0;
            pcb(i).topa_phys = 0;
        }
        if(pcb(i).iptbuf_virt)
        {
//            MmFreeNonCachedMemory(pcb[i].iptbuf_virt, IPT_BUF_SIZE);
            dma_free_coherent(NULL, IPT_BUF_SIZE, pcb(i).iptbuf_virt, (dma_addr_t)pcb(i).iptbuf_phys);
            pcb(i).iptbuf_virt = 0;
            pcb(i).iptbuf_phys = 0;
        }
    }
}
#endif

static void vtss_ipt_disable_on_each_cpu(void* ctx)
{
    vtss_disable_ipt();
}

void vtss_ipt_fini(void)
{
    int i;
    on_each_cpu(vtss_ipt_disable_on_each_cpu, NULL, SMP_CALL_FUNCTION_ARGS);
    for(i = 0; i < hardcfg.cpu_no; i++)
    {
        if(pcb(i).topa_virt)
        {
            kfree(pcb(i).topa_virt);
            pcb(i).topa_virt = 0;
            pcb(i).topa_phys = 0;
        }
        if(pcb(i).iptbuf_virt)
        {
            kfree(pcb(i).iptbuf_virt);
            pcb(i).iptbuf_virt = 0;
            memset(pcb(i).iptbuf_phys, 0, sizeof(pcb(i).iptbuf_phys));
        }
    }
}

int vtss_has_ipt_overflowed(void)
{
    return 0;
}

extern int vtss_lbr_no;
extern int vtss_lbr_msr_ctl;
extern int vtss_lbr_msr_from;
extern int vtss_lbr_msr_to;
extern int vtss_lbr_msr_tos;
extern int vtss_lbr_msr_sel;

void vtss_enable_ipt(unsigned int mode, int is_kernel)
{
    int i;
    vtss_pcb_t* pcbp = &pcb_cpu;

    long long tmp = read_msr(IPT_CONTROL_MSR);
    long long msr_val = 0x2500;

    TRACE("enable IPT");
    wrmsrl(IPT_CONTROL_MSR, tmp & ~1L);

    /// disable LBRs and BTS
    wrmsrl(VTSS_DEBUGCTL_MSR, 0);

    if(hardcfg.family == 0x06 && (hardcfg.model == 0x4e /* SKL */ || hardcfg.model == 0x5e /* SKL */ || 
                                  hardcfg.model == 0x55 /* SKX */ || hardcfg.model == 0x5c /* GLM */ || hardcfg.model == 0x5f /* DNV */ || 
                                  hardcfg.model == 0x7a /* GLP */ || hardcfg.model == 0x42 /* CNL */ ||
                                  hardcfg.model == 0x9e /* KBL */ || hardcfg.model == 0x8e /* KBL */))
    {
        /// form ToPA, and initialize status, base and mask pointers and control MSR
        for(i = 0; i < IPT_BUF_NO; i++)
        {
            ((unsigned long long*)pcbp->topa_virt)[i] = pcbp->iptbuf_phys[i];
        }
        if(mode & vtss_iptmode_full)
        {
            ((unsigned long long*)pcbp->topa_virt)[IPT_BUF_NO / 4 * 3] |= 0x04;    /// INT
            ((unsigned long long*)pcbp->topa_virt)[IPT_BUF_NO - 1] |= 0x10;    /// STOP
        }
        else
        {
            ((unsigned long long*)pcbp->topa_virt)[0] |= 0x10;    /// STOP
        }
        
        ((unsigned long long*)pcbp->topa_virt)[i] = pcbp->topa_phys | 0x1;
        if ((mode & vtss_iptmode_time)) msr_val |= 0x2; //PSB+TSC+CYC
    }
    else
    {
        /// form ToPA, and initialize status, base and mask pointers and control MSR
        if (mode & vtss_iptmode_full)
        {
            ((unsigned long long*)pcbp->topa_virt)[0] = pcbp->iptbuf_phys[0] | 0x14;    /// STOP | INT ///Full-PT addition
        }
        else
        {
            ((unsigned long long*)pcbp->topa_virt)[0] = pcbp->iptbuf_phys[0] | 0x10;    /// STOP
        }
        
        ((unsigned long long*)pcbp->topa_virt)[1] = pcbp->topa_phys | 0x1;
    }
    
    wrmsrl(IPT_OUT_MASK_MSR, 0x7f);
    wrmsrl(IPT_OUT_BASE_MSR, pcbp->topa_phys);
    wrmsrl(IPT_STATUS_MSR, 0);
    
    msr_val |= (is_kernel) ? 0x4/*kernel mode*/ : 0x8/*user mode*/;
    if (mode & vtss_iptmode_ring0) msr_val |= 0x4; // + kernel-mode

    wrmsrl(IPT_CONTROL_MSR, msr_val);
    wrmsrl(IPT_CONTROL_MSR, msr_val+1);

}

void vtss_disable_ipt(void)
{
    long long tmp = read_msr(IPT_CONTROL_MSR);

    wrmsrl(IPT_CONTROL_MSR, tmp & ~1L);
    /// clear control MSR
    wrmsrl(IPT_CONTROL_MSR, 0);
}

void vtss_dump_ipt(struct vtss_transport_data* trnd, int tidx, int cpu, int is_safe)
{
    unsigned short size;

    /// form IPT record and save the contents of the output buffer (from base to current mask pointer)

    if((reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) &&
        hardcfg.family == 0x06 && (hardcfg.model == 0x3d /* BDW */ || hardcfg.model == 0x47 /* BDW */ || hardcfg.model == 0x56 /* BDW-DE */ || hardcfg.model == 0x4f /* BDW-DE */ || 
                                   hardcfg.model == 0x4e /* SKL */ || hardcfg.model == 0x5e /* SKL */ || hardcfg.model == 0x55 /* SKX */ || 
                                   hardcfg.model == 0x9e /* KBL */ || hardcfg.model == 0x8e /* KBL */ ||
                                   hardcfg.model == 0x5c /* GLM */ || hardcfg.model == 0x5f /* DNV */ ||
                                   hardcfg.model == 0x7a /* GLP */ || hardcfg.model == 0x42 /* CNL */))
    {
#ifdef VTSS_USE_UEC
        ipt_trace_record_t iptrec;
#else
        ipt_trace_record_t* iptrec;
        void* entry;
#endif
        TRACE("IPT before reset: Control = %llX; Status = %llX; Base = %llX; Mask = %llX",
                read_msr(IPT_CONTROL_MSR), read_msr(IPT_STATUS_MSR), read_msr(IPT_OUT_BASE_MSR), read_msr(IPT_OUT_MASK_MSR));
        //vtss_disable_ipt();
        size = (unsigned short)(((unsigned long long)read_msr(IPT_OUT_MASK_MSR) >> 32) & 0xffff);
        size += (unsigned short)(((unsigned long long)read_msr(IPT_OUT_MASK_MSR) & 0xffffff80L) << 5);


#if 0
        if (reqcfg.ipt_cfg.mode & vtss_iptmode_full)  /// TODO: use vtss_iptmode_mark and configure appropriately via GUI
        {
            unsigned char* src = pcb_cpu.iptbuf_virt;
            unsigned char* dst = src + IPT_BUF_SIZE * IPT_BUF_NO;
            if(decode_pt(src, size, dst, IPT_BUF_SIZE * IPT_BUF_NO, vtss_iptmode_mark) == -1)
            {
                /// stop PT collection
                reqcfg.trace_cfg.trace_flags  &= ~VTSS_CFGTRACE_IPT;
            }
        }
#endif
#ifdef VTSS_USE_UEC
        /// [flagword][residx][cpuidx][tsc][systrace(bts)]
        iptrec.flagword = UEC_LEAF1 | UECL1_VRESIDX | UECL1_CPUIDX | UECL1_CPUTSC | UECL1_SYSTRACE;
        iptrec.residx = (unsigned int)tidx;
        preempt_disable();
        iptrec.cpuidx = (unsigned int)smp_processor_id();
        preempt_enable_no_resched();
        iptrec.cputsc = vtss_time_cpu();
        iptrec.type = UECSYSTRACE_IPT;
        iptrec.size = size + 4;

        if (vtss_transport_record_write(trnd, &iptrec, sizeof(ipt_trace_record_t), pcb_cpu.iptbuf_virt, size, is_safe)) {
            ERROR("vtss_transport_record_write() FAIL");
            vtss_init_ipt();
            return;
        }


#else
        iptrec = (ipt_trace_record_t*)vtss_transport_record_reserve(trnd, &entry, sizeof(ipt_trace_record_t) + size);
        if (unlikely(!iptrec)) {
            TRACE("vtss_transport_record_reserve() FAIL");
            vtss_init_ipt();
            return;
        }
        /// [flagword][residx][cpuidx][tsc][systrace(bts)]
        iptrec->flagword = UEC_LEAF1 | UECL1_VRESIDX | UECL1_CPUIDX | UECL1_CPUTSC | UECL1_SYSTRACE;
        iptrec->residx = (unsigned int)tidx;
        preempt_disable();
        iptrec->cpuidx = (unsigned int)smp_processor_id();
        preempt_enable_no_resched();
        iptrec->cputsc = vtss_time_cpu();
        iptrec->size = (unsigned short)(size + sizeof(iptrec->size) + sizeof(iptrec->type));
        iptrec->type = UECSYSTRACE_IPT;
        memcpy(++iptrec, pcb_cpu.iptbuf_virt, size);
        if (vtss_transport_record_commit(trnd, entry, is_safe)){
            ERROR("vtss_transport_record_write() FAIL");
            vtss_init_ipt();
            return;
        }
#endif
        vtss_init_ipt();
        TRACE("IPT after reset: Control = %llX; Status = %llX; Base = %llX; Mask = %llX",
            read_msr(IPT_CONTROL_MSR), read_msr(IPT_STATUS_MSR), read_msr(IPT_OUT_BASE_MSR), read_msr(IPT_OUT_MASK_MSR));
    }
}

///     ********************************************     ///
/// --- Intel PT decoding part - derived from libipt --- ///
///     ********************************************     ///

/* A psb packet contains a unique 2-byte repeating pattern.
* There are only two ways to fill up a 64bit work with such a pattern.
*/
const unsigned long long psb_unique_pattern[] = {
        ((unsigned long long)pt_psb_lohi | (unsigned long long)pt_psb_lohi << 16 |
        (unsigned long long)pt_psb_lohi << 32 | (unsigned long long)pt_psb_lohi << 48),
        ((unsigned long long)pt_psb_hilo | (unsigned long long)pt_psb_hilo << 16 |
        (unsigned long long)pt_psb_hilo << 32 | (unsigned long long)pt_psb_hilo << 48)
};

/* Synchronizes to the next PSB packet in case of packet decoding error */
int sync_forward_to_psb(const unsigned char *begin, 
                        const unsigned char *end, 
                        const unsigned char *pos, 
                        unsigned char **sync)
{
        unsigned char hi, lo;
        const unsigned char *cur;
        unsigned long long val;
        int psb_pattern_size;
        uintptr_t raw;

        if (pos == *sync)
        {
            pos += ptps_psb;
        }

        if (!((begin <= pos) && (pos < end)))
        {
            return -pte_internal;
        }

        /* We search for a full 64bit word. It's OK to skip the cur one. */
    psb_pattern_size = sizeof(*psb_unique_pattern);
    raw = (uintptr_t)(pos + psb_pattern_size -1);
    raw /= psb_pattern_size;
    raw *= psb_pattern_size;
    pos = (const unsigned char *)raw;

    /* Search for the psb payload pattern in the buffer. */
    for (;;)
    {
        cur = pos;
        pos += sizeof(unsigned long long);

        if (pos >= end)
        {
            return -pte_eos;
        }

        val = *(const unsigned long long *)cur;

        if ((val != psb_unique_pattern[0]) && (val != psb_unique_pattern[1]))
        {
            continue;
        }

        /* We found a 64bit word's worth of psb payload pattern. */
        /* Navigate to the end of the psb payload pattern.
        *
        * Beware that PSB is an extended opcode. We must not confuse the extend
        * opcode of the following packet as belonging to the PSB.
        */
        cur = pos;

        if (*pos != pt_psb_hi)
        {
            pos++;
        }

        for (; (pos + 1) < end; pos += 2)
        {
            hi = pos[0];
            lo = pos[1];

            if (hi != pt_psb_hi)
            {
                break;
            }
            if (lo != pt_psb_lo)
            {
                break;
            }
        }
        /*
        * We're right after the psb payload and within the buffer.
        * Navigate to the expected beginning of the psb packet.
        */
        pos -= ptps_psb;

        /* Check if we're still inside the buffer. */
        if (pos < begin)
        {
            pos = cur;
            continue;
        }
        /* Check that this is indeed a psb packet we're at. */
        if (pos[0] != pt_opc_psb || pos[1] != pt_ext_psb)
        {
            pos = cur;
            continue;
        }

        *sync = (unsigned char*) pos;
        break;
    }

    return 0;
}

/* decodes PT packets given in 'buffer' of length 'size'*/
int decode_pt(unsigned char* buffer, size_t size, unsigned char* dst, size_t dst_size, uint32_t mode)
{
    unsigned char *end, *pos, *start, *sync;
    unsigned char ipc, opc, ext, ext2;
    unsigned char cyc, shl;
    unsigned long long value;
    unsigned long long signbit, mask, bits;
    int ipsize = 0;
    int curr_dst_size = 0;

    struct pt_last_ip last_ip;

    int state = 0;

    memset(&last_ip, 0, sizeof(last_ip));

    start = buffer;
    end = buffer + size;
    sync = buffer;

    for (pos = buffer; pos < end;)
    {
        start = pos;

        opc = *pos;

        switch (opc)
        {
        case pt_opc_pad:
            //pt_decode_pad;
            pos = pos + ptps_pad;
            break;

        case pt_opc_mode:
            //pt_decode_mode;
            pos = pos + ptps_mode;
            break;

        case pt_opc_tsc:
            //pt_decode_tsc;
            pos = pos + ptps_tsc;
            break;

        case pt_opc_mtc:
            //pt_decode_mtc;
            pos = pos + ptps_mtc;
            break;

        case pt_opc_ext:

            pos++;

            if (pos == end)
            {
                return curr_dst_size;
            }
            ext = *pos;

            switch(ext)
            {
                default:
                    //pt_decode_unknown; may need to PSB sync
                    if (!sync_forward_to_psb(buffer, end, pos, &sync))
                    {
                        pos = sync;
                        last_ip.ip = 0ull;
                        last_ip.have_ip = 0;
                        last_ip.suppressed = 0;
                    }
                    else
                    {
                        return curr_dst_size;
                    }
                    break;

                case pt_ext_psb:
                    //pt_decode_psb;
                    pos = start + ptps_psb;
                    break;

                case pt_ext_ovf:
                    //pt_decode_ovf;
                    pos = start + ptps_ovf;
                    break;

                case pt_ext_tnt_64:
                    //pt_decode_tnt_64;
                    pos = start + ptps_tnt_64;
                    break;

                case pt_ext_psbend:
                    //pt_decode_psbend;
                    pos = start + ptps_psbend;
                    break;

                case pt_ext_cbr:
                    //pt_decode_cbr;
                    pos = start + ptps_cbr;
                    break;

                case pt_ext_pip:
                    //pt_decode_pip;
                    pos = start + ptps_pip;
                    break;

                case pt_ext_tma:
                    //pt_decode_tma;
                    pos = start + ptps_tma;
                    break;

                case pt_ext_stop:
                    //pt_decode_stop;
                    pos = start + ptps_stop;
                    break;

                case pt_ext_vmcs:
                    //pt_decode_vmcs;
                    pos = start + ptps_vmcs;
                    break;

                case pt_ext_ext2:

                    pos++;
                    if (pos == end)
                    {
                        return curr_dst_size;
                    }
                    ext2 = *pos;

                    switch (ext2)
                    {
                        /// TODO: save MNT packet
                        case pt_ext2_mnt:
                            //pt_decode_mnt;
                            pos = start + ptps_mnt;

                            if(mode & vtss_iptmode_ucode)
                            {
                                if(dst_size - curr_dst_size >= 8)
                                {
                                    *(unsigned long long*)&dst[curr_dst_size] = *(unsigned long long*)&start[3];
                                    curr_dst_size += 8;
                                }
                                else
                                {
                                    /// set the last element to 0 to indicate an overflow
                                    *(unsigned long long*)&dst[curr_dst_size - 8] = 0;

                                    return curr_dst_size;
                                }
                            }
                            break;

                        default:
                            //pt_decode_unknown; may need to PSB sync
                            if (!sync_forward_to_psb(buffer, end, pos, &sync))
                            {
                                pos = sync;
                                last_ip.ip = 0ull;
                                last_ip.have_ip = 0;
                                last_ip.suppressed = 0;
                            }
                            else
                            {
                                return curr_dst_size;
                            }
                            break;
                    }
                    break;
            }
            break;

        default:
            /* Check opcodes that require masking. */
            if ((opc & pt_opm_tnt_8) == pt_opc_tnt_8)
            {
                /// reset stop-mark-tracking state if not TIP
                state = 0;

                pos = pos + ptps_tnt_8;
                break;
            }

            if ((opc & pt_opm_cyc) == pt_opc_cyc)
            {
                //pt_decode_cyc;
                /* The first byte contains the opcode and part of the payload.
                * We already checked that this first byte is within bounds.
                */
                cyc = *pos++;
                ext = cyc & pt_opm_cyc_ext;
                cyc >>= pt_opm_cyc_shr;
                value = cyc;
                shl = (8 - pt_opm_cyc_shr);

                while (ext)
                {
                    if (pos >= end)
                    {
                        return curr_dst_size;
                    }
                    bits = *pos++;
                    ext = (unsigned char)(bits & pt_opm_cycx_ext);

                    bits >>= pt_opm_cycx_shr;
                    bits <<= shl;

                    shl += (8 - pt_opm_cycx_shr);

                    if (sizeof(value) * 8 < shl)
                    {
                        break; // -pte_bad_packet, may need to PSB sync
                    }
                    value |= bits;
                }
                break;
            }

            if ((opc & pt_opm_tip) == pt_opc_tip ||
                (opc & pt_opm_fup) == pt_opc_fup ||
                (opc & pt_opm_tip) == pt_opc_tip_pge ||
                (opc & pt_opm_tip) == pt_opc_tip_pgd)
            {
                //pt_decode_tip; pt_decode_fup; pt_decode_tip_pge; pt_decode_tip_pgd 

                ipc = (*pos++ >> pt_opm_ipc_shr) & pt_opm_ipc_shr_mask;

                switch ((enum pt_ip_compression)ipc)
                {
                    case pt_ipc_suppressed:

                        ipsize = 0;
                        break;

                    case pt_ipc_update_16:

                        ipsize = 2;
                        break;

                    case pt_ipc_update_32:

                        ipsize = 4;
                        break;

                    case pt_ipc_update_48:
                    case pt_ipc_sext_48:

                        ipsize = 6;
                        break;

                    case pt_ipc_full:

                        ipsize = 8;
                        break;

                    default:
                        // -pte_bad_packet; may need PSB sync
                        break;
                }

                if (pos + ipsize > end)
                {
                    return curr_dst_size;
                }
                value = 0;

                if (ipsize)
                {
                    int idx;

                    for (idx = 0; idx < ipsize; ++idx)
                    {
                        unsigned long long byte = *pos++;
                        byte <<= (idx * 8);
                        value |= byte;
                    }
                }

                switch ((enum pt_ip_compression)ipc)
                {
                    case pt_ipc_suppressed:

                        last_ip.suppressed = 1;
                        break;

                    case pt_ipc_sext_48:

                        signbit = 1ull << (48 - 1);
                        mask = ~0ull << 48;

                        last_ip.ip = value & signbit ? value | mask : value & ~mask; //sext(ip, 48);
                        last_ip.have_ip = 1;
                        last_ip.suppressed = 0;
                        break;

                    case pt_ipc_update_16:

                        last_ip.ip = (last_ip.ip & ~0xffffull) | (value & 0xffffull);
                        last_ip.have_ip = 1;
                        last_ip.suppressed = 0;
                        break;

                    case pt_ipc_update_32:

                        last_ip.ip = (last_ip.ip & ~0xffffffffull) | (value & 0xffffffffull);
                        last_ip.have_ip = 1;
                        last_ip.suppressed = 0;
                        break;

                    case pt_ipc_update_48:

                        last_ip.ip = (last_ip.ip & ~0xffffffffffffull) | (value & 0xffffffffffffull);
                        last_ip.have_ip = 1;
                        last_ip.suppressed = 0;
                        break;

                    case pt_ipc_full:

                        last_ip.ip = value;
                        last_ip.have_ip = 1;
                        last_ip.suppressed = 0;
                        break;
                }

                /// TODO: copy IP to an output buffer
                /* Prints only TIP packets */
                if ((opc & pt_opm_tip) == pt_opc_tip)
                {
                    if(mode & vtss_iptmode_tips)
                    {
                        if(dst_size - curr_dst_size >= 8)
                        {
                            *(unsigned long long*)&dst[curr_dst_size] = last_ip.ip;
                            curr_dst_size += 8;
                        }
                        else
                        {
                            /// set the last element to 0 to indicate an overflow
                            *(unsigned long long*)&dst[curr_dst_size - 8] = 0;

                            return curr_dst_size;
                        }
                    }
                    /// locate a stop-mark to stop PT collection
                    if(mode & vtss_iptmode_mark)
                    {
                        if((last_ip.ip & 0x0f) - 1 == state)
                        {
                            if(state == 2)
                            {
                                /// stop-mark indication
                                return -1;
                            }
                            state++;
                        }
                        else
                        {
                            state = 0;
                        }
                    }
                }
                /// reset stop-mark-tracking state if not TIP
                else
                {
                    state = 0;
                }
                break;
            }

            //pt_decode_unknown; may need PSB sync or just keep iterating
            if (!sync_forward_to_psb(buffer, end, pos, &sync))
            {
                pos = sync;
                last_ip.ip = 0ull;
                last_ip.have_ip = 0;
                last_ip.suppressed = 0;
            }
            else
            {
                return curr_dst_size;
            }
            break;
        }
    }

    /* case 1: pos == end; decoding the buffer ends normally
    *  case 2: pos == end; decoding the buffer has ended in the middle of opcode
               - solved by returning immediately after detection
    *  case 3: pos > end; decoding the buffer has ended in the middle of a packet
    */

    /// but we do not differentiate between any of those cases for now...

    if (pos == end)
    {
        return curr_dst_size;
    }
    if (pos > end)
    {
        return curr_dst_size;
    }

    return curr_dst_size;
}

