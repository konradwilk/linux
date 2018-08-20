/*COPYRIGHT**
// -------------------------------------------------------------------------
//               INTEL CORPORATION PROPRIETARY INFORMATION
//  This software is supplied under the terms of the accompanying license
//  agreement or nondisclosure agreement with Intel Corporation and may not
//  be copied or disclosed except in accordance with the terms of that
//  agreement.
//        Copyright (c) 2013 Intel Corporation. All Rights Reserved.
// -------------------------------------------------------------------------
**COPYRIGHT*/

/*
//  File  : iptdec.h
//  Author: derived from libipt
*/
#ifndef _IPTDEC_H_
#define _IPTDEC_H_

/* Configuration. */

/** A cpu vendor. */
enum pt_cpu_vendor {
	pcv_unknown,
	pcv_intel
};

/** A cpu identifier. */
struct pt_cpu {
	/** The cpu vendor. */
	enum pt_cpu_vendor vendor;

	/** The cpu family. */
	uint16_t family;

	/** The cpu model. */
	uint8_t model;

	/** The stepping. */
	uint8_t stepping;
};

/** A collection of Intel PT errata. */
struct pt_errata {
	/** BDM70: Intel(R) Processor Trace PSB+ Packets May Contain
	*         Unexpected Packets.
	*
	* Same as: SKD024.
	*
	* Some Intel Processor Trace packets should be issued only between
	* TIP.PGE and TIP.PGD packets.  Due to this erratum, when a TIP.PGE
	* packet is generated it may be preceded by a PSB+ that incorrectly
	* includes FUP and MODE.Exec packets.
	*/
	uint32_t bdm70 : 1;

	/** BDM64: An Incorrect LBR or Intel(R) Processor Trace Packet May Be
	*         Recorded Following a Transactional Abort.
	*
	* Use of Intel(R) Transactional Synchronization Extensions (Intel(R)
	* TSX) may result in a transactional abort.  If an abort occurs
	* immediately following a branch instruction, an incorrect branch
	* target may be logged in an LBR (Last Branch Record) or in an Intel(R)
	* Processor Trace (Intel(R) PT) packet before the LBR or Intel PT
	* packet produced by the abort.
	*/
	uint32_t bdm64 : 1;

	/** SKD007: Intel(R) PT Buffer Overflow May Result in Incorrect Packets.
	*
	* Under complex micro-architectural conditions, an Intel PT (Processor
	* Trace) OVF (Overflow) packet may be issued after the first byte of a
	* multi-byte CYC (Cycle Count) packet, instead of any remaining bytes
	* of the CYC.
	*/
	uint32_t skd007 : 1;

	/** SKD022: VM Entry That Clears TraceEn May Generate a FUP.
	*
	* If VM entry clears Intel(R) PT (Intel Processor Trace)
	* IA32_RTIT_CTL.TraceEn (MSR 570H, bit 0) while PacketEn is 1 then a
	* FUP (Flow Update Packet) will precede the TIP.PGD (Target IP Packet,
	* Packet Generation Disable).  VM entry can clear TraceEn if the
	* VM-entry MSR-load area includes an entry for the IA32_RTIT_CTL MSR.
	*/
	uint32_t skd022 : 1;

	/** SKD010: Intel(R) PT FUP May be Dropped After OVF.
	*
	* Same as: SKD014.
	*
	* Some Intel PT (Intel Processor Trace) OVF (Overflow) packets may not
	* be followed by a FUP (Flow Update Packet) or TIP.PGE (Target IP
	* Packet, Packet Generation Enable).
	*/
	uint32_t skd010 : 1;

	/* Reserve a few bytes for the future. */
	uint32_t reserved[15];
};

/* Errors. */

/** Error codes. */
enum pt_error_code {
	/* No error. Everything is OK. */
	pte_ok,

	/* Internal decoder error. */
	pte_internal,

	/* Invalid argument. */
	pte_invalid,

	/* Decoder out of sync. */
	pte_nosync,

	/* Unknown opcode. */
	pte_bad_opc,

	/* Unknown payload. */
	pte_bad_packet,

	/* Unexpected packet context. */
	pte_bad_context,

	/* Decoder reached end of trace stream. */
	pte_eos,

	/* No packet matching the query to be found. */
	pte_bad_query,

	/* Decoder out of memory. */
	pte_nomem,

	/* Bad configuration. */
	pte_bad_config,

	/* There is no IP. */
	pte_noip,

	/* The IP has been suppressed. */
	pte_ip_suppressed,

	/* There is no memory mapped at the requested address. */
	pte_nomap,

	/* An instruction could not be decoded. */
	pte_bad_insn,

	/* No wall-clock time is available. */
	pte_no_time,

	/* No core:bus ratio available. */
	pte_no_cbr,

	/* Bad traced image. */
	pte_bad_image,

	/* A locking error. */
	pte_bad_lock,

	/* The requested feature is not supported. */
	pte_not_supported,

	/* The return address stack is empty. */
	pte_retstack_empty,

	/* A compressed return is not indicated correctly by a taken branch. */
	pte_bad_retcomp,

	/* The current decoder state does not match the state in the trace. */
	pte_bad_status_update,

	/* The trace did not contain an expected enabled event. */
	pte_no_enable,

	/* An event was ignored. */
	pte_event_ignored
};

/* Opcodes. */

/** A one byte opcode. */
enum pt_opcode {
	pt_opc_pad = 0x00,
	pt_opc_ext = 0x02,
	pt_opc_psb = pt_opc_ext,
	pt_opc_tip = 0x0d,
	pt_opc_tnt_8 = 0x00,
	pt_opc_tip_pge = 0x11,
	pt_opc_tip_pgd = 0x01,
	pt_opc_fup = 0x1d,
	pt_opc_mode = 0x99,
	pt_opc_tsc = 0x19,
	pt_opc_mtc = 0x59,
	pt_opc_cyc = 0x03,

	/* A free opcode to trigger a decode fault. */
	pt_opc_bad = 0xd9
};

/** A one byte extension code for ext opcodes. */
enum pt_ext_code {
	pt_ext_psb = 0x82,
	pt_ext_tnt_64 = 0xa3,
	pt_ext_pip = 0x43,
	pt_ext_ovf = 0xf3,
	pt_ext_psbend = 0x23,
	pt_ext_cbr = 0x03,
	pt_ext_tma = 0x73,
	pt_ext_stop = 0x83,
	pt_ext_vmcs = 0xc8,
	pt_ext_ext2 = 0xc3,

	pt_ext_bad = 0x04
};

/** A one byte extension 2 code for ext2 extension opcodes. */
enum pt_ext2_code {
	pt_ext2_mnt = 0x88,

	pt_ext2_bad = 0x00
};

/** A one byte opcode mask. */
enum pt_opcode_mask {
	pt_opm_tip = 0x1f,
	pt_opm_tnt_8 = 0x01,
	pt_opm_tnt_8_shr = 1,
	pt_opm_fup = pt_opm_tip,

	/* The bit mask for the compression bits in the opcode. */
	pt_opm_ipc = 0xe0,

	/* The shift right value for ipc bits. */
	pt_opm_ipc_shr = 5,

	/* The bit mask for the compression bits after shifting. */
	pt_opm_ipc_shr_mask = 0x7,

	/* Shift counts and masks for decoding the cyc packet. */
	pt_opm_cyc = 0x03,
	pt_opm_cyc_ext = 0x04,
	pt_opm_cyc_bits = 0xf8,
	pt_opm_cyc_shr = 3,
	pt_opm_cycx_ext = 0x01,
	pt_opm_cycx_shr = 1
};

/** The size of the various opcodes in bytes. */
enum pt_opcode_size {
	pt_opcs_pad = 1,
	pt_opcs_tip = 1,
	pt_opcs_tip_pge = 1,
	pt_opcs_tip_pgd = 1,
	pt_opcs_fup = 1,
	pt_opcs_tnt_8 = 1,
	pt_opcs_mode = 1,
	pt_opcs_tsc = 1,
	pt_opcs_mtc = 1,
	pt_opcs_cyc = 1,
	pt_opcs_psb = 2,
	pt_opcs_psbend = 2,
	pt_opcs_ovf = 2,
	pt_opcs_pip = 2,
	pt_opcs_tnt_64 = 2,
	pt_opcs_cbr = 2,
	pt_opcs_tma = 2,
	pt_opcs_stop = 2,
	pt_opcs_vmcs = 2,
	pt_opcs_mnt = 3
};

/** The psb magic payload.
*
* The payload is a repeating 2-byte pattern.
*/
enum pt_psb_pattern {
	/* The high and low bytes in the pattern. */
	pt_psb_hi = pt_opc_psb,
	pt_psb_lo = pt_ext_psb,

	/* Various combinations of the above parts. */
	pt_psb_lohi = pt_psb_lo | pt_psb_hi << 8,
	pt_psb_hilo = pt_psb_hi | pt_psb_lo << 8,

	/* The repeat count of the payload, not including opc and ext. */
	pt_psb_repeat_count = 7,

	/* The size of the repeated pattern in bytes. */
	pt_psb_repeat_size = 2
};

/** An execution mode. */
enum pt_exec_mode {
	ptem_unknown,
	ptem_16bit,
	ptem_32bit,
	ptem_64bit
};

/** The payload details. */
enum pt_payload {
	/* The shift counts for post-processing the PIP payload. */
	pt_pl_pip_shr = 1,
	pt_pl_pip_shl = 5,

	/* The size of a PIP payload in bytes. */
	pt_pl_pip_size = 6,

	/* The non-root bit in the first byte of the PIP payload. */
	pt_pl_pip_nr = 0x01,

	/* The size of a 8bit TNT packet's payload in bits. */
	pt_pl_tnt_8_bits = 8 - pt_opm_tnt_8_shr,

	/* The size of a 64bit TNT packet's payload in bytes. */
	pt_pl_tnt_64_size = 6,

	/* The size of a 64bit TNT packet's payload in bits. */
	pt_pl_tnt_64_bits = 48,

	/* The size of a TSC packet's payload in bytes and in bits. */
	pt_pl_tsc_size = 7,
	pt_pl_tsc_bit_size = pt_pl_tsc_size * 8,

	/* The size of a CBR packet's payload in bytes. */
	pt_pl_cbr_size = 2,

	/* The size of a PSB packet's payload in bytes. */
	pt_pl_psb_size = pt_psb_repeat_count * pt_psb_repeat_size,

	/* The size of a MODE packet's payload in bytes. */
	pt_pl_mode_size = 1,

	/* The size of an IP packet's payload with update-16 compression. */
	pt_pl_ip_upd16_size = 2,

	/* The size of an IP packet's payload with update-32 compression. */
	pt_pl_ip_upd32_size = 4,

	/* The size of an IP packet's payload with update-48 compression. */
	pt_pl_ip_upd48_size = 6,

	/* The size of an IP packet's payload with sext-48 compression. */
	pt_pl_ip_sext48_size = 6,

	/* The size of an IP packet's payload with full-ip compression. */
	pt_pl_ip_full_size = 8,

	/* Byte locations, sizes, and masks for processing TMA packets. */
	pt_pl_tma_size = 5,
	pt_pl_tma_ctc_size = 2,
	pt_pl_tma_ctc_bit_size = pt_pl_tma_ctc_size * 8,
	pt_pl_tma_ctc_0 = 2,
	pt_pl_tma_ctc_1 = 3,
	pt_pl_tma_ctc_mask = (1 << pt_pl_tma_ctc_bit_size) - 1,
	pt_pl_tma_fc_size = 2,
	pt_pl_tma_fc_bit_size = 9,
	pt_pl_tma_fc_0 = 5,
	pt_pl_tma_fc_1 = 6,
	pt_pl_tma_fc_mask = (1 << pt_pl_tma_fc_bit_size) - 1,

	/* The size of a MTC packet's payload in bytes and in bits. */
	pt_pl_mtc_size = 1,
	pt_pl_mtc_bit_size = pt_pl_mtc_size * 8,

	/* A mask for the MTC payload bits. */
	pt_pl_mtc_mask = (1 << pt_pl_mtc_bit_size) - 1,

	/* The maximal payload size in bytes of a CYC packet. */
	pt_pl_cyc_max_size = 15,

	/* The size of a VMCS packet's payload in bytes. */
	pt_pl_vmcs_size = 5,

	/* The shift counts for post-processing the VMCS payload. */
	pt_pl_vmcs_shl = 12,

	/* The size of a MNT packet's payload in bytes. */
	pt_pl_mnt_size = 8
};

/** Mode packet masks. */
enum pt_mode_mask {
	pt_mom_leaf = 0xe0,
	pt_mom_leaf_shr = 5,
	pt_mom_bits = 0x1f
};

/** Mode packet leaves. */
enum pt_mode_leaf {
	pt_mol_exec = 0x00,
	pt_mol_tsx = 0x20
};

/** Mode packet bits. */
enum pt_mode_bit {
	/* mode.exec */
	pt_mob_exec_csl = 0x01,
	pt_mob_exec_csd = 0x02,

	/* mode.tsx */
	pt_mob_tsx_intx = 0x01,
	pt_mob_tsx_abrt = 0x02
};

/** The IP compression. */
enum pt_ip_compression {
	/* The bits encode the payload size and the encoding scheme.
	*
	* No payload.  The IP has been suppressed.
	*/
	pt_ipc_suppressed = 0x0,

	/* Payload: 16 bits.  Update last IP. */
	pt_ipc_update_16 = 0x01,

	/* Payload: 32 bits.  Update last IP. */
	pt_ipc_update_32 = 0x02,

	/* Payload: 48 bits.  Sign extend to full address. */
	pt_ipc_sext_48 = 0x03,

	/* Payload: 48 bits.  Update last IP. */
	pt_ipc_update_48 = 0x04,

	/* Payload: 64 bits.  Full address. */
	pt_ipc_full = 0x06
};

/** The size of the various packets in bytes. */
enum pt_packet_size {
	ptps_pad = pt_opcs_pad,
	ptps_tnt_8 = pt_opcs_tnt_8,
	ptps_mode = pt_opcs_mode + pt_pl_mode_size,
	ptps_tsc = pt_opcs_tsc + pt_pl_tsc_size,
	ptps_mtc = pt_opcs_mtc + pt_pl_mtc_size,
	ptps_psb = pt_opcs_psb + pt_pl_psb_size,
	ptps_psbend = pt_opcs_psbend,
	ptps_ovf = pt_opcs_ovf,
	ptps_pip = pt_opcs_pip + pt_pl_pip_size,
	ptps_tnt_64 = pt_opcs_tnt_64 + pt_pl_tnt_64_size,
	ptps_cbr = pt_opcs_cbr + pt_pl_cbr_size,
	ptps_tip_supp = pt_opcs_tip,
	ptps_tip_upd16 = pt_opcs_tip + pt_pl_ip_upd16_size,
	ptps_tip_upd32 = pt_opcs_tip + pt_pl_ip_upd32_size,
	ptps_tip_upd48 = pt_opcs_tip + pt_pl_ip_upd48_size,
	ptps_tip_sext48 = pt_opcs_tip + pt_pl_ip_sext48_size,
	ptps_tip_full = pt_opcs_tip + pt_pl_ip_full_size,
	ptps_tip_pge_supp = pt_opcs_tip_pge,
	ptps_tip_pge_upd16 = pt_opcs_tip_pge + pt_pl_ip_upd16_size,
	ptps_tip_pge_upd32 = pt_opcs_tip_pge + pt_pl_ip_upd32_size,
	ptps_tip_pge_upd48 = pt_opcs_tip_pge + pt_pl_ip_upd48_size,
	ptps_tip_pge_sext48 = pt_opcs_tip_pge + pt_pl_ip_sext48_size,
	ptps_tip_pge_full = pt_opcs_tip_pge + pt_pl_ip_full_size,
	ptps_tip_pgd_supp = pt_opcs_tip_pgd,
	ptps_tip_pgd_upd16 = pt_opcs_tip_pgd + pt_pl_ip_upd16_size,
	ptps_tip_pgd_upd32 = pt_opcs_tip_pgd + pt_pl_ip_upd32_size,
	ptps_tip_pgd_upd48 = pt_opcs_tip_pgd + pt_pl_ip_upd48_size,
	ptps_tip_pgd_sext48 = pt_opcs_tip_pgd + pt_pl_ip_sext48_size,
	ptps_tip_pgd_full = pt_opcs_tip_pgd + pt_pl_ip_full_size,
	ptps_fup_supp = pt_opcs_fup,
	ptps_fup_upd16 = pt_opcs_fup + pt_pl_ip_upd16_size,
	ptps_fup_upd32 = pt_opcs_fup + pt_pl_ip_upd32_size,
	ptps_fup_upd48 = pt_opcs_fup + pt_pl_ip_upd48_size,
	ptps_fup_sext48 = pt_opcs_fup + pt_pl_ip_sext48_size,
	ptps_fup_full = pt_opcs_fup + pt_pl_ip_full_size,
	ptps_tma = pt_opcs_tma + pt_pl_tma_size,
	ptps_stop = pt_opcs_stop,
	ptps_vmcs = pt_opcs_vmcs + pt_pl_vmcs_size,
	ptps_mnt = pt_opcs_mnt + pt_pl_mnt_size
};

/* We define a few abbreviations outside of the below enum as we don't
* want to handle those in switches.
*/
enum {
	ppt_ext = pt_opc_ext << 8,
	ppt_ext2 = ppt_ext << 8 | pt_ext_ext2 << 8
};

/** Intel PT packet types. */
enum
{
	/* 1-byte header packets. */
	ppt_pad = pt_opc_pad,
	ppt_tip = pt_opc_tip,
	ppt_tnt_8 = pt_opc_tnt_8 | 0xFE,
	ppt_tip_pge = pt_opc_tip_pge,
	ppt_tip_pgd = pt_opc_tip_pgd,
	ppt_fup = pt_opc_fup,
	ppt_mode = pt_opc_mode,
	ppt_tsc = pt_opc_tsc,
	ppt_mtc = pt_opc_mtc,
	ppt_cyc = pt_opc_cyc,

	/* 2-byte header packets. */
	ppt_psb = ppt_ext | pt_ext_psb,
	ppt_tnt_64 = ppt_ext | pt_ext_tnt_64,
	ppt_pip = ppt_ext | pt_ext_pip,
	ppt_stop = ppt_ext | pt_ext_stop,
	ppt_ovf = ppt_ext | pt_ext_ovf,
	ppt_psbend = ppt_ext | pt_ext_psbend,
	ppt_cbr = ppt_ext | pt_ext_cbr,
	ppt_tma = ppt_ext | pt_ext_tma,
	ppt_vmcs = ppt_ext | pt_ext_vmcs,

	/* 3-byte header packets. */
	ppt_mnt = ppt_ext2 | pt_ext2_mnt,

	/* A packet decodable by the optional decoder callback. */
	ppt_unknown = 0x7ffffffe,

	/* An invalid packet. */
	ppt_invalid = 0x7fffffff
};

/* Keeping track of the last-ip in Intel PT packets. */
struct pt_last_ip {
	/* The last IP. */
	uint64_t ip;

	/* Flags governing the handling of IP updates and queries:
	*
	* - we have seen an IP update.
	*/
	uint32_t have_ip : 1;
	/* - the IP has been suppressed in the last update. */
	uint32_t suppressed : 1;
};

int decode_pt(uint8_t* buffer, size_t size, uint8_t*dst, size_t dst_size, uint32_t mode);

#endif  /* _IPTDEC_H_ */
