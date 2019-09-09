/*
 * Copyright (c) 2015--2018 Intel Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/delay.h>
#include <linux/module.h>
#include "libcsspsys2600.h"
#include <vied_nci_psys_resource_model.h>
#include <ia_css_psys_device.h>
#include <ipu_device_cell_properties_func.h>

#include <uapi/linux/ipu-psys.h>

#include "ipu.h"
#include "ipu-fw-psys.h"
#include "ipu-psys.h"
#include "ipu-wrapper.h"
#include "ipu-mmu.h"

#include <ia_css_psys_process_group_cmd_impl.h>
#include <ia_css_psys_process_private_types.h>
#include <ia_css_psys_init.h>
#include <ia_css_psys_transport.h>
#include <ia_css_terminal_base_types.h>
#include <ia_css_terminal_types.h>
#include <ia_css_program_group_param_types.h>
#include <ia_css_psys_terminal_private_types.h>
#include <ia_css_program_group_data.h>
#include <ia_css_psys_program_group_private.h>

#define BASIC_ABI_CHECK

#ifndef BASIC_ABI_CHECK
#define ABI_CHECK(a, b, field)					\
	{								\
	if (offsetof(typeof(*a), field) != offsetof(typeof(*b), field))	\
		pr_err("intel_ipu4 psys ABI mismatch %s\n",		\
		       __stringify(field));		    \
	}
#else
#define ABI_CHECK(a, b, field) { }
#endif

#define SIZE_OF_CHECK(a, b) \
	{		    \
	if (sizeof(*a) != sizeof(*b))\
		pr_err("intel_ipu4 psys ABI size of mismatch %s\n",	\
		       __stringify(a));					\
	}								\

static void abi_sanity_checker(void)
{
	struct ipu_fw_psys_process_group *ipu_fw_psys_pg;
	struct ia_css_process_group_s *ia_css_pg;

	struct ipu_fw_psys_process *ipu_fw_psys_ps;
	struct ia_css_process_s *ia_css_ps;

	struct ipu_fw_psys_srv_init *ipu_fw_psys_init;
	struct ia_css_psys_server_init *ia_css_psys_init;

	struct ipu_fw_psys_cmd *ipu_fw_psys_cmd;
	struct ia_css_psys_cmd_s *ia_css_psys_cmd;

	struct ipu_fw_psys_event *ipu_fw_psys_event;
	struct ia_css_psys_event_s *ia_css_psys_event;

	struct ipu_fw_psys_terminal *ipu_fw_psys_terminal;
	struct ia_css_terminal_s *ia_css_terminal;

	struct ipu_fw_psys_param_terminal *ipu_fw_psys_param_terminal;
	struct ia_css_param_terminal_s *ia_css_param_terminal;

	struct ipu_fw_psys_param_payload *ipu_fw_psys_param_payload;
	struct ia_css_param_payload_s *ia_css_param_payload;

	struct ipu_fw_psys_data_terminal *ipu_fw_psys_data_terminal;
	struct ia_css_data_terminal_s *ia_css_data_terminal;

	struct ipu_fw_psys_frame *ipu_fw_psys_frame;
	struct ia_css_frame_s *ia_css_frame;

	struct ipu_fw_psys_frame_descriptor *ipu_fw_psys_frame_descriptor;
	struct ia_css_frame_descriptor_s *ia_css_frame_descriptor;

	struct ipu_fw_psys_stream *ipu_fw_psys_stream;
	struct ia_css_stream_s *ia_css_stream;

	SIZE_OF_CHECK(ipu_fw_psys_pg, ia_css_pg);
	ABI_CHECK(ipu_fw_psys_pg, ia_css_pg, ID);
	ABI_CHECK(ipu_fw_psys_pg, ia_css_pg, process_count);
	ABI_CHECK(ipu_fw_psys_pg, ia_css_pg, processes_offset);
	ABI_CHECK(ipu_fw_psys_pg, ia_css_pg, routing_bitmap);

	SIZE_OF_CHECK(ipu_fw_psys_ps, ia_css_ps);
	ABI_CHECK(ipu_fw_psys_ps, ia_css_ps, ID);
	ABI_CHECK(ipu_fw_psys_ps, ia_css_ps, dev_chn_offset);
	ABI_CHECK(ipu_fw_psys_ps, ia_css_ps, cell_id);

	SIZE_OF_CHECK(ipu_fw_psys_init, ia_css_psys_init);
	ABI_CHECK(ipu_fw_psys_init, ia_css_psys_init, icache_prefetch_sp);
	ABI_CHECK(ipu_fw_psys_init, ia_css_psys_init, icache_prefetch_isp);

	SIZE_OF_CHECK(ipu_fw_psys_cmd, ia_css_psys_cmd);
	ABI_CHECK(ipu_fw_psys_cmd, ia_css_psys_cmd, command);
	ABI_CHECK(ipu_fw_psys_cmd, ia_css_psys_cmd, msg);
	ABI_CHECK(ipu_fw_psys_cmd, ia_css_psys_cmd, context_handle);

	SIZE_OF_CHECK(ipu_fw_psys_event, ia_css_psys_event);
	ABI_CHECK(ipu_fw_psys_event, ia_css_psys_event, status);
	ABI_CHECK(ipu_fw_psys_event, ia_css_psys_event, token);

	SIZE_OF_CHECK(ipu_fw_psys_terminal, ia_css_terminal);
	ABI_CHECK(ipu_fw_psys_terminal, ia_css_terminal, terminal_type);

	SIZE_OF_CHECK(ipu_fw_psys_param_terminal, ia_css_param_terminal);
	ABI_CHECK(ipu_fw_psys_param_terminal, ia_css_param_terminal,
		  param_payload);

	SIZE_OF_CHECK(ipu_fw_psys_param_payload, ia_css_param_payload);
	ABI_CHECK(ipu_fw_psys_param_payload, ia_css_param_payload, buffer);

	SIZE_OF_CHECK(ipu_fw_psys_data_terminal, ia_css_data_terminal);
	ABI_CHECK(ipu_fw_psys_data_terminal, ia_css_data_terminal, frame);
	ABI_CHECK(ipu_fw_psys_data_terminal, ia_css_data_terminal,
		  connection_type);

	SIZE_OF_CHECK(ipu_fw_psys_frame, ia_css_frame);
	ABI_CHECK(ipu_fw_psys_frame, ia_css_frame, data_bytes);
	ABI_CHECK(ipu_fw_psys_frame, ia_css_frame, data);
	ABI_CHECK(ipu_fw_psys_frame, ia_css_frame, buffer_state);

	SIZE_OF_CHECK(ipu_fw_psys_frame_descriptor, ia_css_frame_descriptor);
	SIZE_OF_CHECK(ipu_fw_psys_stream, ia_css_stream);
}

int ipu_fw_psys_pg_start(struct ipu_psys_kcmd *kcmd)
{
	return -ia_css_process_group_start((ia_css_process_group_t *)
					   kcmd->kpg->pg);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_start);

int ipu_fw_psys_pg_disown(struct ipu_psys_kcmd *kcmd)
{
	return -ia_css_process_group_disown((ia_css_process_group_t *)
					    kcmd->kpg->pg);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_disown);

int ipu_fw_psys_pg_abort(struct ipu_psys_kcmd *kcmd)
{
	int rval;

	rval = ia_css_process_group_stop((ia_css_process_group_t *)
					 kcmd->kpg->pg);
	if (rval) {
		dev_err(&kcmd->fh->psys->adev->dev,
			"failed to abort kcmd!\n");
		kcmd->pg_user = NULL;
		rval = -EIO;
		/* TODO: need to reset PSYS by power cycling it */
	}
	return rval;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_abort);

int ipu_fw_psys_pg_submit(struct ipu_psys_kcmd *kcmd)
{
	return -ia_css_process_group_submit((ia_css_process_group_t *)
					    kcmd->kpg->pg);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_submit);

static void *syscom_buffer;
static struct ia_css_syscom_config *syscom_config;
static struct ia_css_psys_server_init *server_init;

int ipu_fw_psys_rcv_event(struct ipu_psys *psys,
				struct ipu_fw_psys_event *event)
{
	return ia_css_psys_event_queue_receive(psys_syscom,
		IA_CSS_PSYS_EVENT_QUEUE_MAIN_ID,
		(struct ia_css_psys_event_s *)event);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_rcv_event);

int ipu_fw_psys_terminal_set(struct ipu_fw_psys_terminal *terminal,
				       int terminal_idx,
				       struct ipu_psys_kcmd *kcmd,
				       u32 buffer,
				       unsigned	size)
{
	ia_css_terminal_type_t type;
	u32 buffer_state;

	type = ia_css_terminal_get_type((ia_css_terminal_t *)terminal);

	switch (type) {
	case IA_CSS_TERMINAL_TYPE_PARAM_CACHED_IN:
	case IA_CSS_TERMINAL_TYPE_PARAM_CACHED_OUT:
	case IA_CSS_TERMINAL_TYPE_PARAM_SPATIAL_IN:
	case IA_CSS_TERMINAL_TYPE_PARAM_SPATIAL_OUT:
	case IA_CSS_TERMINAL_TYPE_PARAM_SLICED_IN:
	case IA_CSS_TERMINAL_TYPE_PARAM_SLICED_OUT:
	case IA_CSS_TERMINAL_TYPE_PROGRAM:
		buffer_state = IA_CSS_BUFFER_UNDEFINED;
		break;
	case IA_CSS_TERMINAL_TYPE_PARAM_STREAM:
	case IA_CSS_TERMINAL_TYPE_DATA_IN:
	case IA_CSS_TERMINAL_TYPE_STATE_IN:
		buffer_state = IA_CSS_BUFFER_FULL;
		break;
	case IA_CSS_TERMINAL_TYPE_DATA_OUT:
	case IA_CSS_TERMINAL_TYPE_STATE_OUT:
		buffer_state = IA_CSS_BUFFER_EMPTY;
		break;
	default:
		dev_err(&kcmd->fh->psys->adev->dev,
			"unknown terminal type: 0x%x\n", type);
		return -EAGAIN;
	}

	if (type == IA_CSS_TERMINAL_TYPE_DATA_IN ||
	    type == IA_CSS_TERMINAL_TYPE_DATA_OUT) {
		ia_css_frame_t *frame;

		if (ia_css_data_terminal_set_connection_type(
			    (ia_css_data_terminal_t *)terminal,
			    IA_CSS_CONNECTION_MEMORY))
			return -EIO;
		frame = ia_css_data_terminal_get_frame(
			(ia_css_data_terminal_t *)terminal);
		if (!frame)
			return -EIO;

		if (ia_css_frame_set_data_bytes(frame, size))
			return -EIO;
	}

	return -ia_css_process_group_attach_buffer(
		(ia_css_process_group_t *)kcmd->kpg->pg, buffer,
		buffer_state, terminal_idx);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_terminal_set);

void ipu_fw_psys_pg_dump(struct ipu_psys *psys,
				   struct ipu_psys_kcmd *kcmd,
				   const char *note)
{
	ia_css_process_group_t *pg = (ia_css_process_group_t *)kcmd->kpg->pg;
	ia_css_program_group_ID_t pgid =
		ia_css_process_group_get_program_group_ID(pg);
	uint8_t processes = ia_css_process_group_get_process_count(
		(ia_css_process_group_t *)kcmd->kpg->pg);
	unsigned int p, chn, mem;

	dev_dbg(&psys->adev->dev, "%s %s pgid %i has %i processes\n",
		__func__, note, pgid, processes);
	for (p = 0; p < processes; p++) {
		ia_css_process_t *process =
			ia_css_process_group_get_process(pg, p);
		int cell = ia_css_process_get_cell(process);
		dev_dbg(&psys->adev->dev,
			"%s pgid %i process %i cell %i cell_bitmap = 0x%x size = %zu\n",
			__func__, pgid, p,
			cell,
			ia_css_process_get_cells_bitmap(process),
			ia_css_process_get_size(process));
		dev_dbg(&psys->adev->dev,
			"%s pgid %i process %i kernel bitmap 0x%llx \n",
			__func__, pgid, p,
			ia_css_process_get_kernel_bitmap(process));
		for (mem = 0; mem < VIED_NCI_N_DATA_MEM_TYPE_ID; mem++ ) {
			unsigned int mem_id = process->ext_mem_id[mem];
			dev_dbg(&psys->adev->dev,
				"%s pgid %i process %i index %u type %d id %d offset 0x%x \n",
				__func__, pgid, p, mem,
				vied_nci_cell_get_mem_type(cell, mem),
				mem_id, process->ext_mem_offset[mem]);
		}
		for (chn = 0; chn < VIED_NCI_N_DEV_CHN_ID; chn++ ) {
			dev_dbg(&psys->adev->dev,
				"%s pgid %i process %i dev_chn[%u] = %i\n",
				__func__, pgid, p, chn,
				ia_css_process_get_dev_chn(process, chn));
		}
	}
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_dump);

int ipu_fw_psys_pg_get_id(struct ipu_psys_kcmd *kcmd)
{
	return ia_css_process_group_get_program_group_ID(
		(ia_css_process_group_t *)kcmd->kpg->pg);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_get_id);

int ipu_fw_psys_pg_get_terminal_count(struct ipu_psys_kcmd *kcmd)
{
	return ia_css_process_group_get_terminal_count(
		(ia_css_process_group_t *)kcmd->kpg->pg);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_get_terminal_count);

int ipu_fw_psys_pg_get_size(struct ipu_psys_kcmd *kcmd)
{
	return ia_css_process_group_get_size((ia_css_process_group_t *)
					     kcmd->kpg->pg);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_get_size);

int ipu_fw_psys_pg_set_ipu_vaddress(struct ipu_psys_kcmd *kcmd,
				       dma_addr_t vaddress)
{
	return ia_css_process_group_set_ipu_vaddress((ia_css_process_group_t *)
						     kcmd->kpg->pg, vaddress);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_set_ipu_vaddress);

int ipu_fw_psys_pg_load_cycles(struct ipu_psys_kcmd *kcmd)
{
	return ia_css_process_group_get_pg_load_cycles(
		(ia_css_process_group_t *)kcmd->kpg->pg);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_load_cycles);

int ipu_fw_psys_pg_init_cycles(struct ipu_psys_kcmd *kcmd)
{
	return ia_css_process_group_get_pg_init_cycles(
		(ia_css_process_group_t *)kcmd->kpg->pg);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_init_cycles);

int ipu_fw_psys_pg_processing_cycles(struct ipu_psys_kcmd *kcmd)
{
	return ia_css_process_group_get_pg_processing_cycles(
		(ia_css_process_group_t *)kcmd->kpg->pg);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_processing_cycles);

struct ipu_fw_psys_terminal *
ipu_fw_psys_pg_get_terminal(struct ipu_psys_kcmd *kcmd, int index)
{
	return (struct ipu_fw_psys_terminal *)ia_css_process_group_get_terminal(
			(ia_css_process_group_t *)kcmd->kpg->pg, index);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_get_terminal);

void ipu_fw_psys_pg_set_token(struct ipu_psys_kcmd *kcmd, u64 token)
{
	ia_css_process_group_set_token((ia_css_process_group_t *)kcmd->kpg->pg,
				       token);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_set_token);

int ipu_fw_psys_pg_get_protocol(
	struct ipu_psys_kcmd *kcmd)
{
	return ia_css_process_group_get_protocol_version(
		(ia_css_process_group_t *)kcmd->kpg->pg);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_get_protocol);

int ipu_fw_psys_open(struct ipu_psys *psys)
{
	bool opened;
	int retry = IPU_PSYS_OPEN_RETRY;

	ipu_wrapper_init(PSYS_MMID, &psys->adev->dev,
				psys->pdata->base);

	server_init->icache_prefetch_sp = psys->icache_prefetch_sp;
	server_init->icache_prefetch_isp = psys->icache_prefetch_isp;

	psys_syscom = ia_css_psys_open(syscom_buffer, syscom_config);
	if (!psys_syscom) {
		dev_err(&psys->adev->dev,
			"psys library open failed\n");
		return -ENODEV;
	}
	do {
		opened = ia_css_psys_open_is_ready(psys_syscom);
		if (opened)
			break;
		usleep_range(IPU_PSYS_OPEN_TIMEOUT_US,
			     IPU_PSYS_OPEN_TIMEOUT_US + 10);
		retry--;
	} while (retry > 0);

	if (!retry && !opened) {
		dev_err(&psys->adev->dev,
			"psys library open ready failed\n");
		ia_css_psys_close(psys_syscom);
		ia_css_psys_release(psys_syscom, 1);
		psys_syscom = NULL;
		return -ENODEV;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_open);

int ipu_fw_psys_close(struct ipu_psys *psys)
{
	int rval;
	unsigned int retry = IPU_PSYS_CLOSE_TIMEOUT;

	if (!psys_syscom)
		return 0;

	if (ia_css_psys_close(psys_syscom)) {
		dev_err(&psys->adev->dev,
			"psys library close ready failed\n");
		return 0;
	}

	do {
		rval = ia_css_psys_release(psys_syscom, 0);
		if (rval && rval != -EBUSY) {
			dev_dbg(&psys->adev->dev, "psys library release failed\n");
			break;
		}
		usleep_range(IPU_PSYS_CLOSE_TIMEOUT_US,
			     IPU_PSYS_CLOSE_TIMEOUT_US + 10);
	} while (rval && --retry);

	psys_syscom = NULL;

	return 0;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_close);

u64 ipu_fw_psys_pg_get_token(struct ipu_psys_kcmd *kcmd)
{
	return 0;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_pg_get_token);

int ipu_fw_psys_ppg_set_buffer_set(struct ipu_psys_kcmd *kcmd,
				    struct ipu_fw_psys_terminal *terminal,
				    int terminal_idx, u32 buffer)
{
	return 0;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_ppg_set_buffer_set);

size_t
ipu_fw_psys_ppg_get_buffer_set_size(struct ipu_psys_kcmd *kcmd)
{
	return 0;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_ppg_get_buffer_set_size);

int
ipu_fw_psys_ppg_buffer_set_vaddress(struct ipu_fw_psys_buffer_set *buf_set,
				     u32 vaddress)
{
	return 0;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_ppg_buffer_set_vaddress);

struct ipu_fw_psys_buffer_set *
ipu_fw_psys_ppg_create_buffer_set(struct ipu_psys_kcmd *kcmd,
				   void *kaddr, u32 frame_counter)
{
	return NULL;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_ppg_create_buffer_set);

int
ipu_fw_psys_ppg_enqueue_bufs(struct ipu_psys_kcmd *kcmd,
			      unsigned int queue_offset)
{
	return 0;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_ppg_enqueue_bufs);

static const struct ipu_fw_resource_definitions default_defs = {
	.cells = vied_nci_cell_type,
	.num_cells = VIED_NCI_N_CELL_ID,
	.num_cells_type = VIED_NCI_N_CELL_TYPE_ID,
	.dev_channels = vied_nci_dev_chn_size,
	.num_dev_channels = VIED_NCI_N_DEV_CHN_ID,

	.num_ext_mem_types = VIED_NCI_N_DATA_MEM_TYPE_ID,
	.num_ext_mem_ids = VIED_NCI_N_MEM_ID,
	.ext_mem_ids = vied_nci_mem_size,

	.cell_mem_row = VIED_NCI_N_MEM_TYPE_ID,
	.cell_mem = (enum ipu_mem_id *)vied_nci_cell_mem,
	.process.ext_mem_id = offsetof(struct ia_css_process_s,
				       ext_mem_id[0]),
	.process.ext_mem_offset = offsetof(struct ia_css_process_s,
					   ext_mem_offset[0]),
	.process.dev_chn_offset = offsetof(struct ia_css_process_s,
					   dev_chn_offset[0]),
	.process.cell_id = offsetof(struct ia_css_process_s, cell_id),
};

const struct ipu_fw_resource_definitions *res_defs = &default_defs;
EXPORT_SYMBOL_GPL(res_defs);

/*
 * Extension library gives byte offsets to its internal structures.
 * use those offsets to update fields. Without extension lib access
 * structures directly.
 */
void ipu_fw_psys_set_process_cell_id(struct ipu_fw_psys_process *ptr, u8 index,
				u8 value)
{
	/* Byte offset */
	*((u8 *)ptr + res_defs->process.cell_id) = value;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_set_process_cell_id);

u8 ipu_fw_psys_get_process_cell_id(struct ipu_fw_psys_process *ptr, u8 index)
{
	/* Byte offset */
	return *((u8 *)ptr + res_defs->process.cell_id);
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_get_process_cell_id);

void ipu_fw_psys_set_process_dev_chn_offset(struct ipu_fw_psys_process *ptr,
				       u16 offset, u16 value)
{
	/* dev_chn_offset is a byte offset, offset is u16 index */
	*((u16 *)((u8 *)ptr + res_defs->process.dev_chn_offset) +
		 offset) = value;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_set_process_dev_chn_offset);

void ipu_fw_psys_set_process_ext_mem_offset(struct ipu_fw_psys_process *ptr,
				       u16 offset, u16 value)
{
	/* ext_mem_offset is a byte offset, offset is u16 index */
	*((u16 *)((u8 *)ptr + res_defs->process.ext_mem_offset) +
		  offset) = value;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_set_process_ext_mem_offset);

void ipu_fw_psys_set_process_ext_mem_id(struct ipu_fw_psys_process *ptr,
				   u16 offset, u8 value)
{
	/* ext_mem_id is a byte offset, offset parameter is u8 index */
	*((u8 *)ptr + res_defs->process.ext_mem_id + offset) = value;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_set_process_ext_mem_id);

int ipu_fw_psys_get_program_manifest_by_process(
	struct ipu_fw_generic_program_manifest *gen_pm,
	const struct ipu_fw_psys_program_group_manifest *pg_manifest,
	struct ipu_fw_psys_process *process)
{
	ia_css_program_ID_t process_id =
		ia_css_process_get_program_ID(
			(const ia_css_process_t *)process);
	int programs =
		ia_css_program_group_manifest_get_program_count(
			(const ia_css_program_group_manifest_t *)pg_manifest);
	int i;

	for (i = 0; i < programs; i++) {
		ia_css_program_ID_t program_id;
		ia_css_program_manifest_t *pm =
			ia_css_program_group_manifest_get_prgrm_mnfst(
				(const ia_css_program_group_manifest_t *)
				pg_manifest, i);
		if (!pm)
			continue;
		program_id = ia_css_program_manifest_get_program_ID(pm);
		if (program_id == process_id) {
			gen_pm->dev_chn_size = (u16 *)pm->dev_chn_size;
			gen_pm->ext_mem_size = (u16 *)pm->ext_mem_size;
			gen_pm->cell_id = pm->cell_id;
			gen_pm->cell_type_id = pm->cell_type_id;
			return 0;
		}
	}
	return -ENOENT;
}
EXPORT_SYMBOL_GPL(ipu_fw_psys_get_program_manifest_by_process);

static int __init libcsspsys2600_init(void)
{
	int rval;

	syscom_buffer = kzalloc(ia_css_sizeof_psys(NULL), GFP_KERNEL);
	if (!syscom_buffer)
		return -ENOMEM;

	syscom_config = kzalloc(
		sizeof(struct ia_css_syscom_config), GFP_KERNEL);
	if (!syscom_config) {
		rval = -ENOMEM;
		goto out_syscom_buffer_free;
	}

	server_init = kzalloc(
		sizeof(struct ia_css_psys_server_init), GFP_KERNEL);
	if (!server_init) {
		rval = -ENOMEM;
		goto out_syscom_config_free;
	}

	server_init->ddr_pkg_dir_address = 0;
	server_init->host_ddr_pkg_dir = 0;
	server_init->pkg_dir_size = 0;

	*syscom_config = *ia_css_psys_specify();
	syscom_config->specific_addr = server_init;
	syscom_config->specific_size =
		sizeof(struct ia_css_psys_server_init);
	syscom_config->ssid = PSYS_SSID;
	syscom_config->mmid = PSYS_MMID;
	syscom_config->regs_addr =
		ipu_device_cell_memory_address(
			SPC0, IPU_DEVICE_SP2600_CONTROL_REGS);
	syscom_config->dmem_addr =
		ipu_device_cell_memory_address(
			SPC0, IPU_DEVICE_SP2600_CONTROL_DMEM);
	abi_sanity_checker();

	return 0;

out_syscom_config_free:
	kfree(syscom_config);
out_syscom_buffer_free:
	kfree(syscom_buffer);

	return rval;
}

static void __exit libcsspsys2600_exit(void)
{
	kfree(syscom_buffer);
	kfree(syscom_config);
	kfree(server_init);
}

module_init(libcsspsys2600_init);
module_exit(libcsspsys2600_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Intel ipu psys css library");
