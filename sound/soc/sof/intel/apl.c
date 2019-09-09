// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * Copyright(c) 2017 Intel Corporation. All rights reserved.
 *
 * Authors: Liam Girdwood <liam.r.girdwood@linux.intel.com>
 *	    Ranjani Sridharan <ranjani.sridharan@linux.intel.com>
 *	    Jeeja KP <jeeja.kp@intel.com>
 *	    Rander Wang <rander.wang@intel.com>
 *          Keyon Jie <yang.jie@linux.intel.com>
 */

/*
 * Hardware interface for audio DSP on Apollolake and GeminiLake
 */

#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/pci.h>
#include <sound/hdaudio_ext.h>
#include <sound/sof.h>
#include <sound/pcm_params.h>
#include <linux/pm_runtime.h>

#include "../sof-priv.h"
#include "../ops.h"
#include "hda.h"

static const struct snd_sof_debugfs_map apl_dsp_debugfs[] = {
	{"hda", HDA_DSP_HDA_BAR, 0, 0x4000},
	{"pp", HDA_DSP_PP_BAR,  0, 0x1000},
	{"dsp", HDA_DSP_BAR,  0, 0x10000},
};

/* apollolake ops */
struct snd_sof_dsp_ops sof_apl_ops = {
	/* probe and remove */
	.probe		= hda_dsp_probe,
	.remove		= hda_dsp_remove,

	/* Register IO */
	.write		= hda_dsp_write,
	.read		= hda_dsp_read,
	.write64	= hda_dsp_write64,
	.read64		= hda_dsp_read64,

	/* Block IO */
	.block_read	= hda_dsp_block_read,
	.block_write	= hda_dsp_block_write,

	/* doorbell */
	.irq_handler	= hda_dsp_ipc_irq_handler,
	.irq_thread	= hda_dsp_ipc_irq_thread,

	/* mailbox */
	.mailbox_read	= hda_dsp_mailbox_read,
	.mailbox_write	= hda_dsp_mailbox_write,

	/* ipc */
	.send_msg	= hda_dsp_ipc_send_msg,
	.get_reply	= hda_dsp_ipc_get_reply,
	.fw_ready	= hda_dsp_ipc_fw_ready,
	.is_ready	= hda_dsp_ipc_is_ready,
	.cmd_done	= hda_dsp_ipc_cmd_done,

	/* debug */
	.debug_map	= apl_dsp_debugfs,
	.debug_map_count	= ARRAY_SIZE(apl_dsp_debugfs),
	.dbg_dump	= hda_dsp_dump,

	/* stream callbacks */
	.host_stream_open = hda_dsp_pcm_open,
	.host_stream_close = hda_dsp_pcm_close,
	.host_stream_hw_params = hda_dsp_pcm_hw_params,
	.host_stream_trigger = hda_dsp_pcm_trigger,

	/* firmware loading */
	.load_firmware = hda_dsp_cl_load_fw,

	/* firmware run */
	.run = hda_dsp_cl_boot_firmware,

	/* trace callback */
	.trace_init = hda_dsp_trace_init,
	.trace_release = hda_dsp_trace_release,
	.trace_trigger = hda_dsp_trace_trigger,
};
EXPORT_SYMBOL(sof_apl_ops);
