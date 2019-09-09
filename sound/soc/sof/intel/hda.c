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
 * Hardware interface for generic Intel audio DSP HDA IP
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

/*
 * Register IO
 */

void hda_dsp_write(struct snd_sof_dev *sdev, void __iomem *addr, u32 value)
{
	writel(value, addr);
}

u32 hda_dsp_read(struct snd_sof_dev *sdev, void __iomem *addr)
{
	return readl(addr);
}

void hda_dsp_write64(struct snd_sof_dev *sdev, void __iomem *addr, u64 value)
{
	memcpy_toio(addr, &value, sizeof(value));
}

u64 hda_dsp_read64(struct snd_sof_dev *sdev, void __iomem *addr)
{
	u64 val;

	memcpy_fromio(&val, addr, sizeof(val));
	return val;
}

/*
 * Memory copy.
 */

void hda_dsp_block_write(struct snd_sof_dev *sdev, u32 offset, void *src,
			 size_t size)
{
	void __iomem *dest = sdev->bar[sdev->mmio_bar] + offset;
	u32 tmp = 0;
	int i, m, n;
	const u8 *src_byte = src;

	m = size / 4;
	n = size % 4;

	/* __iowrite32_copy use 32bit size values so divide by 4 */
	__iowrite32_copy((void *)dest, src, m);

	if (n) {
		for (i = 0; i < n; i++)
			tmp |= (u32)*(src_byte + m * 4 + i) << (i * 8);
		__iowrite32_copy((void *)(dest + m * 4), &tmp, 1);
	}
}

void hda_dsp_block_read(struct snd_sof_dev *sdev, u32 offset, void *dest,
			size_t size)
{
	void __iomem *src = sdev->bar[sdev->mmio_bar] + offset;

	memcpy_fromio(dest, src, size);
}

/*
 * Debug
 */

struct hda_dsp_msg_code {
	u32 code;
	const char *msg;
};

static const struct hda_dsp_msg_code hda_dsp_rom_msg[] = {
	{HDA_DSP_ROM_FW_MANIFEST_LOADED, "status: manifest loaded"},
	{HDA_DSP_ROM_FW_FW_LOADED, "status: fw loaded"},
	{HDA_DSP_ROM_FW_ENTERED, "status: fw entered"},
	{HDA_DSP_ROM_CSE_ERROR, "error: cse error"},
	{HDA_DSP_ROM_CSE_WRONG_RESPONSE, "error: cse wrong response"},
	{HDA_DSP_ROM_IMR_TO_SMALL, "error: IMR too small"},
	{HDA_DSP_ROM_BASE_FW_NOT_FOUND, "error: base fw not found"},
	{HDA_DSP_ROM_CSE_VALIDATION_FAILED, "error: signature verification failed"},
	{HDA_DSP_ROM_IPC_FATAL_ERROR, "error: ipc fatal error"},
	{HDA_DSP_ROM_L2_CACHE_ERROR, "error: L2 cache error"},
	{HDA_DSP_ROM_LOAD_OFFSET_TO_SMALL, "error: load offset too small"},
	{HDA_DSP_ROM_API_PTR_INVALID, "error: API ptr invalid"},
	{HDA_DSP_ROM_BASEFW_INCOMPAT, "error: base fw incompatble"},
	{HDA_DSP_ROM_UNHANDLED_INTERRUPT, "error: unhandled interrupt"},
	{HDA_DSP_ROM_MEMORY_HOLE_ECC, "error: ECC memory hole"},
	{HDA_DSP_ROM_KERNEL_EXCEPTION, "error: kernel exception"},
	{HDA_DSP_ROM_USER_EXCEPTION, "error: user exception"},
	{HDA_DSP_ROM_UNEXPECTED_RESET, "error: unexpected reset"},
	{HDA_DSP_ROM_NULL_FW_ENTRY,	"error: null FW entry point"},
};

static void hda_dsp_get_status(struct snd_sof_dev *sdev)
{
	u32 status;
	int i;

	status = snd_sof_dsp_read(sdev, HDA_DSP_BAR,
				  HDA_DSP_SRAM_REG_ROM_STATUS);

	for (i = 0; i < ARRAY_SIZE(hda_dsp_rom_msg); i++) {
		if (status == hda_dsp_rom_msg[i].code) {
			dev_err(sdev->dev, "%s - code %8.8x\n",
				hda_dsp_rom_msg[i].msg, status);
			return;
		}
	}

	/* not for us, must be generic sof message */
	dev_dbg(sdev->dev, "unknown ROM status value %8.8x\n", status);
}

static void hda_dsp_get_registers(struct snd_sof_dev *sdev,
				  struct sof_ipc_dsp_oops_xtensa *xoops,
				  u32 *stack, size_t stack_words)
{
	/* first read registers */
	hda_dsp_block_read(sdev, sdev->dsp_oops_offset, xoops, sizeof(*xoops));

	/* then get the stack */
	hda_dsp_block_read(sdev, sdev->dsp_oops_offset + sizeof(*xoops), stack,
			   stack_words * sizeof(u32));
}

void hda_dsp_dump(struct snd_sof_dev *sdev, u32 flags)
{
	struct sof_ipc_dsp_oops_xtensa xoops;
	u32 stack[HDA_DSP_STACK_DUMP_SIZE];
	u32 status, panic;

	/* try APL specific status message types first */
	hda_dsp_get_status(sdev);

	/* now try generic SOF status messages */
	status = snd_sof_dsp_read(sdev, HDA_DSP_BAR,
				  HDA_DSP_SRAM_REG_FW_STATUS);
	panic = snd_sof_dsp_read(sdev, HDA_DSP_BAR, HDA_DSP_SRAM_REG_FW_TRACEP);

	if (sdev->boot_complete) {
		hda_dsp_get_registers(sdev, &xoops, stack,
				      HDA_DSP_STACK_DUMP_SIZE);
		snd_sof_get_status(sdev, status, panic, &xoops, stack,
				   HDA_DSP_STACK_DUMP_SIZE);
	} else {
		dev_err(sdev->dev, "error: status = 0x%8.8x panic = 0x%8.8x\n",
			status, panic);
		hda_dsp_get_status(sdev);
	}
}

/*
 * IPC Mailbox IO
 */

void hda_dsp_mailbox_write(struct snd_sof_dev *sdev, u32 offset,
			   void *message, size_t bytes)
{
	void __iomem *dest = sdev->bar[sdev->mailbox_bar] + offset;

	memcpy_toio(dest, message, bytes);
}

void hda_dsp_mailbox_read(struct snd_sof_dev *sdev, u32 offset,
			  void *message, size_t bytes)
{
	void __iomem *src = sdev->bar[sdev->mailbox_bar] + offset;

	memcpy_fromio(message, src, bytes);
}

/*
 * Supported devices.
 */

static const struct sof_intel_dsp_desc chip_info[] = {
{
	/* Skylake */
	.id = 0x9d70,
	.cores_num = 2,
	.cores_mask = HDA_DSP_CORE_MASK(0) | HDA_DSP_CORE_MASK(1),
	.ipc_req = HDA_DSP_REG_HIPCI,
	.ipc_req_mask = HDA_DSP_REG_HIPCI_BUSY,
	.ipc_ack = HDA_DSP_REG_HIPCIE,
	.ipc_ack_mask = HDA_DSP_REG_HIPCIE_DONE,
	.ipc_ctl = HDA_DSP_REG_HIPCCTL,
	.ops = &sof_skl_ops,
},
{
	/* Kabylake */
	.id = 0x9d71,
	.cores_num = 2,
	.cores_mask = HDA_DSP_CORE_MASK(0) | HDA_DSP_CORE_MASK(1),
	.ipc_req = HDA_DSP_REG_HIPCI,
	.ipc_req_mask = HDA_DSP_REG_HIPCI_BUSY,
	.ipc_ack = HDA_DSP_REG_HIPCIE,
	.ipc_ack_mask = HDA_DSP_REG_HIPCIE_DONE,
	.ipc_ctl = HDA_DSP_REG_HIPCCTL,
	.ops = &sof_skl_ops,
},
{
	/* Apollolake - BXT-P */
	.id = 0x5a98,
	.cores_num = 2,
	.cores_mask = HDA_DSP_CORE_MASK(0) | HDA_DSP_CORE_MASK(1),
	.ipc_req = HDA_DSP_REG_HIPCI,
	.ipc_req_mask = HDA_DSP_REG_HIPCI_BUSY,
	.ipc_ack = HDA_DSP_REG_HIPCIE,
	.ipc_ack_mask = HDA_DSP_REG_HIPCIE_DONE,
	.ipc_ctl = HDA_DSP_REG_HIPCCTL,
	.ops = &sof_apl_ops,
},
{
	/* BXT-M */
	.id = 0x1a98,
	.cores_num = 2,
	.cores_mask = HDA_DSP_CORE_MASK(0) | HDA_DSP_CORE_MASK(1),
	.ipc_req = HDA_DSP_REG_HIPCI,
	.ipc_req_mask = HDA_DSP_REG_HIPCI_BUSY,
	.ipc_ack = HDA_DSP_REG_HIPCIE,
	.ipc_ack_mask = HDA_DSP_REG_HIPCIE_DONE,
	.ipc_ctl = HDA_DSP_REG_HIPCCTL,
	.ops = &sof_apl_ops,
},
{
	/* GeminiLake */
	.id = 0x3198,
	.cores_num = 2,
	.cores_mask = HDA_DSP_CORE_MASK(0) | HDA_DSP_CORE_MASK(1),
	.ipc_req = HDA_DSP_REG_HIPCI,
	.ipc_req_mask = HDA_DSP_REG_HIPCI_BUSY,
	.ipc_ack = HDA_DSP_REG_HIPCIE,
	.ipc_ack_mask = HDA_DSP_REG_HIPCIE_DONE,
	.ipc_ctl = HDA_DSP_REG_HIPCCTL,
	.ops = &sof_apl_ops,
},
{
	/* Cannonlake */
	.id = 0x9dc8,
	.cores_num = 4,
	.cores_mask = HDA_DSP_CORE_MASK(0) |
				HDA_DSP_CORE_MASK(1) |
				HDA_DSP_CORE_MASK(2) |
				HDA_DSP_CORE_MASK(3),
	.ipc_req = CNL_DSP_REG_HIPCIDR,
	.ipc_req_mask = CNL_DSP_REG_HIPCIDR_BUSY,
	.ipc_ack = CNL_DSP_REG_HIPCIDA,
	.ipc_ack_mask = CNL_DSP_REG_HIPCIDA_DONE,
	.ipc_ctl = CNL_DSP_REG_HIPCCTL,
	.ops = &sof_cnl_ops,
},
};

static const struct sof_intel_dsp_desc *get_chip_info(int pci_id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(chip_info); i++) {
		if (chip_info[i].id == pci_id)
			return &chip_info[i];
	}

	return NULL;
}

/*
 * We don't need to do a full HDA codec probe as external HDA codec mode is
 * considered legacy and will not be supported under SOF. HDMI/DP HDA will
 * be supported in the DSP.
 */
int hda_dsp_probe(struct snd_sof_dev *sdev)
{
	struct pci_dev *pci = sdev->pci;
	struct sof_intel_hda_dev *hdev;
	struct sof_intel_hda_stream *stream;
	const struct sof_intel_dsp_desc *chip;
	int i;
	int ret = 0;

	chip = get_chip_info(pci->device);
	if (!chip) {
		dev_err(sdev->dev, "no such device supported, chip id:%x\n",
			pci->device);
		ret = -EIO;
		goto err;
	}

	hdev = devm_kzalloc(&pci->dev, sizeof(*hdev), GFP_KERNEL);
	if (!hdev)
		return -ENOMEM;
	sdev->hda = hdev;
	hdev->desc = chip;

	/* HDA base */
	sdev->bar[HDA_DSP_HDA_BAR] = pci_ioremap_bar(pci, HDA_DSP_HDA_BAR);
	if (!sdev->bar[HDA_DSP_HDA_BAR]) {
		dev_err(&pci->dev, "error: ioremap error\n");
		/*
		 * FIXME: why do we return directly,
		 *  should we have a goto err here?
		 *  or should all these gotos be replaced
		 * by a return?
		 */
		return -ENXIO;
	}

	/* DSP base */
	sdev->bar[HDA_DSP_BAR] = pci_ioremap_bar(pci, HDA_DSP_BAR);
	if (!sdev->bar[HDA_DSP_BAR]) {
		dev_err(&pci->dev, "error: ioremap error\n");
		ret = -ENXIO;
		goto err;
	}

	sdev->mmio_bar = HDA_DSP_BAR;
	sdev->mailbox_bar = HDA_DSP_BAR;

	pci_set_master(pci);
	synchronize_irq(pci->irq);

	/* allow 64bit DMA address if supported by H/W */
	if (!dma_set_mask(&pci->dev, DMA_BIT_MASK(64))) {
		dev_dbg(&pci->dev, "DMA mask is 64 bit\n");
		dma_set_coherent_mask(&pci->dev, DMA_BIT_MASK(64));
	} else {
		dev_dbg(&pci->dev, "DMA mask is 32 bit\n");
		dma_set_mask(&pci->dev, DMA_BIT_MASK(32));
		dma_set_coherent_mask(&pci->dev, DMA_BIT_MASK(32));
	}

	/* get controller capabilities */
	ret = hda_dsp_ctrl_get_caps(sdev);
	if (ret < 0) {
		dev_err(&pci->dev, "error: failed to find DSP capability\n");
		goto err;
	}

	/* init streams */
	ret = hda_dsp_stream_init(sdev);
	if (ret < 0) {
		dev_err(&pci->dev, "error: failed to init streams\n");
		/*
		 * not all errors are due to memory issues, but trying
		 * to free everything does not harm
		 */
		goto stream_err;
	}

	/*
	 * clear bits 0-2 of PCI register TCSEL (at offset 0x44)
	 * TCSEL == Traffic Class Select Register, which sets PCI express QOS
	 * Ensuring these bits are 0 clears playback static on some HD Audio
	 * codecs. PCI register TCSEL is defined in the Intel manuals.
	 */
	snd_sof_pci_update_bits(sdev, PCI_TCSEL, 0x07, 0);

	/*
	 * while performing reset, controller may not come back properly causing
	 * issues, so recommendation is to set CGCTL.MISCBDCGE to 0 then do
	 * reset (init chip) and then again set CGCTL.MISCBDCGE to 1
	 */
	snd_sof_pci_update_bits(sdev, PCI_CGCTL,
				PCI_CGCTL_MISCBDCGE_MASK, 0);

	/* clear WAKESTS */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_HDA_BAR, SOF_HDA_WAKESTS,
				SOF_HDA_WAKESTS_INT_MASK,
				SOF_HDA_WAKESTS_INT_MASK);

	/* reset HDA controller */
	ret = hda_dsp_ctrl_link_reset(sdev);
	if (ret < 0) {
		dev_err(&pci->dev, "error: failed to reset HDA controller\n");
		goto stream_err;
	}

	/* clear stream status */
	for (i = 0 ; i < hdev->num_capture ; i++) {
		stream = &hdev->cstream[i];
		if (stream)
			snd_sof_dsp_update_bits(sdev, HDA_DSP_HDA_BAR,
						stream->sd_offset +
						SOF_HDA_ADSP_REG_CL_SD_STS,
						SOF_HDA_CL_DMA_SD_INT_MASK,
						SOF_HDA_CL_DMA_SD_INT_MASK);
	}

	for (i = 0 ; i < hdev->num_playback ; i++) {
		stream = &hdev->pstream[i];
		if (stream)
			snd_sof_dsp_update_bits(sdev, HDA_DSP_HDA_BAR,
						stream->sd_offset +
						SOF_HDA_ADSP_REG_CL_SD_STS,
						SOF_HDA_CL_DMA_SD_INT_MASK,
						SOF_HDA_CL_DMA_SD_INT_MASK);
	}

	/* clear WAKESTS */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_HDA_BAR, SOF_HDA_WAKESTS,
				SOF_HDA_WAKESTS_INT_MASK,
				SOF_HDA_WAKESTS_INT_MASK);

	/* clear interrupt status register */
	snd_sof_dsp_write(sdev, HDA_DSP_HDA_BAR, SOF_HDA_INTSTS,
			  SOF_HDA_INT_CTRL_EN | SOF_HDA_INT_ALL_STREAM);

	/* enable CIE and GIE interrupts */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_HDA_BAR, SOF_HDA_INTCTL,
				SOF_HDA_INT_CTRL_EN | SOF_HDA_INT_GLOBAL_EN,
				SOF_HDA_INT_CTRL_EN | SOF_HDA_INT_GLOBAL_EN);

	dev_dbg(sdev->dev, "using PCI IRQ %d\n", pci->irq);

	/* register our IRQ */
	ret = request_threaded_irq(pci->irq, hda_dsp_stream_interrupt,
				   hda_dsp_stream_threaded_handler,
				    IRQF_SHARED, "AudioHDA", sdev);
	if (ret < 0) {
		dev_err(sdev->dev, "error: failed to register HDA IRQ %d\n",
			sdev->ipc_irq);
		goto stream_err;
	}
	sdev->hda->irq = pci->irq;

	sdev->ipc_irq = pci->irq;
	dev_dbg(sdev->dev, "using IPC IRQ %d\n", sdev->ipc_irq);
	ret = request_threaded_irq(sdev->ipc_irq, hda_dsp_ipc_irq_handler,
				   chip->ops->irq_thread, IRQF_SHARED,
				   "AudioDSP", sdev);
	if (ret < 0) {
		dev_err(sdev->dev, "error: failed to register IPC IRQ %d\n",
			sdev->ipc_irq);
		goto irq_err;
	}

	/* re-enable CGCTL.MISCBDCGE after reset */
	snd_sof_pci_update_bits(sdev, PCI_CGCTL,
				PCI_CGCTL_MISCBDCGE_MASK,
				PCI_CGCTL_MISCBDCGE_MASK);

	device_disable_async_suspend(&pci->dev);

	/* enable DSP features */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_PP_BAR, SOF_HDA_REG_PP_PPCTL,
				SOF_HDA_PPCTL_GPROCEN, SOF_HDA_PPCTL_GPROCEN);

	/* enable DSP IRQ */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_PP_BAR, SOF_HDA_REG_PP_PPCTL,
				SOF_HDA_PPCTL_PIE, SOF_HDA_PPCTL_PIE);

	/* initialize waitq for code loading */
	init_waitqueue_head(&sdev->waitq);

	/* set default mailbox offset for FW ready message */
	sdev->dsp_box.offset = HDA_DSP_MBOX_UPLINK_OFFSET;

	return 0;

irq_err:
	free_irq(pci->irq, sdev);
stream_err:
	hda_dsp_stream_free(sdev);
err:
	/* disable DSP */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_PP_BAR, SOF_HDA_REG_PP_PPCTL,
				SOF_HDA_PPCTL_GPROCEN, 0);
	return ret;
}

int hda_dsp_remove(struct snd_sof_dev *sdev)
{
	const struct sof_intel_dsp_desc *chip = sdev->hda->desc;

	/* disable DSP IRQ */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_PP_BAR, SOF_HDA_REG_PP_PPCTL,
				SOF_HDA_PPCTL_PIE, 0);

	/* disable CIE and GIE interrupts */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_HDA_BAR, SOF_HDA_INTCTL,
				SOF_HDA_INT_CTRL_EN | SOF_HDA_INT_GLOBAL_EN, 0);

	/* disable cores */
	if (chip)
		hda_dsp_core_reset_power_down(sdev, chip->cores_mask);

	/* disable DSP */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_PP_BAR, SOF_HDA_REG_PP_PPCTL,
				SOF_HDA_PPCTL_GPROCEN, 0);

	free_irq(sdev->ipc_irq, sdev);
	free_irq(sdev->pci->irq, sdev);

	hda_dsp_stream_free(sdev);
	return 0;
}

MODULE_LICENSE("Dual BSD/GPL");
