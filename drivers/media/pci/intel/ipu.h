/* SPDX-License_Identifier: GPL-2.0 */
/* Copyright (C) 2013 - 2018 Intel Corporation */

#ifndef IPU_H
#define IPU_H

#include <linux/ioport.h>
#include <linux/list.h>
#include <uapi/linux/media.h>

#include "ipu-pdata.h"
#include "ipu-bus.h"
#include "ipu-buttress.h"
#include "ipu-trace.h"

#if defined(CONFIG_VIDEO_INTEL_IPU4)
#define IPU_PCI_ID	0x5a88
#elif defined(CONFIG_VIDEO_INTEL_IPU4P)
#define IPU_PCI_ID	0x5a19
#endif

/* processing system frequency: 25Mhz x ratio, Legal values [8,32] */
#define PS_FREQ_CTL_DEFAULT_RATIO	0x12

/* input system frequency: 1600Mhz / divisor. Legal values [2,8] */
#define IS_FREQ_SOURCE			1600000000
#define IS_FREQ_CTL_DIVISOR		0x4

#define IPU_ISYS_NUM_STREAMS		8	/* Max 8 */

/*
 * ISYS DMA can overshoot. For higher resolutions over allocation is one line
 * but it must be at minimum 1024 bytes. Value could be different in
 * different versions / generations thus provide it via platform data.
 */
#define IPU_ISYS_OVERALLOC_MIN		1024

/*
 * Physical pages in GDA 128 * 1K pages.
 */
#define IPU_DEVICE_GDA_NR_PAGES		128

/*
 * Virtualization factor for Broxton to calculate the available virtual pages.
 * In IPU4, there is limitation of only 1024 virtual pages. Hence the
 * virtualization factor is 8 (128 * 8 = 1024).
 */
#define IPU_DEVICE_GDA_VIRT_FACTOR	8

struct pci_dev;
struct list_head;
struct firmware;

#define NR_OF_MMU_RESOURCES			2

struct ipu_device {
	struct pci_dev *pdev;
	struct list_head devices;
	struct ipu_bus_device *isys_iommu, *isys;
	struct ipu_bus_device *psys_iommu, *psys;
	struct ipu_buttress buttress;

	const struct firmware *cpd_fw;
	const char *cpd_fw_name;
	u64 *pkg_dir;
	dma_addr_t pkg_dir_dma_addr;
	unsigned int pkg_dir_size;

	void __iomem *base;
	void __iomem *base2;
	struct dentry *ipu_dir;
	struct ipu_trace *trace;
	bool flr_done;
	bool ipc_reinit;
	bool secure_mode;

	int (*isys_fw_reload)(struct ipu_device *isp);
	int (*cpd_fw_reload)(struct ipu_device *isp);
};

#define IPU_DMA_MASK	39
#define IPU_LIB_CALL_TIMEOUT_MS		2000
#define IPU_PSYS_CMD_TIMEOUT_MS	2000
#define IPU_PSYS_OPEN_TIMEOUT_US	   50
#define IPU_PSYS_OPEN_RETRY (10000 / IPU_PSYS_OPEN_TIMEOUT_US)

int ipu_fw_authenticate(void *data, u64 val);
void ipu_configure_spc(struct ipu_device *isp,
		       const struct ipu_hw_variants *hw_variant,
		       int pkg_dir_idx, void __iomem *base, u64 *pkg_dir,
		       dma_addr_t pkg_dir_dma_addr);
#endif /* IPU_H */
