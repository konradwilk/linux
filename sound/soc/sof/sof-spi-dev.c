// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * Copyright(c) 2017 Intel Corporation. All rights reserved.
 *
 * Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/platform_device.h>
#include <linux/firmware.h>
#include <sound/pcm.h>
#include <sound/sof.h>
#include <linux/spi/spi.h>
#include <linux/of_device.h>
#include "sof-priv.h"

struct sof_spi_priv {
	struct snd_sof_pdata *sof_pdata;
	struct platform_device *pdev_pcm;
};

static void sof_spi_fw_cb(const struct firmware *fw, void *context)
{
	struct sof_spi_priv *priv = context;
	struct snd_sof_pdata *sof_pdata = priv->sof_pdata;
	const struct snd_sof_machine *mach = sof_pdata->machine;
	struct device *dev = sof_pdata->dev;

	sof_pdata->fw = fw;
	if (!fw) {
		dev_err(dev, "Cannot load firmware %s\n",
			mach->sof_fw_filename);
		return;
	}

	/* register PCM and DAI driver */
	priv->pdev_pcm =
		platform_device_register_data(dev, "sof-audio", -1,
					      sof_pdata, sizeof(*sof_pdata));
	if (IS_ERR(priv->pdev_pcm)) {
		dev_err(dev, "Cannot register device sof-audio. Error %d\n",
			(int)PTR_ERR(priv->pdev_pcm));
	}
}

static const struct dev_pm_ops sof_spi_pm = {
	SET_SYSTEM_SLEEP_PM_OPS(snd_sof_suspend, snd_sof_resume)
	SET_RUNTIME_PM_OPS(snd_sof_runtime_suspend, snd_sof_runtime_resume,
			   NULL)
	.suspend_late = snd_sof_suspend_late,
};

static int sof_spi_probe(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	const struct snd_sof_machine *mach;
	struct snd_sof_machine *m;
	struct snd_sof_pdata *sof_pdata;
	struct sof_spi_priv *priv;
	int ret = 0;

	dev_dbg(&spi->dev, "SPI DSP detected");

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	spi_set_drvdata(spi, priv);

	sof_pdata = devm_kzalloc(dev, sizeof(*sof_pdata), GFP_KERNEL);
	if (!sof_pdata)
		return -ENOMEM;

	/* use nocodec machine atm */
	dev_err(dev, "No matching ASoC machine driver found - using nocodec\n");
	sof_pdata->drv_name = "sof-nocodec";
	m = devm_kzalloc(dev, sizeof(*mach), GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	m->drv_name = "sof-nocodec";
	m->sof_fw_filename = desc->nocodec_fw_filename;
	m->sof_tplg_filename = desc->nocodec_tplg_filename;
	m->ops = desc->machines[0].ops;
	m->asoc_plat_name = "sof-platform";
	mach = m;

	sof_pdata->id = pci_id->device;
	sof_pdata->name = spi_name(spi);
	sof_pdata->machine = mach;
	sof_pdata->desc = (struct sof_dev_desc *)pci_id->driver_data;
	priv->sof_pdata = sof_pdata;
	sof_pdata->spi = spi;
	sof_pdata->dev = dev;

	/* register machine driver */
	sof_pdata->pdev_mach =
		platform_device_register_data(dev, mach->drv_name, -1,
					      sof_pdata, sizeof(*sof_pdata));
	if (IS_ERR(sof_pdata->pdev_mach))
		return PTR_ERR(sof_pdata->pdev_mach);
	dev_dbg(dev, "created machine %s\n",
		dev_name(&sof_pdata->pdev_mach->dev));

	/* continue probing after firmware is loaded */
	ret = request_firmware_nowait(THIS_MODULE, true, mach->sof_fw_filename,
				      dev, GFP_KERNEL, priv, sof_spi_fw_cb);
	if (ret)
		platform_device_unregister(sof_pdata->pdev_mach);

	return ret;
}

static int sof_spi_remove(struct spi_device *spi)
{
	struct sof_spi_priv *priv = spi_get_drvdata(spi);
	struct snd_sof_pdata *sof_pdata = priv->sof_pdata;

	platform_device_unregister(sof_pdata->pdev_mach);
	if (!IS_ERR_OR_NULL(priv->pdev_pcm))
		platform_device_unregister(priv->pdev_pcm);
	release_firmware(sof_pdata->fw);
}

static struct spi_driver wm8731_spi_driver = {
	.driver = {
		.name	= "sof-spi-dev",
		.of_match_table = sof_of_match,
	},
	.probe		= sof_spi_probe,
	.remove		= sof_spi_remove,
};

static const struct snd_sof_machine sof_spi_machines[] = {
	{ "INT343A", "bxt_alc298s_i2s", "intel/sof-spi.ri",
		"intel/sof-spi.tplg", "0000:00:0e.0", &snd_sof_spi_ops },
};

static const struct sof_dev_desc spi_desc = {
	.machines		= sof_spi_machines,
	.nocodec_fw_filename = "intel/sof-spi.ri",
	.nocodec_tplg_filename = "intel/sof-spi.tplg"
};

static int __init sof_spi_modinit(void)
{
	int ret;

	ret = spi_register_driver(&sof_spi_driver);
	if (ret != 0)
		pr_err("Failed to register SOF SPI driver: %d\n", ret);

	return ret;
}
module_init(sof_spi_modinit);

static void __exit sof_spi_modexit(void)
{
	spi_unregister_driver(&sof_spi_driver);
}
module_exit(sof_spi_modexit);

MODULE_LICENSE("Dual BSD/GPL");
