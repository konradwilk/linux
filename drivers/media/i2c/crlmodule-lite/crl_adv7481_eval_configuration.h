/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0) */
/*
 * Copyright (C) 2018 Intel Corporation
 */

#ifndef __CRLMODULE_ADV7481_EVAL_CONFIGURATION_H_
#define __CRLMODULE_ADV7481_EVAL_CONFIGURATION_H_

#include "crlmodule-sensor-ds.h"

static const s64 adv7481_eval_op_sys_clock[] =  {400000000, };

struct crl_ctrl_data_pair ctrl_data_lanes[] = {
	{
		.ctrl_id = ICI_EXT_SD_PARAM_ID_MIPI_LANES,
		.data = 4,
	},
	{
		.ctrl_id = ICI_EXT_SD_PARAM_ID_MIPI_LANES,
		.data = 2,
	},
};
static struct crl_pll_configuration adv7481_eval_pll_configurations[] = {
	{
		.input_clk = 24000000,
		.op_sys_clk = 400000000,
		.bitsperpixel = 16,
		.pixel_rate_csi = 800000000,
		.pixel_rate_pa = 800000000,
		.comp_items = 0,
		.ctrl_data = 0,
		.pll_regs_items = 0,
		.pll_regs = NULL,
	 },
	 {
		.input_clk = 24000000,
		.op_sys_clk = 400000000,
		.bitsperpixel = 24,
		.pixel_rate_csi = 800000000,
		.pixel_rate_pa = 800000000,
		.comp_items = 0,
		.ctrl_data = 0,
		.pll_regs_items = 0,
		.pll_regs = NULL,
	 },
};

static struct crl_subdev_rect_rep adv7481_eval_1080p_rects[] = {
	{
		.subdev_type = CRL_SUBDEV_TYPE_PIXEL_ARRAY,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 1920,
		.out_rect.height = 1080,
	},
	{
		.subdev_type = CRL_SUBDEV_TYPE_BINNER,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 1920,
		.out_rect.height = 1080,
	},
};

static struct crl_subdev_rect_rep adv7481_eval_720p_rects[] = {
	{
		.subdev_type = CRL_SUBDEV_TYPE_PIXEL_ARRAY,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 1920,
		.out_rect.height = 1080,
	},
	{
		.subdev_type = CRL_SUBDEV_TYPE_BINNER,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 1280,
		.out_rect.height = 720,
	},
};

static struct crl_subdev_rect_rep adv7481_eval_VGA_rects[] = {
	{
		.subdev_type = CRL_SUBDEV_TYPE_PIXEL_ARRAY,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 1920,
		.out_rect.height = 1080,
	},
	{
		.subdev_type = CRL_SUBDEV_TYPE_BINNER,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 640,
		.out_rect.height = 480,
	},
};

static struct crl_subdev_rect_rep adv7481_eval_1080i_rects[] = {
	{
		.subdev_type = CRL_SUBDEV_TYPE_PIXEL_ARRAY,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 1920,
		.out_rect.height = 1080,
	},
	{
		.subdev_type = CRL_SUBDEV_TYPE_BINNER,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 1920,
		.out_rect.height = 540,
	},
};

static struct crl_subdev_rect_rep adv7481_eval_480i_rects[] = {
	{
		.subdev_type = CRL_SUBDEV_TYPE_PIXEL_ARRAY,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 1920,
		.out_rect.height = 1080,
	},
	{
		.subdev_type = CRL_SUBDEV_TYPE_BINNER,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 720,
		.out_rect.height = 240,
	},
};

static struct crl_subdev_rect_rep adv7481_eval_576p_rects[] = {
	{
		.subdev_type = CRL_SUBDEV_TYPE_PIXEL_ARRAY,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 1920,
		.out_rect.height = 1080,
	},
	{
		.subdev_type = CRL_SUBDEV_TYPE_BINNER,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 720,
		.out_rect.height = 576,
	},
};

static struct crl_subdev_rect_rep adv7481_eval_576i_rects[] = {
	{
		.subdev_type = CRL_SUBDEV_TYPE_PIXEL_ARRAY,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 1920,
		.out_rect.height = 1080,
	},
	{
		.subdev_type = CRL_SUBDEV_TYPE_BINNER,
		.in_rect.left = 0,
		.in_rect.top = 0,
		.in_rect.width = 1920,
		.in_rect.height = 1080,
		.out_rect.left = 0,
		.out_rect.top = 0,
		.out_rect.width = 720,
		.out_rect.height = 288,
	},
};
static struct crl_mode_rep adv7481_eval_modes[] = {
	{
		.sd_rects_items = ARRAY_SIZE(adv7481_eval_1080p_rects),
		.sd_rects = adv7481_eval_1080p_rects,
		.binn_hor = 1,
		.binn_vert = 1,
		.scale_m = 1,
		.width = 1920,
		.height = 1080,
		.comp_items = 1,
		.ctrl_data = &ctrl_data_lanes[0],
		.mode_regs_items = 0,
		.mode_regs = NULL,
	},
	{
		.sd_rects_items = ARRAY_SIZE(adv7481_eval_720p_rects),
		.sd_rects = adv7481_eval_720p_rects,
		.binn_hor = 1,
		.binn_vert = 1,
		.scale_m = 1,
		.width = 1280,
		.height = 720,
		.comp_items = 1,
		.ctrl_data = &ctrl_data_lanes[0],
		.mode_regs_items = 0,
		.mode_regs = NULL,
	},
	{
		.sd_rects_items = ARRAY_SIZE(adv7481_eval_VGA_rects),
		.sd_rects = adv7481_eval_VGA_rects,
		.binn_hor = 3,
		.binn_vert = 2,
		.scale_m = 1,
		.width = 640,
		.height = 480,
		.comp_items = 1,
		.ctrl_data = &ctrl_data_lanes[1],
		.mode_regs_items = 0,
		.mode_regs = NULL,
	},
	{
		.sd_rects_items = ARRAY_SIZE(adv7481_eval_1080i_rects),
		.sd_rects = adv7481_eval_1080i_rects,
		.binn_hor = 1,
		.binn_vert = 2,
		.scale_m = 1,
		.width = 1920,
		.height = 540,
		.comp_items = 1,
		.ctrl_data = &ctrl_data_lanes[1],
		.mode_regs_items = 0,
		.mode_regs = NULL,
	},
	{
		.sd_rects_items = ARRAY_SIZE(adv7481_eval_480i_rects),
		.sd_rects = adv7481_eval_480i_rects,
		.binn_hor = 2,
		.binn_vert = 4,
		.scale_m = 1,
		.width = 720,
		.height = 240,
		.comp_items = 1,
		.ctrl_data = &ctrl_data_lanes[1],
		.mode_regs_items = 0,
		.mode_regs = NULL,
	},
	{
		.sd_rects_items = ARRAY_SIZE(adv7481_eval_576p_rects),
		.sd_rects = adv7481_eval_576p_rects,
		.binn_hor = 2,
		.binn_vert = 1,
		.scale_m = 1,
		.width = 720,
		.height = 576,
		.comp_items = 1,
		.ctrl_data = &ctrl_data_lanes[1],
		.mode_regs_items = 0,
		.mode_regs = NULL,
	},
	{
		.sd_rects_items = ARRAY_SIZE(adv7481_eval_576i_rects),
		.sd_rects = adv7481_eval_576i_rects,
		.binn_hor = 2,
		.binn_vert = 3,
		.scale_m = 1,
		.width = 720,
		.height = 288,
		.comp_items = 1,
		.ctrl_data = &ctrl_data_lanes[1],
		.mode_regs_items = 0,
		.mode_regs = NULL,
	},
};

static struct crl_sensor_subdev_config adv7481_eval_sensor_subdevs[] = {
	{
		.subdev_type = CRL_SUBDEV_TYPE_BINNER,
		.name = "adv7481 binner",
	},
	{
		.subdev_type = CRL_SUBDEV_TYPE_PIXEL_ARRAY,
		.name = "adv7481 pixel array",
	},
};

static struct crl_sensor_subdev_config adv7481b_eval_sensor_subdevs[] = {
	{
		.subdev_type = CRL_SUBDEV_TYPE_BINNER,
		.name = "adv7481b binner",
	},
	{
		.subdev_type = CRL_SUBDEV_TYPE_PIXEL_ARRAY,
		.name = "adv7481b pixel array",
	},
};

static struct crl_sensor_limits adv7481_eval_sensor_limits = {
	.x_addr_min = 0,
	.y_addr_min = 0,
	.x_addr_max = 1920,
	.y_addr_max = 1080,
	.min_frame_length_lines = 160,
	.max_frame_length_lines = 65535,
	.min_line_length_pixels = 6024,
	.max_line_length_pixels = 32752,
	.scaler_m_min = 1,
	.scaler_m_max = 1,
	.scaler_n_min = 1,
	.scaler_n_max = 1,
	.min_even_inc = 1,
	.max_even_inc = 1,
	.min_odd_inc = 1,
	.max_odd_inc = 1,
};

static struct crl_csi_data_fmt adv7481_eval_crl_csi_data_fmt[] = {
	{
		.code = ICI_FORMAT_YUYV,
		.pixel_order = CRL_PIXEL_ORDER_GRBG,
		.bits_per_pixel = 16,
		.regs_items = 0,
		.regs = NULL,
	},
	{
		.code = ICI_FORMAT_UYVY,
		.pixel_order = CRL_PIXEL_ORDER_GRBG,
		.bits_per_pixel = 16,
		.regs_items = 0,
		.regs = NULL,
	},
	{
		.code = ICI_FORMAT_RGB565,
		.pixel_order = CRL_PIXEL_ORDER_GRBG,
		.bits_per_pixel = 16,
		.regs_items = 0,
		.regs = NULL,
	},
	{
		.code = ICI_FORMAT_RGB888,
		.pixel_order = CRL_PIXEL_ORDER_GRBG,
		.bits_per_pixel = 24,
		.regs_items = 0,
		.regs = NULL,
	},
};

static struct crl_ctrl_data adv7481_eval_ctrls[] = {
	{
		.sd_type = CRL_SUBDEV_TYPE_BINNER,
		.op_type = CRL_CTRL_SET_OP,
		.context = SENSOR_IDLE,
		.ctrl_id = ICI_EXT_SD_PARAM_ID_LINK_FREQ,
		.name = "CTRL_ID_LINK_FREQ",
		.type = CRL_CTRL_TYPE_MENU_INT,
		.data.int_menu.def = 0,
		.data.int_menu.max = ARRAY_SIZE(adv7481_eval_pll_configurations) - 1,
		.data.int_menu.menu = adv7481_eval_op_sys_clock,
		.flags = 0,
		.impact = CRL_IMPACTS_NO_IMPACT,
		.regs_items = 0,
		.regs = 0,
		.dep_items = 0,
		.dep_ctrls = 0,
	},
	{
		.sd_type = CRL_SUBDEV_TYPE_PIXEL_ARRAY,
		.op_type = CRL_CTRL_GET_OP,
		.context = SENSOR_POWERED_ON,
		.ctrl_id = ICI_EXT_SD_PARAM_ID_PIXEL_RATE,
		.name = "CTRL_ID_PIXEL_RATE_PA",
		.type = CRL_CTRL_TYPE_INTEGER,
		.data.std_data.min = 0,
		.data.std_data.max = 0,
		.data.std_data.step = 1,
		.data.std_data.def = 0,
		.flags = 0,
		.impact = CRL_IMPACTS_NO_IMPACT,
		.regs_items = 0,
		.regs = 0,
		.dep_items = 0,
		.dep_ctrls = 0,
	},
	{
		.sd_type = CRL_SUBDEV_TYPE_BINNER,
		.op_type = CRL_CTRL_GET_OP,
		.context = SENSOR_POWERED_ON,
		.ctrl_id = ICI_EXT_SD_PARAM_ID_PIXEL_RATE,
		.name = "CTRL_ID_PIXEL_RATE_CSI",
		.type = CRL_CTRL_TYPE_INTEGER,
		.data.std_data.min = 0,
		.data.std_data.max = 0,
		.data.std_data.step = 1,
		.data.std_data.def = 0,
		.flags = 0,
		.impact = CRL_IMPACTS_NO_IMPACT,
		.regs_items = 0,
		.regs = 0,
		.dep_items = 0,
		.dep_ctrls = 0,
	},
	{
		.sd_type = CRL_SUBDEV_TYPE_BINNER,
		.op_type = CRL_CTRL_GET_OP,
		.context = SENSOR_POWERED_ON,
		.ctrl_id = ICI_EXT_SD_PARAM_ID_MIPI_LANES,
		.name = "CTRL_ID_MIPI_LANES",
		.type = CRL_CTRL_TYPE_CUSTOM,
		.data.std_data.min = 2,
		.data.std_data.max = 4,
		.data.std_data.step = 2,
		.data.std_data.def = 4,
		.flags = 0,
		.impact = CRL_IMPACTS_NO_IMPACT,
		.regs_items = 0,
		.regs = 0,
		.dep_items = 0,
		.dep_ctrls = 0,
		.param.type = ICI_EXT_SD_PARAM_TYPE_INT32,
	},
};

static struct crl_sensor_configuration adv7481_eval_crl_configuration = {

	.powerup_regs_items = 0,
	.powerup_regs = NULL,

	.poweroff_regs_items = 0,
	.poweroff_regs = NULL,

	.id_reg_items = 0,
	.id_regs = NULL,

	.subdev_items = 0,
	.subdevs = adv7481_eval_sensor_subdevs,

	.sensor_limits = &adv7481_eval_sensor_limits,

	.pll_config_items = ARRAY_SIZE(adv7481_eval_pll_configurations),
	.pll_configs = adv7481_eval_pll_configurations,
	.op_sys_clk = adv7481_eval_op_sys_clock,

	.modes_items = ARRAY_SIZE(adv7481_eval_modes),
	.modes = adv7481_eval_modes,

	.streamon_regs_items = 0,
	.streamon_regs = NULL,

	.streamoff_regs_items = 0,
	.streamoff_regs = NULL,

	.ctrl_items = ARRAY_SIZE(adv7481_eval_ctrls),
	.ctrl_bank = adv7481_eval_ctrls,

	.csi_fmts_items = ARRAY_SIZE(adv7481_eval_crl_csi_data_fmt),
	.csi_fmts = adv7481_eval_crl_csi_data_fmt,
};

static struct crl_sensor_configuration adv7481b_eval_crl_configuration = {

	.powerup_regs_items = 0,
	.powerup_regs = NULL,

	.poweroff_regs_items = 0,
	.poweroff_regs = NULL,

	.id_reg_items = 0,
	.id_regs = NULL,

	.subdev_items = 0,
	.subdevs = adv7481b_eval_sensor_subdevs,

	.sensor_limits = &adv7481_eval_sensor_limits,

	.pll_config_items = ARRAY_SIZE(adv7481_eval_pll_configurations),
	.pll_configs = adv7481_eval_pll_configurations,
	.op_sys_clk = adv7481_eval_op_sys_clock,

	.modes_items = ARRAY_SIZE(adv7481_eval_modes),
	.modes = adv7481_eval_modes,

	.streamon_regs_items = 0,
	.streamon_regs = NULL,

	.streamoff_regs_items = 0,
	.streamoff_regs = NULL,

	.ctrl_items = ARRAY_SIZE(adv7481_eval_ctrls),
	.ctrl_bank = adv7481_eval_ctrls,

	.csi_fmts_items = ARRAY_SIZE(adv7481_eval_crl_csi_data_fmt),
	.csi_fmts = adv7481_eval_crl_csi_data_fmt,
};

#endif  /* __CRLMODULE_ADV7481_EVAL_CONFIGURATION_H_ */
