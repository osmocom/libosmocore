/*! \file card_fs_hpsim.c
 * 3GPP HPSIM specific structures / routines. */
/*
 * (C) 2020 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */


#include <errno.h>
#include <string.h>

#include <osmocom/sim/sim.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/gsm48.h>

#include "sim_int.h"
#include "gsm_int.h"

/* TS 31.104 Version 15.0.0 Release 15 / Chapter 7.1.3 */
const struct osim_card_sw ts31_104_sw[] = {
	{
		0x9862, 0xffff, SW_TYPE_STR, SW_CLS_ERROR,
		.u.str = "Security management - Authentication error, incorrect MAC",
	},
	OSIM_CARD_SW_LAST
};

/* TS 31.104 Version 15.0.0 Release 15 / Chapter 4.2 */
static const struct osim_file_desc hpsim_ef_in_adf_hpsim[] = {
	EF_LIN_FIX_N(0x6F06, 0x06, "EF.ARR", 0, 1, 256,
		"Access Rule TLV data objects"),
	EF_TRANSP_N(0x6F07, 0x07, "EF.IMST", 0, 9, 9,
		"IMSI"),
	EF_TRANSP_N(0x6FAD, 0x03, "EF_AD", 0, 4, 8,
		"Administrative Data"),
};

/* Annex E - TS 101 220 */
static const uint8_t adf_hpsim_aid[] = { 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x0A };

struct osim_card_app_profile *osim_aprof_hpsim(void *ctx)
{
	struct osim_card_app_profile *aprof;
	struct osim_file_desc *iadf;

	aprof = talloc_zero(ctx, struct osim_card_app_profile);
	aprof->name = "3GPP HPSIM";
	aprof->sw = ts31_104_sw;
	aprof->aid_len = sizeof(adf_hpsim_aid);
	memcpy(aprof->aid, adf_hpsim_aid, aprof->aid_len);

	/* ADF.HPSIM with its EF siblings */
	iadf = alloc_adf_with_ef(aprof, adf_hpsim_aid, sizeof(adf_hpsim_aid), "ADF.HPSIM",
				 hpsim_ef_in_adf_hpsim, ARRAY_SIZE(hpsim_ef_in_adf_hpsim));
	aprof->adf = iadf;

	return aprof;
}
