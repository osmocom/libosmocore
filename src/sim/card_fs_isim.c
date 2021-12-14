/*! \file card_fs_isim.c
 * 3GPP ISIM specific structures / routines. */
/*
 * (C) 2014-2020 by Harald Welte <laforge@gnumonks.org>
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

/* TS 31.103 Version 15.5.0 Release 15 / Chapter 7.1.3 */
const struct osim_card_sw ts31_103_sw[] = {
	{
		0x9862, 0xffff, SW_TYPE_STR, SW_CLS_ERROR,
		.u.str = "Security management - Authentication error, incorrect MAC",
	}, {
		0x9864, 0xffff, SW_TYPE_STR, SW_CLS_ERROR,
		.u.str = "Security management - Authentication error, security context not supported",
	},
	OSIM_CARD_SW_LAST
};

/* TS 31.103 Version 15.5.0 Release 15 / Chapter 4.2 */
static const struct osim_file_desc isim_ef_in_adf_isim[] = {
	EF_TRANSP_N(0x6F02, 0x02, "EF.IMPI", 0, 1, 256,
		"IMS private user identity"),
	EF_TRANSP_N(0x6F03, 0x05, "EF.DOMAIN", 0, 1, 256,
		"Home Network Domain Name"),
	EF_LIN_FIX_N(0x6F04, 0x04, "EF.IMPU", 0, 1, 256,
		"IMS public user identity"),
	EF_TRANSP_N(0x6FAD, 0x03, "EF.AD", 0, 4, 16,
		"Administrative Data"),
	EF_LIN_FIX_N(0x6F06, 0x06, "EF.ARR", 0, 1, 256,
		"Access Rule TLV data objects"),
	EF_TRANSP_N(0x6F07, 0x07, "EF.IST", F_OPTIONAL, 1, 16,
		"ISIM Service Table"),
	EF_LIN_FIX_N(0x6F09, SFI_NONE, "EF.P-CSCF", F_OPTIONAL, 1, 256,
		"P-CSCF Address"),
	EF_TRANSP_N(0x6FD5, SFI_NONE, "EF.GBABP", F_OPTIONAL, 1, 35,
		"GBA Bootstrapping parameters"),
	EF_LIN_FIX_N(0x6FD7, SFI_NONE, "EF.GBANL", F_OPTIONAL, 1, 256,
		"NAF Key Identifier TLV Objects"),
	EF_LIN_FIX_N(0x6FDD, SFI_NONE, "EF.NAFKCA", F_OPTIONAL, 1, 256,
		"NAF Key Centre Address"),
	EF_LIN_FIX_N(0x6F3C, SFI_NONE, "EF.SMS", F_OPTIONAL, 176, 176,
		"Short messages"),
	EF_TRANSP_N(0x6F43, SFI_NONE, "EF.SMSS", F_OPTIONAL, 2, 4,
		"SMS status"),
	EF_LIN_FIX_N(0x6F47, SFI_NONE, "EF.SMSR", F_OPTIONAL, 30, 30,
		"Short message status reports"),
	EF_LIN_FIX_N(0x6F42, SFI_NONE, "EF.SMSP", F_OPTIONAL, 29, 64,
		"Short message service parameters"),
	EF_LIN_FIX_N(0x6FE7, SFI_NONE, "EF.UICCIARI", F_OPTIONAL, 1, 256,
		"UICC IARI"),
	EF_TRANSP_N(0x6FF7, SFI_NONE, "EF_FromPreferred", F_OPTIONAL, 1, 1,
		"From Preferred"),
	EF_TRANSP_N(0x6FF8, SFI_NONE, "EF_IMSConfigData", F_OPTIONAL, 3, 128,
		"IMS Configuration Data"),
	EF_TRANSP_N(0x6FFC, SFI_NONE, "EF_XCAPConfigData", F_OPTIONAL, 1, 128,
		"XCAP Configuration Data"),
	EF_LIN_FIX_N(0x6FFA, SFI_NONE, "EF_WebRTCURI", F_OPTIONAL, 3, 128,
		"WebRTC URI"),
};

/* Annex E - TS 101 220 */
static const uint8_t adf_isim_aid[] = { 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04 };

struct osim_card_app_profile *osim_aprof_isim(void *ctx)
{
	struct osim_card_app_profile *aprof;
	struct osim_file_desc *iadf;

	aprof = talloc_zero(ctx, struct osim_card_app_profile);
	aprof->name = "3GPP ISIM";
	aprof->sw = ts31_103_sw;
	aprof->aid_len = sizeof(adf_isim_aid);
	memcpy(aprof->aid, adf_isim_aid, aprof->aid_len);

	/* ADF.USIM with its EF siblings */
	iadf = alloc_adf_with_ef(aprof, adf_isim_aid, sizeof(adf_isim_aid), "ADF.ISIM",
				 isim_ef_in_adf_isim, ARRAY_SIZE(isim_ef_in_adf_isim));
	aprof->adf = iadf;

	return aprof;
}
