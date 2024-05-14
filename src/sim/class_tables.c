/*! \file class_tables.c
 * simtrace - tables determining APDU case for card emulation. */
/*
 * (C) 2016 by Harald Welte <laforge@gnumonks.org>
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2, or
 *  any later version as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#include <stdint.h>
#include <osmocom/core/utils.h>
#include <osmocom/sim/class_tables.h>

/* Quick reminder about the "cases" as per ISO7816-3 / ETSI TS 102 221 Section 7.3.1.1
 *
 * Case 1: Command Length 0, Response Length 0
 * Case 2: Command Length 0, Response Length from P3
 * Case 3: Command Length P3, Response Length 0
 * Case 4: Command Length P3, followed by 61xx for response length + GET RESPONSE
 */

static const uint8_t iso7816_ins_tbl[256] = {
	[0xB0]	= 2,	/* READ BIN */
	[0xD0]	= 3,	/* WRITE BIN */
	[0xD6]	= 3,	/* UPDATE BIN */
	[0x0E]	= 3,	/* ERASE BIN */
	[0xB2]	= 2,	/* READ REC */
	[0xD2]	= 3,	/* WRITE REC */
	[0xE2]	= 3,	/* APPEND REC */
	[0xDC]	= 3,	/* UPDATE REC */
	[0xCA]	= 2,	/* GET DATA */
	[0xDA]	= 3,	/* PUT DATA */
	[0xA4]	= 4,	/* SELECT FILE */
	[0x20]	= 3,	/* VERIFY */
	[0x88]	= 4,	/* INT AUTH */
	[0x82]	= 3,	/* EXT AUTH */
	[0x84]	= 2,	/* GET CHALLENGE */
	[0x70]	= 2,	/* MANAGE CHANNEL */
};

static const struct osim_cla_ins_case iso7816_4_ins_case[] = {
	{
		.cla		= 0x00,
		.cla_mask	= 0xF0,
		.ins_tbl	= iso7816_ins_tbl,
	}, {
		.cla		= 0x80,	/* 0x80/0x90 */
		.cla_mask	= 0xE0,
		.ins_tbl	= iso7816_ins_tbl,
	}, {
		.cla		= 0xB0,
		.cla_mask	= 0xF0,
		.ins_tbl	= iso7816_ins_tbl,
	}, {
		.cla		= 0xC0,
		.cla_mask	= 0xF0,
		.ins_tbl	= iso7816_ins_tbl,
	},
};

const struct osim_cla_ins_card_profile osim_iso7816_cic_profile = {
	.name		= "ISO 7816-4",
	.description	= "ISO 7816-4",
	.cic_arr	= iso7816_4_ins_case,
	.cic_arr_size	= ARRAY_SIZE(iso7816_4_ins_case),
};

static const uint8_t gsm1111_ins_tbl[256] = {
	[0xA4]	= 4,	/* SELECT FILE */
	[0xF2]	= 2,	/* STATUS */
	[0xB0]	= 2,	/* READ BINARY */
	[0xD6]	= 3,	/* UPDATE BINARY */
	[0xB2]	= 2,	/* READ RECORD */
	[0xDC]	= 3,	/* UPDATE RECORD */
	[0xA2]	= 4,	/* SEEK */
	[0x32]	= 4,	/* INCREASE */
	[0x20]	= 3,	/* VERIFY CHV */
	[0x24]	= 3,	/* CHANGE CHV */
	[0x26]	= 3,	/* DISABLE CHV */
	[0x28]	= 3,	/* ENABLE CHV */
	[0x2C]	= 3,	/* UNBLOCK CHV */
	[0x04]	= 1,	/* INVALIDATE */
	[0x44]	= 1,	/* REHABILITATE */
	[0x88]	= 4,	/* RUN GSM ALGO */
	[0xFA]	= 1,	/* SLEEP */
	[0xC0]	= 2,	/* GET RESPONSE */
	[0x10]	= 3,	/* TERMINAL PROFILE */
	[0xC2]	= 4,	/* ENVELOPE */
	[0x12]	= 2,	/* FETCH */
	[0x14]	= 3,	/* TERMINAL RESPONSE */
};

/* According to Table 9 / Section 9.2 of TS 11.11 */
static const struct osim_cla_ins_case gsm1111_ins_case[] = {
	{
		.cla		= 0xA0,
		.cla_mask	= 0xFF,
		.ins_tbl	= gsm1111_ins_tbl,
	},
};

const struct osim_cla_ins_card_profile osim_gsm1111_cic_profile = {
	.name		= "GSM SIM",
	.description	= "GSM/3GPP TS 11.11",
	.cic_arr	= gsm1111_ins_case,
	.cic_arr_size	= ARRAY_SIZE(gsm1111_ins_case),
};

/* ETSI TS 102 221, Table 10.5, CLA = 0x0x, 0x4x or 0x6x */
static const uint8_t uicc_ins_tbl_046[256] = {
	[0xA4]	= 4,	/* SELECT FILE */
	[0xB0]	= 2,	/* READ BINARY */
	[0xD6]	= 3,	/* UPDATE BINARY */
	[0xB2]	= 2,	/* READ RECORD */
	[0xDC]	= 3,	/* UPDATE RECORD */
	[0xA2]	= 4,	/* SEARCH RECORD */
	[0x20]	= 3,	/* VERIFY PIN */
	[0x24]	= 3,	/* CHANGE PIN */
	[0x26]	= 3,	/* DISABLE PIN */
	[0x28]	= 3,	/* ENABLE PIN */
	[0x2C]	= 3,	/* UNBLOCK PIN */
	[0x04]	= 1,	/* DEACTIVATE FILE */
	[0x44]	= 1,	/* ACTIVATE FILE */
	[0x88]	= 4,	/* AUTHENTICATE */
	[0x89]	= 4,	/* AUTHENTICATE */
	[0x84]	= 2,	/* GET CHALLENGE */
	[0x70]	= 2,	/* MANAGE CHANNEL */
	[0x73]	= 0x80,	/* MANAGE SECURE CHANNEL */
	[0x75]	= 0x80,	/* TRANSACT DATA */
	[0xC0]	= 2,	/* GET RESPONSE */
};

static int uicc046_cla_ins_helper(const struct osim_cla_ins_case *cic,
				  const uint8_t *hdr)
{
	uint8_t ins = hdr[1];
	uint8_t p1 = hdr[2];
	uint8_t p2 = hdr[3];
	uint8_t p2_cmd;

	switch (ins) {
	case 0x73:	/* MANAGE SECURE CHANNEL */
		if (p1 == 0x00)		/* Retrieve UICC Endpoints */
			return 2;
		switch (p1 & 0x07) {
		case 1:	/* Establish SA - Master SA */
		case 2:	/* Establish SA - Conn. SA */
		case 3:	/* Start secure channel SA */
			p2_cmd = p2 >> 5;
			if (p2 == 0x80 || p2_cmd == 0) {
				/* command data */
				return 3;
			}
			if (p2_cmd == 5 || p2_cmd == 1) {
				/* response data */
				return 2;
			}
			return 0;
			break;
		case 4:	/* Terminate secure chan SA */
			return 3;
			break;
		}
		break;
	case 0x75:	/* TRANSACT DATA */
		if (p1 & 0x04)
			return 3;
		else
			return 2;
		break;
	}

	return 0;
}

static int gp_cla_ins_helper(const struct osim_cla_ins_case *cic,
				  const uint8_t *hdr)
{
	uint8_t ins = hdr[1];
	uint8_t p1 = hdr[2];
	uint8_t p3 = hdr[4];

	switch (ins) {
	case 0xE2:	/* STORE DATA */
		switch (p1 & 0x01) {
		case 1:
			return 4;
		default:
			return 3;
		}
		break;
	case 0xF2:
		/* in their infinite wisdom, GlobalPlatform re-defined the CLA 8x / INS F2 command, so one can
		 * take a guess if it's GlobalPlatform or ETSI.  Lucikly, the P1 coding of ETSI [so far]
		 * states all the four upper bits must be 0, while GP always has one of those bits set */
		if (p1 & 0xF0)
			return 4; /* GlobalPlatform v2.2 11.4.2 */
		else
			return 2; /* ETSI TS 102 221 V16.2.0 11.1.2 */
		break;
	case 0xCA:
	case 0xCB:
		/* in their infinite wisdom, GlobalPlatform made GET DATA a command that can be either APDU
		 * case 2 or case 4.  As the specify Le must be 0x00, we can conclude that P3 == 0x00 must be
		 * Le, while P3 != 0x00 must be Lc and hence case 4 */
		if (p3 == 0x00)
			return 2;
		else
			return 4;
		break;
	}
	return 0;
}

/* ETSI TS 102 221, Table 10.5, CLA = 0x8x, 0xCx or 0xEx */
static const uint8_t uicc_ins_tbl_8ce[256] = {
	[0xF2]		= 2,	/* STATUS */
	[0x32]		= 4,	/* INCREASE */
	[0xCB]		= 4,	/* RETRIEVE DATA */
	[0xDB]		= 3,	/* SET DATA */
	[0xAA]		= 3,	/* TERMINAL CAPABILITY */
	[0x78]		= 4,	/* GET IDENTITY */
};

/* ETSI TS 102 221, Table 10.5, CLA = 0x80 */
static const uint8_t uicc_ins_tbl_80[256] = {
	[0x10]		= 3,	/* TERMINAL PROFILE */
	[0xC2]		= 4,	/* ENVELOPE */
	[0x12]		= 2,	/* FETCH */
	[0x14]		= 3,	/* TERMINAL RESPONSE */
	[0x76]		= 4,	/* SUSPEND UICC */
	[0x7A]		= 4,	/* EXCHANGE CAPABILITIES */
};

/* Card Specification v2.3.1*/
static const uint8_t gp_ins_tbl_8ce[256] = {
	[0xE4]		= 4,	/* DELETE */
	[0xE2]		= 0x80,	/* STORE DATA */
	[0xCA]		= 0x80,	/* GET DATA */
	[0xCB]		= 0x80,	/* GET DATA */
	[0xF2]		= 0x80,	/* GET STATUS */
	[0xE6]		= 4,	/* INSTALL */
	[0xE8]		= 4,	/* LOAD */
	[0xD8]		= 4,	/* PUT KEY */
	[0xF0]		= 3,	/* SET STATUS */
	[0xC0]		= 2,	/* GET RESPONSE */
};

static const struct osim_cla_ins_case uicc_ins_case[] = {
	{
		.cla		= 0x80,
		.cla_mask	= 0xFF,
		.ins_tbl	= uicc_ins_tbl_80,
	}, {
		.cla		= 0x00,
		.cla_mask	= 0xF0,
		.helper		= uicc046_cla_ins_helper,
		.ins_tbl	= uicc_ins_tbl_046,
	}, {
		.cla		= 0x40,
		.cla_mask	= 0xF0,
		.helper		= uicc046_cla_ins_helper,
		.ins_tbl	= uicc_ins_tbl_046,
	}, {
		.cla		= 0x60,
		.cla_mask	= 0xF0,
		.helper		= uicc046_cla_ins_helper,
		.ins_tbl	= uicc_ins_tbl_046,
	}, {
		/* must be before uicc_ins_tbl_8ce below with same CLA+mask */
		.cla		= 0x80,
		.cla_mask	= 0xF0,
		.helper		= gp_cla_ins_helper,
		.ins_tbl	= gp_ins_tbl_8ce,
	}, {
		.cla		= 0x80,
		.cla_mask	= 0xF0,
		.ins_tbl	= uicc_ins_tbl_8ce,
	}, {
		.cla		= 0xC0,
		.cla_mask	= 0xF0,
		.ins_tbl	= uicc_ins_tbl_8ce,
	}, {
		.cla		= 0xE0,
		.cla_mask	= 0xF0,
		.ins_tbl	= uicc_ins_tbl_8ce,
	}, {
		.cla		= 0xC0,
		.cla_mask	= 0xF0,
		.helper		= gp_cla_ins_helper,
		.ins_tbl	= gp_ins_tbl_8ce,
	}, {
		.cla		= 0xE0,
		.cla_mask	= 0xF0,
		.helper		= gp_cla_ins_helper,
		.ins_tbl	= gp_ins_tbl_8ce,
	},
};

const struct osim_cla_ins_card_profile osim_uicc_cic_profile = {
	.name		= "UICC",
	.description	= "TS 102 221 / 3GPP TS 31.102",
	.cic_arr	= uicc_ins_case,
	.cic_arr_size	= ARRAY_SIZE(uicc_ins_case),
};


static const struct osim_cla_ins_case uicc_sim_ins_case[] = {
	{
		.cla		= 0xA0,
		.cla_mask	= 0xFF,
		.ins_tbl	= gsm1111_ins_tbl,
	}, {
		.cla		= 0x80,
		.cla_mask	= 0xFF,
		.ins_tbl	= uicc_ins_tbl_80,
	}, {
		.cla		= 0x00,
		.cla_mask	= 0xF0,
		.helper		= uicc046_cla_ins_helper,
		.ins_tbl	= uicc_ins_tbl_046,
	}, {
		.cla		= 0x40,
		.cla_mask	= 0xF0,
		.helper		= uicc046_cla_ins_helper,
		.ins_tbl	= uicc_ins_tbl_046,
	}, {
		.cla		= 0x60,
		.cla_mask	= 0xF0,
		.helper		= uicc046_cla_ins_helper,
		.ins_tbl	= uicc_ins_tbl_046,
	}, {
		/* must be before uicc_ins_tbl_8ce below with same CLA+mask */
		.cla		= 0x80,
		.cla_mask	= 0xF0,
		.helper		= gp_cla_ins_helper,
		.ins_tbl	= gp_ins_tbl_8ce,
	}, {
		.cla		= 0x80,
		.cla_mask	= 0xF0,
		.ins_tbl	= uicc_ins_tbl_8ce,
	}, {
		.cla		= 0xC0,
		.cla_mask	= 0xF0,
		.ins_tbl	= uicc_ins_tbl_8ce,
	}, {
		.cla		= 0xE0,
		.cla_mask	= 0xF0,
		.ins_tbl	= uicc_ins_tbl_8ce,
	}, {
		.cla		= 0x80,
		.cla_mask	= 0xF0,
		.helper		= gp_cla_ins_helper,
		.ins_tbl	= gp_ins_tbl_8ce,
	}, {
		.cla		= 0xC0,
		.cla_mask	= 0xF0,
		.helper		= gp_cla_ins_helper,
		.ins_tbl	= gp_ins_tbl_8ce,
	}, {
		.cla		= 0xE0,
		.cla_mask	= 0xF0,
		.helper		= gp_cla_ins_helper,
		.ins_tbl	= gp_ins_tbl_8ce,
	},

};

const struct osim_cla_ins_card_profile osim_uicc_sim_cic_profile = {
	.name		= "UICC+SIM",
	.description	= "TS 102 221 / 3GPP TS 31.102 + GSM TS 11.11",
	.cic_arr	= uicc_sim_ins_case,
	.cic_arr_size	= ARRAY_SIZE(uicc_sim_ins_case),
};

/* 3GPP TS 31.102 */
const uint8_t usim_ins_case[256] = {
	[0x88]		= 4,	/* AUTHENTICATE */
};

/* https://learn.microsoft.com/en-us/windows-hardware/drivers/smartcard/discovery-process */
static const uint8_t microsoft_discovery_ins_tbl[256] = {
	[0xA4]	= 4,	/* SELECT FILE */
	[0xCA]	= 2,	/* GET DATA */
	[0xC0]	= 2,	/* GET RESPONSE */
};

int osim_determine_apdu_case(const struct osim_cla_ins_card_profile *prof,
			     const uint8_t *hdr)
{
	uint8_t cla = hdr[0];
	uint8_t ins = hdr[1];
	int i;
	int rc;

	for (i = 0; i < prof->cic_arr_size; i++) {
		const struct osim_cla_ins_case *cic = &prof->cic_arr[i];
		if ((cla & cic->cla_mask) != cic->cla)
			continue;
		rc = cic->ins_tbl[ins];
		switch (rc) {
		case 0x80:
			return cic->helper(cic, hdr);
		case 0x00:
			/* continue with further cic, rather than abort
			 * now */
			continue;
		default:
			return rc;
		}
	}
	/* special handling for Microsoft who insists to use INS=0xCA in CLA=0x00 which is not
	 * really part of GSM SIM, ETSI UICC or 3GPP USIM specifications, but only ISO7816. Rather than adding
	 * it to each and every card profile, let's add the instructions listed at
	 * https://learn.microsoft.com/en-us/windows-hardware/drivers/smartcard/discovery-process explicitly
	 * here. They will only be used in case no more specific match was found in the actual profile above. */
	if (cla == 0x00) {
		rc = microsoft_discovery_ins_tbl[ins];
		if (rc)
			return rc;
	}

	return 0;
}
