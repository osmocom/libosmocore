/*! \file gsm/gprs_rlc.c
 *  helper functions for (E)GPRS RLC according to 3GPP TS 44.060.
 *
 *  (C) 2016 by Thomas Thou
 *  (C) 2016-2017 by sysmocom - s.f.m.c. GmbH
 *  (C) 2017 by Harald Welte <laforge@gnumonks.org>
 *  All Rights Reserved.
 *
 *  SPDX-License-Identifier: GPL-2.0+
 */

#include <errno.h>
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/gprs/gprs_rlc.h>
#include <osmocom/coding/gsm0503_coding.h>
#include <osmocom/gprs/protocol/gsm_04_60.h>

#define EGPRS_CPS_TYPE1_TBL_SZ		29
#define EGPRS_CPS_TYPE2_TBL_SZ		8
#define EGPRS_CPS_TYPE3_TBL_SZ		16

/* 3GPP TS 44.060 10.4.8a.1.1 "Header type 1" */
static const struct egprs_cps egprs_cps_table_type1[EGPRS_CPS_TYPE1_TBL_SZ] = {
	{ .bits =  0, .mcs = EGPRS_MCS9, .p = { EGPRS_CPS_P1, EGPRS_CPS_P1 } },
	{ .bits =  1, .mcs = EGPRS_MCS9, .p = { EGPRS_CPS_P1, EGPRS_CPS_P2 } },
	{ .bits =  2, .mcs = EGPRS_MCS9, .p = { EGPRS_CPS_P1, EGPRS_CPS_P3 } },
	{ .bits =  3, .mcs = EGPRS_NUM_MCS, .p = { EGPRS_CPS_NONE, EGPRS_CPS_NONE } }, /* reserved for future use */
	{ .bits =  4, .mcs = EGPRS_MCS9, .p = { EGPRS_CPS_P2, EGPRS_CPS_P1 } },
	{ .bits =  5, .mcs = EGPRS_MCS9, .p = { EGPRS_CPS_P2, EGPRS_CPS_P2 } },
	{ .bits =  6, .mcs = EGPRS_MCS9, .p = { EGPRS_CPS_P2, EGPRS_CPS_P3 } },
	{ .bits =  7, .mcs = EGPRS_NUM_MCS, .p = { EGPRS_CPS_NONE, EGPRS_CPS_NONE } }, /* reserved for future use */
	{ .bits =  8, .mcs = EGPRS_MCS9, .p = { EGPRS_CPS_P3, EGPRS_CPS_P1 } },
	{ .bits =  9, .mcs = EGPRS_MCS9, .p = { EGPRS_CPS_P3, EGPRS_CPS_P2 } },
	{ .bits = 10, .mcs = EGPRS_MCS9, .p = { EGPRS_CPS_P3, EGPRS_CPS_P3 } },
	{ .bits = 11, .mcs = EGPRS_MCS8, .p = { EGPRS_CPS_P1, EGPRS_CPS_P1 } },
	{ .bits = 12, .mcs = EGPRS_MCS8, .p = { EGPRS_CPS_P1, EGPRS_CPS_P2 } },
	{ .bits = 13, .mcs = EGPRS_MCS8, .p = { EGPRS_CPS_P1, EGPRS_CPS_P3 } },
	{ .bits = 14, .mcs = EGPRS_MCS8, .p = { EGPRS_CPS_P2, EGPRS_CPS_P1 } },
	{ .bits = 15, .mcs = EGPRS_MCS8, .p = { EGPRS_CPS_P2, EGPRS_CPS_P2 } },
	{ .bits = 16, .mcs = EGPRS_MCS8, .p = { EGPRS_CPS_P2, EGPRS_CPS_P3 } },
	{ .bits = 17, .mcs = EGPRS_MCS8, .p = { EGPRS_CPS_P3, EGPRS_CPS_P1 } },
	{ .bits = 18, .mcs = EGPRS_MCS8, .p = { EGPRS_CPS_P3, EGPRS_CPS_P2 } },
	{ .bits = 19, .mcs = EGPRS_MCS8, .p = { EGPRS_CPS_P3, EGPRS_CPS_P3 } },
	{ .bits = 20, .mcs = EGPRS_MCS7, .p = { EGPRS_CPS_P1, EGPRS_CPS_P1 } },
	{ .bits = 21, .mcs = EGPRS_MCS7, .p = { EGPRS_CPS_P1, EGPRS_CPS_P2 } },
	{ .bits = 22, .mcs = EGPRS_MCS7, .p = { EGPRS_CPS_P1, EGPRS_CPS_P3 } },
	{ .bits = 23, .mcs = EGPRS_MCS7, .p = { EGPRS_CPS_P2, EGPRS_CPS_P1 } },
	{ .bits = 24, .mcs = EGPRS_MCS7, .p = { EGPRS_CPS_P2, EGPRS_CPS_P2 } },
	{ .bits = 25, .mcs = EGPRS_MCS7, .p = { EGPRS_CPS_P2, EGPRS_CPS_P3 } },
	{ .bits = 26, .mcs = EGPRS_MCS7, .p = { EGPRS_CPS_P3, EGPRS_CPS_P1 } },
	{ .bits = 27, .mcs = EGPRS_MCS7, .p = { EGPRS_CPS_P3, EGPRS_CPS_P2 } },
	{ .bits = 28, .mcs = EGPRS_MCS7, .p = { EGPRS_CPS_P3, EGPRS_CPS_P3 } },
};

/*
 * 3GPP TS 44.060 10.4.8a.2.1
 * "Header type 2 in EGPRS TBF or uplink EGPRS2-A TBF"
 */
static const struct egprs_cps egprs_cps_table_type2[EGPRS_CPS_TYPE2_TBL_SZ] = {
	{ .bits =  0, .mcs = EGPRS_MCS6, .p = { EGPRS_CPS_P1, EGPRS_CPS_NONE } },
	{ .bits =  1, .mcs = EGPRS_MCS6, .p = { EGPRS_CPS_P2, EGPRS_CPS_NONE } },
	{ .bits =  2, .mcs = EGPRS_MCS6, .p = { EGPRS_CPS_P1, EGPRS_CPS_NONE } },
	{ .bits =  3, .mcs = EGPRS_MCS6, .p = { EGPRS_CPS_P2, EGPRS_CPS_NONE } },
	{ .bits =  4, .mcs = EGPRS_MCS5, .p = { EGPRS_CPS_P1, EGPRS_CPS_NONE } },
	{ .bits =  5, .mcs = EGPRS_MCS5, .p = { EGPRS_CPS_P2, EGPRS_CPS_NONE } },
	{ .bits =  6, .mcs = EGPRS_MCS6, .p = { EGPRS_CPS_P1, EGPRS_CPS_NONE } },
	{ .bits =  7, .mcs = EGPRS_MCS6, .p = { EGPRS_CPS_P2, EGPRS_CPS_NONE } },
};

/* 3GPP TS 44.060 10.4.8a.3 "Header type 3" */
static const struct egprs_cps egprs_cps_table_type3[EGPRS_CPS_TYPE3_TBL_SZ] = {
	{ .bits =  0, .mcs = EGPRS_MCS4, .p = { EGPRS_CPS_P1, EGPRS_CPS_NONE } },
	{ .bits =  1, .mcs = EGPRS_MCS4, .p = { EGPRS_CPS_P2, EGPRS_CPS_NONE } },
	{ .bits =  2, .mcs = EGPRS_MCS4, .p = { EGPRS_CPS_P3, EGPRS_CPS_NONE } },
	{ .bits =  3, .mcs = EGPRS_MCS3, .p = { EGPRS_CPS_P1, EGPRS_CPS_NONE } },
	{ .bits =  4, .mcs = EGPRS_MCS3, .p = { EGPRS_CPS_P2, EGPRS_CPS_NONE } },
	{ .bits =  5, .mcs = EGPRS_MCS3, .p = { EGPRS_CPS_P3, EGPRS_CPS_NONE } },
	{ .bits =  6, .mcs = EGPRS_MCS3, .p = { EGPRS_CPS_P1, EGPRS_CPS_NONE } },
	{ .bits =  7, .mcs = EGPRS_MCS3, .p = { EGPRS_CPS_P2, EGPRS_CPS_NONE } },
	{ .bits =  8, .mcs = EGPRS_MCS3, .p = { EGPRS_CPS_P3, EGPRS_CPS_NONE } },
	{ .bits =  9, .mcs = EGPRS_MCS2, .p = { EGPRS_CPS_P1, EGPRS_CPS_NONE } },
	{ .bits = 10, .mcs = EGPRS_MCS2, .p = { EGPRS_CPS_P2, EGPRS_CPS_NONE } },
	{ .bits = 11, .mcs = EGPRS_MCS1, .p = { EGPRS_CPS_P1, EGPRS_CPS_NONE } },
	{ .bits = 12, .mcs = EGPRS_MCS1, .p = { EGPRS_CPS_P2, EGPRS_CPS_NONE } },
	{ .bits = 13, .mcs = EGPRS_MCS2, .p = { EGPRS_CPS_P1, EGPRS_CPS_NONE } },
	{ .bits = 14, .mcs = EGPRS_MCS2, .p = { EGPRS_CPS_P2, EGPRS_CPS_NONE } },
	{ .bits = 15, .mcs = EGPRS_MCS0, .p = { EGPRS_CPS_NONE, EGPRS_CPS_NONE } },
};

int egprs_get_cps(struct egprs_cps *cps, uint8_t type, uint8_t bits)
{
	const struct egprs_cps *table_cps;

	switch (type) {
	case EGPRS_HDR_TYPE1:
		if (bits >= EGPRS_CPS_TYPE1_TBL_SZ)
			return -EINVAL;
		table_cps = &egprs_cps_table_type1[bits];
		break;
	case EGPRS_HDR_TYPE2:
		if (bits >= EGPRS_CPS_TYPE2_TBL_SZ)
			return -EINVAL;
		table_cps = &egprs_cps_table_type2[bits];
		break;
	case EGPRS_HDR_TYPE3:
		if (bits >= EGPRS_CPS_TYPE3_TBL_SZ)
			return -EINVAL;
		table_cps = &egprs_cps_table_type3[bits];
		break;
	default:
		return -EINVAL;
	}

	memcpy(cps, table_cps, sizeof *cps);

	return 0;
}

struct gprs_cs_desc {
	struct {
		uint8_t bytes;
		uint8_t bits;
	} uplink, downlink;
};

const struct gprs_cs_desc gprs_cs_desc[_NUM_OSMO_GPRS_CS] = {
	[OSMO_GPRS_CS1]		= { {23, 0},	{23, 0} },
	[OSMO_GPRS_CS2]		= { {33, 7},	{33, 7} },
	[OSMO_GPRS_CS3]		= { {39, 3},	{39, 3} },
	[OSMO_GPRS_CS4]		= { {53, 7}, 	{53, 7} },

	[OSMO_GPRS_MCS1]	= { {26, 1}, 	{26, 1} },
	[OSMO_GPRS_MCS2]	= { {32, 1}, 	{32, 1} },
	[OSMO_GPRS_MCS3]	= { {41, 1}, 	{41, 1} },
	[OSMO_GPRS_MCS4]	= { {48, 1}, 	{48, 1} },

	[OSMO_GPRS_MCS5]	= { {60, 7}, 	{59, 6} },
	[OSMO_GPRS_MCS6]	= { {78, 7}, 	{77, 6} },
	[OSMO_GPRS_MCS7]	= { {118, 2}, 	{117, 4} },
	[OSMO_GPRS_MCS8]	= { {142, 2}, 	{141, 4} },
	[OSMO_GPRS_MCS9]	= { {154, 2}, 	{153, 4} },
};

/*! Return size of (E)GPRS uplink block for given coding scheme in bits */
int osmo_gprs_ul_block_size_bits(enum osmo_gprs_cs cs)
{
	if (cs >= ARRAY_SIZE(gprs_cs_desc))
		return -EINVAL;
	return gprs_cs_desc[cs].uplink.bytes * 8 + gprs_cs_desc[cs].uplink.bits;
}

/*! Return size of (E)GPRS downlink block for given coding scheme in bits */
int osmo_gprs_dl_block_size_bits(enum osmo_gprs_cs cs)
{
	if (cs >= ARRAY_SIZE(gprs_cs_desc))
		return -EINVAL;
	return gprs_cs_desc[cs].downlink.bytes * 8 + gprs_cs_desc[cs].downlink.bits;
}

/*! Return size of (E)GPRS uplink block for given coding scheme in bytes */
int osmo_gprs_ul_block_size_bytes(enum osmo_gprs_cs cs)
{
	int rc;
	if (cs >= ARRAY_SIZE(gprs_cs_desc))
		return -EINVAL;
	rc = gprs_cs_desc[cs].uplink.bytes;
	if (gprs_cs_desc[cs].uplink.bits)
		rc++;
	return rc;
}

/*! Return size of (E)GPRS downlink block for given coding scheme in bytes */
int osmo_gprs_dl_block_size_bytes(enum osmo_gprs_cs cs)
{
	int rc;
	if (cs >= ARRAY_SIZE(gprs_cs_desc))
		return -EINVAL;
	rc = gprs_cs_desc[cs].downlink.bytes;
	if (gprs_cs_desc[cs].downlink.bits)
		rc++;
	return rc;
}

/*! Return coding scheme for given (E)GPRS uplink block size */
enum osmo_gprs_cs osmo_gprs_ul_cs_by_block_bytes(uint8_t block_size)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(gprs_cs_desc); i++) {
		if (block_size == osmo_gprs_ul_block_size_bytes(i))
			return i;
	}
	return OSMO_GPRS_CS_NONE;
}

/*! Return coding scheme for given (E)GPRS downlink block size */
enum osmo_gprs_cs osmo_gprs_dl_cs_by_block_bytes(uint8_t block_size)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(gprs_cs_desc); i++) {
		if (block_size == osmo_gprs_dl_block_size_bytes(i))
			return i;
	}
	return OSMO_GPRS_CS_NONE;
}
