#include <errno.h>
#include <string.h>

#include <osmocom/gprs/gprs_rlc.h>
#include <osmocom/coding/gsm0503_coding.h>
#include <osmocom/gprs/protocol/gsm_04_60.h>

/*! \file gsm/gprs_rlc.c
 *  helper functions for (E)GPRS RLC according to 3GPP TS 44.060
 */

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
