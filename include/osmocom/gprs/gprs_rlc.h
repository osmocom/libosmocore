/*! \file gprs_rlc.h */

#pragma once

#include <stdint.h>

/*! Structure for CPS coding and puncturing scheme (TS 04.60 10.4.8a) */
struct egprs_cps {
	uint8_t bits;
	uint8_t mcs;
	uint8_t p[2];
};

/*! CPS puncturing table selection (TS 04.60 10.4.8a) */
enum egprs_cps_punc {
	EGPRS_CPS_P1,
	EGPRS_CPS_P2,
	EGPRS_CPS_P3,
	EGPRS_CPS_NONE = -1,
};

/*! EGPRS header types (TS 04.60 10.0a.2) */
enum egprs_hdr_type {
        EGPRS_HDR_TYPE1,
        EGPRS_HDR_TYPE2,
        EGPRS_HDR_TYPE3,
};

enum osmo_gprs_cs {
	OSMO_GPRS_CS_NONE,
	OSMO_GPRS_CS1,
	OSMO_GPRS_CS2,
	OSMO_GPRS_CS3,
	OSMO_GPRS_CS4,
	OSMO_GPRS_MCS1,
	OSMO_GPRS_MCS2,
	OSMO_GPRS_MCS3,
	OSMO_GPRS_MCS4,
	OSMO_GPRS_MCS5,
	OSMO_GPRS_MCS6,
	OSMO_GPRS_MCS7,
	OSMO_GPRS_MCS8,
	OSMO_GPRS_MCS9,
	_NUM_OSMO_GPRS_CS
};

int egprs_get_cps(struct egprs_cps *cps, uint8_t type, uint8_t bits);

int osmo_gprs_ul_block_size_bits(enum osmo_gprs_cs cs);
int osmo_gprs_dl_block_size_bits(enum osmo_gprs_cs cs);
int osmo_gprs_ul_block_size_bytes(enum osmo_gprs_cs cs);
int osmo_gprs_dl_block_size_bytes(enum osmo_gprs_cs cs);
enum osmo_gprs_cs osmo_gprs_ul_cs_by_block_bytes(uint8_t block_size);
enum osmo_gprs_cs osmo_gprs_dl_cs_by_block_bytes(uint8_t block_size);
