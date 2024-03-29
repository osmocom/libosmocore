/*! \file gsm_44_060.h
 * General Packet Radio Service (GPRS).
 * Radio Link Control / Medium Access Control (RLC/MAC) protocol
 * 3GPP TS 44.060
 */

#pragma once

#include <stdint.h>
#include <osmocom/core/endian.h>

/* TS 44.060  10.3a.4.1.1 */
struct gprs_rlc_ul_header_egprs_1 {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t r:1,
		 si:1,
		 cv:4,
		 tfi_hi:2;
	uint8_t tfi_lo:3,
		 bsn1_hi:5;
	uint8_t bsn1_lo:6,
		 bsn2_hi:2;
	uint8_t bsn2_lo:8;
	uint8_t cps:5,
		 rsb:1,
		 pi:1,
		 spare_hi:1;
	uint8_t spare_lo:6,
		 dummy:2;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t tfi_hi:2, cv:4, si:1, r:1;
	uint8_t bsn1_hi:5, tfi_lo:3;
	uint8_t bsn2_hi:2, bsn1_lo:6;
	uint8_t bsn2_lo:8;
	uint8_t spare_hi:1, pi:1, rsb:1, cps:5;
	uint8_t dummy:2, spare_lo:6;
#endif
} __attribute__ ((packed));

/* TS 44.060  10.3a.4.2.1 */
struct gprs_rlc_ul_header_egprs_2 {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t r:1,
		 si:1,
		 cv:4,
		 tfi_hi:2;
	uint8_t tfi_lo:3,
		 bsn1_hi:5;
	uint8_t bsn1_lo:6,
		 cps_hi:2;
	uint8_t cps_lo:1,
		 rsb:1,
		 pi:1,
		 spare_hi:5;
	uint8_t spare_lo:5,
		 dummy:3;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t tfi_hi:2, cv:4, si:1, r:1;
	uint8_t bsn1_hi:5, tfi_lo:3;
	uint8_t cps_hi:2, bsn1_lo:6;
	uint8_t spare_hi:5, pi:1, rsb:1, cps_lo:1;
	uint8_t dummy:3, spare_lo:5;
#endif
} __attribute__ ((packed));

/* TS 44.060  10.3a.4.3.1 */
struct gprs_rlc_ul_header_egprs_3 {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t r:1,
		 si:1,
		 cv:4,
		 tfi_hi:2;
	uint8_t tfi_lo:3,
		 bsn1_hi:5;
	uint8_t bsn1_lo:6,
		 cps_hi:2;
	uint8_t cps_lo:2,
		 spb:2,
		 rsb:1,
		 pi:1,
		 spare:1,
		 dummy:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t tfi_hi:2, cv:4, si:1, r:1;
	uint8_t bsn1_hi:5, tfi_lo:3;
	uint8_t cps_hi:2, bsn1_lo:6;
	uint8_t dummy:1, spare:1, pi:1, rsb:1, spb:2, cps_lo:2;
#endif
} __attribute__ ((packed));

struct gprs_rlc_dl_header_egprs_1 {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t usf:3,
		 es_p:2,
		 rrbp:2,
		 tfi_hi:1;
	uint8_t tfi_lo:4,
		 pr:2,
		 bsn1_hi:2;
	uint8_t bsn1_mid:8;
	uint8_t bsn1_lo:1,
		 bsn2_hi:7;
	uint8_t bsn2_lo:3,
		 cps:5;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t tfi_hi:1, rrbp:2, es_p:2, usf:3;
	uint8_t bsn1_hi:2, pr:2, tfi_lo:4;
	uint8_t bsn1_mid:8;
	uint8_t bsn2_hi:7, bsn1_lo:1;
	uint8_t cps:5, bsn2_lo:3;
#endif
} __attribute__ ((packed));

struct gprs_rlc_dl_header_egprs_2 {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t usf:3,
		 es_p:2,
		 rrbp:2,
		 tfi_hi:1;
	uint8_t tfi_lo:4,
		 pr:2,
		 bsn1_hi:2;
	uint8_t bsn1_mid:8;
	uint8_t bsn1_lo:1,
		 cps:3,
		 dummy:4;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t tfi_hi:1, rrbp:2, es_p:2, usf:3;
	uint8_t bsn1_hi:2, pr:2, tfi_lo:4;
	uint8_t bsn1_mid:8;
	uint8_t dummy:4, cps:3, bsn1_lo:1;
#endif
} __attribute__ ((packed));

struct gprs_rlc_dl_header_egprs_3 {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t usf:3,
		 es_p:2,
		 rrbp:2,
		 tfi_hi:1;
	uint8_t tfi_lo:4,
		 pr:2,
		 bsn1_hi:2;
	uint8_t bsn1_mid:8;
	uint8_t bsn1_lo:1,
		 cps:4,
		 spb:2,
		 dummy:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t tfi_hi:1, rrbp:2, es_p:2, usf:3;
	uint8_t bsn1_hi:2, pr:2, tfi_lo:4;
	uint8_t bsn1_mid:8;
	uint8_t dummy:1, spb:2, cps:4, bsn1_lo:1;
#endif
} __attribute__ ((packed));

/* TS 44.060 Table 12.24.2
* Meaning of values documented in TS 23.060 Chapter 6.3.3.1: Network Mode of Operation */
enum osmo_gprs_nmo {
	GPRS_NMO_I	= 0,	/* CS pagin on GPRS paging or traffic channel */
	GPRS_NMO_II	= 1,	/* all paging on CCCH */
	GPRS_NMO_III	= 2,	/* no paging coordination */
};

/* TS 44.060 12.24 */
struct osmo_gprs_cell_options {
	enum osmo_gprs_nmo nmo;
	/* T3168: wait for packet uplink assignment message */
	uint32_t t3168;	/* in milliseconds */
	/* T3192: wait for release of the TBF after reception of the final block */
	uint32_t t3192;	/* in milliseconds */
	uint32_t drx_timer_max;/* in seconds */
	uint32_t bs_cv_max;
	uint8_t  supports_egprs_11bit_rach;
	bool ctrl_ack_type_use_block; /* use PACKET CONTROL ACKNOWLEDGMENT */

	uint8_t ext_info_present;
	struct {
		uint8_t egprs_supported;
		uint8_t use_egprs_p_ch_req;
		uint8_t bep_period;
		uint8_t pfc_supported;
		uint8_t dtm_supported;
		uint8_t bss_paging_coordination;
		bool ccn_active;
	} ext_info;
};

/* TS 44.060 Table 12.9.2 */
struct osmo_gprs_power_ctrl_pars {
	uint8_t alpha;
	uint8_t t_avg_w;
	uint8_t t_avg_t;
	uint8_t pc_meas_chan;
	uint8_t n_avg_i;
};


/*! Structure for CPS coding and puncturing scheme (TS 44.060 10.4.8a) */
struct egprs_cps {
	uint8_t bits;
	uint8_t mcs;
	uint8_t p[2];
};

/*! CPS puncturing table selection (TS 44.060 10.4.8a) */
enum egprs_cps_punc {
	EGPRS_CPS_P1,
	EGPRS_CPS_P2,
	EGPRS_CPS_P3,
	EGPRS_CPS_NONE = -1,
};

/*! EGPRS header types (TS 44.060 10.0a.2) */
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
