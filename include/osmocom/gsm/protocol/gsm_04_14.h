/*! \file gsm_04_14.h */

#pragma once

#include <stdint.h>
#include <osmocom/core/endian.h>
#include <osmocom/core/utils.h>

/* According to 3GPP TS 44.014 / GSM TS 04.14 */

#define GSM414_MT_CLOSE_TCH_LOOP_CMD	0x00	/* 8.1 */
enum gsm414_tch_loop_mode {
	GSM414_LOOP_A	= 0x00,
	GSM414_LOOP_B	= 0x01,
	GSM414_LOOP_C	= 0x02,
	GSM414_LOOP_D	= 0x04,
	GSM414_LOOP_E	= 0x08,
	GSM414_LOOP_F	= 0x0c,
	GSM414_LOOP_I	= 0x1c,
};

#define GSM414_MT_CLOSE_TCH_LOOP_ACK	0x01	/* 8.2 */
#define GSM414_MT_OPEN_LOOP_CMD		0x02	/* 8.3 */
#define GSM414_OPEN_LOOP_ACK_IE		0x81

#define GSM414_MT_CLOSE_MSLOT_LOOP_CMD	0x20	/* 8.4 */
struct gsm414_close_mslot_loop_cmd {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t chc:2,
		loop_mech:3,
		tn:3;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t tn:3, loop_mech:3, chc:2;
#endif
} __attribute__((packed));

#define GSM414_MT_CLOSE_MSLOT_LOOP_ACK	0x21	/* 8.5 */
struct gsm414_close_mslot_loop_ack {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t err_ind:1,
		loop_mech:3,
		chc:2,
		spare:2;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t spare:2, chc:2, loop_mech:3, err_ind:1;
#endif
} __attribute__((packed));

#define GSM414_MT_OPEN_MSLOT_LOOP_CMD	0x22	/* 8.6 */
#define GSM414_MT_OPEN_MSLOT_LOOP_ACK	0x23	/* 8.7 */
#define GSM414_MT_ACT_EMMI_CMD		0x0c	/* 8.8 */
#define GSM414_MT_ACT_EMMI_ACK		0x0d	/* 8.9 */
#define GSM414_MT_DEACT_EMMI_CMD	0x80	/* 8.10 */
#define GSM414_MT_TEST_INTERFACE	0x84	/* 8.11 */

/* 8.12 Timers (milli-seconds) */
#define GSM414_TT01_MS	2500
#define GSM414_TT02_MS	2500
#define GSM414_TT03_MS	50

#define GSM414_MT_GPRS_TEST_MODE_CMD	0x24	/* 8.13 */
struct gsm414_gprs_test_mode_cmd {
#if OSMO_IS_LITTLE_ENDIAN
	uint16_t d:12,
		spare:3,
		l:1;
	uint8_t m:1,
		dl_tx_offset:3,
		_spare:4;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint16_t d:12,
		spare:3,
		l:1;
	uint8_t _spare:4, dl_tx_offset:3, m:1;
#endif
} __attribute__((packed));


#define GSM414_MT_EGPRS_ST_RB_LOOP_CMD	0x25	/* 8.14 */
struct gsm414_egprs_st_sb_loop_cmd {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t _spare:4,
		dl_tx_offset:3,
		m:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t m:1, dl_tx_offset:3, _spare:4;
#endif
} __attribute__((packed));

#define GSM414_MT_RESET_MS_POS_STORED	0x26	/* 8.15 */
#define GSM414_MS_POS_TECH_AGPS		0x00
#define GSM414_MS_POS_TECH_AGNSS	0x01

extern const struct value_string gsm414_msgt_names[];
