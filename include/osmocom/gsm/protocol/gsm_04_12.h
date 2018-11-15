/*! \file gsm_04_12.h
 * GSM TS 04.12 definitions for Short Message Service Cell Broadcast. */

#pragma once

#include <stdint.h>
#include <osmocom/core/endian.h>

#define GSM412_MSG_LEN		88	/* TS 04.12 Section 3.1 */
#define GSM412_BLOCK_LEN	22	/* TS 04.12 Section 3.1 */

#define GSM412_SEQ_FST_BLOCK		0x0
#define GSM412_SEQ_SND_BLOCK		0x1
#define GSM412_SEQ_TRD_BLOCK		0x2
#define GSM412_SEQ_FTH_BLOCK		0x3
#define GSM412_SEQ_FST_SCHED_BLOCK	0x8
#define GSM412_SEQ_NULL_MSG		0xf

struct gsm412_block_type {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t	seq_nr : 4,
		lb : 1,
		lpd : 2,
		spare : 1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t	spare:1, lpd:2, lb:1, seq_nr:4;
#endif
} __attribute__((packed));

struct gsm412_sched_msg {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t beg_slot_nr : 6,
		type : 2;
	uint8_t end_slot_nr : 6,
		spare1 : 1, spare2: 1;
	uint8_t cbsms_msg_map[6];
	uint8_t data[0];
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t type:2, beg_slot_nr:6;
	uint8_t spare2:1, spare1:1, end_slot_nr:6;
	uint8_t cbsms_msg_map[6];
	uint8_t data[0];
#endif
} __attribute__((packed));
