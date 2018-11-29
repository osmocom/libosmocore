#pragma once
/* Iu User Plane (IuUP) Definitions as per 3GPP TS 25.415 */
/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <stdint.h>

/* 3GPP TS 25.415 Section 6.6.2.1 */
struct iuup_pdutype0_hdr {
	/* control part */
	uint8_t frame_nr:4,
		pdu_type:4;
	uint8_t rfci:6,
		fqc:2;
	/* checksum part */
	uint16_t payload_crc:10,
		 header_crc:6;
	/* payload part */
	uint8_t payload[0];
} __attribute__((packed));

/* 3GPP TS 25.415 Section 6.6.2.2 */
struct iuup_pdutype1_hdr {
	/* control part */
	uint8_t frame_nr:4,
		pdu_type:4;
	uint8_t rfci:6,
		fqc:2;
	/* checksum part */
	uint8_t spare:2,
		header_crc:6;
	/* payload part */
	uint8_t payload[0];
} __attribute__((packed));

/* 3GPP TS 25.415 Section 6.6.2.3 */
struct iuup_pdutype14_hdr {
	/* control part */
	uint8_t frame_nr:2,
		ack_nack:2,
		pdu_type:4;
	uint8_t proc_ind:4,
		mode_version:4;
	/* checksum part */
	uint16_t payload_crc:10,
		 header_crc:6;
	/* payload part */
	uint8_t payload[0];
} __attribute__((packed));

/* 3GPP TS 25.415 Section 6.6.2 + 6.6.3.1 */
enum iuup_pdu_type {
	IUUP_PDU_T_DATA_CRC	= 0,
	IUUP_PDU_T_DATA_NOCRC	= 1,
	IUUP_PDU_T_CONTROL	= 14,
};

/* 3GPP TS 25.415 Section 6.6.3.2 */
enum iuup_ack_nack {
	IUUP_AN_PROCEDURE	= 0,
	IUUP_AN_ACK		= 1,
	IUUP_AN_NACK		= 2,
};

/* 3GPP TS 25.415 Section 6.6.3.5 */
enum iuup_fqc {
	IUUP_FQC_FRAME_GOOD	= 0,
	IUUP_FQC_FRAME_BAD	= 1,
	IUUP_FQC_FRAME_BAD_RADIO= 2,
};

/* 3GPP TS 25.415 Section 6.6.3.7 */
enum iuup_procedure {
	IUUP_PROC_INIT		= 0,
	IUUP_PROC_RATE_CTRL	= 1,
	IUUP_PROC_TIME_ALIGN	= 2,
	IUUP_PROC_ERR_EVENT	= 3,
};


/* 3GPP TS 25.415 Section 6.6.3.15 */
enum iuup_error_distance {
	IUUP_ERR_DIST_LOCAL		= 0,
	IUUP_ERR_DIST_FIRST_FWD		= 1,
	IUUP_ERR_DIST_SECOND_FWD	= 2,
	IUUP_ERR_DIST_RESERVED		= 3,
};


/* 3GPP TS 25.415 Section 6.6.3.16 */
enum iuup_error_cause {
	IUUP_ERR_CAUSE_CRC_ERR_HDR	= 0,
	IUUP_ERR_CAUSE_CRC_ERR_DATA	= 1,
	IUUP_ERR_CAUSE_UNEXPECTED_FN	= 2,
	IUUP_ERR_CAUSE_FRAME_LOSS	= 3,
	IUUP_ERR_CAUSE_UNKNOWN_PDUTYPE	= 4,
	IUUP_ERR_CAUSE_UNKNOWN_PROC	= 5,
	IUUP_ERR_CAUSE_UNKNNOWN_RES_VAL	= 6,
	IUUP_ERR_CAUSE_UNKNNOWN_FIELD	= 7,
	IUUP_ERR_CAUSE_FRAME_TOO_SHORT	= 8,
	IUUP_ERR_CAUSE_MISSING_FIELDS	= 9,
	IUUP_ERR_CAUSE_UNEXPECTED_PDU_T	= 16,
	IUUP_ERR_CAUSE_UNEXPECTED_PROC	= 18,
	IUUP_ERR_CAUSE_UNEXPECTED_RFCI	= 19,
	IUUP_ERR_CAUSE_UNEXPECTED_VALUE	= 20,
	IUUP_ERR_CAUSE_INIT_FAILURE	= 42,
	IUUP_ERR_CAUSE_INIT_FAILURE_NET_TMR = 43,
	IUUP_ERR_CAUSE_INIT_FAILURE_REP_NACK = 44,
	IUUP_ERR_CAUSE_RATE_CTRL_FAILURE= 45,
	IUUP_ERR_CAUSE_ERR_EVENT_FAIL	= 46,
	IUUP_ERR_CAUSE_TIME_ALIGN_NOTSUPP = 47,
	IUUP_ERR_CAUSE_REQ_TIME_ALIGN_NOTPOSS = 48,
};
