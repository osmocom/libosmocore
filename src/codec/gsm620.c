/*! \file gsm620.c
 * GSM 06.20 - GSM HR codec. */
/*
 * (C) 2010 Sylvain Munaut <tnt@246tNt.com>
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

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <osmocom/codec/codec.h>

/* GSM HR unvoiced (mode=0) frames - subjective importance bit ordering */
	/* This array encode mapping between GSM 05.03 Table 3a (bits
	 * ordering before channel coding on TCH) and GSM 06.20 Table B.1
	 * (bit ordering on A-bis */
const uint16_t gsm620_unvoiced_bitorder[112] = {
	3,	/* R0:1 */
	25,	/* LPC 3:7 */
	52,	/* GSP 0-1:2 */
	71,	/* GSP 0-2:2 */
	90,	/* GSP 0-3:2 */
	109,	/* GSP 0-4:2 */
	15,	/* LPC 1:0 */
	19,	/* LPC 2:5 */
	20,	/* LPC 2:4 */
	21,	/* LPC 2:3 */
	22,	/* LPC 2:2 */
	23,	/* LPC 2:1 */
	26,	/* LPC 3:6 */
	27,	/* LPC 3:5 */
	28,	/* LPC 3:4 */
	29,	/* LPC 3:3 */
	30,	/* LPC 3:2 */
	31,	/* LPC 3:1 */
	61,	/* Code 1-2:0 */
	62,	/* Code 2-2:6 */
	63,	/* Code 2-2:5 */
	64,	/* Code 2-2:4 */
	65,	/* Code 2-2:3 */
	66,	/* Code 2-2:2 */
	67,	/* Code 2-2:1 */
	68,	/* Code 2-2:0 */
	74,	/* Code 1-3:6 */
	75,	/* Code 1-3:5 */
	76,	/* Code 1-3:4 */
	77,	/* Code 1-3:3 */
	78,	/* Code 1-3:2 */
	79,	/* Code 1-3:1 */
	80,	/* Code 1-3:0 */
	81,	/* Code 2-3:6 */
	82,	/* Code 2-3:5 */
	83,	/* Code 2-3:4 */
	84,	/* Code 2-3:3 */
	32,	/* LPC 3:0 */
	4,	/* R0:0 */
	33,	/* INT-LPC:0 */
	60,	/* Code 1-2:1 */
	59,	/* Code 1-2:2 */
	58,	/* Code 1-2:3 */
	57,	/* Code 1-2:4 */
	56,	/* Code 1-2:5 */
	55,	/* Code 1-2:6 */
	49,	/* Code 2-1:0 */
	48,	/* Code 2-1:1 */
	47,	/* Code 2-1:2 */
	46,	/* Code 2-1:3 */
	45,	/* Code 2-1:4 */
	44,	/* Code 2-1:5 */
	43,	/* Code 2-1:6 */
	42,	/* Code 1-1:0 */
	41,	/* Code 1-1:1 */
	40,	/* Code 1-1:2 */
	39,	/* Code 1-1:3 */
	38,	/* Code 1-1:4 */
	37,	/* Code 1-1:5 */
	36,	/* Code 1-1:6 */
	111,	/* GSP 0-4:0 */
	92,	/* GSP 0-3:0 */
	73,	/* GSP 0-2:0 */
	54,	/* GSP 0-1:0 */
	24,	/* LPC 2:0 */
	110,	/* GSP 0-4:1 */
	91,	/* GSP 0-3:1 */
	72,	/* GSP 0-2:1 */
	53,	/* GSP 0-1:1 */
	14,	/* LPC 1:1 */
	13,	/* LPC 1:2 */
	12,	/* LPC 1:3 */
	11,	/* LPC 1:4 */
	10,	/* LPC 1:5 */
	108,	/* GSP 0-4:3 */
	89,	/* GSP 0-3:3 */
	70,	/* GSP 0-2:3 */
	51,	/* GSP 0-1:3 */
	16,	/* LPC 2:8 */
	17,	/* LPC 2:7 */
	18,	/* LPC 2:6 */
	107,	/* GSP 0-4:4 */
	88,	/* GSP 0-3:4 */
	69,	/* GSP 0-2:4 */
	50,	/* GSP 0-1:4 */
	9,	/* LPC 1:6 */
	8,	/* LPC 1:7 */
	7,	/* LPC 1:8 */
	6,	/* LPC 1:9 */
	2,	/* R0:2 */
	5,	/* LPC 1:10 */
	1,	/* R0:3 */
	0,	/* R0:4 */
	35,	/* Mode:0 */
	34,	/* Mode:1 */
	106,	/* Code 2-4:0 */
	105,	/* Code 2-4:1 */
	104,	/* Code 2-4:2 */
	103,	/* Code 2-4:3 */
	102,	/* Code 2-4:4 */
	101,	/* Code 2-4:5 */
	100,	/* Code 2-4:6 */
	99,	/* Code 1-4:0 */
	98,	/* Code 1-4:1 */
	97,	/* Code 1-4:2 */
	96,	/* Code 1-4:3 */
	95,	/* Code 1-4:4 */
	94,	/* Code 1-4:5 */
	93,	/* Code 1-4:6 */
	87,	/* Code 2-3:0 */
	86,	/* Code 2-3:1 */
	85,	/* Code 2-3:2 */
};

/* GSM HR voiced (mode=1,2,3) frames - subjective importance bit ordering */
	/* This array encode mapping between GSM 05.03 Table 3b (bits
	 * ordering before channel coding on TCH) and GSM 06.20 Table B.2
	 * (bit ordering on A-bis */
const uint16_t gsm620_voiced_bitorder[112] = {
	13,	/* LPC 1:2 */
	14,	/* LPC 1:1 */
	18,	/* LPC 2:6 */
	19,	/* LPC 2:5 */
	20,	/* LPC 2:4 */
	53,	/* GSP 0-1:4 */
	71,	/* GSP 0-2:4 */
	89,	/* GSP 0-3:4 */
	107,	/* GSP 0-4:4 */
	54,	/* GSP 0-1:3 */
	72,	/* GSP 0-2:3 */
	90,	/* GSP 0-3:3 */
	108,	/* GSP 0-4:3 */
	55,	/* GSP 0-1:2 */
	73,	/* GSP 0-2:2 */
	91,	/* GSP 0-3:2 */
	109,	/* GSP 0-4:2 */
	44,	/* Code 1:8 */
	45,	/* Code 1:7 */
	46,	/* Code 1:6 */
	47,	/* Code 1:5 */
	48,	/* Code 1:4 */
	49,	/* Code 1:3 */
	50,	/* Code 1:2 */
	51,	/* Code 1:1 */
	52,	/* Code 1:0 */
	62,	/* Code 2:8 */
	63,	/* Code 2:7 */
	64,	/* Code 2:6 */
	65,	/* Code 2:5 */
	68,	/* Code 2:2 */
	69,	/* Code 2:1 */
	70,	/* Code 2:0 */
	80,	/* Code 3:8 */
	66,	/* Code 2:4 */
	67,	/* Code 2:3 */
	56,	/* GSP 0-1:1 */
	74,	/* GSP 0-2:1 */
	92,	/* GSP 0-3:1 */
	110,	/* GSP 0-4:1 */
	57,	/* GSP 0-1:0 */
	75,	/* GSP 0-2:0 */
	93,	/* GSP 0-3:0 */
	111,	/* GSP 0-4:0 */
	33,	/* INT-LPC:0 */
	24,	/* LPC 2:0 */
	32,	/* LPC 3:0 */
	97,	/* LAG 4:0 */
	31,	/* LPC 3:1 */
	23,	/* LPC 2:1 */
	96,	/* LAG 4:1 */
	79,	/* LAG 3:0 */
	61,	/* LAG 2:0 */
	43,	/* LAG 1:0 */
	95,	/* LAG 4:2 */
	78,	/* LAG 3:1 */
	60,	/* LAG 2:1 */
	42,	/* LAG 1:1 */
	30,	/* LPC 3:2 */
	29,	/* LPC 3:3 */
	28,	/* LPC 3:4 */
	22,	/* LPC 2:2 */
	27,	/* LPC 3:5 */
	26,	/* LPC 3:6 */
	21,	/* LPC 2:3 */
	4,	/* R0:0 */
	25,	/* LPC 3:7 */
	15,	/* LPC 1:0 */
	94,	/* LAG 4:3 */
	77,	/* LAG 3:2 */
	59,	/* LAG 2:2 */
	41,	/* LAG 1:2 */
	3,	/* R0:1 */
	76,	/* LAG 3:3 */
	58,	/* LAG 2:3 */
	40,	/* LAG 1:3 */
	39,	/* LAG 1:4 */
	17,	/* LPC 2:7 */
	16,	/* LPC 2:8 */
	12,	/* LPC 1:3 */
	11,	/* LPC 1:4 */
	10,	/* LPC 1:5 */
	9,	/* LPC 1:6 */
	2,	/* R0:2 */
	38,	/* LAG 1:5 */
	37,	/* LAG 1:6 */
	36,	/* LAG 1:7 */
	8,	/* LPC 1:7 */
	7,	/* LPC 1:8 */
	6,	/* LPC 1:9 */
	5,	/* LPC 1:10 */
	1,	/* R0:3 */
	0,	/* R0:4 */
	35,	/* Mode:0 */
	34,	/* Mode:1 */
	106,	/* Code 4:0 */
	105,	/* Code 4:1 */
	104,	/* Code 4:2 */
	103,	/* Code 4:3 */
	102,	/* Code 4:4 */
	101,	/* Code 4:5 */
	100,	/* Code 4:6 */
	99,	/* Code 4:7 */
	98,	/* Code 4:8 */
	88,	/* Code 3:0 */
	87,	/* Code 3:1 */
	86,	/* Code 3:2 */
	85,	/* Code 3:3 */
	84,	/* Code 3:4 */
	83,	/* Code 3:5 */
	82,	/* Code 3:6 */
	81,	/* Code 3:7 */
};

/*
 * There is no officially defined silence frame for GSM-HR codec like there is
 * for GSM-FR.  However, if one feeds all-zeros (complete silence) linear PCM
 * input to the official GSM-HR encoder, the result will be an endless stream
 * of these frames:
 *
 * R0=00 LPC=164,171,cb Int=0 Mode=0
 * s1=00,00,00 s2=00,00,00 s3=00,00,00 s4=00,00,00
 *
 * The following const datum is the above unofficial GSM-HR silence frame in
 * the packed RTP format of TS 101 318.
 */
const uint8_t osmo_gsm620_silence_frame[GSM_HR_BYTES] = {
	0x01, 0x64, 0xB8, 0xE5, 0x80, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
 * GSM 06.20 defines, by reference to GSM 06.06 C code and GSM 06.07 test
 * sequences, a special frame of codec parameters called the decoder homing
 * frame (DHF).  When a spec-compliant speech decoder processes this frame,
 * it resets itself to the spec-defined home state.
 *
 * The following const datum is GSM-HR DHF in the packed RTP format of
 * TS 101 318.
 */
const uint8_t osmo_gsm620_homing_frame[GSM_HR_BYTES] = {
	0x03, 0x71, 0xAF, 0x61, 0xC8, 0xF2, 0x80,
	0x25, 0x31, 0xC0, 0x00, 0x00, 0x00, 0x00
};

/*! Check whether RTP frame contains HR SID code word according to
 *  TS 101 318 §5.2.2
 *  \param[in] rtp_payload Buffer with RTP payload
 *  \param[in] payload_len Length of payload
 *  \returns true if code word is found, false otherwise
 *
 *  Note that this function checks only for a perfect, error-free SID.
 *  Unlike GSM 06.31 for FR or GSM 06.81 for EFR, GSM 06.41 spec for HR
 *  does not prescribe exact bit counting rules, hence detection of
 *  partially corrupted SID frames in downstream network elements
 *  without out-of-band indication is not possible.
 */
bool osmo_hr_check_sid(const uint8_t *rtp_payload, size_t payload_len)
{
	static const uint8_t all_ff_bytes[9] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						0xFF, 0xFF, 0xFF, 0xFF};

	if (payload_len < GSM_HR_BYTES)
		return false;

	/* A SID frame is identified by a SID codeword consisting of 79 bits
	 * which are all 1, so we basically check if all bits in range
	 * r34..r112 (inclusive) are 1.  However, given the position of
	 * these bits in the frame, the most efficient way to perform
	 * this check does not use any bit-level operations. */
	if ((rtp_payload[4] & 0x7F) != 0x7F)
		return false;
	if (memcmp(rtp_payload + 5, all_ff_bytes, 9) == 0)
		return true;
	else
		return false;
}

/*! Reset the SID field of a potentially corrupted, but still valid GSM-HR
 *  SID frame in TS 101 318 format to its pristine state (full SID codeword).
 *  \param[in] rtp_payload Buffer with RTP payload - must be writable!
 *
 *  Per GSM 06.22 section 5.3, a freshly minted SID frame consists of 33 bits
 *  of comfort noise parameters and 79 bits of SID codeword (all 1s).  Network
 *  elements that receive SID frames from call leg A uplink and need to
 *  retransmit them on leg B downlink should "rejuvenate" received SID frames
 *  prior to retransmission by resetting the SID field to its pristine state
 *  of all 1s; this function does the job.
 *
 *  Important note: because of HR-specific quirks (lack of exact bit counting
 *  rules in GSM 06.41 spec compared to 06.31 & 06.81, plus the fact that such
 *  bit counting can only be done efficiently in the GSM 05.03 channel decoder
 *  prior to bit reordering based on voiced or unvoiced mode), a generic
 *  (usable from any network element) SID classification function similar to
 *  osmo_{fr,efr}_sid_classify() unfortunately cannot exist for HR.  Therefore,
 *  the triggering condition for invoking this SID rejuvenation/reset function
 *  can only be an out-of-band SID indication, as in GSM 08.61 TRAU frames
 *  or RFC 5993 ToC octet.
 */
void osmo_hr_sid_reset(uint8_t *rtp_payload)
{
	/* set all 79 SID codeword bits to 1 */
	rtp_payload[4] |= 0x7F;
	memset(rtp_payload + 5, 0xFF, 9);
}
