/*
 * This module implements osmo_hr_sid_classify() function - an independent
 * reimplementation of the logic that was recommended (but not stipulated
 * as normative) by ETSI for classifying received TCH/HS frames as
 * valid SID, invalid SID or non-SID speech.
 *
 * Author: Mychaela N. Falconia <falcon@freecalypso.org>, 2024 - however,
 * Mother Mychaela's contributions are NOT subject to copyright.
 * No rights reserved, all rights relinquished.
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
 */

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/codec/codec.h>

/*
 * Input to the table: any 4-bit nibble.
 * Output from the table: number of 1 bits in that nibble.
 */
static const uint8_t ones_in_nibble[16] = {0, 1, 1, 2, 1, 2, 2, 3,
					   1, 2, 2, 3, 2, 3, 3, 4};

/*
 * This helper function takes two byte arrays of equal length (data and mask),
 * applies the mask to the data, then counts how many bits are set to 1
 * under the mask, and returns that number.
 */
static unsigned count_ones_under_mask(const uint8_t *data, const uint8_t *mask,
				      unsigned nbytes)
{
	unsigned n, accum;
	uint8_t and;

	accum = 0;
	for (n = 0; n < nbytes; n++) {
		and = *data++ & *mask++;
		accum += ones_in_nibble[and >> 4] + ones_in_nibble[and & 0xF];
	}
	return accum;
}

/*
 * When a GSM-HR SID frame has been decoded correctly in voiced mode,
 * the 79 bits of the SID field will be the last bits in the frame.
 * In the packed format of TS 101 318, the bits of interest will be
 * in the last 10 bytes.  The following array is the mask to be applied.
 */
static const uint8_t sid_field_last10_mask[10] = {
	0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/*
 * When a GSM-HR SID frame has been incorrectly decoded in unvoiced mode
 * (both mode bits got flipped to 0 by channel errors), the 79 bits
 * of the SID field will be badly misordered all over the frame.
 * However, they can still be counted for the purpose of SID detection.
 * The following array is the mask to be applied to the whole frame
 * (14 bytes) to locate the misordered SID field.
 */
static const uint8_t sid_field_misordered[14] = {
	0x08, 0xEF, 0x1F, 0x3F, 0xF3, 0xFC, 0xA4,
	0xFF, 0xFA, 0x3F, 0xFF, 0x47, 0xFF, 0xEC
};

/*
 * In the channel coding scheme on TCH/HS, the HR codec frame of 112 bits
 * is divided into 95 class 1 bits and 17 class 2 bits.  In the packed
 * format of TS 101 318, all 17 class 2 bits will always be in the last
 * 4 bytes; however, the specific bits will be different depending on
 * whether the frame was decoded in voiced or unvoiced mode.
 * The following two arrays are masks to be applied to the last 4 bytes.
 */
static const uint8_t class2_mask_voiced[4]   = {0x7F, 0x80, 0x3F, 0xE0};
static const uint8_t class2_mask_unvoiced[4] = {0x07, 0x07, 0xFF, 0xE0};

/*
 * osmo_hr_sid_classify() - this function is an independent reimplementation
 * of the logic that was recommended (but not stipulated as normative) by ETSI
 * for classifying received TCH/HS frames as valid SID, invalid SID or non-SID
 * speech.  ETSI's original version is swSidDetection() function in reid.c
 * in GSM 06.06 source; the present version implements exactly the same
 * logic (same inputs will produce same output), but differs in the following
 * ways:
 *
 * - The frame of channel-decoded 112 payload bits was passed in the form
 *   of an array of 18 codec parameters in ETSI's version; the present version
 *   uses the packed format of TS 101 318 instead.
 *
 * - The C code implementation was written anew by Mother Mychaela; no code
 *   in this file has been copied directly from GSM 06.06 code drop.
 *
 * This function is meant to be used only in the same network element
 * that performs GSM 05.03 channel decoding (OsmoBTS, new implementations
 * of GSM MS), _*NOT*_ in programs or network elements that receive
 * HRv1 codec frames from other elements via RTP or Abis-E1 etc!
 *
 * The BCI logic recommended by ETSI and implemented in practice by at least
 * one vendor whose implementation has been reverse-engineered (TI Calypso)
 * is included in this function.  To understand this logic, please refer
 * to this wiki description:
 *
 * https://osmocom.org/projects/retro-gsm/wiki/HRv1_error_flags
 */
enum osmo_gsm631_sid_class osmo_hr_sid_classify(const uint8_t *rtp_payload,
						bool bci_flag,
						bool *bfi_from_bci)
{
	uint8_t mode_bits = rtp_payload[4] & 0x30;
	unsigned sid_field_ones, class1_ones, class2_ones;
	unsigned sid_field_zeros, class1_zeros;
	unsigned invalid_sid_threshold;
	enum osmo_gsm631_sid_class sidc;

	if (mode_bits != 0) {	/* decoded as voiced */
		sid_field_ones = count_ones_under_mask(rtp_payload + 4,
					sid_field_last10_mask, 10);
		class2_ones = count_ones_under_mask(rtp_payload + 10,
						    class2_mask_voiced, 4);
	} else {		/* decoded as unvoiced */
		sid_field_ones = count_ones_under_mask(rtp_payload,
					sid_field_misordered, 14);
		class2_ones = count_ones_under_mask(rtp_payload + 10,
						    class2_mask_unvoiced, 4);
	}
	/* All class 2 bits are in SID field, hence class2_ones can never
	 * be greater than sid_field_ones. */
	class1_ones = sid_field_ones - class2_ones;
	/* 79 is the total number of bits in the SID field */
	sid_field_zeros = 79 - sid_field_ones;
	/* 62 is the total number of class 1 bits in TCH/HS frame */
	class1_zeros = 62 - class1_ones;

	/* frame classification logic recommended by ETSI */
	if (bci_flag)
		invalid_sid_threshold = 16;
	else
		invalid_sid_threshold = 11;

	if (class1_zeros < 3)
		sidc = OSMO_GSM631_SID_CLASS_VALID;
	else if (sid_field_zeros < invalid_sid_threshold)
		sidc = OSMO_GSM631_SID_CLASS_INVALID;
	else
		sidc = OSMO_GSM631_SID_CLASS_SPEECH;

	/* If the mode bits got corrupted and the frame was channel-decoded
	 * as unvoiced, it cannot be taken as valid SID because the bits
	 * that hold CN parameters have been misordered.  Therefore,
	 * we have to turn it into invalid SID classification.
	 */
	if (mode_bits == 0 && sidc == OSMO_GSM631_SID_CLASS_VALID)
		sidc = OSMO_GSM631_SID_CLASS_INVALID;

	/* ETSI's peculiar logic that "upgrades" BCI error flag to BFI
	 * (from lowest to highest error severity) when the decoded bit
	 * pattern matches a set criterion.  We leave it up to applications
	 * whether they choose to apply this logic or not.  If this logic
	 * is not wanted, pass NULL pointer as the last argument.
	 */
	if (bci_flag && bfi_from_bci &&
	    sid_field_zeros >= 16 && sid_field_zeros <= 25)
		*bfi_from_bci = true;

	return sidc;
}
