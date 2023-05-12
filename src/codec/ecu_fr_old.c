/*
 * (C) 2017 by sysmocom - s.f.m.c. GmbH
 * (C) 2017 by Philipp Maier <pmaier@sysmocom.de>
 *
 * All Rights Reserved
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
 *
 * This module implements legacy, deprecated osmo_ecu_fr_reset() and
 * osmo_ecu_fr_conceal() functions only - see ecu_fr.c for the new
 * GSM-FR ECU implementation.
 */

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <osmocom/core/bitvec.h>

#include <osmocom/codec/gsm610_bits.h>
#include <osmocom/codec/codec.h>
#include <osmocom/codec/ecu.h>

/* See also GSM 06.11, chapter 6 Example solution */
#define GSM610_XMAXC_REDUCE	4
#define GSM610_XMAXC_LEN	6

/**
 * Reduce the XMAXC field. When the XMAXC field reaches
 * zero the function will return true.
 */
static bool reduce_xmaxcr(struct bitvec *frame_bitvec,
	const unsigned int index)
{
	unsigned int field_index;
	uint64_t field;

	field_index = index;
	field = bitvec_read_field(frame_bitvec, &field_index, GSM610_XMAXC_LEN);
	if (field > GSM610_XMAXC_REDUCE)
		field -= GSM610_XMAXC_REDUCE;
	else
		field = 0;

	field_index = index;
	bitvec_write_field(frame_bitvec, &field_index, field, GSM610_XMAXC_LEN);

	return field == 0;
}

/**
 * Reduce all XMAXC fields in the frame. When all XMAXC fields
 * reach zero, then the function will return true.
 */
static bool reduce_xmaxcr_all(struct bitvec *frame_bitvec)
{
	bool silent = true;

	silent &= reduce_xmaxcr(frame_bitvec, GSM610_RTP_XMAXC00);
	silent &= reduce_xmaxcr(frame_bitvec, GSM610_RTP_XMAXC10);
	silent &= reduce_xmaxcr(frame_bitvec, GSM610_RTP_XMAXC20);
	silent &= reduce_xmaxcr(frame_bitvec, GSM610_RTP_XMAXC30);

	return silent;
}

/* Use certain modifications to conceal the errors in a full rate frame */
static int conceal_frame(uint8_t *frame)
{
	struct bitvec *frame_bitvec;
	unsigned int len;
	bool silent;
	int rc = 0;

	/* In case we already deal with a silent frame,
	 * there is nothing to, we just abort immediately */
	if (osmo_fr_check_sid(frame, GSM_FR_BYTES))
		return 0;

	/* Attempt to allocate memory for bitvec */
	frame_bitvec = bitvec_alloc(GSM_FR_BYTES, NULL);
	if (!frame_bitvec)
		return -ENOMEM;

	/* Convert a frame to bitvec */
	len = bitvec_unpack(frame_bitvec, frame);
	if (len != GSM_FR_BYTES) {
		rc = -EIO;
		goto leave;
	}

	/* Fudge frame parameters */
	silent = reduce_xmaxcr_all(frame_bitvec);

	/* If we reached silence level, mute the frame
	 * completely, this also means that we can
	 * save the bitvec_pack operation */
	if (silent) {
		memset(frame, 0x00, GSM_FR_BYTES);
		frame[0] = 0xd0;
		goto leave;
	}

	/* Convert back to packed byte form */
	len = bitvec_pack(frame_bitvec, frame);
	if (len != GSM_FR_BYTES) {
		rc = -EIO;
		goto leave;
	}

leave:
	bitvec_free(frame_bitvec);
	return rc;
}

/*!
 * To be called when a good frame is received.
 * This function will then create a backup of the frame
 * and reset the internal state.
 * \param[in] state The state object for the ECU
 * \param[out] frame The valid frame (GSM_FR_BYTES bytes in RTP payload format)
 */
void osmo_ecu_fr_reset(struct osmo_ecu_fr_state *state, const uint8_t *frame)
{
	state->subsequent_lost_frame = false;
	memcpy(state->frame_backup, frame, GSM_FR_BYTES);
}

/*!
 * To be called when a bad frame is received.
 * This function will then generate a replacement frame
 * that can be used to conceal the dropout.
 * \param[in] state The state object for the ECU
 * \param[out] frame The buffer to fill with GSM_FR_BYTES of replacement frame
 * \returns 0 if the frame was successfully filled
 */
int osmo_ecu_fr_conceal(struct osmo_ecu_fr_state *state, uint8_t *frame)
{
	int rc;

	/* For subsequent frames we run the error concealment
	 * functions on the backed up frame before we restore
	 * the backup */
	if (state->subsequent_lost_frame) {
		rc = conceal_frame(state->frame_backup);
		if (rc)
			return rc;
	}

	/* Restore the backed up frame and set flag in case
	 * we receive even more bad frames */
	memcpy(frame, state->frame_backup, GSM_FR_BYTES);
	state->subsequent_lost_frame = true;

	return 0;
}
