/*
 * (C) 2017 by sysmocom - s.f.m.c. GmbH
 * (C) 2017 by Philipp Maier <pmaier@sysmocom.de>
 * All Rights Reserved
 *
 * Significantly reworked in 2023 by Mother
 * Mychaela N. Falconia <falcon@freecalypso.org> - however,
 * Mother Mychaela's contributions are NOT subject to copyright.
 * No rights reserved, all rights relinquished.
 * Portions of this code are based on Themyscira libgsmfrp,
 * a public domain library by the same author.
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
 * The present ECU implementation for GSM-FR is closely based on the
 * TS 46.011 spec from 3GPP; more specifically, it is based on the
 * Example solution presented in Chapter 6 of that spec, adapted for
 * libosmocodec ECU architecture, and comes as close to fulfilling
 * the spec's officially stated requirements (Chapter 5) as is
 * possible within this Osmocom-imposed architecture.  Please note
 * the following areas where the present implementation fails to
 * fulfill the original intent of GSM spec authors:
 *
 * - The "lost SID" criterion, defined in GSM 06.31, is based on the
 *   TAF bit from the Radio Subsystem.  However, libosmocodec ECU API
 *   does not include this flag, thus spec requirements related to
 *   lost SID conditions cannot be implemented in a strictly compliant
 *   manner.  The present implementation improvises its own "lost SID"
 *   detector (not strictly spec-compliant) by counting frame_out()
 *   calls in between good traffic frame inputs via frame_in().
 *
 * - In the architecture envisioned and assumed in the GSM specs,
 *   the ECU function of GSM 06.11 was never intended to be a fully
 *   modular component with its own bona fide I/O interfaces - this
 *   approach appears to be an Osmocom invention - instead this ECU
 *   function was intended to be subsumed in the Rx DTX handler
 *   component of GSM 06.31, also incorporating the comfort noise
 *   generator of GSM 06.12 - and unlike the narrower-scope ECU,
 *   this slightly-larger-scope Rx DTX handler is a modular component
 *   with well-defined I/O interfaces.  In the case of BFI conditions
 *   following a SID, GSM 06.11 spec was written with the assumption
 *   that the ECU controls the comfort noise generator via internal
 *   signals, as opposed to emitting "corrected" SID frames on a
 *   modular interface going to a CN generator located somewhere else.
 *   Thus the "correct" behavior for a fully modularized ECU is unclear,
 *   and an argument can be made that the very existence of such a
 *   fully modularized ECU is incorrect in itself.  The present
 *   implementation re-emits a "rejuvenated" form of the last saved
 *   SID frame during BFI conditions following a SID within the
 *   permitted window of 48 frames, then starts emitting muted SIDs
 *   with Xmaxc decreasing by 4 on each frame, and finally switches
 *   to emitting non-SID silence frames (Table 1 of TS 46.011)
 *   once Xmaxc reaches 0.
 */

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <osmocom/core/prbs.h>

#include <osmocom/codec/codec.h>
#include <osmocom/codec/ecu.h>

/* See TS 46.011, Chapter 6 Example solution */
#define GSM611_XMAXC_REDUCE	4

/* The first 5 bytes of RTP encoding neatly contain the magic nibble
 * and LARc parameters, which also happens to be the part of SID frames
 * that needs to be passed through as-is. */
#define	SID_PREFIX_LEN		5

enum ecu_principal_state {
	STATE_NO_DATA,
	STATE_SPEECH,
	STATE_SP_MUTING,
	STATE_SID,
	STATE_SID_MUTING,
};

struct fr_ecu_state {
	enum ecu_principal_state pr_state;
	uint8_t speech_frame[GSM_FR_BYTES];
	uint8_t sid_prefix[SID_PREFIX_LEN];
	uint8_t sid_xmaxc;
	uint8_t sid_reemit_count;
	struct osmo_prbs_state prng;
};

/* This function is the frame input to the ECU - all inputs to this
 * function have been received by the Radio Subsystem as good traffic
 * frames in the GSM 06.31 definition.
 */
static void fr_ecu_input(struct fr_ecu_state *fr, const uint8_t *frame)
{
	enum osmo_gsm631_sid_class sidc;

	sidc = osmo_fr_sid_classify(frame);
	switch (sidc) {
	case OSMO_GSM631_SID_CLASS_SPEECH:
		memcpy(fr->speech_frame, frame, GSM_FR_BYTES);
		fr->pr_state = STATE_SPEECH;
		return;
	case OSMO_GSM631_SID_CLASS_INVALID:
		/* GSM 06.31 section 6.1.2 says: "an invalid SID frame
		 * shall be substituted by the last valid SID frame
		 * and the procedure for valid SID frames be applied."
		 * However, libosmocodec ECU architecture prevents us
		 * from doing what the spec says: the frame_in() method
		 * gets a const frame that can't be modified, and
		 * frame_out() will never get called when BFI=0, even
		 * when the "good traffic frame" (in the BFI=0 sense)
		 * is an invalid SID by the bit-counting rule.
		 * Thus there is no place where we can re-emit a cached
		 * copy of the last valid SID upon receiving an invalid SID.
		 *
		 * In the standard GSM architecture this problem never
		 * arises because the ECU is not a separate component
		 * but is coupled with the CN generator, thus the output
		 * from the Rx DTX handler block will be a CN frame,
		 * for both valid-SID and invalid-SID inputs to the block.
		 * But what can we do within the constraints of libosmocodec
		 * ECU framework?  We treat the invalid SID almost like a
		 * BFI, doing almost nothing in the frame_in() method,
		 * but we reset sid_reemit_count because by the rules of
		 * GSM 06.31 an invalid SID is still an accepted SID frame
		 * for the purpose of "lost SID" logic. */
		fr->sid_reemit_count = 0;
		return;
	case OSMO_GSM631_SID_CLASS_VALID:
		/* save LARc part */
		memcpy(fr->sid_prefix, frame, SID_PREFIX_LEN);
		/* save Xmaxc from the last subframe */
		fr->sid_xmaxc = ((frame[27] & 0x1F) << 1) | (frame[28] >> 7);
		fr->pr_state = STATE_SID;
		fr->sid_reemit_count = 0;
		return;
	default:
		/* There are only 3 possible SID classifications per GSM 06.31
		 * section 6.1.1, thus any other return value is a grave error
		 * in the code. */
		OSMO_ASSERT(0);
	}
}

/* Reduce all 4 Xmaxc fields in the frame.  When all 4 Xmaxc fields
 * reach 0, the function will return true for "mute".
 */
static bool reduce_xmaxc(uint8_t *frame)
{
	bool mute_flag = true;
	uint8_t sub, xmaxc;

	for (sub = 0; sub < 4; sub++) {
		xmaxc = ((frame[sub*7+6] & 0x1F) << 1) | (frame[sub*7+7] >> 7);
		if (xmaxc > GSM611_XMAXC_REDUCE) {
			xmaxc -= GSM611_XMAXC_REDUCE;
			mute_flag = false;
		} else
			xmaxc = 0;
		frame[sub*7+6] &= 0xE0;
		frame[sub*7+6] |= xmaxc >> 1;
		frame[sub*7+7] &= 0x7F;
		frame[sub*7+7] |= (xmaxc & 1) << 7;
	}
	return mute_flag;
}

/* TS 46.011 chapter 6, paragraph 4, last sentence: "The grid position
 * parameters are chosen randomly between 0 and 3 during this time."
 * (The "during this time" qualifier refers to the speech muting state.)
 * This sentence in the spec must have been overlooked by previous ECU
 * implementors, as this aspect of the muting logic was missing.
 */
static void random_grid_pos(struct fr_ecu_state *fr, uint8_t *frame)
{
	uint8_t sub;

	for (sub = 0; sub < 4; sub++) {
		frame[sub*7+6] &= 0x9F;
		frame[sub*7+6] |= osmo_prbs_get_ubit(&fr->prng) << 6;
		frame[sub*7+6] |= osmo_prbs_get_ubit(&fr->prng) << 5;
	}
}

/* Like reduce_xmaxc() above, but for comfort noise rather than speech. */
static bool reduce_xmaxc_sid(struct fr_ecu_state *fr)
{
	if (fr->sid_xmaxc > GSM611_XMAXC_REDUCE) {
		fr->sid_xmaxc -= GSM611_XMAXC_REDUCE;
		return false;
	}
	fr->sid_xmaxc = 0;
	return true;
}

/* This function implements the part which is peculiar to the present
 * "standalone" packaging of GSM-FR ECU, without a directly coupled
 * comfort noise generator - it re-emits synthetic SID frames during
 * DTX pauses, initially unchanged from the saved SID and later muted.
 */
static void reemit_sid(struct fr_ecu_state *fr, uint8_t *frame)
{
	uint8_t *p, sub;

	memcpy(frame, fr->sid_prefix, SID_PREFIX_LEN);
	p = frame + SID_PREFIX_LEN;
	for (sub = 0; sub < 4; sub++) {
		*p++ = 0;
		*p++ = fr->sid_xmaxc >> 1;
		*p++ = (fr->sid_xmaxc & 1) << 7;
		*p++ = 0;
		*p++ = 0;
		*p++ = 0;
		*p++ = 0;
	}
}

/* This function is responsible for generating the ECU's output
 * in the event that the Radio Subsystem does not have a good
 * traffic frame - conditions corresponding to BFI=1 in the specs.
 */
static void fr_ecu_output(struct fr_ecu_state *fr, uint8_t *frame)
{
	bool mute;

	switch (fr->pr_state) {
	case STATE_NO_DATA:
		memcpy(frame, osmo_gsm611_silence_frame, GSM_FR_BYTES);
		return;
	case STATE_SPEECH:
		/* TS 46.011 chapter 6: "The first lost speech frame is
		 * replaced at the speech decoder input by the previous
		 * good speech frame." */
		memcpy(frame, fr->speech_frame, GSM_FR_BYTES);
		fr->pr_state = STATE_SP_MUTING;
		return;
	case STATE_SP_MUTING:
		mute = reduce_xmaxc(fr->speech_frame);
		memcpy(frame, fr->speech_frame, GSM_FR_BYTES);
		random_grid_pos(fr, frame);
		if (mute)
			fr->pr_state = STATE_NO_DATA;
		return;
	case STATE_SID:
		fr->sid_reemit_count++;
		if (fr->sid_reemit_count >= 48) {
			fr->pr_state = STATE_SID_MUTING;
			reduce_xmaxc_sid(fr);
		}
		reemit_sid(fr, frame);
		return;
	case STATE_SID_MUTING:
		if (reduce_xmaxc_sid(fr)) {
			fr->pr_state = STATE_NO_DATA;
			memcpy(frame, osmo_gsm611_silence_frame, GSM_FR_BYTES);
		} else
			reemit_sid(fr, frame);
		return;
	default:
		/* a severe bug in the state machine! */
		OSMO_ASSERT(0);
	}
}

/***********************************************************************
 * Integration with ECU core
 ***********************************************************************/

static struct osmo_ecu_state *ecu_fr_init(void *ctx, enum osmo_ecu_codec codec)
{
	struct osmo_ecu_state *st;
	struct fr_ecu_state *fr;
	size_t size = sizeof(*st) + sizeof(*fr);

	st = talloc_named_const(ctx, size, "ecu_state_FR");
	if (!st)
		return NULL;

	memset(st, 0, size);
	st->codec = codec;
	fr = (struct fr_ecu_state *) &st->data;
	fr->pr_state = STATE_NO_DATA;
	osmo_prbs_state_init(&fr->prng, &osmo_prbs15);

	return st;
}

static int ecu_fr_frame_in(struct osmo_ecu_state *st, bool bfi, const uint8_t *frame,
			   unsigned int frame_bytes)
{
	struct fr_ecu_state *fr = (struct fr_ecu_state *) &st->data;

	if (bfi)
		return 0;
	if (frame_bytes != GSM_FR_BYTES)
		return 0;
	if ((frame[0] & 0xF0) != 0xD0)
		return 0;

	fr_ecu_input(fr, frame);
	return 0;
}

static int ecu_fr_frame_out(struct osmo_ecu_state *st, uint8_t *frame_out)
{
	struct fr_ecu_state *fr = (struct fr_ecu_state *) &st->data;

	fr_ecu_output(fr, frame_out);
	return GSM_FR_BYTES;
}

static const struct osmo_ecu_ops osmo_ecu_ops_fr = {
	.init = ecu_fr_init,
	.frame_in = ecu_fr_frame_in,
	.frame_out = ecu_fr_frame_out,
};

static __attribute__((constructor)) void on_dso_load_ecu_fr(void)
{
	osmo_ecu_register(&osmo_ecu_ops_fr, OSMO_ECU_CODEC_FR);
}
