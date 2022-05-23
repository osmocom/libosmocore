/*
 * (C) 2020-2022 by sysmocom - s.f.m.c. GmbH, Author: Philipp Maier
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <osmocom/core/bits.h>
#include <osmocom/core/conv.h>
#include <osmocom/core/utils.h>
#include <osmocom/coding/gsm0503_amr_dtx.h>
#include <osmocom/coding/gsm0503_parity.h>
#include <osmocom/gsm/gsm0503.h>

#define S2U(b)	((b) < 0)

/* See also: 3GPP TS 05.03, chapter 3.10.1.3, 3.10.5.2 Identification marker */
static const ubit_t id_marker_1[] = { 1, 0, 1, 1, 0, 0, 0, 0, 1 };

/* See also: 3GPP TS 05.03, chapter 3.9.1.3, 3.10.2.2, 3.10.2.2 Identification marker */
static const ubit_t id_marker_0[] = { 0, 1, 0, 0, 1, 1, 1, 1, 0 };

/* See also: 3GPP TS 05.03, chapter 3.9 Adaptive multi rate speech channel at full rate (TCH/AFS) */
static const ubit_t codec_mode_1_sid[] = { 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0 };
static const ubit_t codec_mode_2_sid[] = { 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0 };
static const ubit_t codec_mode_3_sid[] = { 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1 };
static const ubit_t codec_mode_4_sid[] = { 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1 };

const struct value_string gsm0503_amr_dtx_frame_names[] = {
	{ AMR_OTHER,		"AMR_OTHER (audio)" },
	{ AFS_SID_FIRST,	"AFS_SID_FIRST" },
	{ AFS_SID_UPDATE,	"AFS_SID_UPDATE (marker)" },
	{ AFS_SID_UPDATE_CN,	"AFS_SID_UPDATE_CN (audio)" },
	{ AFS_ONSET,		"AFS_ONSET" },
	{ AHS_SID_UPDATE,	"AHS_SID_UPDATE (marker)" },
	{ AHS_SID_UPDATE_CN,	"AHS_SID_UPDATE_CN (audio)" },
	{ AHS_SID_FIRST_P1,	"AHS_SID_FIRST_P1" },
	{ AHS_SID_FIRST_P2,	"AHS_SID_FIRST_P2" },
	{ AHS_ONSET,		"AHS_ONSET" },
	{ AHS_SID_FIRST_INH,	"AHS_SID_FIRST_INH" },
	{ AHS_SID_UPDATE_INH,	"AHS_SID_UPDATE_INH" },
	{ 0, NULL }
};

static bool detect_afs_id_marker(int *n_errors, int *n_bits_total, const sbit_t *sbits, uint8_t offset, uint8_t count,
				 const ubit_t * id_marker, uint8_t id_marker_len)
{
	unsigned int i, k;
	unsigned int id_bit_nr = 0;
	int errors = 0;
	int bits = 0;

	/* Override coded in-band data */
	sbits += offset;

	/* Check for identification marker bits */
	for (i = 0; i < count; i++) {
		for (k = 0; k < 4; k++) {
			if (*sbits == 0 || id_marker[id_bit_nr % id_marker_len] != S2U(*sbits))
				errors++;
			id_bit_nr++;
			sbits++;
			bits++;
		}

		/* Jump to the next block of 4 bits */
		sbits += 4;
	}

	*n_errors = errors;
	*n_bits_total = bits;

	/* Tolerate up to 1/8 errornous bits */
	return *n_errors < *n_bits_total / 8;
}

static bool detect_ahs_id_marker(int *n_errors, int *n_bits_total, const sbit_t *sbits, const ubit_t *id_marker)
{
	unsigned int i, k;
	int errors = 0;
	int bits = 0;

	/* Override coded in-band data */
	sbits += 16;

	/* Check first identification marker bits (23*9 bits) */
	for (i = 0; i < 23; i++) {
		for (k = 0; k < 9; k++) {
			if (*sbits == 0 || id_marker[k] != S2U(*sbits))
				errors++;
			sbits++;
			bits++;
		}
	}

	/* Check remaining identification marker bits (5 bits) */
	for (k = 0; k < 5; k++) {
		if (*sbits == 0 || id_marker[k] != S2U(*sbits))
			errors++;
		sbits++;
		bits++;
	}

	*n_errors = errors;
	*n_bits_total = bits;

	/* Tolerate up to 1/8 errornous bits */
	return *n_errors < *n_bits_total / 8;
}

static bool detect_interleaved_ahs_id_marker(int *n_errors, int *n_bits_total, const sbit_t *sbits, uint8_t offset,
					     uint8_t n_bits, const ubit_t * id_marker, uint8_t id_marker_len)
{
	unsigned int i, k;
	int errors = 0;
	int bits = 0;
	uint8_t full_rounds = n_bits / id_marker_len;
	uint8_t remainder = n_bits % id_marker_len;

	/* Override coded in-band data */
	sbits += offset;

	/* Check first identification marker bits (23*9 bits) */
	for (i = 0; i < full_rounds; i++) {
		for (k = 0; k < id_marker_len; k++) {
			if (*sbits == 0 || id_marker[k] != S2U(*sbits))
				errors++;
			sbits += 2;
			bits++;
		}
	}

	/* Check remaining identification marker bits (5 bits) */
	for (k = 0; k < remainder; k++) {
		if (*sbits == 0 || id_marker[k] != S2U(*sbits))
			errors++;
		sbits += 2;
		bits++;
	}

	*n_errors = errors;
	*n_bits_total = bits;

	/* Tolerate up to 1/8 errornous bits */
	return *n_errors < *n_bits_total / 8;
}

/* Detect an FR AMR SID_FIRST frame by its identifcation marker */
static bool detect_afs_sid_first(int *n_errors, int *n_bits_total, const sbit_t *sbits)
{
	return detect_afs_id_marker(n_errors, n_bits_total, sbits, 32, 53, id_marker_0, 9);
}

/* Detect an FR AMR SID_UPDATE frame by its identification marker */
static bool detect_afs_sid_update(int *n_errors, int *n_bits_total, const sbit_t *sbits)
{
	return detect_afs_id_marker(n_errors, n_bits_total, sbits, 36, 53, id_marker_0, 9);
}

/* Detect an FR AMR ONSET frame by its repeating coded inband data */
static int detect_afs_onset(int *n_errors, int *n_bits_total, const sbit_t *sbits)
{
	bool rc;

	rc = detect_afs_id_marker(n_errors, n_bits_total, sbits, 4, 57, codec_mode_1_sid, 16);
	if (rc)
		return 0;

	rc = detect_afs_id_marker(n_errors, n_bits_total, sbits, 4, 57, codec_mode_2_sid, 16);
	if (rc)
		return 1;

	rc = detect_afs_id_marker(n_errors, n_bits_total, sbits, 4, 57, codec_mode_3_sid, 16);
	if (rc)
		return 2;

	rc = detect_afs_id_marker(n_errors, n_bits_total, sbits, 4, 57, codec_mode_4_sid, 16);
	if (rc)
		return 3;

	return -1;
}

/* Detect an HR AMR SID UPDATE frame by its identification marker */
static bool detect_ahs_sid_update(int *n_errors, int *n_bits_total, const sbit_t *sbits)
{
	return detect_ahs_id_marker(n_errors, n_bits_total, sbits, id_marker_1);
}

/* Detect an HR AMR SID FIRST (part 1) frame by its identification marker */
static bool detect_ahs_sid_first_p1(int *n_errors, int *n_bits_total, const sbit_t *sbits)
{
	return detect_ahs_id_marker(n_errors, n_bits_total, sbits, id_marker_0);
}

/* Detect an HR AMR SID FIRST (part 2) frame by its repeating coded inband data */
static int detect_ahs_sid_first_p2(int *n_errors, int *n_bits_total, const sbit_t *sbits)
{
	bool rc;

	rc = detect_interleaved_ahs_id_marker(n_errors, n_bits_total, sbits, 0, 114, codec_mode_1_sid, 16);
	if (rc)
		return 0;

	rc = detect_interleaved_ahs_id_marker(n_errors, n_bits_total, sbits, 0, 114, codec_mode_2_sid, 16);
	if (rc)
		return 1;

	rc = detect_interleaved_ahs_id_marker(n_errors, n_bits_total, sbits, 0, 114, codec_mode_3_sid, 16);
	if (rc)
		return 2;

	rc = detect_interleaved_ahs_id_marker(n_errors, n_bits_total, sbits, 0, 114, codec_mode_4_sid, 16);
	if (rc)
		return 3;

	return -1;
}

/* Detect an HR AMR ONSET frame by its repeating coded inband data */
static int detect_ahs_onset(int *n_errors, int *n_bits_total, const sbit_t *sbits)
{
	bool rc;

	rc = detect_interleaved_ahs_id_marker(n_errors, n_bits_total, sbits, 1, 114, codec_mode_1_sid, 16);
	if (rc)
		return 0;

	rc = detect_interleaved_ahs_id_marker(n_errors, n_bits_total, sbits, 1, 114, codec_mode_2_sid, 16);
	if (rc)
		return 1;

	rc = detect_interleaved_ahs_id_marker(n_errors, n_bits_total, sbits, 1, 114, codec_mode_3_sid, 16);
	if (rc)
		return 2;

	rc = detect_interleaved_ahs_id_marker(n_errors, n_bits_total, sbits, 1, 114, codec_mode_4_sid, 16);
	if (rc)
		return 3;

	return -1;
}

/* Detect an HR AMR SID FIRST INHIBIT frame by its identification marker */
static bool detect_ahs_sid_first_inh(int *n_errors, int *n_bits_total, const sbit_t *sbits)
{
	return detect_interleaved_ahs_id_marker(n_errors, n_bits_total, sbits, 33, 212, id_marker_1, 9);
}

/* Detect an HR AMR SID UPDATE INHIBIT frame by its identification marker */
static bool detect_ahs_sid_update_inh(int *n_errors, int *n_bits_total, const sbit_t *sbits)
{
	return detect_interleaved_ahs_id_marker(n_errors, n_bits_total, sbits, 33, 212, id_marker_0, 9);
}

/*! Detect FR AMR DTX frame in unmapped, deinterleaved frame bits.
 *  \param[out] n_errors number of errornous bits.
 *  \param[out] n_bits_total number of checked bits.
 *  \param[out] mode_id codec mode ID (0..3 or -1).
 *  \param[in] sbits input soft-bits (456 bit).
 *  \returns dtx frame type. */
enum gsm0503_amr_dtx_frames gsm0503_detect_afs_dtx_frame2(int *n_errors, int *n_bits_total,
							  int *mode_id, const sbit_t *sbits)
{
	if (detect_afs_sid_first(n_errors, n_bits_total, sbits))
		return AFS_SID_FIRST;
	if (detect_afs_sid_update(n_errors, n_bits_total, sbits))
		return AFS_SID_UPDATE;
	if ((*mode_id = detect_afs_onset(n_errors, n_bits_total, sbits)) != -1)
		return AFS_ONSET;

	*n_errors = 0;
	*n_bits_total = 0;
	return AMR_OTHER;
}

/*! Detect FR AMR DTX frame in unmapped, deinterleaved frame bits.
 *  DEPRECATED: use gsm0503_detect_afs_dtx_frame2() instead.
 *  \param[out] n_errors number of errornous bits.
 *  \param[out] n_bits_total number of checked bits.
 *  \param[in] ubits input bits (456 bit).
 *  \returns dtx frame type. */
enum gsm0503_amr_dtx_frames gsm0503_detect_afs_dtx_frame(int *n_errors, int *n_bits_total,
							 const ubit_t *ubits)
{
	int mode_id; /* unused */
	sbit_t sbits[456];

	osmo_ubit2sbit(&sbits[0], &ubits[0], sizeof(sbits));
	return gsm0503_detect_afs_dtx_frame2(n_errors, n_bits_total, &mode_id, &sbits[0]);
}

/*! Detect HR AMR DTX frame in unmapped, deinterleaved frame bits.
 *  \param[out] n_errors number of errornous bits.
 *  \param[out] n_bits_total number of checked bits.
 *  \param[out] mode_id codec ID (CMI or CMC/CMR).
 *  \param[out] mode_id codec mode ID (0..3 or -1).
 *  \param[in] sbits input soft-bits (456 bit).
 *  \returns dtx frame type, */
enum gsm0503_amr_dtx_frames gsm0503_detect_ahs_dtx_frame2(int *n_errors, int *n_bits_total,
							  int *mode_id, const sbit_t *sbits)
{
	if (detect_ahs_sid_update(n_errors, n_bits_total, sbits))
		return AHS_SID_UPDATE;
	if (detect_ahs_sid_first_inh(n_errors, n_bits_total, sbits))
		return AHS_SID_FIRST_INH;
	if (detect_ahs_sid_update_inh(n_errors, n_bits_total, sbits))
		return AHS_SID_UPDATE_INH;
	if (detect_ahs_sid_first_p1(n_errors, n_bits_total, sbits))
		return AHS_SID_FIRST_P1;
	if ((*mode_id = detect_ahs_sid_first_p2(n_errors, n_bits_total, sbits)) != -1)
		return AHS_SID_FIRST_P2;
	if ((*mode_id = detect_ahs_onset(n_errors, n_bits_total, sbits)) != -1)
		return AHS_ONSET;

	*n_errors = 0;
	*n_bits_total = 0;
	return AMR_OTHER;
}

/*! Detect HR AMR DTX frame in unmapped, deinterleaved frame bits.
 *  DEPRECATED: use gsm0503_detect_ahs_dtx_frame2() instead.
 *  \param[out] n_errors number of errornous bits.
 *  \param[out] n_bits_total number of checked bits.
 *  \param[in] ubits input bits (456 bit).
 *  \returns dtx frame type, */
enum gsm0503_amr_dtx_frames gsm0503_detect_ahs_dtx_frame(int *n_errors, int *n_bits_total,
							 const ubit_t *ubits)
{
	int mode_id; /* unused */
	sbit_t sbits[456];

	osmo_ubit2sbit(&sbits[0], &ubits[0], sizeof(sbits));
	return gsm0503_detect_ahs_dtx_frame2(n_errors, n_bits_total, &mode_id, &sbits[0]);
}
