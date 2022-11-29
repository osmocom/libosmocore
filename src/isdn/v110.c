/* V.110 frames according to ITU-T V.110
 *
 * This code implements the following functionality:
 * - parsing/encoding of osmo_v110_decoded_frame from/to actual 80-bit V.110 frame
 * - synchronous rate adapting of user bit rate to V.110 D-bits as per Table 6
 *
 * It is (at least initially) a very "naive" implementation, as it first and foremost
 * aims to be functional and correct, rather than efficient in any way.  Hence it
 * operates on unpacked bits (ubit_t, 1 bit per byte), and has various intermediate
 * representations and indirect function calls.  If needed, a more optimized variant
 * can always be developed later on.
 */

/* (C) 2022 by Harald Welte <laforge@osmocom.org>
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#include <stdint.h>
#include <errno.h>

#include <osmocom/core/bits.h>

#include <osmocom/isdn/v110.h>

/*************************************************************************
 * V.110 frame decoding/encoding (ubits <-> struct with D/S/X/E bits)
 *************************************************************************/

/*! Decode a 80-bit V.110 frame present as 80 ubits into a struct osmo_v110_decoded_frame.
 *  \param[out] fr caller-allocated output data structure, filled by this function
 *  \param[in] ra_bits One V.110 frame as 80 unpacked bits.
 *  \param[in] n_bits number of unpacked bits provided in ra_bits
 *  \returns 0 in case of success; negative on error. */
int osmo_v110_decode_frame(struct osmo_v110_decoded_frame *fr, const ubit_t *ra_bits, size_t n_bits)
{
	if (n_bits < 80)
		return -EINVAL;

	/* X1 .. X2 */
	fr->x_bits[0] = ra_bits[2 * 8 + 7];
	fr->x_bits[1] = ra_bits[7 * 8 + 7];

	/* S1, S3, S4, S6, S8, S9 */
	fr->s_bits[0] = ra_bits[1 * 8 + 7];
	fr->s_bits[2] = ra_bits[3 * 8 + 7];
	fr->s_bits[3] = ra_bits[4 * 8 + 7];
	fr->s_bits[5] = ra_bits[6 * 8 + 7];
	fr->s_bits[7] = ra_bits[8 * 8 + 7];
	fr->s_bits[8] = ra_bits[9 * 8 + 7];

	/* E1 .. E7 */
	memcpy(fr->e_bits, ra_bits + 5 * 8 + 1, 7);

	/* D-bits */
	memcpy(fr->d_bits + 0 * 6, ra_bits + 1 * 8 + 1, 6);
	memcpy(fr->d_bits + 1 * 6, ra_bits + 2 * 8 + 1, 6);
	memcpy(fr->d_bits + 2 * 6, ra_bits + 3 * 8 + 1, 6);
	memcpy(fr->d_bits + 3 * 6, ra_bits + 4 * 8 + 1, 6);

	memcpy(fr->d_bits + 4 * 6, ra_bits + 6 * 8 + 1, 6);
	memcpy(fr->d_bits + 5 * 6, ra_bits + 7 * 8 + 1, 6);
	memcpy(fr->d_bits + 6 * 6, ra_bits + 8 * 8 + 1, 6);
	memcpy(fr->d_bits + 7 * 6, ra_bits + 9 * 8 + 1, 6);

	return 0;
}

/*! Encode a struct osmo_v110_decoded_frame into an 80-bit V.110 frame as ubits.
 *  \param[out] ra_bits caller-provided output buffer at leat 80 ubits large
 *  \param[in] n_bits length of ra_bits. Must be at least 80.
 *  \param[in] input data structure
 *  \returns number of bits written to ra_bits */
int osmo_v110_encode_frame(ubit_t *ra_bits, size_t n_bits, const struct osmo_v110_decoded_frame *fr)
{
	if (n_bits < 80)
		return -ENOSPC;

	/* alignment pattern */
	memset(ra_bits+0, 0, 8);
	for (int i = 1; i < 10; i++)
		ra_bits[i*8] = 1;

	/* X1 .. X2 */
	ra_bits[2 * 8 + 7] = fr->x_bits[0];
	ra_bits[7 * 8 + 7] = fr->x_bits[1];

	/* S1, S3, S4, S6, S8, S9 */
	ra_bits[1 * 8 + 7] = fr->s_bits[0];
	ra_bits[3 * 8 + 7] = fr->s_bits[2];
	ra_bits[4 * 8 + 7] = fr->s_bits[3];
	ra_bits[6 * 8 + 7] = fr->s_bits[5];
	ra_bits[8 * 8 + 7] = fr->s_bits[7];
	ra_bits[9 * 8 + 7] = fr->s_bits[8];

	/* E1 .. E7 */
	memcpy(ra_bits + 5 * 8 + 1, fr->e_bits, 7);

	/* D-bits */
	memcpy(ra_bits + 1 * 8 + 1, fr->d_bits + 0 * 6, 6);
	memcpy(ra_bits + 2 * 8 + 1, fr->d_bits + 1 * 6, 6);
	memcpy(ra_bits + 3 * 8 + 1, fr->d_bits + 2 * 6, 6);
	memcpy(ra_bits + 4 * 8 + 1, fr->d_bits + 3 * 6, 6);

	memcpy(ra_bits + 6 * 8 + 1, fr->d_bits + 4 * 6, 6);
	memcpy(ra_bits + 7 * 8 + 1, fr->d_bits + 5 * 6, 6);
	memcpy(ra_bits + 8 * 8 + 1, fr->d_bits + 6 * 6, 6);
	memcpy(ra_bits + 9 * 8 + 1, fr->d_bits + 7 * 6, 6);

	return 10 * 8;
}

/*! Print a encoded V.110 frame in the same table-like structure as the spec.
 *  \param outf output FILE stream to which to dump
 *  \param[in] fr unpacked bits to dump
 *  \param[in] in_len length of unpacked bits available at fr. */
void osmo_v110_ubit_dump(FILE *outf, const ubit_t *fr, size_t in_len)
{
	if (in_len < 80)
		fprintf(outf, "short input data\n");

	for (unsigned int octet = 0; octet < 10; octet++) {
		fprintf(outf, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
			fr[octet * 8 + 0], fr[octet * 8 + 1], fr[octet * 8 + 2], fr[octet * 8 + 3],
			fr[octet * 8 + 4], fr[octet * 8 + 5], fr[octet * 8 + 6], fr[octet * 8 + 7]);
	}
}

/*************************************************************************
 * RA1 synchronous rate adaptation
 *************************************************************************/

/* I actually couldn't find any reference as to the value of F(ill) bits */
#define F 1

/*! Adapt from 6 synchronous 600bit/s input bits to a decoded V.110 frame.
 *  \param[out] fr caller-allocated output frame to which E+D bits are stored
 *  \param[in] d_in input user bits
 *  \param[in] in_len number of bits in d_in. Must be 6.
 *  \returns 0 on success; negative in case of error. */
static int v110_adapt_600_to_IR8000(struct osmo_v110_decoded_frame *fr, const ubit_t *d_in, size_t in_len)
{
	if (in_len != 6)
		return -EINVAL;

	/* Table 6a / V.110 */
	fr->e_bits[0] = 1;
	fr->e_bits[1] = 0;
	fr->e_bits[2] = 0;
	for (int i = 0; i < 6; i++)
		memset(fr->d_bits + i*8, d_in[i], 8);

	return 0;
}

static int v110_adapt_IR8000_to_600(ubit_t *d_out, size_t out_len, const struct osmo_v110_decoded_frame *fr)
{
	if (out_len < 6)
		return -ENOSPC;

	if (fr->e_bits[0] != 1 || fr->e_bits[1] != 0 || fr->e_bits[2] != 0)
		return -EINVAL;

	for (int i = 0; i < 6; i++) {
		/* we only use one of the bits, not some kind of consistency check or majority vote */
		d_out[i] = fr->d_bits[i*8];
	}

	return 6;
}

/*! Adapt from 12 synchronous 1200bit/s input bits to a decoded V.110 frame.
 *  \param[out] fr caller-allocated output frame to which E+D bits are stored
 *  \param[in] d_in input user bits
 *  \param[in] in_len number of bits in d_in. Must be 12.
 *  \returns 0 on success; negative in case of error. */
static int v110_adapt_1200_to_IR8000(struct osmo_v110_decoded_frame *fr, const ubit_t *d_in, size_t in_len)
{
	if (in_len != 12)
		return -EINVAL;

	/* Table 6b / V.110 */
	fr->e_bits[0] = 0;
	fr->e_bits[1] = 1;
	fr->e_bits[2] = 0;
	for (int i = 0; i < 12; i++)
		memset(fr->d_bits + i*4, d_in[i], 4);

	return 0;
}

static int v110_adapt_IR8000_to_1200(ubit_t *d_out, size_t out_len, const struct osmo_v110_decoded_frame *fr)
{
	if (out_len < 12)
		return -ENOSPC;

	if (fr->e_bits[0] != 0 || fr->e_bits[1] != 1 || fr->e_bits[2] != 0)
		return -EINVAL;

	for (int i = 0; i < 12; i++) {
		/* we only use one of the bits, not some kind of consistency check or majority vote */
		d_out[i] = fr->d_bits[i*4];
	}

	return 12;
}

/*! Adapt from 24 synchronous 2400bit/s input bits to a decoded V.110 frame.
 *  \param[out] fr caller-allocated output frame to which E+D bits are stored
 *  \param[in] d_in input user bits
 *  \param[in] in_len number of bits in d_in. Must be 24.
 *  \returns 0 on success; negative in case of error. */
static int v110_adapt_2400_to_IR8000(struct osmo_v110_decoded_frame *fr, const ubit_t *d_in, size_t in_len)
{
	if (in_len != 24)
		return -EINVAL;

	/* Table 6c / V.110 */
	fr->e_bits[0] = 1;
	fr->e_bits[1] = 1;
	fr->e_bits[2] = 0;
	for (int i = 0; i < 24; i++) {
		fr->d_bits[i*2 + 0] = d_in[i];
		fr->d_bits[i*2 + 1] = d_in[i];
	}

	return 0;
}

static int v110_adapt_IR8000_to_2400(ubit_t *d_out, size_t out_len, const struct osmo_v110_decoded_frame *fr)
{
	if (out_len < 24)
		return -ENOSPC;

	if (fr->e_bits[1] != 1 || fr->e_bits[1] != 1 || fr->e_bits[2] != 0)
		return -EINVAL;

	for (int i = 0; i < 24; i++) {
		/* we only use one of the bits, not some kind of consistency check or majority vote */
		d_out[i] = fr->d_bits[i*2];
	}

	return 24;
}

/*! Adapt from 36 synchronous N x 3600bit/s input bits to a decoded V.110 frame.
 *  \param[out] fr caller-allocated output frame to which E+D bits are stored
 *  \param[in] d_in input user bits
 *  \param[in] in_len number of bits in d_in. Must be 36.
 *  \returns 0 on success; negative in case of error. */
static int v110_adapt_Nx3600_to_IR(struct osmo_v110_decoded_frame *fr, const ubit_t *d_in, size_t in_len)
{
	int d_idx = 0;

	if (in_len != 36)
		return -EINVAL;

	/* Table 6d / V.110 */
	fr->e_bits[0] = 1;
	fr->e_bits[1] = 0;
	fr->e_bits[2] = 1;

	memcpy(fr->d_bits + d_idx, d_in + 0, 10); d_idx += 10;	/* D1..D10 */
	memset(fr->d_bits + d_idx, F, 2); d_idx += 2;
	memcpy(fr->d_bits + d_idx, d_in + 10, 2); d_idx += 2;	/* D11..D12 */
	memset(fr->d_bits + d_idx, F, 2); d_idx += 2;
	memcpy(fr->d_bits + d_idx, d_in + 12, 2); d_idx += 2;	/* D13..D14 */
	memset(fr->d_bits + d_idx, F, 2); d_idx += 2;
	memcpy(fr->d_bits + d_idx, d_in + 14, 14); d_idx += 14;	/* D15..D28 */
	memset(fr->d_bits + d_idx, F, 2); d_idx += 2;
	memcpy(fr->d_bits + d_idx, d_in + 28, 2); d_idx += 2;	/* D29..D30 */
	memset(fr->d_bits + d_idx, F, 2); d_idx += 2;
	memcpy(fr->d_bits + d_idx, d_in + 30, 2); d_idx += 2;	/* D31..D32 */
	memset(fr->d_bits + d_idx, F, 2); d_idx += 2;
	memcpy(fr->d_bits + d_idx, d_in + 32, 4); d_idx += 4;	/* D33..D36 */

	OSMO_ASSERT(d_idx == 48);

	return 0;
}

static int v110_adapt_IR_to_Nx3600(ubit_t *d_out, size_t out_len, const struct osmo_v110_decoded_frame *fr)
{
	int d_idx = 0;

	if (out_len < 36)
		return -ENOSPC;

	if (fr->e_bits[0] != 1 || fr->e_bits[1] != 0 || fr->e_bits[2] != 1)
		return -EINVAL;

	memcpy(d_out + 0, fr->d_bits + d_idx, 10); d_idx += 10;	/* D1..D10 */
	d_idx += 2;
	memcpy(d_out + 10, fr->d_bits + d_idx, 2); d_idx += 2;	/* D11..D12 */
	d_idx += 2;
	memcpy(d_out + 12, fr->d_bits + d_idx, 2); d_idx += 2;	/* D13..D14 */
	d_idx += 2;
	memcpy(d_out + 14, fr->d_bits + d_idx, 14); d_idx += 14;/* D15..D28 */
	d_idx += 2;
	memcpy(d_out + 28, fr->d_bits + d_idx, 2); d_idx += 2;	/* D29..D30 */
	d_idx += 2;
	memcpy(d_out + 30, fr->d_bits + d_idx, 2); d_idx += 2;	/* D31..D32 */
	d_idx += 2;
	memcpy(d_out + 32, fr->d_bits + d_idx, 4); d_idx += 4;	/* D33..D36 */

	OSMO_ASSERT(d_idx == 48);

	return 36;
}


/*! Adapt from 48 synchronous N x 4800bit/s input bits to a decoded V.110 frame.
 *  \param[out] fr caller-allocated output frame to which E+D bits are stored
 *  \param[in] d_in input user bits
 *  \param[in] in_len number of bits in d_in. Must be 48.
 *  \returns 0 on success; negative in case of error. */
static int v110_adapt_Nx4800_to_IR(struct osmo_v110_decoded_frame *fr, const ubit_t *d_in, size_t in_len)
{
	if (in_len != 48)
		return -EINVAL;

	/* Table 6e / V.110 */
	fr->e_bits[0] = 0;
	fr->e_bits[1] = 1;
	fr->e_bits[2] = 1;

	memcpy(fr->d_bits, d_in, 48);

	return 0;
}

static int v110_adapt_IR_to_Nx4800(ubit_t *d_out, size_t out_len, const struct osmo_v110_decoded_frame *fr)
{
	if (out_len < 48)
		return -ENOSPC;

	if (fr->e_bits[0] != 0 || fr->e_bits[1] != 1 || fr->e_bits[2] != 1)
		return -EINVAL;

	memcpy(d_out, fr->d_bits, 48);

	return 48;
}

/*! Adapt from 30 synchronous N x 12000bit/s input bits to a decoded V.110 frame.
 *  \param[out] fr caller-allocated output frame to which E+D bits are stored
 *  \param[in] d_in input user bits
 *  \param[in] in_len number of bits in d_in. Must be 30.
 *  \returns 0 on success; negative in case of error. */
static int v110_adapt_Nx12000_to_IR(struct osmo_v110_decoded_frame *fr, const ubit_t *d_in, size_t in_len)
{
	int d_idx = 0;

	if (in_len != 30)
		return -EINVAL;

	/* Table 6f / V.110 */
	fr->e_bits[0] = 0;
	fr->e_bits[1] = 0;
	fr->e_bits[2] = 1;

	memcpy(fr->d_bits + d_idx, d_in + 0, 10); d_idx += 10;	/* D1..D10 */
	memset(fr->d_bits + d_idx, F, 2); d_idx += 2;
	memcpy(fr->d_bits + d_idx, d_in + 10, 2); d_idx += 2;	/* D11..D12 */
	memset(fr->d_bits + d_idx, F, 2); d_idx += 2;
	memcpy(fr->d_bits + d_idx, d_in + 12, 2); d_idx += 2;	/* D13..D14 */
	memset(fr->d_bits + d_idx, F, 2); d_idx += 2;
	fr->d_bits[d_idx++] = d_in[14];				/* D15 */
	memset(fr->d_bits + d_idx, F, 3); d_idx += 3;
	memcpy(fr->d_bits + d_idx, d_in + 15, 10); d_idx += 10;	/* D16..D25 */
	memset(fr->d_bits + d_idx, F, 2); d_idx += 2;
	memcpy(fr->d_bits + d_idx, d_in + 25, 2); d_idx += 2;	/* D26..D27 */
	memset(fr->d_bits + d_idx, F, 2); d_idx += 2;
	memcpy(fr->d_bits + d_idx, d_in + 27, 2); d_idx += 2;	/* D28..D29 */
	memset(fr->d_bits + d_idx, F, 2); d_idx += 2;
	fr->d_bits[d_idx++] = d_in[29];				/* D30 */
	memset(fr->d_bits + d_idx, F, 3); d_idx += 3;

	OSMO_ASSERT(d_idx == 48);

	return 0;
}

static int v110_adapt_IR_to_Nx12000(ubit_t *d_out, size_t out_len, const struct osmo_v110_decoded_frame *fr)
{
	int d_idx = 0;

	if (out_len < 30)
		return -ENOSPC;

	if (fr->e_bits[0] != 0 || fr->e_bits[1] != 0 || fr->e_bits[2] != 1)
		return -EINVAL;

	memcpy(d_out + 0, fr->d_bits + d_idx, 10); d_idx += 10;	/* D1..D10 */
	d_idx += 2;
	memcpy(d_out + 10, fr->d_bits + d_idx, 2); d_idx += 2;	/* D11..D12 */
	d_idx += 2;
	memcpy(d_out + 12, fr->d_bits + d_idx, 2); d_idx += 2;	/* D13..D14 */
	d_idx += 2;
	d_out[14] = fr->d_bits[d_idx++];			/* D15 */
	d_idx += 3;
	memcpy(d_out + 15, fr->d_bits + d_idx, 10); d_idx += 10;/* D16..D25 */
	d_idx += 2;
	memcpy(d_out + 25, fr->d_bits + d_idx, 2); d_idx += 2;	/* D26..D27 */
	d_idx += 2;
	memcpy(d_out + 27, fr->d_bits + d_idx, 2); d_idx += 2;	/* D28..D29 */
	d_idx += 2;
	d_out[29] = fr->d_bits[d_idx++];			/* D30 */
	d_idx += 3;

	OSMO_ASSERT(d_idx == 48);

	return 30;
}

/* definition of a synchronous V.110 RA1 rate adaptation. There is one for each supported tuple
 * of user data rate and intermediate rate (IR). */
struct osmo_v110_sync_ra1 {
	unsigned int data_rate;
	unsigned int intermediate_rate;
	unsigned int user_data_chunk_bits;
	/*! RA1 function in user bitrate -> intermediate rate direction */
	int (*adapt_user_to_ir)(struct osmo_v110_decoded_frame *fr, const ubit_t *d_in, size_t in_len);
	/*! RA1 function in intermediate rate -> user bitrate direction */
	int (*adapt_ir_to_user)(ubit_t *d_out, size_t out_len, const struct osmo_v110_decoded_frame *fr);
};

/* all of the synchronous data signalling rates; see Table 1/V.110 */
static const struct osmo_v110_sync_ra1 osmo_v110_sync_ra1_def[_NUM_OSMO_V110_SYNC_RA1] = {
	[OSMO_V110_SYNC_RA1_600] = {
		.data_rate = 600,
		.intermediate_rate = 8000,
		.user_data_chunk_bits = 6,
		.adapt_user_to_ir = v110_adapt_600_to_IR8000,
		.adapt_ir_to_user = v110_adapt_IR8000_to_600,
	},
	[OSMO_V110_SYNC_RA1_1200] = {
		.data_rate = 1200,
		.intermediate_rate = 8000,
		.user_data_chunk_bits = 12,
		.adapt_user_to_ir = v110_adapt_1200_to_IR8000,
		.adapt_ir_to_user = v110_adapt_IR8000_to_1200,
	},
	[OSMO_V110_SYNC_RA1_2400] = {
		.data_rate = 2400,
		.intermediate_rate = 8000,
		.user_data_chunk_bits = 24,
		.adapt_user_to_ir = v110_adapt_2400_to_IR8000,
		.adapt_ir_to_user = v110_adapt_IR8000_to_2400,
	},
	[OSMO_V110_SYNC_RA1_4800] = {
		.data_rate = 4800,
		.intermediate_rate = 8000,
		.user_data_chunk_bits = 48,
		.adapt_user_to_ir = v110_adapt_Nx4800_to_IR,
		.adapt_ir_to_user = v110_adapt_IR_to_Nx4800,
	},
	[OSMO_V110_SYNC_RA1_7200] = {
		.data_rate = 7200,
		.intermediate_rate = 16000,
		.user_data_chunk_bits = 36,
		.adapt_user_to_ir = v110_adapt_Nx3600_to_IR,
		.adapt_ir_to_user = v110_adapt_IR_to_Nx3600,
	},
	[OSMO_V110_SYNC_RA1_9600] = {
		.data_rate = 9600,
		.intermediate_rate = 16000,
		.user_data_chunk_bits = 48,
		.adapt_user_to_ir = v110_adapt_Nx4800_to_IR,
		.adapt_ir_to_user = v110_adapt_IR_to_Nx4800,
	},
	[OSMO_V110_SYNC_RA1_12000] = {
		.data_rate = 12000,
		.intermediate_rate = 32000,
		.user_data_chunk_bits = 30,
		.adapt_user_to_ir = v110_adapt_Nx12000_to_IR,
		.adapt_ir_to_user = v110_adapt_IR_to_Nx12000,
	},
	[OSMO_V110_SYNC_RA1_14400] = {
		.data_rate = 14400,
		.intermediate_rate = 32000,
		.user_data_chunk_bits = 36,
		.adapt_user_to_ir = v110_adapt_Nx3600_to_IR,
		.adapt_ir_to_user = v110_adapt_IR_to_Nx3600,
	},
	[OSMO_V110_SYNC_RA1_19200] = {
		.data_rate = 19200,
		.intermediate_rate = 32000,
		.user_data_chunk_bits = 48,
		.adapt_user_to_ir = v110_adapt_Nx4800_to_IR,
		.adapt_ir_to_user = v110_adapt_IR_to_Nx4800,
	},
	[OSMO_V110_SYNC_RA1_24000] = {
		.data_rate = 24000,
		.intermediate_rate = 64000,
		.user_data_chunk_bits = 30,
		.adapt_user_to_ir = v110_adapt_Nx12000_to_IR,
		.adapt_ir_to_user = v110_adapt_IR_to_Nx12000,
	},
	[OSMO_V110_SYNC_RA1_28800] = {
		.data_rate = 28800,
		.intermediate_rate = 64000,
		.user_data_chunk_bits = 36,
		.adapt_user_to_ir = v110_adapt_Nx3600_to_IR,
		.adapt_ir_to_user = v110_adapt_IR_to_Nx3600,
	},
	[OSMO_V110_SYNC_RA1_38400] = {
		.data_rate = 38400,
		.intermediate_rate = 64000,
		.user_data_chunk_bits = 48,
		.adapt_user_to_ir = v110_adapt_Nx4800_to_IR,
		.adapt_ir_to_user = v110_adapt_IR_to_Nx4800,
	},
};

/*! obtain the size (in number of bits) of the user data bits in one V.110
 *  frame for specified RA1 rate */
int osmo_v110_sync_ra1_get_user_data_chunk_bitlen(enum osmo_v100_sync_ra1_rate rate)
{
	if (rate < 0 || rate >= _NUM_OSMO_V110_SYNC_RA1)
		return -EINVAL;

	return osmo_v110_sync_ra1_def[rate].user_data_chunk_bits;
}

/*! obtain the user data rate (in bits/s) for specified RA1 rate */
int osmo_v110_sync_ra1_get_user_data_rate(enum osmo_v100_sync_ra1_rate rate)
{
	if (rate < 0 || rate >= _NUM_OSMO_V110_SYNC_RA1)
		return -EINVAL;

	return osmo_v110_sync_ra1_def[rate].data_rate;
}

/*! obtain the intermediate rate (in bits/s) for specified RA1 rate */
int osmo_v110_sync_ra1_get_intermediate_rate(enum osmo_v100_sync_ra1_rate rate)
{
	if (rate < 0 || rate >= _NUM_OSMO_V110_SYNC_RA1)
		return -EINVAL;

	return osmo_v110_sync_ra1_def[rate].intermediate_rate;
}

/*! perform V.110 RA1 function in user rate -> intermediate rate direction.
 *  \param[in] rate specification of the user bitrate
 *  \param[out] fr caller-allocated output buffer for the [decoded] V.110 frame generated
 *  \param[in] d_in input user data (unpacked bits)
 *  \param[in] in_len length of user input data (in number of bits)
 *  \returns 0 on success; negative in case of error */
int osmo_v110_sync_ra1_user_to_ir(enum osmo_v100_sync_ra1_rate rate, struct osmo_v110_decoded_frame *fr,
				  const ubit_t *d_in, size_t in_len)
{
	if (rate < 0 || rate >= _NUM_OSMO_V110_SYNC_RA1)
		return -EINVAL;

	return osmo_v110_sync_ra1_def[rate].adapt_user_to_ir(fr, d_in, in_len);
}

/*! perform V.110 RA1 function in intermediate rate -> user rate direction.
 *  \param[in] rate specification of the user bitrate
 *  \param[out] d_out caller-allocated output user data (unpacked bits)
 *  \param[out] out_len length of d_out output buffer
 *  \param[in] fr [decoded] V.110 frame used as input
 *  \returns number of unpacked bits written to d_out on success; negative in case of error */
int osmo_v110_sync_ra1_ir_to_user(enum osmo_v100_sync_ra1_rate rate, ubit_t *d_out, size_t out_len,
				  const struct osmo_v110_decoded_frame *fr)
{
	if (rate < 0 || rate >= _NUM_OSMO_V110_SYNC_RA1)
		return -EINVAL;

	return osmo_v110_sync_ra1_def[rate].adapt_ir_to_user(d_out, out_len, fr);
}
