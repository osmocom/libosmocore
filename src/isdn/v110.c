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
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>

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

	/* Table 6c / V.110 */
	if (fr->e_bits[0] != 1 || fr->e_bits[1] != 1 || fr->e_bits[2] != 0)
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

/*********************************************************************************
 * V.110 TERMINAL ADAPTER FSMs
 *********************************************************************************/

enum v110_ta_state {
	V110_TA_S_IDLE_READY,		/* Idle (or ready) state */
	V110_TA_S_CON_TA_LINE,		/* Connect TA to line state */
	V110_TA_S_DATA_TRANSFER,	/* Data transfer state */
	V110_TA_S_RESYNCING,		/* Re-synchronizing state */
};

enum v110_ta_event {
	V110_TA_E_RX_FRAME_IND,		/* Received V.110 frame indication */
	V110_TA_E_TX_FRAME_RTS,		/* V.110 frame Ready-to-send indication */
};

static const struct value_string v110_ta_event_names[] = {
	{ V110_TA_E_RX_FRAME_IND,	"RX_FRAME_IND" },
	{ V110_TA_E_TX_FRAME_RTS,	"TX_FRAME_RTS" },
	{ 0, NULL }
};

enum v110_ta_tx_d_bit_mode {
	V110_TA_TX_FRAME_ALL_ONE,
	V110_TA_TX_FRAME_ALL_ZERO,
	V110_TA_TX_FRAME_FROM_DTE,
};

struct v110_ta_state {
	/* V.24 status flags shared between DTE (user) and DCE (TA, us) */
	v24_flagmask	v24_flags;
	struct {
		/* is end-to-end flow-control enabled or not? */
		bool end_to_end_flowctrl;
		/* synchronous user rate */
		enum osmo_v100_sync_ra1_rate rate;
	} cfg;
	struct {
		/* what kind of D-bits to transmit in V.110 frames */
		enum v110_ta_tx_d_bit_mode d_bit_mode;
		/* what to put in S-bits of transmitted V.110 frames (true = ON) */
		bool s_bits;
		/* what to put in X-bits of transmitted V.110 frames (true = OFF) */
		bool x_bits;
		/* what to put in E-bits of transmitted V.110 frames */
		ubit_t e_bits[MAX_E_BITS];
	} tx;
	struct { 
		enum v11o_ta_tx_d_bit_mode bit_mode;
	} rx;
};

/* build one V.110 frame to transmit */
static void v110_ta_build_frame(struct osmo_v110_decoded_frame *out, struct osmo_fsm_inst *fi)
{
	struct v110_ta_state *ts = (struct v110_ta_state *) fi->priv;

	/* D-bits */
	switch (ts->tx.d_bit_mode) {
	case V110_TA_TX_FRAME_ALL_ONE:
		memset(out->d_bits, 1, sizeof(out->d_bits));
		break;
	case V110_TA_TX_FRAME_ALL_ZERO:
		memset(out->d_bits, 0, sizeof(out->d_bits));
		break;
	case V110_TA_TX_FRAME_FROM_DTE:
		//FIXME: retrieve user bits */
		rc = osmo_v110_sync_ra1_user_to_ir(ts->cfg.rate, out, user_bits, num_user_bits);
		OSMO_ASSERT(rc == 0);
		break;
	};

	/* E-bits */
	memcpy(out->e_bits, ts->tx.e_bits, sizeof(out->e_bits));

	/* S-bits */
	if (ts->tx.s_bits == true)
		memset(out->s_bits, 0, sizeof(out->s_bits));
	else
		memset(out->s_bits, 1, sizeof(out->s_bits));

	/* X-bits */
	if (ts->tx.x_bits == true)
		memset(out->x_bits, 0, sizeof(out->x_bits));
	else
		memset(out->x_bits, 1, sizeof(out->x_bits));
}

static void v24_flags_updated(struct osmo_fsm_inst *fi)
{
	/* FIXME: somehow notify the USART about it */
}

/* ITU-T V.110 Section 7.1.1 */
static void v110fsm_ta_idle_ready_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state);
{
	struct v110_ta_state *ts = (struct v110_ta_state *) fi->priv;

	/* E4 .. E7 bits (lower 3 bits are generated by v110 frame encoder) */
	memset(ts->tx.e_bits+3, 1, 4);
	ts->user_data_cunk_bitlen = osmo_v110_sync_ra1_get_user_data_chunk_bitlen(ts->cfg.rate);

	/* 7.1.1.2 During the idle (or ready) state the TA will transmit continuous binary 1s into the B-channel */
	/* 7.1.1.3 During the idle (or ready) state the TA (DCE) will transmit the following toward the DTE: * */
	/* - 104: continuous binary 1*/
	ts->rx.bit_mode = V110_TA_TX_FRAME_ALL_ONE;
	/* - 107, 106, 109 = OFF */
	V24_FLAGMASK_SET_OFF(ts->v24_flags, OSMO_V24_C_106);
	V24_FLAGMASK_SET_OFF(ts->v24_flags, OSMO_V24_C_107);
	V24_FLAGMASK_SET_OFF(ts->v24_flags, OSMO_V24_C_109);
	v24_flags_updated(fi);
}

/* ITU-T V.110 Section 7.1.1 */
static void v110fsm_ta_idle_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct v110_ta_state *ts = (struct v110_ta_state *) fi->priv;
	const struct osmo_v110_decoded_frame *fr = NULL;
	int rc;

	switch (event) {
	case V110_TA_E_RX_FRAME_IND:
		fr = data;
		rc = osmo_v110_sync_ra1_ir_to_user(ts->cfg.rate, d_out, out_len, fr);
		break;
	case V110_TA_E_TX_FRAME_RTS:
		/* transmit continuous binary 1 to B channels */
		break;
	case V110_TA_E_SWITCH_TO_DATA_MODE:
		/* When the TA is to be switched to the data mode, circuit 108 must be ON */
		if (V24_FLAGMASK_IS_ON(ts->v24_flags, OSMO_V24_C_108_2)) {
			/* 7.12.2: Start timer T1 when switching to CON_TA_LINE */
			osmo_fsm_inst_state_chg(fi, V110_TA_S_CON_TA_LINE, 10, 1);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* ITU-t V.110 Section 7.1.2 */
static void v110fsm_ta_connect_to_line_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state);
{
	struct v110_ta_state *ts = (struct v110_ta_state *) fi->priv;

	/* frame sync pattern as per 5.1.3.1 / 5.2.1 */
	FIXME
	/* data bits: binary 1 */
	ts->tx.d_bit_mode = V110_TA_TX_FRAME_ALL_ONE;
	/* S = OFF, X = OFF (ON = binary 0; OFF = binary 1) */
	ts->tx.s_bits = false;
	ts->tx.x_bits = false;
	/* onenter: T1 has been started */
	OSMO_ASSERT(fi->T = 1);
}

static bool all_bits_are(const ubit_t *in, ubit_t cmp, size_t in_len)
{
	for (unsigned int i = 0; i < in_len; i++) {
		if (in[i] != cmp)
			return false;
	}
	return true;
}
#define ARRAY_ALL_BITS_ONE(arr)		all_bits_are((arr), 1, sizeof(arr))
#define ARRAY_ALL_BITS_ZERO(arr)	all_bits_are((arr), 0, sizeof(arr))

/* ITU-t V.110 Section 7.1.2 */
static void v110fsm_ta_connect_ta_to_line(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct v110_ta_state *ts = (struct v110_ta_state *) fi->priv;
	struct osmo_v110_decoded_frame *fr = NULL;

	switch (event) {
	case V110_TA_E_RX_FRAME_IND:
		fr = data;
		if (ARRAY_ALL_BITS_ZERO(fr->s_bits) && ARRAY_ALL_BITS_ZERO(fr->x_bits)) {
			/* 7.1.2.4 When the receiver recognizes that the status of bits S and X are in the ON
			 * condition, it will perform the following functions: */
			/* a) Turn ON circuit 107 toward the DTE and stop timer T1. */
			V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V24_C_107);
			/* b) Then, circuit 103 may be connected to the data bits in the frame; however, the
			 * DTE must maintain a binary 1 condition on circuit 103 until circuit 106 is turned
			 * ON in the next portion of the sequence. */
			/* c) Turn ON circuit 109 and connect the data bits to circuit 104. */
			V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V24_C_109);
			/* d) After an interval of N bits (see 6.3), it will turn ON circuit 106. */
			V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V24_C_106);
			v24_flags_updated(fi);
			/* Circuit 106 transitioning from OFF to ON will cause the transmitted data to
			 * transition from binary 1 to the data mode. */
			osmo_fsm_inst_state_chg(fi, V110_TA_S_DATA_XFER, 0, 0);

			rc = osmo_v110_sync_ra1_ir_to_user(ts->cfg.rate, d_out, out_len, fr);
		}
		break;
	case V110_TA_E_TX_FRAME_RTS:
		fr = data;
		v110_ta_build_frame(fr, fi);
		break;
	case V110_TA_E_RX_SYNC_IND:
		/* 7.1.2.3 When the receiver recognizes the frame synchronization pattern, it causes the S-
		 * and X-bits in the transmitted frames to be turned ON (provided that circuit 108 is ON). */
		if (V24_FLAGMASK_IS_ON(ts->v24_flags, OSMO_V24_C_108_2)) {
			ts->tx.s_bits = true;
			ts->tx.x_bits = true;
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* ITU-t V.110 Section 7.1.3 */
static void v110fsm_ta_data_transfer_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct v110_ta_state *ts = (struct v110_ta_state *) fi->priv;

	ts->tx.d_bit_mode = V110_TA_TX_FRAME_FROM_DTE;

	/* 7.1.3.1 a): 105, 107, 108/1, 108/2 and 109 are in the ON condition */
	V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V24_C_105);
	V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V24_C_107);
	V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V24_C_108_1);
	V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V24_C_108_2);
	V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V24_C_109);
	/* 7.1.3.1 c): 133 (when implemented) and 106 are in the ON condition unless local out-of-band
	   flow control is being used, either or both circuits may be in the ON or the OFF condition. */
	if (!ts->cfg.end_to_end_flowctrl) {
		V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V24_C_133);
		V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V24_C_106);
	}
	v24_flags_updated(fi);
	/* 7.1.3.2 While in the data transfer state, the following status bit conditions exist: */
	/* a) status bits S in both directions are in the ON condition; */
	ts->tx.s_bits = true;
	/* b) status bits X in both directions are in the ON condition unless end-to-end flow control is
	      being used, in which case status bit X in either or both directions may be in the ON or the OFF
	      condition. */
	if (!ts->cfg.end_to_end_flowctrl) {
		ts->tx.x_bits = true;
	}
}

/* ITU-t V.110 Section 7.1.3 */
static void v110fsm_ta_data_transfer(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct v110_ta_state *ts = (struct v110_ta_state *) fi->priv;
	struct osmo_v110_decoded_frame *fr = NULL;

	switch (event) {
	case V110_TA_E_RX_V24_STATUS_CHG:
		/* 7.1.4.1 At the completion of the data transfer phase, the local DTE will indicate a
		 * disconnect request by turning OFF circuit 108 */
		if (V24_FLAGMASK_IS_OFF(ts->v24_flags, OSMO_V24_C_108_2)) {
			/* a) the status bits S in the frame toward ISDN will turn OFF, status bits X are kept ON */
			ts->tx.s_bits = false;
			/* b) circuit 106 will be turned OFF */
			V24_FLAGMASK_SET_OFF(ts->v24_flags, OSMO_V24_C_106);
			v24_flags_updated(fi);
			/* c) the data bits in the frame will be set to binary 0. */
			ts->tx.d_bit_mode = V110_TA_TX_FRAME_ALL_ZERO;
			/* to guard against the failure of the remote TA to respond to the disconnect request,
			 * the local TA may start a timer T2 (suggested value 5 s) which is stopped by the
			 * reception or transmission of any D-channel clearing message (DISCONNECT, RELEASE,
			 * RELEASE COMPLETE) */
			osmo_fsm_inst_state_chg(fi, V110_TA_S_WAIT_DISC_CONF, 5, 2);
		}
		break;
	case V110_TA_E_TX_FRAME_RTS:
		fr = data;
		v110_ta_build_frame(fr, fi);
		break;
	case V110_TA_E_RX_FRAME_IND:
		fr = data;
		rc = osmo_v110_sync_ra1_ir_to_user(ts->cfg.rate, d_out, out_len, fr);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int v110_ta_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->T) {
	case 1:	/* T1: wait for sync pattern */
		break;
	case 2: /* T2: wait for response to disconnect */
		break;
	}
}

static const struct osmo_fsm_state v110_ta_states[] = {
	[V110_TA_S_IDLE_READY] = {
		.name = "IDLE_READY",
		.in_event_mask = S(V110_TA_E_TX_FRAME_RTS),
		.out_state_mask = S(V110_TA_S_CON_TA_LINE),
		.action = v110fsm_ta_idle_ready,
		.ontenter = v110fsm_ta_idle_ready_onenter,
	},
	[V110_TA_S_CON_TA_LINE] = {
		.name = "CONNECT_TA_TO_LINE",
		.in_event_mask = S(V110_TA_E_TX_FRAME_RTS),
		.out_state_mask = S(V110_TA_S_IDLE_READY) |
				  S(V110_TA_S_DATA_TRANSFER),
		.action = v110fsm_ta_connect_ta_to_line,
		.ontenter = v110fsm_ta_connect_ta_to_line_onenter,
	},
	[V110_TA_S_DATA_TRANSFER] = {
		.name = "DATA_TRANSFER",
		.in_event_mask = ,
		.out_state_mask = ,
		.action = v110fsm_ta_data_transfer,
		.onenter = v110fsm_ta_data_transfer_onenter,
	},
};

static struct osmo_fsm osmo_v110_ta_fsm = {
	.name = "V110-TA",
	.states = v110_ta_states,
	.num_states = ARRAY_SIZE(v110_ta_states),
	.allstate_event_mask = FIXME,
	.allstate_action = FIXME,
	.timer_cb = v110_ta_timer_cb,
	.log_subsys = FIXME,
	.event_names = v110_ta_event_names,
};
