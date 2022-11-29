/*************************************************************************
 * GSM CSD modified V.110 frame decoding/encoding (ubits <-> struct with D/S/X/E bits)
 *************************************************************************/

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

#include <errno.h>
#include <osmocom/core/bits.h>
#include <osmocom/isdn/v110.h>

/*! Decode a 60-bit GSM 12kbit/s CSD frame present as 60 ubits into a struct osmo_v110_decoded_frame.
 *  \param[out] caller-allocated output data structure, filled by this function
 *  \param[in] ra_bits One V.110 frame as 60 unpacked bits. */
int osmo_csd_12k_6k_decode_frame(struct osmo_v110_decoded_frame *fr, const ubit_t *ra_bits, size_t n_bits)
{
	/* 3GPP TS 44.021 Section 8.1.2 / 8.1.3
	D1	D2	D3	D4	D5	D6	S1
	D7	D8	D9	D10	D11	D12	X
	D13	D14	D15	D16	D17	D18	S3
	D19	D20	D21	D22	D23	D24	S4
	E4	E5	E6	E7	D25	D26	D27
	D28	D29	D30	S6	D31	D32	D33
	D34	D35	D36	X	D37	D38	D39
	D40	D41	D42	S8	D43	D44	D45
	D46	D47	D48	S9 */

	if (n_bits < 60)
		return -EINVAL;

	/* X1 .. X2 */
	fr->x_bits[0] = ra_bits[1 * 7 + 6];
	fr->x_bits[1] = ra_bits[6 * 7 + 3];

	/* S1, S3, S4, S6, S8, S9 */
	fr->s_bits[0] = ra_bits[0 * 7 + 6];
	fr->s_bits[2] = ra_bits[2 * 7 + 6];
	fr->s_bits[3] = ra_bits[3 * 7 + 6];
	fr->s_bits[5] = ra_bits[5 * 7 + 3];
	fr->s_bits[7] = ra_bits[7 * 7 + 3];
	fr->s_bits[8] = ra_bits[8 * 7 + 3];

	/* E1 .. E3 must be set by out-of-band knowledge! */

	/* E4 .. E7 */
	memcpy(fr->e_bits+3, ra_bits + 4 * 7 + 0, 4);

	/* D-bits */
	memcpy(fr->d_bits + 0 * 6 + 0, ra_bits + 0 * 7 + 0, 6);
	memcpy(fr->d_bits + 1 * 6 + 0, ra_bits + 1 * 7 + 0, 6);
	memcpy(fr->d_bits + 2 * 6 + 0, ra_bits + 2 * 7 + 0, 6);
	memcpy(fr->d_bits + 3 * 6 + 0, ra_bits + 3 * 7 + 0, 6);
	memcpy(fr->d_bits + 4 * 6 + 0, ra_bits + 4 * 7 + 4, 3);
	memcpy(fr->d_bits + 4 * 6 + 3, ra_bits + 5 * 7 + 0, 3);
	memcpy(fr->d_bits + 5 * 6 + 0, ra_bits + 5 * 7 + 4, 3);
	memcpy(fr->d_bits + 5 * 6 + 3, ra_bits + 6 * 7 + 0, 3);
	memcpy(fr->d_bits + 6 * 6 + 0, ra_bits + 6 * 7 + 4, 3);
	memcpy(fr->d_bits + 6 * 6 + 3, ra_bits + 7 * 7 + 0, 3);
	memcpy(fr->d_bits + 7 * 6 + 0, ra_bits + 7 * 7 + 4, 3);
	memcpy(fr->d_bits + 7 * 6 + 3, ra_bits + 8 * 7 + 0, 3);

	return 0;
}

int osmo_csd_12k_6k_encode_frame(ubit_t *ra_bits, size_t ra_bits_size, const struct osmo_v110_decoded_frame *fr)
{
	if (ra_bits_size < 60)
		return -EINVAL;

	/* X1 .. X2 */
	ra_bits[1 * 7 + 6] = fr->x_bits[0];
	ra_bits[6 * 7 + 3] = fr->x_bits[1];

	/* S1, S3, S4, S6, S8, S9 */
	ra_bits[0 * 7 + 6] = fr->s_bits[0];
	ra_bits[2 * 7 + 6] = fr->s_bits[2];
	ra_bits[3 * 7 + 6] = fr->s_bits[3];
	ra_bits[5 * 7 + 3] = fr->s_bits[5];
	ra_bits[7 * 7 + 3] = fr->s_bits[7];
	ra_bits[8 * 7 + 3] = fr->s_bits[8];

	/* E1 .. E3 are dropped */

	/* E4 .. E7 */
	memcpy(ra_bits + 4 * 7 + 0, fr->e_bits+3, 4);

	/* D-bits */
	memcpy(ra_bits + 0 * 7 + 0, fr->d_bits + 0 * 6 + 0, 6);
	memcpy(ra_bits + 1 * 7 + 0, fr->d_bits + 1 * 6 + 0, 6);
	memcpy(ra_bits + 2 * 7 + 0, fr->d_bits + 2 * 6 + 0, 6);
	memcpy(ra_bits + 3 * 7 + 0, fr->d_bits + 3 * 6 + 0, 6);
	memcpy(ra_bits + 4 * 7 + 4, fr->d_bits + 4 * 6 + 0, 3);
	memcpy(ra_bits + 5 * 7 + 0, fr->d_bits + 4 * 6 + 3, 3);
	memcpy(ra_bits + 5 * 7 + 4, fr->d_bits + 5 * 6 + 0, 3);
	memcpy(ra_bits + 6 * 7 + 0, fr->d_bits + 5 * 6 + 3, 3);
	memcpy(ra_bits + 6 * 7 + 4, fr->d_bits + 6 * 6 + 0, 3);
	memcpy(ra_bits + 7 * 7 + 0, fr->d_bits + 6 * 6 + 3, 3);
	memcpy(ra_bits + 7 * 7 + 4, fr->d_bits + 7 * 6 + 0, 3);
	memcpy(ra_bits + 8 * 7 + 0, fr->d_bits + 7 * 6 + 3, 3);

	return 60;
}

/*! Decode a 36-bit GSM 3k6kbit/s CSD frame present as 36 ubits into a struct osmo_v110_decoded_frame.
 *  \param[out] caller-allocated output data structure, filled by this function
 *  \param[in] ra_bits One V.110 frame as 36 unpacked bits. */
int osmo_csd_3k6_decode_frame(struct osmo_v110_decoded_frame *fr, const ubit_t *ra_bits, size_t n_bits)
{

	/* 3GPP TS 44.021 Section 8.1.4
	D1	D2	D3	S1	D4	D5	D6	X
	D7	D8	D9	S3	D10	D11	D12	S4
	E4	E5	E6	E7	D13	D14	D15	S6
	D16	D17	D18	X	D19	D20	D21	S8
	D22	D23	D24	S9
	*/

	if (n_bits < 36)
		return -EINVAL;

	/* X1 .. X2 */
	fr->x_bits[0] = ra_bits[0 * 8 + 7];
	fr->x_bits[1] = ra_bits[3 * 8 + 3];

	/* S1, S3, S4, S6, S8, S9 */
	fr->s_bits[0] = ra_bits[0 * 8 + 3];
	fr->s_bits[2] = ra_bits[1 * 8 + 3];
	fr->s_bits[3] = ra_bits[1 * 8 + 7];
	fr->s_bits[5] = ra_bits[2 * 8 + 7];
	fr->s_bits[7] = ra_bits[3 * 8 + 7];
	fr->s_bits[8] = ra_bits[4 * 8 + 3];

	/* E1 .. E3 must be set by out-of-band knowledge! */

	/* E4 .. E7 */
	memcpy(fr->e_bits+3, ra_bits + 2 * 8 + 0, 4);

	/* D-bits */
	unsigned int d_idx = 0;
	fr->d_bits[d_idx++] = ra_bits[0 * 8 + 0];	/* D1 */
	fr->d_bits[d_idx++] = ra_bits[0 * 8 + 0];	/* D1 */
	fr->d_bits[d_idx++] = ra_bits[0 * 8 + 1];	/* D2 */
	fr->d_bits[d_idx++] = ra_bits[0 * 8 + 1];	/* D2 */
	fr->d_bits[d_idx++] = ra_bits[0 * 8 + 2];	/* D3 */
	fr->d_bits[d_idx++] = ra_bits[0 * 8 + 2];	/* D3 */
	fr->d_bits[d_idx++] = ra_bits[0 * 8 + 4];	/* D4 */
	fr->d_bits[d_idx++] = ra_bits[0 * 8 + 4];	/* D4 */
	fr->d_bits[d_idx++] = ra_bits[0 * 8 + 5];	/* D5 */
	fr->d_bits[d_idx++] = ra_bits[0 * 8 + 5];	/* D5 */
	fr->d_bits[d_idx++] = ra_bits[0 * 8 + 6];	/* D6 */
	fr->d_bits[d_idx++] = ra_bits[0 * 8 + 6];	/* D6 */

	fr->d_bits[d_idx++] = ra_bits[1 * 8 + 0];	/* D7 */
	fr->d_bits[d_idx++] = ra_bits[1 * 8 + 0];	/* D7 */
	fr->d_bits[d_idx++] = ra_bits[1 * 8 + 1];	/* D8 */
	fr->d_bits[d_idx++] = ra_bits[1 * 8 + 1];	/* D8 */
	fr->d_bits[d_idx++] = ra_bits[1 * 8 + 2];	/* D9 */
	fr->d_bits[d_idx++] = ra_bits[1 * 8 + 2];	/* D9 */
	fr->d_bits[d_idx++] = ra_bits[1 * 8 + 4];	/* D10 */
	fr->d_bits[d_idx++] = ra_bits[1 * 8 + 4];	/* D10 */
	fr->d_bits[d_idx++] = ra_bits[1 * 8 + 5];	/* D11 */
	fr->d_bits[d_idx++] = ra_bits[1 * 8 + 5];	/* D11 */
	fr->d_bits[d_idx++] = ra_bits[1 * 8 + 6];	/* D12 */
	fr->d_bits[d_idx++] = ra_bits[1 * 8 + 6];	/* D12 */

	fr->d_bits[d_idx++] = ra_bits[2 * 8 + 4];	/* D13 */
	fr->d_bits[d_idx++] = ra_bits[2 * 8 + 4];	/* D13 */
	fr->d_bits[d_idx++] = ra_bits[2 * 8 + 5];	/* D14 */
	fr->d_bits[d_idx++] = ra_bits[2 * 8 + 5];	/* D14 */
	fr->d_bits[d_idx++] = ra_bits[2 * 8 + 6];	/* D15 */
	fr->d_bits[d_idx++] = ra_bits[2 * 8 + 6];	/* D15 */

	fr->d_bits[d_idx++] = ra_bits[3 * 8 + 0];	/* D16 */
	fr->d_bits[d_idx++] = ra_bits[3 * 8 + 0];	/* D16 */
	fr->d_bits[d_idx++] = ra_bits[3 * 8 + 1];	/* D17 */
	fr->d_bits[d_idx++] = ra_bits[3 * 8 + 1];	/* D17 */
	fr->d_bits[d_idx++] = ra_bits[3 * 8 + 2];	/* D18 */
	fr->d_bits[d_idx++] = ra_bits[3 * 8 + 2];	/* D18 */
	fr->d_bits[d_idx++] = ra_bits[3 * 8 + 4];	/* D19 */
	fr->d_bits[d_idx++] = ra_bits[3 * 8 + 4];	/* D19 */
	fr->d_bits[d_idx++] = ra_bits[3 * 8 + 5];	/* D20 */
	fr->d_bits[d_idx++] = ra_bits[3 * 8 + 5];	/* D20 */
	fr->d_bits[d_idx++] = ra_bits[3 * 8 + 6];	/* D21 */
	fr->d_bits[d_idx++] = ra_bits[3 * 8 + 6];	/* D21 */

	fr->d_bits[d_idx++] = ra_bits[4 * 8 + 0];	/* D22 */
	fr->d_bits[d_idx++] = ra_bits[4 * 8 + 0];	/* D22 */
	fr->d_bits[d_idx++] = ra_bits[4 * 8 + 1];	/* D23 */
	fr->d_bits[d_idx++] = ra_bits[4 * 8 + 1];	/* D23 */
	fr->d_bits[d_idx++] = ra_bits[4 * 8 + 2];	/* D24 */
	fr->d_bits[d_idx++] = ra_bits[4 * 8 + 2];	/* D24 */

	OSMO_ASSERT(d_idx == 48);

	return 0;
}

int osmo_csd_3k6_encode_frame(ubit_t *ra_bits, size_t ra_bits_size, const struct osmo_v110_decoded_frame *fr)
{
	if (ra_bits_size < 36)
		return -EINVAL;

	/* X1 .. X2 */
	ra_bits[0 * 8 + 7] = fr->x_bits[0];
	ra_bits[3 * 8 + 3] = fr->x_bits[1];

	/* S1, S3, S4, S6, S8, S9 */
	ra_bits[0 * 8 + 3] = fr->s_bits[0];
	ra_bits[1 * 8 + 3] = fr->s_bits[2];
	ra_bits[1 * 8 + 7] = fr->s_bits[3];
	ra_bits[2 * 8 + 7] = fr->s_bits[5];
	ra_bits[3 * 8 + 7] = fr->s_bits[7];
	ra_bits[4 * 8 + 3] = fr->s_bits[8];

	/* E1 .. E3 are ignored */

	/* E4 .. E7 */
	memcpy(ra_bits + 2 * 8 + 0, fr->e_bits+3, 4);

	/* D-bits */
	unsigned int d_idx = 0;
	ra_bits[0 * 8 + 0] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[0 * 8 + 1] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[0 * 8 + 2] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[0 * 8 + 4] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[0 * 8 + 5] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[0 * 8 + 6] = fr->d_bits[d_idx]; d_idx += 2;

	ra_bits[1 * 8 + 0] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[1 * 8 + 1] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[1 * 8 + 2] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[1 * 8 + 4] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[1 * 8 + 5] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[1 * 8 + 6] = fr->d_bits[d_idx]; d_idx += 2;

	ra_bits[2 * 8 + 4] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[2 * 8 + 5] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[2 * 8 + 6] = fr->d_bits[d_idx]; d_idx += 2;

	ra_bits[3 * 8 + 0] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[3 * 8 + 1] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[3 * 8 + 2] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[3 * 8 + 4] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[3 * 8 + 5] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[3 * 8 + 6] = fr->d_bits[d_idx]; d_idx += 2;

	ra_bits[4 * 8 + 0] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[4 * 8 + 1] = fr->d_bits[d_idx]; d_idx += 2;
	ra_bits[4 * 8 + 2] = fr->d_bits[d_idx]; d_idx += 2;

	OSMO_ASSERT(d_idx == 48);

	return 36;
}

/*! Print a encoded "CSD modififed V.110" frame in the same table-like structure as the spec.
 *  \param outf output FILE stream to which to dump
 *  \param[in] fr unpacked bits to dump
 *  \param[in] in_len length of unpacked bits available at fr. */
void osmo_csd_ubit_dump(FILE *outf, const ubit_t *fr, size_t in_len)
{
	switch (in_len) {
	case 60:
		for (unsigned int septet = 0; septet < 9; septet++) {
			if (septet < 8) {
				fprintf(outf, "%d\t%d\t%d\t%d\t%d\t%d\t%d\n", fr[septet * 7 + 0],
					fr[septet * 7 + 1], fr[septet * 7 + 2], fr[septet * 7 + 3],
					fr[septet * 7 + 4], fr[septet * 7 + 5], fr[septet*7 + 6]);
			} else {
				fprintf(outf, "%d\t%d\t%d\t%d\n", fr[septet * 7 + 0],
					fr[septet * 7 + 1], fr[septet * 7 + 2], fr[septet * 7 + 3]);
			}
		}
		break;
	case 36:
		for (unsigned int octet = 0; octet < 5; octet++) {
			if (octet < 4) {
				fprintf(outf, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
					fr[octet * 8 + 0], fr[octet * 8 + 1], fr[octet * 8 + 2],
					fr[octet * 8 + 3], fr[octet * 8 + 4], fr[octet * 8 + 5],
					fr[octet * 8 + 6], fr[octet * 8 + 7]);
			} else {
				fprintf(outf, "%d\t%d\t%d\t%d\n", fr[octet * 8 + 0],
					fr[octet * 8 + 1], fr[octet * 8 + 2], fr[octet * 8 + 3]);
			}
		}
		break;
	default:
		fprintf(outf, "invalid input data length: %zu\n", in_len);
	}
}
