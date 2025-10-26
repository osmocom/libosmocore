/*! \file gsm690.c
 * GSM 06.90 - GSM AMR Codec. */
/*
 * (C) 2010 Sylvain Munaut <tnt@246tNt.com>
 * (C) 2020 Harald Welte <laforge@gnumonks.org>
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/bits.h>
#include <osmocom/codec/codec.h>
/*
 * These table map between the raw encoder parameter output and
 * the format used before channel coding. Both in GSM and in various
 * file/network format (same tables used in several specs).
 */

/* AMR 12.2 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 7
	 * It's also TS 26.101 Table B.8
	 */
const uint16_t gsm690_12_2_bitorder[244] = {
	  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
	 10,  11,  12,  13,  14,  23,  15,  16,  17,  18,
	 19,  20,  21,  22,  24,  25,  26,  27,  28,  38,
	141,  39, 142,  40, 143,  41, 144,  42, 145,  43,
	146,  44, 147,  45, 148,  46, 149,  47,  97, 150,
	200,  48,  98, 151, 201,  49,  99, 152, 202,  86,
	136, 189, 239,  87, 137, 190, 240,  88, 138, 191,
	241,  91, 194,  92, 195,  93, 196,  94, 197,  95,
	198,  29,  30,  31,  32,  33,  34,  35,  50, 100,
	153, 203,  89, 139, 192, 242,  51, 101, 154, 204,
	 55, 105, 158, 208,  90, 140, 193, 243,  59, 109,
	162, 212,  63, 113, 166, 216,  67, 117, 170, 220,
	 36,  37,  54,  53,  52,  58,  57,  56,  62,  61,
	 60,  66,  65,  64,  70,  69,  68, 104, 103, 102,
	108, 107, 106, 112, 111, 110, 116, 115, 114, 120,
	119, 118, 157, 156, 155, 161, 160, 159, 165, 164,
	163, 169, 168, 167, 173, 172, 171, 207, 206, 205,
	211, 210, 209, 215, 214, 213, 219, 218, 217, 223,
	222, 221,  73,  72,  71,  76,  75,  74,  79,  78,
	 77,  82,  81,  80,  85,  84,  83, 123, 122, 121,
	126, 125, 124, 129, 128, 127, 132, 131, 130, 135,
	134, 133, 176, 175, 174, 179, 178, 177, 182, 181,
	180, 185, 184, 183, 188, 187, 186, 226, 225, 224,
	229, 228, 227, 232, 231, 230, 235, 234, 233, 238,
	237, 236,  96, 199,
};

/* AMR 10.2 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 8
	 * It's also TS 26.101 Table B.7
	 */
const uint16_t gsm690_10_2_bitorder[204] = {
	  7,   6,   5,   4,   3,   2,   1,   0,  16,  15,
	 14,  13,  12,  11,  10,   9,   8,  26,  27,  28,
	 29,  30,  31, 115, 116, 117, 118, 119, 120,  72,
	 73, 161, 162,  65,  68,  69, 108, 111, 112, 154,
	157, 158, 197, 200, 201,  32,  33, 121, 122,  74,
	 75, 163, 164,  66, 109, 155, 198,  19,  23,  21,
	 22,  18,  17,  20,  24,  25,  37,  36,  35,  34,
	 80,  79,  78,  77, 126, 125, 124, 123, 169, 168,
	167, 166,  70,  67,  71, 113, 110, 114, 159, 156,
	160, 202, 199, 203,  76, 165,  81,  82,  92,  91,
	 93,  83,  95,  85,  84,  94, 101, 102,  96, 104,
	 86, 103,  87,  97, 127, 128, 138, 137, 139, 129,
	141, 131, 130, 140, 147, 148, 142, 150, 132, 149,
	133, 143, 170, 171, 181, 180, 182, 172, 184, 174,
	173, 183, 190, 191, 185, 193, 175, 192, 176, 186,
	 38,  39,  49,  48,  50,  40,  52,  42,  41,  51,
	 58,  59,  53,  61,  43,  60,  44,  54, 194, 179,
	189, 196, 177, 195, 178, 187, 188, 151, 136, 146,
	153, 134, 152, 135, 144, 145, 105,  90, 100, 107,
	 88, 106,  89,  98,  99,  62,  47,  57,  64,  45,
	 63,  46,  55,  56,
};

/* AMR 7.95 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 9
	 * It's also TS 26.101 Table B.6
	 */
const uint16_t gsm690_7_95_bitorder[159] = {
	  8,   7,   6,   5,   4,   3,   2,  14,  16,   9,
	 10,  12,  13,  15,  11,  17,  20,  22,  24,  23,
	 19,  18,  21,  56,  88, 122, 154,  57,  89, 123,
	155,  58,  90, 124, 156,  52,  84, 118, 150,  53,
	 85, 119, 151,  27,  93,  28,  94,  29,  95,  30,
	 96,  31,  97,  61, 127,  62, 128,  63, 129,  59,
	 91, 125, 157,  32,  98,  64, 130,   1,   0,  25,
	 26,  33,  99,  34, 100,  65, 131,  66, 132,  54,
	 86, 120, 152,  60,  92, 126, 158,  55,  87, 121,
	153, 117, 116, 115,  46,  78, 112, 144,  43,  75,
	109, 141,  40,  72, 106, 138,  36,  68, 102, 134,
	114, 149, 148, 147, 146,  83,  82,  81,  80,  51,
	 50,  49,  48,  47,  45,  44,  42,  39,  35,  79,
	 77,  76,  74,  71,  67, 113, 111, 110, 108, 105,
	101, 145, 143, 142, 140, 137, 133,  41,  73, 107,
	139,  37,  69, 103, 135,  38,  70, 104, 136,
};

/* AMR 7.4 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 10
	 * It's also TS 26.101 Table B.5
	 */
const uint16_t gsm690_7_4_bitorder[148] = {
	  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
	 10,  11,  12,  13,  14,  15,  16,  26,  87,  27,
	 88,  28,  89,  29,  90,  30,  91,  51,  80, 112,
	141,  52,  81, 113, 142,  54,  83, 115, 144,  55,
	 84, 116, 145,  58, 119,  59, 120,  21,  22,  23,
	 17,  18,  19,  31,  60,  92, 121,  56,  85, 117,
	146,  20,  24,  25,  50,  79, 111, 140,  57,  86,
	118, 147,  49,  78, 110, 139,  48,  77,  53,  82,
	114, 143, 109, 138,  47,  76, 108, 137,  32,  33,
	 61,  62,  93,  94, 122, 123,  41,  42,  43,  44,
	 45,  46,  70,  71,  72,  73,  74,  75, 102, 103,
	104, 105, 106, 107, 131, 132, 133, 134, 135, 136,
	 34,  63,  95, 124,  35,  64,  96, 125,  36,  65,
	 97, 126,  37,  66,  98, 127,  38,  67,  99, 128,
	 39,  68, 100, 129,  40,  69, 101, 130,
};

/* AMR 6.7 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 11
	 * It's also TS 26.101 Table B.4
	 */
const uint16_t gsm690_6_7_bitorder[134] = {
	  0,   1,   4,   3,   5,   6,  13,   7,   2,   8,
	  9,  11,  15,  12,  14,  10,  28,  82,  29,  83,
	 27,  81,  26,  80,  30,  84,  16,  55, 109,  56,
	110,  31,  85,  57, 111,  48,  73, 102, 127,  32,
	 86,  51,  76, 105, 130,  52,  77, 106, 131,  58,
	112,  33,  87,  19,  23,  53,  78, 107, 132,  21,
	 22,  18,  17,  20,  24,  25,  50,  75, 104, 129,
	 47,  72, 101, 126,  54,  79, 108, 133,  46,  71,
	100, 125, 128, 103,  74,  49,  45,  70,  99, 124,
	 42,  67,  96, 121,  39,  64,  93, 118,  38,  63,
	 92, 117,  35,  60,  89, 114,  34,  59,  88, 113,
	 44,  69,  98, 123,  43,  68,  97, 122,  41,  66,
	 95, 120,  40,  65,  94, 119,  37,  62,  91, 116,
	 36,  61,  90, 115,
};

/* AMR 5.9 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 12
	 * It's also TS 26.101 Table B.3
	 */
const uint16_t gsm690_5_9_bitorder[118] = {
	  0,   1,   4,   5,   3,   6,   7,   2,  13,  15,
	  8,   9,  11,  12,  14,  10,  16,  28,  74,  29,
	 75,  27,  73,  26,  72,  30,  76,  51,  97,  50,
	 71,  96, 117,  31,  77,  52,  98,  49,  70,  95,
	116,  53,  99,  32,  78,  33,  79,  48,  69,  94,
	115,  47,  68,  93, 114,  46,  67,  92, 113,  19,
	 21,  23,  22,  18,  17,  20,  24, 111,  43,  89,
	110,  64,  65,  44,  90,  25,  45,  66,  91, 112,
	 54, 100,  40,  61,  86, 107,  39,  60,  85, 106,
	 36,  57,  82, 103,  35,  56,  81, 102,  34,  55,
	 80, 101,  42,  63,  88, 109,  41,  62,  87, 108,
	 38,  59,  84, 105,  37,  58,  83, 104,
};

/* AMR 5.15 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 13
	 * It's also TS 26.101 Table B.2
	 */
const uint16_t gsm690_5_15_bitorder[103] = {
	  7,   6,   5,   4,   3,   2,   1,   0,  15,  14,
	 13,  12,  11,  10,   9,   8,  23,  24,  25,  26,
	 27,  46,  65,  84,  45,  44,  43,  64,  63,  62,
	 83,  82,  81, 102, 101, 100,  42,  61,  80,  99,
	 28,  47,  66,  85,  18,  41,  60,  79,  98,  29,
	 48,  67,  17,  20,  22,  40,  59,  78,  97,  21,
	 30,  49,  68,  86,  19,  16,  87,  39,  38,  58,
	 57,  77,  35,  54,  73,  92,  76,  96,  95,  36,
	 55,  74,  93,  32,  51,  33,  52,  70,  71,  89,
	 90,  31,  50,  69,  88,  37,  56,  75,  94,  34,
	 53,  72,  91,
};

/* AMR 4.75 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 14
	 * It's also TS 26.101 Table B.1
	 */
const uint16_t gsm690_4_75_bitorder[95] = {
	  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
	 10,  11,  12,  13,  14,  15,  23,  24,  25,  26,
	 27,  28,  48,  49,  61,  62,  82,  83,  47,  46,
	 45,  44,  81,  80,  79,  78,  17,  18,  20,  22,
	 77,  76,  75,  74,  29,  30,  43,  42,  41,  40,
	 38,  39,  16,  19,  21,  50,  51,  59,  60,  63,
	 64,  72,  73,  84,  85,  93,  94,  32,  33,  35,
	 36,  53,  54,  56,  57,  66,  67,  69,  70,  87,
	 88,  90,  91,  34,  55,  68,  89,  37,  58,  71,
	 92,  31,  52,  65,  86,
};

/*! These constants refer to the length of one "AMR core frame" as per
 *  TS 26.101 Section 4.2.2 / Table 2. */
const uint8_t gsm690_bitlength[AMR_NO_DATA+1] = {
	[AMR_4_75] = 95,
	[AMR_5_15] = 103,
	[AMR_5_90] = 118,
	[AMR_6_70] = 134,
	[AMR_7_40] = 148,
	[AMR_7_95] = 159,
	[AMR_10_2] = 204,
	[AMR_12_2] = 244,
	[AMR_SID] = 39,
};

struct ts26101_reorder_table {
	/*! Table as per TS 26.101 Annex B to compute d-bits from s-bits */
	const uint16_t *s_to_d;
	/*! size of table */
	uint8_t len;
};

static const struct ts26101_reorder_table ts26101_reorder_tables[8] = {
	[AMR_4_75] = {
		.s_to_d = gsm690_4_75_bitorder,
		.len = ARRAY_SIZE(gsm690_4_75_bitorder),
	},
	[AMR_5_15] = {
		.s_to_d = gsm690_5_15_bitorder,
		.len = ARRAY_SIZE(gsm690_5_15_bitorder),
	},
	[AMR_5_90] = {
		.s_to_d = gsm690_5_9_bitorder,
		.len = ARRAY_SIZE(gsm690_5_9_bitorder),
	},
	[AMR_6_70] = {
		.s_to_d = gsm690_6_7_bitorder,
		.len = ARRAY_SIZE(gsm690_6_7_bitorder),
	},
	[AMR_7_40] = {
		.s_to_d = gsm690_7_4_bitorder,
		.len = ARRAY_SIZE(gsm690_7_4_bitorder),
	},
	[AMR_7_95] = {
		.s_to_d = gsm690_7_95_bitorder,
		.len = ARRAY_SIZE(gsm690_7_95_bitorder),
	},
	[AMR_10_2] = {
		.s_to_d = gsm690_10_2_bitorder,
		.len = ARRAY_SIZE(gsm690_10_2_bitorder),
	},
	[AMR_12_2] = {
		.s_to_d = gsm690_12_2_bitorder,
		.len = ARRAY_SIZE(gsm690_12_2_bitorder),
	},
};

/*! Convert from S-bits (codec output) to d-bits.
 *  \param[out] out user-provided output buffer for generated unpacked d-bits
 *  \param[in] in input buffer for unpacked s-bits
 *  \param[in] n_bits number of bits (in both in and out)
 *  \param[in] AMR mode (0..7) */
int osmo_amr_s_to_d(ubit_t *out, const ubit_t *in, uint16_t n_bits, enum osmo_amr_type amr_mode)
{
	const struct ts26101_reorder_table *tbl;
	int i;

	if (amr_mode >= ARRAY_SIZE(ts26101_reorder_tables))
		return -ENODEV;

	tbl = &ts26101_reorder_tables[amr_mode];

	if (n_bits > tbl->len)
		return -EINVAL;

	for (i = 0; i < n_bits; i++) {
		uint16_t n = tbl->s_to_d[i];
		out[i] = in[n];
	}

	return n_bits;
}

/*! Convert from d-bits to s-bits (codec input).
 *  \param[out] out user-provided output buffer for generated unpacked s-bits
 *  \param[in] in input buffer for unpacked d-bits
 *  \param[in] n_bits number of bits (in both in and out)
 *  \param[in] AMR mode (0..7) */
int osmo_amr_d_to_s(ubit_t *out, const ubit_t *in, uint16_t n_bits, enum osmo_amr_type amr_mode)
{
	const struct ts26101_reorder_table *tbl;
	int i;

	if (amr_mode >= ARRAY_SIZE(ts26101_reorder_tables))
		return -ENODEV;

	tbl = &ts26101_reorder_tables[amr_mode];

	if (n_bits > tbl->len)
		return -EINVAL;

	for (i = 0; i < n_bits; i++) {
		uint16_t n = tbl->s_to_d[i];
		out[n] = in[i];
	}

	return n_bits;
}

/*! This table provides the number of s-bits (as defined in TS 26.090 and
 *  TS 26.092, clause 7 in each spec) for every possible speech or SID mode
 *  in AMR.  It differs from gsm690_bitlength[] in the case of SID: there are
 *  35 s-bits in the original 2G definition that started out as GSM 06.92,
 *  captured in this table, whereas 3G-oriented TS 26.101 AMR Core Frame
 *  definition captured in gsm690_bitlength[] has 39 d-bits for SID instead.
 *
 *  The array is allocated up to AMR_NO_DATA in order to reduce the probability
 *  of buggy code making an out-of-bounds read access.
 */
const uint8_t osmo_amr_sbits_per_mode[AMR_NO_DATA+1] = {
	[AMR_4_75] = 95,
	[AMR_5_15] = 103,
	[AMR_5_90] = 118,
	[AMR_6_70] = 134,
	[AMR_7_40] = 148,
	[AMR_7_95] = 159,
	[AMR_10_2] = 204,
	[AMR_12_2] = 244,
	[AMR_SID]  = 35,
};

/*! This table provides the number of distinct codec parameters (groupings
 *  of s-bits into 16-bit parameter words as implemented in 3GPP reference
 *  C code and assumed in TS 26.073 definition of decoder homing frames)
 *  that exist for every possible speech or SID mode in AMR.
 *
 *  The array is allocated up to AMR_NO_DATA in order to reduce the probability
 *  of buggy code making an out-of-bounds read access.
 */
const uint8_t osmo_amr_params_per_mode[AMR_NO_DATA+1] = {
	[AMR_4_75] = 17,
	[AMR_5_15] = 19,
	[AMR_5_90] = 19,
	[AMR_6_70] = 19,
	[AMR_7_40] = 19,
	[AMR_7_95] = 23,
	[AMR_10_2] = 39,
	[AMR_12_2] = 57,
	[AMR_SID]  = 5,
};

/* parameter sizes (# of bits), one table per mode */

static const uint8_t bit_counts_4_75[17] = {
	8, 8, 7,				/* LSP VQ */
	8, 7, 2, 8,				/* 1st subframe */
	4, 7, 2,				/* 2nd subframe */
	4, 7, 2, 8,				/* 3rd subframe */
	4, 7, 2,				/* 4th subframe */
};

static const uint8_t bit_counts_5_15[19] = {
	8, 8, 7,				/* LSP VQ */
	8, 7, 2, 6,				/* 1st subframe */
	4, 7, 2, 6,				/* 2nd subframe */
	4, 7, 2, 6,				/* 3rd subframe */
	4, 7, 2, 6,				/* 4th subframe */
};

static const uint8_t bit_counts_5_90[19] = {
	8, 9, 9,				/* LSP VQ */
	8, 9, 2, 6,				/* 1st subframe */
	4, 9, 2, 6,				/* 2nd subframe */
	8, 9, 2, 6,				/* 3rd subframe */
	4, 9, 2, 6,				/* 4th subframe */
};

static const uint8_t bit_counts_6_70[19] = {
	8, 9, 9,				/* LSP VQ */
	8, 11, 3, 7,				/* 1st subframe */
	4, 11, 3, 7,				/* 2nd subframe */
	8, 11, 3, 7,				/* 3rd subframe */
	4, 11, 3, 7,				/* 4th subframe */
};

static const uint8_t bit_counts_7_40[19] = {
	8, 9, 9,				/* LSP VQ */
	8, 13, 4, 7,				/* 1st subframe */
	5, 13, 4, 7,				/* 2nd subframe */
	8, 13, 4, 7,				/* 3rd subframe */
	5, 13, 4, 7,				/* 4th subframe */
};

static const uint8_t bit_counts_7_95[23] = {
	9, 9, 9,				/* LSP VQ */
	8, 13, 4, 4, 5,				/* 1st subframe */
	6, 13, 4, 4, 5,				/* 2nd subframe */
	8, 13, 4, 4, 5,				/* 3rd subframe */
	6, 13, 4, 4, 5,				/* 4th subframe */
};

static const uint8_t bit_counts_10_2[39] = {
	8, 9, 9,				/* LSP VQ */
	8, 1, 1, 1, 1, 10, 10, 7, 7,		/* 1st subframe */
	5, 1, 1, 1, 1, 10, 10, 7, 7,		/* 2nd subframe */
	8, 1, 1, 1, 1, 10, 10, 7, 7,		/* 3rd subframe */
	5, 1, 1, 1, 1, 10, 10, 7, 7,		/* 4th subframe */
};

static const uint8_t bit_counts_12_2[57] = {
	7, 8, 9, 8, 6,				/* LSP VQ */
	9, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 5,	/* 1st subframe */
	6, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 5,	/* 2nd subframe */
	9, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 5,	/* 3rd subframe */
	6, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 5,	/* 4th subframe */
};

static const uint8_t bit_counts_sid[5] = { 3, 8, 9, 9, 6 };

/* overall table with all parameter sizes for all modes */
static const uint8_t * const bit_counts_per_mode[AMR_SID + 1] = {
	bit_counts_4_75,
	bit_counts_5_15,
	bit_counts_5_90,
	bit_counts_6_70,
	bit_counts_7_40,
	bit_counts_7_95,
	bit_counts_10_2,
	bit_counts_12_2,
	bit_counts_sid,
};

/*! Convert AMR codec frame from parameters to s-bits
 *
 * \param[out] s_bits Caller-provided array of unpacked bits to be filled
 * with s-bits of the converted codec frame.
 * \param[in] param Array of AMR codec speech or SID parameters.
 * \param[in] mode Speech or SID mode according to which conversion shall
 * be performed.
 * \returns 0 if successful, or negative if \ref mode is invalid.
 */
int osmo_amr_param_to_sbits(ubit_t *s_bits, const uint16_t *param,
				enum osmo_amr_type mode)
{
	if (mode > AMR_SID)
		return -EINVAL;

	const uint8_t *table = bit_counts_per_mode[mode];
	unsigned nparam = osmo_amr_params_per_mode[mode];
	unsigned n, p, mask;
	ubit_t *b = s_bits;

	for (n = 0; n < nparam; n++) {
		p = param[n];
		mask = 1 << (*table++ - 1);
		for (; mask; mask >>= 1) {
			if (p & mask)
				*b++ = 1;
			else
				*b++ = 0;
		}
	}
	return 0;
}

/*! Convert AMR codec frame from s-bits to parameters
 *
 * \param[out] param Caller-provided buffer for array of AMR codec speech
 * or SID parameters.
 * \param[in] s_bits Unpacked s-bits of the frame to be converted.
 * \param[in] mode Speech or SID mode according to which conversion shall
 * be performed.
 * \returns 0 if successful, or negative if \ref mode is invalid.
 */
int osmo_amr_sbits_to_param(uint16_t *param, const ubit_t *s_bits,
				enum osmo_amr_type mode)
{
	if (mode > AMR_SID)
		return -EINVAL;

	const ubit_t *bit = s_bits;
	const uint8_t *table = bit_counts_per_mode[mode];
	unsigned nparam = osmo_amr_params_per_mode[mode];
	unsigned n, m, acc;

	for (n = 0; n < nparam; n++) {
		acc = 0;
		for (m = 0; m < *table; m++) {
			acc <<= 1;
			if (*bit)
				acc |= 1;
			bit++;
		}
		param[n] = acc;
		table++;
	}
	return 0;
}

/* For each of the 8 modes of AMR codec, there exists a special encoded frame
 * bit pattern which the speech decoder is required to recognize as a special
 * decoder homing frame (DHF), as specified in TS 26.090 section 8.4.  Bit
 * patterns of these 8 DHFs are specified in TS 26.073 Tables 9a through 9h
 * and captured in the following const arrays.  Note that the canonical form
 * of each DHF is an array of codec parameters; in order to emit any of these
 * DHFs as an RTP payload or a TRAU frame, the application will need to
 * convert it to s-bits with osmo_amr_param_to_sbits(), followed by
 * osmo_amr_s_to_d() in the case of RTP output.
 */

const uint16_t osmo_amr_dhf_4_75[17] = {
	0x00F8, 0x009D, 0x001C, 0x0066, 0x0000, 0x0003, 0x0028, 0x000F,
	0x0038, 0x0001, 0x000F, 0x0031, 0x0002, 0x0008, 0x000F, 0x0026,
	0x0003
};

const uint16_t osmo_amr_dhf_5_15[19] = {
	0x00F8, 0x009D, 0x001C, 0x0066, 0x0000, 0x0003, 0x0037, 0x000F,
	0x0000, 0x0003, 0x0005, 0x000F, 0x0037, 0x0003, 0x0037, 0x000F,
	0x0023, 0x0003, 0x001F
};

const uint16_t osmo_amr_dhf_5_90[19] = {
	0x00F8, 0x00E3, 0x002F, 0x00BD, 0x0000, 0x0003, 0x0037, 0x000F,
	0x0001, 0x0003, 0x000F, 0x0060, 0x00F9, 0x0003, 0x0037, 0x000F,
	0x0000, 0x0003, 0x0037
};

const uint16_t osmo_amr_dhf_6_70[19] = {
	0x00F8, 0x00E3, 0x002F, 0x00BD, 0x0002, 0x0007, 0x0000, 0x000F,
	0x0098, 0x0007, 0x0061, 0x0060, 0x05C5, 0x0007, 0x0000, 0x000F,
	0x0318, 0x0007, 0x0000
};

const uint16_t osmo_amr_dhf_7_40[19] = {
	0x00F8, 0x00E3, 0x002F, 0x00BD, 0x0006, 0x000F, 0x0000, 0x001B,
	0x0208, 0x000F, 0x0062, 0x0060, 0x1BA6, 0x000F, 0x0000, 0x001B,
	0x0006, 0x000F, 0x0000
};

const uint16_t osmo_amr_dhf_7_95[23] = {
	0x00C2, 0x00E3, 0x002F, 0x00BD, 0x0006, 0x000F, 0x000A, 0x0000,
	0x0039, 0x1C08, 0x0007, 0x000A, 0x000B, 0x0063, 0x11A6, 0x000F,
	0x0001, 0x0000, 0x0039, 0x09A0, 0x000F, 0x0002, 0x0001
};

const uint16_t osmo_amr_dhf_10_2[39] = {
	0x00F8, 0x00E3, 0x002F, 0x0045, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x001B, 0x0000, 0x0001, 0x0000,
	0x0001, 0x0326, 0x00CE, 0x007E, 0x0051, 0x0062, 0x0000, 0x0000,
	0x0000, 0x0000, 0x015A, 0x0359, 0x0076, 0x0000, 0x001B, 0x0000,
	0x0000, 0x0000, 0x0000, 0x017C, 0x0215, 0x0038, 0x0030
};

const uint16_t osmo_amr_dhf_12_2[57] = {
	0x0004, 0x002A, 0x00DB, 0x0096, 0x002A, 0x0156, 0x000B, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0036, 0x000B, 0x0000, 0x000F, 0x000E, 0x000C,
	0x000D, 0x0000, 0x0001, 0x0005, 0x0007, 0x0001, 0x0008, 0x0024,
	0x0000, 0x0001, 0x0000, 0x0005, 0x0006, 0x0001, 0x0002, 0x0004,
	0x0007, 0x0004, 0x0002, 0x0003, 0x0036, 0x000B, 0x0000, 0x0002,
	0x0004, 0x0000, 0x0003, 0x0006, 0x0001, 0x0007, 0x0006, 0x0005,
	0x0000
};

/* See also RFC 4867 §3.6, Table 1, Column "Total speech bits" */
static const uint8_t amr_len_by_ft[16] = {
	12, 13, 15, 17, 19, 20, 26, 31, 5,  0,  0,  0,  0,  0,  0,  0
};

const struct value_string osmo_amr_type_names[] = {
	{ AMR_4_75,		"AMR 4,75 kbits/s" },
	{ AMR_5_15,		"AMR 5,15 kbit/s" },
	{ AMR_5_90,		"AMR 5,90 kbit/s" },
	{ AMR_6_70,		"AMR 6,70 kbit/s (PDC-EFR)" },
	{ AMR_7_40,		"AMR 7,40 kbit/s (TDMA-EFR)" },
	{ AMR_7_95,		"AMR 7,95 kbit/s" },
	{ AMR_10_2,		"AMR 10,2 kbit/s" },
	{ AMR_12_2,		"AMR 12,2 kbit/s (GSM-EFR)" },
	{ AMR_SID,		"AMR SID" },
	{ AMR_GSM_EFR_SID,	"GSM-EFR SID" },
	{ AMR_TDMA_EFR_SID,	"TDMA-EFR SID" },
	{ AMR_PDC_EFR_SID,	"PDC-EFR SID" },
	{ AMR_NO_DATA,		"No Data/NA" },
	{ 0,			NULL },
};

/*! Decode various AMR parameters from RTP payload (RFC 4867) acording to
 *         3GPP TS 26.101
 *  \param[in] rtppayload Payload from RTP packet
 *  \param[in] payload_len length of rtppayload
 *  \param[out] cmr AMR Codec Mode Request, not filled if NULL
 *  \param[out] cmi AMR Codec Mode Indicator, -1 if not applicable for this type,
 *              not filled if NULL
 *  \param[out] ft AMR Frame Type, not filled if NULL
 *  \param[out] bfi AMR Bad Frame Indicator, not filled if NULL
 *  \param[out] sti AMR SID Type Indicator, -1 if not applicable for this type,
 *              not filled if NULL
 *  \returns length of AMR data or negative value on error
 */
int osmo_amr_rtp_dec(const uint8_t *rtppayload, int payload_len, uint8_t *cmr,
		     int8_t *cmi, enum osmo_amr_type *ft,
		     enum osmo_amr_quality *bfi, int8_t *sti)
{
	if (payload_len < 2 || !rtppayload)
		return -EINVAL;

	/* RFC 4867 § 4.4.2 ToC - compound payloads are not supported: F = 0 */
	uint8_t type = (rtppayload[1] >> 3) & 0xf;

	/* compound payloads are not supported */
	if (rtppayload[1] >> 7)
		return -ENOTSUP;

	if (payload_len < amr_len_by_ft[type])
		return -ENOTSUP;

	if (ft)
		*ft = type;

	if (cmr)
		*cmr = rtppayload[0] >> 4;

	if (bfi)
		*bfi = (rtppayload[1] >> 2) & 1;

	/* Table 6 in 3GPP TS 26.101 */
	if (cmi)
		*cmi = (type == AMR_SID) ? ((rtppayload[6] >> 1) & 7) : -1;

	if (sti)
		*sti = (type == AMR_SID) ? (rtppayload[6] & 0x10) : -1;

	return 2 + amr_len_by_ft[type];
}

/*! Encode various AMR parameters from RTP payload (RFC 4867)
 *  \param[out] payload Payload for RTP packet, contains speech data (if any)
 *              except for have 2 first bytes where header will be built
 *  \param[in] cmr AMR codec Mode Request
 *  \param[in] ft AMR Frame Type
 *  \param[in] bfi AMR Bad Frame Indicator
 *  \returns length of AMR data (header + ToC + speech data) or negative value
 *           on error
 *
 *  Note: only octet-aligned mode is supported so the header occupies 2 full
 *  bytes. Optional interleaving header is not supported.
 */
int osmo_amr_rtp_enc(uint8_t *payload, uint8_t cmr, enum osmo_amr_type ft,
		     enum osmo_amr_quality bfi)
{
	if (cmr > 15)
		return -EINVAL;

	if (ft > 15)
		return -ENOTSUP;

	/* RFC 4867 § 4.3.1 payload header */
	payload[0] = cmr << 4;

	/* RFC 4867 § 4.4.2 ToC - compound payloads are not supported: F = 0 */
	payload[1] = (((uint8_t)ft) << 3) | (((uint8_t)bfi) << 2);

	/* speech data */
	return 2 + amr_len_by_ft[ft];
}
