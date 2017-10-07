/*! \file conv_acc_sse_impl.h
 * Accelerated Viterbi decoder implementation:
 * Actual definitions which are being included
 * from both conv_acc_sse.c and conv_acc_sse_avx.c. */
/*
 * Copyright (C) 2013, 2014 Thomas Tsou <tom@tsou.cc>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

extern int sse41_supported;

/* Octo-Viterbi butterfly
 * Compute 8-wide butterfly generating 16 path decisions and 16 accumulated
 * sums. Inputs all packed 16-bit integers in three 128-bit XMM registers.
 * Two intermediate registers are used and results are set in the upper 4
 * registers.
 *
 * Input:
 * M0 - Path metrics 0 (packed 16-bit integers)
 * M1 - Path metrics 1 (packed 16-bit integers)
 * M2 - Branch metrics (packed 16-bit integers)
 *
 * Output:
 * M2 - Selected and accumulated path metrics 0
 * M4 - Selected and accumulated path metrics 1
 * M3 - Path selections 0
 * M1 - Path selections 1
 */
#define SSE_BUTTERFLY(M0, M1, M2, M3, M4) \
{ \
	M3 = _mm_adds_epi16(M0, M2); \
	M4 = _mm_subs_epi16(M1, M2); \
	M0 = _mm_subs_epi16(M0, M2); \
	M1 = _mm_adds_epi16(M1, M2); \
	M2 = _mm_max_epi16(M3, M4); \
	M3 = _mm_or_si128(_mm_cmpgt_epi16(M3, M4), _mm_cmpeq_epi16(M3, M4)); \
	M4 = _mm_max_epi16(M0, M1); \
	M1 = _mm_or_si128(_mm_cmpgt_epi16(M0, M1), _mm_cmpeq_epi16(M0, M1)); \
}

/* Two lane deinterleaving K = 5:
 * Take 16 interleaved 16-bit integers and deinterleave to 2 packed 128-bit
 * registers. The operation summarized below. Four registers are used with
 * the lower 2 as input and upper 2 as output.
 *
 * In   - 10101010 10101010 10101010 10101010
 * Out  - 00000000 11111111 00000000 11111111
 *
 * Input:
 * M0:1 - Packed 16-bit integers
 *
 * Output:
 * M2:3 - Deinterleaved packed 16-bit integers
 */
#define _I8_SHUFFLE_MASK 15, 14, 11, 10, 7, 6, 3, 2, 13, 12, 9, 8, 5, 4, 1, 0

#define SSE_DEINTERLEAVE_K5(M0, M1, M2, M3) \
{ \
	M2 = _mm_set_epi8(_I8_SHUFFLE_MASK); \
	M0 = _mm_shuffle_epi8(M0, M2); \
	M1 = _mm_shuffle_epi8(M1, M2); \
	M2 = _mm_unpacklo_epi64(M0, M1); \
	M3 = _mm_unpackhi_epi64(M0, M1); \
}

/* Two lane deinterleaving K = 7:
 * Take 64 interleaved 16-bit integers and deinterleave to 8 packed 128-bit
 * registers. The operation summarized below. 16 registers are used with the
 * lower 8 as input and upper 8 as output.
 *
 * In   - 10101010 10101010 10101010 10101010 ...
 * Out  - 00000000 11111111 00000000 11111111 ...
 *
 * Input:
 * M0:7 - Packed 16-bit integers
 *
 * Output:
 * M8:15 - Deinterleaved packed 16-bit integers
 */
#define SSE_DEINTERLEAVE_K7(M0, M1, M2, M3, M4, M5, M6, M7, \
	M8, M9, M10, M11, M12, M13, M14, M15) \
{ \
	M8  = _mm_set_epi8(_I8_SHUFFLE_MASK); \
	M0  = _mm_shuffle_epi8(M0, M8); \
	M1  = _mm_shuffle_epi8(M1, M8); \
	M2  = _mm_shuffle_epi8(M2, M8); \
	M3  = _mm_shuffle_epi8(M3, M8); \
	M4  = _mm_shuffle_epi8(M4, M8); \
	M5  = _mm_shuffle_epi8(M5, M8); \
	M6  = _mm_shuffle_epi8(M6, M8); \
	M7  = _mm_shuffle_epi8(M7, M8); \
	M8  = _mm_unpacklo_epi64(M0, M1); \
	M9  = _mm_unpackhi_epi64(M0, M1); \
	M10 = _mm_unpacklo_epi64(M2, M3); \
	M11 = _mm_unpackhi_epi64(M2, M3); \
	M12 = _mm_unpacklo_epi64(M4, M5); \
	M13 = _mm_unpackhi_epi64(M4, M5); \
	M14 = _mm_unpacklo_epi64(M6, M7); \
	M15 = _mm_unpackhi_epi64(M6, M7); \
}

/* Generate branch metrics N = 2:
 * Compute 16 branch metrics from trellis outputs and input values.
 *
 * Input:
 * M0:3 - 16 x 2 packed 16-bit trellis outputs
 * M4   - Expanded and packed 16-bit input value
 *
 * Output:
 * M6:7 - 16 computed 16-bit branch metrics
 */
#define SSE_BRANCH_METRIC_N2(M0, M1, M2, M3, M4, M6, M7) \
{ \
	M0 = _mm_sign_epi16(M4, M0); \
	M1 = _mm_sign_epi16(M4, M1); \
	M2 = _mm_sign_epi16(M4, M2); \
	M3 = _mm_sign_epi16(M4, M3); \
	M6 = _mm_hadds_epi16(M0, M1); \
	M7 = _mm_hadds_epi16(M2, M3); \
}

/* Generate branch metrics N = 4:
 * Compute 8 branch metrics from trellis outputs and input values. This
 * macro is reused for N less than 4 where the extra soft input bits are
 * padded.
 *
 * Input:
 * M0:3 - 8 x 4 packed 16-bit trellis outputs
 * M4   - Expanded and packed 16-bit input value
 *
 * Output:
 * M5   - 8 computed 16-bit branch metrics
 */
#define SSE_BRANCH_METRIC_N4(M0, M1, M2, M3, M4, M5) \
{ \
	M0 = _mm_sign_epi16(M4, M0); \
	M1 = _mm_sign_epi16(M4, M1); \
	M2 = _mm_sign_epi16(M4, M2); \
	M3 = _mm_sign_epi16(M4, M3); \
	M0 = _mm_hadds_epi16(M0, M1); \
	M1 = _mm_hadds_epi16(M2, M3); \
	M5 = _mm_hadds_epi16(M0, M1); \
}

/* Horizontal minimum
 * Compute horizontal minimum of packed unsigned 16-bit integers and place
 * result in the low 16-bit element of the source register. Only SSE 4.1
 * has a dedicated minpos instruction. One intermediate register is used
 * if SSE 4.1 is not available. This is a destructive operation and the
 * source register is overwritten.
 *
 * Input:
 * M0 - Packed unsigned 16-bit integers
 *
 * Output:
 * M0 - Minimum value placed in low 16-bit element
 */
#if defined(HAVE_SSE4_1) || defined(HAVE_SSE41)
#define SSE_MINPOS(M0, M1) \
{ \
	if (sse41_supported) { \
		M0 = _mm_minpos_epu16(M0); \
	} else { \
		M1 = _mm_shuffle_epi32(M0, _MM_SHUFFLE(0, 0, 3, 2)); \
		M0 = _mm_min_epi16(M0, M1); \
		M1 = _mm_shufflelo_epi16(M0, _MM_SHUFFLE(0, 0, 3, 2)); \
		M0 = _mm_min_epi16(M0, M1); \
		M1 = _mm_shufflelo_epi16(M0, _MM_SHUFFLE(0, 0, 0, 1)); \
		M0 = _mm_min_epi16(M0, M1); \
	} \
}
#else
#define SSE_MINPOS(M0, M1) \
{ \
	M1 = _mm_shuffle_epi32(M0, _MM_SHUFFLE(0, 0, 3, 2)); \
	M0 = _mm_min_epi16(M0, M1); \
	M1 = _mm_shufflelo_epi16(M0, _MM_SHUFFLE(0, 0, 3, 2)); \
	M0 = _mm_min_epi16(M0, M1); \
	M1 = _mm_shufflelo_epi16(M0, _MM_SHUFFLE(0, 0, 0, 1)); \
	M0 = _mm_min_epi16(M0, M1); \
}
#endif

/* Normalize state metrics K = 5:
 * Compute 16-wide normalization by subtracting the smallest value from
 * all values. Inputs are 16 packed 16-bit integers across 2 XMM registers.
 * Two intermediate registers are used and normalized results are placed
 * in the originating locations.
 *
 * Input:
 * M0:1 - Path metrics 0:1 (packed 16-bit integers)
 *
 * Output:
 * M0:1 - Normalized path metrics 0:1
 */
#define SSE_NORMALIZE_K5(M0, M1, M2, M3) \
{ \
	M2 = _mm_min_epi16(M0, M1); \
	SSE_MINPOS(M2, M3) \
	SSE_BROADCAST(M2) \
	M0 = _mm_subs_epi16(M0, M2); \
	M1 = _mm_subs_epi16(M1, M2); \
}

/* Normalize state metrics K = 7:
 * Compute 64-wide normalization by subtracting the smallest value from
 * all values. Inputs are 8 registers of accumulated sums and 4 temporary
 * registers. Normalized results are returned in the originating locations.
 *
 * Input:
 * M0:7 - Path metrics 0:7 (packed 16-bit integers)
 *
 * Output:
 * M0:7 - Normalized path metrics 0:7
 */
#define SSE_NORMALIZE_K7(M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11) \
{ \
	M8  = _mm_min_epi16(M0, M1); \
	M9  = _mm_min_epi16(M2, M3); \
	M10 = _mm_min_epi16(M4, M5); \
	M11 = _mm_min_epi16(M6, M7); \
	M8  = _mm_min_epi16(M8, M9); \
	M10 = _mm_min_epi16(M10, M11); \
	M8  = _mm_min_epi16(M8, M10); \
	SSE_MINPOS(M8, M9) \
	SSE_BROADCAST(M8) \
	M0  = _mm_subs_epi16(M0, M8); \
	M1  = _mm_subs_epi16(M1, M8); \
	M2  = _mm_subs_epi16(M2, M8); \
	M3  = _mm_subs_epi16(M3, M8); \
	M4  = _mm_subs_epi16(M4, M8); \
	M5  = _mm_subs_epi16(M5, M8); \
	M6  = _mm_subs_epi16(M6, M8); \
	M7  = _mm_subs_epi16(M7, M8); \
}

/* Combined BMU/PMU (K=5, N=2)
 * Compute branch metrics followed by path metrics for half rate 16-state
 * trellis. 8 butterflies are computed. Accumulated path sums are not
 * preserved and read and written into the same memory location. Normalize
 * sums if requires.
 */
static void _sse_metrics_k5_n2(const int16_t *val,
	const int16_t *out, int16_t *sums, int16_t *paths, int norm)
{
	__m128i m0, m1, m2, m3, m4, m5, m6;

	/* (BMU) Load input sequence */
	m2 = _mm_castpd_si128(_mm_loaddup_pd((double const *) val));

	/* (BMU) Load trellis outputs */
	m0 = _mm_load_si128((__m128i *) &out[0]);
	m1 = _mm_load_si128((__m128i *) &out[8]);

	/* (BMU) Compute branch metrics */
	m0 = _mm_sign_epi16(m2, m0);
	m1 = _mm_sign_epi16(m2, m1);
	m2 = _mm_hadds_epi16(m0, m1);

	/* (PMU) Load accumulated path metrics */
	m0 = _mm_load_si128((__m128i *) &sums[0]);
	m1 = _mm_load_si128((__m128i *) &sums[8]);

	SSE_DEINTERLEAVE_K5(m0, m1, m3, m4)

	/* (PMU) Butterflies: 0-7 */
	SSE_BUTTERFLY(m3, m4, m2, m5, m6)

	if (norm)
		SSE_NORMALIZE_K5(m2, m6, m0, m1)

	_mm_store_si128((__m128i *) &sums[0], m2);
	_mm_store_si128((__m128i *) &sums[8], m6);
	_mm_store_si128((__m128i *) &paths[0], m5);
	_mm_store_si128((__m128i *) &paths[8], m4);
}

/* Combined BMU/PMU (K=5, N=3 and N=4)
 * Compute branch metrics followed by path metrics for 16-state and rates
 * to 1/4. 8 butterflies are computed. The input sequence is read four 16-bit
 * values at a time, and extra values should be set to zero for rates other
 * than 1/4. Normally only rates 1/3 and 1/4 are used as there is a
 * dedicated implementation of rate 1/2.
 */
static void _sse_metrics_k5_n4(const int16_t *val,
	const int16_t *out, int16_t *sums, int16_t *paths, int norm)
{
	__m128i m0, m1, m2, m3, m4, m5, m6;

	/* (BMU) Load input sequence */
	m4 = _mm_castpd_si128(_mm_loaddup_pd((double const *) val));

	/* (BMU) Load trellis outputs */
	m0 = _mm_load_si128((__m128i *) &out[0]);
	m1 = _mm_load_si128((__m128i *) &out[8]);
	m2 = _mm_load_si128((__m128i *) &out[16]);
	m3 = _mm_load_si128((__m128i *) &out[24]);

	SSE_BRANCH_METRIC_N4(m0, m1, m2, m3, m4, m2)

	/* (PMU) Load accumulated path metrics */
	m0 = _mm_load_si128((__m128i *) &sums[0]);
	m1 = _mm_load_si128((__m128i *) &sums[8]);

	SSE_DEINTERLEAVE_K5(m0, m1, m3, m4)

	/* (PMU) Butterflies: 0-7 */
	SSE_BUTTERFLY(m3, m4, m2, m5, m6)

	if (norm)
		SSE_NORMALIZE_K5(m2, m6, m0, m1)

	_mm_store_si128((__m128i *) &sums[0], m2);
	_mm_store_si128((__m128i *) &sums[8], m6);
	_mm_store_si128((__m128i *) &paths[0], m5);
	_mm_store_si128((__m128i *) &paths[8], m4);
}

/* Combined BMU/PMU (K=7, N=2)
 * Compute branch metrics followed by path metrics for half rate 64-state
 * trellis. 32 butterfly operations are computed. Deinterleaving path
 * metrics requires usage of the full SSE register file, so separate sums
 * before computing branch metrics to avoid register spilling.
 */
static void _sse_metrics_k7_n2(const int16_t *val,
	const int16_t *out, int16_t *sums, int16_t *paths, int norm)
{
	__m128i m0, m1, m2, m3, m4, m5, m6, m7, m8,
		m9, m10, m11, m12, m13, m14, m15;

	/* (PMU) Load accumulated path metrics */
	m0 = _mm_load_si128((__m128i *) &sums[0]);
	m1 = _mm_load_si128((__m128i *) &sums[8]);
	m2 = _mm_load_si128((__m128i *) &sums[16]);
	m3 = _mm_load_si128((__m128i *) &sums[24]);
	m4 = _mm_load_si128((__m128i *) &sums[32]);
	m5 = _mm_load_si128((__m128i *) &sums[40]);
	m6 = _mm_load_si128((__m128i *) &sums[48]);
	m7 = _mm_load_si128((__m128i *) &sums[56]);

	/* (PMU) Deinterleave to even-odd registers */
	SSE_DEINTERLEAVE_K7(m0, m1, m2, m3 ,m4 ,m5, m6, m7,
			    m8, m9, m10, m11, m12, m13, m14, m15)

	/* (BMU) Load input symbols */
	m7 = _mm_castpd_si128(_mm_loaddup_pd((double const *) val));

	/* (BMU) Load trellis outputs */
	m0 = _mm_load_si128((__m128i *) &out[0]);
	m1 = _mm_load_si128((__m128i *) &out[8]);
	m2 = _mm_load_si128((__m128i *) &out[16]);
	m3 = _mm_load_si128((__m128i *) &out[24]);

	SSE_BRANCH_METRIC_N2(m0, m1, m2, m3, m7, m4, m5)

	m0 = _mm_load_si128((__m128i *) &out[32]);
	m1 = _mm_load_si128((__m128i *) &out[40]);
	m2 = _mm_load_si128((__m128i *) &out[48]);
	m3 = _mm_load_si128((__m128i *) &out[56]);

	SSE_BRANCH_METRIC_N2(m0, m1, m2, m3, m7, m6, m7)

	/* (PMU) Butterflies: 0-15 */
	SSE_BUTTERFLY(m8, m9, m4, m0, m1)
	SSE_BUTTERFLY(m10, m11, m5, m2, m3)

	_mm_store_si128((__m128i *) &paths[0], m0);
	_mm_store_si128((__m128i *) &paths[8], m2);
	_mm_store_si128((__m128i *) &paths[32], m9);
	_mm_store_si128((__m128i *) &paths[40], m11);

	/* (PMU) Butterflies: 17-31 */
	SSE_BUTTERFLY(m12, m13, m6, m0, m2)
	SSE_BUTTERFLY(m14, m15, m7, m9, m11)

	_mm_store_si128((__m128i *) &paths[16], m0);
	_mm_store_si128((__m128i *) &paths[24], m9);
	_mm_store_si128((__m128i *) &paths[48], m13);
	_mm_store_si128((__m128i *) &paths[56], m15);

	if (norm)
		SSE_NORMALIZE_K7(m4, m1, m5, m3, m6, m2,
				 m7, m11, m0, m8, m9, m10)

	_mm_store_si128((__m128i *) &sums[0], m4);
	_mm_store_si128((__m128i *) &sums[8], m5);
	_mm_store_si128((__m128i *) &sums[16], m6);
	_mm_store_si128((__m128i *) &sums[24], m7);
	_mm_store_si128((__m128i *) &sums[32], m1);
	_mm_store_si128((__m128i *) &sums[40], m3);
	_mm_store_si128((__m128i *) &sums[48], m2);
	_mm_store_si128((__m128i *) &sums[56], m11);
}

/* Combined BMU/PMU (K=7, N=3 and N=4)
 * Compute branch metrics followed by path metrics for half rate 64-state
 * trellis. 32 butterfly operations are computed. Deinterleave path
 * metrics before computing branch metrics as in the half rate case.
 */
static void _sse_metrics_k7_n4(const int16_t *val,
	const int16_t *out, int16_t *sums, int16_t *paths, int norm)
{
	__m128i m0, m1, m2, m3, m4, m5, m6, m7;
	__m128i m8, m9, m10, m11, m12, m13, m14, m15;

	/* (PMU) Load accumulated path metrics */
	m0 = _mm_load_si128((__m128i *) &sums[0]);
	m1 = _mm_load_si128((__m128i *) &sums[8]);
	m2 = _mm_load_si128((__m128i *) &sums[16]);
	m3 = _mm_load_si128((__m128i *) &sums[24]);
	m4 = _mm_load_si128((__m128i *) &sums[32]);
	m5 = _mm_load_si128((__m128i *) &sums[40]);
	m6 = _mm_load_si128((__m128i *) &sums[48]);
	m7 = _mm_load_si128((__m128i *) &sums[56]);

	/* (PMU) Deinterleave into even and odd packed registers */
	SSE_DEINTERLEAVE_K7(m0, m1, m2, m3 ,m4 ,m5, m6, m7,
			    m8, m9, m10, m11, m12, m13, m14, m15)

	/* (BMU) Load and expand 8-bit input out to 16-bits */
	m7 = _mm_castpd_si128(_mm_loaddup_pd((double const *) val));

	/* (BMU) Load and compute branch metrics */
	m0 = _mm_load_si128((__m128i *) &out[0]);
	m1 = _mm_load_si128((__m128i *) &out[8]);
	m2 = _mm_load_si128((__m128i *) &out[16]);
	m3 = _mm_load_si128((__m128i *) &out[24]);

	SSE_BRANCH_METRIC_N4(m0, m1, m2, m3, m7, m4)

	m0 = _mm_load_si128((__m128i *) &out[32]);
	m1 = _mm_load_si128((__m128i *) &out[40]);
	m2 = _mm_load_si128((__m128i *) &out[48]);
	m3 = _mm_load_si128((__m128i *) &out[56]);

	SSE_BRANCH_METRIC_N4(m0, m1, m2, m3, m7, m5)

	m0 = _mm_load_si128((__m128i *) &out[64]);
	m1 = _mm_load_si128((__m128i *) &out[72]);
	m2 = _mm_load_si128((__m128i *) &out[80]);
	m3 = _mm_load_si128((__m128i *) &out[88]);

	SSE_BRANCH_METRIC_N4(m0, m1, m2, m3, m7, m6)

	m0 = _mm_load_si128((__m128i *) &out[96]);
	m1 = _mm_load_si128((__m128i *) &out[104]);
	m2 = _mm_load_si128((__m128i *) &out[112]);
	m3 = _mm_load_si128((__m128i *) &out[120]);

	SSE_BRANCH_METRIC_N4(m0, m1, m2, m3, m7, m7)

	/* (PMU) Butterflies: 0-15 */
	SSE_BUTTERFLY(m8, m9, m4, m0, m1)
	SSE_BUTTERFLY(m10, m11, m5, m2, m3)

	_mm_store_si128((__m128i *) &paths[0], m0);
	_mm_store_si128((__m128i *) &paths[8], m2);
	_mm_store_si128((__m128i *) &paths[32], m9);
	_mm_store_si128((__m128i *) &paths[40], m11);

	/* (PMU) Butterflies: 17-31 */
	SSE_BUTTERFLY(m12, m13, m6, m0, m2)
	SSE_BUTTERFLY(m14, m15, m7, m9, m11)

	_mm_store_si128((__m128i *) &paths[16], m0);
	_mm_store_si128((__m128i *) &paths[24], m9);
	_mm_store_si128((__m128i *) &paths[48], m13);
	_mm_store_si128((__m128i *) &paths[56], m15);

	if (norm)
		SSE_NORMALIZE_K7(m4, m1, m5, m3, m6, m2,
				 m7, m11, m0, m8, m9, m10)

	_mm_store_si128((__m128i *) &sums[0], m4);
	_mm_store_si128((__m128i *) &sums[8], m5);
	_mm_store_si128((__m128i *) &sums[16], m6);
	_mm_store_si128((__m128i *) &sums[24], m7);
	_mm_store_si128((__m128i *) &sums[32], m1);
	_mm_store_si128((__m128i *) &sums[40], m3);
	_mm_store_si128((__m128i *) &sums[48], m2);
	_mm_store_si128((__m128i *) &sums[56], m11);
}
