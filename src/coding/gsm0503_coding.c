/*
 * (C) 2013 by Andreas Eversberg <jolly@eversberg.eu>
 * (C) 2015 by Alexander Chemeris <Alexander.Chemeris@fairwaves.co>
 * (C) 2016 by Tom Tsou <tom.tsou@ettus.com>
 * (C) 2017 by Harald Welte <laforge@gnumonks.org>
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
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <osmocom/core/bits.h>
#include <osmocom/core/conv.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/crcgen.h>
#include <osmocom/core/endian.h>

#include <osmocom/gprs/protocol/gsm_04_60.h>
#include <osmocom/gprs/gprs_rlc.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm0503.h>
#include <osmocom/codec/codec.h>

#include <osmocom/coding/gsm0503_interleaving.h>
#include <osmocom/coding/gsm0503_mapping.h>
#include <osmocom/coding/gsm0503_tables.h>
#include <osmocom/coding/gsm0503_coding.h>
#include <osmocom/coding/gsm0503_parity.h>
#include <osmocom/coding/gsm0503_amr_dtx.h>

/*! \mainpage libosmocoding Documentation
 *
 * \section sec_intro Introduction
 * This library is a collection of definitions, tables and functions
 * implementing the GSM/GPRS/EGPRS channel coding (and decoding) as
 * specified in 3GPP TS 05.03 / 45.003.
 *
 * libosmocoding is developed as part of the Osmocom (Open Source Mobile
 * Communications) project, a community-based, collaborative development
 * project to create Free and Open Source implementations of mobile
 * communications systems.  For more information about Osmocom, please
 * see https://osmocom.org/
 *
 * \section sec_copyright Copyright and License
 * Copyright © 2013 by Andreas Eversberg\n
 * Copyright © 2015 by Alexander Chemeris\n
 * Copyright © 2016 by Tom Tsou\n
 * Documentation Copyright © 2017 by Harald Welte\n
 * All rights reserved. \n\n
 * The source code of libosmocoding is licensed under the terms of the GNU
 * General Public License as published by the Free Software Foundation;
 * either version 2 of the License, or (at your option) any later
 * version.\n
 * See <http://www.gnu.org/licenses/> or COPYING included in the source
 * code package istelf.\n
 * The information detailed here is provided AS IS with NO WARRANTY OF
 * ANY KIND, INCLUDING THE WARRANTY OF DESIGN, MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE.
 * \n\n
 *
 * \section sec_tracker Homepage + Issue Tracker
 * libosmocoding is distributed as part of libosmocore and shares its
 * project page at http://osmocom.org/projects/libosmocore
 *
 * An Issue Tracker can be found at
 * https://osmocom.org/projects/libosmocore/issues
 *
 * \section sec_contact Contact and Support
 * Community-based support is available at the OpenBSC mailing list
 * <http://lists.osmocom.org/mailman/listinfo/openbsc>\n
 * Commercial support options available upon request from
 * <http://sysmocom.de/>
 */


/*! \addtogroup coding
 *  @{
 *
 *  GSM TS 05.03 coding
 *
 *  This module is the "master module" of libosmocoding. It uses the
 *  various other modules (mapping, parity, interleaving) in order to
 *  implement the complete channel coding (and decoding) chain for the
 *  various channel types as defined in TS 05.03 / 45.003.
 *
 * \file gsm0503_coding.c */

/*
 * EGPRS coding limits
 */

/* Max header size with parity bits */
#define EGPRS_HDR_UPP_MAX	54

/* Max encoded header size */
#define EGPRS_HDR_C_MAX		162

/* Max punctured header size */
#define EGPRS_HDR_HC_MAX	160

/* Max data block size with parity bits */
#define EGPRS_DATA_U_MAX	612

/* Max encoded data block size */
#define EGPRS_DATA_C_MAX	1836

/* Max single block punctured data size */
#define EGPRS_DATA_DC_MAX	1248

/* Dual block punctured data size */
#define EGPRS_DATA_C1		612
#define EGPRS_DATA_C2		EGPRS_DATA_C1

/*! union across the three different EGPRS Uplink header types */
union gprs_rlc_ul_hdr_egprs {
	struct gprs_rlc_ul_header_egprs_1 type1;
	struct gprs_rlc_ul_header_egprs_2 type2;
	struct gprs_rlc_ul_header_egprs_3 type3;
};

/*! union across the three different EGPRS Downlink header types */
union gprs_rlc_dl_hdr_egprs {
	struct gprs_rlc_dl_header_egprs_1 type1;
	struct gprs_rlc_dl_header_egprs_2 type2;
	struct gprs_rlc_dl_header_egprs_3 type3;
};

/*! Structure describing a Modulation and Coding Scheme */
struct gsm0503_mcs_code {
	/*! Modulation and Coding Scheme (MSC) number */
	uint8_t mcs;
	/*! Length of Uplink Stealing Flag (USF) in bits */
	uint8_t usf_len;

	/* Header coding */
	/*! Length of header (bits) */
	uint8_t hdr_len;
	/*! Length of header convolutional code */
	uint8_t hdr_code_len;
	/*! Length of header code puncturing sequence */
	uint8_t hdr_punc_len;
	/*! header convolutional code */
	const struct osmo_conv_code *hdr_conv;
	/*! header puncturing sequence */
	const uint8_t *hdr_punc;

	/* Data coding */
	/*! length of data (bits) */
	uint16_t data_len;
	/*! length of data convolutional code */
	uint16_t data_code_len;
	/*! length of data code puncturing sequence */
	uint16_t data_punc_len;
	/*! data convolutional code */
	const struct osmo_conv_code *data_conv;
	/*! data puncturing sequences */
	const uint8_t *data_punc[3];
};

/*
 * EGPRS UL coding parameters
 */
const struct gsm0503_mcs_code gsm0503_mcs_ul_codes[EGPRS_NUM_MCS] = {
	{
		.mcs = EGPRS_MCS0,
	},
	{
		.mcs = EGPRS_MCS1,
		.hdr_len = 31,
		.hdr_code_len = 117,
		.hdr_punc_len = 80,
		.hdr_conv = &gsm0503_mcs1_ul_hdr,
		.hdr_punc = gsm0503_puncture_mcs1_ul_hdr,

		.data_len = 178,
		.data_code_len = 588,
		.data_punc_len = 372,
		.data_conv = &gsm0503_mcs1,
		.data_punc = {
			gsm0503_puncture_mcs1_p1,
			gsm0503_puncture_mcs1_p2,
			NULL,
		},
	},
	{
		.mcs = EGPRS_MCS2,
		.hdr_len = 31,
		.hdr_code_len = 117,
		.hdr_punc_len = 80,
		.hdr_conv = &gsm0503_mcs1_ul_hdr,
		.hdr_punc = gsm0503_puncture_mcs1_ul_hdr,

		.data_len = 226,
		.data_code_len = 732,
		.data_punc_len = 372,
		.data_conv = &gsm0503_mcs2,
		.data_punc = {
			gsm0503_puncture_mcs2_p1,
			gsm0503_puncture_mcs2_p2,
			NULL,
		},
	},
	{
		.mcs = EGPRS_MCS3,
		.hdr_len = 31,
		.hdr_code_len = 117,
		.hdr_punc_len = 80,
		.hdr_conv = &gsm0503_mcs1_ul_hdr,
		.hdr_punc = gsm0503_puncture_mcs1_ul_hdr,

		.data_len = 298,
		.data_code_len = 948,
		.data_punc_len = 372,
		.data_conv = &gsm0503_mcs3,
		.data_punc = {
			gsm0503_puncture_mcs3_p1,
			gsm0503_puncture_mcs3_p2,
			gsm0503_puncture_mcs3_p3,
		},
	},
	{
		.mcs = EGPRS_MCS4,
		.hdr_len = 31,
		.hdr_code_len = 117,
		.hdr_punc_len = 80,
		.hdr_conv = &gsm0503_mcs1_ul_hdr,
		.hdr_punc = gsm0503_puncture_mcs1_ul_hdr,

		.data_len = 354,
		.data_code_len = 1116,
		.data_punc_len = 372,
		.data_conv = &gsm0503_mcs4,
		.data_punc = {
			gsm0503_puncture_mcs4_p1,
			gsm0503_puncture_mcs4_p2,
			gsm0503_puncture_mcs4_p3,
		},
	},
	{
		.mcs = EGPRS_MCS5,
		.hdr_len = 37,
		.hdr_code_len = 135,
		.hdr_punc_len = 136,
		.hdr_conv = &gsm0503_mcs5_ul_hdr,
		.hdr_punc = NULL,

		.data_len = 450,
		.data_code_len = 1404,
		.data_punc_len = 1248,
		.data_conv = &gsm0503_mcs5,
		.data_punc = {
			gsm0503_puncture_mcs5_p1,
			gsm0503_puncture_mcs5_p2,
			NULL,
		},
	},
	{
		.mcs = EGPRS_MCS6,
		.hdr_len = 37,
		.hdr_code_len = 135,
		.hdr_punc_len = 136,
		.hdr_conv = &gsm0503_mcs5_ul_hdr,
		.hdr_punc = NULL,

		.data_len = 594,
		.data_code_len = 1836,
		.data_punc_len = 1248,
		.data_conv = &gsm0503_mcs6,
		.data_punc = {
			gsm0503_puncture_mcs6_p1,
			gsm0503_puncture_mcs6_p2,
			NULL,
		},
	},
	{
		.mcs = EGPRS_MCS7,
		.hdr_len = 46,
		.hdr_code_len = 162,
		.hdr_punc_len = 160,
		.hdr_conv = &gsm0503_mcs7_ul_hdr,
		.hdr_punc = gsm0503_puncture_mcs7_ul_hdr,

		.data_len = 900,
		.data_code_len = 1404,
		.data_punc_len = 612,
		.data_conv = &gsm0503_mcs7,
		.data_punc = {
			gsm0503_puncture_mcs7_p1,
			gsm0503_puncture_mcs7_p2,
			gsm0503_puncture_mcs7_p3,
		}
	},
	{
		.mcs = EGPRS_MCS8,
		.hdr_len = 46,
		.hdr_code_len = 162,
		.hdr_punc_len = 160,
		.hdr_conv = &gsm0503_mcs7_ul_hdr,
		.hdr_punc = gsm0503_puncture_mcs7_ul_hdr,

		.data_len = 1092,
		.data_code_len = 1692,
		.data_punc_len = 612,
		.data_conv = &gsm0503_mcs8,
		.data_punc = {
			gsm0503_puncture_mcs8_p1,
			gsm0503_puncture_mcs8_p2,
			gsm0503_puncture_mcs8_p3,
		}
	},
	{
		.mcs = EGPRS_MCS9,
		.hdr_len = 46,
		.hdr_code_len = 162,
		.hdr_punc_len = 160,
		.hdr_conv = &gsm0503_mcs7_ul_hdr,
		.hdr_punc = gsm0503_puncture_mcs7_ul_hdr,

		.data_len = 1188,
		.data_code_len = 1836,
		.data_punc_len = 612,
		.data_conv = &gsm0503_mcs9,
		.data_punc = {
			gsm0503_puncture_mcs9_p1,
			gsm0503_puncture_mcs9_p2,
			gsm0503_puncture_mcs9_p3,
		}
	},
};

/*
 * EGPRS DL coding parameters
 */
const struct gsm0503_mcs_code gsm0503_mcs_dl_codes[EGPRS_NUM_MCS] = {
	{
		.mcs = EGPRS_MCS0,
	},
	{
		.mcs = EGPRS_MCS1,
		.usf_len = 3,
		.hdr_len = 28,
		.hdr_code_len = 108,
		.hdr_punc_len = 68,
		.hdr_conv = &gsm0503_mcs1_dl_hdr,
		.hdr_punc = gsm0503_puncture_mcs1_dl_hdr,

		.data_len = 178,
		.data_code_len = 588,
		.data_punc_len = 372,
		.data_conv = &gsm0503_mcs1,
		.data_punc = {
			gsm0503_puncture_mcs1_p1,
			gsm0503_puncture_mcs1_p2,
			NULL,
		},
	},
	{
		.mcs = EGPRS_MCS2,
		.usf_len = 3,
		.hdr_len = 28,
		.hdr_code_len = 108,
		.hdr_punc_len = 68,
		.hdr_conv = &gsm0503_mcs1_dl_hdr,
		.hdr_punc = gsm0503_puncture_mcs1_dl_hdr,

		.data_len = 226,
		.data_code_len = 732,
		.data_punc_len = 372,
		.data_conv = &gsm0503_mcs2,
		.data_punc = {
			gsm0503_puncture_mcs2_p1,
			gsm0503_puncture_mcs2_p2,
			NULL,
		},
	},
	{
		.mcs = EGPRS_MCS3,
		.usf_len = 3,
		.hdr_len = 28,
		.hdr_code_len = 108,
		.hdr_punc_len = 68,
		.hdr_conv = &gsm0503_mcs1_dl_hdr,
		.hdr_punc = gsm0503_puncture_mcs1_dl_hdr,

		.data_len = 298,
		.data_code_len = 948,
		.data_punc_len = 372,
		.data_conv = &gsm0503_mcs3,
		.data_punc = {
			gsm0503_puncture_mcs3_p1,
			gsm0503_puncture_mcs3_p2,
			gsm0503_puncture_mcs3_p3,
		},
	},
	{
		.mcs = EGPRS_MCS4,
		.usf_len = 3,
		.hdr_len = 28,
		.hdr_code_len = 108,
		.hdr_punc_len = 68,
		.hdr_conv = &gsm0503_mcs1_dl_hdr,
		.hdr_punc = gsm0503_puncture_mcs1_dl_hdr,

		.data_len = 354,
		.data_code_len = 1116,
		.data_punc_len = 372,
		.data_conv = &gsm0503_mcs4,
		.data_punc = {
			gsm0503_puncture_mcs4_p1,
			gsm0503_puncture_mcs4_p2,
			gsm0503_puncture_mcs4_p3,
		},
	},
	{
		.mcs = EGPRS_MCS5,
		.usf_len = 3,
		.hdr_len = 25,
		.hdr_code_len = 99,
		.hdr_punc_len = 100,
		.hdr_conv = &gsm0503_mcs5_dl_hdr,
		.hdr_punc = NULL,

		.data_len = 450,
		.data_code_len = 1404,
		.data_punc_len = 1248,
		.data_conv = &gsm0503_mcs5,
		.data_punc = {
			gsm0503_puncture_mcs5_p1,
			gsm0503_puncture_mcs5_p2,
			NULL,
		},
	},
	{
		.mcs = EGPRS_MCS6,
		.usf_len = 3,
		.hdr_len = 25,
		.hdr_code_len = 99,
		.hdr_punc_len = 100,
		.hdr_conv = &gsm0503_mcs5_dl_hdr,
		.hdr_punc = NULL,

		.data_len = 594,
		.data_code_len = 1836,
		.data_punc_len = 1248,
		.data_conv = &gsm0503_mcs6,
		.data_punc = {
			gsm0503_puncture_mcs6_p1,
			gsm0503_puncture_mcs6_p2,
			NULL,
		},
	},
	{
		.mcs = EGPRS_MCS7,
		.usf_len = 3,
		.hdr_len = 37,
		.hdr_code_len = 135,
		.hdr_punc_len = 124,
		.hdr_conv = &gsm0503_mcs7_dl_hdr,
		.hdr_punc = gsm0503_puncture_mcs7_dl_hdr,

		.data_len = 900,
		.data_code_len = 1404,
		.data_punc_len = 612,
		.data_conv = &gsm0503_mcs7,
		.data_punc = {
			gsm0503_puncture_mcs7_p1,
			gsm0503_puncture_mcs7_p2,
			gsm0503_puncture_mcs7_p3,
		}
	},
	{
		.mcs = EGPRS_MCS8,
		.usf_len = 3,
		.hdr_len = 37,
		.hdr_code_len = 135,
		.hdr_punc_len = 124,
		.hdr_conv = &gsm0503_mcs7_dl_hdr,
		.hdr_punc = gsm0503_puncture_mcs7_dl_hdr,

		.data_len = 1092,
		.data_code_len = 1692,
		.data_punc_len = 612,
		.data_conv = &gsm0503_mcs8,
		.data_punc = {
			gsm0503_puncture_mcs8_p1,
			gsm0503_puncture_mcs8_p2,
			gsm0503_puncture_mcs8_p3,
		}
	},
	{
		.mcs = EGPRS_MCS9,
		.usf_len = 3,
		.hdr_len = 37,
		.hdr_code_len = 135,
		.hdr_punc_len = 124,
		.hdr_conv = &gsm0503_mcs7_dl_hdr,
		.hdr_punc = gsm0503_puncture_mcs7_dl_hdr,

		.data_len = 1188,
		.data_code_len = 1836,
		.data_punc_len = 612,
		.data_conv = &gsm0503_mcs9,
		.data_punc = {
			gsm0503_puncture_mcs9_p1,
			gsm0503_puncture_mcs9_p2,
			gsm0503_puncture_mcs9_p3,
		}
	},
};

/*! Convolutional Decode + compute BER for punctured codes
 *  \param[in] code Description of Convolutional Code
 *  \param[in] input Input soft-bits (-127...127)
 *  \param[out] output bits
 *  \param[out] n_errors Number of bit-errors
 *  \param[out] n_bits_total Number of bits
 *  \param[in] data_punc Puncturing mask array. Can be NULL.
 */
static int osmo_conv_decode_ber_punctured(const struct osmo_conv_code *code,
	const sbit_t *input, ubit_t *output,
	int *n_errors, int *n_bits_total,
	const uint8_t *data_punc)
{
	int res, i, coded_len;
	ubit_t recoded[EGPRS_DATA_C_MAX];

	res = osmo_conv_decode(code, input, output);

	if (!n_bits_total && !n_errors)
		return res;

	coded_len = osmo_conv_encode(code, output, recoded);
	OSMO_ASSERT(ARRAY_SIZE(recoded) >= coded_len);

	/* Count bit errors */
	if (n_errors) {
		*n_errors = 0;
		for (i = 0; i < coded_len; i++) {
			if (((!data_punc) || (data_punc && !data_punc[i])) &&
				!((recoded[i] && input[i] < 0) ||
					(!recoded[i] && input[i] > 0)) )
						*n_errors += 1;
		}
	}

	if (n_bits_total)
		*n_bits_total = coded_len;

	return res;
}

/*! Convolutional Decode + compute BER for non-punctured codes
 *  \param[in] code Description of Convolutional Code
 *  \param[in] input Input soft-bits (-127...127)
 *  \param[out] output bits
 *  \param[out] n_errors Number of bit-errors
 *  \param[out] n_bits_total Number of bits
 */
static int osmo_conv_decode_ber(const struct osmo_conv_code *code,
	const sbit_t *input, ubit_t *output,
	int *n_errors, int *n_bits_total)
{
	return osmo_conv_decode_ber_punctured(code, input, output,
		n_errors, n_bits_total, NULL);
}

/*! convenience wrapper for decoding coded bits
 *  \param[out] l2_data caller-allocated buffer for L2 Frame
 *  \param[in] cB 456 coded (soft) bits as per TS 05.03 4.1.3
 *  \param[out] n_errors Number of detected errors
 *  \param[out] n_bits_total Number of total coded bits
 *  \returns 0 on success; -1 on CRC error */
static int _xcch_decode_cB(uint8_t *l2_data, const sbit_t *cB,
	int *n_errors, int *n_bits_total)
{
	ubit_t conv[224];
	int rv;

	osmo_conv_decode_ber(&gsm0503_xcch, cB,
		conv, n_errors, n_bits_total);

	rv = osmo_crc64gen_check_bits(&gsm0503_fire_crc40,
		conv, 184, conv + 184);
	if (rv)
		return -1;

	osmo_ubit2pbit_ext(l2_data, 0, conv, 0, 184, 1);

	return 0;
}

/*! convenience wrapper for encoding to coded bits
 *  \param[out] cB caller-allocated buffer for 456 coded bits as per TS 05.03 4.1.3
 *  \param[out] l2_data to-be-encoded L2 Frame
 *  \returns 0 */
static int _xcch_encode_cB(ubit_t *cB, const uint8_t *l2_data)
{
	ubit_t conv[224];

	osmo_pbit2ubit_ext(conv, 0, l2_data, 0, 184, 1);

	osmo_crc64gen_set_bits(&gsm0503_fire_crc40, conv, 184, conv + 184);

	osmo_conv_encode(&gsm0503_xcch, conv, cB);

	return 0;
}

/*
 * GSM xCCH block transcoding
 */

/*! Decoding of xCCH data from bursts to L2 frame
 *  \param[out] l2_data caller-allocated output data buffer
 *  \param[in] bursts four GSM bursts in soft-bits
 *  \param[out] n_errors Number of detected errors
 *  \param[out] n_bits_total Number of total coded bits
 */
int gsm0503_xcch_decode(uint8_t *l2_data, const sbit_t *bursts,
	int *n_errors, int *n_bits_total)
{
	sbit_t iB[456], cB[456];
	int i;

	for (i = 0; i < 4; i++)
		gsm0503_xcch_burst_unmap(&iB[i * 114], &bursts[i * 116], NULL, NULL);

	gsm0503_xcch_deinterleave(cB, iB);

	return _xcch_decode_cB(l2_data, cB, n_errors, n_bits_total);
}

/*! Encoding of xCCH data from L2 frame to bursts
 *  \param[out] bursts caller-allocated burst data (unpacked bits)
 *  \param[in] l2_data L2 input data (MAC block)
 *  \returns 0
 */
int gsm0503_xcch_encode(ubit_t *bursts, const uint8_t *l2_data)
{
	ubit_t iB[456], cB[456], hl = 1, hn = 1;
	int i;

	_xcch_encode_cB(cB, l2_data);

	gsm0503_xcch_interleave(cB, iB);

	for (i = 0; i < 4; i++)
		gsm0503_xcch_burst_map(&iB[i * 114], &bursts[i * 116], &hl, &hn);

	return 0;
}

/*
 * EGPRS PDTCH UL block decoding
 */

/*
 * Type 3 - MCS-1,2,3,4
 * Unmapping and deinterleaving
 */
static int egprs_type3_unmap(const sbit_t *bursts, sbit_t *hc, sbit_t *dc)
{
	int i;
	sbit_t iB[456], q[8];

	for (i = 0; i < 4; i++) {
		gsm0503_xcch_burst_unmap(&iB[i * 114], &bursts[i * 116],
			q + i * 2, q + i * 2 + 1);
	}

	gsm0503_mcs1_ul_deinterleave(hc, dc, iB);

	return 0;
}

/*
 * Type 2 - MCS-5,6
 * Unmapping and deinterleaving
 */
static int egprs_type2_unmap(const sbit_t *bursts, sbit_t *hc, sbit_t *dc)
{
	int i;
	sbit_t burst[348];
	sbit_t hi[EGPRS_HDR_HC_MAX];
	sbit_t di[EGPRS_DATA_DC_MAX];

	for (i = 0; i < 4; i++) {
		memcpy(burst, &bursts[i * 348], 348);

		gsm0503_mcs5_burst_swap(burst);
		gsm0503_mcs5_ul_burst_unmap(di, burst, hi, i);
	}

	gsm0503_mcs5_ul_deinterleave(hc, dc, hi, di);

	return 0;
}

/*
 * Type 1 - MCS-7,8,9
 * Unmapping and deinterleaving - Note that MCS-7 interleaver is unique
 */
static int egprs_type1_unmap(const sbit_t *bursts, sbit_t *hc,
	sbit_t *c1, sbit_t *c2, int msc)
{
	int i;
	sbit_t burst[348];
	sbit_t hi[EGPRS_HDR_HC_MAX];
	sbit_t di[EGPRS_DATA_C1 * 2];

	for (i = 0; i < 4; i++) {
		memcpy(burst, &bursts[i * 348], 348);

		gsm0503_mcs5_burst_swap(burst);
		gsm0503_mcs7_ul_burst_unmap(di, burst, hi, i);
	}

	if (msc == EGPRS_MCS7)
		gsm0503_mcs7_ul_deinterleave(hc, c1, c2, hi, di);
	else
		gsm0503_mcs8_ul_deinterleave(hc, c1, c2, hi, di);

	return 0;
}

/*
 * Decode EGPRS UL header section
 *
 * 1. Depuncture
 * 2. Convolutional decoding
 * 3. CRC check
 */
static int _egprs_decode_hdr(const sbit_t *hc, int mcs,
	union gprs_rlc_ul_hdr_egprs *hdr)
{
	sbit_t C[EGPRS_HDR_C_MAX];
	ubit_t upp[EGPRS_HDR_UPP_MAX];
	int i, j, rc;
	const struct gsm0503_mcs_code *code;

	code = &gsm0503_mcs_ul_codes[mcs];

	/* Skip depuncturing on MCS-5,6 header */
	if ((mcs == EGPRS_MCS5) || (mcs == EGPRS_MCS6)) {
		memcpy(C, hc, code->hdr_code_len);
		goto hdr_conv_decode;
	}

	if (!code->hdr_punc) {
		/* Invalid MCS-X header puncture matrix */
		return -1;
	}

	i = code->hdr_code_len - 1;
	j = code->hdr_punc_len - 1;

	for (; i >= 0; i--) {
		if (!code->hdr_punc[i])
			C[i] = hc[j--];
		else
			C[i] = 0;
	}

hdr_conv_decode:
	osmo_conv_decode_ber(code->hdr_conv, C, upp, NULL, NULL);
	rc = osmo_crc8gen_check_bits(&gsm0503_mcs_crc8_hdr, upp,
		code->hdr_len, upp + code->hdr_len);
	if (rc)
		return -1;

	osmo_ubit2pbit_ext((pbit_t *) hdr, 0, upp, 0, code->hdr_len, 1);

	return 0;
}

/*
 * Blind MCS header decoding based on burst length and CRC validation.
 * Ignore 'q' value coding identification. This approach provides
 * the strongest chance of header recovery.
 */
static int egprs_decode_hdr(union gprs_rlc_ul_hdr_egprs *hdr,
	const sbit_t *bursts, uint16_t nbits)
{
	int rc;
	sbit_t hc[EGPRS_HDR_HC_MAX];

	if (nbits == GSM0503_GPRS_BURSTS_NBITS) {
		/* MCS-1,2,3,4 */
		egprs_type3_unmap(bursts, hc, NULL);
		rc = _egprs_decode_hdr(hc, EGPRS_MCS1, hdr);
		if (!rc)
			return EGPRS_HDR_TYPE3;
	} else if (nbits == GSM0503_EGPRS_BURSTS_NBITS) {
		/* MCS-5,6 */
		egprs_type2_unmap(bursts, hc, NULL);
		rc = _egprs_decode_hdr(hc, EGPRS_MCS5, hdr);
		if (!rc)
			return EGPRS_HDR_TYPE2;

		/* MCS-7,8,9 */
		egprs_type1_unmap(bursts, hc, NULL, NULL, EGPRS_MCS7);
		rc = _egprs_decode_hdr(hc, EGPRS_MCS7, hdr);
		if (!rc)
			return EGPRS_HDR_TYPE1;
	}

	return -1;
}

/*
 * Parse EGPRS UL header for coding and puncturing scheme (CPS)
 *
 * Type 1 - MCS-7,8,9
 * Type 2 - MCS-5,6
 * Type 3 - MCS-1,2,3,4
 */
static int egprs_parse_ul_cps(struct egprs_cps *cps,
	union gprs_rlc_ul_hdr_egprs *hdr, int type)
{
	uint8_t bits;

	switch (type) {
	case EGPRS_HDR_TYPE1:
		bits = hdr->type1.cps;
		break;
	case EGPRS_HDR_TYPE2:
		bits = (hdr->type2.cps_lo << 2) | hdr->type2.cps_hi;
		break;
	case EGPRS_HDR_TYPE3:
		bits = (hdr->type3.cps_lo << 2) | hdr->type3.cps_hi;
		break;
	default:
		return -1;
	}

	return egprs_get_cps(cps, type, bits);
}

/*
 * Decode EGPRS UL data section
 *
 * 1. Depuncture
 * 2. Convolutional decoding
 * 3. CRC check
 * 4. Block combining (MCS-7,8,9 only)
 */
static int egprs_decode_data(uint8_t *l2_data, const sbit_t *c,
	int mcs, int p, int blk, int *n_errors, int *n_bits_total)
{
	ubit_t u[EGPRS_DATA_U_MAX];
	sbit_t C[EGPRS_DATA_C_MAX];

	int i, j, rc, data_len;
	const struct gsm0503_mcs_code *code;

	if (blk && mcs < EGPRS_MCS7) {
		/* Invalid MCS-X block state */
		return -1;
	}

	code = &gsm0503_mcs_ul_codes[mcs];
	if (!code->data_punc[p]) {
		/* Invalid MCS-X data puncture matrix */
		return -1;
	}

	/*
	 * MCS-1,6 - single block processing
	 * MCS-7,9 - dual block processing
	 */
	if (mcs >= EGPRS_MCS7)
		data_len = code->data_len / 2;
	else
		data_len = code->data_len;

	i = code->data_code_len - 1;
	j = code->data_punc_len - 1;

	for (; i >= 0; i--) {
		if (!code->data_punc[p][i])
			C[i] = c[j--];
		else
			C[i] = 0;
	}

	osmo_conv_decode_ber_punctured(code->data_conv, C, u,
		n_errors, n_bits_total, code->data_punc[p]);
	rc = osmo_crc16gen_check_bits(&gsm0503_mcs_crc12, u,
		data_len, u + data_len);
	if (rc)
		return -1;

	/* Offsets output pointer on the second block of Type 1 MCS */
	osmo_ubit2pbit_ext(l2_data, code->hdr_len + blk * data_len,
		u, 0, data_len, 1);

	/* Return the number of bytes required for the bit message */
	return OSMO_BYTES_FOR_BITS(code->hdr_len + code->data_len);
}

/*! Decode EGPRS UL message
 * 	1. Header section decoding
 * 	2. Extract CPS settings
 * 	3. Burst unmapping and deinterleaving
 * 	4. Data section decoding
 *  \param[out] l2_data caller-allocated buffer for L2 Frame
 *  \param[in] bursts burst input data as soft unpacked bits
 *  \param[in] nbits number of bits in \a bursts
 *  \param usf_p unused argument ?!?
 *  \param[out] n_errors number of detected bit-errors
 *  \param[out] n_bits_total total number of decoded bits
 *  \returns 0 on success; negative on error */
int gsm0503_pdtch_egprs_decode(uint8_t *l2_data, const sbit_t *bursts, uint16_t nbits,
	uint8_t *usf_p, int *n_errors, int *n_bits_total)
{
	sbit_t dc[EGPRS_DATA_DC_MAX];
	sbit_t c1[EGPRS_DATA_C1], c2[EGPRS_DATA_C2];
	int type, rc;
	struct egprs_cps cps;
	union gprs_rlc_ul_hdr_egprs *hdr;

	if (n_errors)
		*n_errors = 0;
	if (n_bits_total)
		*n_bits_total = 0;

	if ((nbits != GSM0503_GPRS_BURSTS_NBITS) &&
		(nbits != GSM0503_EGPRS_BURSTS_NBITS)) {
		/* Invalid EGPRS bit length */
		return -EOVERFLOW;
	}

	hdr = (union gprs_rlc_ul_hdr_egprs *) l2_data;
	type = egprs_decode_hdr(hdr, bursts, nbits);
	if (egprs_parse_ul_cps(&cps, hdr, type) < 0)
		return -EIO;

	switch (cps.mcs) {
	case EGPRS_MCS0:
		return -ENOTSUP;
	case EGPRS_MCS1:
	case EGPRS_MCS2:
	case EGPRS_MCS3:
	case EGPRS_MCS4:
		egprs_type3_unmap(bursts, NULL, dc);
		break;
	case EGPRS_MCS5:
	case EGPRS_MCS6:
		egprs_type2_unmap(bursts, NULL, dc);
		break;
	case EGPRS_MCS7:
	case EGPRS_MCS8:
	case EGPRS_MCS9:
		egprs_type1_unmap(bursts, NULL, c1, c2, cps.mcs);
		break;
	default:
		/* Invalid MCS-X */
		return -EINVAL;
	}

	/* Decode MCS-X block, where X = cps.mcs */
	if (cps.mcs < EGPRS_MCS7) {
		rc = egprs_decode_data(l2_data, dc, cps.mcs, cps.p[0],
			0, n_errors, n_bits_total);
		if (rc < 0)
			return -EFAULT;
	} else {
		/* Bit counters for the second block */
		int n_errors2, n_bits_total2;

		/* MCS-7,8,9 block 1 */
		rc = egprs_decode_data(l2_data, c1, cps.mcs, cps.p[0],
			0, n_errors, n_bits_total);
		if (rc < 0)
			return -EFAULT;

		/* MCS-7,8,9 block 2 */
		rc = egprs_decode_data(l2_data, c2, cps.mcs, cps.p[1],
			1, &n_errors2, &n_bits_total2);
		if (n_errors)
			*n_errors += n_errors2;
		if (n_bits_total)
			*n_bits_total += n_bits_total2;
		if (rc < 0)
			return -EFAULT;
	}

	return rc;
}

/*
 * GSM PDTCH block transcoding
 */

/*! Decode GPRS PDTCH
 *  \param[out] l2_data caller-allocated buffer for L2 Frame
 *  \param[in] bursts burst input data as soft unpacked bits
 *  \param[out] usf_p uplink stealing flag
 *  \param[out] n_errors number of detected bit-errors
 *  \param[out] n_bits_total total number of dcoded bits
 *  \returns 0 on success; negative on error */
int gsm0503_pdtch_decode(uint8_t *l2_data, const sbit_t *bursts, uint8_t *usf_p,
	int *n_errors, int *n_bits_total)
{
	sbit_t iB[456], cB[676], hl_hn[8];
	ubit_t conv[456];
	int i, j, k, rv, best = 0, cs = 0, usf = 0; /* make GCC happy */

	for (i = 0; i < 4; i++)
		gsm0503_xcch_burst_unmap(&iB[i * 114], &bursts[i * 116],
			hl_hn + i * 2, hl_hn + i * 2 + 1);

	for (i = 0; i < 4; i++) {
		for (j = 0, k = 0; j < 8; j++)
			k += abs(((int)gsm0503_pdtch_hl_hn_sbit[i][j]) - ((int)hl_hn[j]));

		if (i == 0 || k < best) {
			best = k;
			cs = i + 1;
		}
	}

	gsm0503_xcch_deinterleave(cB, iB);

	switch (cs) {
	case 1:
		osmo_conv_decode_ber(&gsm0503_xcch, cB,
			conv, n_errors, n_bits_total);

		rv = osmo_crc64gen_check_bits(&gsm0503_fire_crc40,
			conv, 184, conv + 184);
		if (rv)
			return -1;

		osmo_ubit2pbit_ext(l2_data, 0, conv, 0, 184, 1);

		return 23;
	case 2:
		for (i = 587, j = 455; i >= 0; i--) {
			if (!gsm0503_puncture_cs2[i])
				cB[i] = cB[j--];
			else
				cB[i] = 0;
		}

		osmo_conv_decode_ber(&gsm0503_cs2_np, cB,
			conv, n_errors, n_bits_total);

		for (i = 0; i < 8; i++) {
			for (j = 0, k = 0; j < 6; j++)
				k += abs(((int)gsm0503_usf2six[i][j]) - ((int)conv[j]));

			if (i == 0 || k < best) {
				best = k;
				usf = i;
			}
		}

		conv[3] = usf & 1;
		conv[4] = (usf >> 1) & 1;
		conv[5] = (usf >> 2) & 1;
		if (usf_p)
			*usf_p = usf;

		rv = osmo_crc16gen_check_bits(&gsm0503_cs234_crc16,
			conv + 3, 271, conv + 3 + 271);
		if (rv)
			return -1;

		osmo_ubit2pbit_ext(l2_data, 0, conv, 3, 271, 1);

		return 34;
	case 3:
		for (i = 675, j = 455; i >= 0; i--) {
			if (!gsm0503_puncture_cs3[i])
				cB[i] = cB[j--];
			else
				cB[i] = 0;
		}

		osmo_conv_decode_ber(&gsm0503_cs3_np, cB,
			conv, n_errors, n_bits_total);

		for (i = 0; i < 8; i++) {
			for (j = 0, k = 0; j < 6; j++)
				k += abs(((int)gsm0503_usf2six[i][j]) - ((int)conv[j]));

			if (i == 0 || k < best) {
				best = k;
				usf = i;
			}
		}

		conv[3] = usf & 1;
		conv[4] = (usf >> 1) & 1;
		conv[5] = (usf >> 2) & 1;
		if (usf_p)
			*usf_p = usf;

		rv = osmo_crc16gen_check_bits(&gsm0503_cs234_crc16,
			conv + 3, 315, conv + 3 + 315);
		if (rv)
			return -1;

		osmo_ubit2pbit_ext(l2_data, 0, conv, 3, 315, 1);

		return 40;
	case 4:
		for (i = 12; i < 456; i++)
			conv[i] = (cB[i] < 0) ? 1 : 0;

		for (i = 0; i < 8; i++) {
			for (j = 0, k = 0; j < 12; j++)
				k += abs(((int)gsm0503_usf2twelve_sbit[i][j]) - ((int)cB[j]));

			if (i == 0 || k < best) {
				best = k;
				usf = i;
			}
		}

		conv[9] = usf & 1;
		conv[10] = (usf >> 1) & 1;
		conv[11] = (usf >> 2) & 1;
		if (usf_p)
			*usf_p = usf;

		rv = osmo_crc16gen_check_bits(&gsm0503_cs234_crc16,
			conv + 9, 431, conv + 9 + 431);
		if (rv) {
			*n_bits_total = 456 - 12;
			*n_errors = *n_bits_total;
			return -1;
		}

		*n_bits_total = 456 - 12;
		*n_errors = 0;

		osmo_ubit2pbit_ext(l2_data, 0, conv, 9, 431, 1);

		return 54;
	default:
		*n_bits_total = 0;
		*n_errors = 0;
		break;
	}

	return -1;
}

/*
 * EGPRS PDTCH DL block encoding
 */
static int egprs_type3_map(ubit_t *bursts, const ubit_t *hc, const ubit_t *dc, int usf)
{
	int i;
	ubit_t iB[456];
	const ubit_t *hl_hn = gsm0503_pdtch_hl_hn_ubit[3];

	gsm0503_mcs1_dl_interleave(gsm0503_usf2twelve_ubit[usf], hc, dc, iB);

	for (i = 0; i < 4; i++) {
		gsm0503_xcch_burst_map(&iB[i * 114], &bursts[i * 116],
			hl_hn + i * 2, hl_hn + i * 2 + 1);
	}

	return 0;
}

static int egprs_type2_map(ubit_t *bursts, const ubit_t *hc, const ubit_t *dc, int usf)
{
	int i;
	const ubit_t *up;
	ubit_t hi[EGPRS_HDR_HC_MAX];
	ubit_t di[EGPRS_DATA_DC_MAX];

	gsm0503_mcs5_dl_interleave(hc, dc, hi, di);
	up = gsm0503_mcs5_usf_precode_table[usf];

	for (i = 0; i < 4; i++) {
		gsm0503_mcs5_dl_burst_map(di, &bursts[i * 348], hi, up, i);
		gsm0503_mcs5_burst_swap((sbit_t *) &bursts[i * 348]);
	}

	return 0;
}

static int egprs_type1_map(ubit_t *bursts, const ubit_t *hc,
	const ubit_t *c1, const ubit_t *c2, int usf, int mcs)
{
	int i;
	const ubit_t *up;
	ubit_t hi[EGPRS_HDR_HC_MAX];
	ubit_t di[EGPRS_DATA_C1 * 2];

	if (mcs == EGPRS_MCS7)
		gsm0503_mcs7_dl_interleave(hc, c1, c2, hi, di);
	else
		gsm0503_mcs8_dl_interleave(hc, c1, c2, hi, di);

	up = gsm0503_mcs5_usf_precode_table[usf];

	for (i = 0; i < 4; i++) {
		gsm0503_mcs7_dl_burst_map(di, &bursts[i * 348], hi, up, i);
		gsm0503_mcs5_burst_swap((sbit_t *) &bursts[i * 348]);
	}

	return 0;
}

static int egprs_encode_hdr(ubit_t *hc, const uint8_t *l2_data, int mcs)
{
	int i, j;
	ubit_t upp[EGPRS_HDR_UPP_MAX], C[EGPRS_HDR_C_MAX];
	const struct gsm0503_mcs_code *code;

	code = &gsm0503_mcs_dl_codes[mcs];

	osmo_pbit2ubit_ext(upp, 0, l2_data, code->usf_len, code->hdr_len, 1);
	osmo_crc8gen_set_bits(&gsm0503_mcs_crc8_hdr, upp,
		code->hdr_len, upp + code->hdr_len);

	osmo_conv_encode(code->hdr_conv, upp, C);

	/* MCS-5,6 header direct puncture instead of table */
	if ((mcs == EGPRS_MCS5) || (mcs == EGPRS_MCS6)) {
		memcpy(hc, C, code->hdr_code_len);
		hc[99] = hc[98];
		return 0;
	}

	if (!code->hdr_punc) {
		/* Invalid MCS-X header puncture matrix */
		return -1;
	}

	for (i = 0, j = 0; i < code->hdr_code_len; i++) {
		if (!code->hdr_punc[i])
			hc[j++] = C[i];
	}

	return 0;
}

static int egprs_encode_data(ubit_t *c, const uint8_t *l2_data,
	int mcs, int p, int blk)
{
	int i, j, data_len;
	ubit_t u[EGPRS_DATA_U_MAX], C[EGPRS_DATA_C_MAX];
	const struct gsm0503_mcs_code *code;

	code = &gsm0503_mcs_dl_codes[mcs];

	/*
	 * Dual block   - MCS-7,8,9
	 * Single block - MCS-1,2,3,4,5,6
	 */
	if (mcs >= EGPRS_MCS7)
		data_len = code->data_len / 2;
	else
		data_len = code->data_len;

	osmo_pbit2ubit_ext(u, 0, l2_data,
		code->usf_len + code->hdr_len + blk * data_len, data_len, 1);

	osmo_crc16gen_set_bits(&gsm0503_mcs_crc12, u, data_len, u + data_len);

	osmo_conv_encode(code->data_conv, u, C);

	if (!code->data_punc[p]) {
		/* Invalid MCS-X data puncture matrix */
		return -1;
	}

	for (i = 0, j = 0; i < code->data_code_len; i++) {
		if (!code->data_punc[p][i])
			c[j++] = C[i];
	}

	return 0;
}

/*
 * Parse EGPRS DL header for coding and puncturing scheme (CPS)
 *
 * Type 1 - MCS-7,8,9
 * Type 2 - MCS-5,6
 * Type 3 - MCS-1,2,3,4
 */
static int egprs_parse_dl_cps(struct egprs_cps *cps,
	const union gprs_rlc_dl_hdr_egprs *hdr, int type)
{
	uint8_t bits;

	switch (type) {
	case EGPRS_HDR_TYPE1:
		bits = hdr->type1.cps;
		break;
	case EGPRS_HDR_TYPE2:
		bits = hdr->type2.cps;
		break;
	case EGPRS_HDR_TYPE3:
		bits = hdr->type3.cps;
		break;
	default:
		return -1;
	}

	return egprs_get_cps(cps, type, bits);
}

/*! EGPRS DL message encoding
 *  \param[out] bursts caller-allocated buffer for unpacked burst bits
 *  \param[in] l2_data L2 (MAC) block to be encoded
 *  \param[in] l2_len length of l2_data in bytes, used to determine MCS
 *  \returns number of bits encoded; negative on error */
int gsm0503_pdtch_egprs_encode(ubit_t *bursts,
	const uint8_t *l2_data, uint8_t l2_len)
{
	ubit_t hc[EGPRS_DATA_C_MAX], dc[EGPRS_DATA_DC_MAX];
	ubit_t c1[EGPRS_DATA_C1], c2[EGPRS_DATA_C2];
	uint8_t mcs;
	struct egprs_cps cps;
	union gprs_rlc_dl_hdr_egprs *hdr;

	switch (l2_len) {
	case 27:
		mcs = EGPRS_MCS1;
		break;
	case 33:
		mcs = EGPRS_MCS2;
		break;
	case 42:
		mcs = EGPRS_MCS3;
		break;
	case 49:
		mcs = EGPRS_MCS4;
		break;
	case 60:
		mcs = EGPRS_MCS5;
		break;
	case 78:
		mcs = EGPRS_MCS6;
		break;
	case 118:
		mcs = EGPRS_MCS7;
		break;
	case 142:
		mcs = EGPRS_MCS8;
		break;
	case 154:
		mcs = EGPRS_MCS9;
		break;
	default:
		return -1;
	}

	/* Read header for USF and puncturing matrix selection. */
	hdr = (union gprs_rlc_dl_hdr_egprs *) l2_data;

	switch (mcs) {
	case EGPRS_MCS1:
	case EGPRS_MCS2:
	case EGPRS_MCS3:
	case EGPRS_MCS4:
		/* Check for valid CPS and matching MCS to message size */
		if ((egprs_parse_dl_cps(&cps, hdr, EGPRS_HDR_TYPE3) < 0) ||
			(cps.mcs != mcs))
			goto bad_header;

		egprs_encode_hdr(hc, l2_data, mcs);
		egprs_encode_data(dc, l2_data, mcs, cps.p[0], 0);
		egprs_type3_map(bursts, hc, dc, hdr->type3.usf);
		break;
	case EGPRS_MCS5:
	case EGPRS_MCS6:
		if ((egprs_parse_dl_cps(&cps, hdr, EGPRS_HDR_TYPE2) < 0) ||
			(cps.mcs != mcs))
			goto bad_header;

		egprs_encode_hdr(hc, l2_data, mcs);
		egprs_encode_data(dc, l2_data, mcs, cps.p[0], 0);
		egprs_type2_map(bursts, hc, dc, hdr->type2.usf);
		break;
	case EGPRS_MCS7:
	case EGPRS_MCS8:
	case EGPRS_MCS9:
		if ((egprs_parse_dl_cps(&cps, hdr, EGPRS_HDR_TYPE1) < 0) ||
			(cps.mcs != mcs))
			goto bad_header;

		egprs_encode_hdr(hc, l2_data, mcs);
		egprs_encode_data(c1, l2_data, mcs, cps.p[0], 0);
		egprs_encode_data(c2, l2_data, mcs, cps.p[1], 1);
		egprs_type1_map(bursts, hc, c1, c2, hdr->type1.usf, mcs);
		break;
	}

	return mcs >= EGPRS_MCS5 ?
		GSM0503_EGPRS_BURSTS_NBITS : GSM0503_GPRS_BURSTS_NBITS;

bad_header:
	/* Invalid EGPRS MCS-X header */
	return -1;
}

/*! GPRS DL message encoding
 *  \param[out] bursts caller-allocated buffer for unpacked burst bits
 *  \param[in] l2_data L2 (MAC) block to be encoded
 *  \param[in] l2_len length of l2_data in bytes, used to determine CS
 *  \returns number of bits encoded; negative on error */
int gsm0503_pdtch_encode(ubit_t *bursts, const uint8_t *l2_data, uint8_t l2_len)
{
	ubit_t iB[456], cB[676];
	const ubit_t *hl_hn;
	ubit_t conv[334];
	int i, j, usf;

	switch (l2_len) {
	case 23:
		osmo_pbit2ubit_ext(conv, 0, l2_data, 0, 184, 1);

		osmo_crc64gen_set_bits(&gsm0503_fire_crc40, conv, 184, conv + 184);

		osmo_conv_encode(&gsm0503_xcch, conv, cB);

		hl_hn = gsm0503_pdtch_hl_hn_ubit[0];

		break;
	case 34:
		osmo_pbit2ubit_ext(conv, 3, l2_data, 0, 271, 1);
		usf = l2_data[0] & 0x7;

		osmo_crc16gen_set_bits(&gsm0503_cs234_crc16, conv + 3,
			271, conv + 3 + 271);

		memcpy(conv, gsm0503_usf2six[usf], 6);

		osmo_conv_encode(&gsm0503_cs2_np, conv, cB);

		for (i = 0, j = 0; i < 588; i++)
			if (!gsm0503_puncture_cs2[i])
				cB[j++] = cB[i];

		hl_hn = gsm0503_pdtch_hl_hn_ubit[1];

		break;
	case 40:
		osmo_pbit2ubit_ext(conv, 3, l2_data, 0, 315, 1);
		usf = l2_data[0] & 0x7;

		osmo_crc16gen_set_bits(&gsm0503_cs234_crc16, conv + 3,
			315, conv + 3 + 315);

		memcpy(conv, gsm0503_usf2six[usf], 6);

		osmo_conv_encode(&gsm0503_cs3_np, conv, cB);

		for (i = 0, j = 0; i < 676; i++)
			if (!gsm0503_puncture_cs3[i])
				cB[j++] = cB[i];

		hl_hn = gsm0503_pdtch_hl_hn_ubit[2];

		break;
	case 54:
		osmo_pbit2ubit_ext(cB, 9, l2_data, 0, 431, 1);
		usf = l2_data[0] & 0x7;

		osmo_crc16gen_set_bits(&gsm0503_cs234_crc16, cB + 9,
			431, cB + 9 + 431);

		memcpy(cB, gsm0503_usf2twelve_ubit[usf], 12);

		hl_hn = gsm0503_pdtch_hl_hn_ubit[3];

		break;
	default:
		return -1;
	}

	gsm0503_xcch_interleave(cB, iB);

	for (i = 0; i < 4; i++) {
		gsm0503_xcch_burst_map(&iB[i * 114], &bursts[i * 116],
			hl_hn + i * 2, hl_hn + i * 2 + 1);
	}

	return GSM0503_GPRS_BURSTS_NBITS;
}

/*
 * GSM TCH/F FR/EFR transcoding
 */

/*! assemble a FR codec frame in format as used inside RTP
 *  \param[out] tch_data Codec frame in RTP format
 *  \param[in] b_bits Codec frame in 'native' format
 *  \param[in] net_order FIXME */
static void tch_fr_reassemble(uint8_t *tch_data,
	const ubit_t *b_bits, int net_order)
{
	int i, j, k, l, o;

	tch_data[0] = 0xd << 4;
	memset(tch_data + 1, 0, 32);

	if (net_order) {
		for (i = 0, j = 4; i < 260; i++, j++)
			tch_data[j >> 3] |= (b_bits[i] << (7 - (j & 7)));

		return;
	}

	/* reassemble d-bits */
	i = 0; /* counts bits */
	j = 4; /* counts output bits */
	k = gsm0503_gsm_fr_map[0]-1; /* current number bit in element */
	l = 0; /* counts element bits */
	o = 0; /* offset input bits */
	while (i < 260) {
		tch_data[j >> 3] |= (b_bits[k + o] << (7 - (j & 7)));
		if (--k < 0) {
			o += gsm0503_gsm_fr_map[l];
			k = gsm0503_gsm_fr_map[++l]-1;
		}
		i++;
		j++;
	}
}

static void tch_fr_disassemble(ubit_t *b_bits,
	const uint8_t *tch_data, int net_order)
{
	int i, j, k, l, o;

	if (net_order) {
		for (i = 0, j = 4; i < 260; i++, j++)
			b_bits[i] = (tch_data[j >> 3] >> (7 - (j & 7))) & 1;

		return;
	}

	i = 0; /* counts bits */
	j = 4; /* counts input bits */
	k = gsm0503_gsm_fr_map[0] - 1; /* current number bit in element */
	l = 0; /* counts element bits */
	o = 0; /* offset output bits */
	while (i < 260) {
		b_bits[k + o] = (tch_data[j >> 3] >> (7 - (j & 7))) & 1;
		if (--k < 0) {
			o += gsm0503_gsm_fr_map[l];
			k = gsm0503_gsm_fr_map[++l] - 1;
		}
		i++;
		j++;
	}
}

/* assemble a HR codec frame in format as used inside RTP */
static void tch_hr_reassemble(uint8_t *tch_data, const ubit_t *b_bits)
{
	int i, j;

	tch_data[0] = 0x00; /* F = 0, FT = 000 */
	memset(tch_data + 1, 0, 14);

	for (i = 0, j = 8; i < 112; i++, j++)
		tch_data[j >> 3] |= (b_bits[i] << (7 - (j & 7)));
}

static void tch_hr_disassemble(ubit_t *b_bits, const uint8_t *tch_data)
{
	int i, j;

	for (i = 0, j = 8; i < 112; i++, j++)
		b_bits[i] = (tch_data[j >> 3] >> (7 - (j & 7))) & 1;
}

/* assemble a EFR codec frame in format as used inside RTP */
static void tch_efr_reassemble(uint8_t *tch_data, const ubit_t *b_bits)
{
	int i, j;

	tch_data[0] = 0xc << 4;
	memset(tch_data + 1, 0, 30);

	for (i = 0, j = 4; i < 244; i++, j++)
		tch_data[j >> 3] |= (b_bits[i] << (7 - (j & 7)));
}

static void tch_efr_disassemble(ubit_t *b_bits, const uint8_t *tch_data)
{
	int i, j;

	for (i = 0, j = 4; i < 244; i++, j++)
		b_bits[i] = (tch_data[j >> 3] >> (7 - (j & 7))) & 1;
}

/* assemble a AMR codec frame in format as used inside RTP */
static void tch_amr_reassemble(uint8_t *tch_data, const ubit_t *d_bits, int len)
{
	int i, j;

	memset(tch_data, 0, (len + 7) >> 3);

	for (i = 0, j = 0; i < len; i++, j++)
		tch_data[j >> 3] |= (d_bits[i] << (7 - (j & 7)));
}

static void tch_amr_disassemble(ubit_t *d_bits, const uint8_t *tch_data, int len)
{
	int i, j;

	for (i = 0, j = 0; i < len; i++, j++)
		d_bits[i] = (tch_data[j >> 3] >> (7 - (j & 7))) & 1;
}

/* Append STI and MI bits to the SID_UPDATE frame, see also
 * 3GPP TS 26.101, chapter 4.2.3 AMR Core Frame with comfort noise bits */
static void tch_amr_sid_update_append(ubit_t *sid_update, uint8_t sti, uint8_t mi)
{
	/* Zero out the space that had been used by the CRC14 */
	memset(sid_update + 35, 0, 14);

	/* Append STI and MI parameters */
	sid_update[35] = sti & 1;
	sid_update[36] = mi & 1;
	sid_update[37] = mi >> 1 & 1;
	sid_update[38] = mi >> 2 & 1;
}

/* Extract a SID UPDATE fram the sbits of an FR AMR frame */
static void extract_afs_sid_update(sbit_t *sid_update, const sbit_t *sbits)
{

	unsigned int i;

	sbits += 32;

	for (i = 0; i < 53; i++) {
		sid_update[0] = sbits[0];
		sid_update[1] = sbits[1];
		sid_update[2] = sbits[2];
		sid_update[3] = sbits[3];
		sid_update += 4;
		sbits += 8;
	}

}

/* re-arrange according to TS 05.03 Table 2 (receiver) */
static void tch_fr_d_to_b(ubit_t *b_bits, const ubit_t *d_bits)
{
	int i;

	for (i = 0; i < 260; i++)
		b_bits[gsm610_bitorder[i]] = d_bits[i];
}

/* re-arrange according to TS 05.03 Table 2 (transmitter) */
static void tch_fr_b_to_d(ubit_t *d_bits, const ubit_t *b_bits)
{
	int i;

	for (i = 0; i < 260; i++)
		d_bits[i] = b_bits[gsm610_bitorder[i]];
}

/* re-arrange according to TS 05.03 Table 3a (receiver) */
static void tch_hr_d_to_b(ubit_t *b_bits, const ubit_t *d_bits)
{
	int i;

	const uint16_t *map;

	if (!d_bits[93] && !d_bits[94])
		map = gsm620_unvoiced_bitorder;
	else
		map = gsm620_voiced_bitorder;

	for (i = 0; i < 112; i++)
		b_bits[map[i]] = d_bits[i];
}

/* re-arrange according to TS 05.03 Table 3a (transmitter) */
static void tch_hr_b_to_d(ubit_t *d_bits, const ubit_t *b_bits)
{
	int i;
	const uint16_t *map;

	if (!b_bits[34] && !b_bits[35])
		map = gsm620_unvoiced_bitorder;
	else
		map = gsm620_voiced_bitorder;

	for (i = 0; i < 112; i++)
		d_bits[i] = b_bits[map[i]];
}

/* re-arrange according to TS 05.03 Table 6 (receiver) */
static void tch_efr_d_to_w(ubit_t *b_bits, const ubit_t *d_bits)
{
	int i;

	for (i = 0; i < 260; i++)
		b_bits[gsm660_bitorder[i]] = d_bits[i];
}

/* re-arrange according to TS 05.03 Table 6 (transmitter) */
static void tch_efr_w_to_d(ubit_t *d_bits, const ubit_t *b_bits)
{
	int i;

	for (i = 0; i < 260; i++)
		d_bits[i] = b_bits[gsm660_bitorder[i]];
}

/* extract the 65 protected class1a+1b bits */
static void tch_efr_protected(const ubit_t *s_bits, ubit_t *b_bits)
{
	int i;

	for (i = 0; i < 65; i++)
		b_bits[i] = s_bits[gsm0503_gsm_efr_protected_bits[i] - 1];
}

static void tch_fr_unreorder(ubit_t *d, ubit_t *p, const ubit_t *u)
{
	int i;

	for (i = 0; i < 91; i++) {
		d[i << 1] = u[i];
		d[(i << 1) + 1] = u[184 - i];
	}

	for (i = 0; i < 3; i++)
		p[i] = u[91 + i];
}

static void tch_fr_reorder(ubit_t *u, const ubit_t *d, const ubit_t *p)
{
	int i;

	for (i = 0; i < 91; i++) {
		u[i] = d[i << 1];
		u[184 - i] = d[(i << 1) + 1];
	}

	for (i = 0; i < 3; i++)
		u[91 + i] = p[i];
}

static void tch_hr_unreorder(ubit_t *d, ubit_t *p, const ubit_t *u)
{
	memcpy(d, u, 95);
	memcpy(p, u + 95, 3);
}

static void tch_hr_reorder(ubit_t *u, const ubit_t *d, const ubit_t *p)
{
	memcpy(u, d, 95);
	memcpy(u + 95, p, 3);
}

static void tch_efr_reorder(ubit_t *w, const ubit_t *s, const ubit_t *p)
{
	memcpy(w, s, 71);
	w[71] = w[72] = s[69];
	memcpy(w + 73, s + 71, 50);
	w[123] = w[124] = s[119];
	memcpy(w + 125, s + 121, 53);
	w[178] = w[179] = s[172];
	memcpy(w + 180, s + 174, 50);
	w[230] = w[231] = s[222];
	memcpy(w + 232, s + 224, 20);
	memcpy(w + 252, p, 8);
}

static void tch_efr_unreorder(ubit_t *s, ubit_t *p, const ubit_t *w)
{
	int sum;

	memcpy(s, w, 71);
	sum = s[69] + w[71] + w[72];
	s[69] = (sum >= 2);
	memcpy(s + 71, w + 73, 50);
	sum = s[119] + w[123] + w[124];
	s[119] = (sum >= 2);
	memcpy(s + 121, w + 125, 53);
	sum = s[172] + w[178] + w[179];
	s[172] = (sum > 2);
	memcpy(s + 174, w + 180, 50);
	sum = s[222] + w[230] + w[231];
	s[222] = (sum >= 2);
	memcpy(s + 224, w + 232, 20);
	memcpy(p, w + 252, 8);
}

static void tch_amr_merge(ubit_t *u, const ubit_t *d, const ubit_t *p, int len, int prot)
{
	memcpy(u, d, prot);
	memcpy(u + prot, p, 6);
	memcpy(u + prot + 6, d + prot, len - prot);
}

static void tch_amr_unmerge(ubit_t *d, ubit_t *p, const ubit_t *u, int len, int prot)
{
	memcpy(d, u, prot);
	memcpy(p, u + prot, 6);
	memcpy(d + prot, u + prot + 6, len - prot);
}

/*! Perform channel decoding of a FR/EFR channel according TS 05.03
 *  \param[out] tch_data Codec frame in RTP payload format
 *  \param[in] bursts buffer containing the symbols of 8 bursts
 *  \param[in] net_order FIXME
 *  \param[in] efr Is this channel using EFR (1) or FR (0)
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \returns length of bytes used in \a tch_data output buffer; negative on error */
int gsm0503_tch_fr_decode(uint8_t *tch_data, const sbit_t *bursts,
	int net_order, int efr, int *n_errors, int *n_bits_total)
{
	sbit_t iB[912], cB[456], h;
	ubit_t conv[185], s[244], w[260], b[65], d[260], p[8];
	int i, rv, len, steal = 0;

	/* map from 8 bursts to interleaved data bits (iB) */
	for (i = 0; i < 8; i++) {
		gsm0503_tch_burst_unmap(&iB[i * 114],
			&bursts[i * 116], &h, i >> 2);
		steal -= h;
	}
	/* we now have the bits of the four bursts (interface 4 in
	 * Figure 1a of TS 05.03 */

	gsm0503_tch_fr_deinterleave(cB, iB);
	/* we now have the coded bits c(B): interface 3 in Fig. 1a */

	if (steal > 0) {
		rv = _xcch_decode_cB(tch_data, cB, n_errors, n_bits_total);
		if (rv) {
			/* Error decoding FACCH frame */
			return -1;
		}

		return 23;
	}

	osmo_conv_decode_ber(&gsm0503_tch_fr, cB, conv, n_errors, n_bits_total);
	/* we now have the data bits 'u': interface 2 in Fig. 1a */

	/* input: 'conv', output: d[ata] + p[arity] */
	tch_fr_unreorder(d, p, conv);

	for (i = 0; i < 78; i++)
		d[i + 182] = (cB[i + 378] < 0) ? 1 : 0;

	/* check if parity of first 50 (class 1) 'd'-bits match 'p' */
	rv = osmo_crc8gen_check_bits(&gsm0503_tch_fr_crc3, d, 50, p);
	if (rv) {
		/* Error checking CRC8 for the FR part of an EFR/FR frame */
		return -1;
	}

	if (efr) {
		tch_efr_d_to_w(w, d);
		/* we now have the preliminary-coded bits w(k) */

		tch_efr_unreorder(s, p, w);
		/* we now have the data delivered to the preliminary
		 * channel encoding unit s(k) */

		/* extract the 65 most important bits according TS 05.03 3.1.1.1 */
		tch_efr_protected(s, b);

		/* perform CRC-8 on 65 most important bits (50 bits of
		 * class 1a + 15 bits of class 1b) */
		rv = osmo_crc8gen_check_bits(&gsm0503_tch_efr_crc8, b, 65, p);
		if (rv) {
			/* Error checking CRC8 for the EFR part of an EFR frame */
			return -1;
		}

		tch_efr_reassemble(tch_data, s);

		len = GSM_EFR_BYTES;
	} else {
		tch_fr_d_to_b(w, d);

		tch_fr_reassemble(tch_data, w, net_order);

		len = GSM_FR_BYTES;
	}

	return len;
}

/*! Perform channel encoding on a TCH/FS channel according to TS 05.03
 *  \param[out] bursts caller-allocated output buffer for bursts bits
 *  \param[in] tch_data Codec input data in RTP payload format
 *  \param[in] len Length of \a tch_data in bytes
 *  \param[in] net_order FIXME
 *  \returns 0 in case of success; negative on error */
int gsm0503_tch_fr_encode(ubit_t *bursts, const uint8_t *tch_data,
	int len, int net_order)
{
	ubit_t iB[912], cB[456], h;
	ubit_t conv[185], w[260], b[65], s[244], d[260], p[8];
	int i;

	switch (len) {
	case GSM_EFR_BYTES: /* TCH EFR */

		tch_efr_disassemble(s, tch_data);

		tch_efr_protected(s, b);

		osmo_crc8gen_set_bits(&gsm0503_tch_efr_crc8, b, 65, p);

		tch_efr_reorder(w, s, p);

		tch_efr_w_to_d(d, w);

		goto coding_efr_fr;
	case GSM_FR_BYTES: /* TCH FR */
		tch_fr_disassemble(w, tch_data, net_order);

		tch_fr_b_to_d(d, w);

coding_efr_fr:
		osmo_crc8gen_set_bits(&gsm0503_tch_fr_crc3, d, 50, p);

		tch_fr_reorder(conv, d, p);

		memcpy(cB + 378, d + 182, 78);

		osmo_conv_encode(&gsm0503_tch_fr, conv, cB);

		h = 0;

		break;
	case GSM_MACBLOCK_LEN: /* FACCH */
		_xcch_encode_cB(cB, tch_data);

		h = 1;

		break;
	default:
		return -1;
	}

	gsm0503_tch_fr_interleave(cB, iB);

	for (i = 0; i < 8; i++) {
		gsm0503_tch_burst_map(&iB[i * 114],
			&bursts[i * 116], &h, i >> 2);
	}

	return 0;
}

/*! Perform channel decoding of a HR(v1) channel according TS 05.03
 *  \param[out] tch_data Codec frame in RTP payload format
 *  \param[in] bursts buffer containing the symbols of 8 bursts
 *  \param[in] odd Odd (1) or even (0) frame number
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \returns length of bytes used in \a tch_data output buffer; negative on error */
int gsm0503_tch_hr_decode(uint8_t *tch_data, const sbit_t *bursts, int odd,
	int *n_errors, int *n_bits_total)
{
	sbit_t iB[912], cB[456], h;
	ubit_t conv[98], b[112], d[112], p[3];
	int i, rv, steal = 0;

	/* Only unmap the stealing bits */
	if (!odd) {
		for (i = 0; i < 4; i++) {
			gsm0503_tch_burst_unmap(NULL, &bursts[i * 116], &h, 0);
			steal -= h;
		}

		for (i = 2; i < 5; i++) {
			gsm0503_tch_burst_unmap(NULL, &bursts[i * 116], &h, 1);
			steal -= h;
		}
	}

	/* If we found a stole FACCH, but only at correct alignment */
	if (steal > 0) {
		for (i = 0; i < 6; i++) {
			gsm0503_tch_burst_unmap(&iB[i * 114],
				&bursts[i * 116], NULL, i >> 2);
		}

		for (i = 2; i < 4; i++) {
			gsm0503_tch_burst_unmap(&iB[i * 114 + 456],
				&bursts[i * 116], NULL, 1);
		}

		gsm0503_tch_fr_deinterleave(cB, iB);

		rv = _xcch_decode_cB(tch_data, cB, n_errors, n_bits_total);
		if (rv) {
			/* Error decoding FACCH frame */
			return -1;
		}

		return GSM_MACBLOCK_LEN;
	}

	for (i = 0; i < 4; i++) {
		gsm0503_tch_burst_unmap(&iB[i * 114],
			&bursts[i * 116], NULL, i >> 1);
	}

	gsm0503_tch_hr_deinterleave(cB, iB);

	osmo_conv_decode_ber(&gsm0503_tch_hr, cB, conv, n_errors, n_bits_total);

	tch_hr_unreorder(d, p, conv);

	for (i = 0; i < 17; i++)
		d[i + 95] = (cB[i + 211] < 0) ? 1 : 0;

	rv = osmo_crc8gen_check_bits(&gsm0503_tch_fr_crc3, d + 73, 22, p);
	if (rv) {
		/* Error checking CRC8 for an HR frame */
		return -1;
	}

	tch_hr_d_to_b(b, d);

	tch_hr_reassemble(tch_data, b);

	return 15;
}

/*! Perform channel encoding on a TCH/HS channel according to TS 05.03
 *  \param[out] bursts caller-allocated output buffer for bursts bits
 *  \param[in] tch_data Codec input data in RTP payload format
 *  \param[in] len Length of \a tch_data in bytes
 *  \returns 0 in case of success; negative on error */
int gsm0503_tch_hr_encode(ubit_t *bursts, const uint8_t *tch_data, int len)
{
	ubit_t iB[912], cB[456], h;
	ubit_t conv[98], b[112], d[112], p[3];
	int i;

	switch (len) {
	case 15: /* TCH HR */
		tch_hr_disassemble(b, tch_data);

		tch_hr_b_to_d(d, b);

		osmo_crc8gen_set_bits(&gsm0503_tch_fr_crc3, d + 73, 22, p);

		tch_hr_reorder(conv, d, p);

		osmo_conv_encode(&gsm0503_tch_hr, conv, cB);

		memcpy(cB + 211, d + 95, 17);

		h = 0;

		gsm0503_tch_hr_interleave(cB, iB);

		for (i = 0; i < 4; i++) {
			gsm0503_tch_burst_map(&iB[i * 114],
				&bursts[i * 116], &h, i >> 1);
		}

		break;
	case GSM_MACBLOCK_LEN: /* FACCH */
		_xcch_encode_cB(cB, tch_data);

		h = 1;

		gsm0503_tch_fr_interleave(cB, iB);

		for (i = 0; i < 6; i++) {
			gsm0503_tch_burst_map(&iB[i * 114],
				&bursts[i * 116], &h, i >> 2);
		}

		for (i = 2; i < 4; i++) {
			gsm0503_tch_burst_map(&iB[i * 114 + 456],
				&bursts[i * 116], &h, 1);
		}

		break;
	default:
		return -1;
	}

	return 0;
}

/* TCH/AFS: parse codec ID (CMI or CMC/CMR) from coded in-band data (16 bit) */
static uint8_t gsm0503_tch_afs_decode_inband(const sbit_t *cB)
{
	unsigned int id = 0, best = 0;
	unsigned int i, j, k;

	for (i = 0; i < 4; i++) {
		/* FIXME: why not using remaining (16 - 8) soft-bits here? */
		for (j = 0, k = 0; j < 8; j++)
			k += abs(((int)gsm0503_afs_ic_sbit[i][j]) - ((int)cB[j]));

		if (i == 0 || k < best) {
			best = k;
			id = i;
		}
	}

	return id;
}

/*! Perform channel decoding of a TCH/AFS channel according TS 05.03
 *  \param[out] tch_data Codec frame in RTP payload format
 *  \param[in] bursts buffer containing the symbols of 8 bursts
 *  \param[in] codec_mode_req is this CMR (1) or CMC (0)
 *  \param[in] codec array of active codecs (active codec set)
 *  \param[in] codecs number of codecs in \a codec
 *  \param ft Frame Type; Input if \a codec_mode_req = 1, Output *  otherwise
 *  \param[out] cmr Output in \a codec_mode_req = 1
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \returns (>=4) length of bytes used in \a tch_data output buffer; ([0,3])
 *  	     codec out of range; negative on error
 */
int gsm0503_tch_afs_decode(uint8_t *tch_data, const sbit_t *bursts,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t *ft,
	uint8_t *cmr, int *n_errors, int *n_bits_total)
{
	return gsm0503_tch_afs_decode_dtx(tch_data, bursts, codec_mode_req,
					  codec, codecs, ft, cmr, n_errors,
					  n_bits_total, NULL);
}

/*! Perform channel decoding of a TCH/AFS channel according TS 05.03
 *  \param[out] tch_data Codec frame in RTP payload format
 *  \param[in] bursts buffer containing the symbols of 8 bursts
 *  \param[in] codec_mode_req is this CMR (1) or CMC (0)
 *  \param[in] codec array of active codecs (active codec set)
 *  \param[in] codecs number of codecs in \a codec
 *  \param ft Frame Type; Input if \a codec_mode_req = 1, Output *  otherwise
 *  \param[out] cmr Output in \a codec_mode_req = 1
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \param[inout] dtx DTX frame type output, previous DTX frame type input
 *  \returns (>=4) length of bytes used in \a tch_data output buffer; ([0,3])
 *  	     codec out of range; negative on error
 */
int gsm0503_tch_afs_decode_dtx(uint8_t *tch_data, const sbit_t *bursts,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t *ft,
	uint8_t *cmr, int *n_errors, int *n_bits_total, uint8_t *dtx)
{
	sbit_t iB[912], cB[456], h;
	ubit_t d[244], p[6], conv[250];
	int i, rv, len, steal = 0, id = -1;
	*n_errors = 0; *n_bits_total = 0;
	static ubit_t sid_first_dummy[64] = { 0 };
	sbit_t sid_update_enc[256];

	for (i=0; i<8; i++) {
		gsm0503_tch_burst_unmap(&iB[i * 114], &bursts[i * 116], &h, i >> 2);
		steal -= h;
	}

	gsm0503_tch_fr_deinterleave(cB, iB);

	if (steal > 0) {
		/* If not NULL, dtx indicates type of previously decoded TCH/AFS frame.
		 * It's normally updated by gsm0503_detect_afs_dtx_frame2(), which is not
		 * reached in case of FACCH.  Reset it here to avoid FACCH/F frames being
		 * misinterpreted as AMR's special DTX frames. */
		if (dtx != NULL)
			*dtx = AMR_OTHER;
		rv = _xcch_decode_cB(tch_data, cB, n_errors, n_bits_total);
		if (rv) {
			/* Error decoding FACCH frame */
			return -1;
		}

		return GSM_MACBLOCK_LEN;
	}

	/* Determine the DTX frame type (SID_UPDATE, ONSET etc...) */
	if (dtx) {
		const enum gsm0503_amr_dtx_frames dtx_prev = *dtx;

		*dtx = gsm0503_detect_afs_dtx_frame2(n_errors, n_bits_total, &id, cB);

		switch (*dtx) {
		case AMR_OTHER:
			/* NOTE: The AFS_SID_UPDATE frame is splitted into
			 * two half rate frames. If the id marker frame
			 * (AFS_SID_UPDATE) is detected the following frame
			 * contains the actual comfort noised data part of
			 * (AFS_SID_UPDATE_CN). */
			if (dtx_prev != AFS_SID_UPDATE)
				break;
			/* TODO: parse CMI _and_ CMC/CMR (16 + 16 bit) */
			*dtx = AFS_SID_UPDATE_CN;

			extract_afs_sid_update(sid_update_enc, cB);
			osmo_conv_decode_ber(&gsm0503_tch_axs_sid_update,
					     sid_update_enc, conv, n_errors,
					     n_bits_total);
			rv = osmo_crc16gen_check_bits(&gsm0503_amr_crc14, conv,
						      35, conv + 35);
			if (rv != 0) {
				/* Error checking CRC14 for an AMR SID_UPDATE frame */
				return -1;
			}

			tch_amr_sid_update_append(conv, 1,
						  (codec_mode_req) ? codec[*ft]
						  : codec[id > 0 ? id : 0]);
			tch_amr_reassemble(tch_data, conv, 39);
			len = 5;
			goto out;
		case AFS_SID_FIRST: /* TODO: parse CMI or CMC/CMR (16 bit) */
			tch_amr_sid_update_append(sid_first_dummy, 0,
						  (codec_mode_req) ? codec[*ft]
						  : codec[id > 0 ? id : 0]);
			tch_amr_reassemble(tch_data, conv, 39);
			len = 5;
			goto out;
		case AFS_SID_UPDATE: /* TODO: parse CMI _and_ CMC/CMR (16 + 16 bit) */
		case AFS_ONSET:
			len = 0;
			goto out;
		default:
			break;
		}
	}

	/* Parse codec ID (CMI or CMC/CMR) and check if it fits into range of codecs */
	if ((id = gsm0503_tch_afs_decode_inband(&cB[0])) >= codecs) {
		/* Codec mode out of range, return id */
		return id;
	}

	switch ((codec_mode_req) ? codec[*ft] : codec[id]) {
	case 7: /* TCH/AFS12.2 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_12_2, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 244, 81);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 81, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 12.2 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 244);

		len = 31;

		break;
	case 6: /* TCH/AFS10.2 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_10_2, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 204, 65);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 65, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 10.2 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 204);

		len = 26;

		break;
	case 5: /* TCH/AFS7.95 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_7_95, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 159, 75);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 75, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 7.95 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 159);

		len = 20;

		break;
	case 4: /* TCH/AFS7.4 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_7_4, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 148, 61);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 61, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 7.4 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 148);

		len = 19;

		break;
	case 3: /* TCH/AFS6.7 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_6_7, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 134, 55);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 55, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 6.7 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 134);

		len = 17;

		break;
	case 2: /* TCH/AFS5.9 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_5_9, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 118, 55);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 55, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 5.9 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 118);

		len = 15;

		break;
	case 1: /* TCH/AFS5.15 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_5_15, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 103, 49);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 49, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 5.15 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 103);

		len = 13;

		break;
	case 0: /* TCH/AFS4.75 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_4_75, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 95, 39);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 39, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 4.75 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 95);

		len = 12;

		break;
	default:
		/* Unknown frame type */
		*n_bits_total = 448;
		*n_errors = *n_bits_total;
		return -1;
	}

out:
	/* Change codec request / indication, if frame is valid */
	if (id != -1) {
		if (codec_mode_req)
			*cmr = id;
		else
			*ft = id;
	}

	return len;
}

/*! Perform channel encoding on a TCH/AFS channel according to TS 05.03
 *  \param[out] bursts caller-allocated output buffer for bursts bits
 *  \param[in] tch_data Codec input data in RTP payload format
 *  \param[in] len Length of \a tch_data in bytes
 *  \param[in] codec_mode_req Use CMR (1) or FT (0)
 *  \param[in] codec Array of codecs (active codec set)
 *  \param[in] codecs Number of entries in \a codec
 *  \param[in] ft Frame Type to be used for encoding (index to \a codec)
 *  \param[in] cmr Codec Mode Request (used in codec_mode_req = 1 only)
 *  \returns 0 in case of success; negative on error */
int gsm0503_tch_afs_encode(ubit_t *bursts, const uint8_t *tch_data, int len,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t ft,
	uint8_t cmr)
{
	ubit_t iB[912], cB[456], h;
	ubit_t d[244], p[6], conv[250];
	int i;
	uint8_t id;

	if (len == GSM_MACBLOCK_LEN) { /* FACCH */
		_xcch_encode_cB(cB, tch_data);

		h = 1;

		goto facch;
	}

	h = 0;

	if (codec_mode_req) {
		if (cmr >= codecs) {
			/* FIXME: CMR ID is not in codec list! */
			return -1;
		}
		id = cmr;
	} else {
		if (ft >= codecs) {
			/* FIXME: FT ID is not in codec list! */
			return -1;
		}
		id = ft;
	}

	switch (codec[ft]) {
	case 7: /* TCH/AFS12.2 */
		if (len != 31)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 244);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 81, p);

		tch_amr_merge(conv, d, p, 244, 81);

		osmo_conv_encode(&gsm0503_tch_afs_12_2, conv, cB + 8);

		break;
	case 6: /* TCH/AFS10.2 */
		if (len != 26)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 204);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 65, p);

		tch_amr_merge(conv, d, p, 204, 65);

		osmo_conv_encode(&gsm0503_tch_afs_10_2, conv, cB + 8);

		break;
	case 5: /* TCH/AFS7.95 */
		if (len != 20)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 159);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 75, p);

		tch_amr_merge(conv, d, p, 159, 75);

		osmo_conv_encode(&gsm0503_tch_afs_7_95, conv, cB + 8);

		break;
	case 4: /* TCH/AFS7.4 */
		if (len != 19)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 148);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 61, p);

		tch_amr_merge(conv, d, p, 148, 61);

		osmo_conv_encode(&gsm0503_tch_afs_7_4, conv, cB + 8);

		break;
	case 3: /* TCH/AFS6.7 */
		if (len != 17)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 134);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 55, p);

		tch_amr_merge(conv, d, p, 134, 55);

		osmo_conv_encode(&gsm0503_tch_afs_6_7, conv, cB + 8);

		break;
	case 2: /* TCH/AFS5.9 */
		if (len != 15)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 118);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 55, p);

		tch_amr_merge(conv, d, p, 118, 55);

		osmo_conv_encode(&gsm0503_tch_afs_5_9, conv, cB + 8);

		break;
	case 1: /* TCH/AFS5.15 */
		if (len != 13)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 103);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 49, p);

		tch_amr_merge(conv, d, p, 103, 49);

		osmo_conv_encode(&gsm0503_tch_afs_5_15, conv, cB + 8);

		break;
	case 0: /* TCH/AFS4.75 */
		if (len != 12)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 95);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 39, p);

		tch_amr_merge(conv, d, p, 95, 39);

		osmo_conv_encode(&gsm0503_tch_afs_4_75, conv, cB + 8);

		break;
	default:
		/* FIXME: FT %ft is not supported */
		return -1;
	}

	memcpy(cB, gsm0503_afs_ic_ubit[id], 8);

facch:
	gsm0503_tch_fr_interleave(cB, iB);

	for (i = 0; i < 8; i++) {
		gsm0503_tch_burst_map(&iB[i * 114],
			&bursts[i * 116], &h, i >> 2);
	}

	return 0;

invalid_length:
	/* FIXME: payload length %len does not comply with codec type %ft */
	return -1;
}

/* TCH/AHS: parse codec ID (CMI or CMC/CMR) from coded in-band data (16 bit) */
static uint8_t gsm0503_tch_ahs_decode_inband(const sbit_t *cB)
{
	unsigned int id = 0, best = 0;
	unsigned int i, j, k;

	for (i = 0, k = 0; i < 4; i++) {
		/* FIXME: why not using remaining (16 - 4) soft-bits here? */
		for (j = 0, k = 0; j < 4; j++)
			k += abs(((int)gsm0503_ahs_ic_sbit[i][j]) - ((int)cB[j]));

		if (i == 0 || k < best) {
			best = k;
			id = i;
		}
	}

	return id;
}

/*! Perform channel decoding of a TCH/AFS channel according TS 05.03
 *  \param[out] tch_data Codec frame in RTP payload format
 *  \param[in] bursts buffer containing the symbols of 8 bursts
 *  \param[in] odd Is this an odd (1) or even (0) frame number?
 *  \param[in] codec_mode_req is this CMR (1) or CMC (0)
 *  \param[in] codec array of active codecs (active codec set)
 *  \param[in] codecs number of codecs in \a codec
 *  \param ft Frame Type; Input if \a codec_mode_req = 1, Output *  otherwise
 *  \param[out] cmr Output in \a codec_mode_req = 1
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \returns (>=4) length of bytes used in \a tch_data output buffer; ([0,3])
 *  	     codec out of range; negative on error
 */
int gsm0503_tch_ahs_decode(uint8_t *tch_data, const sbit_t *bursts, int odd,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t *ft,
	uint8_t *cmr, int *n_errors, int *n_bits_total)
{
	return gsm0503_tch_ahs_decode_dtx(tch_data, bursts, odd, codec_mode_req,
					  codec, codecs, ft, cmr, n_errors,
					  n_bits_total, NULL);
}

/*! Perform channel decoding of a TCH/AFS channel according TS 05.03
 *  \param[out] tch_data Codec frame in RTP payload format
 *  \param[in] bursts buffer containing the symbols of 8 bursts
 *  \param[in] odd Is this an odd (1) or even (0) frame number?
 *  \param[in] codec_mode_req is this CMR (1) or CMC (0)
 *  \param[in] codec array of active codecs (active codec set)
 *  \param[in] codecs number of codecs in \a codec
 *  \param ft Frame Type; Input if \a codec_mode_req = 1, Output *  otherwise
 *  \param[out] cmr Output in \a codec_mode_req = 1
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \param[inout] dtx DTX frame type output, previous DTX frame type input
 *  \returns (>=4) length of bytes used in \a tch_data output buffer; ([0,3])
 *  	     codec out of range; negative on error
 */
int gsm0503_tch_ahs_decode_dtx(uint8_t *tch_data, const sbit_t *bursts, int odd,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t *ft,
	uint8_t *cmr, int *n_errors, int *n_bits_total, uint8_t *dtx)
{
	sbit_t iB[912], cB[456], h;
	ubit_t d[244], p[6], conv[135];
	int i, rv, len, steal = 0, id = -1;
	static ubit_t sid_first_dummy[64] = { 0 };

	/* only unmap the stealing bits */
	if (!odd) {
		for (i = 0; i < 4; i++) {
			gsm0503_tch_burst_unmap(NULL, &bursts[i * 116], &h, 0);
			steal -= h;
		}
		for (i = 2; i < 5; i++) {
			gsm0503_tch_burst_unmap(NULL, &bursts[i * 116], &h, 1);
			steal -= h;
		}
	}

	/* if we found a stole FACCH, but only at correct alignment */
	if (steal > 0) {
		/* If not NULL, dtx indicates type of previously decoded TCH/AHS frame.
		 * It's normally updated by gsm0503_detect_ahs_dtx_frame2(), which is not
		 * reached in case of FACCH.  Reset it here to avoid FACCH/H frames being
		 * misinterpreted as AMR's special DTX frames. */
		if (dtx != NULL)
			*dtx = AMR_OTHER;

		for (i = 0; i < 6; i++) {
			gsm0503_tch_burst_unmap(&iB[i * 114],
				&bursts[i * 116], NULL, i >> 2);
		}

		for (i = 2; i < 4; i++) {
			gsm0503_tch_burst_unmap(&iB[i * 114 + 456],
				&bursts[i * 116], NULL, 1);
		}

		gsm0503_tch_fr_deinterleave(cB, iB);

		rv = _xcch_decode_cB(tch_data, cB, n_errors, n_bits_total);
		if (rv) {
			/* Error decoding FACCH frame */
			return -1;
		}

		return GSM_MACBLOCK_LEN;
	}

	for (i = 0; i < 4; i++) {
		gsm0503_tch_burst_unmap(&iB[i * 114],
			&bursts[i * 116], NULL, i >> 1);
	}

	gsm0503_tch_hr_deinterleave(cB, iB);

	/* Determine the DTX frame type (SID_UPDATE, ONSET etc...) */
	if (dtx) {
		int n_bits_total_sid;
		int n_errors_sid;

		*dtx = gsm0503_detect_ahs_dtx_frame2(n_errors, n_bits_total, &id, cB);
		/* TODO: detect and handle AHS_SID_UPDATE + AHS_SID_UPDATE_INH */

		switch (*dtx) {
		case AHS_SID_UPDATE: /* TODO: parse CMI _and_ CMC/CMR (16 + 16 bit) */
			/* cB[] contains 16 bits of coded in-band data and 212 bits containing
			 * the identification marker.  We need to unmap/deinterleave 114 odd
			 * bits from the last two blocks, 114 even bits from the first two
			 * blocks and combine them together. */
			gsm0503_tch_burst_unmap(&iB[0 * 114], &bursts[2 * 116], NULL, 0);
			gsm0503_tch_burst_unmap(&iB[1 * 114], &bursts[3 * 116], NULL, 0);
			gsm0503_tch_burst_unmap(&iB[2 * 114], &bursts[0 * 116], NULL, 1);
			gsm0503_tch_burst_unmap(&iB[3 * 114], &bursts[1 * 116], NULL, 1);
			gsm0503_tch_hr_deinterleave(cB, iB);

			/* cB[] is expected to contain 16 bits of coded in-band data and
			 * 212 bits containing the coded data (53 bits coded at 1/4 rate). */
			*dtx = AHS_SID_UPDATE_CN;

			osmo_conv_decode_ber(&gsm0503_tch_axs_sid_update,
					     cB + 16, conv, &n_errors_sid,
					     &n_bits_total_sid);
			/* gsm0503_detect_ahs_dtx_frame2() calculates BER for the marker,
			 * osmo_conv_decode_ber() calculates BER for the coded data. */
			if (n_errors != NULL)
				*n_errors += n_errors_sid;
			if (n_bits_total != NULL)
				*n_bits_total += n_bits_total_sid;
			rv = osmo_crc16gen_check_bits(&gsm0503_amr_crc14, conv,
						      35, conv + 35);
			if (rv != 0) {
				/* Error checking CRC14 for an AMR SID_UPDATE frame */
				return -1;
			}

			tch_amr_sid_update_append(conv, 1,
						  (codec_mode_req) ? codec[*ft]
						  : codec[id > 0 ? id : 0]);
			tch_amr_reassemble(tch_data, conv, 39);
			len = 5;
			goto out;
		case AHS_SID_FIRST_P2:
			tch_amr_sid_update_append(sid_first_dummy, 0,
						  (codec_mode_req) ? codec[*ft]
						  : codec[id > 0 ? id : 0]);
			tch_amr_reassemble(tch_data, sid_first_dummy, 39);
			len = 5;
			goto out;
		case AHS_ONSET:
		case AHS_SID_FIRST_INH: /* TODO: parse CMI or CMC/CMR (16 bit) */
		case AHS_SID_UPDATE_INH: /* TODO: parse CMI or CMC/CMR (16 bit) */
		case AHS_SID_FIRST_P1: /* TODO: parse CMI or CMC/CMR (16 bit) */
			len = 0;
			goto out;
		default:
			break;
		}
	}

	/* Parse codec ID (CMI or CMC/CMR) and check if it fits into range of codecs */
	if ((id = gsm0503_tch_ahs_decode_inband(&cB[0])) >= codecs) {
		/* Codec mode out of range, return id */
		return id;
	}

	switch ((codec_mode_req) ? codec[*ft] : codec[id]) {
	case 5: /* TCH/AHS7.95 */
		osmo_conv_decode_ber(&gsm0503_tch_ahs_7_95, cB + 4,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 123, 67);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 67, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 7.95 frame */
			return -1;
		}

		for (i = 0; i < 36; i++)
			d[i + 123] = (cB[i + 192] < 0) ? 1 : 0;

		tch_amr_reassemble(tch_data, d, 159);

		len = 20;

		break;
	case 4: /* TCH/AHS7.4 */
		osmo_conv_decode_ber(&gsm0503_tch_ahs_7_4, cB + 4,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 120, 61);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 61, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 7.4 frame */
			return -1;
		}

		for (i = 0; i < 28; i++)
			d[i + 120] = (cB[i + 200] < 0) ? 1 : 0;

		tch_amr_reassemble(tch_data, d, 148);

		len = 19;

		break;
	case 3: /* TCH/AHS6.7 */
		osmo_conv_decode_ber(&gsm0503_tch_ahs_6_7, cB + 4,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 110, 55);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 55, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 6.7 frame */
			return -1;
		}

		for (i = 0; i < 24; i++)
			d[i + 110] = (cB[i + 204] < 0) ? 1 : 0;

		tch_amr_reassemble(tch_data, d, 134);

		len = 17;

		break;
	case 2: /* TCH/AHS5.9 */
		osmo_conv_decode_ber(&gsm0503_tch_ahs_5_9, cB + 4,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 102, 55);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 55, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 5.9 frame */
			return -1;
		}

		for (i = 0; i < 16; i++)
			d[i + 102] = (cB[i + 212] < 0) ? 1 : 0;

		tch_amr_reassemble(tch_data, d, 118);

		len = 15;

		break;
	case 1: /* TCH/AHS5.15 */
		osmo_conv_decode_ber(&gsm0503_tch_ahs_5_15, cB + 4,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 91, 49);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 49, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 5.15 frame */
			return -1;
		}

		for (i = 0; i < 12; i++)
			d[i + 91] = (cB[i + 216] < 0) ? 1 : 0;

		tch_amr_reassemble(tch_data, d, 103);

		len = 13;

		break;
	case 0: /* TCH/AHS4.75 */
		osmo_conv_decode_ber(&gsm0503_tch_ahs_4_75, cB + 4,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 83, 39);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 39, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 4.75 frame */
			return -1;
		}

		for (i = 0; i < 12; i++)
			d[i + 83] = (cB[i + 216] < 0) ? 1 : 0;

		tch_amr_reassemble(tch_data, d, 95);

		len = 12;

		break;
	default:
		/* Unknown frame type */
		*n_bits_total = 159;
		*n_errors = *n_bits_total;
		return -1;
	}

out:
	/* Change codec request / indication, if frame is valid */
	if (id != -1) {
		if (codec_mode_req)
			*cmr = id;
		else
			*ft = id;
	}

	return len;
}

/*! Perform channel encoding on a TCH/AHS channel according to TS 05.03
 *  \param[out] bursts caller-allocated output buffer for bursts bits
 *  \param[in] tch_data Codec input data in RTP payload format
 *  \param[in] len Length of \a tch_data in bytes
 *  \param[in] codec_mode_req Use CMR (1) or FT (0)
 *  \param[in] codec Array of codecs (active codec set)
 *  \param[in] codecs Number of entries in \a codec
 *  \param[in] ft Frame Type to be used for encoding (index to \a codec)
 *  \param[in] cmr Codec Mode Request (used in codec_mode_req = 1 only)
 *  \returns 0 in case of success; negative on error */
int gsm0503_tch_ahs_encode(ubit_t *bursts, const uint8_t *tch_data, int len,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t ft,
	uint8_t cmr)
{
	ubit_t iB[912], cB[456], h;
	ubit_t d[244], p[6], conv[135];
	int i;
	uint8_t id;

	if (len == GSM_MACBLOCK_LEN) { /* FACCH */
		_xcch_encode_cB(cB, tch_data);

		h = 1;

		gsm0503_tch_fr_interleave(cB, iB);

		for (i = 0; i < 6; i++)
			gsm0503_tch_burst_map(&iB[i * 114], &bursts[i * 116],
				&h, i >> 2);
		for (i = 2; i < 4; i++)
			gsm0503_tch_burst_map(&iB[i * 114 + 456],
				&bursts[i * 116], &h, 1);

		return 0;
	}

	h = 0;

	if (codec_mode_req) {
		if (cmr >= codecs) {
			/* FIXME: CMR ID %d not in codec list */
			return -1;
		}
		id = cmr;
	} else {
		if (ft >= codecs) {
			/* FIXME: FT ID %d not in codec list */
			return -1;
		}
		id = ft;
	}

	switch (codec[ft]) {
	case 5: /* TCH/AHS7.95 */
		if (len != 20)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 159);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 67, p);

		tch_amr_merge(conv, d, p, 123, 67);

		osmo_conv_encode(&gsm0503_tch_ahs_7_95, conv, cB + 4);

		memcpy(cB + 192, d + 123, 36);

		break;
	case 4: /* TCH/AHS7.4 */
		if (len != 19)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 148);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 61, p);

		tch_amr_merge(conv, d, p, 120, 61);

		osmo_conv_encode(&gsm0503_tch_ahs_7_4, conv, cB + 4);

		memcpy(cB + 200, d + 120, 28);

		break;
	case 3: /* TCH/AHS6.7 */
		if (len != 17)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 134);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 55, p);

		tch_amr_merge(conv, d, p, 110, 55);

		osmo_conv_encode(&gsm0503_tch_ahs_6_7, conv, cB + 4);

		memcpy(cB + 204, d + 110, 24);

		break;
	case 2: /* TCH/AHS5.9 */
		if (len != 15)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 118);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 55, p);

		tch_amr_merge(conv, d, p, 102, 55);

		osmo_conv_encode(&gsm0503_tch_ahs_5_9, conv, cB + 4);

		memcpy(cB + 212, d + 102, 16);

		break;
	case 1: /* TCH/AHS5.15 */
		if (len != 13)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 103);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 49, p);

		tch_amr_merge(conv, d, p, 91, 49);

		osmo_conv_encode(&gsm0503_tch_ahs_5_15, conv, cB + 4);

		memcpy(cB + 216, d + 91, 12);

		break;
	case 0: /* TCH/AHS4.75 */
		if (len != 12)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 95);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 39, p);

		tch_amr_merge(conv, d, p, 83, 39);

		osmo_conv_encode(&gsm0503_tch_ahs_4_75, conv, cB + 4);

		memcpy(cB + 216, d + 83, 12);

		break;
	default:
		/* FIXME: FT %ft is not supported */
		return -1;
	}

	memcpy(cB, gsm0503_ahs_ic_ubit[id], 4);

	gsm0503_tch_hr_interleave(cB, iB);

	for (i = 0; i < 4; i++)
		gsm0503_tch_burst_map(&iB[i * 114], &bursts[i * 116], &h, i >> 1);

	return 0;

invalid_length:
	/* FIXME: payload length %len does not comply with codec type %ft */
	return -1;
}

/*
 * GSM RACH transcoding
 */

/*
 * GSM RACH apply BSIC to parity
 *
 * p(j) = p(j) xor b(j)     j = 0, ..., 5
 * b(0) = MSB of PLMN colour code
 * b(5) = LSB of BS colour code
 */
static inline void rach_apply_bsic(ubit_t *d, uint8_t bsic, uint8_t start)
{
	int i;

	/* Apply it */
	for (i = 0; i < 6; i++)
		d[start + i] ^= ((bsic >> (5 - i)) & 1);
}

static inline int16_t rach_decode_ber(const sbit_t *burst, uint8_t bsic, bool is_11bit,
				      int *n_errors, int *n_bits_total)
{
	ubit_t conv[17];
	uint8_t ra[2] = { 0 }, nbits = is_11bit ? 11 : 8;
	int rv;

	osmo_conv_decode_ber(is_11bit ? &gsm0503_rach_ext : &gsm0503_rach, burst, conv,
			     n_errors, n_bits_total);

	rach_apply_bsic(conv, bsic, nbits);

	rv = osmo_crc8gen_check_bits(&gsm0503_rach_crc6, conv, nbits, conv + nbits);
	if (rv)
		return -1;

	osmo_ubit2pbit_ext(ra, 0, conv, 0, nbits, 1);

	return is_11bit ? ((ra[0] << 3) | (ra[1] & 0x07)) : ra[0];
}

/*! Decode the Extended (11-bit) RACH according to 3GPP TS 45.003
 *  \param[out] ra output buffer for RACH data
 *  \param[in] burst Input burst data
 *  \param[in] bsic BSIC used in this cell
 *  \returns 0 on success; negative on error (e.g. CRC error) */
int gsm0503_rach_ext_decode(uint16_t *ra, const sbit_t *burst, uint8_t bsic)
{
	int16_t r = rach_decode_ber(burst, bsic, true, NULL, NULL);

	if (r < 0)
		return r;

	*ra = r;

	return 0;
}

/*! Decode the (8-bit) RACH according to TS 05.03
 *  \param[out] ra output buffer for RACH data
 *  \param[in] burst Input burst data
 *  \param[in] bsic BSIC used in this cell
 *  \returns 0 on success; negative on error (e.g. CRC error) */
int gsm0503_rach_decode(uint8_t *ra, const sbit_t *burst, uint8_t bsic)
{
	int16_t r = rach_decode_ber(burst, bsic, false, NULL, NULL);
	if (r < 0)
		return r;

	*ra = r;
	return 0;
}

/*! Decode the Extended (11-bit) RACH according to 3GPP TS 45.003
 *  \param[out] ra output buffer for RACH data
 *  \param[in] burst Input burst data
 *  \param[in] bsic BSIC used in this cell
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \returns 0 on success; negative on error (e.g. CRC error) */
int gsm0503_rach_ext_decode_ber(uint16_t *ra, const sbit_t *burst, uint8_t bsic,
				int *n_errors, int *n_bits_total)
{
	int16_t r = rach_decode_ber(burst, bsic, true, n_errors, n_bits_total);
	if (r < 0)
		return r;

	*ra = r;
	return 0;
}

/*! Decode the (8-bit) RACH according to TS 05.03
 *  \param[out] ra output buffer for RACH data
 *  \param[in] burst Input burst data
 *  \param[in] bsic BSIC used in this cell
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \returns 0 on success; negative on error (e.g. CRC error) */
int gsm0503_rach_decode_ber(uint8_t *ra, const sbit_t *burst, uint8_t bsic,
			    int *n_errors, int *n_bits_total)
{
	int16_t r = rach_decode_ber(burst, bsic, false, n_errors, n_bits_total);

	if (r < 0)
		return r;

	*ra = r;

	return 0;
}

/*! Encode the (8-bit) RACH according to TS 05.03
 *  \param[out] burst Caller-allocated output burst buffer
 *  \param[in] ra Input RACH data
 *  \param[in] bsic BSIC used in this cell
 *  \returns 0 on success; negative on error */
int gsm0503_rach_encode(ubit_t *burst, const uint8_t *ra, uint8_t bsic)
{
	return gsm0503_rach_ext_encode(burst, *ra, bsic, false);
}

/*! Encode the Extended (11-bit) or regular (8-bit) RACH according to 3GPP TS 45.003
 *  \param[out] burst Caller-allocated output burst buffer
 *  \param[in] ra11 Input RACH data
 *  \param[in] bsic BSIC used in this cell
 *  \param[in] is_11bit whether given RA is 11 bit or not
 *  \returns 0 on success; negative on error */
int gsm0503_rach_ext_encode(ubit_t *burst, uint16_t ra11, uint8_t bsic, bool is_11bit)
{
	ubit_t conv[17];
	uint8_t ra[2] = { 0 }, nbits = 8;

	if (is_11bit) {
		ra[0] = (uint8_t) (ra11 >> 3);
		ra[1] = (uint8_t) (ra11 & 0x07);
		nbits = 11;
	} else
		ra[0] = (uint8_t)ra11;

	osmo_pbit2ubit_ext(conv, 0, ra, 0, nbits, 1);

	osmo_crc8gen_set_bits(&gsm0503_rach_crc6, conv, nbits, conv + nbits);

	rach_apply_bsic(conv, bsic, nbits);

	osmo_conv_encode(is_11bit ? &gsm0503_rach_ext : &gsm0503_rach, conv, burst);

	return 0;
}

/*
 * GSM SCH transcoding
 */

/*! Decode the SCH according to TS 05.03
 *  \param[out] sb_info output buffer for SCH data
 *  \param[in] burst Input burst data
 *  \returns 0 on success; negative on error (e.g. CRC error) */
int gsm0503_sch_decode(uint8_t *sb_info, const sbit_t *burst)
{
	ubit_t conv[35];
	int rv;

	osmo_conv_decode(&gsm0503_sch, burst, conv);

	rv = osmo_crc16gen_check_bits(&gsm0503_sch_crc10, conv, 25, conv + 25);
	if (rv)
		return -1;

	osmo_ubit2pbit_ext(sb_info, 0, conv, 0, 25, 1);

	return 0;
}

/*! Encode the SCH according to TS 05.03
 *  \param[out] burst Caller-allocated output burst buffer
 *  \param[in] sb_info Input SCH data
 *  \returns 0 on success; negative on error */
int gsm0503_sch_encode(ubit_t *burst, const uint8_t *sb_info)
{
	ubit_t conv[35];

	osmo_pbit2ubit_ext(conv, 0, sb_info, 0, 25, 1);

	osmo_crc16gen_set_bits(&gsm0503_sch_crc10, conv, 25, conv + 25);

	osmo_conv_encode(&gsm0503_sch, conv, burst);

	return 0;
}

/*! @} */
