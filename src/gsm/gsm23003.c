/*! \file gsm23003.c
 * Utility function implementations related to 3GPP TS 23.003 */
/*
 * (C) 2017 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/core/utils.h>

static bool is_n_digits(const char *str, int min_digits, int max_digits)
{
	int len;
	/* Use unsigned char * to avoid a compiler warning of
	 * "error: array subscript has type 'char' [-Werror=char-subscripts]" */
	const unsigned char *pos = (const unsigned char *)str;
	if (!pos)
		return min_digits < 1;
	for (len = 0; *pos && len < max_digits; len++, pos++)
		if (!isdigit(*pos))
			return false;
	if (len < min_digits)
		return false;
	/* With not too many digits, we should have reached *str == nul */
	if (*pos)
		return false;
	return true;
}

/*! Determine whether the given IMSI is valid according to 3GPP TS 23.003.
 * \param imsi  IMSI digits in ASCII string representation.
 * \returns true when the IMSI is valid, false for invalid characters or number
 *          of digits.
 */
bool osmo_imsi_str_valid(const char *imsi)
{
	return is_n_digits(imsi, GSM23003_IMSI_MIN_DIGITS, GSM23003_IMSI_MAX_DIGITS);
}

/*! Determine whether the given MSISDN is valid according to 3GPP TS 23.003.
 * \param msisdn  MSISDN digits in ASCII string representation.
 * \returns true when the MSISDN is valid, false for invalid characters or number
 *          of digits.
 */
bool osmo_msisdn_str_valid(const char *msisdn)
{
	return is_n_digits(msisdn, GSM23003_MSISDN_MIN_DIGITS, GSM23003_MSISDN_MAX_DIGITS);
}

/*! Determine whether the given IMEI is valid according to 3GPP TS 23.003,
 * Section 6.2.1. It consists of 14 digits, the 15th check digit is not
 * intended for digital transmission.
 * \param imei  IMEI digits in ASCII string representation.
 * \param with_15th_digit  when true, expect the 15th digit to be present and
 *        verify it.
 * \returns true when the IMEI is valid, false for invalid characters or number
 *          of digits.
 */
bool osmo_imei_str_valid(const char *imei, bool with_15th_digit)
{
	if (with_15th_digit)
		return is_n_digits(imei, 15, 15) && osmo_luhn(imei, 14) == imei[14];
	else
		return is_n_digits(imei, 14, 14);
}

/*! Return MCC string as standardized 3-digit with leading zeros.
 * \param[out] buf caller-allocated output buffer
 * \param[in] buf_len size of buf in bytes
 * \param[in] mcc  MCC value.
 * \returns string in user-supplied output buffer
 */
char *osmo_mcc_name_buf(char *buf, size_t buf_len, uint16_t mcc)
{
	snprintf(buf, buf_len, "%03u", mcc);
	return buf;
}

/*! Return MCC string as standardized 3-digit with leading zeros.
 * \param[in] mcc  MCC value.
 * \returns string in static buffer.
 */
const char *osmo_mcc_name(uint16_t mcc)
{
	static __thread char buf[8];
	return osmo_mcc_name_buf(buf, sizeof(buf), mcc);
}

/*! Return MCC string as standardized 3-digit with leading zeros, into a talloc-allocated buffer.
 * \param[in] ctx talloc context from which to allocate output buffer
 * \param[in] mcc  MCC value.
 * \returns string in dynamically allocated buffer.
 */
const char *osmo_mcc_name_c(const void *ctx, uint16_t mcc)
{
	char *buf = talloc_size(ctx, 8);
	if (!buf)
		return NULL;
	return osmo_mcc_name_buf(buf, 8, mcc);
}

/*! Return MNC string as standardized 2- or 3-digit with leading zeros.
 * \param[out] buf caller-allocated output buffer
 * \param[in] buf_len size of buf in bytes
 * \param[in] mnc  MNC value.
 * \param[in] mnc_3_digits  True if an MNC should fill three digits, only has an effect if MNC < 100.
 * \returns string in static buffer.
 */
char *osmo_mnc_name_buf(char *buf, size_t buf_len, uint16_t mnc, bool mnc_3_digits)
{
	snprintf(buf, buf_len, "%0*u", mnc_3_digits ? 3 : 2, mnc);
	return buf;
}

/*! Return MNC string as standardized 2- or 3-digit with leading zeros, into a talloc-allocated buffer.
 * \param[in] ctx talloc context from which to allocate output buffer
 * \param[in] mnc  MNC value.
 * \param[in] mnc_3_digits  True if an MNC should fill three digits, only has an effect if MNC < 100.
 * \returns string in dynamically allocated buffer.
 */
char *osmo_mnc_name_c(const void *ctx, uint16_t mnc, bool mnc_3_digits)
{
	char *buf = talloc_size(ctx, 8);
	if (!buf)
		return buf;
	return osmo_mnc_name_buf(buf, 8, mnc, mnc_3_digits);
}

/*! Return MNC string as standardized 2- or 3-digit with leading zeros.
 * \param[in] mnc  MNC value.
 * \param[in] mnc_3_digits  True if an MNC should fill three digits, only has an effect if MNC < 100.
 * \returns string in static buffer.
 */
const char *osmo_mnc_name(uint16_t mnc, bool mnc_3_digits)
{
	static __thread char buf[8];
	return osmo_mnc_name_buf(buf, sizeof(buf), mnc, mnc_3_digits);
}

/*! Return MCC-MNC string as standardized 3-digit-dash-2/3-digit with leading zeros.
 * \param[out] buf caller-allocated output buffer
 * \param[in] buf_len size of buf in bytes
 * \param[in] plmn  MCC-MNC value.
 * \returns string in static buffer.
 */
char *osmo_plmn_name_buf(char *buf, size_t buf_len, const struct osmo_plmn_id *plmn)
{
	char mcc[8], mnc[8];
	snprintf(buf, buf_len, "%s-%s", osmo_mcc_name_buf(mcc, sizeof(mcc), plmn->mcc),
		 osmo_mnc_name_buf(mnc, sizeof(mnc), plmn->mnc, plmn->mnc_3_digits));
	return buf;
}

/*! Return MCC-MNC string as standardized 3-digit-dash-2/3-digit with leading zeros.
 * \param[in] plmn  MCC-MNC value.
 * \returns string in static buffer.
 */
const char *osmo_plmn_name(const struct osmo_plmn_id *plmn)
{
	static __thread char buf[16];
	return osmo_plmn_name_buf(buf, sizeof(buf), plmn);
}


/*! Same as osmo_plmn_name(), but returning in a different static buffer.
 * \param[in] plmn  MCC-MNC value.
 * \returns string in static buffer.
 */
const char *osmo_plmn_name2(const struct osmo_plmn_id *plmn)
{
	static __thread char buf[16];
	return osmo_plmn_name_buf(buf, sizeof(buf), plmn);
}

/*! Return MCC-MNC string as standardized 3-digit-dash-2/3-digit with leading zeros, into
 *  a dynamically-allocated output buffer.
 * \param[in] ctx talloc context from which to allocate output buffer
 * \param[in] plmn  MCC-MNC value.
 * \returns string in dynamically allocated buffer.
 */
char *osmo_plmn_name_c(const void *ctx, const struct osmo_plmn_id *plmn)
{
	char *buf = talloc_size(ctx, 16);
	if (!buf)
		return NULL;
	return osmo_plmn_name_buf(buf, 16, plmn);
}

/*! Return MCC-MNC-LAC as string, in caller-provided output buffer.
 * \param[out] buf caller-allocated output buffer
 * \param[in] buf_len size of buf in bytes
 * \param[in] lai  LAI to encode, the rac member is ignored.
 * \returns buf
 */
char *osmo_lai_name_buf(char *buf, size_t buf_len, const struct osmo_location_area_id *lai)
{
	char plmn[16];
	snprintf(buf, buf_len, "%s-%u", osmo_plmn_name_buf(plmn, sizeof(plmn), &lai->plmn), lai->lac);
	return buf;
}

/*! Return MCC-MNC-LAC as string, in a static buffer.
 * \param[in] lai  LAI to encode, the rac member is ignored.
 * \returns Static string buffer.
 */
const char *osmo_lai_name(const struct osmo_location_area_id *lai)
{
	static __thread char buf[32];
	return osmo_lai_name_buf(buf, sizeof(buf), lai);
}

/*! Return MCC-MNC-LAC as string, in a talloc-allocated output buffer.
 * \param[in] ctx talloc context from which to allocate output buffer
 * \param[in] lai  LAI to encode, the rac member is ignored.
 * \returns string representation of lai in dynamically allocated buffer.
 */
char *osmo_lai_name_c(const void *ctx, const struct osmo_location_area_id *lai)
{
	char *buf = talloc_size(ctx, 32);
	if (!buf)
		return NULL;
	return osmo_lai_name_buf(buf, 32, lai);
}

/*! Return MCC-MNC-LAC-RAC as string, in caller-provided output buffer.
 * \param[out] buf caller-allocated output buffer
 * \param[in] buf_len size of buf in bytes
 * \param[in] rai  RAI to encode, the rac member is ignored.
 * \returns buf
 */
char *osmo_rai_name2_buf(char *buf, size_t buf_len, const struct osmo_routing_area_id *rai)
{
	char plmn[16];
	snprintf(buf, buf_len, "%s-%u-%u", osmo_plmn_name_buf(plmn, sizeof(plmn),
		 &rai->lac.plmn), rai->lac.lac, rai->rac);
	return buf;
}

/*! Return MCC-MNC-LAC-RAC as string, in a static buffer.
 * \param[in] rai  RAI to encode, the rac member is ignored.
 * \returns Static string buffer.
 */
const char *osmo_rai_name2(const struct osmo_routing_area_id *rai)
{
	static __thread char buf[32];
	return osmo_rai_name2_buf(buf, sizeof(buf), rai);
}

/*! Return MCC-MNC-LAC-RAC as string, in a talloc-allocated output buffer.
 * \param[in] ctx talloc context from which to allocate output buffer
 * \param[in] rai  RAI to encode, the rac member is ignored.
 * \returns string representation of lai in dynamically allocated buffer.
 */
char *osmo_rai_name2_c(const void *ctx, const struct osmo_routing_area_id *rai)
{
	char *buf = talloc_size(ctx, 32);
	if (!buf)
		return NULL;
	return osmo_rai_name2_buf(buf, 32, rai);
}

/*! Return MCC-MNC-LAC-CI as string, in caller-provided output buffer.
 * \param[out] buf caller-allocated output buffer
 * \param[in] buf_len size of buf in bytes
 * \param[in] cgi  CGI to encode.
 * \returns buf
 */
char *osmo_cgi_name_buf(char *buf, size_t buf_len, const struct osmo_cell_global_id *cgi)
{
	snprintf(buf, buf_len, "%s-%u", osmo_lai_name(&cgi->lai), cgi->cell_identity);
	return buf;
}

/*! Return MCC-MNC-LAC-CI as string, in a static buffer.
 * \param[in] cgi  CGI to encode.
 * \returns Static string buffer.
 */
const char *osmo_cgi_name(const struct osmo_cell_global_id *cgi)
{
	static __thread char buf[32];
	return osmo_cgi_name_buf(buf, sizeof(buf), cgi);
}

/*! Same as osmo_cgi_name(), but uses a different static buffer.
 * Useful for printing two distinct CGIs in the same printf format.
 * \param[in] cgi  CGI to encode.
 * \returns Static string buffer.
 */
const char *osmo_cgi_name2(const struct osmo_cell_global_id *cgi)
{
	static __thread char buf[32];
	return osmo_cgi_name_buf(buf, sizeof(buf), cgi);
}

/*! Return MCC-MNC-LAC-CI as string, in a talloc-allocated output buffer.
 * \param[in] ctx talloc context from which to allocate output buffer
 * \param[in] cgi  CGI to encode.
 * \returns string representation of CGI in dynamically-allocated buffer.
 */
char *osmo_cgi_name_c(const void *ctx, const struct osmo_cell_global_id *cgi)
{
	char *buf = talloc_size(ctx, 32);
	return osmo_cgi_name_buf(buf, 32, cgi);
}

/*! Return MCC-MNC-LAC-RAC-CI as string, in caller-provided output buffer.
 * \param[out] buf caller-allocated output buffer
 * \param[in] buf_len size of buf in bytes
 * \param[in] cgi_ps  CGI-PS to encode.
 * \returns buf
 */
char *osmo_cgi_ps_name_buf(char *buf, size_t buf_len, const struct osmo_cell_global_id_ps *cgi_ps)
{
	snprintf(buf, buf_len, "%s-%u", osmo_rai_name2(&cgi_ps->rai), cgi_ps->cell_identity);
	return buf;
}

/*! Return MCC-MNC-LAC-RAC-CI as string, in a static buffer.
 * \param[in] cgi_ps  CGI-PS to encode.
 * \returns Static string buffer.
 */
const char *osmo_cgi_ps_name(const struct osmo_cell_global_id_ps *cgi_ps)
{
	static __thread char buf[32];
	return osmo_cgi_ps_name_buf(buf, sizeof(buf), cgi_ps);
}

/*! Same as osmo_cgi_ps_name(), but uses a different static buffer.
 * Useful for printing two distinct CGI-PSs in the same printf format.
 * \param[in] cgi  CGI-PS to encode.
 * \returns Static string buffer.
 */
const char *osmo_cgi_ps_name2(const struct osmo_cell_global_id_ps *cgi_ps)
{
	static __thread char buf[32];
	return osmo_cgi_ps_name_buf(buf, sizeof(buf), cgi_ps);
}

/*! Return MCC-MNC-LAC-RAC-CI as string, in a talloc-allocated output buffer.
 * \param[in] ctx talloc context from which to allocate output buffer
 * \param[in] cgi_ps  CGI-PS to encode.
 * \returns string representation of CGI in dynamically-allocated buffer.
 */
char *osmo_cgi_ps_name_c(const void *ctx, const struct osmo_cell_global_id_ps *cgi_ps)
{
	char *buf = talloc_size(ctx, 32);
	return osmo_cgi_ps_name_buf(buf, 32, cgi_ps);
}

static void to_bcd(uint8_t *bcd, uint16_t val)
{
	bcd[2] = val % 10;
	val = val / 10;
	bcd[1] = val % 10;
	val = val / 10;
	bcd[0] = val % 10;
}

/*! Return string representation of GUMMEI in caller-provided output buffer.
 * \param[out] buf pointer to caller-provided output buffer
 * \param[in] buf_len size of buf in bytes
 * \param[in] gummei GUMMEI to be stringified
 * \returns buf
 */
char *osmo_gummei_name_buf(char *buf, size_t buf_len, const struct osmo_gummei *gummei)
{
	char plmn[16];
	snprintf(buf, buf_len, "%s-%04x-%02x", osmo_plmn_name_buf(plmn, sizeof(plmn), &gummei->plmn),
		 gummei->mme.group_id, gummei->mme.code);
	return buf;
}

/*! Return string representation of GUMMEI in static output buffer.
 * \param[in] gummei GUMMEI to be stringified
 * \returns pointer to static output buffer
 */
const char *osmo_gummei_name(const struct osmo_gummei *gummei)
{
	static __thread char buf[32];
	return osmo_gummei_name_buf(buf, sizeof(buf), gummei);
}

/*! Return string representation of GUMMEI in static output buffer.
 * \param[out] buf pointer to caller-provided output buffer
 * \param[in] buf_len size of buf in bytes
 * \param[in] gummei GUMMEI to be stringified
 * \returns pointer to static output buffer
 */
char *osmo_gummei_name_c(const void *ctx, const struct osmo_gummei *gummei)
{
	char *buf = talloc_size(ctx, 32);
	if (!buf)
		return NULL;
	return osmo_gummei_name_buf(buf, 32, gummei);
}

/* Convert MCC + MNC to BCD representation
 * \param[out] bcd_dst caller-allocated memory for output
 * \param[in] mcc Mobile Country Code
 * \param[in] mnc Mobile Network Code
 * \param[in] mnc_3_digits true if the MNC shall have three digits.
 *
 * Convert given mcc and mnc to BCD and write to *bcd_dst, which must be an
 * allocated buffer of (at least) 3 bytes length. Encode the MNC in three
 * digits if its integer value is > 99, or if mnc_3_digits is passed true.
 * Encode an MNC < 100 with mnc_3_digits passed as true as a three-digit MNC
 * with leading zeros in the BCD representation.
 */
void osmo_plmn_to_bcd(uint8_t *bcd_dst, const struct osmo_plmn_id *plmn)
{
	uint8_t bcd[3];

	to_bcd(bcd, plmn->mcc);
	bcd_dst[0] = bcd[0] | (bcd[1] << 4);
	bcd_dst[1] = bcd[2];

	to_bcd(bcd, plmn->mnc);
	if (plmn->mnc > 99 || plmn->mnc_3_digits) {
		bcd_dst[1] |= bcd[2] << 4;
		bcd_dst[2] = bcd[0] | (bcd[1] << 4);
	} else {
		bcd_dst[1] |= 0xf << 4;
		bcd_dst[2] = bcd[1] | (bcd[2] << 4);
	}
}

/* Convert given 3-byte BCD buffer to integers and write results to *mcc and
 * *mnc. The first three BCD digits result in the MCC and the remaining ones in
 * the MNC. Return mnc_3_digits as false if the MNC's most significant digit is encoded as 0xF, true
 * otherwise; i.e. true if MNC > 99 or if it is represented with leading zeros instead of 0xF.
 * \param[in] bcd_src 	3-byte BCD buffer containing MCC+MNC representations.
 * \param[out] mcc 	MCC result buffer, or NULL.
 * \param[out] mnc	MNC result buffer, or NULL.
 * \param[out] mnc_3_digits	Result buffer for 3-digit flag, or NULL.
 */
void osmo_plmn_from_bcd(const uint8_t *bcd_src, struct osmo_plmn_id *plmn)
{
	plmn->mcc = (bcd_src[0] & 0x0f) * 100
		  + (bcd_src[0] >> 4) * 10
		  + (bcd_src[1] & 0x0f);

	if ((bcd_src[1] & 0xf0) == 0xf0) {
		plmn->mnc = (bcd_src[2] & 0x0f) * 10
			  + (bcd_src[2] >> 4);
		plmn->mnc_3_digits = false;
	} else {
		plmn->mnc = (bcd_src[2] & 0x0f) * 100
			  + (bcd_src[2] >> 4) * 10
			  + (bcd_src[1] >> 4);
		plmn->mnc_3_digits = true;
	}
}

/* Convert string to MNC, detecting 3-digit MNC with leading zeros.
 * Return mnc_3_digits as false if the MNC's most significant digit is encoded as 0xF, true
 * otherwise; i.e. true if MNC > 99 or if it is represented with leading zeros instead of 0xF.
 * \param mnc_str[in]	String representation of an MNC, with or without leading zeros.
 * \param mnc[out]	MNC result buffer, or NULL.
 * \param[out] mnc_3_digits	Result buffer for 3-digit flag, or NULL.
 * \returns zero on success, -EINVAL in case of surplus characters, negative errno in case of conversion
 *          errors. In case of error, do not modify the out-arguments.
 */
int osmo_mnc_from_str(const char *mnc_str, uint16_t *mnc, bool *mnc_3_digits)
{
	int _mnc = 0;
	bool _mnc_3_digits = false;
	int rc = 0;

	if (!mnc_str || !isdigit((unsigned char)mnc_str[0]) || strlen(mnc_str) > 3)
		return -EINVAL;

	rc = osmo_str_to_int(&_mnc, mnc_str, 10, 0, 999);
	/* Heed the API definition to return -EINVAL in case of surplus chars */
	if (rc == -E2BIG)
		return -EINVAL;
	/* Heed the API definition to always return negative errno */
	if (rc > 0)
		return -rc;
	if (rc < 0)
		return rc;

	_mnc_3_digits = strlen(mnc_str) > 2;

	if (mnc)
		*mnc = (uint16_t)_mnc;
	if (mnc_3_digits)
		*mnc_3_digits = _mnc_3_digits;
	return rc;
}

/* Compare two MNC with three-digit flag.
 * The mnc_3_digits flags passed in only have an effect if the MNC are < 100, i.e. if they would amount
 * to a change in leading zeros in a BCD representation. An MNC >= 100 implies three digits, and the flag
 * is actually ignored.
 * \param a_mnc[in]		"Left" side MNC.
 * \param a_mnc_3_digits[in]	"Left" side three-digits flag.
 * \param b_mnc[in]		"Right" side MNC.
 * \param b_mnc_3_digits[in]	"Right" side three-digits flag.
 * \returns 0 if the MNC are equal, -1 if a < b or a shorter, 1 if a > b or a longer. */
int osmo_mnc_cmp(uint16_t a_mnc, bool a_mnc_3_digits, uint16_t b_mnc, bool b_mnc_3_digits)
{
	if (a_mnc < b_mnc)
		return -1;
	if (a_mnc > b_mnc)
		return 1;
	/* a_mnc == b_mnc, but same amount of leading zeros? */
	if (a_mnc < 100 && a_mnc_3_digits != b_mnc_3_digits)
		return a_mnc_3_digits ? 1 : -1;
	return 0;
}

/* Compare two PLMN.
 * \param a[in]  "Left" side PLMN.
 * \param b[in]  "Right" side PLMN.
 * \returns 0 if the PLMN are equal, -1 if a < b or a shorter, 1 if a > b or a longer. */
int osmo_plmn_cmp(const struct osmo_plmn_id *a, const struct osmo_plmn_id *b)
{
	if (a == b)
		return 0;
	if (a->mcc < b->mcc)
		return -1;
	if (a->mcc > b->mcc)
		return 1;
	return osmo_mnc_cmp(a->mnc, a->mnc_3_digits, b->mnc, b->mnc_3_digits);
}

/* Compare two LAI.
 * The order of comparison is MCC, MNC, LAC. See also osmo_plmn_cmp().
 * \param a[in]  "Left" side LAI.
 * \param b[in]  "Right" side LAI.
 * \returns 0 if the LAI are equal, -1 if a < b, 1 if a > b. */
int osmo_lai_cmp(const struct osmo_location_area_id *a, const struct osmo_location_area_id *b)
{
	int rc = osmo_plmn_cmp(&a->plmn, &b->plmn);
	if (rc)
		return rc;
	if (a->lac < b->lac)
		return -1;
	if (a->lac > b->lac)
		return 1;
	return 0;
}

/* Compare two RAI.
 * The order of comparison is MCC, MNC, LAC, RAC. See also osmo_lai_cmp().
 * \param a[in]  "Left" side RAI.
 * \param b[in]  "Right" side RAI.
 * \returns 0 if the RAI are equal, -1 if a < b, 1 if a > b. */
int osmo_rai_cmp(const struct osmo_routing_area_id *a, const struct osmo_routing_area_id *b)
{
	int rc = osmo_lai_cmp(&a->lac, &b->lac);
	if (rc)
		return rc;
	if (a->rac < b->rac)
		return -1;
	if (a->rac > b->rac)
		return 1;
	return 0;
}

/* Compare two CGI.
 * The order of comparison is MCC, MNC, LAC, CI. See also osmo_lai_cmp().
 * \param a[in]  "Left" side CGI.
 * \param b[in]  "Right" side CGI.
 * \returns 0 if the CGI are equal, -1 if a < b, 1 if a > b. */
int osmo_cgi_cmp(const struct osmo_cell_global_id *a, const struct osmo_cell_global_id *b)
{
	int rc = osmo_lai_cmp(&a->lai, &b->lai);
	if (rc)
		return rc;
	if (a->cell_identity < b->cell_identity)
		return -1;
	if (a->cell_identity > b->cell_identity)
		return 1;
	return 0;
}

/* Compare two CGI-PS.
 * The order of comparison is MCC, MNC, LAC, RAC, CI. See also osmo_rai_cmp().
 * \param a[in]  "Left" side CGI-PS.
 * \param b[in]  "Right" side CGI-PS.
 * \returns 0 if the CGI are equal, -1 if a < b, 1 if a > b. */
int osmo_cgi_ps_cmp(const struct osmo_cell_global_id_ps *a, const struct osmo_cell_global_id_ps *b)
{
	int rc = osmo_rai_cmp(&a->rai, &b->rai);
	if (rc)
		return rc;
	if (a->cell_identity < b->cell_identity)
		return -1;
	if (a->cell_identity > b->cell_identity)
		return 1;
	return 0;
}

/*! Generate TS 23.003 Section 19.2 Home Network Realm/Domain (text form)
 *  \param out[out] caller-provided output buffer, at least 33 bytes long
 *  \param plmn[in] Osmocom representation of PLMN ID (MCC + MNC)
 *  \returns number of characters printed (excluding NUL); negative on error */
int osmo_gen_home_network_domain(char *out, const struct osmo_plmn_id *plmn)
{
	if (plmn->mcc > 999)
		return -EINVAL;
	if (plmn->mnc > 999)
		return -EINVAL;
	return sprintf(out, "epc.mnc%03u.mcc%03u.3gppnetwork.org", plmn->mnc, plmn->mcc);
}

/*! Parse a TS 23.003 Section 19.2 Home Network Realm/Domain (text form) into a \ref osmo_plmn_id
 *  \param out[out] caller-allocated output structure
 *  \param in[in] character string representation to be parsed
 *  \returns 0 on success; negative on error */
int osmo_parse_home_network_domain(struct osmo_plmn_id *out, const char *in)
{
	int rc;

	memset(out, 0, sizeof(*out));
	rc = sscanf(in, "epc.mnc%03hu.mcc%03hu.3gppnetwork.org", &out->mnc, &out->mcc);
	if (rc < 0)
		return rc;
	if (rc != 2)
		return -EINVAL;
	return 0;
}

/*! Generate TS 23.003 Section 19.4.2.4 MME Domain (text form)
 *  \param out[out] caller-provided output buffer, at least 56 bytes long
 *  \param gummei[in] Structure representing the Globally Unique MME Identifier
 *  \returns number of characters printed (excluding NUL); negative on error */
int osmo_gen_mme_domain(char *out, const struct osmo_gummei *gummei)
{
	char domain[GSM23003_HOME_NETWORK_DOMAIN_LEN+1];
	int rc;
	rc = osmo_gen_home_network_domain(domain, &gummei->plmn);
	if (rc < 0)
		return rc;
	return sprintf(out, "mmec%02x.mmegi%04x.mme.%s", gummei->mme.code, gummei->mme.group_id, domain);
}

/*! Parse a TS 23.003 Section 19.4.2.4 MME Domain (text form) into a \ref osmo_gummei
 *  \param out[out] caller-allocated output GUMMEI structure
 *  \param in[in] character string representation to be parsed
 *  \returns 0 on success; negative on error */
int osmo_parse_mme_domain(struct osmo_gummei *out, const char *in)
{
	int rc;

	memset(out, 0, sizeof(*out));
	rc = sscanf(in, "mmec%02hhx.mmegi%04hx.mme.epc.mnc%03hu.mcc%03hu.3gppnetwork.org",
		    &out->mme.code, &out->mme.group_id,
		    &out->plmn.mnc, &out->plmn.mcc);
	if (rc < 0)
		return rc;
	if (rc != 4)
		return -EINVAL;
	return 0;
}

/*! Generate TS 23.003 Section 19.4.2.4 MME Group Domain (text form)
 *  \param out[out] caller-provided output buffer, at least 56 bytes long
 *  \param mmegi[in] MME Group Identifier
 *  \param plmn[in] Osmocom representation of PLMN ID (MCC + MNC)
 *  \returns number of characters printed (excluding NUL); negative on error */
int osmo_gen_mme_group_domain(char *out, uint16_t mmegi, const struct osmo_plmn_id *plmn)
{
	char domain[GSM23003_HOME_NETWORK_DOMAIN_LEN+1];
	int rc;
	rc = osmo_gen_home_network_domain(domain, plmn);
	if (rc < 0)
		return rc;
	return sprintf(out, "mmegi%04x.mme.%s", mmegi, domain);
}
