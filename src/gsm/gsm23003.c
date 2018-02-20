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

#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

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
	return is_n_digits(msisdn, 1, 15);
}

/*! Return MCC string as standardized 3-digit with leading zeros.
 * \param[in] mcc  MCC value.
 * \returns string in static buffer.
 */
const char *osmo_mcc_name(uint16_t mcc)
{
	static char buf[8];
	snprintf(buf, sizeof(buf), "%03u", mcc);
	return buf;
}

/*! Return MNC string as standardized 2- or 3-digit with leading zeros.
 * \param[in] mnc  MNC value.
 * \param[in] mnc_3_digits  True if an MNC should fill three digits, only has an effect if MNC < 100.
 * \returns string in static buffer.
 */
const char *osmo_mnc_name(uint16_t mnc, bool mnc_3_digits)
{
	static char buf[8];
	snprintf(buf, sizeof(buf), "%0*u", mnc_3_digits ? 3 : 2, mnc);
	return buf;
}

static inline void plmn_name(char *buf, size_t buflen, const struct osmo_plmn_id *plmn)
{
	snprintf(buf, buflen, "%s-%s", osmo_mcc_name(plmn->mcc),
		 osmo_mnc_name(plmn->mnc, plmn->mnc_3_digits));
}

/*! Return MCC-MNC string as standardized 3-digit-dash-2/3-digit with leading zeros.
 * \param[in] plmn  MCC-MNC value.
 * \returns string in static buffer.
 */
const char *osmo_plmn_name(const struct osmo_plmn_id *plmn)
{
	static char buf[16];
	plmn_name(buf, sizeof(buf), plmn);
	return buf;
}

/*! Same as osmo_mcc_mnc_name(), but returning in a different static buffer.
 * \param[in] plmn  MCC-MNC value.
 * \returns string in static buffer.
 */
const char *osmo_plmn_name2(const struct osmo_plmn_id *plmn)
{
	static char buf[16];
	plmn_name(buf, sizeof(buf), plmn);
	return buf;
}

/*! Return MCC-MNC-LAC as string, in a static buffer.
 * \param[in] lai  LAI to encode, the rac member is ignored.
 * \returns Static string buffer.
 */
const char *osmo_lai_name(const struct osmo_location_area_id *lai)
{
	static char buf[32];
	snprintf(buf, sizeof(buf), "%s-%u", osmo_plmn_name(&lai->plmn), lai->lac);
	return buf;
}

static void to_bcd(uint8_t *bcd, uint16_t val)
{
	bcd[2] = val % 10;
	val = val / 10;
	bcd[1] = val % 10;
	val = val / 10;
	bcd[0] = val % 10;
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
