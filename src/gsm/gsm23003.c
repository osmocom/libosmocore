/*! \file gsm23003.c
 * Utility function implementations related to 3GPP TS 23.003 */
/*
 * (C) 2017 sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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
