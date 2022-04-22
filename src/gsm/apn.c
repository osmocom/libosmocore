/*! \file apn.c 
 *
 * (C) 2014 by Harald Welte <laforge@gnumonks.org>
 * (C) 2015,2017 by sysmocom - s.f.m.c. GmbH
 * All Rights Reserved.
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
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <osmocom/core/talloc.h>
#include <osmocom/gsm/apn.h>

#define APN_OI_GPRS_FMT	"mnc%03u.mcc%03u.gprs"
#define APN_GPRS_FMT	"%s.mnc%03u.mcc%03u.gprs"

static __thread char apn_strbuf[APN_MAXLEN+1];

char *osmo_apn_qualify_buf(char *buf, size_t buf_len, unsigned int mcc, unsigned int mnc, const char *ni)
{
	snprintf(buf, buf_len-1, APN_GPRS_FMT, ni, mnc, mcc);
	buf[buf_len-1] = '\0';

	return buf;
}

char *osmo_apn_qualify(unsigned int mcc, unsigned int mnc, const char *ni)
{
	return osmo_apn_qualify_buf(apn_strbuf, sizeof(apn_strbuf), mcc, mnc, ni);
}

char *osmo_apn_qualify_c(const void *ctx, unsigned int mcc, unsigned int mnc, const char *ni)
{
	char *buf = talloc_size(ctx, APN_MAXLEN);
	if (!buf)
		return NULL;
	return osmo_apn_qualify_buf(buf, APN_MAXLEN, mcc, mnc, ni);
}

char *osmo_apn_qualify_from_imsi_buf(char *buf, size_t buf_len, const char *imsi,
				     const char *ni, int have_3dig_mnc)
{
	char cbuf[3+1], nbuf[3+1];

	strncpy(cbuf, imsi, 3);
	cbuf[3] = '\0';

	if (have_3dig_mnc) {
		strncpy(nbuf, imsi+3, 3);
		nbuf[3] = '\0';
	} else {
		strncpy(nbuf, imsi+3, 2);
		nbuf[2] = '\0';
	}
	return osmo_apn_qualify_buf(buf, buf_len, atoi(cbuf), atoi(nbuf), ni);
}

char *osmo_apn_qualify_from_imsi(const char *imsi,
				 const char *ni, int have_3dig_mnc)
{
	return osmo_apn_qualify_from_imsi_buf(apn_strbuf, sizeof(apn_strbuf), imsi, ni, have_3dig_mnc);
}

char *osmo_apn_qualify_from_imsi_c(const void *ctx, const char *imsi, const char *ni, int have_3dig_mnc)
{
	char *buf = talloc_size(ctx, APN_MAXLEN);
	if (!buf)
		return NULL;
	return osmo_apn_qualify_from_imsi_buf(buf, APN_MAXLEN, imsi, ni, have_3dig_mnc);
}

/**
 * Convert an encoded APN into a dot-separated string.
 *
 * \param out_str      the destination buffer (size must be >= max(app_enc_len,1))
 * \param apn_enc      the encoded APN
 * \param apn_enc_len  the length of the encoded APN
 *
 * \returns out_str on success and NULL otherwise
 */
char *osmo_apn_to_str(char *out_str, const uint8_t *apn_enc, size_t apn_enc_len)
{
	char *str = out_str;
	size_t rest_chars = apn_enc_len;

	if (!apn_enc)
		return NULL;

	while (rest_chars > 0 && apn_enc[0]) {
		size_t label_size = apn_enc[0];
		if (label_size + 1 > rest_chars)
			return NULL;

		memmove(str, apn_enc + 1, label_size);
		str += label_size;
		rest_chars -= label_size + 1;
		apn_enc += label_size + 1;

		if (rest_chars)
			*(str++) = '.';
	}
	str[0] = '\0';

	return out_str;
}

/**
 * Convert a dot-separated string into an encoded APN.
 *
 * \param apn_enc          the encoded APN
 * \param max_apn_enc_len  the size of the apn_enc buffer
 * \param str              the source string
 *
 * \returns out_str on success and NULL otherwise
 */
int osmo_apn_from_str(uint8_t *apn_enc, size_t max_apn_enc_len, const char *str)
{
	uint8_t *last_len_field;
	int len;

	/* Can we even write the length field to the output? */
	if (max_apn_enc_len == 0)
		return -1;

	/* Remember where we need to put the length once we know it */
	last_len_field = apn_enc;
	len = 1;
	apn_enc += 1;

	while (str[0]) {
		if (len >= max_apn_enc_len)
			return -1;

		if (str[0] == '.') {
			*last_len_field = (apn_enc - last_len_field) - 1;
			last_len_field = apn_enc;
		} else {
			*apn_enc = str[0];
		}
		apn_enc += 1;
		str += 1;
		len += 1;
	}

	*last_len_field = (apn_enc - last_len_field) - 1;

	return len;
}
