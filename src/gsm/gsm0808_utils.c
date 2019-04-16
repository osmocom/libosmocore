/*
 * (C) 2016 by sysmocom - s.f.m.c. GmbH, Author: Philipp Maier
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/byteswap.h>
#include <string.h>
#include <errno.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm0808_utils.h>

#define IP_V4_ADDR_LEN 4
#define IP_V6_ADDR_LEN 16
#define IP_PORT_LEN 2

#define CHANNEL_TYPE_ELEMENT_MAXLEN 11
#define CHANNEL_TYPE_ELEMENT_MINLEN 3
#define ENCRYPT_INFO_ELEMENT_MINLEN 1

#ifdef HAVE_SYS_SOCKET_H

#include <sys/socket.h>
#include <netinet/in.h>

/*! \addtogroup gsm0808
 *  @{
 *  \file gsm0808_utils.c
 */

/*! Encode TS 08.08 AoIP Cause IE
 *  \param[out] msg Message Buffer to which to append IE
 *  \param[in] cause Cause code to be used in IE
 *  \returns number of bytes added to \a msg */
uint8_t gsm0808_enc_cause(struct msgb *msg, uint16_t cause)
{
	/* See also 3GPP TS 48.008 3.2.2.5 Cause */
	uint8_t *old_tail;
	bool extended;

	old_tail = msg->tail;

	extended = gsm0808_cause_ext(cause >> 8);

	msgb_put_u8(msg, GSM0808_IE_CAUSE);
	if (extended) {
		msgb_put_u8(msg, 2);
		msgb_put_u16(msg, cause);
	} else {
		msgb_put_u8(msg, 1);
		msgb_put_u8(msg, (uint8_t) (cause & 0xFF));
	}

	return (uint8_t) (msg->tail - old_tail);
}

/*! Encode TS 08.08 AoIP transport address IE
 *  \param[out] msg Message Buffer to which to append IE
 *  \param[in] ss Socket Address to be used in IE
 *  \returns number of bytes added to \a msg */
uint8_t gsm0808_enc_aoip_trasp_addr(struct msgb *msg,
				    const struct sockaddr_storage *ss)
{
	/* See also 3GPP TS 48.008 3.2.2.102 AoIP Transport Layer Address */
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	uint16_t port = 0;
	uint8_t *ptr;
	uint8_t *old_tail;
	uint8_t *tlv_len;

	OSMO_ASSERT(msg);
	OSMO_ASSERT(ss);
	OSMO_ASSERT(ss->ss_family == AF_INET || ss->ss_family == AF_INET6);

	msgb_put_u8(msg, GSM0808_IE_AOIP_TRASP_ADDR);
	tlv_len = msgb_put(msg,1);
	old_tail = msg->tail;

	switch (ss->ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)ss;
		port = osmo_ntohs(sin->sin_port);
		ptr = msgb_put(msg, IP_V4_ADDR_LEN);
		memcpy(ptr, &sin->sin_addr.s_addr, IP_V4_ADDR_LEN);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)ss;
		port = osmo_ntohs(sin6->sin6_port);
		ptr = msgb_put(msg, IP_V6_ADDR_LEN);
		memcpy(ptr, sin6->sin6_addr.s6_addr, IP_V6_ADDR_LEN);
		break;
	}

	msgb_put_u16(msg, port);

	*tlv_len = (uint8_t) (msg->tail - old_tail);
	return *tlv_len + 2;
}

/*! Decode TS 08.08 AoIP transport address IE
 *  \param[out] ss Caller-provided memory where decoded socket addr is stored
 *  \param[in] elem pointer to IE value
 *  \param[in] len length of \a elem in bytes
 *  \returns number of bytes parsed */
int gsm0808_dec_aoip_trasp_addr(struct sockaddr_storage *ss,
				const uint8_t *elem, uint8_t len)
{
	/* See also 3GPP TS 48.008 3.2.2.102 AoIP Transport Layer Address */
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	const uint8_t *old_elem = elem;

	OSMO_ASSERT(ss);
	if (!elem)
		return -EINVAL;
	if (len == 0)
		return -EINVAL;

	memset(ss, 0, sizeof(*ss));

	switch (len) {
	case IP_V4_ADDR_LEN + IP_PORT_LEN:
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;

		memcpy(&sin.sin_addr.s_addr, elem, IP_V4_ADDR_LEN);
		elem += IP_V4_ADDR_LEN;
		sin.sin_port = osmo_load16le(elem);
		elem += IP_PORT_LEN;

		memcpy(ss, &sin, sizeof(sin));
		break;
	case IP_V6_ADDR_LEN + IP_PORT_LEN:
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;

		memcpy(sin6.sin6_addr.s6_addr, elem, IP_V6_ADDR_LEN);
		elem += IP_V6_ADDR_LEN;
		sin6.sin6_port = osmo_load16le(elem);
		elem += IP_PORT_LEN;

		memcpy(ss, &sin6, sizeof(sin6));
		break;
	default:
		/* Malformed element! */
		return -EINVAL;
		break;
	}

	return (int)(elem - old_elem);
}

/*! Decode TS 08.08 (Osmocom Extension) Osmux CID
 *  TV with len(V) == 1, and V is the CID to be used.
 *  \param[out] cid Caller-provided variable where CID is stored
 *  \param[in] elem pointer to IE value
 *  \param[in] len length of \a elem in bytes
 *  \returns number of bytes parsed */
int gsm0808_dec_osmux_cid(uint8_t *cid, const uint8_t *elem, uint8_t len)
{
	OSMO_ASSERT(cid);
	if (!elem)
		return -EINVAL;
	if (len != 1)
		return -EINVAL;

	*cid = *elem;

	return 1;
}

#endif /* HAVE_SYS_SOCKET_H */

/* Helper function for gsm0808_enc_speech_codec()
 * and gsm0808_enc_speech_codec_list() */
static uint8_t enc_speech_codec(struct msgb *msg,
				const struct gsm0808_speech_codec *sc)
{
	/* See also 3GPP TS 48.008 3.2.2.103 Speech Codec List */
	uint8_t header = 0;
	uint8_t *old_tail;
	bool type_extended = false;

	/* Note: Extended codec types are codec types that require 8 instead
	 * of 4 bit to fully specify the selected codec. In the following,
	 * we check if we work with an extended type or not. We also check
	 * if the codec type is valid at all. */
	switch(sc->type) {
	case GSM0808_SCT_FR1:
	case GSM0808_SCT_FR2:
	case GSM0808_SCT_FR3:
	case GSM0808_SCT_FR4:
	case GSM0808_SCT_FR5:
	case GSM0808_SCT_HR1:
	case GSM0808_SCT_HR3:
	case GSM0808_SCT_HR4:
	case GSM0808_SCT_HR6:
		type_extended = false;
		break;
	case GSM0808_SCT_CSD:
		type_extended = true;
		break;
	default:
		/* Invalid codec type specified */
		OSMO_ASSERT(false);
		break;
	}

	old_tail = msg->tail;

	if (sc->fi)
		header |= (1 << 7);
	if (sc->pi)
		header |= (1 << 6);
	if (sc->pt)
		header |= (1 << 5);
	if (sc->tf)
		header |= (1 << 4);

	if (type_extended) {
		header |= 0x0f;
		msgb_put_u8(msg, header);
		msgb_put_u8(msg, sc->type);
	} else {
		OSMO_ASSERT(sc->type < 0x0f);
		header |= sc->type;
		msgb_put_u8(msg, header);
	}

	/* Note: Whether a configuration is present or not depends on the
	 * selected codec type. If present, it can either consist of one
	 * or two octets, depending on the codec type */
	switch (sc->type) {
	case GSM0808_SCT_FR3:
	case GSM0808_SCT_HR3:
	case GSM0808_SCT_HR6:
		msgb_put_u16(msg, osmo_ntohs(sc->cfg));
		break;
	case GSM0808_SCT_FR4:
	case GSM0808_SCT_FR5:
	case GSM0808_SCT_HR4:
	case GSM0808_SCT_CSD:
		OSMO_ASSERT((sc->cfg & 0xff00) == 0)
		msgb_put_u8(msg, (uint8_t) sc->cfg & 0xff);
		break;
	default:
		OSMO_ASSERT(sc->cfg == 0);
		break;
	}

	return (uint8_t) (msg->tail - old_tail);
}

/*! Encode TS 08.08 Speech Codec IE
 *  \param[out] msg Message Buffer to which IE will be appended
 *  \param[in] sc Speech Codec to be encoded into IE
 *  \returns number of bytes appended to \a msg */
uint8_t gsm0808_enc_speech_codec(struct msgb *msg,
				 const struct gsm0808_speech_codec *sc)
{
	/*! See also 3GPP TS 48.008 3.2.2.103 Speech Codec List */
	uint8_t *old_tail;
	uint8_t *tlv_len;

	OSMO_ASSERT(msg);
	OSMO_ASSERT(sc);

	msgb_put_u8(msg, GSM0808_IE_SPEECH_CODEC);
	tlv_len = msgb_put(msg, 1);
	old_tail = msg->tail;

	enc_speech_codec(msg, sc);

	*tlv_len = (uint8_t) (msg->tail - old_tail);
	return *tlv_len + 2;
}

/*! Decode TS 08.08 Speech Codec IE
 *  \param[out] sc Caller-allocated memory for Speech Codec
 *  \param[in] elem IE value to be decoded
 *  \param[in] len Length of \a elem in bytes
 *  \returns number of bytes parsed; negative on error */
int gsm0808_dec_speech_codec(struct gsm0808_speech_codec *sc,
			     const uint8_t *elem, uint8_t len)
{
	/* See also 3GPP TS 48.008 3.2.2.103 Speech Codec List */
	uint8_t header;
	const uint8_t *old_elem = elem;

	OSMO_ASSERT(sc);
	if (!elem)
		return -EINVAL;
	if (len == 0)
		return -EINVAL;

	memset(sc, 0, sizeof(*sc));

	header = *elem;

	/* An extended codec type needs at least two fields,
	 * bail if the input data length is not sufficient. */
	if ((header & 0x0F) == 0x0F && len < 2)
		return -EINVAL;

	elem++;
	len--;

	if (header & (1 << 7))
		sc->fi = true;
	if (header & (1 << 6))
		sc->pi = true;
	if (header & (1 << 5))
		sc->pt = true;
	if (header & (1 << 4))
		sc->tf = true;

	if ((header & 0x0F) != 0x0F) {
		sc->type = (header & 0x0F);
	} else {
		sc->type = *elem;
		elem++;
		len--;
	}

	/* Note: Whether a configuration is present or not depends on the
	 * selected codec type. If present, it can either consist of one or
	 * two octets depending on the codec type */
	switch (sc->type) {
	case GSM0808_SCT_FR1:
	case GSM0808_SCT_FR2:
	case GSM0808_SCT_HR1:
		break;
	case GSM0808_SCT_HR4:
	case GSM0808_SCT_CSD:
	case GSM0808_SCT_FR4:
	case GSM0808_SCT_FR5:
		if (len < 1)
			return -EINVAL;
		sc->cfg = *elem;
		elem++;
		break;
	case GSM0808_SCT_FR3:
	case GSM0808_SCT_HR3:
	case GSM0808_SCT_HR6:
		if (len < 2)
			return -EINVAL;
		sc->cfg = osmo_load16le(elem);
		elem += 2;
		break;
	default:
		/* Invalid codec type => malformed speech codec element! */
		return -EINVAL;
		break;
	}

	return (int)(elem - old_elem);
}

/*! Encode TS 08.08 Speech Codec list
 *  \param[out] msg  Message Buffer to which IE is to be appended
 *  \param[in] scl Speech Codec List to be encoded into IE
 *  \returns number of bytes added to \a msg */
uint8_t gsm0808_enc_speech_codec_list(struct msgb *msg,
				      const struct gsm0808_speech_codec_list *scl)
{
	/*! See also 3GPP TS 48.008 3.2.2.103 Speech Codec List */
	uint8_t *old_tail;
	uint8_t *tlv_len;
	unsigned int i;
	uint8_t rc;
	unsigned int bytes_used = 0;

	OSMO_ASSERT(msg);
	OSMO_ASSERT(scl);

	msgb_put_u8(msg, GSM0808_IE_SPEECH_CODEC_LIST);
	tlv_len = msgb_put(msg, 1);
	old_tail = msg->tail;

	for (i = 0; i < scl->len; i++) {
		rc = enc_speech_codec(msg, &scl->codec[i]);
		OSMO_ASSERT(rc >= 1);
		bytes_used += rc;
		OSMO_ASSERT(bytes_used <= 255);
	}

	*tlv_len = (uint8_t) (msg->tail - old_tail);
	return *tlv_len + 2;
}

/*! Decode TS 08.08 Speech Codec list IE
 *  \param[out] scl Caller-provided memory to store codec list
 *  \param[in] elem IE value to be decoded
 *  \param[in] len Length of \a elem in bytes
 *  \returns number of bytes parsed; negative on error */
int gsm0808_dec_speech_codec_list(struct gsm0808_speech_codec_list *scl,
				  const uint8_t *elem, uint8_t len)
{
	/*! See also 3GPP TS 48.008 3.2.2.103 Speech Codec List */
	const uint8_t *old_elem = elem;
	unsigned int i;
	int rc;
	uint8_t decoded = 0;

	OSMO_ASSERT(scl);
	if (!elem)
		return -EINVAL;

	memset(scl, 0, sizeof(*scl));

	for (i = 0; i < ARRAY_SIZE(scl->codec); i++) {
		if (len <= 0)
			break;

		rc = gsm0808_dec_speech_codec(&scl->codec[i], elem, len);
		if (rc < 1)
			return -EINVAL;

		elem+=rc;
		len -= rc;
		decoded++;
	}

	scl->len = decoded;

	return (int)(elem - old_elem);
}

/*! Encode TS 08.08 Channel Type IE
 *  \param[out] msg Message Buffer to which IE is to be appended
 *  \param[in] ct Channel Type to be encoded
 *  \returns number of bytes added to \a msg */
uint8_t gsm0808_enc_channel_type(struct msgb *msg,
				 const struct gsm0808_channel_type *ct)
{
	/*! See also 3GPP TS 48.008 3.2.2.11 Channel Type */
	unsigned int i;
	uint8_t byte;
	uint8_t *old_tail;
	uint8_t *tlv_len;

	OSMO_ASSERT(msg);
	OSMO_ASSERT(ct);
	OSMO_ASSERT(ct->perm_spch_len <= CHANNEL_TYPE_ELEMENT_MAXLEN - 2);

	/* FIXME: Implement encoding support for Data
	 * and Speech + CTM Text Telephony */
	if ((ct->ch_indctr & 0x0f) != GSM0808_CHAN_SPEECH
	    && (ct->ch_indctr & 0x0f) != GSM0808_CHAN_SIGN)
		OSMO_ASSERT(false);

	msgb_put_u8(msg, GSM0808_IE_CHANNEL_TYPE);
	tlv_len = msgb_put(msg, 1);
	old_tail = msg->tail;

	msgb_put_u8(msg, ct->ch_indctr & 0x0f);
	msgb_put_u8(msg, ct->ch_rate_type);

	for (i = 0; i < ct->perm_spch_len; i++) {
		byte = ct->perm_spch[i];

		if (i < ct->perm_spch_len - 1)
			byte |= 0x80;
		msgb_put_u8(msg, byte);
	}

	*tlv_len = (uint8_t) (msg->tail - old_tail);
	return *tlv_len + 2;
}

/*! Decode TS 08.08 Channel Type IE
 *  \param[out] ct Caller-provided memory to store channel type
 *  \param[in] elem IE Value to be decoded
 *  \param[in] len Length of \a elem in bytes
 *  \returns number of bytes parsed; negative on error */
int gsm0808_dec_channel_type(struct gsm0808_channel_type *ct,
			     const uint8_t *elem, uint8_t len)
{
	/*! See also 3GPP TS 48.008 3.2.2.11 Channel Type */
	unsigned int i;
	uint8_t byte;
	const uint8_t *old_elem = elem;

	OSMO_ASSERT(ct);
	if (!elem)
		return -EINVAL;
	if (len < 3 || len > 11)
		return -EINVAL;

	memset(ct, 0, sizeof(*ct));

	ct->ch_indctr = (*elem) & 0x0f;
	elem++;
	ct->ch_rate_type = (*elem) & 0x0f;
	elem++;

	for (i = 0; i < ARRAY_SIZE(ct->perm_spch); i++) {
		byte = *elem;
		elem++;
		ct->perm_spch[i] = byte & 0x7f;
		if ((byte & 0x80) == 0x00)
			break;
	}
	ct->perm_spch_len = i + 1;

	return (int)(elem - old_elem);
}

/*! Create BSSMAP Global Call Reference, 3GPP TS 48.008 §3.2.2.115.
 *  \param[out] msg Message Buffer for appending IE
 *  \param[in] g Global Call Reference, 3GPP TS 29.205 Table B 2.1.9.1
 *  \returns number of bytes added to \a msg or 0 on error */
static uint8_t gsm0808_enc_gcr(struct msgb *msg, const struct osmo_gcr_parsed *g)
{
	uint8_t enc, *len = msgb_tl_put(msg, GSM0808_IE_GLOBAL_CALL_REF);

	enc = osmo_enc_gcr(msg, g);
	if (!enc)
		return 0;

	*len = enc;
	return enc + 2; /* type (1 byte) + length (1 byte) */
}

/*! Decode BSSMAP Global Call Reference, 3GPP TS 29.205 Table B 2.1.9.1.
 *  \param[out] gcr Caller-provided memory to store Global Call Reference
 *  \param[in] tp IE values to be decoded
 *  \returns number of bytes parsed; negative on error */
static int gsm0808_dec_gcr(struct osmo_gcr_parsed *gcr, const struct tlv_parsed *tp)
{
	int ret;
	const uint8_t *buf = TLVP_VAL_MINLEN(tp, GSM0808_IE_GLOBAL_CALL_REF, OSMO_GCR_MIN_LEN);
	if (!buf)
		return -EINVAL;

	ret = osmo_dec_gcr(gcr, buf, TLVP_LEN(tp, GSM0808_IE_GLOBAL_CALL_REF));
	if (ret < 0)
		return -ENOENT;

	return 2 + ret;
}

/*! Add LCLS parameters to a given msgb, 3GPP TS 48.008 §3.2.2.115 - 3.2.2.120.
 *  \param[out] msg Message Buffer for appending IE
 *  \param[in] lcls LCLS-related data
 *  \returns number of bytes added to \a msg or 0 on error */
uint8_t gsm0808_enc_lcls(struct msgb *msg, const struct osmo_lcls *lcls)
{
	uint8_t enc = 0;

	/* LCLS: §3.2.2.115 Global Call Reference */
	if (lcls->gcr_available)
		enc = gsm0808_enc_gcr(msg, &lcls->gcr);

	/* LCLS: §3.2.2.116 Configuration */
	if (lcls->config != GSM0808_LCLS_CFG_NA) {
		msgb_tv_put(msg, GSM0808_IE_LCLS_CONFIG, lcls->config);
		enc += 2;
	}

	/* LCLS: §3.2.2.117 Connection Status Control */
	if (lcls->control != GSM0808_LCLS_CSC_NA) {
		msgb_tv_put(msg, GSM0808_IE_LCLS_CONN_STATUS_CTRL, lcls->control);
		enc += 2;
	}

	/* LCLS: §3.2.2.118 Correlation-Not-Needed */
	if (!lcls->corr_needed) {
		msgb_v_put(msg, GSM0808_IE_LCLS_CORR_NOT_NEEDED);
		enc++;
	}

	return enc;
}

/*! Decode LCLS parameters to a given msgb, 3GPP TS 48.008 §3.2.2.115 - 3.2.2.120.
 *  \param[out] lcls Caller-provided memory to store LCLS-related data
 *  \param[in] tp IE values to be decoded
 *  \returns GCR size or negative on error */
int gsm0808_dec_lcls(struct osmo_lcls *lcls, const struct tlv_parsed *tp)
{
	int ret = gsm0808_dec_gcr(&lcls->gcr, tp);

	lcls->gcr_available = (ret < 0) ? false : true;
	lcls->config = tlvp_val8(tp, GSM0808_IE_LCLS_CONFIG, GSM0808_LCLS_CFG_NA);
	lcls->control = tlvp_val8(tp, GSM0808_IE_LCLS_CONN_STATUS_CTRL, GSM0808_LCLS_CSC_NA);
	lcls->corr_needed = TLVP_PRESENT(tp, GSM0808_IE_LCLS_CORR_NOT_NEEDED) ? false : true;

	return ret;
}

static char dbuf[256];

/*! Dump LCLS parameters (GCR excluded) into string for printing.
 *  \param[out] buf caller-allocated output string buffer
 *  \param[in] buf_len size of buf in bytes
 *  \param[in] lcls pointer to the struct to print.
 *  \returns string representation of LCLS or NULL on error. */
char *osmo_lcls_dump_buf(char *buf, size_t buf_len, const struct osmo_lcls *lcls)
{
	struct osmo_strbuf s = { .buf = buf, .len = buf_len };

	if (!lcls)
		return NULL;

	OSMO_STRBUF_PRINTF(s, "LCLS Config: %s, Control: %s, Correlation-Needed: %u",
			   gsm0808_lcls_config_name(lcls->config),
			   gsm0808_lcls_control_name(lcls->control),
			   lcls->corr_needed);

	return dbuf;
}

/*! Dump LCLS parameters (GCR excluded) into static string buffer for printing.
 *  \param[in] lcls pointer to the struct to print.
 *  \returns string representation of LCLS in static buffer or NULL on error. */
char *osmo_lcls_dump(const struct osmo_lcls *lcls)
{
	return osmo_lcls_dump_buf(dbuf, sizeof(dbuf), lcls);
}

char *osmo_lcls_dump_c(void *ctx, const struct osmo_lcls *lcls)
{
	char *buf = talloc_size(ctx, 256);
	if (!buf)
		return NULL;
	return osmo_lcls_dump_buf(buf, 256, lcls);
}

/*! Dump GCR struct into string for printing.
 *  \param[out] buf caller-allocated output string buffer
 *  \param[in] buf_len size of buf in bytes
 *  \param[in] lcls pointer to the struct to print.
 *  \returns string representation of GCR or NULL on error. */
char *osmo_gcr_dump_buf(char *buf, size_t buf_len, const struct osmo_lcls *lcls)
{
	struct osmo_strbuf s = { .buf = buf, .len = buf_len };

	if (!lcls)
		return NULL;

	if (lcls->gcr_available) {
		OSMO_STRBUF_PRINTF(s, "GCR NetID 0x%s, ", osmo_hexdump_nospc(lcls->gcr.net, lcls->gcr.net_len));
		/* osmo_hexdump() uses static buffers so we can't call it twice withing the same parameter list */
		OSMO_STRBUF_PRINTF(s, "Node 0x%x, CallRefID 0x%s", lcls->gcr.node, osmo_hexdump_nospc(lcls->gcr.cr, 5));
	}

	return dbuf;
}

/*! Dump GCR struct into static string buffer for printing.
 *  \param[in] lcls pointer to the struct to print.
 *  \returns string representation of GCR in static buffer or NULL on error. */
char *osmo_gcr_dump(const struct osmo_lcls *lcls)
{
	return osmo_gcr_dump_buf(dbuf, sizeof(dbuf), lcls);
}


/*! Encode TS 08.08 Encryption Information IE
 *  \param[out] msg Message Buffer to which IE is to be appended
 *  \param[in] ei Encryption Information to be encoded
 *  \returns number of bytes appended to \a msg */
uint8_t gsm0808_enc_encrypt_info(struct msgb *msg,
				 const struct gsm0808_encrypt_info *ei)
{
	unsigned int i;
	uint8_t perm_algo = 0;
	uint8_t *ptr;
	uint8_t *old_tail;
	uint8_t *tlv_len;

	OSMO_ASSERT(msg);
	OSMO_ASSERT(ei);
	OSMO_ASSERT(ei->key_len <= ARRAY_SIZE(ei->key));
	OSMO_ASSERT(ei->perm_algo_len <= ENCRY_INFO_PERM_ALGO_MAXLEN);

	msgb_put_u8(msg, GSM0808_IE_ENCRYPTION_INFORMATION);
	tlv_len = msgb_put(msg, 1);
	old_tail = msg->tail;

	for (i = 0; i < ei->perm_algo_len; i++) {
		/* Note: gsm_08_08.h defines the permitted algorithms
		 * as an enum which ranges from 0x01 to 0x08 */
		OSMO_ASSERT(ei->perm_algo[i] != 0);
		OSMO_ASSERT(ei->perm_algo[i] <= ENCRY_INFO_PERM_ALGO_MAXLEN);
		perm_algo |= (1 << (ei->perm_algo[i] - 1));
	}

	msgb_put_u8(msg, perm_algo);
	ptr = msgb_put(msg, ei->key_len);
	memcpy(ptr, ei->key, ei->key_len);

	*tlv_len = (uint8_t) (msg->tail - old_tail);
	return *tlv_len + 2;
}

/*! Decode TS 08.08 Encryption Information IE
 *  \param[out] ei Caller-provided memory to store encryption information
 *  \param[in] elem IE value to be decoded
 *  \param[in] len Length of \a elem in bytes
 *  \returns number of bytes parsed; negative on error */
int gsm0808_dec_encrypt_info(struct gsm0808_encrypt_info *ei,
			     const uint8_t *elem, uint8_t len)
{
	uint8_t perm_algo;
	unsigned int i;
	unsigned int perm_algo_len = 0;
	const uint8_t *old_elem = elem;

	OSMO_ASSERT(ei);
	if (!elem)
		return -EINVAL;
	if (len == 0)
		return -EINVAL;

	memset(ei, 0, sizeof(*ei));

	perm_algo = *elem;
	elem++;

	for (i = 0; i < ENCRY_INFO_PERM_ALGO_MAXLEN; i++) {
		if (perm_algo & (1 << i)) {
			ei->perm_algo[perm_algo_len] = i + 1;
			perm_algo_len++;
		}
	}
	ei->perm_algo_len = perm_algo_len;

	ei->key_len = len - 1;
	memcpy(ei->key, elem, ei->key_len);
	elem+=ei->key_len;

	return (int)(elem - old_elem);
}

void gsm0808_msgb_put_cell_id_u(struct msgb *msg, enum CELL_IDENT id_discr, const union gsm0808_cell_id_u *u)
{
	switch (id_discr) {
	case CELL_IDENT_WHOLE_GLOBAL: {
		const struct osmo_cell_global_id *id = &u->global;
		struct gsm48_loc_area_id lai;
		gsm48_generate_lai2(&lai, &id->lai);
		memcpy(msgb_put(msg, sizeof(lai)), &lai, sizeof(lai));
		msgb_put_u16(msg, id->cell_identity);
		break;
	}
	case CELL_IDENT_LAC_AND_CI: {
		const struct osmo_lac_and_ci_id *id = &u->lac_and_ci;
		msgb_put_u16(msg, id->lac);
		msgb_put_u16(msg, id->ci);
		break;
	}
	case CELL_IDENT_CI:
		msgb_put_u16(msg, u->ci);
		break;
	case CELL_IDENT_LAI_AND_LAC: {
		const struct osmo_location_area_id *id = &u->lai_and_lac;
		struct gsm48_loc_area_id lai;
		gsm48_generate_lai2(&lai, id);
		memcpy(msgb_put(msg, sizeof(lai)), &lai, sizeof(lai));
		break;
	}
	case CELL_IDENT_LAC:
		msgb_put_u16(msg, u->lac);
		break;
	case CELL_IDENT_BSS:
	case CELL_IDENT_NO_CELL:
		/* Does not have any list items */
		break;
	default:
		/* Support for other identifier list types is not implemented. */
		OSMO_ASSERT(false);
	}
}

/*! Encode TS 08.08 Cell Identifier List IE
 *  \param[out] msg Message Buffer to which IE is to be appended
 *  \param[in] cil Cell ID List to be encoded
 *  \returns number of bytes appended to \a msg */
uint8_t gsm0808_enc_cell_id_list2(struct msgb *msg,
				  const struct gsm0808_cell_id_list2 *cil)
{
	uint8_t *old_tail;
	uint8_t *tlv_len;
	unsigned int i;

	OSMO_ASSERT(msg);
	OSMO_ASSERT(cil);

	msgb_put_u8(msg, GSM0808_IE_CELL_IDENTIFIER_LIST);
	tlv_len = msgb_put(msg, 1);
	old_tail = msg->tail;

	msgb_put_u8(msg, cil->id_discr & 0x0f);

	OSMO_ASSERT(cil->id_list_len <= GSM0808_CELL_ID_LIST2_MAXLEN)
	for (i = 0; i < cil->id_list_len; i++)
		gsm0808_msgb_put_cell_id_u(msg, cil->id_discr, &cil->id_list[i]);

	*tlv_len = (uint8_t) (msg->tail - old_tail);
	return *tlv_len + 2;
}

/*! DEPRECATED: Use gsm0808_enc_cell_id_list2 instead.
 *
 * Encode TS 08.08 Cell Identifier List IE
 *  \param[out] msg Message Buffer to which IE is to be appended
 *  \param[in] cil Cell ID List to be encoded
 *  \returns number of bytes appended to \a msg */
uint8_t gsm0808_enc_cell_id_list(struct msgb *msg,
				 const struct gsm0808_cell_id_list *cil)
{
	uint8_t *old_tail;
	uint8_t *tlv_len;
	unsigned int i;

	OSMO_ASSERT(msg);
	OSMO_ASSERT(cil);

	msgb_put_u8(msg, GSM0808_IE_CELL_IDENTIFIER_LIST);
	tlv_len = msgb_put(msg, 1);
	old_tail = msg->tail;

	msgb_put_u8(msg, cil->id_discr & 0x0f);

	switch (cil->id_discr) {
	case CELL_IDENT_LAC:
		OSMO_ASSERT(cil->id_list_len <= CELL_ID_LIST_LAC_MAXLEN)
		for (i=0;i<cil->id_list_len;i++) {
			msgb_put_u16(msg, cil->id_list_lac[i]);
		}
		break;
	case CELL_IDENT_BSS:
		/* Does not have any list items */
		break;
	default:
		/* FIXME: Implement support for all identifier list elements */
		OSMO_ASSERT(false);
	}

	*tlv_len = (uint8_t) (msg->tail - old_tail);
	return *tlv_len + 2;
}

/* Decode 5-byte LAI list element data (see TS 08.08 3.2.2.27) into MCC/MNC/LAC. */
static void decode_lai(const uint8_t *data, struct osmo_location_area_id *decoded)
{
	struct gsm48_loc_area_id lai;

	/* Copy data to stack to prevent unaligned access in gsm48_decode_lai2(). */
	memcpy(&lai, data, sizeof(lai)); /* don't byte swap yet */

	gsm48_decode_lai2(&lai, decoded);
}

static int parse_cell_id_global_list(struct gsm0808_cell_id_list2 *cil, const uint8_t *data, size_t remain,
				     size_t *consumed)
{
	struct osmo_cell_global_id *id;
	uint16_t *ci_be;
	size_t lai_offset;
	int i = 0;
	const size_t elemlen = sizeof(struct gsm48_loc_area_id) + sizeof(*ci_be);

	*consumed = 0;
	while (remain >= elemlen) {
		if (i >= GSM0808_CELL_ID_LIST2_MAXLEN)
			return -ENOSPC;
		id = &cil->id_list[i].global;
		lai_offset = i * elemlen;
		decode_lai(&data[lai_offset], &id->lai);
		ci_be = (uint16_t *)(&data[lai_offset + sizeof(struct gsm48_loc_area_id)]);
		id->cell_identity = osmo_load16be(ci_be);
		*consumed += elemlen;
		remain -= elemlen;
		i++;
	}

	return i;
}

static int parse_cell_id_lac_and_ci_list(struct gsm0808_cell_id_list2 *cil, const uint8_t *data, size_t remain,
					 size_t *consumed)
{
	uint16_t *lacp_be, *ci_be;
	struct osmo_lac_and_ci_id *id;
	int i = 0, j = 0;
	const size_t elemlen = sizeof(*lacp_be) + sizeof(*ci_be);

	*consumed = 0;

	if (remain < elemlen)
		return -EINVAL;

	lacp_be = (uint16_t *)(&data[j]);
	ci_be = (uint16_t *)(&data[j + elemlen/2]);
	while (remain >= elemlen) {
		if (i >= GSM0808_CELL_ID_LIST2_MAXLEN)
			return -ENOSPC;
		id = &cil->id_list[i++].lac_and_ci;
		id->lac = osmo_load16be(lacp_be);
		id->ci = osmo_load16be(ci_be);
		*consumed += elemlen;
		remain -= elemlen;
		j += elemlen;
		lacp_be = (uint16_t *)(&data[j]);
		ci_be = (uint16_t *)(&data[j + elemlen/2]);
	}

	return i;
}

static int parse_cell_id_ci_list(struct gsm0808_cell_id_list2 *cil, const uint8_t *data, size_t remain,
    size_t *consumed)
{
	const uint16_t *ci_be = (const uint16_t *)data;
	int i = 0;
	const size_t elemlen = sizeof(*ci_be);

	*consumed = 0;
	while (remain >= elemlen) {
		if (i >= GSM0808_CELL_ID_LIST2_MAXLEN)
			return -ENOSPC;
		cil->id_list[i++].ci = osmo_load16be(ci_be++);
		*consumed += elemlen;
		remain -= elemlen;
	}
	return i;
}

static int parse_cell_id_lai_and_lac(struct gsm0808_cell_id_list2 *cil, const uint8_t *data, size_t remain,
				     size_t *consumed)
{
	struct osmo_location_area_id *id;
	int i = 0;
	const size_t elemlen = sizeof(struct gsm48_loc_area_id);

	*consumed = 0;
	while (remain >= elemlen) {
		if (i >= GSM0808_CELL_ID_LIST2_MAXLEN)
			return -ENOSPC;
		id = &cil->id_list[i].lai_and_lac;
		decode_lai(&data[i * elemlen], id);
		*consumed += elemlen;
		remain -= elemlen;
		i++;
	}

	return i;
}

static int parse_cell_id_lac_list(struct gsm0808_cell_id_list2 *cil, const uint8_t *data, size_t remain, size_t *consumed)
{
	const uint16_t *lac_be = (const uint16_t *)data;
	int i = 0;
	const size_t elemlen = sizeof(*lac_be);

	*consumed = 0;
	while (remain >= elemlen) {
		if (i >= GSM0808_CELL_ID_LIST2_MAXLEN)
			return -ENOSPC;
		cil->id_list[i++].lac = osmo_load16be(lac_be++);
		*consumed += elemlen;
		remain -= elemlen;
	}
	return i;
}

/*! Decode Cell Identifier List IE
 *  \param[out] cil Caller-provided memory to store Cell ID list
 *  \param[in] elem IE value to be decoded
 *  \param[in] len Length of \a elem in bytes
 *  \returns number of bytes parsed; negative on error */
int gsm0808_dec_cell_id_list2(struct gsm0808_cell_id_list2 *cil,
			      const uint8_t *elem, uint8_t len)
{
	uint8_t id_discr;
	size_t bytes_elem = 0;
	int list_len = 0;

	OSMO_ASSERT(cil);
	if (!elem)
		return -EINVAL;
	if (len == 0)
		return -EINVAL;

	memset(cil, 0, sizeof(*cil));

	id_discr = *elem & 0x0f;
	elem++;
	len--;

	switch (id_discr) {
	case CELL_IDENT_WHOLE_GLOBAL:
		list_len = parse_cell_id_global_list(cil, elem, len, &bytes_elem);
		break;
	case CELL_IDENT_LAC_AND_CI:
		list_len = parse_cell_id_lac_and_ci_list(cil, elem, len, &bytes_elem);
		break;
	case CELL_IDENT_CI:
		list_len = parse_cell_id_ci_list(cil, elem, len, &bytes_elem);
		break;
	case CELL_IDENT_LAI_AND_LAC:
		list_len = parse_cell_id_lai_and_lac(cil, elem, len, &bytes_elem);
		break;
	case CELL_IDENT_LAC:
		list_len = parse_cell_id_lac_list(cil, elem, len, &bytes_elem);
		break;
	case CELL_IDENT_BSS:
	case CELL_IDENT_NO_CELL:
		/* Does not have any list items */
		break;
	default:
		/* Remaining cell identification types are not implemented. */
		return -EINVAL;
	}

	if (list_len < 0) /* parsing error */
		return list_len;

	cil->id_discr = id_discr;
	cil->id_list_len = list_len;

	/* One byte for the cell ID discriminator + any remaining bytes in
	 * the IE which were consumed by the parser functions above. */
	return 1 + (int)bytes_elem;
}

/*! DEPRECATED: Use gsm0808_dec_cell_id_list2 instead.
 *
 * Decode Cell Identifier List IE
 *  \param[out] cil Caller-provided memory to store Cell ID list
 *  \param[in] elem IE value to be decoded
 *  \param[in] len Length of \a elem in bytes
 *  \returns number of bytes parsed; negative on error */
int gsm0808_dec_cell_id_list(struct gsm0808_cell_id_list *cil,
			     const uint8_t *elem, uint8_t len)
{
	uint8_t id_discr;
	const uint8_t *old_elem = elem;
	unsigned int item_count = 0;

	OSMO_ASSERT(cil);
	if (!elem)
		return -EINVAL;
	if (len == 0)
		return -EINVAL;

	memset(cil, 0, sizeof(*cil));

	id_discr = *elem & 0x0f;
	elem++;
	len--;

	cil->id_discr = id_discr;

	switch (id_discr) {
	case CELL_IDENT_LAC:
		while (len >= 2) {
			cil->id_list_lac[item_count] = osmo_load16be(elem);
			elem += 2;
			item_count++;
			len -= 2;
		}
	case CELL_IDENT_BSS:
		/* Does not have any list items */
		break;
	default:
		/* FIXME: Implement support for all identifier list elements */
		return -EINVAL;
	}

	cil->id_list_len = item_count;
	return (int)(elem - old_elem);
}

static bool same_cell_id_list_entries(const struct gsm0808_cell_id_list2 *a, int ai,
				      const struct gsm0808_cell_id_list2 *b, int bi)
{
	struct gsm0808_cell_id_list2 tmp = {
		.id_discr = a->id_discr,
		.id_list_len = 1,
	};
	uint8_t buf_a[32 + sizeof(struct msgb)];
	uint8_t buf_b[32 + sizeof(struct msgb)];
	struct msgb *msg_a = (void*)buf_a;
	struct msgb *msg_b = (void*)buf_b;

	msg_a->data_len = 32;
	msg_b->data_len = 32;
	msgb_reset(msg_a);
	msgb_reset(msg_b);

	if (a->id_discr != b->id_discr)
		return false;
	if (ai >= a->id_list_len
	    || bi >= b->id_list_len)
		return false;

	tmp.id_list[0] = a->id_list[ai];
	gsm0808_enc_cell_id_list2(msg_a, &tmp);

	tmp.id_list[0] = b->id_list[bi];
	gsm0808_enc_cell_id_list2(msg_b, &tmp);

	if (msg_a->len != msg_b->len)
		return false;
	if (memcmp(msg_a->data, msg_b->data, msg_a->len))
		return false;

	return true;
}

/*! Append entries from one Cell Identifier List to another.
 * The cell identifier types must be identical between the two lists.
 * \param dst[out]  Append entries to this list.
 * \param src[in]   Append these entries to \a dst.
 * \returns the nr of items added, or negative on error: -EINVAL if the id_discr mismatch
 *   between the lists, -ENOSPC if the destination list does not have enough space. If an error is
 *   returned, \a dst may have already been changed (particularly on -ENOSPC). Note that a return value
 *   of zero may occur when the src->id_list_len is zero, or when all entries from \a src already exist
 *   in \a dst, and does not indicate error per se. */
int gsm0808_cell_id_list_add(struct gsm0808_cell_id_list2 *dst, const struct gsm0808_cell_id_list2 *src)
{
	int i, j;
	int added = 0;

	if (dst->id_list_len == 0
	    && dst->id_discr != CELL_IDENT_BSS)
		dst->id_discr = src->id_discr;
	else if (dst->id_discr != src->id_discr)
		return -EINVAL;

	for (i = 0; i < src->id_list_len; i++) {
		/* don't add duplicate entries */
		bool skip = false;
		for (j = 0; j < dst->id_list_len; j++) {
			if (same_cell_id_list_entries(dst, j, src, i)) {
				skip = true;
				break;
			}
		}
		if (skip)
			continue;

		if (dst->id_list_len >= ARRAY_SIZE(dst->id_list))
			return -ENOSPC;

		dst->id_list[dst->id_list_len++] = src->id_list[i];
		added ++;
	}

	return added;
}

/*! Convert a single Cell Identifier to a Cell Identifier List with one entry.
 * \param dst[out]  Overwrite this list.
 * \param src[in]   Set \a dst to contain exactly this item.
 */
void gsm0808_cell_id_to_list(struct gsm0808_cell_id_list2 *dst, const struct gsm0808_cell_id *src)
{
	if (!dst)
		return;
	if (!src) {
		*dst = (struct gsm0808_cell_id_list2){
			.id_discr = CELL_IDENT_NO_CELL,
		};
		return;
	}

	*dst = (struct gsm0808_cell_id_list2){
		.id_discr = src->id_discr,
		.id_list = { src->id },
		.id_list_len = 1,
	};

	switch (src->id_discr) {
	case CELL_IDENT_NO_CELL:
	case CELL_IDENT_BSS:
		dst->id_list_len = 0;
		break;
	default:
		break;
	}
}

/*! Encode Cell Identifier IE (3GPP TS 48.008 3.2.2.17).
 *  \param[out] msg Message Buffer to which IE is to be appended
 *  \param[in] ci Cell ID to be encoded
 *  \returns number of bytes appended to \a msg */
uint8_t gsm0808_enc_cell_id(struct msgb *msg, const struct gsm0808_cell_id *ci)
{
	uint8_t rc;
	uint8_t *ie_tag;
	struct gsm0808_cell_id_list2 cil = {
		.id_discr = ci->id_discr,
		.id_list = { ci->id },
		.id_list_len = 1,
	};

	OSMO_ASSERT(msg);
	OSMO_ASSERT(ci);

	ie_tag = msg->tail;
	rc = gsm0808_enc_cell_id_list2(msg, &cil);

	if (rc <= 0)
		return rc;

	*ie_tag = GSM0808_IE_CELL_IDENTIFIER;
	return rc;
}

/*! Decode Cell Identifier IE (3GPP TS 48.008 3.2.2.17).
 *  \param[out] ci Caller-provided memory to store Cell ID.
 *  \param[in] elem IE value to be decoded.
 *  \param[in] len Length of \a elem in bytes.
 *  \returns number of bytes parsed; negative on error */
int gsm0808_dec_cell_id(struct gsm0808_cell_id *ci, const uint8_t *elem, uint8_t len)
{
	struct gsm0808_cell_id_list2 cil;
	int rc;
	rc = gsm0808_dec_cell_id_list2(&cil, elem, len);
	if (rc < 0)
		return rc;
	if (cil.id_discr == CELL_IDENT_BSS || cil.id_discr == CELL_IDENT_NO_CELL) {
		if (cil.id_list_len != 0)
			return -EINVAL;
	} else {
		if (cil.id_list_len != 1)
			return -EINVAL;
	}
	ci->id_discr = cil.id_discr;
	ci->id = cil.id_list[0];
	return rc;
}

/*! Convert the representation of the permitted speech codec identifier
 *  that is used in struct gsm0808_channel_type to the speech codec
 *  representation we use in struct gsm0808_speech_codec.
 *  \param[in] perm_spch to be converted (see also gsm0808_permitted_speech)
 *  \returns GSM speech codec type; negative on error */
int gsm0808_chan_type_to_speech_codec(uint8_t perm_spch)
{
	/*! The speech codec type, which is used in the channel type field to
	 *  signal the permitted speech versions (codecs) has a different
	 *  encoding than the type field in the speech codec type element
	 *  (See also 3GPP TS 48.008, 3.2.2.11 and 3.2.2.103) */

	switch (perm_spch) {
	case GSM0808_PERM_FR1:
		return GSM0808_SCT_FR1;
	case GSM0808_PERM_FR2:
		return GSM0808_SCT_FR2;
	case GSM0808_PERM_FR3:
		return GSM0808_SCT_FR3;
	case GSM0808_PERM_FR4:
		return GSM0808_SCT_FR4;
	case GSM0808_PERM_FR5:
		return GSM0808_SCT_FR5;
	case GSM0808_PERM_HR1:
		return GSM0808_SCT_HR1;
	case GSM0808_PERM_HR3:
		return GSM0808_SCT_HR3;
	case GSM0808_PERM_HR4:
		return GSM0808_SCT_HR4;
	case GSM0808_PERM_HR6:
		return GSM0808_SCT_HR6;
	}

	/* Invalid input */
	return -EINVAL;
}

/*! Extrapolate a speech codec field from a given permitted speech
 *  parameter (channel type).
 *  \param[out] sc Caller provided memory to store the resulting speech codec
 *  \param[in] perm_spch value that is used to derive the speech codec info
 *  (see also: enum gsm0808_speech_codec_type in gsm0808_utils.h)
 *  \returns zero when successful; negative on error */
int gsm0808_speech_codec_from_chan_type(struct gsm0808_speech_codec *sc,
					uint8_t perm_spch)
{
	int rc;

	memset(sc, 0, sizeof(*sc));

	/* Determine codec type */
	rc = gsm0808_chan_type_to_speech_codec(perm_spch);
	if (rc < 0)
		return -EINVAL;
	sc->type = (uint8_t) rc;

	/* Depending on the speech codec type, pick a default codec
	 * configuration that exactly matches the configuration on the
	 * air interface. */
	switch (sc->type) {
	case GSM0808_SCT_FR3:
		sc->cfg = GSM0808_SC_CFG_DEFAULT_FR_AMR;
		break;
	case GSM0808_SCT_FR4:
		sc->cfg = GSM0808_SC_CFG_DEFAULT_OFR_AMR_WB;
		break;
	case GSM0808_SCT_FR5:
		sc->cfg = GSM0808_SC_CFG_DEFAULT_FR_AMR_WB;
		break;
	case GSM0808_SCT_HR3:
		sc->cfg = GSM0808_SC_CFG_DEFAULT_HR_AMR;
		break;
	case GSM0808_SCT_HR4:
		sc->cfg = GSM0808_SC_CFG_DEFAULT_OHR_AMR_WB;
		break;
	case GSM0808_SCT_HR6:
		sc->cfg = GSM0808_SC_CFG_DEFAULT_OHR_AMR;
		break;
	default:
		/* Note: Not all codec types specify a default setting,
		 * in this case, we just set the field to zero. */
		sc->cfg = 0;
	}

	/* Tag all codecs as "Full IP"
	 * (see als 3GPP TS 48.008 3.2.2.103) */
	sc->fi = true;

	return 0;
}

/*! Determine a set of AMR speech codec configuration bits (S0-S15) from a
 *  given GSM 04.08 AMR configuration struct.
 *  \param[in] cfg AMR configuration in GSM 04.08 format.
 *  \param[in] hint if the resulting configuration shall be used with a FR or HR TCH.
 *  \returns configuration bits (S0-S15) */
uint16_t gsm0808_sc_cfg_from_gsm48_mr_cfg(const struct gsm48_multi_rate_conf *cfg,
					  bool fr)
{
	uint16_t s15_s0 = 0;

	/* Check each rate bit in the AMR multirate configuration and pick the
	 * matching default configuration as specified in 3GPP TS 28.062,
	 * Table 7.11.3.1.3-2. */
	if (cfg->m4_75)
		s15_s0 |= GSM0808_SC_CFG_DEFAULT_AMR_4_75;
	if (cfg->m5_15)
		s15_s0 |= GSM0808_SC_CFG_DEFAULT_AMR_5_15;
	if (cfg->m5_90)
		s15_s0 |= GSM0808_SC_CFG_DEFAULT_AMR_5_90;
	if (cfg->m6_70)
		s15_s0 |= GSM0808_SC_CFG_DEFAULT_AMR_6_70;
	if (cfg->m7_40)
		s15_s0 |= GSM0808_SC_CFG_DEFAULT_AMR_7_40;
	if (cfg->m7_95)
		s15_s0 |= GSM0808_SC_CFG_DEFAULT_AMR_7_95;
	if (cfg->m10_2)
		s15_s0 |= GSM0808_SC_CFG_DEFAULT_AMR_10_2;
	if (cfg->m12_2)
		s15_s0 |= GSM0808_SC_CFG_DEFAULT_AMR_12_2;

	/* Note: 3GPP TS 48.008, chapter 3GPP TS 48.008 states that for AMR
	 * some of the configuration bits must be coded as zeros. The applied
	 * bitmask matches the default codec settings. See also the definition
	 * of enum gsm0808_speech_codec_defaults in gsm_08_08.h and
	 * 3GPP TS 28.062, Table 7.11.3.1.3-2. */
	if (fr)
		s15_s0 &= GSM0808_SC_CFG_DEFAULT_FR_AMR;
	else
		s15_s0 &= GSM0808_SC_CFG_DEFAULT_HR_AMR;

	/* The mode that is encoded by S1 (Config-NB-Code = 1), takes a special
	 * role as it does not stand for a single rate, but for up to four rates
	 * at once (12.2, 7.4, 5.9, 4.75). We must check if the supplied cfg
	 * covers this mode. If not, we need to make sure that the related
	 * bit is removed. (See also 3GPP TS 28.062, Table 7.11.3.1.3-2) */
	if (!(cfg->m12_2 && cfg->m7_40 && cfg->m5_90 && cfg->m4_75) && fr)
		s15_s0 &= ~GSM0808_SC_CFG_AMR_4_75_5_90_7_40_12_20;
	else if (!(cfg->m7_40 && cfg->m5_90 && cfg->m4_75))
		s15_s0 &= ~GSM0808_SC_CFG_AMR_4_75_5_90_7_40_12_20;

	return s15_s0;
}

/*! Determine a GSM 04.08 AMR configuration struct from a set of speech codec
 *  configuration bits (S0-S15)
 *  \param[out] cfg AMR configuration in GSM 04.08 format.
 *  \param[in] s15_s0 configuration bits (S15-S0, non-ambiguous).
 *  \returns zero when successful; negative on error */
int gsm48_mr_cfg_from_gsm0808_sc_cfg(struct gsm48_multi_rate_conf *cfg,
				     uint16_t s15_s0)
{
	unsigned int count = 0;

	/* Note: See also: 3GPP TS 28.062
	 * Table 7.11.3.1.3-2: Preferred Configurations for the Adaptive
	 * Multi-Rate Codec Types */

	/* Note: The resulting multirate-configuration must not contain an
	 * active set of more than four codec rates. The active set also
	 * must contain at least one rate. */

	memset(cfg, 0, sizeof(*cfg));
	cfg->ver = 1;
	cfg->icmi = 1;

	/* Strip option bits */
	s15_s0 &= 0x00ff;

	/* Rate 5,15k can never be selected (see table) */
	cfg->m5_15 = 0;

	if (s15_s0 & GSM0808_SC_CFG_AMR_4_75_5_90_7_40_12_20 & 0xff) {
		/* Table Table 7.11.3.1.3-2 lists one mode that selects 4
		 * rates at once (Config-NB-Code = 1). The rates selected
		 * are known to be compatible between GERAN and UTRAN, since
		 * an active set must not contain more than four rates at
		 * a time, we ignore all other settings as they are either
		 * redundaned or excess settings (invalid) */
		cfg->m4_75 = 1;
		cfg->m5_90 = 1;
		cfg->m7_40 = 1;
		cfg->m12_2 = 1;
		count += 4;
	}

	/* Check the bits in s15_s0 and set the flags for the
	 * respective rates. */
	if (s15_s0 & GSM0808_SC_CFG_AMR_4_75 && !cfg->m4_75) {
		if (count >= 4)
			return -EINVAL;
		cfg->m4_75 = 1;
		count++;
	}
	if (s15_s0 & GSM0808_SC_CFG_AMR_5_90 && !cfg->m5_90) {
		if (count >= 4)
			return -EINVAL;
		cfg->m5_90 = 1;
		count++;
	}
	if (s15_s0 & GSM0808_SC_CFG_AMR_6_70) {
		if (count >= 4)
			return -EINVAL;
		cfg->m6_70 = 1;
		count++;
	}
	if (s15_s0 & GSM0808_SC_CFG_AMR_7_40 && !cfg->m7_40) {
		if (count >= 4)
			return -EINVAL;
		cfg->m7_40 = 1;
		count++;
	}
	if (s15_s0 & GSM0808_SC_CFG_AMR_7_95) {
		if (count >= 4)
			return -EINVAL;
		cfg->m7_95 = 1;
		count++;
	}
	if (s15_s0 & GSM0808_SC_CFG_AMR_10_2) {
		if (count >= 4)
			return -EINVAL;
		cfg->m10_2 = 1;
		count++;
	}
	if (s15_s0 & GSM0808_SC_CFG_AMR_12_2 && !cfg->m12_2) {
		if (count >= 4)
			return -EINVAL;
		cfg->m12_2 = 1;
		count++;
	}

	if (count == 0)
		return -EINVAL;

	return 0;
}

int gsm0808_get_cipher_reject_cause(const struct tlv_parsed *tp)
{
	const uint8_t *buf = TLVP_VAL_MINLEN(tp, GSM0808_IE_CAUSE, 1);

	if (!buf)
		return -EBADMSG;

	if (TLVP_LEN(tp, GSM0808_IE_CAUSE) > 1) {
		if (!gsm0808_cause_ext(buf[0]))
			return -EINVAL;
		return buf[1];
	}

	return buf[0];
}

/*! Print a human readable name of the cell identifier to the char buffer.
 * This is useful both for struct gsm0808_cell_id and struct gsm0808_cell_id_list2.
 * See also gsm0808_cell_id_name() and gsm0808_cell_id_list_name().
 * \param[out] buf  Destination buffer to write string representation to.
 * \param[in] buflen  Amount of memory available in \a buf.
 * \param[in] id_discr  Cell Identifier type.
 * \param[in] u  Cell Identifer value.
 * \returns Like snprintf(): the amount of characters (excluding terminating nul) written,
 *          or that would have been written if the buffer were large enough.
 */
int gsm0808_cell_id_u_name(char *buf, size_t buflen,
			   enum CELL_IDENT id_discr, const union gsm0808_cell_id_u *u)
{
	switch (id_discr) {
	case CELL_IDENT_LAC:
		return snprintf(buf, buflen, "%u", u->lac);
	case CELL_IDENT_CI:
		return snprintf(buf, buflen, "%u", u->ci);
	case CELL_IDENT_LAC_AND_CI:
		return snprintf(buf, buflen, "%u-%u", u->lac_and_ci.lac, u->lac_and_ci.ci);
	case CELL_IDENT_LAI_AND_LAC:
		return snprintf(buf, buflen, "%s", osmo_lai_name(&u->lai_and_lac));
	case CELL_IDENT_WHOLE_GLOBAL:
		return snprintf(buf, buflen, "%s", osmo_cgi_name(&u->global));
	default:
		/* For CELL_IDENT_BSS and CELL_IDENT_NO_CELL, just print the discriminator.
		 * Same for kinds we have no string representation of yet. */
		return snprintf(buf, buflen, "%s", gsm0808_cell_id_discr_name(id_discr));
	}
}

/* Store individual Cell Identifier information in a CGI, without clearing the remaining ones.
 * This is useful to supplement one CGI with information from more than one Cell Identifier,
 * which in turn is useful to match Cell Identifiers of differing kinds to each other.
 * Before first invocation, clear the *dst struct externally, this function does only write those members
 * that are present in parameter u.
 */
static void cell_id_to_cgi(struct osmo_cell_global_id *dst,
			   enum CELL_IDENT discr, const union gsm0808_cell_id_u *u)
{
	switch (discr) {
	case CELL_IDENT_WHOLE_GLOBAL:
		*dst = u->global;
		return;

	case CELL_IDENT_LAC_AND_CI:
		dst->lai.lac = u->lac_and_ci.lac;
		dst->cell_identity = u->lac_and_ci.ci;
		return;

	case CELL_IDENT_CI:
		dst->cell_identity = u->ci;
		return;

	case CELL_IDENT_LAI_AND_LAC:
		dst->lai = u->lai_and_lac;
		return;

	case CELL_IDENT_LAC:
		dst->lai.lac = u->lac;
		return;

	case CELL_IDENT_NO_CELL:
	case CELL_IDENT_BSS:
	case CELL_IDENT_UTRAN_PLMN_LAC_RNC:
	case CELL_IDENT_UTRAN_RNC:
	case CELL_IDENT_UTRAN_LAC_RNC:
		/* No values to set. */
		return;
	}
}

/*! Return true if the common information between the two Cell Identifiers match.
 * For example, if a LAC+CI is compared to LAC, return true if the LAC are the same.
 * Note that CELL_IDENT_NO_CELL will always return false.
 * Also CELL_IDENT_BSS will always return false, since this function cannot possibly
 * know the bounds of the BSS, so the caller must handle CELL_IDENT_BSS specially.
 * \param[in] discr1  Cell Identifier type.
 * \param[in] u1  Cell Identifier value.
 * \param[in] discr2  Other Cell Identifier type.
 * \param[in] u2  Other Cell Identifier value.
 * \param[in] exact_match  If true, return true only if the CELL_IDENT types and all values are identical.
 * \returns True if the common fields of the above match.
 */
static bool gsm0808_cell_id_u_match(enum CELL_IDENT discr1, const union gsm0808_cell_id_u *u1,
				    enum CELL_IDENT discr2, const union gsm0808_cell_id_u *u2,
				    bool exact_match)
{
	struct osmo_cell_global_id a = {};
	struct osmo_cell_global_id b = {};

	if (exact_match && discr1 != discr2)
		return false;

	/* First handle the odd wildcard like CELL_IDENT kinds. We can't really match any of these. */
	switch (discr1) {
	case CELL_IDENT_NO_CELL:
	case CELL_IDENT_BSS:
		return discr1 == discr2;
	case CELL_IDENT_UTRAN_PLMN_LAC_RNC:
	case CELL_IDENT_UTRAN_RNC:
	case CELL_IDENT_UTRAN_LAC_RNC:
		return false;
	default:
		break;
	}
	switch (discr2) {
	case CELL_IDENT_NO_CELL:
	case CELL_IDENT_UTRAN_PLMN_LAC_RNC:
	case CELL_IDENT_UTRAN_RNC:
	case CELL_IDENT_UTRAN_LAC_RNC:
	case CELL_IDENT_BSS:
		return false;
	default:
		break;
	}

	/* Enrich both sides to full CGI, then compare those. First set the *other* ID's values in case
	 * they assign more items. For example:
	 * u1 = LAC:42
	 * u2 = LAC+CI:23+5
	 * 1) a <- LAC+CI:23+5
	 * 2) a <- LAC:42 so that a = LAC+CI:42+5
	 * Now we can compare those two and find a mismatch. If the LAC were the same, we would get
	 * identical LAC+CI and hence a match. */

	cell_id_to_cgi(&a, discr2, u2);
	cell_id_to_cgi(&a, discr1, u1);

	cell_id_to_cgi(&b, discr1, u1);
	cell_id_to_cgi(&b, discr2, u2);

	return osmo_cgi_cmp(&a, &b) == 0;
}

/*! Return true if the common information between the two Cell Identifiers match.
 * For example, if a LAC+CI is compared to LAC, return true if the LAC are the same.
 * Note that CELL_IDENT_NO_CELL will always return false.
 * Also CELL_IDENT_BSS will always return false, since this function cannot possibly
 * know the bounds of the BSS, so the caller must handle CELL_IDENT_BSS specially.
 * \param[in] id1  Cell Identifier.
 * \param[in] id2  Other Cell Identifier.
 * \param[in] exact_match  If true, return true only if the CELL_IDENT types and all values are identical.
 * \returns True if the common fields of the above match.
 */
bool gsm0808_cell_ids_match(const struct gsm0808_cell_id *id1, const struct gsm0808_cell_id *id2, bool exact_match)
{
	return gsm0808_cell_id_u_match(id1->id_discr, &id1->id, id2->id_discr, &id2->id, exact_match);
}

/*! Find an index in a Cell Identifier list that matches a given single Cell Identifer.
 * Compare \a id against each entry in \a list using gsm0808_cell_ids_match(), and return the list index
 * if a match is found. \a match_nr allows iterating all matches in the list. A match_nr <= 0 returns the
 * first match in the list, match_nr == 1 the second match, etc., and if match_nr exceeds the available
 * matches in the list, -1 is returned.
 * \param[in] id  Cell Identifier to match.
 * \param[in] list  Cell Identifier list to search in.
 * \param[in] match_nr  Ignore this many matches.
 * \param[in] exact_match  If true, consider as match only if the CELL_IDENT types and all values are identical.
 * \returns -1 if no match is found, list index if a match is found (i.e. rc == 0 means a match was found on the first
 *           entry).
 */
int gsm0808_cell_id_matches_list(const struct gsm0808_cell_id *id, const struct gsm0808_cell_id_list2 *list,
				 unsigned int match_nr, bool exact_match)
{
	int i;
	for (i = 0; i < list->id_list_len; i++) {
		if (gsm0808_cell_id_u_match(id->id_discr, &id->id, list->id_discr, &list->id_list[i], exact_match)) {
			if (match_nr)
				match_nr--;
			else
				return i;
		}
	}
	return -1;
}

/*! Copy information from a CGI to form a Cell Identifier of the specified kind.
 * \param [out] cid  Compose new Cell Identifier here.
 * \param [in] id_discr  Which kind of Cell Identifier to compose.
 * \param [in] cgi  Cell Global Identifier to form the Cell Identifier from.
 */
void gsm0808_cell_id_from_cgi(struct gsm0808_cell_id *cid, enum CELL_IDENT id_discr,
			      const struct osmo_cell_global_id *cgi)
{
	*cid = (struct gsm0808_cell_id){
		.id_discr = id_discr,
	};

	switch (id_discr) {
	case CELL_IDENT_WHOLE_GLOBAL:
		cid->id.global = *cgi;
		return;

	case CELL_IDENT_LAC_AND_CI:
		cid->id.lac_and_ci = (struct osmo_lac_and_ci_id){
			.lac = cgi->lai.lac,
			.ci = cgi->cell_identity,
		};
		return;

	case CELL_IDENT_CI:
		cid->id.ci = cgi->cell_identity;
		return;

	case CELL_IDENT_LAI:
		cid->id.lai_and_lac = cgi->lai;
		return;

	case CELL_IDENT_LAC:
		cid->id.lac = cgi->lai.lac;
		return;

	case CELL_IDENT_NO_CELL:
	case CELL_IDENT_BSS:
	case CELL_IDENT_UTRAN_PLMN_LAC_RNC:
	case CELL_IDENT_UTRAN_RNC:
	case CELL_IDENT_UTRAN_LAC_RNC:
	default:
		return;
	};
}

/*! Overwrite parts of cgi with values from a Cell Identifier.
 * Place only those items given in cid into cgi, leaving other values unchanged.
 * \param[out] cgi  Cell Global Identity to write to.
 * \param[in] cid  Cell Identity to read from.
 * \return a bitmask of items that were set: OSMO_CGI_PART_PLMN | OSMO_CGI_PART_LAC | OSMO_CGI_PART_CI; 0 if nothing was
 *         written to cgi.
 */
int gsm0808_cell_id_to_cgi(struct osmo_cell_global_id *cgi, const struct gsm0808_cell_id *cid)
{
	switch (cid->id_discr) {
	case CELL_IDENT_WHOLE_GLOBAL:
		*cgi = cid->id.global;
		return OSMO_CGI_PART_PLMN | OSMO_CGI_PART_LAC | OSMO_CGI_PART_CI;

	case CELL_IDENT_LAC_AND_CI:
		cgi->lai.lac = cid->id.lac_and_ci.lac;
		cgi->cell_identity = cid->id.lac_and_ci.ci;
		return OSMO_CGI_PART_LAC | OSMO_CGI_PART_CI;

	case CELL_IDENT_CI:
		cgi->cell_identity = cid->id.ci;
		return OSMO_CGI_PART_CI;

	case CELL_IDENT_LAI:
		cgi->lai = cid->id.lai_and_lac;
		return OSMO_CGI_PART_PLMN | OSMO_CGI_PART_LAC;

	case CELL_IDENT_LAC:
		cgi->lai.lac = cid->id.lac;
		return OSMO_CGI_PART_LAC;

	case CELL_IDENT_NO_CELL:
	case CELL_IDENT_BSS:
	case CELL_IDENT_UTRAN_PLMN_LAC_RNC:
	case CELL_IDENT_UTRAN_RNC:
	case CELL_IDENT_UTRAN_LAC_RNC:
	default:
		return 0;
	};
}

/*! value_string[] for enum CELL_IDENT. */
const struct value_string gsm0808_cell_id_discr_names[] = {
	{ CELL_IDENT_WHOLE_GLOBAL, "CGI" },
	{ CELL_IDENT_LAC_AND_CI, "LAC-CI" },
	{ CELL_IDENT_CI, "CI" },
	{ CELL_IDENT_NO_CELL, "NO-CELL" },
	{ CELL_IDENT_LAI_AND_LAC, "LAI" },
	{ CELL_IDENT_LAC, "LAC" },
	{ CELL_IDENT_BSS, "BSS" },
	{ CELL_IDENT_UTRAN_PLMN_LAC_RNC, "UTRAN-PLMN-LAC-RNC" },
	{ CELL_IDENT_UTRAN_RNC, "UTRAN-RNC" },
	{ CELL_IDENT_UTRAN_LAC_RNC, "UTRAN-LAC-RNC" },
	{ 0, NULL }
};

#define APPEND_THING(func, args...) do { \
		int remain = buflen - (pos - buf); \
		int l = func(pos, remain, ##args); \
		if (l < 0 || l > remain) \
			pos = buf + buflen; \
		else \
			pos += l; \
		if (l > 0) \
			total_len += l; \
	} while(0)
#define APPEND_STR(fmt, args...) APPEND_THING(snprintf, fmt, ##args)
#define APPEND_CELL_ID_U(DISCR, U) APPEND_THING(gsm0808_cell_id_u_name, DISCR, U)

char *gsm0808_cell_id_name_buf(char *buf, size_t buflen, const struct gsm0808_cell_id *cid)
{
	char *pos = buf;
	int total_len = 0;
	APPEND_STR("%s:", gsm0808_cell_id_discr_name(cid->id_discr));
	APPEND_CELL_ID_U(cid->id_discr, &cid->id);
	return buf;
}

/*! Return a human readable representation of a Cell Identifier, like "LAC:123"
 * or "CGI:001-01-42-23".
 * \param[in] cid  Cell Identifer.
 * \returns String in a static buffer.
 */
const char *gsm0808_cell_id_name(const struct gsm0808_cell_id *cid)
{
	static char buf[64];
	return gsm0808_cell_id_name_buf(buf, sizeof(buf), cid);
}

/*! Like gsm0808_cell_id_name() but uses a different static buffer.
 * \param[in] cid  Cell Identifer.
 * \returns String in a static buffer.
 */
const char *gsm0808_cell_id_name2(const struct gsm0808_cell_id *cid)
{
	static char buf[64];
	return gsm0808_cell_id_name_buf(buf, sizeof(buf), cid);
}

char *gsm0808_cell_id_name_c(const void *ctx, const struct gsm0808_cell_id *cid)
{
	char *buf = talloc_size(ctx, 64);
	if (!buf)
		return NULL;
	return gsm0808_cell_id_name_buf(buf, 64, cid);
}

/*! Return a human readable representation of the Cell Identifier List, like
 * "LAC[2]:{123, 456}".
 * The return value semantics are like snprintf() and thus allow ensuring a complete
 * untruncated string by determining the required string length from the return value.
 * If buflen > 0, always nul-terminate the string in buf, also when it is truncated.
 * If buflen == 0, do not modify buf, just return the would-be length.
 * \param[out] buf  Destination buffer to write string representation to.
 * \param[in] buflen  Amount of memory available in \a buf.
 * \param[in] cil  Cell Identifer List.
 * \returns Like snprintf(): the amount of characters (excluding terminating nul) written,
 *          or that would have been written if the buffer were large enough.
 */
int gsm0808_cell_id_list_name_buf(char *buf, size_t buflen, const struct gsm0808_cell_id_list2 *cil)
{
	char *pos = buf;
	int total_len = 0;
	int i;

	APPEND_STR("%s[%u]", gsm0808_cell_id_discr_name(cil->id_discr), cil->id_list_len);

	switch (cil->id_discr) {
	case CELL_IDENT_BSS:
	case CELL_IDENT_NO_CELL:
		return total_len;
	default:
		break;
	}

	APPEND_STR(":{");

	for (i = 0; i < cil->id_list_len; i++) {
		if (i)
			APPEND_STR(", ");
		APPEND_CELL_ID_U(cil->id_discr, &cil->id_list[i]);
	}

	APPEND_STR("}");
	return total_len;
}

/*! Return a human-readable representation of \a cil in a static buffer.
 * If the list is too long, the output may be truncated.
 * See also gsm0808_cell_id_list_name_buf(). */
const char *gsm0808_cell_id_list_name(const struct gsm0808_cell_id_list2 *cil)
{
	static char buf[1024];
	gsm0808_cell_id_list_name_buf(buf, sizeof(buf), cil);
	return buf;
}

char *gsm0808_cell_id_list_name_c(const void *ctx, const struct gsm0808_cell_id_list2 *cil)
{
	char *buf = talloc_size(ctx, 1024);
	if (!buf)
		return NULL;
	gsm0808_cell_id_list_name_buf(buf, 1024, cil);
	return buf;
}

#undef APPEND_STR
#undef APPEND_CELL_ID_U

char *gsm0808_channel_type_name_buf(char *buf, size_t buf_len, const struct gsm0808_channel_type *ct)
{
	snprintf(buf, buf_len, "ch_indctr=0x%x ch_rate_type=0x%x perm_spch=%s",
		 ct->ch_indctr, ct->ch_rate_type,
		 osmo_hexdump(ct->perm_spch, ct->perm_spch_len));
	return buf;
}

const char *gsm0808_channel_type_name(const struct gsm0808_channel_type *ct)
{
	static char buf[128];
	return gsm0808_channel_type_name_buf(buf, sizeof(buf), ct);
}

char *gsm0808_channel_type_name_c(const void *ctx, const struct gsm0808_channel_type *ct)
{
	char *buf = talloc_size(ctx, 128);
	if (!buf)
		return NULL;
	return gsm0808_channel_type_name_buf(buf, 128, ct);
}

/*! @} */
