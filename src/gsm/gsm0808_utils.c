/* (C) 2016 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/byteswap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>

#define IP_V4_ADDR_LEN 4
#define IP_V6_ADDR_LEN 16
#define IP_PORT_LEN 2

#define CHANNEL_TYPE_ELEMENT_MAXLEN 11
#define CHANNEL_TYPE_ELEMENT_MINLEN 3
#define ENCRYPT_INFO_ELEMENT_MINLEN 1

/* Encode AoIP transport address element */
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

/* Decode AoIP transport address element */
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
	if (len <= 0)
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

/* Helper function for gsm0808_enc_speech_codec()
 * and gsm0808_enc_speech_codec_list() */
static uint8_t enc_speech_codec(struct msgb *msg,
				const struct gsm0808_speech_codec *sc)
{
	/* See also 3GPP TS 48.008 3.2.2.103 Speech Codec List */
	uint8_t header = 0;
	uint8_t *old_tail;

	old_tail = msg->tail;

	if (sc->fi)
		header |= (1 << 7);
	if (sc->pi)
		header |= (1 << 6);
	if (sc->pt)
		header |= (1 << 5);
	if (sc->tf)
		header |= (1 << 4);
	if (sc->type_extended) {
		header |= 0x0f;
		msgb_put_u8(msg, header);
	} else {
		OSMO_ASSERT(sc->type < 0x0f);
		header |= sc->type;
		msgb_put_u8(msg, header);
		return (uint8_t) (msg->tail - old_tail);
	}

	msgb_put_u8(msg, sc->type);

	if (sc->cfg_present)
		msgb_put_u16(msg, sc->cfg);

	return (uint8_t) (msg->tail - old_tail);
}

/* Encode Speech Codec element */
uint8_t gsm0808_enc_speech_codec(struct msgb *msg,
				 const struct gsm0808_speech_codec *sc)
{
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

/* Decode Speech Codec element */
int gsm0808_dec_speech_codec(struct gsm0808_speech_codec *sc,
			     const uint8_t *elem, uint8_t len)
{
	/* See also 3GPP TS 48.008 3.2.2.103 Speech Codec List */
	uint8_t header;
	const uint8_t *old_elem = elem;

	OSMO_ASSERT(sc);
	if (!elem)
		return -EINVAL;
	if (len <= 0)
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
		return (int)(elem - old_elem);
	}

	sc->type = *elem;
	elem++;
	len--;

	sc->type_extended = true;

	if (len < 2)
		return (int)(elem - old_elem);

	sc->cfg = osmo_load16be(elem);
	elem += 2;
	sc->cfg_present = true;

	return (int)(elem - old_elem);
}

/* Encode Speech Codec list */
uint8_t gsm0808_enc_speech_codec_list(struct msgb *msg,
				      const struct gsm0808_speech_codec_list *scl)
{
	uint8_t *old_tail;
	uint8_t *tlv_len;
	unsigned int i;
	uint8_t rc;
	unsigned int bytes_used = 0;

	OSMO_ASSERT(msg);
	OSMO_ASSERT(scl);

	/* Empty list */
	OSMO_ASSERT(scl->len >= 1);

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

/* Decode Speech Codec list */
int gsm0808_dec_speech_codec_list(struct gsm0808_speech_codec_list *scl,
				  const uint8_t *elem, uint8_t len)
{
	const uint8_t *old_elem = elem;
	unsigned int i;
	int rc;
	uint8_t decoded = 0;

	OSMO_ASSERT(scl);
	if (!elem)
		return -EINVAL;
	if (len <= 0)
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

	/* Empty list */
	if (decoded < 1) {
		return -EINVAL;
	}

	return (int)(elem - old_elem);
}

/* Encode Channel Type element */
uint8_t gsm0808_enc_channel_type(struct msgb *msg,
				 const struct gsm0808_channel_type *ct)
{
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

/* Decode Channel Type element */
int gsm0808_dec_channel_type(struct gsm0808_channel_type *ct,
			     const uint8_t *elem, uint8_t len)
{
	unsigned int i;
	uint8_t byte;
	const uint8_t *old_elem = elem;

	OSMO_ASSERT(ct);
	if (!elem)
		return -EINVAL;
	if (len <= 0)
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

/* Encode Encryption Information element */
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

/* Decode Encryption Information element */
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
	if (len <= 0)
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

/* Encode Cell Identifier List element */
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

/* Decode Cell Identifier List element */
int gsm0808_dec_cell_id_list(struct gsm0808_cell_id_list *cil,
			     const uint8_t *elem, uint8_t len)
{
	uint8_t id_discr;
	const uint8_t *old_elem = elem;
	unsigned int item_count = 0;

	OSMO_ASSERT(cil);
	if (!elem)
		return -EINVAL;
	if (len <= 0)
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
