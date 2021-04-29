/*! \file ipa.c
 * OpenBSC Abis input driver for ip.access */
/*
 * (C) 2009-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by Holger Hans Peter Freyther
 * (C) 2010 by On-Waves
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"

#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>

#include <sys/types.h>

#include <osmocom/core/byteswap.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/macaddr.h>
#include <osmocom/core/select.h>

#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/gsm/ipa.h>

/*! \addtogroup ipa
 *  @{
 *  IPA Multiplex utility routines
 */

#define IPA_ALLOC_SIZE 1200

/*
 * Common propietary IPA messages:
 *      - PONG: in reply to PING.
 *      - ID_REQUEST: first messages once OML has been established.
 *      - ID_ACK: in reply to ID_ACK.
 */
static const uint8_t ipa_pong_msg[] = {
	0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_PONG
};

static const uint8_t ipa_id_ack_msg[] = {
	0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_ACK
};

static const uint8_t ipa_id_req_msg[] = {
	0, 17, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_GET,
	0x01, IPAC_IDTAG_UNIT,
	0x01, IPAC_IDTAG_MACADDR,
	0x01, IPAC_IDTAG_LOCATION1,
	0x01, IPAC_IDTAG_LOCATION2,
	0x01, IPAC_IDTAG_EQUIPVERS,
	0x01, IPAC_IDTAG_SWVERSION,
	0x01, IPAC_IDTAG_UNITNAME,
	0x01, IPAC_IDTAG_SERNR,
};


static const char *idtag_names[] = {
	[IPAC_IDTAG_SERNR]	= "Serial_Number",
	[IPAC_IDTAG_UNITNAME]	= "Unit_Name",
	[IPAC_IDTAG_LOCATION1]	= "Location_1",
	[IPAC_IDTAG_LOCATION2]	= "Location_2",
	[IPAC_IDTAG_EQUIPVERS]	= "Equipment_Version",
	[IPAC_IDTAG_SWVERSION]	= "Software_Version",
	[IPAC_IDTAG_IPADDR]	= "IP_Address",
	[IPAC_IDTAG_MACADDR]	= "MAC_Address",
	[IPAC_IDTAG_UNIT]	= "Unit_ID",
};

const char *ipa_ccm_idtag_name(uint8_t tag)
{
	if (tag >= ARRAY_SIZE(idtag_names))
		return "unknown";

	return idtag_names[tag];
}

/*! Parse the payload part of an IPA CCM ID GET, return \ref tlv_parsed format. */
int ipa_ccm_idtag_parse(struct tlv_parsed *dec, unsigned char *buf, int len)
{
	return ipa_ccm_idtag_parse_off(dec, buf, len, 1);
}

/*! Parse the payload part of an IPA CCM ID GET, return \ref tlv_parsed format.
 *	WARNING: This function can only parse correctly IPA CCM ID GET/REQUEST
 *	messages, and only when len_offset is passed value of 1.
 *  \param[out] dec Caller-provided/allocated output structure for parsed payload
 *  \param[in] buf Buffer containing the payload (excluding 1 byte msg_type) of the message
 *  \param[in] len Length of \a buf in octets
 *  \param[in] len_offset Offset from end of len field to start of value (ommiting tag). Must be 1!
 *  \returns 0 on success; negative on error
 */
int ipa_ccm_idtag_parse_off(struct tlv_parsed *dec, unsigned char *buf, int len, const int len_offset)
{
	uint8_t t_len;
	uint8_t t_tag;
	uint8_t *cur = buf;

	memset(dec, 0, sizeof(*dec));

	LOGP(DLMI, LOGL_DEBUG, "Rx IPA CCM ID_GET: ");
	while (len >= 2) {
		len -= 2;
		t_len = *cur++;
		t_tag = *cur++;

		if (t_len < len_offset) {
			LOGPC(DLMI, LOGL_DEBUG, "\n");
			LOGP(DLMI, LOGL_ERROR, "minimal offset not included: %d < %d\n", t_len, len_offset);
			return -EINVAL;
		}

		if (t_len > len + 1) {
			LOGPC(DLMI, LOGL_DEBUG, "\n");
			LOGP(DLMI, LOGL_ERROR, "The tag does not fit: %d > %d\n", t_len, len + 1);
			return -EINVAL;
		}

		LOGPC(DLMI, LOGL_DEBUG, "%s='%s' ", ipa_ccm_idtag_name(t_tag), cur);

		dec->lv[t_tag].len = t_len - len_offset;
		dec->lv[t_tag].val = cur;

		cur += t_len - len_offset;
		len -= t_len - len_offset;
	}
	LOGPC(DLMI, LOGL_DEBUG, "\n");
	return 0;
}

/*! Parse the payload part of an IPA CCM ID GET, return \ref tlv_parsed format.
 *  The odd payload format of those messages is structured as follows:
 *   * 8bit length value (length of payload *and tag*)
 *   * 8bit tag value
 *   * optional, variable-length payload
 *  \param[out] dec Caller-provided/allocated output structure for parsed payload
 *  \param[in] buf Buffer containing the payload (excluding 1 byte msg_type) of the message
 *  \param[in] len Length of \a buf in octets
 *  \returns 0 on success; negative on error */
int ipa_ccm_id_get_parse(struct tlv_parsed *dec, const uint8_t *buf, unsigned int len)
{
	uint8_t t_len;
	uint8_t t_tag;
	const uint8_t *cur = buf;

	memset(dec, 0, sizeof(*dec));

	LOGP(DLMI, LOGL_DEBUG, "Rx IPA CCM ID_GET: ");
	while (len >= 2) {
		len -= 2;
		t_len = *cur++;
		t_tag = *cur++;

		if (t_len > len + 1) {
			LOGPC(DLMI, LOGL_DEBUG, "\n");
			LOGP(DLMI, LOGL_ERROR, "The tag does not fit: %d > %d\n", t_len, len + 1);
			return -EINVAL;
		}

		LOGPC(DLMI, LOGL_DEBUG, "%s='%s' ", ipa_ccm_idtag_name(t_tag), cur);

		dec->lv[t_tag].len = t_len-1;
		dec->lv[t_tag].val = cur;

		cur += t_len-1;
		len -= t_len-1;
	}
	LOGPC(DLMI, LOGL_DEBUG, "\n");
	return 0;
}

/*! Parse the payload part of an IPA CCM ID RESP, return \ref tlv_parsed format.
 *  The odd payload format of those messages is structured as follows:
 *   * 16bit length value (length of payload *and tag*)
 *   * 8bit tag value
 *   * optional, variable-length payload
 *  \param[out] dec Caller-provided/allocated output structure for parsed payload
 *  \param[in] buf Buffer containing the payload (excluding 1 byte msg_type) of the message
 *  \param[in] len Length of \a buf in octets
 *  \returns 0 on success; negative on error */
int ipa_ccm_id_resp_parse(struct tlv_parsed *dec, const uint8_t *buf, unsigned int len)
{
	uint8_t t_len;
	uint8_t t_tag;
	const uint8_t *cur = buf;

	memset(dec, 0, sizeof(*dec));

	LOGP(DLMI, LOGL_DEBUG, "Rx IPA CCM ID_RESP: ");
	while (len >= 3) {
		len -= 3;
		t_len = osmo_load16be(cur);
		cur += 2;
		t_tag = *cur++;

		if (t_len > len + 1) {
			LOGPC(DLMI, LOGL_DEBUG, "\n");
			LOGP(DLMI, LOGL_ERROR, "The tag does not fit: %d > %d\n", t_len, len + 1);
			return -EINVAL;
		}

		DEBUGPC(DLMI, "%s='%s' ", ipa_ccm_idtag_name(t_tag), cur);

		dec->lv[t_tag].len = t_len-1;
		dec->lv[t_tag].val = cur;

		cur += t_len-1;
		len -= t_len-1;
	}
	LOGPC(DLMI, LOGL_DEBUG, "\n");
	return 0;
}

int ipa_parse_unitid(const char *str, struct ipaccess_unit *unit_data)
{
	unsigned long ul;
	char *endptr;
	const char *nptr;

	nptr = str;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->site_id = ul & 0xffff;

	if (*endptr++ != '/')
		return -EINVAL;

	nptr = endptr;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->bts_id = ul & 0xffff;

	if (*endptr++ != '/')
		return -EINVAL;

	nptr = endptr;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->trx_id = ul & 0xffff;

	return 0;
}

int ipa_ccm_tlv_to_unitdata(struct ipaccess_unit *ud,
			     const struct tlv_parsed *tp)
{
	int rc = 0;

	if (TLVP_PRES_LEN(tp, IPAC_IDTAG_SERNR, 1))
		ud->serno = talloc_strdup(ud, (char *)
					TLVP_VAL(tp, IPAC_IDTAG_SERNR));

	if (TLVP_PRES_LEN(tp, IPAC_IDTAG_UNITNAME, 1))
		ud->unit_name = talloc_strdup(ud, (char *)
					TLVP_VAL(tp, IPAC_IDTAG_UNITNAME));

	if (TLVP_PRES_LEN(tp, IPAC_IDTAG_LOCATION1, 1))
		ud->location1 = talloc_strdup(ud, (char *)
					TLVP_VAL(tp, IPAC_IDTAG_LOCATION1));

	if (TLVP_PRES_LEN(tp, IPAC_IDTAG_LOCATION2, 1))
		ud->location2 = talloc_strdup(ud, (char *)
					TLVP_VAL(tp, IPAC_IDTAG_LOCATION2));

	if (TLVP_PRES_LEN(tp, IPAC_IDTAG_EQUIPVERS, 1))
		ud->equipvers = talloc_strdup(ud, (char *)
					TLVP_VAL(tp, IPAC_IDTAG_EQUIPVERS));

	if (TLVP_PRES_LEN(tp, IPAC_IDTAG_SWVERSION, 1))
		ud->swversion = talloc_strdup(ud, (char *)
					TLVP_VAL(tp, IPAC_IDTAG_SWVERSION));

	if (TLVP_PRES_LEN(tp, IPAC_IDTAG_MACADDR, 17)) {
		rc = osmo_macaddr_parse(ud->mac_addr, (char *)
					TLVP_VAL(tp, IPAC_IDTAG_MACADDR));
		if (rc < 0)
			goto out;
	}

	if (TLVP_PRES_LEN(tp, IPAC_IDTAG_UNIT, 1))
		rc = ipa_parse_unitid((char *)
					TLVP_VAL(tp, IPAC_IDTAG_UNIT), ud);

out:
	return rc;
}

#define IPA_STRING_MAX 64

/*! Generate IPA CCM ID RESP based on list of IEs
 *  \param[in] dev Descriptor describing identity data for response
 *  \param[in] ies_req List of IEIs to include in response
 *  \param[in] num_ies_req Number of IEIs in \a ies_req
 *  \returns Message buffer with IPA CCM ID RESP */
struct msgb *ipa_ccm_make_id_resp(const struct ipaccess_unit *dev,
				  const uint8_t *ies_req, unsigned int num_ies_req)
{
	struct msgb *msg = ipa_msg_alloc(16);
	char str[IPA_STRING_MAX];
	unsigned int i;

	if (!msg)
		return NULL;

	*msgb_put(msg, 1) = IPAC_MSGT_ID_RESP;

	for (i = 0; i < num_ies_req; i++) {
		uint8_t *tag;

		str[0] = '\0';
		switch (ies_req[i]) {
		case IPAC_IDTAG_UNIT:
			snprintf(str, sizeof(str), "%u/%u/%u",
				dev->site_id, dev->bts_id, dev->trx_id);
			break;
		case IPAC_IDTAG_MACADDR:
			snprintf(str, sizeof(str),
				 "%02x:%02x:%02x:%02x:%02x:%02x",
				 dev->mac_addr[0], dev->mac_addr[1],
				 dev->mac_addr[2], dev->mac_addr[3],
				 dev->mac_addr[4], dev->mac_addr[5]);
			break;
		case IPAC_IDTAG_LOCATION1:
			if (dev->location1)
				osmo_strlcpy(str, dev->location1, sizeof(str));
			break;
		case IPAC_IDTAG_LOCATION2:
			if (dev->location2)
				osmo_strlcpy(str, dev->location2, sizeof(str));
			break;
		case IPAC_IDTAG_EQUIPVERS:
			if (dev->equipvers)
				osmo_strlcpy(str, dev->equipvers, sizeof(str));
			break;
		case IPAC_IDTAG_SWVERSION:
			if (dev->swversion)
				osmo_strlcpy(str, dev->swversion, sizeof(str));
			break;
		case IPAC_IDTAG_UNITNAME:
			if (dev->unit_name) {
				snprintf(str, sizeof(str), "%s", dev->unit_name);
			} else {
				snprintf(str, sizeof(str),
					 "%02x-%02x-%02x-%02x-%02x-%02x",
					 dev->mac_addr[0], dev->mac_addr[1],
					 dev->mac_addr[2], dev->mac_addr[3],
					 dev->mac_addr[4], dev->mac_addr[5]);
			}
			break;
		case IPAC_IDTAG_SERNR:
			if (dev->serno)
				osmo_strlcpy(str, dev->serno, sizeof(str));
			break;
		default:
			LOGP(DLINP, LOGL_NOTICE,
				"Unknown ipaccess tag 0x%02x\n", ies_req[i]);
			msgb_free(msg);
			return NULL;
		}

		LOGP(DLINP, LOGL_INFO, " tag %d: %s\n", ies_req[i], str);
		tag = msgb_put(msg, 3 + strlen(str) + 1);
		tag[0] = 0x00;
		tag[1] = 1 + strlen(str) + 1;
		tag[2] = ies_req[i];
		memcpy(tag + 3, str, strlen(str) + 1);
	}
	ipa_prepend_header(msg, IPAC_PROTO_IPACCESS);
	return msg;
}

/*! Generate IPA CCM ID RESP based on requets payload
 *  \param[in] dev Descriptor describing identity data for response
 *  \param[in] data Payload of the IPA CCM ID GET request
 *  \param[in] len Length of \a data in octets
 *  \returns Message buffer with IPA CCM ID RESP */
struct msgb *ipa_ccm_make_id_resp_from_req(const struct ipaccess_unit *dev,
					   const uint8_t *data, unsigned int len)
{
	uint8_t ies[len/2];
	unsigned int num_ies = 0;
	const uint8_t *cur = data;

	memset(ies, 0, sizeof(ies));

	/* build a array of the IEIs */
	while (len >= 2) {
		uint8_t t_len, t_tag;
		len -= 2; /* subtract the length of the two bytes read below */
		t_len = *cur++;
		t_tag = *cur++;

		/* as the 'tag' is included in the length of t_len, this cannot happen */
		if (t_len == 0)
			break;

		if (t_len > len + 1) {
			LOGP(DLINP, LOGL_ERROR, "IPA CCM tag 0x%02x does not fit\n", t_tag);
			break;
		}

		ies[num_ies++] = t_tag;

		/* we need to subtract one from t_len to account for the tag */
		cur += t_len - 1;
		/* prevent any unsigned integer underflow due to somebody sending us
		 * messages with wrong length values */
		if (len <= t_len)
			len = 0;
		else
			len -= t_len - 1;
	}
	return ipa_ccm_make_id_resp(dev, ies, num_ies);
}

int ipa_send(int fd, const void *msg, size_t msglen)
{
	int ret;

	ret = write(fd, msg, msglen);
	if (ret < 0)
		return -errno;
	if (ret < msglen) {
		LOGP(DLINP, LOGL_ERROR, "ipa_send: short write\n");
		return -EIO;
	}
	return ret;
}

int ipa_ccm_send_pong(int fd)
{
	return ipa_send(fd, ipa_pong_msg, sizeof(ipa_pong_msg));
}

int ipa_ccm_send_id_ack(int fd)
{
	return ipa_send(fd, ipa_id_ack_msg, sizeof(ipa_id_ack_msg));
}

int ipa_ccm_send_id_req(int fd)
{
	return ipa_send(fd, ipa_id_req_msg, sizeof(ipa_id_req_msg));
}

/* base handling of the ip.access protocol */
int ipa_ccm_rcvmsg_base(struct msgb *msg, struct osmo_fd *bfd)
{
	uint8_t msg_type = *(msg->l2h);
	int ret;

	switch (msg_type) {
	case IPAC_MSGT_PING:
		ret = ipa_ccm_send_pong(bfd->fd);
		if (ret < 0) {
			LOGP(DLINP, LOGL_ERROR, "Cannot send PING "
			     "message. Reason: %s\n", strerror(errno));
			break;
		}
		ret = 1;
		break;
	case IPAC_MSGT_PONG:
		DEBUGP(DLMI, "PONG!\n");
		ret = 1;
		break;
	case IPAC_MSGT_ID_ACK:
		DEBUGP(DLMI, "ID_ACK? -> ACK!\n");
		ret = ipa_ccm_send_id_ack(bfd->fd);
		if (ret < 0) {
			LOGP(DLINP, LOGL_ERROR, "Cannot send ID_ACK "
			     "message. Reason: %s\n", strerror(errno));
			break;
		}
		ret = 1;
		break;
	default:
		/* This is not an IPA PING, PONG or ID_ACK message */
		ret = 0;
		break;
	}
	return ret;
}

/* base handling of the ip.access protocol */
int ipa_ccm_rcvmsg_bts_base(struct msgb *msg, struct osmo_fd *bfd)
{
	uint8_t msg_type = *(msg->l2h);
	int ret = 0;

	switch (msg_type) {
	case IPAC_MSGT_PING:
		ret = ipa_ccm_send_pong(bfd->fd);
		if (ret < 0) {
			LOGP(DLINP, LOGL_ERROR, "Cannot send PONG "
			     "message. Reason: %s\n", strerror(errno));
		}
		break;
	case IPAC_MSGT_PONG:
		DEBUGP(DLMI, "PONG!\n");
		break;
	case IPAC_MSGT_ID_ACK:
		DEBUGP(DLMI, "ID_ACK\n");
		break;
	}
	return ret;
}


void ipa_prepend_header_ext(struct msgb *msg, int proto)
{
	struct ipaccess_head_ext *hh_ext;

	/* prepend the osmo ip.access header extension */
	hh_ext = (struct ipaccess_head_ext *) msgb_push(msg, sizeof(*hh_ext));
	hh_ext->proto = proto;
}

void ipa_prepend_header(struct msgb *msg, int proto)
{
	struct ipaccess_head *hh;

	/* prepend the ip.access header */
	hh = (struct ipaccess_head *) msgb_push(msg, sizeof(*hh));
	hh->len = osmo_htons(msg->len - sizeof(*hh));
	hh->proto = proto;
}

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>

/*! Read one ipa message from socket fd without caching not fully received
 * messages. See \ref ipa_msg_recv_buffered for further information.
 */
int ipa_msg_recv(int fd, struct msgb **rmsg)
{
	int rc = ipa_msg_recv_buffered(fd, rmsg, NULL);
	if (rc < 0) {
		errno = -rc;
		rc = -1;
	}
	return rc;
}

/*! Read one ipa message from socket fd or store part if still not fully received.
 *  \param[in] fd The fd for the socket to read from.
 *  \param[out] rmsg internally allocated msgb containing a fully received ipa message.
 *  \param[inout] tmp_msg internally allocated msgb caching data for not yet fully received message.
 *
 *  As ipa can run on top of stream based protocols such as TCP, there's the
 *  possibility that such lower layers split ipa messages in several low level
 *  packets. If a low layer packet is received containing several ipa frames,
 *  this function will pull from the socket and return only the first one
 *  available in the stream. As the socket will remain with data, it will
 *  trigger again during next select() and then this function will fetch the
 *  next ipa message, and so on.
 *
 *  \returns -EAGAIN and allocated tmp_msg if message was not yet fully
 *  received. Other negative values indicate an error and cached msgb will be
 *  freed. 0 if socket is found dead. Positive value indicating l2 msgb len and
 *  rmsg pointing to internally allocated msgb containing the ipa frame on
 *  scucess.
 */
int ipa_msg_recv_buffered(int fd, struct msgb **rmsg, struct msgb **tmp_msg)
{
	struct msgb *msg = tmp_msg ? *tmp_msg : NULL;
	struct ipaccess_head *hh;
	int len, ret;
	int needed;

	if (msg == NULL) {
		msg = ipa_msg_alloc(0);
		if (msg == NULL) {
			ret = -ENOMEM;
			goto discard_msg;
		}
		msg->l1h = msg->tail;
	}

	if (msg->l2h == NULL) {
		/* first read our 3-byte header */
		needed = sizeof(*hh) - msg->len;
		ret = recv(fd, msg->tail, needed, 0);
		if (ret == 0)
		       goto discard_msg;

		if (ret < 0) {
			if (errno == EAGAIN || errno == EINTR)
				ret = 0;
			else {
				ret = -errno;
				goto discard_msg;
			}
		}

		msgb_put(msg, ret);

		if (ret < needed) {
			if (msg->len == 0) {
				ret = -EAGAIN;
				goto discard_msg;
			}

			LOGP(DLINP, LOGL_INFO,
			     "Received part of IPA message header (%d/%zu)\n",
			     msg->len, sizeof(*hh));
			if (!tmp_msg) {
				ret = -EIO;
				goto discard_msg;
			}
			*tmp_msg = msg;
			return -EAGAIN;
		}

		msg->l2h = msg->tail;
	}

	hh = (struct ipaccess_head *) msg->data;

	/* then read the length as specified in header */
	len = osmo_ntohs(hh->len);

	if (len < 0 || IPA_ALLOC_SIZE < len + sizeof(*hh)) {
		LOGP(DLINP, LOGL_ERROR, "bad message length of %d bytes, "
					"received %d bytes\n", len, msg->len);
		ret = -EIO;
		goto discard_msg;
	}

	needed = len - msgb_l2len(msg);

	if (needed > 0) {
		ret = recv(fd, msg->tail, needed, 0);

		if (ret == 0)
			goto discard_msg;

		if (ret < 0) {
			if (errno == EAGAIN || errno == EINTR)
				ret = 0;
			else {
				ret = -errno;
				goto discard_msg;
			}
		}

		msgb_put(msg, ret);

		if (ret < needed) {
			LOGP(DLINP, LOGL_INFO,
			     "Received part of IPA message L2 data (%d/%d)\n",
			    msgb_l2len(msg), len);
			if (!tmp_msg) {
				ret = -EIO;
				goto discard_msg;
			}
			*tmp_msg = msg;
			return -EAGAIN;
		}
	}

	ret = msgb_l2len(msg);

	if (ret == 0) {
		LOGP(DLINP, LOGL_INFO,
		     "Discarding IPA message without payload\n");
		ret = -EAGAIN;
		goto discard_msg;
	}

	if (tmp_msg)
		*tmp_msg = NULL;
	*rmsg = msg;
	return ret;

discard_msg:
	if (tmp_msg)
		*tmp_msg = NULL;
	msgb_free(msg);
	return ret;
}

#endif /* SYS_SOCKET_H */

struct msgb *ipa_msg_alloc(int headroom)
{
	struct msgb *nmsg;

	headroom += sizeof(struct ipaccess_head);

	nmsg = msgb_alloc_headroom(1200 + headroom, headroom, "IPA Multiplex");
	if (!nmsg)
		return NULL;
	return nmsg;
}

/*! @} */
