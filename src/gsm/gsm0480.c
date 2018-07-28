/*! \file gsm0480.c
 * Format functions for GSM 04.80. */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Mike Haben <michael.haben@btinternet.com>
 * (C) 2018 by Harald Welte <laforge@gnumonks.org>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/core/logging.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_04_80.h>

#include <string.h>
#include <errno.h>

const struct value_string gsm0480_comp_type_names[] = {
	{ GSM0480_CTYPE_INVOKE,			"Invoke" },
	{ GSM0480_CTYPE_RETURN_RESULT,		"ReturnResult" },
	{ GSM0480_CTYPE_RETURN_ERROR,		"ReturnError" },
	{ GSM0480_CTYPE_REJECT,			"Reject" },
	{ 0, NULL }
};

const struct value_string gsm0480_op_code_names[] = {
	{ GSM0480_OP_CODE_REGISTER_SS,			"RegisterSS" },
	{ GSM0480_OP_CODE_ERASE_SS,			"EraseSS" },
	{ GSM0480_OP_CODE_ACTIVATE_SS,			"ActivateSS" },
	{ GSM0480_OP_CODE_DEACTIVATE_SS,		"DeactivateSS" },
	{ GSM0480_OP_CODE_INTERROGATE_SS,		"IngerrogateSS" },
	{ GSM0480_OP_CODE_NOTIFY_SS,			"NotifySS" },
	{ GSM0480_OP_CODE_REGISTER_PASSWORD,		"RegisterPassword" },
	{ GSM0480_OP_CODE_GET_PASSWORD,			"GetPassword" },
	{ GSM0480_OP_CODE_PROCESS_USS_DATA,		"ProcessUSSD" },
	{ GSM0480_OP_CODE_FORWARD_CHECK_SS_IND,		"ForwardChecckSSind" },
	{ GSM0480_OP_CODE_PROCESS_USS_REQ,		"ProcessUssReq" },
	{ GSM0480_OP_CODE_USS_REQUEST,			"UssRequest" },
	{ GSM0480_OP_CODE_USS_NOTIFY,			"UssNotify" },
	{ GSM0480_OP_CODE_FORWARD_CUG_INFO,		"ForwardCugInfo" },
	{ GSM0480_OP_CODE_SPLIT_MPTY,			"SplitMPTY" },
	{ GSM0480_OP_CODE_RETRIEVE_MPTY,		"RetrieveMPTY" },
	{ GSM0480_OP_CODE_HOLD_MPTY,			"HoldMPTY" },
	{ GSM0480_OP_CODE_BUILD_MPTY,			"BuildMPTY" },
	{ GSM0480_OP_CODE_FORWARD_CHARGE_ADVICE,	"ForwardChargeAdvice" },
	{ 0, NULL }
};

static inline unsigned char *msgb_wrap_with_TL(struct msgb *msgb, uint8_t tag)
{
	uint8_t *data = msgb_push(msgb, 2);

	data[0] = tag;
	data[1] = msgb->len - 2;
	return data;
}

static inline unsigned char *msgb_push_TLV1(struct msgb *msgb, uint8_t tag,
					    uint8_t value)
{
	uint8_t *data = msgb_push(msgb, 3);

	data[0] = tag;
	data[1] = 1;
	data[2] = value;
	return data;
}

/* wrap an invoke around it... the other way around
 *
 * 1.) Invoke Component tag
 * 2.) Invoke ID Tag
 * 3.) Operation
 * 4.) Data
 */
int gsm0480_wrap_invoke(struct msgb *msg, int op, int link_id)
{
	/* 3. operation */
	msgb_push_TLV1(msg, GSM0480_OPERATION_CODE, op);

	/* 2. invoke id tag */
	msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, link_id);

	/* 1. component tag */
	msgb_wrap_with_TL(msg, GSM0480_CTYPE_INVOKE);

	return 0;
}

/* wrap the GSM 04.08 Facility IE around it */
int gsm0480_wrap_facility(struct msgb *msg)
{
	msgb_wrap_with_TL(msg, GSM0480_IE_FACILITY);

	return 0;
}

struct msgb *gsm0480_create_unstructuredSS_Notify(int alertPattern, const char *text)
{
	struct msgb *msg;
	uint8_t *seq_len_ptr, *ussd_len_ptr, *data;
	int len;

	msg = msgb_alloc_headroom(1024, 128, "GSM 04.80");
	if (!msg)
		return NULL;

	/* SEQUENCE { */
	msgb_put_u8(msg, GSM_0480_SEQUENCE_TAG);
	seq_len_ptr = msgb_put(msg, 1);

	/* DCS { */
	msgb_put_u8(msg, ASN1_OCTET_STRING_TAG);
	msgb_put_u8(msg, 1);
	msgb_put_u8(msg, 0x0F);
	/* } DCS */

	/* USSD-String { */
	msgb_put_u8(msg, ASN1_OCTET_STRING_TAG);
	ussd_len_ptr = msgb_put(msg, 1);
	data = msgb_put(msg, 0);
	gsm_7bit_encode_n_ussd(data, msgb_tailroom(msg), text, &len);
	msgb_put(msg, len);
	ussd_len_ptr[0] = len;
	/* USSD-String } */

	/* alertingPattern { */
	msgb_put_u8(msg, ASN1_OCTET_STRING_TAG);
	msgb_put_u8(msg, 1);
	msgb_put_u8(msg, alertPattern);
	/* } alertingPattern */

	seq_len_ptr[0] = 3 + 2 + ussd_len_ptr[0] + 3;
	/* } SEQUENCE */

	return msg;
}

struct msgb *gsm0480_create_notifySS(const char *text)
{
	struct msgb *msg;
	uint8_t *data, *tmp_len;
	uint8_t *seq_len_ptr, *cal_len_ptr, *opt_len_ptr, *nam_len_ptr;
	int len;

	len = strlen(text);
	if (len < 1 || len > 160)
		return NULL;

	msg = msgb_alloc_headroom(1024, 128, "GSM 04.80");
	if (!msg)
		return NULL;

	msgb_put_u8(msg, GSM_0480_SEQUENCE_TAG);
	seq_len_ptr = msgb_put(msg, 1);

	/* ss_code for CNAP { */
	msgb_put_u8(msg, 0x81);
	msgb_put_u8(msg, 1);
	msgb_put_u8(msg, 0x19);
	/* } ss_code */


	/* nameIndicator { */
	msgb_put_u8(msg, 0xB4);
	nam_len_ptr = msgb_put(msg, 1);

	/* callingName { */
	msgb_put_u8(msg, 0xA0);
	opt_len_ptr = msgb_put(msg, 1);
	msgb_put_u8(msg, 0xA0);
	cal_len_ptr = msgb_put(msg, 1);

	/* namePresentationAllowed { */
	/* add the DCS value */
	msgb_put_u8(msg, 0x80);
	msgb_put_u8(msg, 1);
	msgb_put_u8(msg, 0x0F);

	/* add the lengthInCharacters */
	msgb_put_u8(msg, 0x81);
	msgb_put_u8(msg, 1);
	msgb_put_u8(msg, strlen(text));

	/* add the actual string */
	msgb_put_u8(msg, 0x82);
	tmp_len = msgb_put(msg, 1);
	data = msgb_put(msg, 0);
	gsm_7bit_encode_n_ussd(data, msgb_tailroom(msg), text, &len);
	tmp_len[0] = len;
	msgb_put(msg, len);

	/* }; namePresentationAllowed */

	cal_len_ptr[0] = 3 + 3 + 2 + len;
	opt_len_ptr[0] = cal_len_ptr[0] + 2;
	/* }; callingName */

	nam_len_ptr[0] = opt_len_ptr[0] + 2;
	/* ); nameIndicator */

	/* write the lengths... */
	seq_len_ptr[0] = 3 + nam_len_ptr[0] + 2;

	return msg;
}

/* Forward declarations */
static int parse_ss(const struct gsm48_hdr *hdr,
		    uint16_t len, struct ss_request *req);
static int parse_ss_facility(const uint8_t *ss_facility, uint16_t len,
			     struct ss_request *req);
static int parse_ss_info_elements(const uint8_t *ss_ie, uint16_t len,
				  struct ss_request *req);
static int parse_ss_invoke(const uint8_t *invoke_data, uint16_t length,
					struct ss_request *req);
static int parse_ss_return_result(const uint8_t *rr_data, uint16_t length,
				  struct ss_request *req);
static int parse_process_uss_data(const uint8_t *uss_req_data, uint16_t length,
				  struct ss_request *req);
static int parse_process_uss_req(const uint8_t *uss_req_data, uint16_t length,
					struct ss_request *req);
static int parse_ss_for_bs_req(const uint8_t *ss_req_data,
				     uint16_t length,
				     struct ss_request *req);

/*! Get pointer to the IE of a given type
 * \param[in]  hdr      Pointer to the message starting from header
 * \param[in]  msg_len  Length of the whole message + header
 * \param[out] ie       External pointer to be set
 * \param[out] ie_len   External IE length variable
 * \param[in]  ie_tag   Tag value of the required IE
 * \returns 0 in case of success, otherwise -ERRNO
 *
 * This function iterates over existing IEs within a given
 * message (depending on its type), and looks for the one with
 * given \ref ie_tag value. If the IE is found, the external
 * pointer pointed by \ref ie will be set to its value part
 * (omitting TL), and \ref ie_len will be set to the length.
 * Otherwise, e.g. in case of parsing error, both \ref ie
 * and \ref ie_len are set to NULL and 0 respectively.
 */
int gsm0480_extract_ie_by_tag(const struct gsm48_hdr *hdr, uint16_t msg_len,
			      uint8_t **ie, uint16_t *ie_len, uint8_t ie_tag)
{
	uint8_t pdisc, msg_type;
	uint8_t *tlv, len;

	/* Init external variables */
	*ie_len = 0;
	*ie = NULL;

	/* Drop incomplete / corrupted messages */
	if (msg_len < sizeof(*hdr))
		return -EINVAL;

	pdisc = gsm48_hdr_pdisc(hdr);
	msg_type = gsm48_hdr_msg_type(hdr);

	/* Drop non-SS related messages */
	if (pdisc != GSM48_PDISC_NC_SS)
		return -EINVAL;

	len = msg_len - sizeof(*hdr);
	tlv = (uint8_t *) hdr->data;

	/* Parse a message depending on its type */
	switch (msg_type) {
	/* See table 2.5: RELEASE COMPLETE message content */
	case GSM0480_MTYPE_RELEASE_COMPLETE:
	/* See tables 2.3 and 2.4: REGISTER message content */
	case GSM0480_MTYPE_REGISTER:
		/* Iterate over TLV-based IEs */
		while (len > 2) {
			if (tlv[0] == ie_tag) {
				*ie_len = tlv[1];
				*ie = tlv + 2;
				return 0;
			}

			len -= tlv[1] + 2;
			tlv += tlv[1] + 2;
			continue;
		}

		/* The Facility IE is mandatory for REGISTER */
		if (msg_type == GSM0480_MTYPE_REGISTER)
			if (ie_tag == GSM0480_IE_FACILITY)
				return -EINVAL;
		break;

	/* See table 2.2: FACILITY message content */
	case GSM0480_MTYPE_FACILITY:
		/* There is no other IEs */
		if (ie_tag != GSM0480_IE_FACILITY)
			break;

		/* Mandatory LV-based Facility IE */
		if (len < 2)
			return -EINVAL;

		*ie_len = tlv[0];
		*ie = tlv + 1;
		return 0;

	default:
		/* Wrong message type, out of specs */
		return -EINVAL;
	}

	return 0;
}

/* Decode a mobile-originated USSD-request message */
int gsm0480_decode_ussd_request(const struct gsm48_hdr *hdr, uint16_t len,
				struct ussd_request *req)
{
	struct ss_request ss;
	int rc = 0;

	memset(&ss, 0, sizeof(ss));

	if (len < sizeof(*hdr) + 2) {
		LOGP(0, LOGL_DEBUG, "USSD Request is too short.\n");
		return 0;
	}

	if (gsm48_hdr_pdisc(hdr) == GSM48_PDISC_NC_SS) {
		req->transaction_id = hdr->proto_discr & 0x70;

		ss.transaction_id = req->transaction_id;
		rc = parse_ss(hdr, len - sizeof(*hdr), &ss);

		/* convert from ss_request to legacy ussd_request */
		req->transaction_id = ss.transaction_id;
		req->invoke_id = ss.invoke_id;
		if (ss.ussd_text[0] == 0xFF)
			req->text[0] = '\0';
		else {
			memcpy(req->text, ss.ussd_text, sizeof(req->text));
			req->text[sizeof(req->text)-1] = '\0';
		}
	}

	if (!rc)
		LOGP(0, LOGL_DEBUG, "Error occurred while parsing received USSD!\n");

	return rc;
}

/* Decode a mobile-originated SS request message */
int gsm0480_decode_ss_request(const struct gsm48_hdr *hdr, uint16_t len,
				struct ss_request *req)
{
	uint8_t pdisc;

	/**
	 * Check Protocol Discriminator
	 * see TS GSM 04.07 and GSM 04.80
	 */
	pdisc = gsm48_hdr_pdisc(hdr);
	if (pdisc != GSM48_PDISC_NC_SS) {
		LOGP(0, LOGL_ERROR, "Dropping message with "
			"unsupported pdisc=%02x\n", pdisc);
		return 0;
	}

	/* GSM 04.80 3.3 Transaction Identifier */
	req->transaction_id = hdr->proto_discr & 0x70;

	/* Parse SS request */
	return parse_ss(hdr, len - sizeof(*hdr), req);
}

static int parse_ss(const struct gsm48_hdr *hdr, uint16_t len, struct ss_request *req)
{
	int rc = 1;
	uint8_t msg_type = hdr->msg_type & 0x3F;  /* message-type - section 3.4 */

	/**
	 * GSM 04.80 Section 2.5 'Release complete' Table 2.5
	 * payload is optional for 'RELEASE COMPLETE' message
	 */
	if (msg_type != GSM0480_MTYPE_RELEASE_COMPLETE) {
		if (len < 2) {
			LOGP(0, LOGL_DEBUG, "SS Request is too short.\n");
			return 0;
		}
	}

	/* Table 2.1: Messages for call independent SS control */
	switch (msg_type) {
	case GSM0480_MTYPE_RELEASE_COMPLETE:
		LOGP(0, LOGL_DEBUG, "SS Release Complete\n");

		/**
		 * Indicates that there is no decoded message.
		 * To be overwriten by the message otherwise.
		 */
		req->ussd_text[0] = 0xFF;

		/* Parse optional Cause and/or Facility data */
		if (len >= 2)
			rc &= parse_ss_info_elements(&hdr->data[0], len, req);
		break;
	case GSM0480_MTYPE_REGISTER:
		rc &= parse_ss_info_elements(&hdr->data[0], len, req);
		break;
	case GSM0480_MTYPE_FACILITY:
		rc &= parse_ss_facility(&hdr->data[0], len, req);
		break;
	default:
		LOGP(0, LOGL_DEBUG, "Unknown GSM 04.80 message-type field 0x%02x\n",
			hdr->msg_type);
		rc = 0;
		break;
	}

	return rc;
}

static int parse_ss_facility(const uint8_t *ss_facility, uint16_t len,
			     struct ss_request *req)
{
	uint8_t facility_length;

	facility_length = ss_facility[0];
	if (len - 1 < facility_length)
		return 0;

	return !gsm0480_parse_facility_ie(ss_facility + 1, facility_length, req);
}

static int parse_ss_info_elements(const uint8_t *ss_ie, uint16_t len,
				  struct ss_request *req)
{
	int rc = -1;
	/* Information Element Identifier - table 3.2 & GSM 04.08 section 10.5 */
	uint8_t iei;
	uint8_t iei_length;

	/* We need at least two bytes */
	if (len < 2)
		return 0;

	iei = ss_ie[0];
	iei_length = ss_ie[1];

	/* If the data does not fit, report an error */
	if (iei_length + 2 > len)
		return 0;

	switch (iei) {
	case GSM48_IE_CAUSE:
		break;
	case GSM0480_IE_FACILITY:
		rc = !gsm0480_parse_facility_ie(ss_ie + 2, iei_length, req);
		break;
	case GSM0480_IE_SS_VERSION:
		break;
	default:
		LOGP(0, LOGL_DEBUG, "Unhandled GSM 04.08 or 04.80 IEI 0x%02x\n",
			iei);
		rc = 0;
		break;
	}

	/* A message may contain multiple IEs */
	if (iei_length + 2 + 2 < len)
		rc &= parse_ss_info_elements(ss_ie + iei_length + 2,
			len - iei_length - 2, req);

	return rc;
}

/*! Parse the components of a given Facility IE
 * \param[in]  facility_ie  The Facility IE
 * \param[in]  length       The length of Facility IE
 * \param[out] req          Abstract representation of SS message
 * \return     0 in case of success, otherwise -ERRNO
 */
int gsm0480_parse_facility_ie(const uint8_t *facility_ie, uint16_t length,
			      struct ss_request *req)
{
	uint8_t component_length;
	uint8_t component_type;
	uint8_t offset = 0;
	int rc = 1;

	/* Iterate over components within IE */
	while (offset + 2 <= length) {
		/* Component Type tag - table 3.7 */
		component_type = facility_ie[offset];
		component_length = facility_ie[offset + 1];

		/* Make sure that there is no overflow */
		if (offset + 2 + component_length > length) {
			LOGP(0, LOGL_ERROR, "Component does not fit.\n");
			return -EINVAL;
		}

		switch (component_type) {
		case GSM0480_CTYPE_INVOKE:
			rc &= parse_ss_invoke(facility_ie + 2,
					      component_length,
					      req);
			break;
		case GSM0480_CTYPE_RETURN_RESULT:
			rc &= parse_ss_return_result(facility_ie + 2,
						     component_length,
						     req);
			break;
		case GSM0480_CTYPE_RETURN_ERROR:
			break;
		case GSM0480_CTYPE_REJECT:
			break;
		default:
			LOGP(0, LOGL_DEBUG, "Unknown GSM 04.80 Facility "
				"Component Type 0x%02x\n", component_type);
			rc = 0;
			break;
		}

		offset += (component_length + 2);
	}

	/**
	 * The internal functions are using inverted return
	 * codes, where '0' means error/failure. While a
	 * common approach is to return negative errno in
	 * case of any failure, and '0' if all is ok.
	 */
	return (rc == 0) ? -EINVAL : 0;
}

/* Parse an Invoke component - see table 3.3 */
static int parse_ss_invoke(const uint8_t *invoke_data, uint16_t length,
			   struct ss_request *req)
{
	int rc = 1;
	uint8_t offset;

	if (length < 3)
		return 0;

	/* mandatory part */
	if (invoke_data[0] != GSM0480_COMPIDTAG_INVOKE_ID) {
		LOGP(0, LOGL_DEBUG, "Unexpected GSM 04.80 Component-ID tag "
		     "0x%02x (expecting Invoke ID tag)\n", invoke_data[0]);
	}

	offset = invoke_data[1] + 2;
	req->invoke_id = invoke_data[2];

	/* look ahead once */
	if (offset + 1 > length)
		return 0;

	/* optional part */
	if (invoke_data[offset] == GSM0480_COMPIDTAG_LINKED_ID)
		offset += invoke_data[offset+1] + 2;  /* skip over it */

	/* mandatory part */
	if (invoke_data[offset] == GSM0480_OPERATION_CODE) {
		if (offset + 2 > length)
			return 0;
		uint8_t operation_code = invoke_data[offset+2];
		req->opcode = operation_code;
		switch (operation_code) {
		case GSM0480_OP_CODE_USS_NOTIFY:
		case GSM0480_OP_CODE_USS_REQUEST:
		case GSM0480_OP_CODE_PROCESS_USS_REQ:
			rc = parse_process_uss_req(invoke_data + offset + 3,
						   length - offset - 3,
						   req);
			break;
		case GSM0480_OP_CODE_PROCESS_USS_DATA:
			rc = parse_process_uss_data(invoke_data + offset + 3,
						    length - offset - 3,
						    req);
			break;
		case GSM0480_OP_CODE_ACTIVATE_SS:
		case GSM0480_OP_CODE_DEACTIVATE_SS:
		case GSM0480_OP_CODE_INTERROGATE_SS:
			rc = parse_ss_for_bs_req(invoke_data + offset + 3,
						 length - offset - 3,
						 req);
			break;
		default:
			LOGP(0, LOGL_DEBUG, "GSM 04.80 operation code 0x%02x "
				"is not yet handled\n", operation_code);
			rc = 0;
			break;
		}
	} else {
		LOGP(0, LOGL_DEBUG, "Unexpected GSM 04.80 Component-ID tag 0x%02x "
			"(expecting Operation Code tag)\n",
			invoke_data[0]);
		rc = 0;
	}

	return rc;
}

/* Parse a Return Result component - see table 3.4 */
static int parse_ss_return_result(const uint8_t *rr_data, uint16_t length,
				  struct ss_request *req)
{
	uint8_t operation_code;
	uint8_t offset;

	if (length < 3)
		return 0;

	/* Mandatory part */
	if (rr_data[0] != GSM0480_COMPIDTAG_INVOKE_ID) {
		LOGP(0, LOGL_DEBUG, "Unexpected GSM 04.80 Component-ID tag "
		     "0x%02x (expecting Invoke ID tag)\n", rr_data[0]);
		return 0;
	}

	offset = rr_data[1] + 2;
	req->invoke_id = rr_data[2];

	if (offset >= length)
		return 0;

	if (rr_data[offset] != GSM_0480_SEQUENCE_TAG)
		return 0;

	if (offset + 2 > length)
		return 0;

	offset += 2;
	operation_code = rr_data[offset + 2];
	req->opcode = operation_code;

	switch (operation_code) {
	case GSM0480_OP_CODE_USS_NOTIFY:
	case GSM0480_OP_CODE_USS_REQUEST:
	case GSM0480_OP_CODE_PROCESS_USS_REQ:
		return parse_process_uss_req(rr_data + offset + 3,
			length - offset - 3, req);
	case GSM0480_OP_CODE_PROCESS_USS_DATA:
		return parse_process_uss_data(rr_data + offset + 3,
			length - offset - 3, req);
	default:
		LOGP(0, LOGL_DEBUG, "GSM 04.80 operation code 0x%02x "
			"is not yet handled\n", operation_code);
		return 0;
	}

	return 1;
}

static int parse_process_uss_data(const uint8_t *uss_req_data, uint16_t length,
				  struct ss_request *req)
{
	uint8_t num_chars;

	/* we need at least that much */
	if (length < 3)
		return 0;

	if (uss_req_data[0] != ASN1_IA5_STRING_TAG)
		return 0;

	num_chars = uss_req_data[1];
	if (num_chars > length - 2)
		return 0;

	/* Drop messages with incorrect length */
	if (num_chars > GSM0480_USSD_OCTET_STRING_LEN) {
		LOGP(DLGLOBAL, LOGL_ERROR, "Incorrect USS_DATA data length=%u, "
			"dropping message", num_chars);
		return 0;
	}

	memcpy(req->ussd_text, uss_req_data + 2, num_chars);

	/* Copy the data 'as is' */
	memcpy(req->ussd_data, uss_req_data + 2, num_chars);
	req->ussd_data_len = num_chars;
	req->ussd_data_dcs = 0x00;

	return 1;
}

/* Parse the parameters of a Process UnstructuredSS Request */
static int parse_process_uss_req(const uint8_t *uss_req_data, uint16_t length,
				 struct ss_request *req)
{
	uint8_t num_chars;
	uint8_t dcs;

	/* we need at least that much */
	if (length < 8)
		return 0;

	if (uss_req_data[0] != GSM_0480_SEQUENCE_TAG)
		return 0;

	/* Both 2th and 5th should be equal to ASN1_OCTET_STRING_TAG */
	if ((uss_req_data[2] & uss_req_data[5]) != ASN1_OCTET_STRING_TAG)
		return 0;

	/* Get DCS (Data Coding Scheme) */
	dcs = uss_req_data[4];
	/* Get the amount of bytes */
	num_chars = uss_req_data[6];

	/* Drop messages with incorrect length */
	if (num_chars > GSM0480_USSD_OCTET_STRING_LEN) {
		LOGP(DLGLOBAL, LOGL_ERROR, "Incorrect USS_REQ data length=%u, "
			"dropping message", num_chars);
		return 0;
	}

	/* Copy the data 'as is' */
	memcpy(req->ussd_data, uss_req_data + 7, num_chars);
	req->ussd_data_len = num_chars;
	req->ussd_data_dcs = dcs;

	/**
	 * According to GSM 04.08, 4.4.2 "ASN.1 data types":
	 * the USSD-DataCodingScheme shall indicate use of
	 * the default alphabet using the 0x0F value.
	 */
	if (dcs == 0x0F) {
		/* Calculate the amount of 7-bit characters */
		num_chars = (num_chars * 8) / 7;

		gsm_7bit_decode_n_ussd((char *)req->ussd_text,
			sizeof(req->ussd_text), &(uss_req_data[7]), num_chars);

		return 1;
	} else {
		memcpy(req->ussd_text, &(uss_req_data[7]), num_chars);
		return 1;
	}

	return 0;
}

/* Parse the parameters of a Interrogate/Activate/DeactivateSS Request */
static int parse_ss_for_bs_req(const uint8_t *ss_req_data,
			       uint16_t length,
			       struct ss_request *req)
{
	int rc = 0;


	/* we need at least that much */
	if (length < 5)
		return 0;


	if (ss_req_data[0] == GSM_0480_SEQUENCE_TAG) {
		if ((ss_req_data[2] == ASN1_OCTET_STRING_TAG) &&
			ss_req_data[3] == 1) {
			req->ss_code = ss_req_data[4];

			rc = 1;
		}
	}
	return rc;
}

struct msgb *gsm0480_msgb_alloc_name(const char *name)
{
	return msgb_alloc_headroom(1024, 128, name);
}

/*! Generate a USSD ReturnResult component containing a string in default GSM alphabet.
 * \param[in] invoke_id		InvokeID of the request to which we respond
 * \param[in] text		USSD text in ASCII; to be encoded as GSM 7-but alphabet
 */
struct msgb *gsm0480_gen_ussd_resp_7bit(uint8_t invoke_id, const char *text)
{
	struct msgb *msg;
	uint8_t *ptr8;
	int response_len;

	msg = gsm0480_msgb_alloc_name("TS 04.80 USSD Resp");
	if (!msg)
		return NULL;

	/* First put the payload text into the message */
	ptr8 = msgb_put(msg, 0);
	gsm_7bit_encode_n_ussd(ptr8, msgb_tailroom(msg), text, &response_len);
	msgb_put(msg, response_len);

	/* Then wrap it as an Octet String */
	msgb_wrap_with_TL(msg, ASN1_OCTET_STRING_TAG);

	/* Pre-pend the DCS octet string */
	msgb_push_TLV1(msg, ASN1_OCTET_STRING_TAG, 0x0F);

	/* Then wrap these as a Sequence */
	msgb_wrap_with_TL(msg, GSM_0480_SEQUENCE_TAG);

	/* Pre-pend the operation code */
	msgb_push_TLV1(msg, GSM0480_OPERATION_CODE,
			GSM0480_OP_CODE_PROCESS_USS_REQ);

	/* Wrap the operation code and IA5 string as a sequence */
	msgb_wrap_with_TL(msg, GSM_0480_SEQUENCE_TAG);

	/* Pre-pend the invoke ID */
	msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, invoke_id);

	/* Wrap this up as a Return Result component */
	msgb_wrap_with_TL(msg, GSM0480_CTYPE_RETURN_RESULT);

	return msg;
}

/*! Legacy helper: Generate USSD response including FACILITY IE + L3 header.
 *
 * This function is just like \ref gsm0480_gen_ussd_resp_7bit, but it generates
 * not only the FACILITY value, but the full L3 message including message header
 * and FACILITY IE Tag+Length.
 */
struct msgb *gsm0480_create_ussd_resp(uint8_t invoke_id, uint8_t trans_id, const char *text)
{
	struct msgb *msg;

	msg = gsm0480_gen_ussd_resp_7bit(invoke_id, text);
	if (!msg)
		return NULL;

	/* Wrap the component in a Facility message */
	msgb_wrap_with_TL(msg, GSM0480_IE_FACILITY);

	/* And finally pre-pend the L3 header */
	gsm0480_l3hdr_push(msg,
			   GSM48_PDISC_NC_SS | trans_id
			   | (1<<7) /* TI direction = 1 */,
			   GSM0480_MTYPE_RELEASE_COMPLETE);
	return msg;
}

struct gsm48_hdr *gsm0480_l3hdr_push(struct msgb *msg, uint8_t proto_discr,
				     uint8_t msg_type)
{
	struct gsm48_hdr *gh;
	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr = proto_discr;
	gh->msg_type = msg_type;
	return gh;
}

struct msgb *gsm0480_create_ussd_notify(int level, const char *text)
{
	struct msgb *msg;

	msg = gsm0480_create_unstructuredSS_Notify(level, text);
	if (!msg)
		return NULL;

	gsm0480_wrap_invoke(msg, GSM0480_OP_CODE_USS_NOTIFY, 0);
	gsm0480_wrap_facility(msg);

	gsm0480_l3hdr_push(msg, GSM48_PDISC_NC_SS, GSM0480_MTYPE_REGISTER);
	return msg;
}

struct msgb *gsm0480_create_ussd_release_complete(void)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(1024, 128, "GSM 04.80 USSD REL COMPL");
	if (!msg)
		return NULL;

	/* FIXME: should this set trans_id and TI direction flag? */
	gsm0480_l3hdr_push(msg, GSM48_PDISC_NC_SS,
			   GSM0480_MTYPE_RELEASE_COMPLETE);
	return msg;
}
