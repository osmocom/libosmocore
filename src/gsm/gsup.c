/*
 * (C) 2014 by sysmocom - s.f.m.c. GmbH
 * Author: Jacob Erlbeck
 * (C) 2015 by Holger Hans Peter Freyther
 * (C) 2016 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/gsup.h>

#include <stdint.h>

/*! \addtogroup gsup
 *  @{
 *  \file gsup.c
 *  Osmocom Generic Subscriber Update Protocol
 */

const struct value_string osmo_gsup_message_type_names[] = {
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT),

	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT),

	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_AUTH_FAIL_REPORT),

	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_PURGE_MS_REQUEST),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_PURGE_MS_ERROR),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_PURGE_MS_RESULT),

	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_INSERT_DATA_REQUEST),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_INSERT_DATA_ERROR),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_INSERT_DATA_RESULT),

	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_DELETE_DATA_REQUEST),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_DELETE_DATA_ERROR),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_DELETE_DATA_RESULT),

	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_LOCATION_CANCEL_ERROR),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT),

	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_PROC_SS_REQUEST),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_PROC_SS_ERROR),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_PROC_SS_RESULT),

	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_MO_FORWARD_SM_REQUEST),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_MO_FORWARD_SM_ERROR),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_MO_FORWARD_SM_RESULT),

	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_MT_FORWARD_SM_REQUEST),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_MT_FORWARD_SM_ERROR),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_MT_FORWARD_SM_RESULT),

	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_READY_FOR_SM_REQUEST),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_READY_FOR_SM_ERROR),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_READY_FOR_SM_RESULT),

	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_CHECK_IMEI_REQUEST),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_CHECK_IMEI_ERROR),
	OSMO_VALUE_STRING(OSMO_GSUP_MSGT_CHECK_IMEI_RESULT),

	{ 0, NULL }
};

const struct value_string osmo_gsup_session_state_names[] = {
	{ OSMO_GSUP_SESSION_STATE_NONE, "NONE" },
	{ OSMO_GSUP_SESSION_STATE_BEGIN, "BEGIN" },
	{ OSMO_GSUP_SESSION_STATE_CONTINUE, "CONTINUE" },
	{ OSMO_GSUP_SESSION_STATE_END, "END" },
	{ 0, NULL }
};


/*! return the error message type corresponding to \a type_in
 *  \returns matching error message type; -1 on error */
int osmo_gsup_get_err_msg_type(enum osmo_gsup_message_type type_in)
{
	switch (type_in) {
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST:
		return OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR;
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST:
		return OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR;
	case OSMO_GSUP_MSGT_PURGE_MS_REQUEST:
		return OSMO_GSUP_MSGT_PURGE_MS_ERROR;
	case OSMO_GSUP_MSGT_INSERT_DATA_REQUEST:
		return OSMO_GSUP_MSGT_INSERT_DATA_ERROR;
	case OSMO_GSUP_MSGT_DELETE_DATA_REQUEST:
		return OSMO_GSUP_MSGT_DELETE_DATA_ERROR;
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST:
		return OSMO_GSUP_MSGT_LOCATION_CANCEL_ERROR;
	case OSMO_GSUP_MSGT_PROC_SS_REQUEST:
		return OSMO_GSUP_MSGT_PROC_SS_ERROR;
	case OSMO_GSUP_MSGT_MO_FORWARD_SM_REQUEST:
		return OSMO_GSUP_MSGT_MO_FORWARD_SM_ERROR;
	case OSMO_GSUP_MSGT_MT_FORWARD_SM_REQUEST:
		return OSMO_GSUP_MSGT_MT_FORWARD_SM_ERROR;
	case OSMO_GSUP_MSGT_READY_FOR_SM_REQUEST:
		return OSMO_GSUP_MSGT_READY_FOR_SM_ERROR;
	case OSMO_GSUP_MSGT_CHECK_IMEI_REQUEST:
		return OSMO_GSUP_MSGT_CHECK_IMEI_ERROR;
	default:
		return -1;
	}
}

static int decode_pdp_info(uint8_t *data, size_t data_len,
			  struct osmo_gsup_pdp_info *pdp_info)
{
	int rc;
	uint8_t tag;
	uint8_t *value;
	size_t value_len;

	/* specific parts */
	while (data_len > 0) {
		enum osmo_gsup_iei iei;

		rc = osmo_shift_tlv(&data, &data_len, &tag, &value, &value_len);
		if (rc < 0)
			return -GMM_CAUSE_PROTO_ERR_UNSPEC;

		iei = tag;

		switch (iei) {
		case OSMO_GSUP_PDP_CONTEXT_ID_IE:
			pdp_info->context_id = osmo_decode_big_endian(value, value_len);
			break;

		case OSMO_GSUP_PDP_TYPE_IE:
			pdp_info->pdp_type =
				osmo_decode_big_endian(value, value_len) & 0x0fff;
			break;

		case OSMO_GSUP_ACCESS_POINT_NAME_IE:
			pdp_info->apn_enc = value;
			pdp_info->apn_enc_len = value_len;
			break;

		case OSMO_GSUP_PDP_QOS_IE:
			pdp_info->qos_enc = value;
			pdp_info->qos_enc_len = value_len;
			break;

		case OSMO_GSUP_CHARG_CHAR_IE:
			pdp_info->pdp_charg_enc = value;
			pdp_info->pdp_charg_enc_len = value_len;
			break;

		default:
			LOGP(DLGSUP, LOGL_ERROR,
			     "GSUP IE type %d not expected in PDP info\n", iei);
			continue;
		}
	}

	return 0;
}

static int decode_auth_info(uint8_t *data, size_t data_len,
			   struct osmo_auth_vector *auth_vector)
{
	int rc;
	uint8_t tag;
	uint8_t *value;
	size_t value_len;
	enum osmo_gsup_iei iei;
	uint8_t presence = 0;

	/* specific parts */
	while (data_len > 0) {
		rc = osmo_shift_tlv(&data, &data_len, &tag, &value, &value_len);
		if (rc < 0)
			return -GMM_CAUSE_PROTO_ERR_UNSPEC;

		iei = tag;

		switch (iei) {
		case OSMO_GSUP_RAND_IE:
			if (value_len != sizeof(auth_vector->rand))
				goto parse_error;

			memcpy(auth_vector->rand, value, value_len);
			presence |= (1 << 0);
			break;

		case OSMO_GSUP_SRES_IE:
			if (value_len != sizeof(auth_vector->sres))
				goto parse_error;

			memcpy(auth_vector->sres, value, value_len);
			presence |= (1 << 1);
			break;

		case OSMO_GSUP_KC_IE:
			if (value_len != sizeof(auth_vector->kc))
				goto parse_error;

			memcpy(auth_vector->kc, value, value_len);
			presence |= (1 << 2);
			break;

		case OSMO_GSUP_IK_IE:
			if (value_len != sizeof(auth_vector->ik))
				goto parse_error;
			memcpy(auth_vector->ik, value, value_len);
			presence |= (1 << 4);
			break;

		case OSMO_GSUP_CK_IE:
			if (value_len != sizeof(auth_vector->ck))
				goto parse_error;
			memcpy(auth_vector->ck, value, value_len);
			presence |= (1 << 5);
			break;

		case OSMO_GSUP_AUTN_IE:
			if (value_len != sizeof(auth_vector->autn))
				goto parse_error;
			memcpy(auth_vector->autn, value, value_len);
			presence |= (1 << 6);
			break;
		case OSMO_GSUP_RES_IE:
			if (value_len > sizeof(auth_vector->res))
				goto parse_error;
			memcpy(auth_vector->res, value, value_len);
			auth_vector->res_len = value_len;
			presence |= (1 << 7);
			break;

		default:
			LOGP(DLGSUP, LOGL_ERROR,
			     "GSUP IE type %d not expected in PDP info\n", iei);
			continue;
		}
	}

	if (presence & 0x07)
		auth_vector->auth_types |= OSMO_AUTH_TYPE_GSM;
	if (presence & 0xf0)
		auth_vector->auth_types |= OSMO_AUTH_TYPE_UMTS;

	return 0;

parse_error:
	LOGP(DLGSUP, LOGL_ERROR,
	     "GSUP IE type %d, length %zu invalid in PDP info\n", iei, value_len);

	return -1;
}

/*! Decode (parse) a GSUP message
 *  \param[in] const_data input data to be parsed
 *  \param[in] data_len length of input (\a const_data)
 *  \param[out] gsup_msg callee-allocated output data structure
 *  \returns 0 on success; negative otherwise
 */
int osmo_gsup_decode(const uint8_t *const_data, size_t data_len,
		     struct osmo_gsup_message *gsup_msg)
{
	int rc;
	int i;
	uint8_t tag;
	/* the shift/match functions expect non-const pointers, but we'll
	 * either copy the data or cast pointers back to const before returning
	 * them
	 */
	uint8_t *data = (uint8_t *)const_data;
	uint8_t *value;
	size_t value_len;
	static const struct osmo_gsup_pdp_info empty_pdp_info = {0};
	static const struct osmo_auth_vector empty_auth_info = {{0}};
	static const struct osmo_gsup_message empty_gsup_message = {0};

	*gsup_msg = empty_gsup_message;

	/* generic part */
	rc = osmo_shift_v_fixed(&data, &data_len, 1, &value);
	if (rc < 0)
		return -GMM_CAUSE_INV_MAND_INFO;

	gsup_msg->message_type = osmo_decode_big_endian(value, 1);

	rc = osmo_match_shift_tlv(&data, &data_len, OSMO_GSUP_IMSI_IE,
			    &value, &value_len);

	if (rc <= 0)
		return -GMM_CAUSE_INV_MAND_INFO;

	if (value_len * 2 + 1 > sizeof(gsup_msg->imsi))
		return -GMM_CAUSE_INV_MAND_INFO;

	/* Note that gsm48_decode_bcd_number expects the number of encoded IMSI
	 * octets in the first octet. By coincidence (the TLV encoding) the byte
	 * before the value part already contains this length so we can use it
	 * here.
	 */
	OSMO_ASSERT(value[-1] == value_len);
	gsm48_decode_bcd_number(gsup_msg->imsi, sizeof(gsup_msg->imsi),
				value - 1, 0);

	/* specific parts */
	while (data_len > 0) {
		enum osmo_gsup_iei iei;
		struct osmo_gsup_pdp_info pdp_info;
		struct osmo_auth_vector auth_info;

		rc = osmo_shift_tlv(&data, &data_len, &tag, &value, &value_len);
		if (rc < 0)
			return -GMM_CAUSE_PROTO_ERR_UNSPEC;

		iei = tag;

		switch (iei) {
		case OSMO_GSUP_IMSI_IE:
		case OSMO_GSUP_PDP_TYPE_IE:
		case OSMO_GSUP_ACCESS_POINT_NAME_IE:
		case OSMO_GSUP_SRES_IE:
		case OSMO_GSUP_KC_IE:
			LOGP(DLGSUP, LOGL_NOTICE,
			     "GSUP IE type %d not expected (ignored)\n", iei);
			continue;

		case OSMO_GSUP_CAUSE_IE:
			gsup_msg->cause = osmo_decode_big_endian(value, value_len);
			break;

		case OSMO_GSUP_CANCEL_TYPE_IE:
			gsup_msg->cancel_type =
				osmo_decode_big_endian(value, value_len) + 1;
			break;

		case OSMO_GSUP_PDP_INFO_COMPL_IE:
			gsup_msg->pdp_info_compl = 1;
			break;

		case OSMO_GSUP_FREEZE_PTMSI_IE:
			gsup_msg->freeze_ptmsi = 1;
			break;

		case OSMO_GSUP_PDP_CONTEXT_ID_IE:
			/* When these IE appear in the top-level part of the
			 * message, they are used by Delete Subscr Info to delete
			 * single entries. We don't have an extra list for
			 * these but use the PDP info list instead */

			/* fall through */

		case OSMO_GSUP_PDP_INFO_IE:
			if (gsup_msg->num_pdp_infos >= OSMO_GSUP_MAX_NUM_PDP_INFO) {
				LOGP(DLGSUP, LOGL_ERROR,
				     "GSUP IE type %d (PDP_INFO) max exceeded\n",
				     iei);
				return -GMM_CAUSE_COND_IE_ERR;
			}

			pdp_info = empty_pdp_info;

			if (iei == OSMO_GSUP_PDP_INFO_IE) {
				rc = decode_pdp_info(value, value_len, &pdp_info);
				if (rc < 0)
					return rc;
				pdp_info.have_info = 1;
			} else {
				pdp_info.context_id =
					osmo_decode_big_endian(value, value_len);
			}

			gsup_msg->pdp_infos[gsup_msg->num_pdp_infos++] =
				pdp_info;
			break;

		case OSMO_GSUP_AUTH_TUPLE_IE:
			if (gsup_msg->num_auth_vectors >= OSMO_GSUP_MAX_NUM_AUTH_INFO) {
				LOGP(DLGSUP, LOGL_ERROR,
				     "GSUP IE type %d (AUTH_INFO) max exceeded\n",
				     iei);
				return -GMM_CAUSE_INV_MAND_INFO;
			}

			auth_info = empty_auth_info;

			rc = decode_auth_info(value, value_len, &auth_info);
			if (rc < 0)
				return rc;

			gsup_msg->auth_vectors[gsup_msg->num_auth_vectors++] =
				auth_info;
			break;

		case OSMO_GSUP_AUTS_IE:
			if (value_len != 14) {
				LOGP(DLGSUP, LOGL_ERROR,
					"AUTS length != 14 received\n");
				return -GMM_CAUSE_COND_IE_ERR;
			}
			gsup_msg->auts = value;
			break;

		case OSMO_GSUP_RAND_IE:
			if (value_len != 16) {
				LOGP(DLGSUP, LOGL_ERROR,
					"RAND length != 16 received\n");
				return -GMM_CAUSE_COND_IE_ERR;
			}
			gsup_msg->rand = value;
			break;

		case OSMO_GSUP_MSISDN_IE:
			gsup_msg->msisdn_enc = value;
			gsup_msg->msisdn_enc_len = value_len;
			break;

		case OSMO_GSUP_HLR_NUMBER_IE:
			gsup_msg->hlr_enc = value;
			gsup_msg->hlr_enc_len = value_len;
			break;

		case OSMO_GSUP_CN_DOMAIN_IE:
			gsup_msg->cn_domain = *value;
			break;

		case OSMO_GSUP_RAT_TYPES_IE:
			if (value_len > ARRAY_SIZE(gsup_msg->rat_types)) {
				LOGP(DLGSUP, LOGL_ERROR, "nr of RAT types %zu > %zu\n", value_len, ARRAY_SIZE(gsup_msg->rat_types));
				return -GMM_CAUSE_COND_IE_ERR;
			}
			for (i = 0; i < value_len; i++)
				gsup_msg->rat_types[i] = value[i];
			gsup_msg->rat_types_len = value_len;
			break;

		case OSMO_GSUP_CHARG_CHAR_IE:
			gsup_msg->pdp_charg_enc = value;
			gsup_msg->pdp_charg_enc_len = value_len;
			break;

		case OSMO_GSUP_SESSION_ID_IE:
			gsup_msg->session_id = osmo_decode_big_endian(value, value_len);
			break;

		case OSMO_GSUP_SESSION_STATE_IE:
			gsup_msg->session_state = *value;
			break;

		case OSMO_GSUP_SS_INFO_IE:
			gsup_msg->ss_info = value;
			gsup_msg->ss_info_len = value_len;
			break;

		case OSMO_GSUP_SM_RP_MR_IE:
			gsup_msg->sm_rp_mr = value;
			break;

		case OSMO_GSUP_SM_RP_DA_IE:
			rc = osmo_gsup_sms_decode_sm_rp_da(gsup_msg, value, value_len);
			if (rc)
				return rc;
			break;

		case OSMO_GSUP_SM_RP_OA_IE:
			rc = osmo_gsup_sms_decode_sm_rp_oa(gsup_msg, value, value_len);
			if (rc)
				return rc;
			break;

		case OSMO_GSUP_SM_RP_UI_IE:
			gsup_msg->sm_rp_ui = value;
			gsup_msg->sm_rp_ui_len = value_len;
			break;

		case OSMO_GSUP_SM_RP_MMS_IE:
			gsup_msg->sm_rp_mms = value;
			break;

		case OSMO_GSUP_SM_RP_CAUSE_IE:
			gsup_msg->sm_rp_cause = value;
			break;

		case OSMO_GSUP_SM_ALERT_RSN_IE:
			gsup_msg->sm_alert_rsn = *value;
			break;

		case OSMO_GSUP_IMEI_IE:
			gsup_msg->imei_enc = value;
			gsup_msg->imei_enc_len = value_len;
			break;

		case OSMO_GSUP_IMEI_RESULT_IE:
			gsup_msg->imei_result = osmo_decode_big_endian(value, value_len) + 1;
			break;

		default:
			LOGP(DLGSUP, LOGL_NOTICE,
			     "GSUP IE type %d unknown\n", iei);
			continue;
		}
	}

	return 0;
}

static void encode_pdp_info(struct msgb *msg, enum osmo_gsup_iei iei,
			    const struct osmo_gsup_pdp_info *pdp_info)
{
	uint8_t *len_field;
	size_t old_len;
	uint8_t u8;

	len_field = msgb_tlv_put(msg, iei, 0, NULL) - 1;
	old_len = msgb_length(msg);

	u8 = pdp_info->context_id;
	msgb_tlv_put(msg, OSMO_GSUP_PDP_CONTEXT_ID_IE, sizeof(u8), &u8);

	if (pdp_info->pdp_type) {
		msgb_tlv_put(msg, OSMO_GSUP_PDP_TYPE_IE,
			     OSMO_GSUP_PDP_TYPE_SIZE,
			     osmo_encode_big_endian(pdp_info->pdp_type | 0xf000,
					       OSMO_GSUP_PDP_TYPE_SIZE));
	}

	if (pdp_info->apn_enc) {
		msgb_tlv_put(msg, OSMO_GSUP_ACCESS_POINT_NAME_IE,
			     pdp_info->apn_enc_len, pdp_info->apn_enc);
	}

	if (pdp_info->qos_enc) {
		msgb_tlv_put(msg, OSMO_GSUP_PDP_QOS_IE,
				pdp_info->qos_enc_len, pdp_info->qos_enc);
	}

	if (pdp_info->pdp_charg_enc) {
		msgb_tlv_put(msg, OSMO_GSUP_CHARG_CHAR_IE,
				pdp_info->pdp_charg_enc_len, pdp_info->pdp_charg_enc);
	}

	/* Update length field */
	*len_field = msgb_length(msg) - old_len;
}

static void encode_auth_info(struct msgb *msg, enum osmo_gsup_iei iei,
			     const struct osmo_auth_vector *auth_vector)
{
	uint8_t *len_field;
	size_t old_len;

	len_field = msgb_tlv_put(msg, iei, 0, NULL) - 1;
	old_len = msgb_length(msg);

	if (auth_vector->auth_types & OSMO_AUTH_TYPE_GSM) {
		msgb_tlv_put(msg, OSMO_GSUP_RAND_IE,
			     sizeof(auth_vector->rand), auth_vector->rand);

		msgb_tlv_put(msg, OSMO_GSUP_SRES_IE,
			     sizeof(auth_vector->sres), auth_vector->sres);

		msgb_tlv_put(msg, OSMO_GSUP_KC_IE,
			     sizeof(auth_vector->kc), auth_vector->kc);
	}

	if (auth_vector->auth_types & OSMO_AUTH_TYPE_UMTS) {
		msgb_tlv_put(msg, OSMO_GSUP_IK_IE,
			     sizeof(auth_vector->ik), auth_vector->ik);

		msgb_tlv_put(msg, OSMO_GSUP_CK_IE,
			     sizeof(auth_vector->ck), auth_vector->ck);

		msgb_tlv_put(msg, OSMO_GSUP_AUTN_IE,
			     sizeof(auth_vector->autn), auth_vector->autn);

		msgb_tlv_put(msg, OSMO_GSUP_RES_IE,
			     auth_vector->res_len, auth_vector->res);
	}

	/* Update length field */
	*len_field = msgb_length(msg) - old_len;
}

/*! Encode a GSUP message
 *  \param[out] msg message buffer to which encoded message is written
 *  \param[in] gsup_msg \ref osmo_gsup_message data to be encoded
 *  \returns 0 on success; negative otherwise
 */
int osmo_gsup_encode(struct msgb *msg, const struct osmo_gsup_message *gsup_msg)
{
	uint8_t u8;
	int idx, rc;
	uint8_t bcd_buf[GSM48_MI_SIZE] = {0};
	size_t bcd_len;

	/* generic part */
	if(!gsup_msg->message_type)
		return -EINVAL;

	msgb_v_put(msg, gsup_msg->message_type);

	bcd_len = gsm48_encode_bcd_number(bcd_buf, sizeof(bcd_buf), 0,
					  gsup_msg->imsi);

	if (bcd_len <= 0 || bcd_len > sizeof(bcd_buf))
		return -EINVAL;

	/* Note that gsm48_encode_bcd_number puts the length into the first
	 * octet. Since msgb_tlv_put will add this length byte, we'll have to
	 * skip it */
	msgb_tlv_put(msg, OSMO_GSUP_IMSI_IE, bcd_len - 1, &bcd_buf[1]);

	/* specific parts */
	if (gsup_msg->msisdn_enc)
		msgb_tlv_put(msg, OSMO_GSUP_MSISDN_IE,
				gsup_msg->msisdn_enc_len, gsup_msg->msisdn_enc);
	if (gsup_msg->hlr_enc)
		msgb_tlv_put(msg, OSMO_GSUP_HLR_NUMBER_IE,
				gsup_msg->hlr_enc_len, gsup_msg->hlr_enc);

	if ((u8 = gsup_msg->cause))
		msgb_tlv_put(msg, OSMO_GSUP_CAUSE_IE, sizeof(u8), &u8);

	if ((u8 = gsup_msg->cancel_type)) {
		u8 -= 1;
		msgb_tlv_put(msg, OSMO_GSUP_CANCEL_TYPE_IE, sizeof(u8), &u8);
	}

	if (gsup_msg->pdp_info_compl)
		msgb_tlv_put(msg, OSMO_GSUP_PDP_INFO_COMPL_IE, 0, &u8);

	if (gsup_msg->freeze_ptmsi)
		msgb_tlv_put(msg, OSMO_GSUP_FREEZE_PTMSI_IE, 0, &u8);

	for (idx = 0; idx < gsup_msg->num_pdp_infos; idx++) {
		const struct osmo_gsup_pdp_info *pdp_info;

		pdp_info = &gsup_msg->pdp_infos[idx];

		if (pdp_info->context_id == 0)
			continue;

		if (pdp_info->have_info) {
			encode_pdp_info(msg, OSMO_GSUP_PDP_INFO_IE, pdp_info);
		} else {
			u8 = pdp_info->context_id;
			msgb_tlv_put(msg, OSMO_GSUP_PDP_CONTEXT_ID_IE,
				     sizeof(u8), &u8);
		}
	}

	for (idx = 0; idx < gsup_msg->num_auth_vectors; idx++) {
		const struct osmo_auth_vector *auth_vector;

		auth_vector = &gsup_msg->auth_vectors[idx];

		encode_auth_info(msg, OSMO_GSUP_AUTH_TUPLE_IE, auth_vector);
	}

	if (gsup_msg->auts)
		msgb_tlv_put(msg, OSMO_GSUP_AUTS_IE, 14, gsup_msg->auts);

	if (gsup_msg->rand)
		msgb_tlv_put(msg, OSMO_GSUP_RAND_IE, 16, gsup_msg->rand);

	if (gsup_msg->cn_domain) {
		uint8_t dn = gsup_msg->cn_domain;
		msgb_tlv_put(msg, OSMO_GSUP_CN_DOMAIN_IE, 1, &dn);
	}

	if (gsup_msg->rat_types_len) {
		int i;
		uint8_t *len = msgb_tl_put(msg, OSMO_GSUP_RAT_TYPES_IE);
		*len = gsup_msg->rat_types_len;
		for (i = 0; i < gsup_msg->rat_types_len; i++) {
			if (!gsup_msg->rat_types[i] || gsup_msg->rat_types[i] >= OSMO_RAT_COUNT) {
				LOGP(DLGSUP, LOGL_ERROR, "Failed to encode RAT type %s (nr %d)\n",
				     osmo_rat_type_name(gsup_msg->rat_types[i]), i);
				return -EINVAL;
			}
			msgb_v_put(msg, gsup_msg->rat_types[i]);
		}
	}

	if (gsup_msg->pdp_charg_enc) {
		msgb_tlv_put(msg, OSMO_GSUP_CHARG_CHAR_IE,
				gsup_msg->pdp_charg_enc_len, gsup_msg->pdp_charg_enc);
	}

	if ((u8 = gsup_msg->session_state)) {
		size_t len = sizeof(gsup_msg->session_id);
		uint8_t *sid = osmo_encode_big_endian(gsup_msg->session_id, len);

		msgb_tlv_put(msg, OSMO_GSUP_SESSION_ID_IE, len, sid);
		msgb_tlv_put(msg, OSMO_GSUP_SESSION_STATE_IE, sizeof(u8), &u8);
	}

	if (gsup_msg->ss_info) {
		msgb_tlv_put(msg, OSMO_GSUP_SS_INFO_IE,
				gsup_msg->ss_info_len, gsup_msg->ss_info);
	}

	if (gsup_msg->sm_rp_mr) {
		msgb_tlv_put(msg, OSMO_GSUP_SM_RP_MR_IE,
				sizeof(*gsup_msg->sm_rp_mr), gsup_msg->sm_rp_mr);
	}

	if (gsup_msg->sm_rp_da_type) {
		rc = osmo_gsup_sms_encode_sm_rp_da(msg, gsup_msg);
		if (rc) {
			LOGP(DLGSUP, LOGL_ERROR, "Failed to encode SM-RP-DA IE\n");
			return -EINVAL;
		}
	}

	if (gsup_msg->sm_rp_oa_type) {
		rc = osmo_gsup_sms_encode_sm_rp_oa(msg, gsup_msg);
		if (rc) {
			LOGP(DLGSUP, LOGL_ERROR, "Failed to encode SM-RP-OA IE\n");
			return -EINVAL;
		}
	}

	if (gsup_msg->sm_rp_ui) {
		msgb_tlv_put(msg, OSMO_GSUP_SM_RP_UI_IE,
				gsup_msg->sm_rp_ui_len, gsup_msg->sm_rp_ui);
	}

	if (gsup_msg->sm_rp_mms) {
		msgb_tlv_put(msg, OSMO_GSUP_SM_RP_MMS_IE,
				sizeof(*gsup_msg->sm_rp_mms), gsup_msg->sm_rp_mms);
	}

	if (gsup_msg->sm_rp_cause) {
		msgb_tlv_put(msg, OSMO_GSUP_SM_RP_CAUSE_IE,
				sizeof(*gsup_msg->sm_rp_cause), gsup_msg->sm_rp_cause);
	}

	if ((u8 = gsup_msg->sm_alert_rsn)) {
		msgb_tlv_put(msg, OSMO_GSUP_SM_ALERT_RSN_IE,
				sizeof(u8), &u8);
	}

	if (gsup_msg->imei_enc)
		msgb_tlv_put(msg, OSMO_GSUP_IMEI_IE, gsup_msg->imei_enc_len, gsup_msg->imei_enc);

	if ((u8 = gsup_msg->imei_result)) {
		u8 -= 1;
		msgb_tlv_put(msg, OSMO_GSUP_IMEI_RESULT_IE, sizeof(u8), &u8);
	}

	return 0;
}

/*! @} */
