/* (C) 2018 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Harald Welte, Philipp Maier
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

#include <osmocom/core/utils.h>
#include <osmocom/gsm/tlv.h>

#include <osmocom/gsm/protocol/gsm_29_118.h>
#include <osmocom/gsm/gsm29118.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/gsm48.h>

const struct value_string sgsap_msg_type_names[] = {
	{ SGSAP_MSGT_PAGING_REQ,	"PAGING-REQUEST" },
	{ SGSAP_MSGT_PAGING_REJ,	"PAGING-REJECT" },
	{ SGSAP_MSGT_SERVICE_REQ,	"SERVICE-REQUEST" },
	{ SGSAP_MSGT_DL_UD,		"DOWNLINK-UNITDATA" },
	{ SGSAP_MSGT_UL_UD,		"UPLINK-UNITDATA" },
	{ SGSAP_MSGT_LOC_UPD_REQ,	"LOCATION-UPDATE-REQUEST" },
	{ SGSAP_MSGT_LOC_UPD_ACK,	"LOCATION-UPDATE-ACCEPT" },
	{ SGSAP_MSGT_LOC_UPD_REJ,	"LOCATION-UPDATE-REJECT" },
	{ SGSAP_MSGT_TMSI_REALL_CMPL,	"TMSI-REALLOCATION-COMPLETE" },
	{ SGSAP_MSGT_ALERT_REQ,		"ALERT-REQQUEST" },
	{ SGSAP_MSGT_ALERT_ACK,		"ALERT-ACK" },
	{ SGSAP_MSGT_ALERT_REJ,		"ALERT-REJECT" },
	{ SGSAP_MSGT_UE_ACT_IND,	"UE-ACTIVITY-INDICATION" },
	{ SGSAP_MSGT_EPS_DET_IND,	"EPS-DETACH-INDICATION" },
	{ SGSAP_MSGT_EPS_DET_ACK,	"EPS-DETACH-ACK" },
	{ SGSAP_MSGT_IMSI_DET_IND,	"IMSI-DETACH-INDICATION" },
	{ SGSAP_MSGT_IMSI_DET_ACK,	"IMSI-DETACH-ACK" },
	{ SGSAP_MSGT_RESET_IND,		"RESET-INDICATION" },
	{ SGSAP_MSGT_RESET_ACK,		"RESET-ACK" },
	{ SGSAP_MSGT_SERVICE_ABORT_REQ,	"SERVICE-ABORT-REQUEST" },
	{ SGSAP_MSGT_MO_CSFB_IND,	"MO-CSFB-INDICATION" },
	{ SGSAP_MSGT_MM_INFO_REQ,	"MM-INFO-REQUEST" },
	{ SGSAP_MSGT_RELEASE_REQ,	"RELEASE-REQUEST" },
	{ SGSAP_MSGT_STATUS,		"STATUS" },
	{ SGSAP_MSGT_UE_UNREACHABLE,	"UE-UNREACHABLE" },
	{ 0, NULL }
};

const struct value_string sgsap_iei_names[] = {
	{ SGSAP_IE_IMSI,			"IMSI" },
	{ SGSAP_IE_VLR_NAME,			"VLR-NAME" },
	{ SGSAP_IE_TMSI,			"TMSI" },
	{ SGSAP_IE_LAI,				"LAI" },
	{ SGSAP_IE_CHAN_NEEDED,			"CHAN-NEEDED" },
	{ SGSAP_IE_EMLPP_PRIORITY,		"EMLPP-PRIORITY" },
	{ SGSAP_IE_TMSI_STATUS,			"TMSI-STATUS" },
	{ SGSAP_IE_SGS_CAUSE,			"SGS-CAUSE" },
	{ SGSAP_IE_MME_NAME,			"MME-NAME" },
	{ SGSAP_IE_EPS_LU_TYPE,			"EPS-LU-TYPE" },
	{ SGSAP_IE_GLOBAL_CN_ID,		"GLOBAL-CN-ID" },
	{ SGSAP_IE_MOBILE_ID,			"MOBILE-ID" },
	{ SGSAP_IE_REJECT_CAUSE,		"REJECT-CAUSE" },
	{ SGSAP_IE_IMSI_DET_EPS_TYPE,		"IMSI-DET-EPS-TYPE" },
	{ SGSAP_IE_IMSI_DET_NONEPS_TYPE,	"IMSI-DET-NONEPS-TYPE" },
	{ SGSAP_IE_IMEISV,			"IMEISV" },
	{ SGSAP_IE_NAS_MSG_CONTAINER,		"NAS-MSG-CONTAINER" },
	{ SGSAP_IE_MM_INFO,			"MM-INFO" },
	{ SGSAP_IE_ERR_MSG,			"ERR-MSG" },
	{ SGSAP_IE_CLI,				"CLI" },
	{ SGSAP_IE_LCS_CLIENT_ID,		"LCS-CLIENT-ID" },
	{ SGSAP_IE_LCS_INDICATOR,		"LCS-INDICATOR" },
	{ SGSAP_IE_SS_CODE,			"SS-CODE" },
	{ SGSAP_IE_SERVICE_INDICATOR,		"SERVICE-INDICATOR" },
	{ SGSAP_IE_UE_TIMEZONE,			"UE-TIMEZONE" },
	{ SGSAP_IE_MS_CLASSMARK2,		"MS-CLASSMARK2" },
	{ SGSAP_IE_TAI,				"TAI" },
	{ SGSAP_IE_EUTRAN_CGI,			"EUTRAN-CGI" },
	{ SGSAP_IE_UE_EMM_MODE,			"UE-EMM-MODE" },
	{ SGSAP_IE_ADDL_PAGING_INDICATORS,	"ADDL-PAGING-INDICATORS" },
	{ SGSAP_IE_TMSI_BASED_NRI_CONT,		"TMSI-BASED-NRI-CONT" },
	{ SGSAP_IE_MO_FALLBACK_VALUE,		"MO-FALLBACK-VALUE" },
	{ 0, NULL }
};

const struct value_string sgsap_eps_lu_type_names[] = {
	{ SGSAP_EPS_LUT_IMSI_ATTACH,	"IMSI Attach" },
	{ SGSAP_EPS_LUT_NORMAL,		"Normal" },
	{ 0, NULL }
};

const struct value_string sgsap_ismi_det_eps_type_names[] = {
	{ SGSAP_ID_EPS_T_NETWORK_INITIATED,	"Network initiated IMSI detach from EPS" },
	{ SGSAP_ID_EPS_T_UE_INITIATED,		"UE initiated IMSI detach from EPS" },
	{ SGSAP_ID_EPS_T_EPS_NOT_ALLOWED,	"EPS not allowed" },
	{ 0, NULL }
};

const struct value_string sgsap_ismi_det_noneps_type_names[] = {
	{ SGSAP_ID_NONEPS_T_EXPLICIT_UE_NONEPS,
	  "Explicit UE initiated IMSI detach from non-EPS" },
	{ SGSAP_ID_NONEPS_T_COMBINED_UE_EPS_NONEPS,
	  "Combined UE initiated IMSI detach from EPS and non-EPS" },
	{ SGSAP_ID_NONEPS_T_IMPLICIT_UE_EPS_NONEPS,
	  "Implicit network initiated IMSI detach from EPS and non-EPS" },
	{ 0, NULL }
};

const struct value_string sgsap_service_ind_names[] = {
	{ SGSAP_SERV_IND_CS_CALL,	"CS Call" },
	{ SGSAP_SERV_IND_SMS,		"SMS" },
	{ 0, NULL }
};

const struct value_string sgsap_sgs_cause_names[] = {
	{ SGSAP_SGS_CAUSE_IMSI_DET_EPS,		"IMSI detached for EPS" },
	{ SGSAP_SGS_CAUSE_IMSI_DET_EPS_NONEPS,	"IMSI detached for EPS and non-EPS" },
	{ SGSAP_SGS_CAUSE_IMSI_UNKNOWN,		"IMSI unknown" },
	{ SGSAP_SGS_CAUSE_IMSI_DET_NON_EPS,	"IMSI detached for non-EPS" },
	{ SGSAP_SGS_CAUSE_IMSI_IMPL_DET_NON_EPS,"IMSI implicitly detached for non-EPS" },
	{ SGSAP_SGS_CAUSE_UE_UNREACHABLE,	"UE unreachable" },
	{ SGSAP_SGS_CAUSE_MSG_INCOMP_STATE,	"Message not compatible with protocol state" },
	{ SGSAP_SGS_CAUSE_MISSING_MAND_IE,	"Missing mandatory IE" },
	{ SGSAP_SGS_CAUSE_INVALID_MAND_IE,	"Invalid mandatory IE" },
	{ SGSAP_SGS_CAUSE_COND_IE_ERROR,	"Conditional IE error" },
	{ SGSAP_SGS_CAUSE_SEMANT_INCORR_MSG,	"Semantically incorrect message" },
	{ SGSAP_SGS_CAUSE_MSG_UNKNOWN,		"Message unknown" },
	{ SGSAP_SGS_CAUSE_MT_CSFB_REJ_USER,	"MT CSFB call rejected by user" },
	{ SGSAP_SGS_CAUSE_UE_TEMP_UNREACHABLE,	"UE temporarily unreachable" },
	{ 0, NULL }
};


const struct value_string sgsap_ue_emm_mode_names[] = {
	{ SGSAP_UE_EMM_MODE_IDLE, 		"EMM-IDLE" },
	{ SGSAP_UE_EMM_MODE_CONNECTED,		"EMM-CONNECTED" },
	{ 0, NULL }
};

const struct tlv_definition sgsap_ie_tlvdef = {
	.def = {
		[SGSAP_IE_IMSI]			= { TLV_TYPE_TLV },
		[SGSAP_IE_VLR_NAME]		= { TLV_TYPE_TLV },
		[SGSAP_IE_TMSI]			= { TLV_TYPE_TLV },
		[SGSAP_IE_LAI]			= { TLV_TYPE_TLV },
		[SGSAP_IE_CHAN_NEEDED]		= { TLV_TYPE_TLV },
		[SGSAP_IE_EMLPP_PRIORITY]	= { TLV_TYPE_TLV },
		[SGSAP_IE_TMSI_STATUS]		= { TLV_TYPE_TLV },
		[SGSAP_IE_SGS_CAUSE]		= { TLV_TYPE_TLV },
		[SGSAP_IE_MME_NAME]		= { TLV_TYPE_TLV },
		[SGSAP_IE_EPS_LU_TYPE]		= { TLV_TYPE_TLV },
		[SGSAP_IE_GLOBAL_CN_ID]		= { TLV_TYPE_TLV },
		[SGSAP_IE_MOBILE_ID]		= { TLV_TYPE_TLV },
		[SGSAP_IE_REJECT_CAUSE]		= { TLV_TYPE_TLV },
		[SGSAP_IE_IMSI_DET_EPS_TYPE]	= { TLV_TYPE_TLV },
		[SGSAP_IE_IMSI_DET_NONEPS_TYPE]	= { TLV_TYPE_TLV },
		[SGSAP_IE_IMEISV]		= { TLV_TYPE_TLV },
		[SGSAP_IE_NAS_MSG_CONTAINER]	= { TLV_TYPE_TLV },
		[SGSAP_IE_MM_INFO]		= { TLV_TYPE_TLV },
		[SGSAP_IE_ERR_MSG]		= { TLV_TYPE_TLV },
		[SGSAP_IE_CLI]			= { TLV_TYPE_TLV },
		[SGSAP_IE_LCS_CLIENT_ID]	= { TLV_TYPE_TLV },
		[SGSAP_IE_LCS_INDICATOR]	= { TLV_TYPE_TLV },
		[SGSAP_IE_SS_CODE]		= { TLV_TYPE_TLV },
		[SGSAP_IE_SERVICE_INDICATOR]	= { TLV_TYPE_TLV },
		[SGSAP_IE_UE_TIMEZONE]		= { TLV_TYPE_TLV },
		[SGSAP_IE_MS_CLASSMARK2]	= { TLV_TYPE_TLV },
		[SGSAP_IE_TAI]			= { TLV_TYPE_TLV },
		[SGSAP_IE_EUTRAN_CGI]		= { TLV_TYPE_TLV },
		[SGSAP_IE_UE_EMM_MODE]		= { TLV_TYPE_TLV },
		[SGSAP_IE_ADDL_PAGING_INDICATORS]={ TLV_TYPE_TLV },
		[SGSAP_IE_TMSI_BASED_NRI_CONT]	= { TLV_TYPE_TLV },
		[SGSAP_IE_MO_FALLBACK_VALUE]	= { TLV_TYPE_TLV },
	},
};


/* Allocate an empty message buffer, suitable to hold a complete SGsAP msg. */
struct msgb *gsm29118_msgb_alloc(void)
{
	/* by far sufficient for the maximum size message of 298 bytes
	 * (9+7+5+3+10+253+10+1) SGsAP-UP-UD */
	return msgb_alloc_headroom(1024, 512, "SGsAP");
}

/* Encode VLR/MME name from string and append to SGsAP msg */
static int msgb_sgsap_name_put(struct msgb *msg, enum sgsap_iei iei, const char *name)
{
	uint8_t buf[APN_MAXLEN];
	uint8_t len;
	int rc;

	/* encoding is like DNS names, which is like APN fields */
	memset(buf, 0, sizeof(buf));
	rc = osmo_apn_from_str(buf, sizeof(buf), name);
	if (rc < 0)
		return -1;
	len = (uint8_t)rc;

	/* Note: While the VLR-Name (see 3GPP TS 29.118, chapter 9.4.22) has
	 * a flexible length, the MME-Name has a fixed size of 55 octets. (see
	 * 3GPP TS 29.118, chapter 9.4.13). */
	if (iei == SGSAP_IE_MME_NAME && len != SGS_MME_NAME_LEN)
		return -1;
	msgb_tlv_put(msg, iei, len, buf);
	return 0;
}

/* Encode IMSI from string representation and append to SGSaAP msg */
static void msgb_sgsap_imsi_put(struct msgb *msg, const char *imsi)
{
	uint8_t buf[16];
	uint8_t len;
	/* encoding is just like TS 04.08 */
	len = gsm48_generate_mid_from_imsi(buf, imsi);
	/* skip first two bytes (tag+length) so we can use msgb_tlv_put */
	msgb_tlv_put(msg, SGSAP_IE_IMSI, len - 2, buf + 2);
}

/* Encode LAI from struct representation and append to SGSaAP msg */
static void msgb_sgsap_lai_put(struct msgb *msg, const struct osmo_location_area_id *lai)
{
	struct gsm48_loc_area_id lai_enc;
	gsm48_generate_lai2(&lai_enc, lai);
	msgb_tlv_put(msg, SGSAP_IE_LAI, sizeof(lai_enc), (uint8_t *) & lai_enc);
}

/* Many messages consist only of a message type and an imsi */
static struct msgb *create_simple_msg(enum sgsap_msg_type msg_type, const char *imsi)
{
	struct msgb *msg = gsm29118_msgb_alloc();
	msgb_sgsap_imsi_put(msg, imsi);
	msgb_push_u8(msg, msg_type);
	return msg;
}

/* 8.3 SGsAP-ALERT-REQUEST.
 *  \param[in] imsi IMSI of the subscriber.
 *  \returns callee-allocated msgb with the encoded message.*/
struct msgb *gsm29118_create_alert_req(const char *imsi)
{
	return create_simple_msg(SGSAP_MSGT_ALERT_REQ, imsi);
}

/* 8.4 SGsAP-DOWNLINK-UNITDATA.
 *  \param[in] imsi IMSI of the subscriber.
 *  \param[in] nas_msg user provided message buffer with L3 message.
 *  \returns callee-allocated msgb with the encoded message. */
struct msgb *gsm29118_create_dl_ud(const char *imsi, struct msgb *nas_msg)
{
	struct msgb *msg = gsm29118_msgb_alloc();
	msgb_sgsap_imsi_put(msg, imsi);
	msgb_tlv_put(msg, SGSAP_IE_NAS_MSG_CONTAINER, nas_msg->len, nas_msg->data);
	msgb_push_u8(msg, SGSAP_MSGT_DL_UD);
	return msg;
}

/* 8.5 SGsAP-EPS-DETACH-ACK.
 *  \param[in] imsi IMSI of the subscriber.
 *  \returns callee-allocated msgb with the encoded message. */
struct msgb *gsm29118_create_eps_det_ack(const char *imsi)
{
	return create_simple_msg(SGSAP_MSGT_EPS_DET_ACK, imsi);
}

/* 8.7 SGsAP-IMSI-DETACH-ACK.
 *  \param[in] imsi IMSI of the subscriber.
 *  \returns callee-allocated msgb with the encoded message. */
struct msgb *gsm29118_create_imsi_det_ack(const char *imsi)
{
	return create_simple_msg(SGSAP_MSGT_IMSI_DET_ACK, imsi);
}

/*! 8.9 SGsAP-LOCATION-UPDATE-ACCEPT.
 *  \param[in] imsi IMSI of the subscriber.
 *  \param[in] lai Location Area Identity (optional, may be NULL).
 *  \param[in] new_id value part of new Mobile Identity (optional, may be NULL).
 *  \param[in] new_id_len length of \a new_id in octets.
 *  \returns callee-allocated msgb with the encoded message */
struct msgb *gsm29118_create_lu_ack(const char *imsi, const struct osmo_location_area_id *lai, const uint8_t *new_id,
				    unsigned int new_id_len)
{
	struct msgb *msg = gsm29118_msgb_alloc();
	msgb_sgsap_imsi_put(msg, imsi);
	msgb_sgsap_lai_put(msg, lai);
	if (new_id && new_id_len)
		msgb_tlv_put(msg, SGSAP_IE_MOBILE_ID, new_id_len, new_id);
	msgb_push_u8(msg, SGSAP_MSGT_LOC_UPD_ACK);
	return msg;
}

/* 8.10 SGsAP-LOCATION-UPDATE-REJECT.
 *  \param[in] imsi IMSI of the subscriber.
 *  \param[in] rej_cause LU cause code, see also 3GPP TS 29.018, subclause 18.4.21.
 *  \param[in] lai location area identifier.
 *  \returns callee-allocated msgb with the encoded message */
struct msgb *gsm29118_create_lu_rej(const char *imsi, uint8_t rej_cause, const struct osmo_location_area_id *lai)
{
	struct msgb *msg = gsm29118_msgb_alloc();
	msgb_sgsap_imsi_put(msg, imsi);
	msgb_tlv_put(msg, SGSAP_IE_REJECT_CAUSE, 1, &rej_cause);
	if (lai)
		msgb_sgsap_lai_put(msg, lai);
	msgb_push_u8(msg, SGSAP_MSGT_LOC_UPD_REJ);
	return msg;
}

/* 8.12 SGsAP-MM-INFORMATION-REQUEST.
 *  \param[in] imsi IMSI of the subscriber.
 *  \param[in] mm_info MM information, see also 3GPP TS 29.018, subclause 18.4.16.
 *  \param[in] mm_info_len length of \a mm_info in octets.
 *  \returns callee-allocated msgb with the encoded message. */
struct msgb *gsm29118_create_mm_info_req(const char *imsi, const uint8_t *mm_info, uint8_t mm_info_len)
{
	struct msgb *msg = gsm29118_msgb_alloc();
	msgb_sgsap_imsi_put(msg, imsi);
	msgb_tlv_put(msg, SGSAP_IE_MM_INFO, mm_info_len, mm_info);
	msgb_push_u8(msg, SGSAP_MSGT_MM_INFO_REQ);
	return msg;
}

/* 8.14 SGsAP-PAGING-REQUEST.
 *  \param[in] params user provided memory with message contents to encode.
 *  \returns callee-allocated msgb with the encoded message or NULL on error. */
struct msgb *gsm29118_create_paging_req(struct gsm29118_paging_req *params)
{
	int rc;
	struct msgb *msg = gsm29118_msgb_alloc();
	msgb_sgsap_imsi_put(msg, params->imsi);
	rc = msgb_sgsap_name_put(msg, SGSAP_IE_VLR_NAME, params->vlr_name);
	if (rc < 0)
		goto error;
	msgb_tlv_put(msg, SGSAP_IE_SERVICE_INDICATOR, 1, &params->serv_ind);
	if (params->lai_present)
		msgb_sgsap_lai_put(msg, &params->lai);
	msgb_push_u8(msg, SGSAP_MSGT_PAGING_REQ);
	return msg;
error:
	msgb_free(msg);
	return NULL;
}

/* 8.15 SGsAP-RESET-ACK.
 *  \param[in] params user provided memory with message contents to encode.
 *  \returns callee-allocated msgb with the encoded message or NULL on error. */
struct msgb *gsm29118_create_reset_ack(struct gsm29118_reset_msg *params)
{
	int rc;
	struct msgb *msg = gsm29118_msgb_alloc();
	if (params->vlr_name_present && params->mme_name_present == false)
		rc = msgb_sgsap_name_put(msg, SGSAP_IE_VLR_NAME, params->vlr_name);
	else if (params->mme_name_present && params->vlr_name_present == false)
		rc = msgb_sgsap_name_put(msg, SGSAP_IE_MME_NAME, params->mme_name);
	else
		goto error;
	if (rc < 0)
		goto error;
	msgb_push_u8(msg, SGSAP_MSGT_RESET_ACK);
	return msg;
error:
	msgb_free(msg);
	return NULL;
}

/* 8.16 SGsAP-RESET-INDICATION.
 *  \param[in] params user provided memory with message contents to encode.
 *  \returns callee-allocated msgb with the encoded message or NULL on error. */
struct msgb *gsm29118_create_reset_ind(struct gsm29118_reset_msg *params)
{
	int rc;
	struct msgb *msg = gsm29118_msgb_alloc();
	if (params->vlr_name_present && params->mme_name_present == false)
		rc = msgb_sgsap_name_put(msg, SGSAP_IE_VLR_NAME, params->vlr_name);
	else if (params->mme_name_present && params->vlr_name_present == false)
		rc = msgb_sgsap_name_put(msg, SGSAP_IE_MME_NAME, params->mme_name);
	else
		goto error;
	if (rc < 0)
		goto error;
	msgb_push_u8(msg, SGSAP_MSGT_RESET_IND);
	return msg;
error:
	msgb_free(msg);
	return NULL;
}

/* 8.18 SGsAP-STATUS.
 *  \param[in] imsi IMSI of the subscriber.
 *  \param[in] cause sgs related cause code.
 *  \param[in] err_msg user provided message buffer containing the errornous message.
 *  \returns callee-allocated msgb with the encoded message */
struct msgb *gsm29118_create_status(const char *imsi, enum sgsap_sgs_cause cause, const struct msgb *err_msg)
{
	struct msgb *msg = gsm29118_msgb_alloc();
	uint8_t c8 = cause;
	unsigned int err_msg_len;
	msgb_tlv_put(msg, SGSAP_IE_SGS_CAUSE, 1, &c8);
	if (imsi)
		msgb_sgsap_imsi_put(msg, imsi);
	if (err_msg) {
		err_msg_len = msgb_l2len(err_msg);
		if (err_msg_len > 255)
			err_msg_len = 255;
		msgb_tlv_put(msg, SGSAP_IE_ERR_MSG, err_msg_len, msgb_l2(err_msg));
	}
	msgb_push_u8(msg, SGSAP_MSGT_STATUS);
	return msg;
}

/* 8.23 SGsAP-RELEASE-REQUEST.
 *  \param[in] imsi IMSI of the subscriber.
 *  \param[in] cause sgs related cause code.
 *  \returns callee-allocated msgb with the encoded message. */
struct msgb *gsm29118_create_release_req(const char *imsi, const uint8_t sgs_cause)
{
	struct msgb *msg = gsm29118_msgb_alloc();
	msgb_sgsap_imsi_put(msg, imsi);
	if (sgs_cause)
		msgb_tlv_put(msg, SGSAP_IE_SGS_CAUSE, 1, &sgs_cause);
	msgb_push_u8(msg, SGSAP_MSGT_RELEASE_REQ);
	return msg;
}

/* 8.24 SGsAP-SERVICE-ABORT-REQUEST.
 *  \param[in] imsi IMSI of the subscriber.
 *  \returns callee-allocated msgb with the encoded message. */
struct msgb *gsm29118_create_service_abort_req(const char *imsi)
{
	return create_simple_msg(SGSAP_MSGT_SERVICE_ABORT_REQ, imsi);
}
