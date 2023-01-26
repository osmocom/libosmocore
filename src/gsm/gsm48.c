/*! \file gsm48.c
 * GSM Mobile Radio Interface Layer 3 messages
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */
/*
 * (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <ctype.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/core/bit16gen.h>
#include <osmocom/core/bit32gen.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0502.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_04_80.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

/*! \addtogroup gsm0408
 *  @{
 *  GSM Mobile Radion Interface L3 messages / TS 04.08
 */

/*! TLV parser definitions for TS 04.08 CC */
const struct tlv_definition gsm48_att_tlvdef = {
	.def = {
		[GSM48_IE_MOBILE_ID]	= { TLV_TYPE_TLV },
		[GSM48_IE_NAME_LONG]	= { TLV_TYPE_TLV },
		[GSM48_IE_NAME_SHORT]	= { TLV_TYPE_TLV },
		[GSM48_IE_UTC]		= { TLV_TYPE_TV },
		[GSM48_IE_NET_TIME_TZ]	= { TLV_TYPE_FIXED, 7 },
		[GSM48_IE_LSA_IDENT]	= { TLV_TYPE_TLV },

		[GSM48_IE_BEARER_CAP]	= { TLV_TYPE_TLV },
		[GSM48_IE_CAUSE]	= { TLV_TYPE_TLV },
		[GSM48_IE_CC_CAP]	= { TLV_TYPE_TLV },
		[GSM48_IE_ALERT]	= { TLV_TYPE_TLV },
		[GSM48_IE_FACILITY]	= { TLV_TYPE_TLV },
		[GSM48_IE_PROGR_IND]	= { TLV_TYPE_TLV },
		[GSM48_IE_AUX_STATUS]	= { TLV_TYPE_TLV },
		[GSM48_IE_NOTIFY]	= { TLV_TYPE_TV },
		[GSM48_IE_KPD_FACILITY]	= { TLV_TYPE_TV },
		[GSM48_IE_SIGNAL]	= { TLV_TYPE_TV },
		[GSM48_IE_CONN_BCD]	= { TLV_TYPE_TLV },
		[GSM48_IE_CONN_SUB]	= { TLV_TYPE_TLV },
		[GSM48_IE_CALLING_BCD]	= { TLV_TYPE_TLV },
		[GSM48_IE_CALLING_SUB]	= { TLV_TYPE_TLV },
		[GSM48_IE_CALLED_BCD]	= { TLV_TYPE_TLV },
		[GSM48_IE_CALLED_SUB]	= { TLV_TYPE_TLV },
		[GSM48_IE_REDIR_BCD]	= { TLV_TYPE_TLV },
		[GSM48_IE_REDIR_SUB]	= { TLV_TYPE_TLV },
		[GSM48_IE_LOWL_COMPAT]	= { TLV_TYPE_TLV },
		[GSM48_IE_HIGHL_COMPAT]	= { TLV_TYPE_TLV },
		[GSM48_IE_USER_USER]	= { TLV_TYPE_TLV },
		[GSM48_IE_SS_VERS]	= { TLV_TYPE_TLV },
		[GSM48_IE_MORE_DATA]	= { TLV_TYPE_T },
		[GSM48_IE_CLIR_SUPP]	= { TLV_TYPE_T },
		[GSM48_IE_CLIR_INVOC]	= { TLV_TYPE_T },
		[GSM48_IE_REV_C_SETUP]	= { TLV_TYPE_T },
		[GSM48_IE_REPEAT_CIR]   = { TLV_TYPE_T },
		[GSM48_IE_REPEAT_SEQ]   = { TLV_TYPE_T },
		/* FIXME: more elements */
	},
};

/*! TLV parser definitions for TS 04.08 RR */
const struct tlv_definition gsm48_rr_att_tlvdef = {
	.def = {
		/* NOTE: Don't add IE 17 = MOBILE_ID here, it already used. */
		[GSM48_IE_VGCS_TARGET]		= { TLV_TYPE_TLV },
		[GSM48_IE_FRQSHORT_AFTER]	= { TLV_TYPE_FIXED, 9 },
		[GSM48_IE_MUL_RATE_CFG]		= { TLV_TYPE_TLV },
		[GSM48_IE_FREQ_L_AFTER]		= { TLV_TYPE_TLV },
		[GSM48_IE_MSLOT_DESC]		= { TLV_TYPE_TLV },
		[GSM48_IE_CHANMODE_2]		= { TLV_TYPE_TV },
		[GSM48_IE_FRQSHORT_BEFORE]	= { TLV_TYPE_FIXED, 9 },
		[GSM48_IE_CHANMODE_3]		= { TLV_TYPE_TV },
		[GSM48_IE_CHANMODE_4]		= { TLV_TYPE_TV },
		[GSM48_IE_CHANMODE_5]		= { TLV_TYPE_TV },
		[GSM48_IE_CHANMODE_6]		= { TLV_TYPE_TV },
		[GSM48_IE_CHANMODE_7]		= { TLV_TYPE_TV },
		[GSM48_IE_CHANMODE_8]		= { TLV_TYPE_TV },
		[GSM48_IE_FREQ_L_BEFORE]	= { TLV_TYPE_TLV },
		[GSM48_IE_CH_DESC_1_BEFORE]	= { TLV_TYPE_FIXED, 3 },
		[GSM48_IE_CH_DESC_2_BEFORE]	= { TLV_TYPE_FIXED, 3 },
		[GSM48_IE_F_CH_SEQ_BEFORE]	= { TLV_TYPE_FIXED, 9 },
		[GSM48_IE_CLASSMARK3]		= { TLV_TYPE_TLV },
		[GSM48_IE_MA_BEFORE]		= { TLV_TYPE_TLV },
		[GSM48_IE_RR_PACKET_UL]		= { TLV_TYPE_TLV },
		[GSM48_IE_RR_PACKET_DL]		= { TLV_TYPE_TLV },
		[GSM48_IE_CELL_CH_DESC]		= { TLV_TYPE_FIXED, 16 },
		[GSM48_IE_CHANMODE_1]		= { TLV_TYPE_TV },
		[GSM48_IE_CHDES_2_AFTER]	= { TLV_TYPE_FIXED, 3 },
		[GSM48_IE_MODE_SEC_CH]		= { TLV_TYPE_TV },
		[GSM48_IE_F_CH_SEQ_AFTER]		= { TLV_TYPE_FIXED, 9 },
		[GSM48_IE_EXTENDED_TSC_SET]	= { TLV_TYPE_TV },
		[GSM48_IE_MA_AFTER]		= { TLV_TYPE_TLV },
		[GSM48_IE_BA_RANGE]		= { TLV_TYPE_TLV },
		[GSM48_IE_GROUP_CHDES]		= { TLV_TYPE_TLV },
		[GSM48_IE_BA_LIST_PREF]		= { TLV_TYPE_TLV },
		[GSM48_IE_MOB_OVSERV_DIF]	= { TLV_TYPE_TLV },
		[GSM48_IE_REALTIME_DIFF]	= { TLV_TYPE_TLV },
		[GSM48_IE_START_TIME]		= { TLV_TYPE_FIXED, 2 },
		[GSM48_IE_TIMING_ADVANCE]	= { TLV_TYPE_TV },
		[GSM48_IE_GROUP_CIP_SEQ]	= { TLV_TYPE_SINGLE_TV },
		[GSM48_IE_CIP_MODE_SET]		= { TLV_TYPE_SINGLE_TV },
		[GSM48_IE_GPRS_RESUMPT]		= { TLV_TYPE_SINGLE_TV },
		[GSM48_IE_SYNC_IND]		= { TLV_TYPE_SINGLE_TV },
	},
};

/*! TLV parser definitions for TS 04.08 MM */
const struct tlv_definition gsm48_mm_att_tlvdef = {
	.def = {
		[GSM48_IE_MOBILE_ID]		= { TLV_TYPE_TLV },
		[GSM48_IE_NAME_LONG]		= { TLV_TYPE_TLV },
		[GSM48_IE_NAME_SHORT]		= { TLV_TYPE_TLV },
		[GSM48_IE_UTC]			= { TLV_TYPE_TV },
		[GSM48_IE_NET_TIME_TZ]		= { TLV_TYPE_FIXED, 7 },
		[GSM48_IE_LSA_IDENT]		= { TLV_TYPE_TLV },
		[GSM48_IE_NET_DST]		= { TLV_TYPE_TLV },

		[GSM48_IE_LOCATION_AREA]	= { TLV_TYPE_FIXED, 5 },
		[GSM48_IE_PRIORITY_LEV]		= { TLV_TYPE_SINGLE_TV },
		[GSM48_IE_FOLLOW_ON_PROC]	= { TLV_TYPE_T },
		[GSM48_IE_CTS_PERMISSION]	= { TLV_TYPE_T },
	},
};

static const struct value_string rr_cause_names[] = {
	{ GSM48_RR_CAUSE_NORMAL,		"Normal event" },
	{ GSM48_RR_CAUSE_ABNORMAL_UNSPEC,	"Abnormal release, unspecified" },
	{ GSM48_RR_CAUSE_ABNORMAL_UNACCT,	"Abnormal release, channel unacceptable" },
	{ GSM48_RR_CAUSE_ABNORMAL_TIMER,	"Abnormal release, timer expired" },
	{ GSM48_RR_CAUSE_ABNORMAL_NOACT,	"Abnormal release, no activity on radio path" },
	{ GSM48_RR_CAUSE_PREMPTIVE_REL,		"Preemptive release" },
	{ GSM48_RR_CAUSE_UTRAN_CFG_UNK,		"UTRAN configuration unknown" },
	{ GSM48_RR_CAUSE_HNDOVER_IMP,		"Handover impossible, timing advance out of range" },
	{ GSM48_RR_CAUSE_CHAN_MODE_UNACCT,	"Channel mode unacceptable" },
	{ GSM48_RR_CAUSE_FREQ_NOT_IMPL,		"Frequency not implemented" },
	{ GSM48_RR_CAUSE_LEAVE_GROUP_CA,	"Originator or talker leaving group call area" },
	{ GSM48_RR_CAUSE_LOW_LEVEL_FAIL,	"Lower layer failure" },
	{ GSM48_RR_CAUSE_CALL_CLEARED,		"Call already cleared" },
	{ GSM48_RR_CAUSE_SEMANT_INCORR,		"Semantically incorrect message" },
	{ GSM48_RR_CAUSE_INVALID_MAND_INF,	"Invalid mandatory information" },
	{ GSM48_RR_CAUSE_MSG_TYPE_N,		"Message type non-existent or not implemented" },
	{ GSM48_RR_CAUSE_MSG_TYPE_N_COMPAT,	"Message type not compatible with protocol state" },
	{ GSM48_RR_CAUSE_COND_IE_ERROR,		"Conditional IE error" },
	{ GSM48_RR_CAUSE_NO_CELL_ALLOC_A,	"No cell allocation available" },
	{ GSM48_RR_CAUSE_PROT_ERROR_UNSPC,	"Protocol error unspecified" },
	{ 0,					NULL },
};

/*! return string representation of RR Cause value */
const char *rr_cause_name(uint8_t cause)
{
	return get_value_string(rr_cause_names, cause);
}

/*! Return MCC-MNC-LAC-RAC as string, in a caller-provided output buffer.
 * \param[out] buf caller-provided output buffer
 * \param[in] buf_len size of buf in bytes
 * \param[in] rai  RAI to encode.
 * \returns buf
 */
char *osmo_rai_name_buf(char *buf, size_t buf_len, const struct gprs_ra_id *rai)
{
	snprintf(buf, buf_len, "%s-%s-%u-%u",
		 osmo_mcc_name(rai->mcc), osmo_mnc_name(rai->mnc, rai->mnc_3_digits), rai->lac,
		 rai->rac);
	return buf;
}

/*! Return MCC-MNC-LAC-RAC as string, in a static buffer.
 * \param[in] rai  RAI to encode.
 * \returns Static string buffer.
 */
const char *osmo_rai_name(const struct gprs_ra_id *rai)
{
	static __thread char buf[32];
	return osmo_rai_name_buf(buf, sizeof(buf), rai);
}

/*! Return MCC-MNC-LAC-RAC as string, in dynamically-allocated output buffer.
 * \param[in] ctx talloc context from which to allocate output buffer
 * \param[in] rai  RAI to encode.
 * \returns string representation in dynamically-allocated output buffer.
 */
char *osmo_rai_name_c(const void *ctx, const struct gprs_ra_id *rai)
{
	char *buf = talloc_size(ctx, 32);
	if (!buf)
		return NULL;
	return osmo_rai_name_buf(buf, 32, rai);
}

/* FIXME: convert to value_string */
static const char *cc_state_names[32] = {
	"NULL",
	"INITIATED",
	"MM_CONNECTION_PEND",
	"MO_CALL_PROC",
	"CALL_DELIVERED",
	"illegal state 5",
	"CALL_PRESENT",
	"CALL_RECEIVED",
	"CONNECT_REQUEST",
	"MO_TERM_CALL_CONF",
	"ACTIVE",
	"DISCONNECT_REQ",
	"DISCONNECT_IND",
	"illegal state 13",
	"illegal state 14",
	"illegal state 15",
	"illegal state 16",
	"illegal state 17",
	"illegal state 18",
	"RELEASE_REQ",
	"illegal state 20",
	"illegal state 21",
	"illegal state 22",
	"illegal state 23",
	"illegal state 24",
	"illegal state 25",
	"MO_ORIG_MODIFY",
	"MO_TERM_MODIFY",
	"CONNECT_IND",
	"illegal state 29",
	"illegal state 30",
	"illegal state 31",
};

/*! return string representation of CC State */
const char *gsm48_cc_state_name(uint8_t state)
{
	if (state < ARRAY_SIZE(cc_state_names))
		return cc_state_names[state];

	return "invalid";
}

static const struct value_string cc_msg_names[] = {
	{ GSM48_MT_CC_ALERTING,		"ALERTING" },
	{ GSM48_MT_CC_CALL_PROC,	"CALL_PROC" },
	{ GSM48_MT_CC_PROGRESS,		"PROGRESS" },
	{ GSM48_MT_CC_ESTAB,		"ESTAB" },
	{ GSM48_MT_CC_SETUP,		"SETUP" },
	{ GSM48_MT_CC_ESTAB_CONF,	"ESTAB_CONF" },
	{ GSM48_MT_CC_CONNECT,		"CONNECT" },
	{ GSM48_MT_CC_CALL_CONF,	"CALL_CONF" },
	{ GSM48_MT_CC_START_CC,		"START_CC" },
	{ GSM48_MT_CC_RECALL,		"RECALL" },
	{ GSM48_MT_CC_EMERG_SETUP,	"EMERG_SETUP" },
	{ GSM48_MT_CC_CONNECT_ACK,	"CONNECT_ACK" },
	{ GSM48_MT_CC_USER_INFO,	"USER_INFO" },
	{ GSM48_MT_CC_MODIFY_REJECT,	"MODIFY_REJECT" },
	{ GSM48_MT_CC_MODIFY,		"MODIFY" },
	{ GSM48_MT_CC_HOLD,		"HOLD" },
	{ GSM48_MT_CC_HOLD_ACK,		"HOLD_ACK" },
	{ GSM48_MT_CC_HOLD_REJ,		"HOLD_REJ" },
	{ GSM48_MT_CC_RETR,		"RETR" },
	{ GSM48_MT_CC_RETR_ACK,		"RETR_ACK" },
	{ GSM48_MT_CC_RETR_REJ,		"RETR_REJ" },
	{ GSM48_MT_CC_MODIFY_COMPL,	"MODIFY_COMPL" },
	{ GSM48_MT_CC_DISCONNECT,	"DISCONNECT" },
	{ GSM48_MT_CC_RELEASE_COMPL,	"RELEASE_COMPL" },
	{ GSM48_MT_CC_RELEASE,		"RELEASE" },
	{ GSM48_MT_CC_STOP_DTMF,	"STOP_DTMF" },
	{ GSM48_MT_CC_STOP_DTMF_ACK,	"STOP_DTMF_ACK" },
	{ GSM48_MT_CC_STATUS_ENQ,	"STATUS_ENQ" },
	{ GSM48_MT_CC_START_DTMF,	"START_DTMF" },
	{ GSM48_MT_CC_START_DTMF_ACK,	"START_DTMF_ACK" },
	{ GSM48_MT_CC_START_DTMF_REJ,	"START_DTMF_REJ" },
	{ GSM48_MT_CC_CONG_CTRL,	"CONG_CTRL" },
	{ GSM48_MT_CC_FACILITY,		"FACILITY" },
	{ GSM48_MT_CC_STATUS,		"STATUS" },
	{ GSM48_MT_CC_NOTIFY,		"NOTFIY" },
	{ 0,				NULL }
};

/*! return string representation of CC Message Type */
const char *gsm48_cc_msg_name(uint8_t msgtype)
{
	return get_value_string(cc_msg_names, msgtype);
}


static const struct value_string rr_msg_names[] = {
	/* Channel establishment messages */
	{ GSM48_MT_RR_INIT_REQ,		"RR INITIALISATION REQUEST" },
	{ GSM48_MT_RR_ADD_ASS,		"ADDITIONAL ASSIGNMENT" },
	{ GSM48_MT_RR_IMM_ASS,		"IMMEDIATE ASSIGNMENT" },
	{ GSM48_MT_RR_IMM_ASS_EXT,	"MMEDIATE ASSIGNMENT EXTENDED" },
	{ GSM48_MT_RR_IMM_ASS_REJ,	"IMMEDIATE ASSIGNMENT REJECT" },
	{ GSM48_MT_RR_DTM_ASS_FAIL,	"DTM ASSIGNMENT FAILURE" },
	{ GSM48_MT_RR_DTM_REJECT,	"DTM REJECT" },
	{ GSM48_MT_RR_DTM_REQUEST,	"DTM REQUEST" },
	{ GSM48_MT_RR_PACKET_ASS,	"PACKET ASSIGNMENT" },

	/* Ciphering messages */
	{ GSM48_MT_RR_CIPH_M_CMD,	"CIPHERING MODE COMMAND" },
	{ GSM48_MT_RR_CIPH_M_COMPL,	"CIPHERING MODE COMPLETE" },

	/* Configuration change messages */
	{ GSM48_MT_RR_CFG_CHG_CMD,	"CONFIGURATION CHANGE COMMAND" },
	{ GSM48_MT_RR_CFG_CHG_ACK,	"CONFIGURATION CHANGE ACK" },
	{ GSM48_MT_RR_CFG_CHG_REJ,	"CONFIGURATION CHANGE REJECT" },

	/* Handover messages */
	{ GSM48_MT_RR_ASS_CMD,		"ASSIGNMENT COMMAND" },
	{ GSM48_MT_RR_ASS_COMPL,	"ASSIGNMENT COMPLETE" },
	{ GSM48_MT_RR_ASS_FAIL,		"ASSIGNMENT FAILURE" },
	{ GSM48_MT_RR_HANDO_CMD,	"HANDOVER COMMAND" },
	{ GSM48_MT_RR_HANDO_COMPL,	"HANDOVER COMPLETE" },
	{ GSM48_MT_RR_HANDO_FAIL,	"HANDOVER FAILURE" },
	{ GSM48_MT_RR_HANDO_INFO,	"PHYSICAL INFORMATION" },
	{ GSM48_MT_RR_DTM_ASS_CMD,	"DTM ASSIGNMENT COMMAND" },

	{ GSM48_MT_RR_CELL_CHG_ORDER,	"RR-CELL CHANGE ORDER" },
	{ GSM48_MT_RR_PDCH_ASS_CMD,	"PDCH ASSIGNMENT COMMAND" },

	/* Channel release messages */
	{ GSM48_MT_RR_CHAN_REL,		"CHANNEL RELEASE" },
	{ GSM48_MT_RR_PART_REL,		"PARTIAL RELEASE" },
	{ GSM48_MT_RR_PART_REL_COMP,	"PARTIAL RELEASE COMPLETE" },

	/* Paging and Notification messages */
	{ GSM48_MT_RR_PAG_REQ_1,		"PAGING REQUEST TYPE 1" },
	{ GSM48_MT_RR_PAG_REQ_2,		"PAGING REQUEST TYPE 2" },
	{ GSM48_MT_RR_PAG_REQ_3,		"PAGING REQUEST TYPE 3" },
	{ GSM48_MT_RR_PAG_RESP,			"PAGING RESPONSE" },
	{ GSM48_MT_RR_NOTIF_NCH,		"NOTIFICATION/NCH" },
	{ GSM48_MT_RR_NOTIF_FACCH,		"(Reserved)" },
	{ GSM48_MT_RR_NOTIF_RESP,		"NOTIFICATION/RESPONSE" },
	{ GSM48_MT_RR_PACKET_NOTIF,		"PACKET NOTIFICATION" },
	/* 3G Specific messages */
	{ GSM48_MT_RR_UTRAN_CLSM_CHG,		"UTRAN Classmark Change" },
	{ GSM48_MT_RR_CDMA2K_CLSM_CHG,		"cdma 2000 Classmark Change" },
	{ GSM48_MT_RR_IS_TO_UTRAN_HANDO,	"Inter System to UTRAN Handover Command" },
	{ GSM48_MT_RR_IS_TO_CDMA2K_HANDO,	"Inter System to cdma2000 Handover Command" },

	/* System information messages */
	{ GSM48_MT_RR_SYSINFO_8,	"SYSTEM INFORMATION TYPE 8" },
	{ GSM48_MT_RR_SYSINFO_1,	"SYSTEM INFORMATION TYPE 1" },
	{ GSM48_MT_RR_SYSINFO_2,	"SYSTEM INFORMATION TYPE 2" },
	{ GSM48_MT_RR_SYSINFO_3,	"SYSTEM INFORMATION TYPE 3" },
	{ GSM48_MT_RR_SYSINFO_4,	"SYSTEM INFORMATION TYPE 4" },
	{ GSM48_MT_RR_SYSINFO_5,	"SYSTEM INFORMATION TYPE 5" },
	{ GSM48_MT_RR_SYSINFO_6,	"SYSTEM INFORMATION TYPE 6" },
	{ GSM48_MT_RR_SYSINFO_7,	"SYSTEM INFORMATION TYPE 7" },
	{ GSM48_MT_RR_SYSINFO_2bis,	"SYSTEM INFORMATION TYPE 2bis" },
	{ GSM48_MT_RR_SYSINFO_2ter,	"SYSTEM INFORMATION TYPE 2ter" },
	{ GSM48_MT_RR_SYSINFO_2quater,	"SYSTEM INFORMATION TYPE 2quater" },
	{ GSM48_MT_RR_SYSINFO_5bis,	"SYSTEM INFORMATION TYPE 5bis" },
	{ GSM48_MT_RR_SYSINFO_5ter,	"SYSTEM INFORMATION TYPE 5ter" },
	{ GSM48_MT_RR_SYSINFO_9,	"SYSTEM INFORMATION TYPE 9" },
	{ GSM48_MT_RR_SYSINFO_13,	"SYSTEM INFORMATION TYPE 13" },
	{ GSM48_MT_RR_SYSINFO_16,	"SYSTEM INFORMATION TYPE 16" },
	{ GSM48_MT_RR_SYSINFO_17,	"SYSTEM INFORMATION TYPE 17" },
	{ GSM48_MT_RR_SYSINFO_18,	"SYSTEM INFORMATION TYPE 18" },
	{ GSM48_MT_RR_SYSINFO_19,	"SYSTEM INFORMATION TYPE 19" },
	{ GSM48_MT_RR_SYSINFO_20,	"SYSTEM INFORMATION TYPE 20" },

	/* Miscellaneous messages */
	{ GSM48_MT_RR_CHAN_MODE_MODIF,		"CHANNEL MODE MODIFY" },
	{ GSM48_MT_RR_STATUS,			"RR STATUS" },
	{ GSM48_MT_RR_CHAN_MODE_MODIF_ACK,	"CHANNEL MODE MODIFY ACKNOWLEDGE" },
	{ GSM48_MT_RR_FREQ_REDEF,		"FREQUENCY REDEFINITION" },
	{ GSM48_MT_RR_MEAS_REP,			"MEASUREMENT REPORT" },
	{ GSM48_MT_RR_CLSM_CHG,			"CLASSMARK CHANGE" },
	{ GSM48_MT_RR_CLSM_ENQ,			"CLASSMARK ENQUIRY" },
	{ GSM48_MT_RR_EXT_MEAS_REP,		"EXTENDED MEASUREMENT REPORT" },
	{ GSM48_MT_RR_EXT_MEAS_REP_ORD,		"EXTENDED MEASUREMENT ORDER" },
	{ GSM48_MT_RR_GPRS_SUSP_REQ,		"GPRS SUSPENSION REQUEST" },
	{ GSM48_MT_RR_DTM_INFO,			"DTM INFORMATION" },

	/* VGCS uplink control messages */
	{ GSM48_MT_RR_VGCS_UPL_GRANT,	"VGCS UPLINK GRANT" },
	{ GSM48_MT_RR_UPLINK_RELEASE,	"UPLINK RELEASE" },
	{ GSM48_MT_RR_UPLINK_FREE,	"0c" },
	{ GSM48_MT_RR_UPLINK_BUSY,	"UPLINK BUSY" },
	{ GSM48_MT_RR_TALKER_IND,	"TALKER INDICATION" },

	/* Application messages */
	{ GSM48_MT_RR_APP_INFO,		"Application Information" },
	{ 0,				NULL }
};

/*! return string representation of RR Message Type */
const char *gsm48_rr_msg_name(uint8_t msgtype)
{
	return get_value_string(rr_msg_names, msgtype);
}

/* 3GPP TS 44.018 Table 10.4.2 */
static const struct value_string rr_msg_type_short_names[] = {
	{ GSM48_MT_RR_SH_SI10,		"System Information Type 10" },
	{ GSM48_MT_RR_SH_FACCH,		"Notification/FACCH" },
	{ GSM48_MT_RR_SH_UL_FREE,	"Uplink Free" },
	{ GSM48_MT_RR_SH_MEAS_REP,	"Enhanced Measurement Report (uplink)" },
	{ GSM48_MT_RR_SH_MEAS_INFO,	"Measurement Information (downlink)" },
	{ GSM48_MT_RR_SH_VGCS_RECON,	"VBS/VGCS Reconfigure" },
	{ GSM48_MT_RR_SH_VGCS_RECON2,	"VBS/VGCS Reconfigure2" },
	{ GSM48_MT_RR_SH_VGCS_INFO,	"VGCS Additional Information" },
	{ GSM48_MT_RR_SH_VGCS_SMS,	"VGCS SMS Information" },
	{ GSM48_MT_RR_SH_SI10bis,	"System Information Type 10bis" },
	{ GSM48_MT_RR_SH_SI10ter,	"System Information Type 10ter" },
	{ GSM48_MT_RR_SH_VGCS_NEIGH,	"VGCS Neighbour Cell Information" },
	{ GSM48_MT_RR_SH_APP_DATA,	"Notify Application Data" },
	{ 0,				NULL }
};

/*! return string representation of RR Message Type using the RR short protocol discriminator */
const char *gsm48_rr_short_pd_msg_name(uint8_t msgtype)
{
	return get_value_string(rr_msg_type_short_names, msgtype);
}

const struct value_string gsm48_chan_mode_names[] = {
	{ GSM48_CMODE_SIGN,		"SIGNALLING" },
	{ GSM48_CMODE_SPEECH_V1,	"SPEECH_V1" },
	{ GSM48_CMODE_SPEECH_EFR,	"SPEECH_EFR" },
	{ GSM48_CMODE_SPEECH_AMR,	"SPEECH_AMR" },
	{ GSM48_CMODE_DATA_14k5,	"DATA_14k5" },
	{ GSM48_CMODE_DATA_12k0,	"DATA_12k0" },
	{ GSM48_CMODE_DATA_6k0,		"DATA_6k0" },
	{ GSM48_CMODE_DATA_3k6,		"DATA_3k6" },
	{ GSM48_CMODE_SPEECH_V1_VAMOS,	"SPEECH_V1_VAMOS" },
	{ GSM48_CMODE_SPEECH_V2_VAMOS,	"SPEECH_V2_VAMOS" },
	{ GSM48_CMODE_SPEECH_V3_VAMOS,	"SPEECH_V3_VAMOS" },
	{ GSM48_CMODE_SPEECH_V5_VAMOS,	"SPEECH_V5_VAMOS" },
	{ 0,				NULL },
};

/*! Translate GSM48_CMODE_SPEECH_* to its corresponding GSM48_CMODE_SPEECH_*_VAMOS mode.
 * If the mode has no equivalent VAMOS mode, return a negative value.
 */
enum gsm48_chan_mode gsm48_chan_mode_to_vamos(enum gsm48_chan_mode mode)
{
	switch (mode) {
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_V1_VAMOS:
		return GSM48_CMODE_SPEECH_V1_VAMOS;
	case GSM48_CMODE_SPEECH_EFR:
	case GSM48_CMODE_SPEECH_V2_VAMOS:
		return GSM48_CMODE_SPEECH_V2_VAMOS;
	case GSM48_CMODE_SPEECH_AMR:
	case GSM48_CMODE_SPEECH_V3_VAMOS:
		return GSM48_CMODE_SPEECH_V3_VAMOS;
	case GSM48_CMODE_SPEECH_V5_VAMOS:
		return GSM48_CMODE_SPEECH_V5_VAMOS;
	default:
		return -1;
	}
}

/*! Translate GSM48_CMODE_SPEECH_*_VAMOS to its corresponding GSM48_CMODE_SPEECH_* non-vamos mode.
 * If the mode is not a VAMOS mode, return the unchanged mode.
 */
enum gsm48_chan_mode gsm48_chan_mode_to_non_vamos(enum gsm48_chan_mode mode)
{
	switch (mode) {
	case GSM48_CMODE_SPEECH_V1_VAMOS:
		return GSM48_CMODE_SPEECH_V1;
	case GSM48_CMODE_SPEECH_V2_VAMOS:
		return GSM48_CMODE_SPEECH_EFR;
	case GSM48_CMODE_SPEECH_V3_VAMOS:
		return GSM48_CMODE_SPEECH_AMR;
	default:
		return mode;
	}
}

const struct value_string gsm_chan_t_names[] = {
	{ GSM_LCHAN_NONE,	"NONE" },
	{ GSM_LCHAN_SDCCH,	"SDCCH" },
	{ GSM_LCHAN_TCH_F,	"TCH_F" },
	{ GSM_LCHAN_TCH_H,	"TCH_H" },
	{ GSM_LCHAN_UNKNOWN,	"UNKNOWN" },
	{ GSM_LCHAN_CCCH,	"CCCH" },
	{ GSM_LCHAN_PDTCH,	"PDTCH" },
	{ GSM_LCHAN_CBCH,	"CBCH" },
	{ 0,			NULL },
};

static const struct value_string mi_type_names[] = {
	{ GSM_MI_TYPE_NONE,	"NONE" },
	{ GSM_MI_TYPE_IMSI,	"IMSI" },
	{ GSM_MI_TYPE_IMEI,	"IMEI" },
	{ GSM_MI_TYPE_IMEISV,	"IMEI-SV" },
	{ GSM_MI_TYPE_TMSI,	"TMSI" },
	{ 0,			NULL }
};

/*! return string representation of Mobile Identity Type */
const char *gsm48_mi_type_name(uint8_t mi)
{
	return get_value_string(mi_type_names, mi);
}

/*! Deprecated, see osmo_mobile_identity instead.
 * Return a human readable representation of a Mobile Identity in caller-provided buffer.
 * \param[out] buf caller-provided output buffer
 * \param[in] buf_len size of buf in bytes
 * \param[in] mi  Mobile Identity buffer containing 3GPP TS 04.08 style MI type and data.
 * \param[in] mi_len  Length of mi.
 * \return buf
 */
char *osmo_mi_name_buf(char *buf, size_t buf_len, const uint8_t *mi, uint8_t mi_len)
{
	uint8_t mi_type;
	uint32_t tmsi;
	char mi_string[GSM48_MI_SIZE];

	mi_type = (mi && mi_len) ? (mi[0] & GSM_MI_TYPE_MASK) : GSM_MI_TYPE_NONE;

	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		/* Table 10.5.4.3, reverse generate_mid_from_tmsi */
		if (mi_len == GSM48_TMSI_LEN && mi[0] == (0xf0 | GSM_MI_TYPE_TMSI)) {
			tmsi = osmo_load32be(&mi[1]);
			snprintf(buf, buf_len, "TMSI-0x%08" PRIX32, tmsi);
		} else {
			snprintf(buf, buf_len, "TMSI-invalid");
		}
		return buf;

	case GSM_MI_TYPE_IMSI:
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		osmo_bcd2str(mi_string, sizeof(mi_string), mi, 1, (mi_len * 2) - (mi[0] & GSM_MI_ODD ? 0 : 1), true);
		snprintf(buf, buf_len, "%s-%s", gsm48_mi_type_name(mi_type), mi_string);
		return buf;

	default:
		snprintf(buf, buf_len, "unknown");
		return buf;
	}
}

/*! Deprecated, see osmo_mobile_identity instead.
 * Return a human readable representation of a Mobile Identity in static buffer.
 * \param[in] mi  Mobile Identity buffer containing 3GPP TS 04.08 style MI type and data.
 * \param[in] mi_len  Length of mi.
 * \return A string like "IMSI-1234567", "TMSI-0x1234ABCD" or "unknown", "TMSI-invalid"...
 */
const char *osmo_mi_name(const uint8_t *mi, uint8_t mi_len)
{
	static __thread char mi_name[10 + GSM48_MI_SIZE + 1];
	return osmo_mi_name_buf(mi_name, sizeof(mi_name), mi, mi_len);
}

/*! Deprecated, see osmo_mobile_identity instead.
 * Return a human readable representation of a Mobile Identity in dynamically-allocated buffer.
 * \param[in] ctx talloc context from which to allocate output buffer
 * \param[in] mi  Mobile Identity buffer containing 3GPP TS 04.08 style MI type and data.
 * \param[in] mi_len  Length of mi.
 * \return A string like "IMSI-1234567", "TMSI-0x1234ABCD" or "unknown", "TMSI-invalid" in a
 * 	   dynamically-allocated output buffer.
 */
char *osmo_mi_name_c(const void *ctx, const uint8_t *mi, uint8_t mi_len)
{
	size_t buf_len = 10 + GSM48_MI_SIZE + 1;
	char *mi_name = talloc_size(ctx, buf_len);
	if (!mi_name)
		return NULL;
	return osmo_mi_name_buf(mi_name, buf_len, mi, mi_len);
}

/*! Extract Mobile Identity from encoded bytes (3GPP TS 24.008 10.5.1.4).
 *
 * On failure (negative return value), mi->type == GSM_MI_TYPE_NONE, mi->string[] is all-zero and mi->tmsi ==
 * GSM_RESERVED_TMSI.
 *
 * On success, mi->type reflects the decoded Mobile Identity type (GSM_MI_TYPE_IMSI, GSM_MI_TYPE_TMSI, GSM_MI_TYPE_IMEI
 * or GSM_MI_TYPE_IMEISV).
 *
 * On success, mi->string always contains a human readable representation of the Mobile Identity digits: IMSI, IMEI and
 * IMEISV as digits like "12345678", and TMSI as "0x" and 8 hexadecimal digits like "0x1234abcd".
 *
 * mi->tmsi contains the uint32_t TMSI value iff the extracted Mobile Identity was a TMSI, or GSM_RESERVED_TMSI
 * otherwise.
 *
 * \param[out] mi  Return buffer for decoded Mobile Identity.
 * \param[in] mi_data  The encoded Mobile Identity octets.
 * \param[in] mi_len  Number of octets in mi_data.
 * \param[in] allow_hex  If false, hexadecimal digits (>9) result in an error return value.
 * \returns 0 on success, negative on error: -EBADMSG = invalid length indication or invalid data,
 *          -EINVAL = unknown Mobile Identity type.
 */
int osmo_mobile_identity_decode(struct osmo_mobile_identity *mi, const uint8_t *mi_data, uint8_t mi_len,
				bool allow_hex)
{
	int rc;
	int nibbles_len;
	char *str = NULL; /* initialize to avoid uninitialized false warnings on some gcc versions (11.1.0) */
	size_t str_size = 0; /* initialize to avoid uninitialized false warnings on some gcc versions (11.1.0) */

	if (!mi_data || mi_len < 1)
		return -EBADMSG;

	nibbles_len = (mi_len - 1) * 2 + ((mi_data[0] & GSM_MI_ODD) ? 1 : 0);

	*mi = (struct osmo_mobile_identity){
		.type = mi_data[0] & GSM_MI_TYPE_MASK,
	};

	/* First do length checks */
	switch (mi->type) {
	case GSM_MI_TYPE_TMSI:
		mi->tmsi = GSM_RESERVED_TMSI;
		if (nibbles_len != (GSM23003_TMSI_NUM_BYTES * 2)) {
			rc = -EBADMSG;
			goto return_error;
		}
		break;

	case GSM_MI_TYPE_IMSI:
		if (nibbles_len < GSM23003_IMSI_MIN_DIGITS || nibbles_len > GSM23003_IMSI_MAX_DIGITS) {
			rc = -EBADMSG;
			goto return_error;
		}
		str = mi->imsi;
		str_size = sizeof(mi->imsi);
		break;

	case GSM_MI_TYPE_IMEI:
		if (nibbles_len != GSM23003_IMEI_NUM_DIGITS && nibbles_len != GSM23003_IMEI_NUM_DIGITS_NO_CHK) {
			rc = -EBADMSG;
			goto return_error;
		}
		str = mi->imei;
		str_size = sizeof(mi->imei);
		break;

	case GSM_MI_TYPE_IMEISV:
		if (nibbles_len != GSM23003_IMEISV_NUM_DIGITS) {
			rc = -EBADMSG;
			goto return_error;
		}
		str = mi->imeisv;
		str_size = sizeof(mi->imeisv);
		break;

	default:
		rc = -EINVAL;
		goto return_error;
	}

	/* Decode BCD digits */
	switch (mi->type) {
	case GSM_MI_TYPE_TMSI:
		/* MI is a 32bit integer TMSI. Length has been checked above. */
		if ((mi_data[0] & 0xf0) != 0xf0) {
			/* A TMSI always has the first nibble == 0xf */
			rc = -EBADMSG;
			goto return_error;
		}
		mi->tmsi = osmo_load32be(&mi_data[1]);
		return 0;

	case GSM_MI_TYPE_IMSI:
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* If the length is even, the last nibble (higher nibble of last octet) must be 0xf */
		if (!(mi_data[0] & GSM_MI_ODD)
		    && ((mi_data[mi_len - 1] & 0xf0) != 0xf0)) {
			rc = -EBADMSG;
			goto return_error;
		}
		rc = osmo_bcd2str(str, str_size, mi_data, 1, 1 + nibbles_len, allow_hex);
		/* check mi->str printing rc */
		if (rc < 1 || rc >= str_size) {
			rc = -EBADMSG;
			goto return_error;
		}
		return 0;

	default:
		/* Already handled above, but as future bug paranoia: */
		rc = -EINVAL;
		goto return_error;
	}

return_error:
	*mi = (struct osmo_mobile_identity){
		.type = GSM_MI_TYPE_NONE,
	};
	return rc;
}

/*! Return the number of encoded Mobile Identity octets, without actually encoding.
 * Useful to write tag-length header before encoding the MI.
 * \param[in] mi  Mobile Identity.
 * \param[out] mi_digits  If not NULL, store the number of nibbles of used MI data (i.e. strlen(mi->string) or 8 for a TMSI).
 * \return octets that osmo_mobile_identity_encode_msgb() will write for this mi.
 */
int osmo_mobile_identity_encoded_len(const struct osmo_mobile_identity *mi, int *mi_digits)
{
	int mi_nibbles;
	if (!mi)
		return -EINVAL;
	switch (mi->type) {
	case GSM_MI_TYPE_TMSI:
		mi_nibbles = GSM23003_TMSI_NUM_BYTES * 2;
		break;
	case GSM_MI_TYPE_IMSI:
		mi_nibbles = strlen(mi->imsi);
		if (mi_nibbles < GSM23003_IMSI_MIN_DIGITS
		    || mi_nibbles > GSM23003_IMSI_MAX_DIGITS)
			return -EINVAL;
		break;
	case GSM_MI_TYPE_IMEI:
		mi_nibbles = strlen(mi->imei);
		if (mi_nibbles < GSM23003_IMEI_NUM_DIGITS_NO_CHK
		    || mi_nibbles > GSM23003_IMEI_NUM_DIGITS)
			return -EINVAL;
		break;
	case GSM_MI_TYPE_IMEISV:
		mi_nibbles = strlen(mi->imeisv);
		if (mi_nibbles != GSM23003_IMEISV_NUM_DIGITS)
			return -EINVAL;
		break;
	default:
		return -ENOTSUP;
	}

	if (mi_digits)
		*mi_digits = mi_nibbles;

	/* one type nibble, plus the MI nibbles, plus a filler nibble to complete the last octet:
	 * mi_octets = ceil((float)(mi_nibbles + 1) / 2)
	 */
	return (mi_nibbles + 2) / 2;
}

/*! Encode Mobile Identity from uint32_t (TMSI) or digits string (all others) (3GPP TS 24.008 10.5.1.4).
 *
 * \param[out] buf  Return buffer for encoded Mobile Identity.
 * \param[in] buflen  sizeof(buf).
 * \param[in] mi  Mobile identity to encode.
 * \param[in] allow_hex  If false, hexadecimal digits (>9) result in an error return value.
 * \returns Amount of bytes written to buf, or negative on error.
 */
int osmo_mobile_identity_encode_buf(uint8_t *buf, size_t buflen, const struct osmo_mobile_identity *mi, bool allow_hex)
{
	int rc;
	int nibbles_len;
	int mi_octets;
	const char *mi_str;

	if (!buf || !buflen)
		return -EIO;

	mi_octets = osmo_mobile_identity_encoded_len(mi, &nibbles_len);
	if (mi_octets < 0)
		return mi_octets;
	if (mi_octets > buflen)
		return -ENOSPC;

	buf[0] = (mi->type & GSM_MI_TYPE_MASK) | ((nibbles_len & 1) ? GSM_MI_ODD : 0);

	switch (mi->type) {
	case GSM_MI_TYPE_TMSI:
		buf[0] |= 0xf0;
		osmo_store32be(mi->tmsi, &buf[1]);
		return mi_octets;

	case GSM_MI_TYPE_IMSI:
		mi_str = mi->imsi;
		break;
	case GSM_MI_TYPE_IMEI:
		mi_str = mi->imei;
		break;
	case GSM_MI_TYPE_IMEISV:
		mi_str = mi->imeisv;
		break;
	default:
		return -ENOTSUP;
	}
	rc = osmo_str2bcd(buf, buflen, mi_str, 1, -1, allow_hex);
	if (rc != mi_octets)
		return -EINVAL;
	return mi_octets;
}

/*! Encode Mobile Identity type and BCD digits, appended to a msgb.
 * Example to add a GSM48_IE_MOBILE_ID IEI with tag and length to a msgb:
 *
 *  struct osmo_mobile_identity mi = { .type = GSM_MI_TYPE_IMSI };
 *  OSMO_STRLCPY_ARRAY(mi.imsi, "1234567890123456");
 *  uint8_t *l = msgb_tl_put(msg, GSM48_IE_MOBILE_ID);
 *  int rc = osmo_mobile_identity_encode_msgb(msg, &mi, false);
 *  if (rc < 0)
 *          goto error;
 *  *l = rc;
 *
 * Example to add a BSSGP_IE_IMSI with tag and variable-size length, where the
 * length needs to be known at the time of writing the IE tag-length header:
 *
 *  struct osmo_mobile_identity mi = { .type = GSM_MI_TYPE_IMSI, };
 *  OSMO_STRLCPY_ARRAY(mi.imsi, pinfo->imsi);
 *  msgb_tvl_put(msg, BSSGP_IE_IMSI, osmo_mobile_identity_encoded_len(&mi, NULL));
 *  if (osmo_mobile_identity_encode_msgb(msg, &mi, false) < 0)
 *          goto error;
 */
int osmo_mobile_identity_encode_msgb(struct msgb *msg, const struct osmo_mobile_identity *mi, bool allow_hex)
{
	int rc = osmo_mobile_identity_encode_buf(msg->tail, msgb_tailroom(msg), mi, allow_hex);
	if (rc < 0)
		return rc;
	msgb_put(msg, rc);
	return rc;
}

/*! Extract Mobile Identity from a Complete Layer 3 message.
 *
 * Determine the Mobile Identity data and call osmo_mobile_identity_decode() to return a decoded struct
 * osmo_mobile_identity.
 *
 * \param[out] mi  Return buffer for decoded Mobile Identity.
 * \param[in] msg  The Complete Layer 3 message to extract from (LU, CM Service Req or Paging Resp).
 * \returns 0 on success, negative on error: return codes as defined in osmo_mobile_identity_decode(), or
 *          -ENOTSUP = not a Complete Layer 3 message,
 */
int osmo_mobile_identity_decode_from_l3(struct osmo_mobile_identity *mi, struct msgb *msg, bool allow_hex)
{
	const struct gsm48_hdr *gh;
	int8_t pdisc = 0;
	uint8_t mtype = 0;
	const struct gsm48_loc_upd_req *lu;
	const uint8_t *cm2_buf;
	uint8_t cm2_len;
	const uint8_t *mi_start;
	const struct gsm48_pag_resp *paging_response;
	const uint8_t *mi_data;
	uint8_t mi_len;
	const struct gsm48_imsi_detach_ind *idi;

	*mi = (struct osmo_mobile_identity){
		.type = GSM_MI_TYPE_NONE,
		.tmsi = GSM_RESERVED_TMSI,
	};

	if (msgb_l3len(msg) < sizeof(*gh))
		return -EBADMSG;

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);
	mtype = gsm48_hdr_msg_type(gh);

	switch (pdisc) {
	case GSM48_PDISC_MM:

		switch (mtype) {
		case GSM48_MT_MM_LOC_UPD_REQUEST:
			/* First make sure that lu-> can be dereferenced */
			if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*lu))
				return -EBADMSG;

			/* Now we know there is enough msgb data to read a lu->mi_len, so also check that */
			lu = (struct gsm48_loc_upd_req*)gh->data;
			if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*lu) + lu->mi_len)
				return -EBADMSG;
			mi_data = lu->mi;
			mi_len = lu->mi_len;
			goto got_mi;

		case GSM48_MT_MM_CM_SERV_REQ:
		case GSM48_MT_MM_CM_REEST_REQ:
			/* Unfortunately in Phase1 the Classmark2 length is variable, so we cannot
			 * just use gsm48_service_request struct, and need to parse it manually. */
			if (msgb_l3len(msg) < sizeof(*gh) + 2)
				return -EBADMSG;

			cm2_len = gh->data[1];
			cm2_buf = gh->data + 2;
			goto got_cm2;

		case GSM48_MT_MM_IMSI_DETACH_IND:
			if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*idi))
				return -EBADMSG;
			idi = (struct gsm48_imsi_detach_ind*) gh->data;
			mi_data = idi->mi;
			mi_len = idi->mi_len;
			goto got_mi;

		case GSM48_MT_MM_ID_RESP:
			if (msgb_l3len(msg) < sizeof(*gh) + 2)
				return -EBADMSG;
			mi_data = gh->data+1;
			mi_len = gh->data[0];
			goto got_mi;

		default:
			break;
		}
		break;

	case GSM48_PDISC_RR:

		switch (mtype) {
		case GSM48_MT_RR_PAG_RESP:
			if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*paging_response))
				return -EBADMSG;
			paging_response = (struct gsm48_pag_resp*)gh->data;
			cm2_len = paging_response->cm2_len;
			cm2_buf = (uint8_t*)&paging_response->cm2;
			goto got_cm2;

		default:
			break;
		}
		break;
	}

	return -ENOTSUP;

got_cm2:
	/* MI (Mobile Identity) LV follows the Classmark2 */

	/* There must be at least a mi_len byte after the CM2 */
	if (cm2_buf + cm2_len + 1 > msg->tail)
		return -EBADMSG;

	mi_start = cm2_buf + cm2_len;
	mi_len = mi_start[0];
	mi_data = mi_start + 1;

got_mi:
	/* mi_data points at the start of the Mobile Identity coding of mi_len bytes */
	if (mi_data + mi_len > msg->tail)
		return -EBADMSG;

	return osmo_mobile_identity_decode(mi, mi_data, mi_len, allow_hex);
}

/*! Return a human readable representation of a struct osmo_mobile_identity.
 * Write a string like "IMSI-1234567", "TMSI-0x1234ABCD" or "NONE", "NULL".
 * \param[out] buf  String buffer to write to.
 * \param[in] buflen  sizeof(buf).
 * \param[in] mi  Decoded Mobile Identity data.
 * \return the strlen() of the string written when buflen is sufficiently large, like snprintf().
 */
int osmo_mobile_identity_to_str_buf(char *buf, size_t buflen, const struct osmo_mobile_identity *mi)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	if (!mi)
		return snprintf(buf, buflen, "NULL");
	OSMO_STRBUF_PRINTF(sb, "%s", gsm48_mi_type_name(mi->type));
	switch (mi->type) {
	case GSM_MI_TYPE_TMSI:
		OSMO_STRBUF_PRINTF(sb, "-0x%08" PRIX32, mi->tmsi);
		break;
	case GSM_MI_TYPE_IMSI:
		OSMO_STRBUF_PRINTF(sb, "-%s", mi->imsi);
		break;
	case GSM_MI_TYPE_IMEI:
		OSMO_STRBUF_PRINTF(sb, "-%s", mi->imei);
		break;
	case GSM_MI_TYPE_IMEISV:
		OSMO_STRBUF_PRINTF(sb, "-%s", mi->imeisv);
		break;
	default:
		break;
	}
	return sb.chars_needed;
}

/*! Like osmo_mobile_identity_to_str_buf(), but return the string in a talloc buffer.
 * \param[in] ctx  Talloc context to allocate from.
 * \param[in] mi  Decoded Mobile Identity data.
 * \return a string like "IMSI-1234567", "TMSI-0x1234ABCD" or "NONE", "NULL".
 */
char *osmo_mobile_identity_to_str_c(void *ctx, const struct osmo_mobile_identity *mi)
{
        OSMO_NAME_C_IMPL(ctx, 32, "ERROR", osmo_mobile_identity_to_str_buf, mi)
}

/*! Compare two osmo_mobile_identity structs, returning typical cmp() result.
 * \param[in] a  Left side osmo_mobile_identity.
 * \param[in] b  Right side osmo_mobile_identity.
 * \returns 0 if both are equal, -1 if a < b, 1 if a > b.
 */
int osmo_mobile_identity_cmp(const struct osmo_mobile_identity *a, const struct osmo_mobile_identity *b)
{
	int cmp;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;
	cmp = OSMO_CMP(a->type, b->type);
	if (cmp)
		return cmp;
	switch (a->type) {
	case GSM_MI_TYPE_TMSI:
		return OSMO_CMP(a->tmsi, b->tmsi);
	case GSM_MI_TYPE_IMSI:
		return strncmp(a->imsi, b->imsi, sizeof(a->imsi));
	case GSM_MI_TYPE_IMEI:
		return strncmp(a->imei, b->imei, sizeof(a->imei));
	case GSM_MI_TYPE_IMEISV:
		return strncmp(a->imeisv, b->imeisv, sizeof(a->imeisv));
	default:
		/* No known type, but both have the same type. */
		return 0;
	}
}

/*! Checks is particular message is cipherable in A/Gb mode according to
 *         3GPP TS 24.008 § 4.7.1.2
 *  \param[in] hdr Message header
 *  \return true if message can be encrypted, false otherwise
 */
bool gsm48_hdr_gmm_cipherable(const struct gsm48_hdr *hdr)
{
	switch(hdr->msg_type) {
	case GSM48_MT_GMM_ATTACH_REQ:
	case GSM48_MT_GMM_ATTACH_REJ:
	case GSM48_MT_GMM_AUTH_CIPH_REQ:
	case GSM48_MT_GMM_AUTH_CIPH_RESP:
	case GSM48_MT_GMM_AUTH_CIPH_REJ:
	case GSM48_MT_GMM_AUTH_CIPH_FAIL:
	case GSM48_MT_GMM_ID_REQ:
	case GSM48_MT_GMM_ID_RESP:
	case GSM48_MT_GMM_RA_UPD_REQ:
	case GSM48_MT_GMM_RA_UPD_REJ:
		return false;
	default:
		return true;
	}
}

/* Convert MCC + MNC to BCD representation, legacy implementation.
 * Instead use osmo_plmn_to_bcd(), which is also capable of converting
 * 3-digit MNC that have leading zeros. For parameters, also see there. */
void gsm48_mcc_mnc_to_bcd(uint8_t *bcd_dst, uint16_t mcc, uint16_t mnc)
{
	const struct osmo_plmn_id plmn = {
		.mcc = mcc,
		.mnc = mnc,
		.mnc_3_digits = false,
	};
	osmo_plmn_to_bcd(bcd_dst, &plmn);
}

/* Convert given 3-byte BCD buffer to integers, legacy implementation.
 * Instead use osmo_plmn_from_bcd(), which is also capable of converting
 * 3-digit MNC that have leading zeros. For parameters, also see there. */
void gsm48_mcc_mnc_from_bcd(uint8_t *bcd_src, uint16_t *mcc, uint16_t *mnc)
{
	struct osmo_plmn_id plmn;
	osmo_plmn_from_bcd(bcd_src, &plmn);
	*mcc = plmn.mcc;
	*mnc = plmn.mnc;
}

/*! Encode TS 04.08 Location Area Identifier, legacy implementation.
 * Instead use gsm48_generate_lai2(), which is capable of three-digit MNC with leading zeros.
 *  \param[out] lai48 caller-provided memory for output
 *  \param[in] mcc Mobile Country Code
 *  \param[in] mnc Mobile Network Code
 *  \param[in] lac Location Area Code */
void gsm48_generate_lai(struct gsm48_loc_area_id *lai48, uint16_t mcc,
			uint16_t mnc, uint16_t lac)
{
	const struct osmo_location_area_id lai = {
		.plmn = {
			.mcc = mcc,
			.mnc = mnc,
			.mnc_3_digits = false,
		},
		.lac = lac,
	};
	gsm48_generate_lai2(lai48, &lai);
}

/*! Encode TS 04.08 Location Area Identifier.
 *  \param[out] lai48 caller-provided memory for output.
 *  \param[in] lai input of MCC-MNC-LAC. */
void gsm48_generate_lai2(struct gsm48_loc_area_id *lai48, const struct osmo_location_area_id *lai)
{
	osmo_plmn_to_bcd(&lai48->digits[0], &lai->plmn);
	lai48->lac = osmo_htons(lai->lac);
}

/*! Decode TS 04.08 Location Area Identifier, legacy implementation.
 * Instead use gsm48_decode_lai2(), which is capable of three-digit MNC with leading zeros.
 *  \param[in] Location Area Identifier (encoded)
 *  \param[out] mcc Mobile Country Code
 *  \param[out] mnc Mobile Network Code
 *  \param[out] lac Location Area Code
 *  \returns 0
 *
 * Attention: this function returns true integers, not hex! */
int gsm48_decode_lai(struct gsm48_loc_area_id *lai, uint16_t *mcc,
		     uint16_t *mnc, uint16_t *lac)
{
	struct osmo_location_area_id decoded;
	gsm48_decode_lai2(lai, &decoded);
	*mcc = decoded.plmn.mcc;
	*mnc = decoded.plmn.mnc;
	*lac = decoded.lac;
	return 0;
}

/*! Decode TS 04.08 Location Area Identifier.
 *  \param[in] Location Area Identifier (encoded).
 *  \param[out] decoded Target buffer to write decoded values of MCC-MNC-LAC.
 *
 * Attention: this function returns true integers, not hex! */
void gsm48_decode_lai2(const struct gsm48_loc_area_id *lai, struct osmo_location_area_id *decoded)
{
	osmo_plmn_from_bcd(&lai->digits[0], &decoded->plmn);
	decoded->lac = osmo_ntohs(lai->lac);
}

/*! Set DTX mode in Cell Options IE (3GPP TS 44.018)
 *  \param[in] op Cell Options structure in which DTX parameters will be set
 *  \param[in] full Mode for full-rate channels
 *  \param[in] half Mode for half-rate channels
 *  \param[in] is_bcch Indicates if we should use 10.5.2.3.1 instead of
 *             10.5.2.3a.2
 *
 * There is no space for separate DTX settings for Full and Half rate channels
 * in BCCH - in this case full setting is used for both and half parameter is
 * ignored.
 */
void gsm48_set_dtx(struct gsm48_cell_options *op, enum gsm48_dtx_mode full,
		   enum gsm48_dtx_mode half, bool is_bcch)
{
	if (is_bcch) {
		switch (full) {
		case GSM48_DTX_MAY_BE_USED:
			op->dtx = 0;
			return;
		case GSM48_DTX_SHALL_BE_USED:
			op->dtx = 1;
			return;
		case GSM48_DTX_SHALL_NOT_BE_USED:
			op->dtx = 2;
			return;
		}
	} else {
		switch (full) {
		case GSM48_DTX_MAY_BE_USED:
			op->dtx = (half == GSM48_DTX_SHALL_BE_USED) ? 3 : 0;
			op->d =   (half == GSM48_DTX_SHALL_NOT_BE_USED) ? 0 : 1;
			return;
		case GSM48_DTX_SHALL_BE_USED:
			op->dtx = (half == GSM48_DTX_MAY_BE_USED) ? 3 : 1;
			op->d =   (half == GSM48_DTX_SHALL_BE_USED) ? 1 : 0;
			return;
		case GSM48_DTX_SHALL_NOT_BE_USED:
			op->dtx = 2;
			op->d =   (half == GSM48_DTX_SHALL_BE_USED) ? 1 : 0;
			return;
		}
	}
}

/*! Deprecated, see osmo_mobile_identity instead.
 * Generate TS 04.08 Mobile ID from TMSI
 *  \param[out] buf Caller-provided output buffer (7 bytes)
 *  \param[in] tmsi TMSI to be encoded
 *  \returns number of byes encoded (always 7) */
int gsm48_generate_mid_from_tmsi(uint8_t *buf, uint32_t tmsi)
{
	uint32_t tmsi_be = osmo_htonl(tmsi);

	buf[0] = GSM48_IE_MOBILE_ID;
	buf[1] = GSM48_TMSI_LEN;
	buf[2] = 0xf0 | GSM_MI_TYPE_TMSI;
	memcpy(&buf[3], &tmsi_be, sizeof(tmsi_be));

	return 7;
}

/*! Deprecated, see osmo_mobile_identity instead.
 * Generate TS 24.008 §10.5.1.4 Mobile ID of BCD type from ASCII string
 *  \param[out] buf Caller-provided output buffer of at least GSM48_MID_MAX_SIZE bytes
 *  \param[in] id Identity to be encoded
 *  \param[in] mi_type Type of identity (e.g. GSM_MI_TYPE_IMSI, IMEI, IMEISV)
 *  \returns number of bytes used in \a buf */
uint8_t gsm48_generate_mid(uint8_t *buf, const char *id, uint8_t mi_type)
{
	uint8_t length = strnlen(id, 16), i, off = 0, odd = (length & 1) == 1;
	/* maximum length == 16 (IMEISV) */

	buf[0] = GSM48_IE_MOBILE_ID;
	buf[2] = osmo_char2bcd(id[0]) << 4 | (mi_type & GSM_MI_TYPE_MASK) | (odd << 3);

	/* if the length is even we will fill half of the last octet */
	buf[1] = (length + (odd ? 1 : 2)) >> 1;
	/* buf[1] maximum = 18/2 = 9 */
	OSMO_ASSERT(buf[1] <= 9);

	for (i = 1; i < buf[1]; ++i) {
		uint8_t upper, lower = osmo_char2bcd(id[++off]);
		if (!odd && off + 1 == length)
			upper = 0x0f;
		else
			upper = osmo_char2bcd(id[++off]) & 0x0f;

		buf[2 + i] = (upper << 4) | lower;
	}

	/* maximum return value: 2 + 9 = 11 */
	return 2 + buf[1];
}

/*! Deprecated, see osmo_mobile_identity instead.
 * Generate TS 04.08 Mobile ID from IMSI
 *  \param[out] buf Caller-provided output buffer
 *  \param[in] imsi IMSI to be encoded
 *  \returns number of bytes used in \a buf */
int gsm48_generate_mid_from_imsi(uint8_t *buf, const char *imsi)
{
	return gsm48_generate_mid(buf, imsi, GSM_MI_TYPE_IMSI);
}

/*! Deprecated, see osmo_mobile_identity instead.
 * Convert TS 04.08 Mobile Identity (10.5.1.4) to string.
 * This function does not validate the Mobile Identity digits, i.e. digits > 9 are returned as 'A'-'F'.
 *  \param[out] string Caller-provided buffer for output
 *  \param[in] str_len Length of \a string in bytes
 *  \param[in] mi Mobile Identity to be stringified
 *  \param[in] mi_len Length of \a mi in bytes
 *  \returns Return <= 0 on error, > 0 on success.
 *           WARNING: the return value of this function is not well implemented.
 *           Depending on the MI type and amount of output buffer, this may return
 *           the nr of written bytes, or the written strlen(), or the snprintf()
 *           style strlen()-if-the-buffer-were-large-enough.
 */
int gsm48_mi_to_string(char *string, int str_len, const uint8_t *mi, int mi_len)
{
	int rc;
	uint8_t mi_type;
	uint32_t tmsi;

	mi_type = (mi && mi_len) ? (mi[0] & GSM_MI_TYPE_MASK) : GSM_MI_TYPE_NONE;

	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		/* Table 10.5.4.3, reverse generate_mid_from_tmsi */
		if (mi_len == GSM48_TMSI_LEN && mi[0] == (0xf0 | GSM_MI_TYPE_TMSI)) {
			tmsi = osmo_load32be(&mi[1]);
			return snprintf(string, str_len, "%"PRIu32, tmsi);
		}
		break;
	case GSM_MI_TYPE_IMSI:
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		rc = osmo_bcd2str(string, str_len, mi,
				  1, mi_len * 2 - ((mi[0] & GSM_MI_ODD) ? 0 : 1), true);
		/* osmo_bcd2str() returns snprintf style strlen(), this returns bytes written. */
		if (rc < 0)
			return 0;
		else if (rc < str_len)
			return rc + 1;
		else
			return strlen(string) + 1;

	default:
		break;
	}

	if (str_len < 1)
		return 0;
	*string = '\0';
	return 1;
}

/*! Parse TS 04.08 Routing Area Identifier
 *  \param[out] Caller-provided memory for decoded RA ID
 *  \param[in] buf Input buffer pointing to RAI IE value */
void gsm48_parse_ra(struct gprs_ra_id *raid, const uint8_t *buf)
{
	raid->mcc = (buf[0] & 0xf) * 100;
	raid->mcc += (buf[0] >> 4) * 10;
	raid->mcc += (buf[1] & 0xf) * 1;

	/* I wonder who came up with the stupidity of encoding the MNC
	 * differently depending on how many digits its decimal number has! */
	if ((buf[1] >> 4) == 0xf) {
		raid->mnc = (buf[2] & 0xf) * 10;
		raid->mnc += (buf[2] >> 4) * 1;
		raid->mnc_3_digits = false;
	} else {
		raid->mnc = (buf[2] & 0xf) * 100;
		raid->mnc += (buf[2] >> 4) * 10;
		raid->mnc += (buf[1] >> 4) * 1;
		raid->mnc_3_digits = true;
	}

	raid->lac = osmo_load16be(buf + 3);
	raid->rac = buf[5];
}

/*! Encode a 3GPP TS 24.008 § 10.5.5.15 Routing area identification
 *  \param[out] out Caller-provided packed struct
 *  \param[in] raid Routing Area ID to be encoded
 */
void gsm48_encode_ra(struct gsm48_ra_id *out, const struct gprs_ra_id *raid)
{
	out->lac = osmo_htons(raid->lac);
	out->rac = raid->rac;

	out->digits[0] = ((raid->mcc / 100) % 10) | (((raid->mcc / 10) % 10) << 4);
	out->digits[1] = raid->mcc % 10;

	if (raid->mnc < 100 && !raid->mnc_3_digits) {
		out->digits[1] |= 0xf0;
		out->digits[2] = ((raid->mnc / 10) % 10) | ((raid->mnc % 10) << 4);
	} else {
		out->digits[1] |= (raid->mnc % 10) << 4;
		out->digits[2] = ((raid->mnc / 100) % 10) | (((raid->mnc / 10) % 10) << 4);
	}
}

/*! Encode a TS 04.08 Routing Area Identifier
 *  \param[out] buf Caller-provided output buffer of 6 bytes
 *  \param[in] raid Routing Area ID to be encoded
 *  \returns number of bytes used in \a buf */
int gsm48_construct_ra(uint8_t *buf, const struct gprs_ra_id *raid)
{
	gsm48_encode_ra((struct gsm48_ra_id *)buf, raid);

	return 6;
}

/*! Compare a TS 04.08 Routing Area Identifier
 *  \param[in] raid1 first Routing Area ID to compare.
 *  \param[in] raid2 second Routing Area ID to compare.
 *  \returns true if raid1 and raid2 match, false otherwise. */
bool gsm48_ra_equal(const struct gprs_ra_id *raid1, const struct gprs_ra_id *raid2)
{
	if (raid1->mcc != raid2->mcc)
		return false;
	if (raid1->mnc != raid2->mnc)
		return false;
	if (raid1->mnc_3_digits != raid2->mnc_3_digits)
		return false;
	if (raid1->lac != raid2->lac)
		return false;
	if (raid1->rac != raid2->rac)
		return false;
	return true;
}

/*! Determine number of paging sub-channels
 *  \param[in] chan_desc Control Channel Description
 *  \returns number of paging sub-channels
 *
 *  Uses From Table 10.5.33 of GSM 04.08 to determine the number of
 *  paging sub-channels in the given control channel configuration
 */
int gsm48_number_of_paging_subchannels(const struct gsm48_control_channel_descr *chan_desc)
{
	unsigned int n_pag_blocks = gsm0502_get_n_pag_blocks(chan_desc);

	if (chan_desc->ccch_conf == RSL_BCCH_CCCH_CONF_1_C)
		return OSMO_MAX(1, n_pag_blocks) * (chan_desc->bs_pa_mfrms + 2);
	else
		return n_pag_blocks * (chan_desc->bs_pa_mfrms + 2);
}

/*! TS 04.08 Protocol Descriptor names */
const struct value_string gsm48_pdisc_names[] = {
	{ GSM48_PDISC_GROUP_CC,		"VGCC" },
	{ GSM48_PDISC_BCAST_CC,		"VBCC" },
	{ GSM48_PDISC_PDSS1,		"PDSS1" },
	{ GSM48_PDISC_CC,		"CC" },
	{ GSM48_PDISC_PDSS2,		"PDSS2" },
	{ GSM48_PDISC_MM,		"MM" },
	{ GSM48_PDISC_RR,		"RR" },
	{ GSM48_PDISC_MM_GPRS,		"GMM" },
	{ GSM48_PDISC_SMS,		"SMS" },
	{ GSM48_PDISC_SM_GPRS,		"SM" },
	{ GSM48_PDISC_NC_SS,		"NCSS" },
	{ GSM48_PDISC_LOC,		"LCS" },
	{ GSM48_PDISC_EXTEND,		"EXTD" },
	{ GSM48_PDISC_MASK,		"MASK" },
	{ 0, NULL }
};

/*! TS 04.08 RR Message Type names */
const struct value_string gsm48_rr_msgtype_names[] = {
	OSMO_VALUE_STRING(GSM48_MT_RR_INIT_REQ),
	OSMO_VALUE_STRING(GSM48_MT_RR_ADD_ASS),
	OSMO_VALUE_STRING(GSM48_MT_RR_IMM_ASS),
	OSMO_VALUE_STRING(GSM48_MT_RR_IMM_ASS_EXT),
	OSMO_VALUE_STRING(GSM48_MT_RR_IMM_ASS_REJ),
	OSMO_VALUE_STRING(GSM48_MT_RR_DTM_ASS_FAIL),
	OSMO_VALUE_STRING(GSM48_MT_RR_DTM_REJECT),
	OSMO_VALUE_STRING(GSM48_MT_RR_DTM_REQUEST),
	OSMO_VALUE_STRING(GSM48_MT_RR_PACKET_ASS),

	OSMO_VALUE_STRING(GSM48_MT_RR_CIPH_M_CMD),
	OSMO_VALUE_STRING(GSM48_MT_RR_CIPH_M_COMPL),

	OSMO_VALUE_STRING(GSM48_MT_RR_CFG_CHG_CMD),
	OSMO_VALUE_STRING(GSM48_MT_RR_CFG_CHG_ACK),
	OSMO_VALUE_STRING(GSM48_MT_RR_CFG_CHG_REJ),

	OSMO_VALUE_STRING(GSM48_MT_RR_ASS_CMD),
	OSMO_VALUE_STRING(GSM48_MT_RR_ASS_COMPL),
	OSMO_VALUE_STRING(GSM48_MT_RR_ASS_FAIL),
	OSMO_VALUE_STRING(GSM48_MT_RR_HANDO_CMD),
	OSMO_VALUE_STRING(GSM48_MT_RR_HANDO_COMPL),
	OSMO_VALUE_STRING(GSM48_MT_RR_HANDO_FAIL),
	OSMO_VALUE_STRING(GSM48_MT_RR_HANDO_INFO),
	OSMO_VALUE_STRING(GSM48_MT_RR_HANDO_INFO),
	OSMO_VALUE_STRING(GSM48_MT_RR_DTM_ASS_CMD),

	OSMO_VALUE_STRING(GSM48_MT_RR_CELL_CHG_ORDER),
	OSMO_VALUE_STRING(GSM48_MT_RR_PDCH_ASS_CMD),

	OSMO_VALUE_STRING(GSM48_MT_RR_CHAN_REL),
	OSMO_VALUE_STRING(GSM48_MT_RR_PART_REL),
	OSMO_VALUE_STRING(GSM48_MT_RR_PART_REL_COMP),

	OSMO_VALUE_STRING(GSM48_MT_RR_PAG_REQ_1),
	OSMO_VALUE_STRING(GSM48_MT_RR_PAG_REQ_2),
	OSMO_VALUE_STRING(GSM48_MT_RR_PAG_REQ_3),
	OSMO_VALUE_STRING(GSM48_MT_RR_PAG_RESP),
	OSMO_VALUE_STRING(GSM48_MT_RR_NOTIF_NCH),
	OSMO_VALUE_STRING(GSM48_MT_RR_NOTIF_FACCH),
	OSMO_VALUE_STRING(GSM48_MT_RR_NOTIF_RESP),
	OSMO_VALUE_STRING(GSM48_MT_RR_PACKET_NOTIF),
	OSMO_VALUE_STRING(GSM48_MT_RR_UTRAN_CLSM_CHG),
	OSMO_VALUE_STRING(GSM48_MT_RR_CDMA2K_CLSM_CHG),
	OSMO_VALUE_STRING(GSM48_MT_RR_IS_TO_UTRAN_HANDO),
	OSMO_VALUE_STRING(GSM48_MT_RR_IS_TO_CDMA2K_HANDO),

	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_8),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_1),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_2),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_3),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_4),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_5),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_6),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_7),

	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_2bis),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_2ter),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_2quater),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_5bis),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_5ter),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_9),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_13),

	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_16),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_17),

	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_18),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_19),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_20),

	OSMO_VALUE_STRING(GSM48_MT_RR_CHAN_MODE_MODIF),
	OSMO_VALUE_STRING(GSM48_MT_RR_STATUS),
	OSMO_VALUE_STRING(GSM48_MT_RR_CHAN_MODE_MODIF_ACK),
	OSMO_VALUE_STRING(GSM48_MT_RR_FREQ_REDEF),
	OSMO_VALUE_STRING(GSM48_MT_RR_MEAS_REP),
	OSMO_VALUE_STRING(GSM48_MT_RR_CLSM_CHG),
	OSMO_VALUE_STRING(GSM48_MT_RR_CLSM_ENQ),
	OSMO_VALUE_STRING(GSM48_MT_RR_EXT_MEAS_REP),
	OSMO_VALUE_STRING(GSM48_MT_RR_EXT_MEAS_REP_ORD),
	OSMO_VALUE_STRING(GSM48_MT_RR_GPRS_SUSP_REQ),
	OSMO_VALUE_STRING(GSM48_MT_RR_DTM_INFO),

	OSMO_VALUE_STRING(GSM48_MT_RR_VGCS_UPL_GRANT),
	OSMO_VALUE_STRING(GSM48_MT_RR_UPLINK_RELEASE),
	OSMO_VALUE_STRING(GSM48_MT_RR_UPLINK_FREE),
	OSMO_VALUE_STRING(GSM48_MT_RR_UPLINK_BUSY),
	OSMO_VALUE_STRING(GSM48_MT_RR_TALKER_IND),
	{ 0, NULL }
};

/*! TS 04.08 MM Message Type names */
const struct value_string gsm48_mm_msgtype_names[] = {
	OSMO_VALUE_STRING(GSM48_MT_MM_IMSI_DETACH_IND),
	OSMO_VALUE_STRING(GSM48_MT_MM_LOC_UPD_ACCEPT),
	OSMO_VALUE_STRING(GSM48_MT_MM_LOC_UPD_REJECT),
	OSMO_VALUE_STRING(GSM48_MT_MM_LOC_UPD_REQUEST),

	OSMO_VALUE_STRING(GSM48_MT_MM_AUTH_REJ),
	OSMO_VALUE_STRING(GSM48_MT_MM_AUTH_REQ),
	OSMO_VALUE_STRING(GSM48_MT_MM_AUTH_RESP),
	OSMO_VALUE_STRING(GSM48_MT_MM_AUTH_FAIL),
	OSMO_VALUE_STRING(GSM48_MT_MM_ID_REQ),
	OSMO_VALUE_STRING(GSM48_MT_MM_ID_RESP),
	OSMO_VALUE_STRING(GSM48_MT_MM_TMSI_REALL_CMD),
	OSMO_VALUE_STRING(GSM48_MT_MM_TMSI_REALL_COMPL),

	OSMO_VALUE_STRING(GSM48_MT_MM_CM_SERV_ACC),
	OSMO_VALUE_STRING(GSM48_MT_MM_CM_SERV_REJ),
	OSMO_VALUE_STRING(GSM48_MT_MM_CM_SERV_ABORT),
	OSMO_VALUE_STRING(GSM48_MT_MM_CM_SERV_REQ),
	OSMO_VALUE_STRING(GSM48_MT_MM_CM_SERV_PROMPT),
	OSMO_VALUE_STRING(GSM48_MT_MM_CM_REEST_REQ),
	OSMO_VALUE_STRING(GSM48_MT_MM_ABORT),

	OSMO_VALUE_STRING(GSM48_MT_MM_NULL),
	OSMO_VALUE_STRING(GSM48_MT_MM_STATUS),
	OSMO_VALUE_STRING(GSM48_MT_MM_INFO),
	{ 0, NULL }
};

/*! TS 04.08 CC Message Type names */
const struct value_string gsm48_cc_msgtype_names[] = {
	OSMO_VALUE_STRING(GSM48_MT_CC_ALERTING),
	OSMO_VALUE_STRING(GSM48_MT_CC_CALL_CONF),
	OSMO_VALUE_STRING(GSM48_MT_CC_CALL_PROC),
	OSMO_VALUE_STRING(GSM48_MT_CC_CONNECT),
	OSMO_VALUE_STRING(GSM48_MT_CC_CONNECT_ACK),
	OSMO_VALUE_STRING(GSM48_MT_CC_EMERG_SETUP),
	OSMO_VALUE_STRING(GSM48_MT_CC_PROGRESS),
	OSMO_VALUE_STRING(GSM48_MT_CC_ESTAB),
	OSMO_VALUE_STRING(GSM48_MT_CC_ESTAB_CONF),
	OSMO_VALUE_STRING(GSM48_MT_CC_RECALL),
	OSMO_VALUE_STRING(GSM48_MT_CC_START_CC),
	OSMO_VALUE_STRING(GSM48_MT_CC_SETUP),

	OSMO_VALUE_STRING(GSM48_MT_CC_MODIFY),
	OSMO_VALUE_STRING(GSM48_MT_CC_MODIFY_COMPL),
	OSMO_VALUE_STRING(GSM48_MT_CC_MODIFY_REJECT),
	OSMO_VALUE_STRING(GSM48_MT_CC_USER_INFO),
	OSMO_VALUE_STRING(GSM48_MT_CC_HOLD),
	OSMO_VALUE_STRING(GSM48_MT_CC_HOLD_ACK),
	OSMO_VALUE_STRING(GSM48_MT_CC_HOLD_REJ),
	OSMO_VALUE_STRING(GSM48_MT_CC_RETR),
	OSMO_VALUE_STRING(GSM48_MT_CC_RETR_ACK),
	OSMO_VALUE_STRING(GSM48_MT_CC_RETR_REJ),

	OSMO_VALUE_STRING(GSM48_MT_CC_DISCONNECT),
	OSMO_VALUE_STRING(GSM48_MT_CC_RELEASE),
	OSMO_VALUE_STRING(GSM48_MT_CC_RELEASE_COMPL),

	OSMO_VALUE_STRING(GSM48_MT_CC_CONG_CTRL),
	OSMO_VALUE_STRING(GSM48_MT_CC_NOTIFY),
	OSMO_VALUE_STRING(GSM48_MT_CC_STATUS),
	OSMO_VALUE_STRING(GSM48_MT_CC_STATUS_ENQ),
	OSMO_VALUE_STRING(GSM48_MT_CC_START_DTMF),
	OSMO_VALUE_STRING(GSM48_MT_CC_STOP_DTMF),
	OSMO_VALUE_STRING(GSM48_MT_CC_STOP_DTMF_ACK),
	OSMO_VALUE_STRING(GSM48_MT_CC_START_DTMF_ACK),
	OSMO_VALUE_STRING(GSM48_MT_CC_START_DTMF_REJ),
	OSMO_VALUE_STRING(GSM48_MT_CC_FACILITY),
	{ 0, NULL }
};

/*! TS 04.08 10.5..4.11 Call Control Cause Values */
const struct value_string gsm48_cc_cause_names[] = {
	{ GSM48_CC_CAUSE_UNASSIGNED_NR,		"UNASSIGNED_NR" },
	{ GSM48_CC_CAUSE_NO_ROUTE,		"NO_ROUTE" },
	{ GSM48_CC_CAUSE_CHAN_UNACCEPT,		"CHAN_UNACCEPT" },
	{ GSM48_CC_CAUSE_OP_DET_BARRING,	"OP_DET_BARRING" },
	{ GSM48_CC_CAUSE_NORM_CALL_CLEAR,	"NORM_CALL_CLEAR" },
	{ GSM48_CC_CAUSE_USER_BUSY,		"USER_BUSY" },
	{ GSM48_CC_CAUSE_USER_NOTRESPOND,	"USER_NOTRESPOND" },
	{ GSM48_CC_CAUSE_USER_ALERTING_NA,	"USER_ALERTING_NA" },
	{ GSM48_CC_CAUSE_CALL_REJECTED,		"CALL_REJECTED" },
	{ GSM48_CC_CAUSE_NUMBER_CHANGED,	"NUMBER_CHANGED" },
	{ GSM48_CC_CAUSE_PRE_EMPTION,		"PRE_EMPTION" },
	{ GSM48_CC_CAUSE_NONSE_USER_CLR,	"NONSE_USER_CLR" },
	{ GSM48_CC_CAUSE_DEST_OOO,		"DEST_OOO" },
	{ GSM48_CC_CAUSE_INV_NR_FORMAT,		"INV_NR_FORMAT" },
	{ GSM48_CC_CAUSE_FACILITY_REJ,		"FACILITY_REJ" },
	{ GSM48_CC_CAUSE_RESP_STATUS_INQ,	"RESP_STATUS_INQ" },
	{ GSM48_CC_CAUSE_NORMAL_UNSPEC,		"NORMAL_UNSPEC" },
	{ GSM48_CC_CAUSE_NO_CIRCUIT_CHAN,	"NO_CIRCUIT_CHAN" },
	{ GSM48_CC_CAUSE_NETWORK_OOO,		"NETWORK_OOO" },
	{ GSM48_CC_CAUSE_TEMP_FAILURE,		"TEMP_FAILURE" },
	{ GSM48_CC_CAUSE_SWITCH_CONG,		"SWITCH_CONG" },
	{ GSM48_CC_CAUSE_ACC_INF_DISCARD,	"ACC_INF_DISCARD" },
	{ GSM48_CC_CAUSE_REQ_CHAN_UNAVAIL,	"REQ_CHAN_UNAVAIL" },
	{ GSM48_CC_CAUSE_RESOURCE_UNAVAIL,	"RESOURCE_UNAVAIL" },
	{ GSM48_CC_CAUSE_QOS_UNAVAIL,		"QOS_UNAVAIL" },
	{ GSM48_CC_CAUSE_REQ_FAC_NOT_SUBSC,	"REQ_FAC_NOT_SUBSC" },
	{ GSM48_CC_CAUSE_INC_BARRED_CUG,	"INC_BARRED_CUG" },
	{ GSM48_CC_CAUSE_BEARER_CAP_UNAUTH,	"BEARER_CAP_UNAUTH" },
	{ GSM48_CC_CAUSE_BEARER_CA_UNAVAIL,	"BEARER_CA_UNAVAIL" },
	{ GSM48_CC_CAUSE_SERV_OPT_UNAVAIL,	"SERV_OPT_UNAVAIL" },
	{ GSM48_CC_CAUSE_BEARERSERV_UNIMPL,	"BEARERSERV_UNIMPL" },
	{ GSM48_CC_CAUSE_ACM_GE_ACM_MAX,	"ACM_GE_ACM_MAX" },
	{ GSM48_CC_CAUSE_REQ_FAC_NOTIMPL,	"REQ_FAC_NOTIMPL" },
	{ GSM48_CC_CAUSE_RESTR_BCAP_AVAIL,	"RESTR_BCAP_AVAIL" },
	{ GSM48_CC_CAUSE_SERV_OPT_UNIMPL,	"SERV_OPT_UNIMPL" },
	{ GSM48_CC_CAUSE_INVAL_TRANS_ID,	"INVAL_TRANS_ID" },
	{ GSM48_CC_CAUSE_USER_NOT_IN_CUG,	"USER_NOT_IN_CUG" },
	{ GSM48_CC_CAUSE_INCOMPAT_DEST,		"INCOMPAT_DEST" },
	{ GSM48_CC_CAUSE_INVAL_TRANS_NET,	"INVAL_TRANS_NET" },
	{ GSM48_CC_CAUSE_SEMANTIC_INCORR,	"SEMANTIC_INCORR" },
	{ GSM48_CC_CAUSE_INVAL_MAND_INF,	"INVAL_MAND_INF" },
	{ GSM48_CC_CAUSE_MSGTYPE_NOTEXIST,	"MSGTYPE_NOTEXIST" },
	{ GSM48_CC_CAUSE_MSGTYPE_INCOMPAT,	"MSGTYPE_INCOMPAT" },
	{ GSM48_CC_CAUSE_IE_NOTEXIST,		"IE_NOTEXIST" },
	{ GSM48_CC_CAUSE_COND_IE_ERR,		"COND_IE_ERR" },
	{ GSM48_CC_CAUSE_MSG_INCOMP_STATE,	"MSG_INCOMP_STATE" },
	{ GSM48_CC_CAUSE_RECOVERY_TIMER,	"RECOVERY_TIMER" },
	{ GSM48_CC_CAUSE_PROTO_ERR,		"PROTO_ERR" },
	{ GSM48_CC_CAUSE_INTERWORKING,		"INTERWORKING" },
	{ 0 , NULL }
};

/*! TS 04.80, section 3.4 Messages for supplementary services control */
const struct value_string gsm48_nc_ss_msgtype_names[] = {
	OSMO_VALUE_STRING(GSM0480_MTYPE_RELEASE_COMPLETE),
	OSMO_VALUE_STRING(GSM0480_MTYPE_FACILITY),
	OSMO_VALUE_STRING(GSM0480_MTYPE_REGISTER),
	{ 0, NULL }
};

/*! Compose a string naming the message type for given protocol, in a caller-provided buffer.
 * If the message type string is known, return the message type name, otherwise
 * return "<protocol discriminator name>:<message type in hex>".
 * \param[out] buf caller-allcated output string buffer
 * \param[in] buf_len size of buf in bytes
 * \param[in] pdisc protocol discriminator like GSM48_PDISC_MM
 * \param[in] msg_type message type like GSM48_MT_MM_LOC_UPD_REQUEST
 * \returns buf
 */
char *gsm48_pdisc_msgtype_name_buf(char *buf, size_t buf_len, uint8_t pdisc, uint8_t msg_type)
{
	const struct value_string *msgt_names;

	switch (pdisc) {
	case GSM48_PDISC_RR:
		msgt_names = gsm48_rr_msgtype_names;
		break;
	case GSM48_PDISC_MM:
		msgt_names = gsm48_mm_msgtype_names;
		break;
	case GSM48_PDISC_CC:
		msgt_names = gsm48_cc_msgtype_names;
		break;
	case GSM48_PDISC_NC_SS:
		msgt_names = gsm48_nc_ss_msgtype_names;
		break;
	default:
		msgt_names = NULL;
		break;
	}

	if (msgt_names)
		snprintf(buf, buf_len, "%s", get_value_string(msgt_names, msg_type));
	else
		snprintf(buf, buf_len, "%s:0x%02x", gsm48_pdisc_name(pdisc), msg_type);
	return buf;
}

/*! Compose a string naming the message type for given protocol, in a static buffer.
 * If the message type string is known, return the message type name, otherwise
 * return "<protocol discriminator name>:<message type in hex>".
 * \param[in] pdisc protocol discriminator like GSM48_PDISC_MM
 * \param[in] msg_type message type like GSM48_MT_MM_LOC_UPD_REQUEST
 * \returns statically allocated string or string constant.
 */
const char *gsm48_pdisc_msgtype_name(uint8_t pdisc, uint8_t msg_type)
{
	static __thread char namebuf[64];
	return gsm48_pdisc_msgtype_name_buf(namebuf, sizeof(namebuf), pdisc, msg_type);
}

/*! Compose a string naming the message type for given protocol, in a dynamically-allocated buffer.
 * If the message type string is known, return the message type name, otherwise
 * return "<protocol discriminator name>:<message type in hex>".
 * \param[in] ctx talloc context from which to allocate output buffer
 * \param[in] pdisc protocol discriminator like GSM48_PDISC_MM
 * \param[in] msg_type message type like GSM48_MT_MM_LOC_UPD_REQUEST
 * \returns string representation in dynamically allocated output buffer.
 */
char *gsm48_pdisc_msgtype_name_c(const void *ctx, uint8_t pdisc, uint8_t msg_type)
{
	char *namebuf = talloc_size(ctx, 64);
	if (!namebuf)
		return NULL;
	return gsm48_pdisc_msgtype_name_buf(namebuf, 64, pdisc, msg_type);
}

const struct value_string gsm48_reject_value_names[] = {
	 { GSM48_REJECT_IMSI_UNKNOWN_IN_HLR, "IMSI_UNKNOWN_IN_HLR" },
	 { GSM48_REJECT_ILLEGAL_MS, "ILLEGAL_MS" },
	 { GSM48_REJECT_IMSI_UNKNOWN_IN_VLR, "IMSI_UNKNOWN_IN_VLR" },
	 { GSM48_REJECT_IMEI_NOT_ACCEPTED, "IMEI_NOT_ACCEPTED" },
	 { GSM48_REJECT_ILLEGAL_ME, "ILLEGAL_ME" },
	 { GSM48_REJECT_PLMN_NOT_ALLOWED, "PLMN_NOT_ALLOWED" },
	 { GSM48_REJECT_LOC_NOT_ALLOWED, "LOC_NOT_ALLOWED" },
	 { GSM48_REJECT_ROAMING_NOT_ALLOWED, "ROAMING_NOT_ALLOWED" },
	 { GSM48_REJECT_NETWORK_FAILURE, "NETWORK_FAILURE" },
	 { GSM48_REJECT_SYNCH_FAILURE, "SYNCH_FAILURE" },
	 { GSM48_REJECT_CONGESTION, "CONGESTION" },
	 { GSM48_REJECT_SRV_OPT_NOT_SUPPORTED, "SRV_OPT_NOT_SUPPORTED" },
	 { GSM48_REJECT_RQD_SRV_OPT_NOT_SUPPORTED, "RQD_SRV_OPT_NOT_SUPPORTED" },
	 { GSM48_REJECT_SRV_OPT_TMP_OUT_OF_ORDER, "SRV_OPT_TMP_OUT_OF_ORDER" },
	 { GSM48_REJECT_CALL_CAN_NOT_BE_IDENTIFIED, "CALL_CAN_NOT_BE_IDENTIFIED" },
	 { GSM48_REJECT_INCORRECT_MESSAGE, "INCORRECT_MESSAGE" },
	 { GSM48_REJECT_INVALID_MANDANTORY_INF, "INVALID_MANDANTORY_INF" },
	 { GSM48_REJECT_MSG_TYPE_NOT_IMPLEMENTED, "MSG_TYPE_NOT_IMPLEMENTED" },
	 { GSM48_REJECT_MSG_TYPE_NOT_COMPATIBLE, "MSG_TYPE_NOT_COMPATIBLE" },
	 { GSM48_REJECT_INF_ELEME_NOT_IMPLEMENTED, "INF_ELEME_NOT_IMPLEMENTED" },
	 { GSM48_REJECT_CONDTIONAL_IE_ERROR, "CONDTIONAL_IE_ERROR" },
	 { GSM48_REJECT_MSG_NOT_COMPATIBLE, "MSG_NOT_COMPATIBLE" },
	 { GSM48_REJECT_PROTOCOL_ERROR, "PROTOCOL_ERROR" },
	 { GSM48_REJECT_GPRS_NOT_ALLOWED, "GPRS_NOT_ALLOWED" },
	 { GSM48_REJECT_SERVICES_NOT_ALLOWED, "SERVICES_NOT_ALLOWED" },
	 { GSM48_REJECT_MS_IDENTITY_NOT_DERVIVABLE, "MS_IDENTITY_NOT_DERVIVABLE" },
	 { GSM48_REJECT_IMPLICITLY_DETACHED, "IMPLICITLY_DETACHED" },
	 { GSM48_REJECT_GPRS_NOT_ALLOWED_IN_PLMN, "GPRS_NOT_ALLOWED_IN_PLMN" },
	 { GSM48_REJECT_MSC_TMP_NOT_REACHABLE, "MSC_TMP_NOT_REACHABLE" },
	 { 0, NULL }
};

/*! Wrap a given \ref msg with \ref gsm48_hdr structure
 * \param[out] msg      A message to be wrapped
 * \param[in]  pdisc    GSM TS 04.07 protocol discriminator 1/2,
 *                      sub-pdisc, trans_id or skip_ind 1/2,
 *                      see section 11.2.3.1 for details
 * \param[in]  msg_type GSM TS 04.08 message type
 * @return              pointer to pushed header within \ref msg
 */
struct gsm48_hdr *gsm48_push_l3hdr(struct msgb *msg,
				   uint8_t pdisc, uint8_t msg_type)
{
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;

	return gh;
}

const struct value_string osmo_lu_type_names[] = {
	{ GSM48_LUPD_NORMAL, "NORMAL" },
	{ GSM48_LUPD_PERIODIC, "PERIODIC" },
	{ GSM48_LUPD_IMSI_ATT, "IMSI-ATTACH" },
	{ GSM48_LUPD_RESERVED, "RESERVED" },
	{}
};

const struct value_string osmo_cm_service_type_names[] = {
	{ GSM48_CMSERV_MO_CALL_PACKET, "MO-Call" },
	{ GSM48_CMSERV_EMERGENCY, "Emergency-Call" },
	{ GSM48_CMSERV_SMS, "Short-Messaging-Service" },
	{ GSM48_CMSERV_SUP_SERV, "Supplementary-Service" },
	{ GSM48_CMSERV_VGCS, "Voice-Group-Call" },
	{ GSM48_CMSERV_VBS, "Voice-Broadcast-Call" },
	{ GSM48_CMSERV_LOC_SERV, "Location-Service" },
	{}
};

bool osmo_gsm48_classmark1_is_r99(const struct gsm48_classmark1 *cm1)
{
	return cm1->rev_lev >= 2;
}

bool osmo_gsm48_classmark2_is_r99(const struct gsm48_classmark2 *cm2, uint8_t cm2_len)
{
	if (!cm2_len)
		return false;
	return cm2->rev_lev >= 2;
}

/*! Return true if any of Classmark 1 or Classmark 2 are present and indicate R99 capability.
 * \param[in] cm  Classmarks.
 * \returns True if R99 or later, false if pre-R99 or no Classmarks are present.
 */
bool osmo_gsm48_classmark_is_r99(const struct osmo_gsm48_classmark *cm)
{
	if (cm->classmark1_set)
		return osmo_gsm48_classmark1_is_r99(&cm->classmark1);
	return osmo_gsm48_classmark2_is_r99(&cm->classmark2, cm->classmark2_len);
}

/*! Return a string representation of A5 cipher algorithms indicated by Classmark 1, 2 and 3.
 * \param[in] cm  Classmarks.
 * \returns A statically allocated string like "cm1{a5/1=supported} cm2{0x23= A5/2 A5/3} no-cm3"
 */
char *osmo_gsm48_classmark_a5_name_buf(char *buf, size_t buf_len, const struct osmo_gsm48_classmark *cm)
{
	char cm1[42] = "no-cm1";
	char cm2[42] = " no-cm2";
	char cm3[42] = " no-cm3";

	if (cm->classmark1_set)
		snprintf(cm1, sizeof(cm1), "cm1{a5/1=%s}",
		     cm->classmark1.a5_1 ? "not-supported":"supported" /* inverted logic */);

	if (cm->classmark2_len >= 3)
		snprintf(cm2, sizeof(cm2), " cm2{0x%x=%s%s}",
			 cm->classmark2.a5_2 + (cm->classmark2.a5_3 << 1),
			 cm->classmark2.a5_2 ? " A5/2" : "",
			 cm->classmark2.a5_3 ? " A5/3" : "");

	if (cm->classmark3_len >= 1)
		snprintf(cm3, sizeof(cm3), " cm3{0x%x=%s%s%s%s}",
			 cm->classmark3[0],
			 cm->classmark3[0] & (1 << 0) ? " A5/4" : "",
			 cm->classmark3[0] & (1 << 1) ? " A5/5" : "",
			 cm->classmark3[0] & (1 << 2) ? " A5/6" : "",
			 cm->classmark3[0] & (1 << 3) ? " A5/7" : "");

	snprintf(buf, buf_len, "%s%s%s", cm1, cm2, cm3);
	return buf;
}

/*! Return a string representation of A5 cipher algorithms indicated by Classmark 1, 2 and 3.
 * \param[in] cm  Classmarks.
 * \returns A statically allocated string like "cm1{a5/1=supported} cm2{0x23= A5/2 A5/3} no-cm3"
 */
const char *osmo_gsm48_classmark_a5_name(const struct osmo_gsm48_classmark *cm)
{
	static __thread char buf[128];
	return osmo_gsm48_classmark_a5_name_buf(buf, sizeof(buf), cm);
}

/*! Return a string representation of A5 cipher algorithms indicated by Classmark 1, 2 and 3.
 * \param[in] ctx talloc context from which to allocate output buffer
 * \param[in] cm  Classmarks.
 * \returns string like "cm1{a5/1=supported} cm2{0x23= A5/2 A5/3} no-cm3" in dynamically-allocated
 *          output buffer.
 */
char *osmo_gsm48_classmark_a5_name_c(const void *ctx, const struct osmo_gsm48_classmark *cm)
{
	char *buf = talloc_size(ctx, 128);
	if (!buf)
		return NULL;
	return osmo_gsm48_classmark_a5_name_buf(buf, 128, cm);
}

/*! Overwrite dst with the Classmark information present in src.
 * Add an new Classmark and overwrite in dst what src has to offer, but where src has no Classmark information, leave
 * dst unchanged. (For Classmark 2 and 3, dst will exactly match any non-zero Classmark length from src, hence may end
 * up with a shorter Classmark after this call.)
 * \param[out] dst  The target Classmark storage to be updated.
 * \param[in] src  The new Classmark information to read from.
 */
void osmo_gsm48_classmark_update(struct osmo_gsm48_classmark *dst, const struct osmo_gsm48_classmark *src)
{
	if (src->classmark1_set) {
		dst->classmark1 = src->classmark1;
		dst->classmark1_set = true;
	}
	if (src->classmark2_len) {
		dst->classmark2_len = src->classmark2_len;
		dst->classmark2 = src->classmark2;
	}
	if (src->classmark3_len) {
		dst->classmark3_len = src->classmark3_len;
		memcpy(dst->classmark3, src->classmark3, OSMO_MIN(sizeof(dst->classmark3), src->classmark3_len));
	}
}


/*! Determine if the given Classmark (1/2/3) value permits a given A5/n cipher.
 * \param[in] cm  Classmarks.
 * \param[in] a5  The N in A5/N for which to query whether support is indicated.
 * \return 1 when the given A5/n is permitted, 0 when not (or a5 > 7), and negative if the respective MS Classmark is
 *         not known, where the negative number indicates the classmark type: -2 means Classmark 2 is not available. The
 *         idea is that when e.g. A5/3 is requested and the corresponding Classmark 3 is not available, that the caller
 *         can react by obtaining Classmark 3 and calling again once it is available.
 */
int osmo_gsm48_classmark_supports_a5(const struct osmo_gsm48_classmark *cm, uint8_t a5)
{
	switch (a5) {
	case 0:
		/* all phones must implement A5/0, see 3GPP TS 43.020 4.9 */
		return 1;
	case 1:
		/* 3GPP TS 43.020 4.9 requires A5/1 to be suppored by all phones and actually states:
		 * "The network shall not provide service to an MS which indicates that it does not
		 *  support the ciphering algorithm A5/1.".  However, let's be more tolerant based
		 * on policy here */
		/* See 3GPP TS 24.008 10.5.1.7 */
		if (!cm->classmark1_set)
			return -1;
		/* Inverted logic for this bit! */
		return cm->classmark1.a5_1 ? 0 : 1;
	case 2:
		/* See 3GPP TS 24.008 10.5.1.6 */
		if (cm->classmark2_len < 3)
			return -2;
		return cm->classmark2.a5_2 ? 1 : 0;
	case 3:
		if (cm->classmark2_len < 3)
			return -2;
		return cm->classmark2.a5_3 ? 1 : 0;
	case 4:
	case 5:
	case 6:
	case 7:
		/* See 3GPP TS 24.008 10.5.1.7 */
		if (!cm->classmark3_len)
			return -3;
		return (cm->classmark3[0] & (1 << (a5-4))) ? 1 : 0;
	default:
		return 0;
	}
}

/*! Decode power class from Classmark1/2 RF power capability field.
 * \param[in] rf_power_cap  The RF power capability field (3 bits).
 * \param[in] band  the band of the arfcn from where the classmark was received
 * \return the MS power class on success, negative on error.
 */
int8_t osmo_gsm48_rfpowercap2powerclass(enum gsm_band band, uint8_t rf_power_cap)
{
	switch (band)  {
	case GSM_BAND_1800:
	case GSM_BAND_1900:
		if (rf_power_cap > 2)
			return -1;
		return rf_power_cap + 1;
	default:
		if (rf_power_cap > 4)
			return -1;
		return rf_power_cap + 1;
	}
}


/*! @} */
