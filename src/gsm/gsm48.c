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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0502.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

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
	{ GSM48_RR_CAUSE_HNDOVER_IMP,		"Handover impossible, timing advance out of range" },
	{ GSM48_RR_CAUSE_CHAN_MODE_UNACCT,	"Channel mode unacceptable" },
	{ GSM48_RR_CAUSE_FREQ_NOT_IMPL,		"Frequency not implemented" },
	{ GSM48_RR_CAUSE_CALL_CLEARED,		"Call already cleared" },
	{ GSM48_RR_CAUSE_SEMANT_INCORR,		"Semantically incorrect message" },
	{ GSM48_RR_CAUSE_INVALID_MAND_INF,	"Invalid mandatory information" },
	{ GSM48_RR_CAUSE_MSG_TYPE_N,		"Message type non-existant or not implemented" },
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

/*! Return MCC-MNC-LAC-RAC as string, in a static buffer.
 * \param[in] rai  RAI to encode.
 * \returns Static string buffer.
 */
const char *osmo_rai_name(const struct gprs_ra_id *rai)
{
	static char buf[32];
	snprintf(buf, sizeof(buf), "%s-%s-%u-%u",
		 osmo_mcc_name(rai->mcc), osmo_mnc_name(rai->mnc, rai->mnc_3_digits), rai->lac,
		 rai->rac);
	return buf;
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


const struct value_string gsm48_chan_mode_names[] = {
	{ GSM48_CMODE_SIGN,		"SIGNALLING" },
	{ GSM48_CMODE_SPEECH_V1,	"SPEECH_V1" },
	{ GSM48_CMODE_SPEECH_EFR,	"SPEECH_EFR" },
	{ GSM48_CMODE_SPEECH_AMR,	"SPEECH_AMR" },
	{ GSM48_CMODE_DATA_14k5,	"DATA_14k5" },
	{ GSM48_CMODE_DATA_12k0,	"DATA_12k0" },
	{ GSM48_CMODE_DATA_6k0,		"DATA_6k0" },
	{ GSM48_CMODE_DATA_3k6,		"DATA_3k6" },
	{ 0,				NULL },
};

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

/*! Generate TS 04.08 Mobile ID from TMSI
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

/*! Generate TS 24.008 §10.5.1.4 Mobile ID
 *  \param[out] buf Caller-provided output buffer
 *  \param[in] id Identity to be encoded
 *  \returns number of bytes used in \a buf */
uint8_t gsm48_generate_mid(uint8_t *buf, const char *id, uint8_t mi_type)
{
	uint8_t length = strnlen(id, 255), i, off = 0, odd = (length & 1) == 1;

	buf[0] = GSM48_IE_MOBILE_ID;
	buf[2] = osmo_char2bcd(id[0]) << 4 | mi_type | (odd << 3);

	/* if the length is even we will fill half of the last octet */
	buf[1] = (length + (odd ? 1 : 2)) >> 1;

	for (i = 1; i < buf[1]; ++i) {
		uint8_t upper, lower = osmo_char2bcd(id[++off]);
		if (!odd && off + 1 == length)
			upper = 0x0f;
		else
			upper = osmo_char2bcd(id[++off]) & 0x0f;

		buf[2 + i] = (upper << 4) | lower;
	}

	return 2 + buf[1];
}

/*! Generate TS 04.08 Mobile ID from IMSI
 *  \param[out] buf Caller-provided output buffer
 *  \param[in] imsi IMSI to be encoded
 *  \returns number of bytes used in \a buf */
int gsm48_generate_mid_from_imsi(uint8_t *buf, const char *imsi)
{
	return gsm48_generate_mid(buf, imsi, GSM_MI_TYPE_IMSI);
}

/*! Convert TS 04.08 Mobile Identity (10.5.1.4) to string
 *  \param[out] string Caller-provided buffer for output
 *  \param[in] str_len Length of \a string in bytes
 *  \param[in] mi Mobile Identity to be stringified
 *  \param[in] mi_len Length of \a mi in bytes
 *  \returns length of string written to \a string */
int gsm48_mi_to_string(char *string, const int str_len, const uint8_t *mi,
		       const int mi_len)
{
	int i;
	uint8_t mi_type;
	char *str_cur = string;
	uint32_t tmsi;

	mi_type = mi[0] & GSM_MI_TYPE_MASK;

	switch (mi_type) {
	case GSM_MI_TYPE_NONE:
		break;
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
		*str_cur++ = osmo_bcd2char(mi[0] >> 4);

                for (i = 1; i < mi_len; i++) {
			if (str_cur + 2 >= string + str_len)
				return str_cur - string;
			*str_cur++ = osmo_bcd2char(mi[i] & 0xf);
			/* skip last nibble in last input byte when GSM_EVEN */
			if( (i != mi_len-1) || (mi[0] & GSM_MI_ODD))
				*str_cur++ = osmo_bcd2char(mi[i] >> 4);
		}
		break;
	default:
		break;
	}
	*str_cur++ = '\0';

	return str_cur - string;
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

/*! Determine number of paging sub-channels
 *  \param[in] chan_desc Control Channel Description
 *  \returns number of paging sub-channels
 *
 *  Uses From Table 10.5.33 of GSM 04.08 to determine the number of
 *  paging sub-channels in the given control channel configuration
 */
int gsm48_number_of_paging_subchannels(struct gsm48_control_channel_descr *chan_desc)
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
	{ GSM48_PDISC_USSD,		"USSD" },
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

/*! Compose a string naming the message type for given protocol.
 * If the message type string is known, return the message type name, otherwise
 * return "<protocol discriminator name>:<message type in hex>".
 * \param[in] pdisc protocol discriminator like GSM48_PDISC_MM
 * \param[in] msg_type message type like GSM48_MT_MM_LOC_UPD_REQUEST
 * \returns statically allocated string or string constant.
 */
const char *gsm48_pdisc_msgtype_name(uint8_t pdisc, uint8_t msg_type)
{
	static char namebuf[64];
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
	default:
		msgt_names = NULL;
		break;
	}

	if (msgt_names)
		return get_value_string(msgt_names, msg_type);

	snprintf(namebuf, sizeof(namebuf), "%s:0x%02x",
		 gsm48_pdisc_name(pdisc), msg_type);
	return namebuf;
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

/*! @} */
