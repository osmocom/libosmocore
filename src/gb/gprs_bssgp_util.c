/*! \file gprs_bssgp_util.c
 * GPRS BSSGP protocol implementation as per 3GPP TS 08.18. */
/*
 * (C) 2009-2017 by Harald Welte <laforge@gnumonks.org>
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

#include <errno.h>
#include <stdint.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_ns.h>

#include "gprs_bssgp_internal.h"

struct gprs_ns_inst *bssgp_nsi;

/* BSSGP Protocol specific, not implementation specific */
/* FIXME: This needs to go into libosmocore after finished */

/* Chapter 11.3.9 / Table 11.10: Cause coding */
static const struct value_string bssgp_cause_strings[] = {
	{ BSSGP_CAUSE_PROC_OVERLOAD,		"Processor overload" },
	{ BSSGP_CAUSE_EQUIP_FAIL,		"Equipment Failure" },
	{ BSSGP_CAUSE_TRASIT_NET_FAIL,		"Transit network service failure" },
	{ BSSGP_CAUSE_CAPA_GREATER_0KPBS,	"Transmission capacity modified" },
	{ BSSGP_CAUSE_UNKNOWN_MS,		"Unknown MS" },
	{ BSSGP_CAUSE_UNKNOWN_BVCI,		"Unknown BVCI" },
	{ BSSGP_CAUSE_CELL_TRAF_CONG,		"Cell traffic congestion" },
	{ BSSGP_CAUSE_SGSN_CONG,		"SGSN congestion" },
	{ BSSGP_CAUSE_OML_INTERV,		"O&M intervention" },
	{ BSSGP_CAUSE_BVCI_BLOCKED,		"BVCI blocked" },
	{ BSSGP_CAUSE_PFC_CREATE_FAIL,		"PFC create failure" },
	{ BSSGP_CAUSE_PFC_PREEMPTED,		"PFC preempted" },
	{ BSSGP_CAUSE_ABQP_NOT_SUPP,		"ABQP no more supported" },
	{ BSSGP_CAUSE_SEM_INCORR_PDU,		"Semantically incorrect PDU" },
	{ BSSGP_CAUSE_INV_MAND_INF,		"Invalid mandatory information" },
	{ BSSGP_CAUSE_MISSING_MAND_IE,		"Missing mandatory IE" },
	{ BSSGP_CAUSE_MISSING_COND_IE,		"Missing conditional IE" },
	{ BSSGP_CAUSE_UNEXP_COND_IE,		"Unexpected conditional IE" },
	{ BSSGP_CAUSE_COND_IE_ERR,		"Conditional IE error" },
	{ BSSGP_CAUSE_PDU_INCOMP_STATE,		"PDU incompatible with protocol state" },
	{ BSSGP_CAUSE_PROTO_ERR_UNSPEC,		"Protocol error - unspecified" },
	{ BSSGP_CAUSE_PDU_INCOMP_FEAT,		"PDU not compatible with feature set" },
	{ BSSGP_CAUSE_REQ_INFO_NOT_AVAIL,	"Requested Information not available" },
	{ BSSGP_CAUSE_UNKN_DST	,		"Unknown Destination address" },
	{ BSSGP_CAUSE_UNKN_RIM_AI,		"Unknown RIM Application Identity or RIM application disabled" },
	{ BSSGP_CAUSE_INVAL_CONT_UI,		"Invalid Container Unit Information" },
	{ BSSGP_CAUSE_PFC_QUEUE,		"PFC queuing" },
	{ BSSGP_CAUSE_PFC_CREATED,		"PFC created successfully" },
	{ BSSGP_CAUSE_T12_EXPIRY,		"T12 expiry" },
	{ BSSGP_CAUSE_MS_UNDER_PS_HO,		"MS under PS Handover treatment" },
	{ BSSGP_CAUSE_UL_QUALITY,		"Uplink quality" },
	{ BSSGP_CAUSE_UL_STRENGTH,		"Uplink strength" },
	{ BSSGP_CAUSE_DL_QUALITY,		"Downlink quality" },
	{ BSSGP_CAUSE_DL_STRENGTH,		"Downlink strength" },
	{ BSSGP_CAUSE_DISTANCE,			"Distance" },
	{ BSSGP_CAUSE_BETTER_CELL,		"Better cell" },
	{ BSSGP_CAUSE_TRAFFIC,			"Traffic" },
	{ BSSGP_CAUSE_MS_RADIO_LOSS,		"Radio contact lost with MS" },
	{ BSSGP_CAUSE_MS_BACK_OLD_CHAN,		"MS back on old channel" },
	{ BSSGP_CAUSE_T13_EXPIRY,		"T13 expiry" },
	{ BSSGP_CAUSE_T14_EXPIRY,		"T14 expiry" },
	{ BSSGP_CAUSE_NOT_ALL_PFC,		"Not all requested PFCs created" },
	{ BSSGP_CAUSE_CS,			"CS cause" },
	{ BSSGP_CAUSE_REQ_ALG_NOT_SUPP,		"Requested ciphering and/or integrity protection algorithms not supported" },
	{ BSSGP_CAUSE_RELOC_FAIL,		"Relocation failure in target system" },
	{ BSSGP_CAUSE_DIR_RETRY	,		"Directed Retry" },
	{ BSSGP_CAUSE_TIME_CRIT_RELOC	,	"Time critical relocation" },
	{ BSSGP_CAUSE_PS_HO_TARG_NA	,	"PS Handover Target not allowed" },
	{ BSSGP_CAUSE_PS_HO_TARG_NOT_SUPP,	"PS Handover not Supported in Target BSS or Target System" },
	{ BSSGP_CAUSE_PUESBINE,			"Incoming relocation not supported due to PUESBINE feature" },
	{ BSSGP_CAUSE_DTM_HO_NO_CS_RES,		"DTM Handover - No CS resource" },
	{ BSSGP_CAUSE_DTM_HO_PS_ALLOC_FAIL,	"DTM Handover - PS Allocation failure" },
	{ BSSGP_CAUSE_DTM_HO_T24_EXPIRY,	"DTM Handover - T24 expiry" },
	{ BSSGP_CAUSE_DTM_HO_INVAL_CS_IND,	"DTM Handover - Invalid CS Indication IE" },
	{ BSSGP_CAUSE_DTM_HO_T23_EXPIRY,	"DTM Handover - T23 expiry" },
	{ BSSGP_CAUSE_DTM_HO_MSC_ERR,		"DTM Handover - MSC Error" },
	{ BSSGP_CAUSE_INVAL_CSG_CELL,		"Invalid CSG cell" },
	{ 0, NULL },
};

static const struct value_string bssgp_pdu_strings[] = {
	{ BSSGP_PDUT_DL_UNITDATA,		"DL-UNITDATA" },
	{ BSSGP_PDUT_UL_UNITDATA,		"UL-UNITDATA" },
	{ BSSGP_PDUT_RA_CAPABILITY,		"RA-CAPABILITY" },
	{ BSSGP_PDUT_PTM_UNITDATA,		"PTM-UNITDATA" },
	{ BSSGP_PDUT_DL_MMBS_UNITDATA,		"DL-MBMS-UNITDATA" },
	{ BSSGP_PDUT_UL_MMBS_UNITDATA,		"UL-MBMS-UNITDATA" },
	{ BSSGP_PDUT_PAGING_PS,			"PAGING-PS" },
	{ BSSGP_PDUT_PAGING_CS,			"PAGING-CS" },
	{ BSSGP_PDUT_RA_CAPA_UDPATE,		"RA-CAPABILITY-UPDATE" },
	{ BSSGP_PDUT_RA_CAPA_UPDATE_ACK,	"RA-CAPABILITY-UPDATE-ACK" },
	{ BSSGP_PDUT_RADIO_STATUS,		"RADIO-STATUS" },
	{ BSSGP_PDUT_SUSPEND,			"SUSPEND" },
	{ BSSGP_PDUT_SUSPEND_ACK,		"SUSPEND-ACK" },
	{ BSSGP_PDUT_SUSPEND_NACK,		"SUSPEND-NACK" },
	{ BSSGP_PDUT_RESUME,			"RESUME" },
	{ BSSGP_PDUT_RESUME_ACK,		"RESUME-ACK" },
	{ BSSGP_PDUT_RESUME_NACK,		"RESUME-NACK" },
	{ BSSGP_PDUT_DUMMY_PAGING_PS,		"DUMMY-PAGING-PS" },
	{ BSSGP_PDUT_DUMMY_PAGING_PS_RESP,	"DUMMY-PAGING-PS-RESP" },
	{ BSSGP_PDUT_MS_REGISTR_ENQ,		"MS-REGISTRATION-ENQ" },
	{ BSSGP_PDUT_MS_REGISTR_ENQ_RESP,	"MS-REGISTRATION-ENQ-RESP" },
	{ BSSGP_PDUT_BVC_BLOCK,			"BVC-BLOCK" },
	{ BSSGP_PDUT_BVC_BLOCK_ACK,		"BVC-BLOCK-ACK" },
	{ BSSGP_PDUT_BVC_RESET,			"BVC-RESET" },
	{ BSSGP_PDUT_BVC_RESET_ACK,		"BVC-RESET-ACK" },
	{ BSSGP_PDUT_BVC_UNBLOCK,		"BVC-UNBLOCK" },
	{ BSSGP_PDUT_BVC_UNBLOCK_ACK,		"BVC-UNBLOCK-ACK" },
	{ BSSGP_PDUT_FLOW_CONTROL_BVC,		"FLOW-CONTROL-BVC" },
	{ BSSGP_PDUT_FLOW_CONTROL_BVC_ACK,	"FLOW-CONTROL-BVC-ACK" },
	{ BSSGP_PDUT_FLOW_CONTROL_MS,		"FLOW-CONTROL-MS" },
	{ BSSGP_PDUT_FLOW_CONTROL_MS_ACK,	"FLOW-CONTROL-MS-ACK" },
	{ BSSGP_PDUT_FLUSH_LL,			"FLUSH-LL" },
	{ BSSGP_PDUT_FLUSH_LL_ACK,		"FLUSH-LL-ACK" },
	{ BSSGP_PDUT_LLC_DISCARD,		"LLC DISCARDED" },
	{ BSSGP_PDUT_FLOW_CONTROL_PFC,		"FLOW-CONTROL-PFC" },
	{ BSSGP_PDUT_FLOW_CONTROL_PFC_ACK,	"FLOW-CONTROL-PFC-ACK" },
	{ BSSGP_PDUT_SGSN_INVOKE_TRACE,		"SGSN-INVOKE-TRACE" },
	{ BSSGP_PDUT_STATUS,			"STATUS" },
	{ BSSGP_PDUT_OVERLOAD,			"OVERLOAD" },
	{ BSSGP_PDUT_DOWNLOAD_BSS_PFC,		"DOWNLOAD-BSS-PFC" },
	{ BSSGP_PDUT_CREATE_BSS_PFC,		"CREATE-BSS-PFC" },
	{ BSSGP_PDUT_CREATE_BSS_PFC_ACK,	"CREATE-BSS-PFC-ACK" },
	{ BSSGP_PDUT_CREATE_BSS_PFC_NACK,	"CREATE-BSS-PFC-NACK" },
	{ BSSGP_PDUT_MODIFY_BSS_PFC,		"MODIFY-BSS-PFC" },
	{ BSSGP_PDUT_MODIFY_BSS_PFC_ACK,	"MODIFY-BSS-PFC-ACK" },
	{ BSSGP_PDUT_DELETE_BSS_PFC,		"DELETE-BSS-PFC" },
	{ BSSGP_PDUT_DELETE_BSS_PFC_ACK,	"DELETE-BSS-PFC-ACK" },
	{ BSSGP_PDUT_DELETE_BSS_PFC_REQ,	"DELETE-BSS-PFC-REQ" },
	{ BSSGP_PDUT_PS_HO_REQUIRED,		"PS-HO-REQUIRED" },
	{ BSSGP_PDUT_PS_HO_REQUIRED_ACK,	"PS-HO-REQUIRED-ACK" },
	{ BSSGP_PDUT_PS_HO_REQUIRED_NACK,	"PS-HO-REQUIRED-NACK" },
	{ BSSGP_PDUT_PS_HO_REQUEST,		"PS-HO-REQUEST" },
	{ BSSGP_PDUT_PS_HO_REQUEST_ACK,		"PS-HO-REQUEST-ACK" },
	{ BSSGP_PDUT_PS_HO_REQUEST_NACK,	"PS-HO-REQUEST-NACK" },
	{ BSSGP_PDUT_PS_HO_COMPLETE,		"PS-HO-COMPLETE" },
	{ BSSGP_PDUT_PS_HO_CANCEL,		"PS-HO-CANCEL" },
	{ BSSGP_PDUT_PS_HO_COMPLETE_ACK,	"PS-HO-COMPLETE-ACK" },
	{ BSSGP_PDUT_PERFORM_LOC_REQ,		"PERFORM-LOC-REQ" },
	{ BSSGP_PDUT_PERFORM_LOC_RESP,		"PERFORM-LOC-RESP" },
	{ BSSGP_PDUT_PERFORM_LOC_ABORT,		"PERFORM-LOC-ABORT" },
	{ BSSGP_PDUT_POSITION_COMMAND,		"POSITION-COMMAND" },
	{ BSSGP_PDUT_POSITION_RESPONSE,		"POSITION-RESPONSE" },
	{ BSSGP_PDUT_RAN_INFO,			"RAN-INFO" },
	{ BSSGP_PDUT_RAN_INFO_REQ,		"RAN-INFO-REQ" },
	{ BSSGP_PDUT_RAN_INFO_ACK,		"RAN-INFO-ACK" },
	{ BSSGP_PDUT_RAN_INFO_ERROR,		"RAN-INFO-ERROR" },
	{ BSSGP_PDUT_RAN_INFO_APP_ERROR,	"RAN-INFO-APP-ERROR" },
	{ BSSGP_PDUT_MBMS_START_REQ,		"MBMS-START-REQ" },
	{ BSSGP_PDUT_MBMS_START_RESP,		"MBMS-START-RESP" },
	{ BSSGP_PDUT_MBMS_STOP_REQ,		"MBMS-STOP-REQ" },
	{ BSSGP_PDUT_MBMS_STOP_RESP,		"MBMS-STOP-RESP" },
	{ BSSGP_PDUT_MBMS_UPDATE_REQ,		"MBMS-UPDATE-REQ" },
	{ BSSGP_PDUT_MBMS_UPDATE_RESP,		"MBMS-UPDATE-RESP" },
	{ 0, NULL },
};

static const uint8_t dl_ud_ies[] = { BSSGP_IE_PDU_LIFETIME };
static const uint8_t ul_ud_ies[] = { BSSGP_IE_CELL_ID };
static const uint8_t ra_cap_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_MS_RADIO_ACCESS_CAP };
static const uint8_t dl_mb_ud_ies[] = { BSSGP_IE_PDU_LIFETIME, BSSGP_IE_TMGI, BSSGP_IE_LLC_PDU };
static const uint8_t ul_mb_ud_ies[] = { BSSGP_IE_PDU_LIFETIME, BSSGP_IE_TMGI, BSSGP_IE_LLC_PDU };
static const uint8_t pag_ps_ies[] = { BSSGP_IE_IMSI, BSSGP_IE_QOS_PROFILE };
static const uint8_t pag_cs_ies[] = { BSSGP_IE_IMSI, BSSGP_IE_DRX_PARAMS };
static const uint8_t ra_cap_upd_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_TAG };
static const uint8_t ra_cap_upd_ack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_TAG, BSSGP_IE_RA_CAP_UPD_CAUSE };
static const uint8_t rad_sts_ies[] = { BSSGP_IE_RADIO_CAUSE };
static const uint8_t suspend_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_ROUTEING_AREA };
static const uint8_t suspend_ack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_ROUTEING_AREA, BSSGP_IE_SUSPEND_REF_NR };
static const uint8_t suspend_nack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_ROUTEING_AREA };
static const uint8_t resume_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_ROUTEING_AREA, BSSGP_IE_SUSPEND_REF_NR };
static const uint8_t resume_ack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_ROUTEING_AREA };
static const uint8_t resume_nack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_ROUTEING_AREA };
static const uint8_t d_pag_ps_ies[] = { BSSGP_IE_IMSI };
static const uint8_t d_pag_ps_resp_ies[] = { BSSGP_IE_IMSI, BSSGP_IE_T_UNTIL_NEXT_PAGING };
static const uint8_t d_pag_ps_rej_ies[] = { BSSGP_IE_IMSI, BSSGP_IE_T_UNTIL_NEXT_PAGING };
static const uint8_t ms_reg_enq_ies[] = { BSSGP_IE_IMSI };
static const uint8_t ms_reg_enq_res_ies[] = { BSSGP_IE_IMSI };
static const uint8_t flush_ll_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_BVCI };
static const uint8_t flush_ll_ack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_FLUSH_ACTION };
static const uint8_t llc_disc_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_LLC_FRAMES_DISCARDED, BSSGP_IE_BVCI,
					BSSGP_IE_NUM_OCT_AFF };
static const uint8_t fc_bvc_ies[] = { BSSGP_IE_TAG, BSSGP_IE_BVC_BUCKET_SIZE, BSSGP_IE_BUCKET_LEAK_RATE,
				      BSSGP_IE_BMAX_DEFAULT_MS, BSSGP_IE_R_DEFAULT_MS };
static const uint8_t fc_bvc_ack_ies[] = { BSSGP_IE_TAG };
static const uint8_t fc_ms_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_TAG, BSSGP_IE_MS_BUCKET_SIZE,
				     BSSGP_IE_BUCKET_LEAK_RATE };
static const uint8_t fc_ms_ack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_TAG };
static const uint8_t block_ies[] = { BSSGP_IE_BVCI, BSSGP_IE_CAUSE };
static const uint8_t block_ack_ies[] = { BSSGP_IE_BVCI };
static const uint8_t unblock_ies[] = { BSSGP_IE_BVCI };
static const uint8_t unblock_ack_ies[] = { BSSGP_IE_BVCI };
static const uint8_t reset_ies[] = { BSSGP_IE_BVCI, BSSGP_IE_CAUSE };
static const uint8_t reset_ack_ies[] = { BSSGP_IE_BVCI };
static const uint8_t status_ies[] = { BSSGP_IE_CAUSE };
static const uint8_t inv_trc_ies[] = { BSSGP_IE_TRACE_TYPE, BSSGP_IE_TRACE_REFERENC };
static const uint8_t dl_bss_pfc_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_PACKET_FLOW_ID };
static const uint8_t crt_bss_pfc_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_PACKET_FLOW_ID,
					   BSSGP_IE_PACKET_FLOW_TIMER, BSSGP_IE_AGG_BSS_QOS_PROFILE };
static const uint8_t crt_bss_pfc_ack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_PACKET_FLOW_ID,
						BSSGP_IE_AGG_BSS_QOS_PROFILE };
static const uint8_t crt_bss_pfc_nack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_PACKET_FLOW_ID, BSSGP_IE_CAUSE };
static const uint8_t mod_bss_pfc_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_PACKET_FLOW_ID,
					   BSSGP_IE_AGG_BSS_QOS_PROFILE };
static const uint8_t mod_bss_pfc_ack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_PACKET_FLOW_ID,
					       BSSGP_IE_PACKET_FLOW_TIMER, BSSGP_IE_AGG_BSS_QOS_PROFILE };
static const uint8_t del_bss_pfc_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_PACKET_FLOW_ID };
static const uint8_t del_bss_pfc_ack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_PACKET_FLOW_ID };
static const uint8_t fc_pfc_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_TAG, BSSGP_IE_PFC_FLOW_CTRL_PARAMS };
static const uint8_t fc_pfc_ack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_TAG };
static const uint8_t del_bss_pfc_req_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_PACKET_FLOW_ID, BSSGP_IE_CAUSE };
static const uint8_t ps_ho_required_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_CAUSE, BSSGP_IE_CELL_ID,
					      BSSGP_IE_ACTIVE_PFC_LIST };
static const uint8_t ps_ho_required_ack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_LIST_OF_SETUP_PFC };
static const uint8_t ps_ho_required_nack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_CAUSE };
static const uint8_t ps_ho_request_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_IMSI, BSSGP_IE_CAUSE,
					     BSSGP_IE_CELL_ID, BSSGP_IE_SBSS_TO_TBSS_TR_CONT,
					     BSSGP_IE_PFC_TO_BE_SETUP_LIST };
static const uint8_t ps_ho_request_ack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_LIST_OF_SETUP_PFC,
						 BSSGP_IE_TBSS_TO_SBSS_TR_CONT };
static const uint8_t ps_ho_request_nack_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_CAUSE };
static const uint8_t ps_ho_compl_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_IMSI };
static const uint8_t ps_ho_cancel_ies[] = { BSSGP_IE_TLLI, BSSGP_IE_CAUSE, BSSGP_IE_CELL_ID };
static const uint8_t ps_ho_compl_ack_ies[] = { BSSGP_IE_TLLI };
static const uint8_t overload_ies[] = { BSSGP_IE_PRIO_CLASS_IND };
static const uint8_t rinfo_ies[] = { BSSGP_IE_RIM_ROUTING_INFO, BSSGP_IE_RI_RIM_CONTAINER };
static const uint8_t rinfo_req_ies[] = { BSSGP_IE_RIM_ROUTING_INFO, BSSGP_IE_RI_REQ_RIM_CONTAINER };
static const uint8_t rinfo_ack_ies[] = { BSSGP_IE_RIM_ROUTING_INFO, BSSGP_IE_RI_ACK_RIM_CONTAINER };
static const uint8_t rinfo_err_ies[] = { BSSGP_IE_RIM_ROUTING_INFO, BSSGP_IE_RI_ERROR_RIM_COINTAINER };
static const uint8_t rinfo_aerr_ies[] = { BSSGP_IE_RIM_ROUTING_INFO, BSSGP_IE_RI_APP_ERROR_RIM_CONT };

#define DL	BSSGP_PDUF_DL
#define UL	BSSGP_PDUF_UL
#define SIG	BSSGP_PDUF_SIG
#define PTP	BSSGP_PDUF_PTP
#define PTM	BSSGP_PDUF_PTM

const struct osmo_tlv_prot_def osmo_pdef_bssgp = {
	.name = "BSSGP",
	.tlv_def = &tvlv_att_def,
	.msg_def = {
		[BSSGP_PDUT_DL_UNITDATA] = MSG_DEF("DL-UNITDATA", dl_ud_ies, DL|PTP),
		[BSSGP_PDUT_UL_UNITDATA] = MSG_DEF("UL-UNITDATA", ul_ud_ies, UL|PTP),
		[BSSGP_PDUT_RA_CAPABILITY] = MSG_DEF("RA-CAPABILITY", ra_cap_ies, DL|PTP),
		[BSSGP_PDUT_DL_MMBS_UNITDATA] = MSG_DEF("DL-MBMS-UNITDATA", dl_mb_ud_ies, DL|PTM),
		[BSSGP_PDUT_UL_MMBS_UNITDATA] = MSG_DEF("UL-MBMS-UNITDATA", ul_mb_ud_ies, UL|PTM),
		[BSSGP_PDUT_PAGING_PS] = MSG_DEF("PAGING-PS", pag_ps_ies, DL|PTP|SIG),
		[BSSGP_PDUT_PAGING_CS] = MSG_DEF("PAGING-CS", pag_cs_ies, DL|PTP|SIG),
		[BSSGP_PDUT_RA_CAPA_UDPATE] = MSG_DEF("RA-CAPABILITY-UPDATE", ra_cap_upd_ies, UL|PTP),
		[BSSGP_PDUT_RA_CAPA_UPDATE_ACK] = MSG_DEF("RA-CAPABILITY-UPDATE-ACK", ra_cap_upd_ack_ies, DL|PTP),
		[BSSGP_PDUT_RADIO_STATUS] = MSG_DEF("RADIO-STATUS", rad_sts_ies, UL|PTP),
		[BSSGP_PDUT_SUSPEND] = MSG_DEF("SUSPEND", suspend_ies, UL|SIG),
		[BSSGP_PDUT_SUSPEND_ACK] = MSG_DEF("SUSPEND-ACK", suspend_ack_ies, DL|SIG),
		[BSSGP_PDUT_SUSPEND_NACK] = MSG_DEF("SUSPEND-NACK", suspend_nack_ies, DL|SIG),
		[BSSGP_PDUT_RESUME] = MSG_DEF("RESUME", resume_ies, UL|SIG),
		[BSSGP_PDUT_RESUME_ACK] = MSG_DEF("RESUME-ACK", resume_ack_ies, DL|SIG),
		[BSSGP_PDUT_RESUME_NACK] = MSG_DEF("RESUME-NACK", resume_nack_ies, DL|SIG),
		[BSSGP_PDUT_DUMMY_PAGING_PS] = MSG_DEF("DUMMY-PAGING-PS", d_pag_ps_ies, DL|SIG|PTP),
		[BSSGP_PDUT_DUMMY_PAGING_PS_RESP] = MSG_DEF("DUMMY-PAGING-PS-RESP", d_pag_ps_resp_ies, UL|SIG|PTP),
		[BSSGP_PDUT_PAGING_PS_REJECT] = MSG_DEF("PAGING-PS-REJ", d_pag_ps_rej_ies, UL|SIG|PTP),
		[BSSGP_PDUT_MS_REGISTR_ENQ] = MSG_DEF("MS-REGISRATION-ENQ", ms_reg_enq_ies, UL|SIG),
		[BSSGP_PDUT_MS_REGISTR_ENQ_RESP] = MSG_DEF("MS-REGISRATION-ENQ-RESP", ms_reg_enq_res_ies, DL|SIG),
		[BSSGP_PDUT_FLUSH_LL] = MSG_DEF("FLUSH-LL", flush_ll_ies, DL|SIG),
		[BSSGP_PDUT_FLUSH_LL_ACK] = MSG_DEF("FLUSH-LL-ACK", flush_ll_ack_ies, UL|SIG),
		[BSSGP_PDUT_LLC_DISCARD] = MSG_DEF("LLC-DISCARDED", llc_disc_ies, UL|SIG),
		[BSSGP_PDUT_FLOW_CONTROL_BVC] = MSG_DEF("FC-BVC", fc_bvc_ies, UL|PTP),
		[BSSGP_PDUT_FLOW_CONTROL_BVC_ACK] = MSG_DEF("FC-BVC-ACK", fc_bvc_ack_ies, DL|PTP),
		[BSSGP_PDUT_FLOW_CONTROL_MS] = MSG_DEF("FC-MS", fc_ms_ies, UL|PTP),
		[BSSGP_PDUT_FLOW_CONTROL_MS_ACK] = MSG_DEF("FC-MS-ACK", fc_ms_ack_ies, DL|PTP),
		[BSSGP_PDUT_BVC_BLOCK] = MSG_DEF("BVC-BLOCK", block_ies, UL|SIG),
		[BSSGP_PDUT_BVC_BLOCK_ACK] = MSG_DEF("BVC-BLOCK-ACK", block_ack_ies, DL|SIG),
		[BSSGP_PDUT_BVC_UNBLOCK] = MSG_DEF("BVC-UNBLOCK", unblock_ies, UL|SIG),
		[BSSGP_PDUT_BVC_UNBLOCK_ACK] = MSG_DEF("BVC-UNBLOCK-ACK", unblock_ack_ies, DL|SIG),
		[BSSGP_PDUT_BVC_RESET] = MSG_DEF("BVC-RESET", reset_ies, UL|DL|SIG|PTP),
		[BSSGP_PDUT_BVC_RESET_ACK] = MSG_DEF("BVC-RESET-ACK", reset_ack_ies, UL|DL|SIG|PTP),
		[BSSGP_PDUT_STATUS] = MSG_DEF("STATUS", status_ies, UL|DL|PTP|SIG|PTM),
		[BSSGP_PDUT_SGSN_INVOKE_TRACE] = MSG_DEF("SGSN-INVOKE-TRACE", inv_trc_ies, DL|SIG),
		[BSSGP_PDUT_DOWNLOAD_BSS_PFC] = MSG_DEF("DOWNLOAD-BSS-PFC", dl_bss_pfc_ies, UL|PTP),
		[BSSGP_PDUT_CREATE_BSS_PFC] = MSG_DEF("CREATE-BSS-PFC", crt_bss_pfc_ies, DL|PTP),
		[BSSGP_PDUT_CREATE_BSS_PFC_ACK] = MSG_DEF("CREATE-BSS-PFC-ACK", crt_bss_pfc_ack_ies, UL|PTP),
		[BSSGP_PDUT_CREATE_BSS_PFC_NACK] = MSG_DEF("CREATE-BSS-PFC-NACK", crt_bss_pfc_nack_ies, UL|PTP),
		[BSSGP_PDUT_MODIFY_BSS_PFC] = MSG_DEF("MODIFY-BSS-PFC", mod_bss_pfc_ies, DL|PTP),
		[BSSGP_PDUT_MODIFY_BSS_PFC_ACK] = MSG_DEF("MODIFY-BSS-PFC-ACK", mod_bss_pfc_ack_ies, UL|PTP),
		[BSSGP_PDUT_DELETE_BSS_PFC] = MSG_DEF("DELETE-BSS-PFC", del_bss_pfc_ies, DL|PTP),
		[BSSGP_PDUT_DELETE_BSS_PFC_ACK] = MSG_DEF("DELETE-BSS-PFC-ACK", del_bss_pfc_ack_ies, UL|PTP),
		[BSSGP_PDUT_FLOW_CONTROL_PFC] = MSG_DEF("FC-PFC", fc_pfc_ies, UL|PTP),
		[BSSGP_PDUT_FLOW_CONTROL_PFC_ACK] = MSG_DEF("FC-PFC-ACK", fc_pfc_ack_ies, DL|PTP),
		[BSSGP_PDUT_DELETE_BSS_PFC_REQ] = MSG_DEF("DELETE-BSS-PFC-REQ", del_bss_pfc_req_ies, UL|PTP),
		[BSSGP_PDUT_PS_HO_REQUIRED] = MSG_DEF("PS-HO-REQUIRED", ps_ho_required_ies, UL|PTP),
		[BSSGP_PDUT_PS_HO_REQUIRED_ACK] = MSG_DEF("PS-HO-REQUIRED-ACK", ps_ho_required_ack_ies, DL|PTP),
		[BSSGP_PDUT_PS_HO_REQUIRED_NACK] = MSG_DEF("PS-HO-REQUIRED-NACK", ps_ho_required_nack_ies, DL|PTP),
		[BSSGP_PDUT_PS_HO_REQUEST] = MSG_DEF("PS-HO-REQUEST", ps_ho_request_ies, DL|PTP),
		[BSSGP_PDUT_PS_HO_REQUEST_ACK] = MSG_DEF("PS-HO-REQUEST-ACK", ps_ho_request_ack_ies, UL|PTP),
		[BSSGP_PDUT_PS_HO_REQUEST_NACK] = MSG_DEF("PS-HO-REQUEST-NACK", ps_ho_request_nack_ies, UL|PTP),
		[BSSGP_PDUT_PS_HO_COMPLETE] = MSG_DEF("PS-HO-COMPLETE", ps_ho_compl_ies, UL|PTP),
		[BSSGP_PDUT_PS_HO_CANCEL] = MSG_DEF("PS-HO-CANCEL", ps_ho_cancel_ies, UL|PTP),
		[BSSGP_PDUT_PS_HO_COMPLETE_ACK] = MSG_DEF("PS-HO-COMPLETE-ACK", ps_ho_compl_ack_ies, DL|PTP),
		[BSSGP_PDUT_OVERLOAD] = MSG_DEF("OVERLOAD", overload_ies, DL|SIG),
		/* TODO: Messages on LCS SAP */
		/* Messages on RIM SAP */
		[BSSGP_PDUT_RAN_INFO] = MSG_DEF("RAN-INFORMATION", rinfo_ies, DL|UL|SIG),
		[BSSGP_PDUT_RAN_INFO_REQ] = MSG_DEF("RAN-INFORMATION-REQUEST", rinfo_req_ies, DL|UL|SIG),
		[BSSGP_PDUT_RAN_INFO_ACK] = MSG_DEF("RAN-INFORMATION-ACK", rinfo_ack_ies, DL|UL|SIG),
		[BSSGP_PDUT_RAN_INFO_ERROR] = MSG_DEF("RAN-INFORMATION-ERROR", rinfo_err_ies, DL|UL|SIG),
		[BSSGP_PDUT_RAN_INFO_APP_ERROR] = MSG_DEF("RAN-INFORMATION-APP-ERROR", rinfo_aerr_ies, DL|UL|SIG),
		/* TODO: Messages on MBMS SAP */
	},
	.ie_def = {
		[BSSGP_IE_ALIGNMENT] = { 0, "Alignment Octets" },
		[BSSGP_IE_BMAX_DEFAULT_MS] = { 2, "Bmax default MS" },
		[BSSGP_IE_BSS_AREA_ID] = { 1, "BSS Area Indication" },
		[BSSGP_IE_BUCKET_LEAK_RATE] = { 2, "Bucket Leak Rate (R)" },
		[BSSGP_IE_BVC_BUCKET_SIZE] = { 2, "BVC Bucket Size" },
		[BSSGP_IE_BVCI] = { 2, "BVCI" },
		[BSSGP_IE_BVC_MEASUREMENT] = {2, "BVC Measurement" },
		[BSSGP_IE_CAUSE] = { 1, "Cause" },
		[BSSGP_IE_CELL_ID] = { 8, "Cell Identifier" },
		[BSSGP_IE_CHAN_NEEDED] = { 1, "Channel Needed" },
		[BSSGP_IE_DRX_PARAMS] = { 2, "DRX Parameters" },
		[BSSGP_IE_EMLPP_PRIO] = { 3, "eMLPP Priority" },
		[BSSGP_IE_FLUSH_ACTION] = { 1, "Flush Action" },
		[BSSGP_IE_IMSI] = { 1, "Mobile Identity" },
		[BSSGP_IE_LLC_PDU] = { 0, "LLC-PDU" },
		[BSSGP_IE_LLC_FRAMES_DISCARDED] = { 1, "LLC Frames Discarded" },
		[BSSGP_IE_LOCATION_AREA] = { 5, "Location Area" },
		[BSSGP_IE_LSA_ID_LIST] = { 3, "LSA Identifier List" },
		[BSSGP_IE_LSA_INFORMATION] = { 5, "LSA Information" },
		[BSSGP_IE_MOBILE_ID] = { 1, "Mobile Identity" },
		[BSSGP_IE_MS_BUCKET_SIZE] = { 2, "MS Bucket Size" },
		[BSSGP_IE_MS_RADIO_ACCESS_CAP] = { 1, "MS Radio Access Capability" },
		[BSSGP_IE_OMC_ID] = { 1, "OMC Id" },
		[BSSGP_IE_PDU_IN_ERROR] = { 0, "PDU In Error" },
		[BSSGP_IE_PDU_LIFETIME] = { 2, "PDU Lifetime" },
		[BSSGP_IE_PRIORITY] = { 1, "Priority" },
		[BSSGP_IE_QOS_PROFILE] = { 3, "QoS Profile" },
		[BSSGP_IE_RADIO_CAUSE] = { 1, "Radio Cause" },
		[BSSGP_IE_RA_CAP_UPD_CAUSE] = { 1, "RA-Cap-UPD-Cause" },
		[BSSGP_IE_ROUTEING_AREA] = { 6, "Routeing Area" },
		[BSSGP_IE_R_DEFAULT_MS] = { 2, "R_default_MS" },
		[BSSGP_IE_SUSPEND_REF_NR] = { 1, "Suspend Reference Number" },
		[BSSGP_IE_TAG] = { 1, "Tag" },
		[BSSGP_IE_TLLI] = { 4, "TLLI" },
		[BSSGP_IE_TMSI] = { 4, "TMSI" },
		[BSSGP_IE_TRACE_REFERENC] = { 2, "Trace Reference" },
		[BSSGP_IE_TRACE_TYPE] = { 1, "Trace Type" },
		[BSSGP_IE_TRANSACTION_ID] = { 2, "Transaction Id" },
		[BSSGP_IE_TRIGGER_ID] = { 1, "Trigger Id" },
		[BSSGP_IE_NUM_OCT_AFF] = { 3, "Number of octets affected" },
		[BSSGP_IE_PACKET_FLOW_ID] = { 1, "Packet Flow Identifier (PFI)" },
		[BSSGP_IE_AGG_BSS_QOS_PROFILE] = { 14, "Aggregate BSS QoS Profile" },
		[BSSGP_IE_PACKET_FLOW_TIMER] = { 1, "GPRS Timer" },
		[BSSGP_IE_FEATURE_BITMAP] = { 1, "Feature Bitmap" },
		[BSSGP_IE_BUCKET_FULL_RATIO] = { 1, "Bucket Full Ratio" },
		[BSSGP_IE_SERVICE_UTRAN_CCO] = { 1, "Service UTRAN COO" },
		[BSSGP_IE_NSEI] = { 2, "NSEI" },
		[BSSGP_IE_RRLP_APDU] = { 1, "RLLP APDU" },
		[BSSGP_IE_LCS_QOS] = { 4, "LCS QoS" },
		[BSSGP_IE_LCS_CLIENT_TYPE] = { 1, "LCS Client Type" },
		[BSSGP_IE_REQUESTED_GPS_AST_DATA] = { 4, "Requested GPS Assistance Data" },
		[BSSGP_IE_LOCATION_TYPE] = { 2, "Location Type" },
		[BSSGP_IE_LOCATION_ESTIMATE] = { 1, "Location Estimate" },
		[BSSGP_IE_POSITIONING_DATA] = { 1, "Positioning Data" },
		[BSSGP_IE_DECIPHERING_KEYS] = { 15, "Deciphering Keys" },
		[BSSGP_IE_LCS_PRIORITY] = { 1, "LCS Priority" },
		[BSSGP_IE_LCS_CAUSE] = { 1, "LCS Cause" },
		[BSSGP_IE_LCS_CAPABILITY] = { 1, "LCS Capability" },
		[BSSGP_IE_RRLP_FLAGS] = { 1, "RRLP Flags" },
		[BSSGP_IE_RIM_APP_IDENTITY] = { 1, "RIM Application Identity" },
		[BSSGP_IE_RIM_SEQ_NR] = { 4, "RIM Sequence Number" },
		[BSSGP_IE_RIM_REQ_APP_CONTAINER] = { 12, "RIM-REQUEST RIM Container" },
		[BSSGP_IE_RAN_INFO_APP_CONTAINER] = { 12, "RAN-INFORMATION RIM Container" },
		[BSSGP_IE_RI_ACK_RIM_CONTAINER] = { 9, "RAN-INFORMATION-ACK RIM Container" },
		[BSSGP_IE_RI_ERROR_RIM_COINTAINER] = { 9, "RAN-INFOIRMATION-ERROR RIM Container" },
		[BSSGP_IE_RI_APP_ERROR_RIM_CONT] = { 14, "RAN-INFORMATION-APP-ERROR RIM Container" },
		[BSSGP_IE_RIM_PDU_INDICATIONS] = { 1, "RIM PDU Indications" },
		[BSSGP_IE_RIM_PROTOCOL_VERSION] = { 1, "RIM Protocol Version Number" },
		[BSSGP_IE_PFC_FLOW_CTRL_PARAMS] = { 7, "PFC FLow Control Parameters" },
		[BSSGP_IE_GLOBAL_CN_ID] = { 5, "Global CN-Id" },
		[BSSGP_IE_RIM_ROUTING_INFO] = { 1, "RIM Routing Information" },
		[BSSGP_IE_MBMS_SESSION_ID] = { 0, "MBMS Session Identity" },
		[BSSGP_IE_MBMS_SESSION_DURATION] = { 0, "MBMS Session Duration" },
		[BSSGP_IE_MBMS_SA_ID_LIST] = { 3, "MBMS Service Area Identity List" },
		[BSSGP_IE_MBMS_RESPONSE] = { 1, "MBMS Response" },
		[BSSGP_IE_MBMS_RA_LIST] = { 9, "MBMS Routing Area List" },
		[BSSGP_IE_MBMS_SESSION_INFO] = { 1, "MBMS Session Information" },
		[BSSGP_IE_TMGI] = { 6, "TMGI" },
		[BSSGP_IE_MBMS_STOP_CAUSE] = { 1, "MBM Stop Cause" },
		[BSSGP_IE_SBSS_TO_TBSS_TR_CONT] = { 7, "Source BSS to Target BSS Transparent Container" },
		[BSSGP_IE_TBSS_TO_SBSS_TR_CONT] = { 0, "Target BSS to Source BSS Transparent Container" },
		[BSSGP_IE_NAS_CONT_FOR_PS_HO] = { 0, "NAS container for PS Handover" },
		[BSSGP_IE_PFC_TO_BE_SETUP_LIST] = { 9, "PFCs to be set-up list" },
		[BSSGP_IE_LIST_OF_SETUP_PFC] = { 1, "List of set-up PFCs" },
		[BSSGP_IE_EXT_FEATURE_BITMAP] = { 1, "Extended Feature Bitmap" },
		[BSSGP_IE_SRC_TO_TGT_TR_CONT] = { 0, "Source to Target Transparent Container" },
		[BSSGP_IE_TGT_TO_SRC_TR_CONT] = { 0, "Target to Source Transparent Container" },
		[BSSGP_IE_NC_ID] = { 8, "RNC Identifier" },
		[BSSGP_IE_PAGE_MODE] = { 1, "Page Mode" },
		[BSSGP_IE_CONTAINER_ID] = { 1, "Container ID" },
		[BSSGP_IE_GLOBAL_TFI] = { 1, "Global TFI" },
		[BSSGP_IE_IMEI] = { 1, "IMEI" },
		[BSSGP_IE_TIME_TO_MBMS_DATA_XFR] = { 1, "Time to MBMS Data Transfer" },
		[BSSGP_IE_MBMS_SESSION_REP_NR] = { 1, "MBMS Session Repetition Number" },
		[BSSGP_IE_INTER_RAT_HO_INFO] = { 0, "Inter RAT Handover Info" },
		[BSSGP_IE_PS_HO_COMMAND] = { 0, "PS Handover Command" },
		[BSSGP_IE_PS_HO_INDICATIONS] = { 1, "PS Handover Indications" },
		[BSSGP_IE_SI_PSI_CONTAINER] = { 1, "SI/PSI Container" },
		[BSSGP_IE_ACTIVE_PFC_LIST] = { 2, "Active PFCs List" },
		[BSSGP_IE_VELOCITY_DATA] = { 0, "Velocity Data" },
		[BSSGP_IE_DTM_HO_COMMAND] = { 0, "DTM Handover Command" },
		[BSSGP_IE_CS_INDICATION] = { 1, "CS Indication" },
		[BSSGP_IE_RQD_GANNS_AST_DATA] = { 0, "Requested GANSS Assistance Data" },
		[BSSGP_IE_GANSS_LOCATION_TYPE] = { 1, "GANSS Location Type" },
		[BSSGP_IE_GANSS_POSITIONING_DATA] = { 0, "GANSS Positioning Data" },
		[BSSGP_IE_FLOW_CTRL_GRANULARITY] = { 1, "Flow Control Granularity" },
		[BSSGP_IE_ENB_ID] = { 6, "eNB Identifier" },
		[BSSGP_IE_EUTRAN_IRAT_HO_INFO] = { 0, "E-UTRAN Inter RAT Handover Info" },
		[BSSGP_IE_SUB_PID4RAT_FREQ_PRIO] = { 1, "Subscriber Profile ID for RAT/Frequency priority" },
		[BSSGP_IE_REQ4IRAT_HO_INFO] = { 1, "Request for Inter-RAT Handover Info" },
		[BSSGP_IE_RELIABLE_IRAT_HO_INFO] = { 1, "Reliable Inter-RAT Handover Info" },
		[BSSGP_IE_SON_TRANSFER_APP_ID] = { 0, "SON Transfer Application Identity" },
		[BSSGP_IE_CSG_ID] = { 5, "CSG Identifier" },
		[BSSGP_IE_TAC] = { 3, "Tracking Area Code" },
		[BSSGP_IE_REDIRECT_ATTEMPT_FLAG] = { 1, "Redirect Attempt Flag" },
		[BSSGP_IE_REDIRECTION_INDICATION] = { 1, "Redirection Indication" },
		[BSSGP_IE_REDIRECTION_COMPLETED] = { 1, "Redirection Completed" },
		[BSSGP_IE_UNCONF_SEND_STATE_VAR] = { 2, "Unconfirmed send state variable" },
		[BSSGP_IE_IRAT_MEASUREMENT_CONF] = { 10, "IRAT Measurement Configuration" },
		[BSSGP_IE_SCI] = { 1, "SCI" },
		[BSSGP_IE_GGSN_PGW_LOCATION] = { 1, "GGSN/P-GW Location" },
		[BSSGP_IE_SELECTED_PLMN_ID] = { 3, "Selected PLMN ID" },
		[BSSGP_IE_PRIO_CLASS_IND] = { 1, "Priority Class Indication" },
		[BSSGP_IE_SOURCE_CELL_ID] = { 6, "Source Cell ID" },
		[BSSGP_IE_IRAT_MEAS_CFG_E_EARFCN] = { 10, "IRAT Measurement Configuration (extended E-ARFCNs)" },
		[BSSGP_IE_EDRX_PARAMETERS] = { 1, "eDRX Parameters" },
		[BSSGP_IE_T_UNTIL_NEXT_PAGING] = { 2, "Time Until Next Paging Occasion" },
		[BSSGP_IE_COVERAGE_CLASS] = { 1, "Coverage Class" },
		[BSSGP_IE_PAGING_ATTEMPT_INFO] = { 1, "Paging Attempt Information" },
		[BSSGP_IE_EXCEPTION_REPORT_FLAG] = { 1, "Exception Report Flag" },
		[BSSGP_IE_OLD_RA_ID] = { 6, "Old Routing Area Identification" },
		[BSSGP_IE_ATTACH_IND] = { 1, "Attach Indicator" },
		[BSSGP_IE_PLMN_ID] = { 3, "PLMN Identity" },
		[BSSGP_IE_MME_QUERY] = { 1, "MME Query" },
		[BSSGP_IE_SGSN_GROUP_ID] = { 3, "SGSN Group Identity" },
		[BSSGP_IE_ADDITIONAL_PTMSI] = { 4, "Additional P-TMSI" },
		[BSSGP_IE_UE_USAGE_TYPE] = { 1, "UE Usage Type" },
		[BSSGP_IE_MLAT_TIMER] = { 1, "Multilateration Timer" },
		[BSSGP_IE_MLAT_TA] = { 2, "Multilateration Timing Advance" },
		[BSSGP_IE_MS_SYNC_ACCURACY] = { 1, "MS Sync Accuracy" },
		[BSSGP_IE_BTS_RX_ACCURACY_LVL] = { 1, "BTS Reception Accuracy Level" },
		[BSSGP_IE_TA_REQ] = { 1, "Timing Advance Request (TAR)" },
	},
};

#undef DL
#undef UL
#undef SIG
#undef PTP
#undef PTM


const char *bssgp_cause_str(enum gprs_bssgp_cause cause)
{
	return get_value_string(bssgp_cause_strings, cause);
}

const char *bssgp_pdu_str(enum bssgp_pdu_type pdu)
{
	return get_value_string(bssgp_pdu_strings, pdu);
}

struct msgb *bssgp_msgb_alloc(void)
{
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "BSSGP");

	/* TODO: Add handling of msg == NULL to this function and to all callers */
	OSMO_ASSERT(msg != NULL);

	msgb_bssgph(msg) = msg->data;
	return msg;
}

struct msgb *bssgp_msgb_copy(const struct msgb *msg, const char *name)
{
	struct libgb_msgb_cb *old_cb, *new_cb;
	struct msgb *new_msg;

	new_msg = msgb_copy(msg, name);
	if (!new_msg)
		return NULL;

	/* copy GB specific data */
	old_cb = LIBGB_MSGB_CB(msg);
	new_cb = LIBGB_MSGB_CB(new_msg);

	if (old_cb->bssgph)
		new_cb->bssgph = new_msg->_data + (old_cb->bssgph - msg->_data);
	if (old_cb->llch)
		new_cb->llch = new_msg->_data + (old_cb->llch - msg->_data);

	/* bssgp_cell_id is a pointer into the old msgb, so we need to make
	 * it a pointer into the new msgb */
	if (old_cb->bssgp_cell_id)
		new_cb->bssgp_cell_id = new_msg->_data +
			(old_cb->bssgp_cell_id - msg->_data);
	new_cb->nsei = old_cb->nsei;
	new_cb->bvci = old_cb->bvci;
	new_cb->tlli = old_cb->tlli;

	return new_msg;
}

/* Transmit a simple response such as BLOCK/UNBLOCK/RESET ACK/NACK */
int bssgp_tx_simple_bvci(uint8_t pdu_type, uint16_t nsei,
			 uint16_t bvci, uint16_t ns_bvci)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph =
			(struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	uint16_t _bvci;

	msgb_nsei(msg) = nsei;
	msgb_bvci(msg) = ns_bvci;

	bgph->pdu_type = pdu_type;
	_bvci = osmo_htons(bvci);
	msgb_tvlv_put(msg, BSSGP_IE_BVCI, 2, (uint8_t *) &_bvci);

	return bssgp_ns_send(bssgp_ns_send_data, msg);
}

/* Chapter 10.4.14: Status */
int bssgp_tx_status(uint8_t cause, uint16_t *bvci, struct msgb *orig_msg)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph =
			(struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));

	/* GSM 08.18, 10.4.14.1: The BVCI must be included if (and only if) the
	   cause is either "BVCI blocked" or "BVCI unknown" */
	if (cause == BSSGP_CAUSE_UNKNOWN_BVCI || cause == BSSGP_CAUSE_BVCI_BLOCKED) {
		if (bvci == NULL)
			LOGP(DLBSSGP, LOGL_ERROR, "BSSGP Tx STATUS, cause=%s: "
			     "missing conditional BVCI\n",
			     bssgp_cause_str(cause));
	} else {
		if (bvci != NULL)
			LOGP(DLBSSGP, LOGL_ERROR, "BSSGP Tx STATUS, cause=%s: "
			     "unexpected conditional BVCI\n",
			     bssgp_cause_str(cause));
	}

	LOGP(DLBSSGP, LOGL_NOTICE, "BSSGP BVCI=%u Tx STATUS, cause=%s\n",
		bvci ? *bvci : 0, bssgp_cause_str(cause));
	msgb_nsei(msg) = msgb_nsei(orig_msg);
	msgb_bvci(msg) = 0;

	bgph->pdu_type = BSSGP_PDUT_STATUS;
	msgb_tvlv_put(msg, BSSGP_IE_CAUSE, 1, &cause);
	if (bvci) {
		uint16_t _bvci = osmo_htons(*bvci);
		msgb_tvlv_put(msg, BSSGP_IE_BVCI, 2, (uint8_t *) &_bvci);
	}
	msgb_tvlv_put(msg, BSSGP_IE_PDU_IN_ERROR,
		      msgb_bssgp_len(orig_msg), msgb_bssgph(orig_msg));

	return bssgp_ns_send(bssgp_ns_send_data, msg);
}
