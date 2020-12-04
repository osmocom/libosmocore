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
#include "common_vty.h"

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
	{ 0, NULL },
};

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
			LOGP(DBSSGP, LOGL_ERROR, "BSSGP Tx STATUS, cause=%s: "
			     "missing conditional BVCI\n",
			     bssgp_cause_str(cause));
	} else {
		if (bvci != NULL)
			LOGP(DBSSGP, LOGL_ERROR, "BSSGP Tx STATUS, cause=%s: "
			     "unexpected conditional BVCI\n",
			     bssgp_cause_str(cause));
	}

	LOGP(DBSSGP, LOGL_NOTICE, "BSSGP BVCI=%u Tx STATUS, cause=%s\n",
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
