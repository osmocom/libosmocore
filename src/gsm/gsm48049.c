/* CBSP is an ETSI/3GPP standard protocol used between CBC (Cell Brodadcast Centre)
 * and BSC (Base Station Controller0 in 2G/GSM/GERAN networks.  It is specified
 * in 3GPP TS 48.049
 *
 * (C) 2019 by Harald Welte <laforge@gnumonks.org>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * Released under the terms of the GNU General Public License, Version 2 or
 * (at your option) any later version.
 */

#include <stddef.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_48_049.h>

/***********************************************************************
 * Protocol Definitions
 ***********************************************************************/

const struct value_string cbsp_msg_type_names[] = {
	{ CBSP_MSGT_WRITE_REPLACE,		"WRITE-REPLACE" },
	{ CBSP_MSGT_WRITE_REPLACE_COMPL,	"WRITE-REPLACE COMPLETE" },
	{ CBSP_MSGT_WRITE_REPLACE_FAIL,		"WRITE-REPLACE FAILURE" },
	{ CBSP_MSGT_KILL,			"KILL" },
	{ CBSP_MSGT_KILL_COMPL,			"KILL COMPLETE" },
	{ CBSP_MSGT_KILL_FAIL,			"KILL FAILURE" },
	{ CBSP_MSGT_LOAD_QUERY,			"LOAD QUERY" },
	{ CBSP_MSGT_LOAD_QUERY_COMPL,		"LOAD QUERY COMPLETE" },
	{ CBSP_MSGT_LOAD_QUERY_FAIL,		"LOAD QUERY FAILURE" },
	{ CBSP_MSGT_MSG_STATUS_QUERY,		"MESSAGE STATUS QUERY" },
	{ CBSP_MSGT_MSG_STATUS_QUERY_COMPL,	"MESSAGE STATUS QUERY COMPLETE" },
	{ CBSP_MSGT_MSG_STATUS_QUERY_FAIL,	"MESSAGE STATUS QUERY FAILURE" },
	{ CBSP_MSGT_SET_DRX,			"SET-DRX" },
	{ CBSP_MSGT_SET_DRX_COMPL,		"SET-DRX COMPLETE" },
	{ CBSP_MSGT_SET_DRX_FAIL,		"SET-DRX FAILURE" },
	{ CBSP_MSGT_RESET,			"RESET" },
	{ CBSP_MSGT_RESET_COMPL,		"RESET COMPLETE" },
	{ CBSP_MSGT_RESET_FAIL,			"RESET FAILURE" },
	{ CBSP_MSGT_RESTART,			"RESTART" },
	{ CBSP_MSGT_FAILURE,			"FAILURE" },
	{ CBSP_MSGT_ERROR_IND,			"ERROR INDICATION" },
	{ CBSP_MSGT_KEEP_ALIVE,			"KEEP-ALIVE" },
	{ CBSP_MSGT_KEEP_ALIVE_COMPL,		"KEEP-ALIVE COMPLETE" },
	{ 0, NULL }
};

const struct value_string cbsp_iei_names[] = {
	{ CBSP_IEI_MSG_CONTENT,		"Message Content" },
	{ CBSP_IEI_OLD_SERIAL_NR,	"Old Serial Number" },
	{ CBSP_IEI_NEW_SERIAL_NR,	"New Serial Number" },
	{ CBSP_IEI_CELL_LIST,		"Cell List" },
	{ CBSP_IEI_CATEGORY,		"Category" },
	{ CBSP_IEI_REP_PERIOD,		"Repetition Period" },
	{ CBSP_IEI_NUM_BCAST_REQ,	"Number of Broadcasts Requested" },
	{ CBSP_IEI_NUM_BCAST_COMPL_LIST,"Number of Broadcasts Completed List" },
	{ CBSP_IEI_FAILURE_LIST,	"Failure List" },
	{ CBSP_IEI_RR_LOADING_LIST,	"Radio Resource Loading List" },
	{ CBSP_IEI_CAUSE,		"Cause" },
	{ CBSP_IEI_DCS,			"Data Coding Scheme" },
	{ CBSP_IEI_RECOVERY_IND,	"Recovery Indication" },
	{ CBSP_IEI_MSG_ID,		"Message Identifier" },
	{ CBSP_IEI_EMERG_IND,		"Emergency Indicator" },
	{ CBSP_IEI_WARN_TYPE,		"Warning Type" },
	{ CBSP_IEI_WARN_SEC_INFO,	"warning Security Information" },
	{ CBSP_IEI_CHANNEL_IND,		"Channel Indicator" },
	{ CBSP_IEI_NUM_OF_PAGES,	"Number of Pages" },
	{ CBSP_IEI_SCHEDULE_PERIOD,	"Schedule Period" },
	{ CBSP_IEI_NUM_OF_RES_SLOTS,	"Number of Reserved Slots" },
	{ CBSP_IEI_BCAST_MSG_TYPE,	"Broadcast Message Type" },
	{ CBSP_IEI_WARNING_PERIOD,	"Waring Period" },
	{ CBSP_IEI_KEEP_ALIVE_REP_PERIOD, "Keep Alive Repetition Period" },
	{ 0, NULL }
};

const struct value_string cbsp_category_names[] = {
	{ CBSP_CATEG_HIGH_PRIO,		"High Priority" },
	{ CBSP_CATEG_BACKGROUND,	"Background" },
	{ CBSP_CATEG_NORMAL,		"Normal" },
	{ 0, NULL }
};

const struct tlv_definition cbsp_att_tlvdef = {
	.def = {
		[CBSP_IEI_MSG_CONTENT] =		{ TLV_TYPE_FIXED, 83 },
		[CBSP_IEI_OLD_SERIAL_NR] =		{ TLV_TYPE_FIXED, 2 },
		[CBSP_IEI_NEW_SERIAL_NR] =		{ TLV_TYPE_FIXED, 2 },
		[CBSP_IEI_CELL_LIST] =			{ TLV_TYPE_TL16V },
		[CBSP_IEI_CATEGORY] =			{ TLV_TYPE_TV },
		[CBSP_IEI_REP_PERIOD] =			{ TLV_TYPE_FIXED, 2 },
		[CBSP_IEI_NUM_BCAST_REQ] =		{ TLV_TYPE_FIXED, 2 },
		[CBSP_IEI_NUM_BCAST_COMPL_LIST] =	{ TLV_TYPE_TL16V },
		[CBSP_IEI_FAILURE_LIST] =		{ TLV_TYPE_TL16V },
		[CBSP_IEI_RR_LOADING_LIST] =		{ TLV_TYPE_TL16V },
		[CBSP_IEI_CAUSE] =			{ TLV_TYPE_TV },
		[CBSP_IEI_DCS] =			{ TLV_TYPE_TV },
		[CBSP_IEI_RECOVERY_IND] =		{ TLV_TYPE_TV },
		[CBSP_IEI_MSG_ID] =			{ TLV_TYPE_FIXED, 2 },
		[CBSP_IEI_EMERG_IND] =			{ TLV_TYPE_TV },
		[CBSP_IEI_WARN_TYPE] =			{ TLV_TYPE_FIXED, 2 },
		[CBSP_IEI_WARN_SEC_INFO] =		{ TLV_TYPE_FIXED, 50 },
		[CBSP_IEI_CHANNEL_IND] =		{ TLV_TYPE_TV },
		[CBSP_IEI_NUM_OF_PAGES] =		{ TLV_TYPE_TV },
		[CBSP_IEI_SCHEDULE_PERIOD] =		{ TLV_TYPE_TV },
		[CBSP_IEI_NUM_OF_RES_SLOTS] =		{ TLV_TYPE_TV },
		[CBSP_IEI_BCAST_MSG_TYPE] =		{ TLV_TYPE_TV },
		[CBSP_IEI_WARNING_PERIOD] =		{ TLV_TYPE_TV },
		[CBSP_IEI_KEEP_ALIVE_REP_PERIOD] =	{ TLV_TYPE_TV },
	},
};
