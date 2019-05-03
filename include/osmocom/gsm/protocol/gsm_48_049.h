#pragma once
#include <stdint.h>
#include <osmocom/core/utils.h>

/* CBSP is an ETSI/3GPP standard protocol used between CBC (Cell
 * Brodadcast Centre) and BSC (Base Station Controller) in 2G/GSM/GERAN
 * networks.  It is specified in 3GPP TS 48.049.
 *
 * (C) 2019 by Harald Welte <laforge@gnumonks.org>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * Released under the terms of the GNU General Public License, Version 2 or
 * (at your option) any later version.
 */

/* 5.2 TCP/IP */
#define CBSP_TCP_PORT 48049

/* 8.2.1 Information Element Identifiers */
enum cbsp_iei {
	CBSP_IEI_MSG_CONTENT		= 0x01,
	CBSP_IEI_OLD_SERIAL_NR		= 0x02,
	CBSP_IEI_NEW_SERIAL_NR		= 0x03,
	CBSP_IEI_CELL_LIST		= 0x04,
	CBSP_IEI_CATEGORY		= 0x05,
	CBSP_IEI_REP_PERIOD		= 0x06,
	CBSP_IEI_NUM_BCAST_REQ		= 0x07,
	CBSP_IEI_NUM_BCAST_COMPL_LIST	= 0x08,
	CBSP_IEI_FAILURE_LIST		= 0x09,
	CBSP_IEI_RR_LOADING_LIST	= 0x0a,
	CBSP_IEI_CAUSE			= 0x0b,
	CBSP_IEI_DCS			= 0x0c,
	CBSP_IEI_RECOVERY_IND		= 0x0d,
	CBSP_IEI_MSG_ID			= 0x0e,
	CBSP_IEI_EMERG_IND		= 0x0f,
	CBSP_IEI_WARN_TYPE		= 0x10,
	CBSP_IEI_WARN_SEC_INFO		= 0x11,
	CBSP_IEI_CHANNEL_IND		= 0x12,
	CBSP_IEI_NUM_OF_PAGES		= 0x13,
	CBSP_IEI_SCHEDULE_PERIOD	= 0x14,
	CBSP_IEI_NUM_OF_RES_SLOTS	= 0x15,
	CBSP_IEI_BCAST_MSG_TYPE		= 0x16,
	CBSP_IEI_WARNING_PERIOD		= 0x17,
	CBSP_IEI_KEEP_ALIVE_REP_PERIOD	= 0x18,
};

/* 8.2.2 Message Type */
enum cbsp_msg_type {
	CBSP_MSGT_WRITE_REPLACE		= 0x01,
	CBSP_MSGT_WRITE_REPLACE_COMPL	= 0x02,
	CBSP_MSGT_WRITE_REPLACE_FAIL	= 0x03,
	CBSP_MSGT_KILL			= 0x04,
	CBSP_MSGT_KILL_COMPL		= 0x05,
	CBSP_MSGT_KILL_FAIL		= 0x06,
	CBSP_MSGT_LOAD_QUERY		= 0x07,
	CBSP_MSGT_LOAD_QUERY_COMPL	= 0x08,
	CBSP_MSGT_LOAD_QUERY_FAIL	= 0x09,
	CBSP_MSGT_MSG_STATUS_QUERY	= 0x0a,
	CBSP_MSGT_MSG_STATUS_QUERY_COMPL= 0x0b,
	CBSP_MSGT_MSG_STATUS_QUERY_FAIL	= 0x0c,
	CBSP_MSGT_SET_DRX		= 0x0d,
	CBSP_MSGT_SET_DRX_COMPL		= 0x0e,
	CBSP_MSGT_SET_DRX_FAIL		= 0x0f,
	CBSP_MSGT_RESET			= 0x10,
	CBSP_MSGT_RESET_COMPL		= 0x11,
	CBSP_MSGT_RESET_FAIL		= 0x12,
	CBSP_MSGT_RESTART		= 0x13,
	CBSP_MSGT_FAILURE		= 0x14,
	CBSP_MSGT_ERROR_IND		= 0x15,
	CBSP_MSGT_KEEP_ALIVE		= 0x16,
	CBSP_MSGT_KEEP_ALIVE_COMPL	= 0x17,
};

/* 8.2.7 Category */
enum cbsp_category {
	CBSP_CATEG_HIGH_PRIO		= 0x00,
	CBSP_CATEG_BACKGROUND		= 0x01,
	CBSP_CATEG_NORMAL		= 0x02,
};

/* Cell ID Discriminator (8.2.11, ...) */
enum cbsp_cell_id_disc {
	CBSP_CIDD_WHOLE_CGI		= 0x0,
	CBSP_CIDD_LAC_CI		= 0x1,
	CBSP_CIDD_CI			= 0x2,
	CBSP_CIDD_LAI			= 0x4,
	CBSP_CIDD_LAC			= 0x5,
	CBSP_CIDD_ALL_IN_BSC		= 0x6,
};

/* 8.2.13 Cause */
enum cbsp_cell_id_cause {
	CBSP_CAUSE_PARAM_NOT_RECOGNISED			= 0x00,
	CBSP_CAUSE_PARAM_VAL_INVALID			= 0x01,
	CBSP_CAUSE_MSG_REF_NOT_IDENTIFIED		= 0x02,
	CBSP_CAUSE_CELL_ID_NOT_VALID			= 0x03,
	CBSP_CAUSE_UNRECOGNISED_MSG			= 0x04,
	CBSP_CAUSE_MISSING_MAND_IE			= 0x05,
	CBSP_CAUSE_BSC_CAPACITY_EXCEEDED		= 0x06,
	CBSP_CAUSE_CELL_MEMORY_EXCEEDED			= 0x07,
	CBSP_CAUSE_BSC_MEMORY_EXCEEDED			= 0x08,
	CBSP_CAUSE_CB_NOT_SUPPORTED			= 0x09,
	CBSP_CAUSE_CB_NOT_OPERATIONAL			= 0x0a,
	CBSP_CAUSE_INCOMPATIBLE_DRX_PARAM		= 0x0b,
	CBSP_CAUSE_EXT_CHAN_NOT_SUPPORTED		= 0x0c,
	CBSP_CAUSE_MSG_REF_ALREADY_USED			= 0x0d,
	CBSP_CAUSE_UNSPECIFIED_ERROR			= 0x0e,
	CBSP_CAUSE_LAI_OR_LAC_NPT_VALID			= 0x0f,
};

/* 8.2.20 Chanel Indicator */
enum cbsp_channel_ind {
	CBSP_CHAN_IND_BASIC	= 0,
	CBSP_CHAN_IND_EXTENDED	= 1,
};

/* not explicitly specified, but every message starts with those mandatory elements */
struct cbsp_header {
	uint8_t msg_type;
	uint8_t len[3]; /* excluding the header */
} __attribute__((packed));

extern const struct value_string cbsp_msg_type_names[];
extern const struct value_string cbsp_iei_names[];
extern const struct value_string cbsp_category_names[];
extern const struct tlv_definition cbsp_att_tlvdef;
