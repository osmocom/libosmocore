#pragma once
#include <stdint.h>
#include <osmocom/core/utils.h>

/* Group Call Control (GCC) is an ETSI/3GPP standard protocol used between
 * MS (Mobile Station) and MSC (Mobile Switchting Center) in 2G/GSM-R network.
 * It is specified in 3GPP TS 44.068.
 *
 * (C) 2023 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Andreas Eversberg
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
 * SPDX-License-Identifier: GPL-2.0+
 */

/* 9 Information Element Identifiers */
enum osmo_gsm44068_iei {
	OSMO_GSM44068_IEI_MOBILE_IDENTITY		= 0x17,
	OSMO_GSM44068_IEI_USER_USER			= 0x7E,
	OSMO_GSM44068_IEI_CALL_STATE			= 0xA0,
	OSMO_GSM44068_IEI_STATE_ATTRIBUTES		= 0xB0,
	OSMO_GSM44068_IEI_TALKER_PRIORITY		= 0xC0,
	OSMO_GSM44068_IEI_SMS_INDICATIONS		= 0xD0,
};

/* 9.3 Message Type */
enum osmo_gsm44068_msg_type {
	OSMO_GSM44068_MSGT_IMMEDIATE_SETUP		= 0x31,
	OSMO_GSM44068_MSGT_SETUP			= 0x32,
	OSMO_GSM44068_MSGT_CONNECT			= 0x33,
	OSMO_GSM44068_MSGT_TERMINATION			= 0x34,
	OSMO_GSM44068_MSGT_TERMINATION_REQUEST		= 0x35,
	OSMO_GSM44068_MSGT_TERMINATION_REJECT		= 0x36,
	OSMO_GSM44068_MSGT_STATUS			= 0x38,
	OSMO_GSM44068_MSGT_GET_STATUS			= 0x39,
	OSMO_GSM44068_MSGT_SET_PARAMETER		= 0x3a,
	OSMO_GSM44068_MSGT_IMMEDIATE_SETUP_2		= 0x3b,
};

/* Table 9.2 priority */
enum osmo_gsm44068_priority_level {
	OSMO_GSM44068_PRIO_LEVEL_4			= 0x1,
	OSMO_GSM44068_PRIO_LEVEL_3			= 0x2,
	OSMO_GSM44068_PRIO_LEVEL_2			= 0x3,
	OSMO_GSM44068_PRIO_LEVEL_1			= 0x4,
	OSMO_GSM44068_PRIO_LEVEL_0			= 0x5,
	OSMO_GSM44068_PRIO_LEVEL_B			= 0x6,
	OSMO_GSM44068_PRIO_LEVEL_A			= 0x7,
};

/* 9.4.2 Call State */
enum osmo_gsm44068_call_state {
	OSMO_GSM44068_CSTATE_U0				= 0x0,
	OSMO_GSM44068_CSTATE_U1				= 0x1,
	OSMO_GSM44068_CSTATE_U2sl_U2			= 0x2,
	OSMO_GSM44068_CSTATE_U3				= 0x3,
	OSMO_GSM44068_CSTATE_U4				= 0x4,
	OSMO_GSM44068_CSTATE_U5				= 0x5,
	OSMO_GSM44068_CSTATE_U0p			= 0x6,
	OSMO_GSM44068_CSTATE_U2wr_U6			= 0x7,
	OSMO_GSM44068_CSTATE_U2r			= 0x8,
	OSMO_GSM44068_CSTATE_U2ws			= 0x9,
	OSMO_GSM44068_CSTATE_U2sr			= 0xa,
	OSMO_GSM44068_CSTATE_U2nc			= 0xb,
};

/* 9.4.3 Cause */
enum osmo_gsm44068_cause {
	OSMO_GSM44068_CAUSE_ILLEGAL_MS			= 0x03,
	OSMO_GSM44068_CAUSE_IMEI_NOT_ACCEPTED		= 0x05,
	OSMO_GSM44068_CAUSE_ILLEGAL_ME			= 0x06,
	OSMO_GSM44068_CAUSE_SERVICE_NOT_AUTHORIZED	= 0x08,
	OSMO_GSM44068_CAUSE_APP_NOT_SUPPORTED_ON_PROTO	= 0x09,
	OSMO_GSM44068_CAUSE_RR_CONNECTION_ABORTED	= 0x0a,
	OSMO_GSM44068_CAUSE_NORMAL_CALL_CLEARING	= 0x10,
	OSMO_GSM44068_CAUSE_NETWORK_FAILURE		= 0x11,
	OSMO_GSM44068_CAUSE_BUSY			= 0x14,
	OSMO_GSM44068_CAUSE_CONGESTION			= 0x16,
	OSMO_GSM44068_CAUSE_USER_NOT_ORIGINATOR		= 0x17,
	OSMO_GSM44068_CAUSE_NET_WANTS_TO_MAINTAIN_CALL	= 0x18,
	OSMO_GSM44068_CAUSE_RESPONSE_TO_GET_STATUS	= 0x1e,
	OSMO_GSM44068_CAUSE_SERVICE_OPTION_NOT_SUBSCR	= 0x20,
	OSMO_GSM44068_CAUSE_REQUESTED_SERVICE_NOT_SUB	= 0x21,
	OSMO_GSM44068_CAUSE_SERVICE_OPTION_OOO		= 0x22,
	OSMO_GSM44068_CAUSE_CALL_CANNOT_BE_IDENTIFIED	= 0x26,
	OSMO_GSM44068_CAUSE_RETRY_UPON_ENTRY_NEW_CALL	= 0x30, /* up to 0x3f */
	OSMO_GSM44068_CAUSE_INVALID_TRANSACTION_ID	= 0x51,
	OSMO_GSM44068_CAUSE_SEMANTICALLY_INCORRECT_MSG	= 0x5f,
	OSMO_GSM44068_CAUSE_INVALID_MANDATORY_INFO	= 0x60,
	OSMO_GSM44068_CAUSE_MESSAGE_TYPE_NON_EXISTENT	= 0x61,
	OSMO_GSM44068_CAUSE_MESSAGE_TYPE_NOT_COMPAT	= 0x62,
	OSMO_GSM44068_CAUSE_IE_NON_EXISTENT		= 0x63,
	OSMO_GSM44068_CAUSE_IE_NOT_COMPAT		= 0x64,
	OSMO_GSM44068_CAUSE_PROTOCOL_ERROR		= 0x70,
};

/* 9.4.4 Originator Indication */
#define OSMO_GSM44068_OI_MS_IS_ORIGINATOR		0x01

/* 9.4.7 State Attributes */
#define OSMO_GSM44068_DA_DOWNLINK_ATTACHED		0x08
#define OSMO_GSM44068_UA_UPLINK_ATTACHED		0x04
#define OSMO_GSM44068_COMM_T				0x02

/* 9.4.9 Talker Priority */
enum osmo_gsm44068_talker_priority {
	OSMO_GSM44068_PRIO_NORMAL			= 0x0,
	OSMO_GSM44068_PRIO_PRIVILEGED			= 0x1,
	OSMO_GSM44068_PRIO_EMERGENCY			= 0x2,
};

/* 9.4.10 SMS Indications */
#define OSMO_GSM44068_DC_DATA_CONFIDENTALLY_RQD		0x02
#define OSMO_GSM44068_GP_GUARANTEED_PRIVACY_RQD		0x01

extern const struct value_string osmo_gsm44068_msg_type_names[];
extern const struct value_string osmo_gsm44068_priority_level_names[];
extern const struct value_string osmo_gsm44068_cause_names[];
extern const struct value_string osmo_gsm44068_call_state_names[];
extern const struct value_string osmo_gsm44068_talker_priority_names[];

extern const struct tlv_definition osmo_gsm44068_att_tlvdef;
