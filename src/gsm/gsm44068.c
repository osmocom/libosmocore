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

#include <stddef.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_44_068.h>

/***********************************************************************
 * Protocol Definitions
 ***********************************************************************/

const struct value_string osmo_gsm44068_msg_type_names[] = {
	{ OSMO_GSM44068_MSGT_IMMEDIATE_SETUP,		"IMMEDIATE SETUP" },
	{ OSMO_GSM44068_MSGT_SETUP,			"SETUP" },
	{ OSMO_GSM44068_MSGT_CONNECT,			"CONNECT" },
	{ OSMO_GSM44068_MSGT_TERMINATION,		"TERMINATION" },
	{ OSMO_GSM44068_MSGT_TERMINATION_REQUEST,	"TERMINATION REQUEST" },
	{ OSMO_GSM44068_MSGT_TERMINATION_REJECT,	"TERMINATION REJECT" },
	{ OSMO_GSM44068_MSGT_STATUS,			"STATUS" },
	{ OSMO_GSM44068_MSGT_GET_STATUS,		"GET STATUS" },
	{ OSMO_GSM44068_MSGT_SET_PARAMETER,		"SET PARAMETER" },
	{ OSMO_GSM44068_MSGT_IMMEDIATE_SETUP_2,		"IMMEDIATE SETUP 2" },
	{ 0, NULL }
};

const struct value_string osmo_gsm44068_priority_level_names[] = {
	{ OSMO_GSM44068_PRIO_LEVEL_4,			"priority level 4" },
	{ OSMO_GSM44068_PRIO_LEVEL_3,			"priority level 3" },
	{ OSMO_GSM44068_PRIO_LEVEL_2,			"priority level 2" },
	{ OSMO_GSM44068_PRIO_LEVEL_1,			"priority level 1" },
	{ OSMO_GSM44068_PRIO_LEVEL_0,			"priority level 0" },
	{ OSMO_GSM44068_PRIO_LEVEL_B,			"priority level B" },
	{ OSMO_GSM44068_PRIO_LEVEL_A,			"priority level A" },
	{ 0, NULL }
};

const struct value_string osmo_gsm44068_cause_names[] = {
	{ OSMO_GSM44068_CAUSE_ILLEGAL_MS,		"Illegal MS" },
	{ OSMO_GSM44068_CAUSE_IMEI_NOT_ACCEPTED,	"IMEI not accepted" },
	{ OSMO_GSM44068_CAUSE_ILLEGAL_ME,		"Illegal ME" },
	{ OSMO_GSM44068_CAUSE_SERVICE_NOT_AUTHORIZED,	"Service not authorized" },
	{ OSMO_GSM44068_CAUSE_APP_NOT_SUPPORTED_ON_PROTO, "Application not supported on the protocol" },
	{ OSMO_GSM44068_CAUSE_RR_CONNECTION_ABORTED,	"RR connection aborted" },
	{ OSMO_GSM44068_CAUSE_NORMAL_CALL_CLEARING,	"Normal call clearing" },
	{ OSMO_GSM44068_CAUSE_NETWORK_FAILURE,		"Network failure" },
	{ OSMO_GSM44068_CAUSE_BUSY,			"Busy" },
	{ OSMO_GSM44068_CAUSE_CONGESTION,		"Congestion" },
	{ OSMO_GSM44068_CAUSE_USER_NOT_ORIGINATOR,	"User not originator of call" },
	{ OSMO_GSM44068_CAUSE_NET_WANTS_TO_MAINTAIN_CALL, "Network wants to maintain call" },
	{ OSMO_GSM44068_CAUSE_RESPONSE_TO_GET_STATUS,	"Response to GET STATUS" },
	{ OSMO_GSM44068_CAUSE_SERVICE_OPTION_NOT_SUBSCR, "Service option not supported" },
	{ OSMO_GSM44068_CAUSE_REQUESTED_SERVICE_NOT_SUB, "Requested service option not subscribed" },
	{ OSMO_GSM44068_CAUSE_SERVICE_OPTION_OOO,	"Service option temporarily out of order" },
	{ OSMO_GSM44068_CAUSE_CALL_CANNOT_BE_IDENTIFIED, "Call cannot be identified" },
	{ OSMO_GSM44068_CAUSE_RETRY_UPON_ENTRY_NEW_CALL, "retry upon entry into a new cell" },
	{ OSMO_GSM44068_CAUSE_INVALID_TRANSACTION_ID,	"Invalid transaction identifier value" },
	{ OSMO_GSM44068_CAUSE_SEMANTICALLY_INCORRECT_MSG, "Semantically incorrect message" },
	{ OSMO_GSM44068_CAUSE_INVALID_MANDATORY_INFO,	"Invalid mandatory information" },
	{ OSMO_GSM44068_CAUSE_MESSAGE_TYPE_NON_EXISTENT, "Message type non-existent or not implemented" },
	{ OSMO_GSM44068_CAUSE_MESSAGE_TYPE_NOT_COMPAT,	"Message type not compatible with the protocol state" },
	{ OSMO_GSM44068_CAUSE_IE_NON_EXISTENT,		"Information element non-existent or not implemented" },
	{ OSMO_GSM44068_CAUSE_IE_NOT_COMPAT,		"Message type not compatible with the protocol state" },
	{ OSMO_GSM44068_CAUSE_PROTOCOL_ERROR,		"Protocol error, unspecified" },
	{ 0, NULL }
};

const struct value_string osmo_gsm44068_call_state_names[] = {
	{ OSMO_GSM44068_CSTATE_U0,			"U0" },
	{ OSMO_GSM44068_CSTATE_U1,			"U1" },
	{ OSMO_GSM44068_CSTATE_U2sl,			"U2sl/U2" },
	{ OSMO_GSM44068_CSTATE_U3,			"U3" },
	{ OSMO_GSM44068_CSTATE_U4,			"U4" },
	{ OSMO_GSM44068_CSTATE_U5,			"U5" },
	{ OSMO_GSM44068_CSTATE_U0p,			"U0.p" },
	{ OSMO_GSM44068_CSTATE_Uwr,			"Uwr" },
	{ OSMO_GSM44068_CSTATE_U2r,			"U2r" },
	{ OSMO_GSM44068_CSTATE_U2ws,			"U2ws" },
	{ OSMO_GSM44068_CSTATE_U2sr,			"U2sr" },
	{ OSMO_GSM44068_CSTATE_U2nc,			"U2nc" },
	{ 0, NULL }
};

const struct value_string osmo_gsm44068_talker_priority_names[] = {
	{ OSMO_GSM44068_PRIO_NORMAL,			"Normal" },
	{ OSMO_GSM44068_PRIO_PRIVILEGED,		"Privileged" },
	{ OSMO_GSM44068_PRIO_EMERGENCY,			"Emergency" },
	{ 0, NULL }
};

const struct tlv_definition osmo_gsm44068_att_tlvdef = {
	.def = {
		[OSMO_GSM44068_IEI_MOBILE_IDENTITY] =	{ TLV_TYPE_TLV },
		[OSMO_GSM44068_IEI_USER_USER] =		{ TLV_TYPE_TLV },
		[OSMO_GSM44068_IEI_CALL_STATE] =	{ TLV_TYPE_SINGLE_TV },
		[OSMO_GSM44068_IEI_STATE_ATTRIBUTES] =	{ TLV_TYPE_SINGLE_TV },
		[OSMO_GSM44068_IEI_TALKER_PRIORITY] =	{ TLV_TYPE_SINGLE_TV },
		[OSMO_GSM44068_IEI_SMS_INDICATIONS] =	{ TLV_TYPE_SINGLE_TV },
	},
};
