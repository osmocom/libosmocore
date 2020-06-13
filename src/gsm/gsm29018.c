/* (C) 2020 by Harald Welte <laforge@osmocom.org>
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
 */

#include <osmocom/core/utils.h>
#include <osmocom/gsm/tlv.h>

#include <osmocom/gsm/protocol/gsm_29_018.h>

const struct value_string bssapp_msg_type_names[] = {
	{ BSSAPP_PAGING_REQ,		"PAGING-REQUEST" },
	{ BSSAPP_PAGING_REJ,		"PAGING-REJECT" },
	{ BSSAPP_DL_TUNNEL_REQ,		"DOWNLINK-TUNNEL-REQUEST" },
	{ BSSAPP_UL_TUNNEL_REQ,		"UPLINK-TUNNEL-REQUEST" },
	{ BSSAPP_LOC_UPD_REQ,		"LOCATION-UPDATE-REQUEST" },
	{ BSSAPP_LOC_UPD_ACC,		"LOCATION-UPDATE-ACCEPT" },
	{ BSSAPP_LOC_UPD_REJ,		"LOCATION-UPDATE-REJECT" },
	{ BSSAPP_TMSI_REALL_CMPL,	"TMSI-REALLOCATION-COMPLETE" },
	{ BSSAPP_ALERT_REQ,		"ALERT-REQUEST" },
	{ BSSAPP_ALERT_ACK,		"ALART-ACK" },
	{ BSSAPP_ALERT_REJ,		"ALERT-REJECT" },
	{ BSSAPP_MS_ACTIVITY_IND,	"MS-ACTIVITY-INDICATION" },
	{ BSSAPP_GPRS_DETACH_IND,	"GPRS-DETACH-INDICATION" },
	{ BSSAPP_GPRS_DETACH_ACK,	"GPRS-DETACH-ACK" },
	{ BSSAPP_IMSI_DETACH_IND,	"IMSI-DETACH-INDICATION" },
	{ BSSAPP_IMSI_DETACH_ACK,	"IMSI-DETACH-ACK" },
	{ BSSAPP_RESET_IND,		"RESET-INDICATION" },
	{ BSSAPP_RESET_ACK,		"RESET-ACK" },
	{ BSSAPP_MS_INFO_REQ,		"MS-INFO-REQUEST" },
	{ BSSAPP_MS_INFO_RESP,		"MS-INFO-RESPONSE" },
	{ BSSAPP_MM_INFO_REQ,		"MM-INFO-REQUEST" },
	{ BSSAPP_MOBILE_STATUS,		"MOBILE-STATUS" },
	{ BSSAPP_MS_UNREACHABLE,	"MS-UNREACHABLE" },
	{ 0, NULL }
};

extern const struct value_string bssapp_iei_names[] = {
	{ 0, FIXME }
};


const struct tlv_definition bssapp_ie_tlvdef = {
	.def = {
		[BSSAPP_IEI_IMSI]			= { TLV_TYPE_TLV },
		[BSSAPP_IEI_VLR_NUMBER]			= { TLV_TYPE_TLV },
		[BSSAPP_IEI_TMSI]			= { TLV_TYPE_TLV },
		[BSSAPP_IEI_LAI]			= { TLV_TYPE_TLV },
		[BSSAPP_IEI_CHAN_NEEDED]		= { TLV_TYPE_TLV },
		[BSSAPP_IEI_eMLPP_PRIORITY]		= { TLV_TYPE_TLV },
		[BSSAPP_IEI_TMSI_STATUS]		= { TLV_TYPE_TLV },
		[BSSAPP_IEI_Gs_CAUSE]			= { TLV_TYPE_TLV },
		[BSSAPP_IEI_SGSN_NUMBER]		= { TLV_TYPE_TLV },
		[BSSAPP_IEI_GPRS_LU_TYPE]		= { TLV_TYPE_TLV },
		[BSSAPP_IEI_GLOBAL_CN_ID]		= { TLV_TYPE_TLV },
		[BSSAPP_IEI_MS_CLASSMARK_1]		= { TLV_TYPE_TLV },
		[BSSAPP_IEI_MOBILE_ID]			= { TLV_TYPE_TLV },
		[BSSAPP_IEI_REJECT_CAUSE]		= { TLV_TYPE_TLV },
		[BSSAPP_IEI_IMSI_DET_FROM_GPRS_TYPE]	= { TLV_TYPE_TLV },
		[BSSAPP_IEI_IMSI_DET_FROM_NON_GPRS_TYPE]= { TLV_TYPE_TLV },
		[BSSAPP_IEI_INFORMATION_REQUESTED]	= { TLV_TYPE_TLV },
		[BSSAPP_IEI_PTMSI]			= { TLV_TYPE_TLV },
		[BSSAPP_IEI_IMEI]			= { TLV_TYPE_TLV },
		[BSSAPP_IEI_IMEISV]			= { TLV_TYPE_TLV },
		[BSSAPP_IEI_MM_INFORMATION]		= { TLV_TYPE_TLV },
		[BSSAPP_IEI_CGI]			= { TLV_TYPE_TLV },
		[BSSAPP_IEI_LOC_INFO_AGE]		= { TLV_TYPE_TLV },
		[BSSAPP_IEI_MS_STATE]			= { TLV_TYPE_TLV },
		[BSSAPP_IEI_ERRONEOUS_MSG]		= { TLV_TYPE_TLV },
		[BSSAPP_IEI_DL_TUN_PAYLOAD_CTRL_INFO]	= { TLV_TYPE_TLV },
		[BSSAPP_IEI_UL_TUN_PAYLOAD_CTRL_INFO]	= { TLV_TYPE_TLV },
		[BSSAPP_IEI_SAI]			= { TLV_TYPE_TLV },
		[BSSAPP_IEI_TMSI_BASED_NRI_CONTAINER]	= { TLV_TYPE_TLV },
	},
};
