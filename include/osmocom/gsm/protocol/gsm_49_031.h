/*! \defgroup bssmap_le 3GPP TS 49.031 BSSMAP-LE.
 *  @{
 *  \file gsm_49_031.h
 */
/*
 * (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/endian.h>
#include <osmocom/gsm/protocol/gsm_48_071.h>
#include <osmocom/gsm/protocol/gsm_23_032.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/gsm/gsm48.h>

/*! 3GPP TS 49.031 10.13 LCS Cause, also in 3GPP TS 48.008 3.2.2.66, which simply refers to the former. */
enum lcs_cause {
	LCS_CAUSE_UNSPECIFIED = 0,
	LCS_CAUSE_SYSTEM_FAILURE = 1,
	LCS_CAUSE_PROTOCOL_ERROR = 2,
	LCS_CAUSE_DATA_MISSING_IN_REQ = 3,
	LCS_CAUSE_UNEXP_DATA_IN_REQ = 4,
	LCS_CAUSE_POS_METH_FAILURE = 5,
	LCS_CAUSE_TGT_MS_UNREACHABLE = 6,
	LCS_CAUSE_REQUEST_ABORTED = 7,
	LCS_CAUSE_FACILITY_NOTSUPP = 8,
	LCS_CAUSE_INTER_BSC_HO = 9,
	LCS_CAUSE_INTRA_BSC_HO = 10,
	LCS_CAUSE_CONGESTION = 11,
	LCS_CAUSE_INTER_NSE_CHG = 12,
	LCS_CAUSE_RA_UPDAT = 13,
	LCS_CAUSE_PTMSI_REALLOC = 14,
	LCS_CAUSE_GPRS_SUSPENSION = 15,
};

/*! 3GPP TS 49.031 10.13 LCS Cause, also in 3GPP TS 48.008 3.2.2.66, which simply refers to the former. */
struct lcs_cause_ie {
	bool present;
	enum lcs_cause cause_val;
	bool diag_val_present;
	uint8_t diag_val;
};

/* 3GPP TS 49.031 10.16 LCS QoS IE */
struct osmo_bssmap_le_lcs_qos {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t vert:1, vel:1, spare1:6;
	uint8_t ha_val:7, ha_ind:1;
	uint8_t va_val:7, va_ind:1;
	uint8_t spare3:6, rt:2;
#elif OSMO_IS_BIG_ENDIAN
	uint8_t spare1:6, vel:1, vert:1;
	uint8_t ha_ind:1, ha_val:7;
	uint8_t va_ind:1, va_val:7;
	uint8_t rt:2, spare3:6;
#endif
} __attribute__ ((packed));

enum bssap_le_msg_discr {
	BSSAP_LE_MSG_DISCR_BSSMAP_LE = 0,
};

enum bssmap_le_msgt {
	BSSMAP_LE_MSGT_PERFORM_LOC_REQ = 0x2b,
	BSSMAP_LE_MSGT_PERFORM_LOC_RESP = 0x2d,
	BSSMAP_LE_MSGT_PERFORM_LOC_ABORT = 0x2e,
	BSSMAP_LE_MSGT_PERFORM_LOC_INFO = 0x2f,
	BSSMAP_LE_MSGT_ASSIST_INFO_REQ = 0x20,
	BSSMAP_LE_MSGT_ASSIST_INFO_RESP = 0x21,
	BSSMAP_LE_MSGT_CONN_ORIENTED_INFO = 0x2a,
	BSSMAP_LE_MSGT_CONN_LESS_INFO = 0x3a,
	BSSMAP_LE_MSGT_RESET = 0x30,
	BSSMAP_LE_MSGT_RESET_ACK = 0x31,
};

enum bssmap_le_iei {
	BSSMAP_LE_IEI_LCS_QoS = 0x3e,
	BSSMAP_LE_IEI_LCS_PRIORITY = 0x43,
	BSSMAP_LE_IEI_LOCATION_TYPE = 0x44,
	BSSMAP_LE_IEI_GANSS_LOCATION_TYPE = 0x82,
	BSSMAP_LE_IEI_GEO_LOCATION = 0x45,
	BSSMAP_LE_IEI_POSITIONING_DATA = 0x46,
	BSSMAP_LE_IEI_GANSS_POS_DATA = 0x83,
	BSSMAP_LE_IEI_VELOCITY_DATA = 0x55,
	BSSMAP_LE_IEI_LCS_CAUSE = 0x47,
	BSSMAP_LE_IEI_LCS_CLIENT_TYPE = 0x48,
	BSSMAP_LE_IEI_APDU = 0x49,
	BSSMAP_LE_IEI_NET_ELEM_ID = 0x4a,
	BSSMAP_LE_IEI_REQ_GPS_ASS_D = 0x4b,
	BSSMAP_LE_IEI_REQ_GANSS_ASS_D = 0x41,
	BSSMAP_LE_IEI_DECIPH_KEYS = 0x4c,
	BSSMAP_LE_IEI_RET_ERR_REQ = 0x4d,
	BSSMAP_LE_IEI_RET_ERR_CAUSE = 0x4e,
	BSSMAP_LE_IEI_SEGMENTATION = 0x4f,
	BSSMAP_LE_IEI_CLASSMARK3_INFO = 0x13,
	BSSMAP_LE_IEI_CAUSE = 0x4,
	BSSMAP_LE_IEI_CELL_ID = 0x5,
	BSSMAP_LE_IEI_CHOSEN_CHAN = 0x21,
	BSSMAP_LE_IEI_IMSI = 0x0,
	BSSMAP_LE_IEI_LCS_CAPABILITY = 0x50,
	BSSMAP_LE_IEI_PKT_MEAS_REP = 0x51,
	BSSMAP_LE_IEI_CELL_ID_LIST = 0x52,
	BSSMAP_LE_IEI_IMEI = 0x80,
	BSSMAP_LE_IEI_BSS_MLAT_CAP = 0x84,
	BSSMAP_LE_IEI_CELL_INFO_LIST = 0x85,
	BSSMAP_LE_IEI_BTS_RX_ACC_LVL = 0x86,
	BSSMAP_LE_IEI_MLAT_METHOD = 0x87,
	BSSMAP_LE_IEI_MLAT_TA = 0x88,
	BSSMAP_LE_IEI_MS_SYNC_ACC = 0x89,
	BSSMAP_LE_IEI_SHORT_ID_SET = 0x8a,
	BSSMAP_LE_IEI_RANDOM_ID_SET = 0x8b,
	BSSMAP_LE_IEI_SHORT_BSS_ID = 0x8c,
	BSSMAP_LE_IEI_RANDOM_ID = 0x8d,
	BSSMAP_LE_IEI_SHORT_ID = 0x8e,
	BSSMAP_LE_IEI_COVERAGE_CLASS = 0x8f,
	BSSMAP_LE_IEI_MTA_ACC_SEC_RQD = 0x90,
};

enum bssmap_le_apdu_proto {
	BSSMAP_LE_APDU_PROT_RESERVED = 0,
	BSSMAP_LE_APDU_PROT_BSSLAP = 1,
	BSSMAP_LE_APDU_PROT_LLP = 2,
	BSSMAP_LE_APDU_PROT_SMLCPP = 3,
};

enum bssmap_le_location_information {
	BSSMAP_LE_LOC_INFO_CURRENT_GEOGRAPHIC = 0x0,
	BSSMAP_LE_LOC_INFO_ASSIST_TARGET_MS = 0x1,
	BSSMAP_LE_LOC_INFO_BC_DECIPHER_KEYS = 0x2,
};

enum bssmap_le_positioning_method {
	BSSMAP_LE_POS_METHOD_OMITTED = 0x0,
	BSSMAP_LE_POS_METHOD_MOBILE_ASSISTED_E_OTD = 0x1,
	BSSMAP_LE_POS_METHOD_MOBILE_BASED_E_OTD = 0x2,
	BSSMAP_LE_POS_METHOD_ASSISTED_GPS = 0x3,
};

struct bssmap_le_location_type {
	enum bssmap_le_location_information location_information;
	enum bssmap_le_positioning_method positioning_method;
};

enum bssmap_le_lcs_client_type {
	BSSMAP_LE_LCS_CTYPE_VALUE_ADDED_UNSPECIFIED = 0x0,
	BSSMAP_LE_LCS_CTYPE_PLMN_OPER_UNSPECIFIED = 0x20,
	BSSMAP_LE_LCS_CTYPE_PLMN_OPER_BCAST_SERVICE = 0x21,
	BSSMAP_LE_LCS_CTYPE_PLMN_OPER_OAM = 0x22,
	BSSMAP_LE_LCS_CTYPE_PLMN_OPER_ANON_STATS = 0x23,
	BSSMAP_LE_LCS_CTYPE_PLMN_OPER_TGT_MS_SVC = 0x24,
	BSSMAP_LE_LCS_CTYPE_EMERG_SVC_UNSPECIFIED = 0x30,
	BSSMAP_LE_LCS_CTYPE_LI_UNSPECIFIED = 0x40,
};

struct bssmap_le_perform_loc_req {
	struct bssmap_le_location_type location_type;
	struct gsm0808_cell_id cell_id;

	bool lcs_client_type_present;
	enum bssmap_le_lcs_client_type lcs_client_type;

	struct osmo_mobile_identity imsi;
	struct osmo_mobile_identity imei;

	bool apdu_present;
	struct bsslap_pdu apdu;

	bool more_items; /*!< set this to true iff any fields below are used */

	bool lcs_priority_present;
	uint8_t lcs_priority; /*!< see in 3GPP TS 29.002 */

	bool lcs_qos_present;
	struct osmo_bssmap_le_lcs_qos lcs_qos;

	bool more_items2; /*!< always set this to false */
};

struct bssmap_le_perform_loc_resp {
	bool location_estimate_present;
	union gad_raw location_estimate;

	struct lcs_cause_ie lcs_cause;

	bool more_items; /*!< always set this to false */
};

struct bssmap_le_conn_oriented_info {
	struct bsslap_pdu apdu;

	bool more_items; /*!< always set this to false */
};

struct bssmap_le_pdu {
	enum bssmap_le_msgt msg_type;
	union {
		enum gsm0808_cause reset;
		/* reset_ack consists only of the message type */
		struct bssmap_le_perform_loc_req perform_loc_req;
		struct bssmap_le_perform_loc_resp perform_loc_resp;
		struct lcs_cause_ie perform_loc_abort;
		struct bssmap_le_conn_oriented_info conn_oriented_info;
	};
};

struct bssap_le_pdu {
	enum bssap_le_msg_discr discr;
	union {
		struct bssmap_le_pdu bssmap_le;
		/* future: add DTAP PDU, currently not implemented */
	};
};

/*! @} */
