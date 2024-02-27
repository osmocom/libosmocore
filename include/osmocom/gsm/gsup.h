/*! \defgroup gsup Generic Subscriber Update Protocol
 *  @{
 *
 *  The Generic Subscriber Update Protocol (GSUP) is an Osmocom-specific
 *  non-standard protocol replacing MAP as the protocol between
 *  MSC/VLR/SGSN and HLR in a 3GPP cellular communications network.
 *
 *  It was designed around the same transactions and architecture as the
 *  MAP messages/operations, but without the complexity of TCAP and MAP,
 *  and without the need for ASN.1 encoding.
 *
 *  The purpose is to keep protocol complexity out of OsmoSGSN and
 *  OsmoMSC, while providing a clean path to an external GSUP to MAP
 *  translator.
 *
 *  \file gsup.h
 *  Osmocom Generic Subscriber Update Protocol message encoder/decoder. */
/*
 * (C) 2014 by sysmocom - s.f.m.c. GmbH, Author: Jacob Erlbeck
 * (C) 2016 by Harald Welte <laforge@gnumonks.org>
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
#pragma once
#if (!EMBEDDED)

#include <stdint.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/defs.h>
#include <osmocom/core/endian.h>
#include <osmocom/core/socket.h>
#include <osmocom/gsm/gsup_sms.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/gsm/protocol/gsm_03_40.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/crypt/auth.h>

#define OSMO_GSUP_PORT 4222

/*! Maximum nubmer of PDP inside \ref osmo_gsup_message */
#define OSMO_GSUP_MAX_NUM_PDP_INFO		10 /* GSM 09.02 limits this to 50 */
/*! Maximum number of auth info inside \ref osmo_gsup_message */
#define OSMO_GSUP_MAX_NUM_AUTH_INFO		5
/*! Maximum number of octets encoding MSISDN in BCD format */
#define OSMO_GSUP_MAX_MSISDN_LEN		9
#define OSMO_GSUP_MAX_CALLED_PARTY_BCD_LEN	43 /* TS 24.008 10.5.4.7 */
#define OSMO_GSUP_MAX_PCO_LEN			251

/*! Information Element Identifiers for GSUP IEs */
enum osmo_gsup_iei {
	OSMO_GSUP_IMSI_IE			= 0x01,
	OSMO_GSUP_CAUSE_IE			= 0x02,
	OSMO_GSUP_AUTH_TUPLE_IE			= 0x03,
	OSMO_GSUP_PDP_INFO_COMPL_IE		= 0x04,
	OSMO_GSUP_PDP_INFO_IE			= 0x05,
	OSMO_GSUP_CANCEL_TYPE_IE		= 0x06,
	OSMO_GSUP_FREEZE_PTMSI_IE		= 0x07,
	OSMO_GSUP_MSISDN_IE			= 0x08,
	OSMO_GSUP_HLR_NUMBER_IE			= 0x09,
	OSMO_GSUP_MESSAGE_CLASS_IE		= 0x0a,
	OSMO_GSUP_PDP_CONTEXT_ID_IE		= 0x10,
	OSMO_GSUP_PDP_ADDRESS_IE		= 0x11,
#define OSMO_GSUP_PDP_TYPE_IE			OSMO_GSUP_PDP_ADDRESS_IE /* Backward compat */
	OSMO_GSUP_ACCESS_POINT_NAME_IE		= 0x12,
	OSMO_GSUP_PDP_QOS_IE			= 0x13,
	OSMO_GSUP_CHARG_CHAR_IE			= 0x14,
	OSMO_GSUP_PCO_IE			= 0x15,
	OSMO_GSUP_RAND_IE			= 0x20,
	OSMO_GSUP_SRES_IE			= 0x21,
	OSMO_GSUP_KC_IE				= 0x22,
	/* 3G support */
	OSMO_GSUP_IK_IE				= 0x23,
	OSMO_GSUP_CK_IE				= 0x24,
	OSMO_GSUP_AUTN_IE			= 0x25,
	OSMO_GSUP_AUTS_IE			= 0x26,
	OSMO_GSUP_RES_IE			= 0x27,
	OSMO_GSUP_CN_DOMAIN_IE			= 0x28,
	OSMO_GSUP_SUPPORTED_RAT_TYPES_IE	= 0x29, /* supported RAT types */
	OSMO_GSUP_CURRENT_RAT_TYPE_IE		= 0x2a, /* currently used RAT type */

	OSMO_GSUP_SESSION_ID_IE			= 0x30,
	OSMO_GSUP_SESSION_STATE_IE		= 0x31,

	/*! Supplementary Services payload */
	OSMO_GSUP_SS_INFO_IE			= 0x35,

	/* SM related IEs (see 3GPP TS 29.002, section 7.6.8) */
	OSMO_GSUP_SM_RP_MR_IE			= 0x40,
	OSMO_GSUP_SM_RP_DA_IE			= 0x41,
	OSMO_GSUP_SM_RP_OA_IE			= 0x42,
	OSMO_GSUP_SM_RP_UI_IE			= 0x43,
	OSMO_GSUP_SM_RP_CAUSE_IE		= 0x44,
	OSMO_GSUP_SM_RP_MMS_IE			= 0x45,
	OSMO_GSUP_SM_ALERT_RSN_IE		= 0x46,

	OSMO_GSUP_IMEI_IE			= 0x50,
	OSMO_GSUP_IMEI_RESULT_IE		= 0x51,
	OSMO_GSUP_NUM_VECTORS_REQ_IE		= 0x52,

	/* Inter-MSC handover related */
	OSMO_GSUP_SOURCE_NAME_IE		= 0x60,
	OSMO_GSUP_DESTINATION_NAME_IE		= 0x61,
	OSMO_GSUP_AN_APDU_IE			= 0x62,
	OSMO_GSUP_CAUSE_RR_IE			= 0x63,
	OSMO_GSUP_CAUSE_BSSAP_IE		= 0x64,
	OSMO_GSUP_CAUSE_SM_IE			= 0x65,

	_OSMO_GSUP_IEI_END_MARKER
};

/*! GSUP message type
 * Make sure that new messages follow this scheme:
 * .----------------------------.
 * | Ending Bits | Category     |
 * |----------------------------|
 * | 00          | Request      |
 * | 01          | Error        |
 * | 10          | Result       |
 * | 11          | Other        |
 * '----------------------------'
 * Request, Error and Result messages must only differ in these last two bits.
 */
enum osmo_gsup_message_type {
	OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST	= 0b00000100,
	OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR	= 0b00000101,
	OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT	= 0b00000110,

	OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST	= 0b00001000,
	OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR	= 0b00001001,
	OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT	= 0b00001010,

	OSMO_GSUP_MSGT_AUTH_FAIL_REPORT		= 0b00001011,

	OSMO_GSUP_MSGT_PURGE_MS_REQUEST		= 0b00001100,
	OSMO_GSUP_MSGT_PURGE_MS_ERROR		= 0b00001101,
	OSMO_GSUP_MSGT_PURGE_MS_RESULT		= 0b00001110,

	OSMO_GSUP_MSGT_INSERT_DATA_REQUEST	= 0b00010000,
	OSMO_GSUP_MSGT_INSERT_DATA_ERROR	= 0b00010001,
	OSMO_GSUP_MSGT_INSERT_DATA_RESULT	= 0b00010010,

	OSMO_GSUP_MSGT_DELETE_DATA_REQUEST	= 0b00010100,
	OSMO_GSUP_MSGT_DELETE_DATA_ERROR	= 0b00010101,
	OSMO_GSUP_MSGT_DELETE_DATA_RESULT	= 0b00010110,

	OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST	= 0b00011100,
	OSMO_GSUP_MSGT_LOCATION_CANCEL_ERROR	= 0b00011101,
	OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT	= 0b00011110,

	OSMO_GSUP_MSGT_PROC_SS_REQUEST		= 0b00100000,
	OSMO_GSUP_MSGT_PROC_SS_ERROR		= 0b00100001,
	OSMO_GSUP_MSGT_PROC_SS_RESULT		= 0b00100010,

	OSMO_GSUP_MSGT_MO_FORWARD_SM_REQUEST	= 0b00100100,
	OSMO_GSUP_MSGT_MO_FORWARD_SM_ERROR	= 0b00100101,
	OSMO_GSUP_MSGT_MO_FORWARD_SM_RESULT	= 0b00100110,

	OSMO_GSUP_MSGT_MT_FORWARD_SM_REQUEST	= 0b00101000,
	OSMO_GSUP_MSGT_MT_FORWARD_SM_ERROR	= 0b00101001,
	OSMO_GSUP_MSGT_MT_FORWARD_SM_RESULT	= 0b00101010,

	OSMO_GSUP_MSGT_READY_FOR_SM_REQUEST	= 0b00101100,
	OSMO_GSUP_MSGT_READY_FOR_SM_ERROR	= 0b00101101,
	OSMO_GSUP_MSGT_READY_FOR_SM_RESULT	= 0b00101110,

	OSMO_GSUP_MSGT_CHECK_IMEI_REQUEST	= 0b00110000,
	OSMO_GSUP_MSGT_CHECK_IMEI_ERROR		= 0b00110001,
	OSMO_GSUP_MSGT_CHECK_IMEI_RESULT	= 0b00110010,

	OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_REQUEST		= 0b00110100,
	OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_ERROR			= 0b00110101,
	OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_RESULT		= 0b00110110,

	OSMO_GSUP_MSGT_E_PREPARE_SUBSEQUENT_HANDOVER_REQUEST	= 0b00111000,
	OSMO_GSUP_MSGT_E_PREPARE_SUBSEQUENT_HANDOVER_ERROR	= 0b00111001,
	OSMO_GSUP_MSGT_E_PREPARE_SUBSEQUENT_HANDOVER_RESULT	= 0b00111010,

	OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_REQUEST		= 0b00111100,
	OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_ERROR			= 0b00111101,
	OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_RESULT			= 0b00111110,

	OSMO_GSUP_MSGT_E_PROCESS_ACCESS_SIGNALLING_REQUEST	= 0b01000000,
	OSMO_GSUP_MSGT_E_FORWARD_ACCESS_SIGNALLING_REQUEST	= 0b01000100,

	OSMO_GSUP_MSGT_E_CLOSE					= 0b01000111,
	OSMO_GSUP_MSGT_E_ABORT					= 0b01001011,

	OSMO_GSUP_MSGT_ROUTING_ERROR				= 0b01001110,

	OSMO_GSUP_MSGT_EPDG_TUNNEL_REQUEST			= 0b01010000,
	OSMO_GSUP_MSGT_EPDG_TUNNEL_ERROR			= 0b01010001,
	OSMO_GSUP_MSGT_EPDG_TUNNEL_RESULT			= 0b01010010,
};

#define OSMO_GSUP_MSGT_E_ROUTING_ERROR OSMO_GSUP_MSGT_ROUTING_ERROR

#define OSMO_GSUP_IS_MSGT_REQUEST(msgt) (((msgt) & 0b00000011) == 0b00)
#define OSMO_GSUP_IS_MSGT_ERROR(msgt)   (((msgt) & 0b00000011) == 0b01)
#define OSMO_GSUP_IS_MSGT_RESULT(msgt)  (((msgt) & 0b00000011) == 0b10)
#define OSMO_GSUP_TO_MSGT_REQUEST(msgt) (((msgt) & 0b11111100))
#define OSMO_GSUP_TO_MSGT_ERROR(msgt)   (((msgt) & 0b11111100) | 0b01)
#define OSMO_GSUP_TO_MSGT_RESULT(msgt)  (((msgt) & 0b11111100) | 0b10)

extern const struct value_string osmo_gsup_message_type_names[];
static inline const char *
osmo_gsup_message_type_name(enum osmo_gsup_message_type val)
{	return get_value_string(osmo_gsup_message_type_names, val); }

enum osmo_gsup_cancel_type {
	OSMO_GSUP_CANCEL_TYPE_UPDATE		= 1, /* on wire: 0 */
	OSMO_GSUP_CANCEL_TYPE_WITHDRAW		= 2, /* on wire: 1 */
};

enum osmo_gsup_cn_domain {
	OSMO_GSUP_CN_DOMAIN_PS			= 1,
	OSMO_GSUP_CN_DOMAIN_CS			= 2,
};

enum osmo_gsup_imei_result {
	OSMO_GSUP_IMEI_RESULT_ACK		= 1, /* on wire: 0 */
	OSMO_GSUP_IMEI_RESULT_NACK		= 2, /* on wire: 1 */
};

/* 3GPP 29.002 AccessNetworkProtocolId */
enum osmo_gsup_access_network_protocol {
	OSMO_GSUP_ACCESS_NETWORK_PROTOCOL_TS3G_48006 = 1,
	OSMO_GSUP_ACCESS_NETWORK_PROTOCOL_TS3G_25413 = 2,
};

/*! TCAP-like session state */
enum osmo_gsup_session_state {
	/*! Undefined session state */
	OSMO_GSUP_SESSION_STATE_NONE		= 0x00,
	/*! Initiation of a new session */
	OSMO_GSUP_SESSION_STATE_BEGIN		= 0x01,
	/*! Communication of an existing session */
	OSMO_GSUP_SESSION_STATE_CONTINUE	= 0x02,
	/*! Indication of the session end */
	OSMO_GSUP_SESSION_STATE_END		= 0x03,
};

extern const struct value_string osmo_gsup_session_state_names[];
static inline const char *
osmo_gsup_session_state_name(enum osmo_gsup_session_state val)
{	return get_value_string(osmo_gsup_session_state_names, val); }

/*! parsed/decoded PDP context information */
struct osmo_gsup_pdp_info {
	unsigned int			context_id;
	int				have_info;
	/*! Type of PDP context, 3GPP TS 29.060, 7.7.27 */
	union {
		uint16_t pdp_type OSMO_DEPRECATED("use pdp_type_org and pdp_type_nr instead");
		struct {
#if OSMO_IS_LITTLE_ENDIAN
			uint8_t	pdp_type_nr; /* enum gsm48_pdp_type_nr */
			uint8_t	pdp_type_org; /* enum gsm48_pdp_type_org */
#elif OSMO_IS_BIG_ENDIAN
			uint8_t	pdp_type_org; /* enum gsm48_pdp_type_org */
			uint8_t	pdp_type_nr; /* enum gsm48_pdp_type_nr */
#endif
		};
	};
	struct osmo_sockaddr		pdp_address[2];
	/*! APN information, still in encoded form. Can be NULL if no
	 * APN information included */
	const uint8_t			*apn_enc;
	/*! length (in octets) of apn_enc */
	size_t				apn_enc_len;
	/*! QoS information, still in encoded form. Can be NULL if no
	 * QoS information included */
	const uint8_t			*qos_enc;
	/*! length (in octets) of qos_enc */
	size_t				qos_enc_len;
	/*! PDP Charging Characteristics, still in encoded form. Can be NULL if no
	 * PDP Charging Characteristics */
	const uint8_t			*pdp_charg_enc;
	/*! length (in octets) of pdp_charg_enc */
	size_t				pdp_charg_enc_len;
};

enum osmo_gsup_message_class {
	OSMO_GSUP_MESSAGE_CLASS_UNSET = 0,
	OSMO_GSUP_MESSAGE_CLASS_SUBSCRIBER_MANAGEMENT = 1,
	OSMO_GSUP_MESSAGE_CLASS_SMS = 2,
	OSMO_GSUP_MESSAGE_CLASS_USSD = 3,
	OSMO_GSUP_MESSAGE_CLASS_INTER_MSC = 4,
	OSMO_GSUP_MESSAGE_CLASS_IPSEC_EPDG = 5,
	/* Keep this as last entry with a value of max(enum osmo_gsup_message_class) + 1.
	 * This value shall serve as the size for an array to aid de-muxing all known GSUP classes. */
	OSMO_GSUP_MESSAGE_CLASS_ARRAYSIZE
};

extern const struct value_string osmo_gsup_message_class_names[];
static inline const char *osmo_gsup_message_class_name(enum osmo_gsup_message_class val)
{ return get_value_string(osmo_gsup_message_class_names, val); }

/*! AccessNetworkSignalInfo as in 3GPP TS 29.002. */
struct osmo_gsup_an_apdu {
	/* AccessNetworkProtocolId as in 3GPP TS 29.002. */
	enum osmo_gsup_access_network_protocol access_network_proto;
	const uint8_t *data;
	size_t data_len;
};

/*! parsed/decoded GSUP protocol message */
struct osmo_gsup_message {
	enum osmo_gsup_message_type	message_type;
	char				imsi[OSMO_IMSI_BUF_SIZE];
	enum gsm48_gmm_cause		cause;
	enum osmo_gsup_cancel_type	cancel_type;
	int				pdp_info_compl;
	int				freeze_ptmsi;
	struct osmo_auth_vector		auth_vectors[OSMO_GSUP_MAX_NUM_AUTH_INFO];
	size_t				num_auth_vectors;
	struct osmo_gsup_pdp_info	pdp_infos[OSMO_GSUP_MAX_NUM_PDP_INFO];
	size_t				num_pdp_infos;
	const uint8_t			*msisdn_enc;
	size_t				msisdn_enc_len;
	const uint8_t			*hlr_enc;
	size_t				hlr_enc_len;
	const uint8_t			*auts;
	const uint8_t			*rand;
	enum osmo_gsup_cn_domain	cn_domain;
	const uint8_t			*pdp_charg_enc;
	size_t				pdp_charg_enc_len;

	/*! Session state \ref osmo_gsup_session_state */
	enum osmo_gsup_session_state	session_state;
	/*! Unique session identifier and origination flag.
	 * Encoded only when \ref session_state != 0x00 */
	uint32_t			session_id;

	/*! ASN.1 encoded MAP payload for Supplementary Services */
	uint8_t				*ss_info;
	size_t				ss_info_len;

	/*! SM-RP-MR (see 3GPP TS 29.002, 7.6.1.1), Message Reference.
	 * Please note that there is no SM-RP-MR in TCAP/MAP! SM-RP-MR
	 * is usually mapped to TCAP's InvokeID, but we don't need it. */
	const uint8_t			*sm_rp_mr;
	/*! SM-RP-DA (see 3GPP TS 29.002, 7.6.8.1), Destination Address */
	enum osmo_gsup_sms_sm_rp_oda_t	sm_rp_da_type;
	size_t				sm_rp_da_len;
	const uint8_t			*sm_rp_da;
	/*! SM-RP-OA (see 3GPP TS 29.002, 7.6.8.2), Originating Address */
	enum osmo_gsup_sms_sm_rp_oda_t	sm_rp_oa_type;
	size_t				sm_rp_oa_len;
	const uint8_t			*sm_rp_oa;
	/*! SM-RP-UI (see 3GPP TS 29.002, 7.6.8.4), SMS TPDU */
	const uint8_t			*sm_rp_ui;
	size_t				sm_rp_ui_len;
	/*! SM-RP-Cause value (1 oct.) as per GSM TS 04.11, section 8.2.5.4 */
	const uint8_t			*sm_rp_cause;
	/*! SM-RP-MMS (More Messages to Send), section 7.6.8.7 */
	const uint8_t			*sm_rp_mms;
	/*! Alert reason (see 3GPP TS 29.002, 7.6.8.8) */
	enum osmo_gsup_sms_sm_alert_rsn_t	sm_alert_rsn;

	const uint8_t			*imei_enc;
	size_t				imei_enc_len;
	enum osmo_gsup_imei_result	imei_result;

	/*! Indicate the message class to trivially dispatch incoming GSUP messages to the right code paths.
	 * Inter-MSC messages are *required* to set a class = OSMO_GSUP_MESSAGE_CLASS_INTER_MSC. For older message
	 * classes, this may be omitted (for backwards compatibility only -- if in doubt, include it). */
	enum osmo_gsup_message_class		message_class;

	/*! For messages routed via another GSUP entity (via HLR), the IPA name of the entity that sent this message. */
	const uint8_t			*source_name;
	/*! Number of bytes in source_name. */
	size_t				source_name_len;
	/*! For messages routed via another GSUP entity (via HLR), the IPA name of the entity that should ultimately
	 * receive this message. */
	const uint8_t			*destination_name;
	/*! Number of bytes in destination_name. */
	size_t				destination_name_len;

	/*! inter-MSC AN-APDU. */
	struct osmo_gsup_an_apdu	an_apdu;

	uint8_t				cause_rr; /*!< 0 is a valid cause */
	bool				cause_rr_set; /*!< whether cause_rr is set */

	enum gsm0808_cause		cause_bssap; /*!< 0 is a valid cause */
	bool				cause_bssap_set; /*!< whether cause_bssap is set */

	/*! Session Management cause as of 3GPP TS 24.008 10.5.6.6 / Table 10.5.157. */
	enum gsm48_gsm_cause		cause_sm;

	enum osmo_rat_type		current_rat_type;
	enum osmo_rat_type		supported_rat_types[8]; /*!< arbitrary choice */
	size_t				supported_rat_types_len;

	/*! PCO protocol option 3GPP TS 24.008 10.5.6.3 / Table 10.5.136. PCO contains Octet 3-ZA */
	const uint8_t			*pco;
	/*! Number of bytes of the PCO. */
	size_t				pco_len;

};

int osmo_gsup_decode(const uint8_t *data, size_t data_len,
		     struct osmo_gsup_message *gsup_msg);
int osmo_gsup_encode(struct msgb *msg, const struct osmo_gsup_message *gsup_msg);
int osmo_gsup_get_err_msg_type(enum osmo_gsup_message_type type_in)
	OSMO_DEPRECATED("Use OSMO_GSUP_TO_MSGT_ERROR() instead");

#endif /* (!EMBEDDED) */
/*! @} */
