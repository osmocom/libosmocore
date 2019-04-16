/*
 * (C) 2009,2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009,2010 by On-Waves
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

#include <osmocom/core/byteswap.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm48.h>

/*! \addtogroup gsm0808
 *  @{
 *  \file gsm0808.c
 *  Helper functions regarding the TS 08.08 / 48.008 A interface, primarily
 *  message generation/encoding.
 */

/*! Create "Complete L3 Info" for AoIP, legacy implementation.
 * Instead use gsm0808_create_layer3_aoip2(), which is capable of three-digit MNC with leading zeros.
 *  \param[in] msg_l3 msgb containing Layer 3 Message
 *  \param[in] nc Mobile Network Code
 *  \param[in] cc Mobile Country Code
 *  \param[in] lac Location Area Code
 *  \param[in] _ci Cell Identity
 *  \param[in] scl Speech Codec List
 *  \returns callee-allocated msgb with Complete L3 Info message */
struct msgb *gsm0808_create_layer3_aoip(const struct msgb *msg_l3, uint16_t nc,
					uint16_t cc, int lac, uint16_t _ci,
					const struct gsm0808_speech_codec_list
					*scl)
{
	struct osmo_cell_global_id cgi = {
		.lai = {
			.plmn = {
				.mcc = cc,
				.mnc = nc,
			},
			.lac = lac,
		},
		.cell_identity = _ci,
	};
	return gsm0808_create_layer3_2(msg_l3, &cgi, scl);
}

/*! Create "Complete L3 Info" for AoIP.
 *  \param[in] msg_l3 msgb containing Layer 3 Message -- not modified by this call.
 *  \param[in] cell  MCC, MNC, LAC, CI to identify the cell.
 *  \param[in] scl Speech Codec List, optional.
 *  \returns newly allocated msgb with Complete L3 Info message */
struct msgb *gsm0808_create_layer3_2(const struct msgb *msg_l3, const struct osmo_cell_global_id *cell,
				     const struct gsm0808_speech_codec_list *scl)
{
	struct msgb* msg;
	struct {
		uint8_t ident;
		struct gsm48_loc_area_id lai;
		uint16_t ci;
	} __attribute__ ((packed)) lai_ci;

	msg  = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
				   "bssmap cmpl l3");
	if (!msg)
		return NULL;

	/* create layer 3 header */
	msgb_v_put(msg, BSS_MAP_MSG_COMPLETE_LAYER_3);

	/* create the cell header */
	lai_ci.ident = CELL_IDENT_WHOLE_GLOBAL;
	gsm48_generate_lai2(&lai_ci.lai, &cell->lai);
	lai_ci.ci = osmo_htons(cell->cell_identity);
	msgb_tlv_put(msg, GSM0808_IE_CELL_IDENTIFIER, sizeof(lai_ci),
		     (uint8_t *) &lai_ci);

	/* copy the layer3 data */
	msgb_tlv_put(msg, GSM0808_IE_LAYER_3_INFORMATION,
		     msgb_l3len(msg_l3), msg_l3->l3h);

	/* AoIP: add Codec List (BSS Supported) 3.2.2.103 */
	if (scl)
		gsm0808_enc_speech_codec_list(msg, scl);

	/* push the bssmap header */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create "Complete L3 Info" for A, legacy implementation.
 * Instead use gsm0808_create_layer3_2() with the scl parameter passed as NULL,
 * which is capable of three-digit MNC with leading zeros.
 *  \param[in] msg_l3 msgb containing Layer 3 Message
 *  \param[in] nc Mobile Network Code
 *  \param[in] cc Mobile Country Code
 *  \param[in] lac Location Area Code
 *  \param[in] _ci Cell Identity
 *  \returns callee-allocated msgb with Complete L3 Info message */
struct msgb *gsm0808_create_layer3(struct msgb *msg_l3, uint16_t nc,
				   uint16_t cc, int lac, uint16_t _ci)
{
	struct osmo_cell_global_id cgi = {
		.lai = {
			.plmn = {
				.mcc = cc,
				.mnc = nc,
			},
			.lac = lac,
		},
		.cell_identity = _ci,
	};
	return gsm0808_create_layer3_2(msg_l3, &cgi, NULL);
}

/*! Create BSSMAP RESET message
 *  \returns callee-allocated msgb with BSSMAP Reset message */
struct msgb *gsm0808_create_reset(void)
{
	uint8_t cause = GSM0808_CAUSE_EQUIPMENT_FAILURE;
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "bssmap: reset");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_RESET);
	gsm0808_enc_cause(msg, cause);
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP RESET ACK message
 *  \returns callee-allocated msgb with BSSMAP Reset ACK message */
struct msgb *gsm0808_create_reset_ack(void)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "bssmap: reset ack");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_RESET_ACKNOWLEDGE);
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP Clear Complete message
 *  \returns callee-allocated msgb with BSSMAP Clear Complete message */
struct msgb *gsm0808_create_clear_complete(void)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "bssmap: clear complete");
	uint8_t val = BSS_MAP_MSG_CLEAR_COMPLETE;
	if (!msg)
		return NULL;

	msg->l3h = msg->data;
	msgb_tlv_put(msg, BSSAP_MSG_BSS_MANAGEMENT, 1, &val);

	return msg;
}

/*! Create BSSMAP Clear Command message with BSSAP header *before* l3h and BSSMAP in l3h.
 *  This is quite different from most (all?) other gsm0808_create_* which have l3h
 *  point to the BSSAP header.  However, we have to keep this for backwards compatibility.
 *  Use gsm0808_create_clear_command2() for a 'modern' implementation.
 *  \param[in] cause TS 08.08 cause value
 *  \returns callee-allocated msgb with BSSMAP Clear Command message */
struct msgb *gsm0808_create_clear_command(uint8_t cause)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "bssmap: clear command");
	if (!msg)
		return NULL;

	msg->l3h = msgb_tv_put(msg, BSSAP_MSG_BSS_MANAGEMENT, 4);
	msgb_v_put(msg, BSS_MAP_MSG_CLEAR_CMD);
	gsm0808_enc_cause(msg, cause);

	return msg;
}

/*! Create BSSMAP Clear Command message.
 *  \param[in] cause TS 08.08 cause value.
 *  \param[in] csfb_ind indicate that the call was established in an CSFB context.
 *  \returns callee-allocated msgb with BSSMAP Clear Command message. */
struct msgb *gsm0808_create_clear_command2(uint8_t cause, bool csfb_ind)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "bssmap: clear command");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_CLEAR_CMD);
	gsm0808_enc_cause(msg, cause);

	if (csfb_ind)
		msgb_v_put(msg, GSM0808_IE_CSFB_INDICATION);

	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP Cipher Mode Command message
 *  \param[in] ei Mandatory Encryption Information
 *  \param[in] cipher_response_mode optional 1-byte Cipher Response Mode
 *  \returns callee-allocated msgb with BSSMAP Cipher Mode Command message */
struct msgb *gsm0808_create_cipher(const struct gsm0808_encrypt_info *ei,
				   const uint8_t *cipher_response_mode)
{
	/* See also: 3GPP TS 48.008 3.2.1.30 CIPHER MODE COMMAND */
	struct msgb *msg;

	/* Mandatory emelent! */
	OSMO_ASSERT(ei);

	msg =
	    msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
				"cipher-mode-command");
	if (!msg)
		return NULL;

	/* Message Type 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_CIPHER_MODE_CMD);

	/* Encryption Information 3.2.2.10 */
	gsm0808_enc_encrypt_info(msg, ei);

	/* Cipher Response Mode 3.2.2.34 */
	if (cipher_response_mode)
		msgb_tv_put(msg, GSM0808_IE_CIPHER_RESPONSE_MODE,
			    *cipher_response_mode);

	/* pre-pend the header */
	msg->l3h =
	    msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP Cipher Mode Complete message
 *  \param[in] layer3 L3 Message to be included
 *  \param[in] alg_id Chosen Encrpytion Algorithm
 *  \returns callee-allocated msgb with BSSMAP Cipher Mode Complete message */
struct msgb *gsm0808_create_cipher_complete(struct msgb *layer3, uint8_t alg_id)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "cipher-complete");
	if (!msg)
		return NULL;

        /* send response with BSS override for A5/1... cheating */
	msgb_v_put(msg, BSS_MAP_MSG_CIPHER_MODE_COMPLETE);

	/* include layer3 in case we have at least two octets */
	if (layer3 && msgb_l3len(layer3) > 2) {
		msg->l4h = msgb_tlv_put(msg, GSM0808_IE_LAYER_3_MESSAGE_CONTENTS,
					msgb_l3len(layer3), layer3->l3h);
	}

	/* and the optional BSS message */
	msgb_tv_put(msg, GSM0808_IE_CHOSEN_ENCR_ALG, alg_id);

	/* pre-pend the header */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP Cipher Mode Reject message
 *  \param[in] cause 3GPP TS 08.08 §3.2.2.5 cause value
 *  \returns callee-allocated msgb with BSSMAP Cipher Mode Reject message */
struct msgb *gsm0808_create_cipher_reject(enum gsm0808_cause cause)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "bssmap: cipher mode reject");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_CIPHER_MODE_REJECT);

	gsm0808_enc_cause(msg, cause);

	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP Cipher Mode Reject message
 *  \param[in] class 3GPP TS 08.08 §3.2.2.5 cause's class
 *  \param[in] ext 3GPP TS 08.08 §3.2.2.5 cause value (national application extension)
 *  \returns callee-allocated msgb with BSSMAP Cipher Mode Reject message */
struct msgb *gsm0808_create_cipher_reject_ext(enum gsm0808_cause_class class, uint8_t ext)
{
	uint16_t cause;
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "bssmap: cipher mode reject");
	if (!msg)
		return NULL;

	/* Set cause code class in the upper byte */
	cause = 0x80 | (class << 4);
	cause = cause << 8;

	/* Set cause code extension in the lower byte */
	cause |= ext;

	msgb_v_put(msg, BSS_MAP_MSG_CIPHER_MODE_REJECT);

	gsm0808_enc_cause(msg, cause);

	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP LCLS CONNECT CONTROL message (TS 48.008 3.2.1.91).
 *  \param[in] config LCLS Configuration
 *  \param[in] control LCLS Connection Status Control
 *  \returns callee-allocated msgb with BSSMAP LCLS NOTIFICATION */
struct msgb *gsm0808_create_lcls_conn_ctrl(enum gsm0808_lcls_config config,
					   enum gsm0808_lcls_control control)
{
	struct msgb *msg;

	/* According to NOTE 1 in §3.2.1.91 at least one of the parameters is required */
	if (config == GSM0808_LCLS_CFG_NA && control == GSM0808_LCLS_CSC_NA)
		return NULL;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "bssmap: LCLS CONN CTRL");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_LCLS_CONNECT_CTRL);
	if (config != GSM0808_LCLS_CFG_NA)
		msgb_tv_put(msg, GSM0808_IE_LCLS_CONFIG, config);
	if (control != GSM0808_LCLS_CSC_NA)
		msgb_tv_put(msg, GSM0808_IE_LCLS_CONFIG, control);
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP LCLS CONNECT CONTROL ACK message (TS 48.008 3.2.1.92).
 *  \param[in] status LCLS BSS Status
 *  \returns callee-allocated msgb with BSSMAP LCLS NOTIFICATION */
struct msgb *gsm0808_create_lcls_conn_ctrl_ack(enum gsm0808_lcls_status status)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "bssmap: LCLS CONN CTRL ACK");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_LCLS_CONNECT_CTRL_ACK);
	msgb_tv_put(msg, GSM0808_IE_LCLS_BSS_STATUS, status);
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP LCLS NOTIFICATION message (TS 48.008 3.2.1.93).
 *  \param[in] status LCLS BSS Status
 *  \param[in] break_req Include the LCLS BREAK REQ IE (true) or not (false)
 *  \returns callee-allocated msgb with BSSMAP LCLS NOTIFICATION */
struct msgb *gsm0808_create_lcls_notification(enum gsm0808_lcls_status status, bool break_req)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "bssmap: LCLS NOTIFICATION");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_LCLS_NOTIFICATION);
	msgb_tv_put(msg, GSM0808_IE_LCLS_BSS_STATUS, status);
	if (break_req)
		msgb_v_put(msg, GSM0808_IE_LCLS_BREAK_REQ);
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP Classmark Request message
 *  \returns callee-allocated msgb with BSSMAP Classmark Request message */
struct msgb *gsm0808_create_classmark_request()
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "classmark-request");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_CLASSMARK_RQST);
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));
	return msg;
}

/*! Create BSSMAP Classmark Update message
 *  \param[in] cm2 Classmark 2
 *  \param[in] cm2_len length (in octets) of \a cm2
 *  \param[in] cm3 Classmark 3
 *  \param[in] cm3_len length (in octets) of \a cm3
 *  \returns callee-allocated msgb with BSSMAP Classmark Update message */
struct msgb *gsm0808_create_classmark_update(const uint8_t *cm2, uint8_t cm2_len,
					     const uint8_t *cm3, uint8_t cm3_len)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "classmark-update");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_CLASSMARK_UPDATE);
	msgb_tlv_put(msg, GSM0808_IE_CLASSMARK_INFORMATION_T2, cm2_len, cm2);
	if (cm3)
		msgb_tlv_put(msg, GSM0808_IE_CLASSMARK_INFORMATION_T3,
			     cm3_len, cm3);

	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP SAPI N Reject message
 *  \param[in] link_id Link Identifier
 *  \returns callee-allocated msgb with BSSMAP SAPI N Reject message */
struct msgb *gsm0808_create_sapi_reject(uint8_t link_id)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "bssmap: sapi 'n' reject");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_SAPI_N_REJECT);
	msgb_v_put(msg, link_id);
	msgb_v_put(msg, GSM0808_CAUSE_BSS_NOT_EQUIPPED);

	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP Assignment Request message, 3GPP TS 48.008 §3.2.1.1.
 *  This is identical to gsm0808_create_ass(), but adds KC and LCLS IEs.
 *  \param[in] ct Channel Type
 *  \param[in] cic Circuit Identity Code (Classic A only)
 *  \param[in] ss Socket Address of MSC-side RTP socket (AoIP only)
 *  \param[in] scl Speech Codec List (AoIP only)
 *  \param[in] ci Call Identifier (Optional), §3.2.2.105
 *  \param[in] kc Kc128 ciphering key (Optional, A5/4), §3.2.2.109
 *  \param[in] lcls Optional LCLS parameters
 *  \returns callee-allocated msgb with BSSMAP Assignment Request message */
struct msgb *gsm0808_create_ass2(const struct gsm0808_channel_type *ct,
				 const uint16_t *cic,
				 const struct sockaddr_storage *ss,
				 const struct gsm0808_speech_codec_list *scl,
				 const uint32_t *ci,
				 const uint8_t *kc, const struct osmo_lcls *lcls)
{
	/* See also: 3GPP TS 48.008 3.2.1.1 ASSIGNMENT REQUEST */
	struct msgb *msg;
	uint16_t cic_sw;
	uint32_t ci_sw;

	/* Mandatory emelent! */
	OSMO_ASSERT(ct);

	msg =
	    msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
				"bssmap: ass req");
	if (!msg)
		return NULL;

	/* Message Type 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_ASSIGMENT_RQST);

	/* Channel Type 3.2.2.11 */
	gsm0808_enc_channel_type(msg, ct);

	/* Circuit Identity Code 3.2.2.2  */
	if (cic) {
		cic_sw = osmo_htons(*cic);
		msgb_tv_fixed_put(msg, GSM0808_IE_CIRCUIT_IDENTITY_CODE,
				  sizeof(cic_sw), (uint8_t *) & cic_sw);
	}

	/* AoIP: AoIP Transport Layer Address (MGW) 3.2.2.102 */
	if (ss) {
		gsm0808_enc_aoip_trasp_addr(msg, ss);
	}

	/* AoIP: Codec List (MSC Preferred) 3.2.2.103 */
	if (scl)
		gsm0808_enc_speech_codec_list(msg, scl);

	/* AoIP: Call Identifier 3.2.2.105 */
	if (ci) {
		ci_sw = osmo_htonl(*ci);
		msgb_tv_fixed_put(msg, GSM0808_IE_CALL_ID, sizeof(ci_sw),
				  (uint8_t *) & ci_sw);
	}

	if (kc)
		msgb_tv_fixed_put(msg, GSM0808_IE_KC_128, 16, kc);

	if (lcls)
		gsm0808_enc_lcls(msg, lcls);

	/* push the bssmap header */
	msg->l3h =
	    msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP Assignment Request message, 3GPP TS 48.008 §3.2.1.1.
 *  \param[in] ct Channel Type
 *  \param[in] cic Circuit Identity Code (Classic A only)
 *  \param[in] ss Socket Address of MSC-side RTP socket (AoIP only)
 *  \param[in] scl Speech Codec List (AoIP only)
 *  \param[in] ci Call Identifier (Optional), §3.2.2.105
 *  \returns callee-allocated msgb with BSSMAP Assignment Request message */
struct msgb *gsm0808_create_ass(const struct gsm0808_channel_type *ct,
				const uint16_t *cic,
				const struct sockaddr_storage *ss,
				const struct gsm0808_speech_codec_list *scl,
				const uint32_t *ci)
{
	return gsm0808_create_ass2(ct, cic, ss, scl, ci, NULL, NULL);
}

/*! Create BSSMAP Assignment Completed message as per 3GPP TS 48.008 §3.2.1.2
 *  \param[in] rr_cause GSM 04.08 RR Cause value
 *  \param[in] chosen_channel Chosen Channel
 *  \param[in] encr_alg_id Encryption Algorithm ID
 *  \param[in] speech_mode Speech Mode
 *  \param[in] ss Socket Address of BSS-side RTP socket
 *  \param[in] sc Speech Codec (current)
 *  \param[in] scl Speech Codec List (permitted)
 *  \param[in] lcls_bss_status §3.2.2.119 LCLS-BSS-Status, optional
 *  \returns callee-allocated msgb with BSSMAP Assignment Complete message */
struct msgb *gsm0808_create_ass_compl2(uint8_t rr_cause, uint8_t chosen_channel,
				      uint8_t encr_alg_id, uint8_t speech_mode,
				      const struct sockaddr_storage *ss,
				      const struct gsm0808_speech_codec *sc,
				       const struct gsm0808_speech_codec_list *scl,
				       enum gsm0808_lcls_status lcls_bss_status)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
						"bssmap: ass compl");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_ASSIGMENT_COMPLETE);

	/* write 3.2.2.22 */
	msgb_tv_put(msg, GSM0808_IE_RR_CAUSE, rr_cause);

	/* write cirtcuit identity  code 3.2.2.2 */
	/* write cell identifier 3.2.2.17 */
	/* write chosen channel 3.2.2.33 when BTS picked it */
	msgb_tv_put(msg, GSM0808_IE_CHOSEN_CHANNEL, chosen_channel);

	/* write chosen encryption algorithm 3.2.2.44 */
	msgb_tv_put(msg, GSM0808_IE_CHOSEN_ENCR_ALG, encr_alg_id);

	/* write circuit pool 3.2.2.45 */
	/* write speech version chosen: 3.2.2.51 when BTS picked it */
	if (speech_mode != 0)
		msgb_tv_put(msg, GSM0808_IE_SPEECH_VERSION, speech_mode);

	/* AoIP: AoIP Transport Layer Address (BSS) 3.2.2.102 */
	if (ss)
		gsm0808_enc_aoip_trasp_addr(msg, ss);

	/* AoIP: Speech Codec (Chosen) 3.2.2.104 */
	if (sc)
		gsm0808_enc_speech_codec(msg, sc);

	/* AoIP: add Codec List (BSS Supported) 3.2.2.103 */
	if (scl)
		gsm0808_enc_speech_codec_list(msg, scl);

	/* FIXME: write LSA identifier 3.2.2.15 - see 3GPP TS 43.073 */

	/* LCLS-BSS-Status 3.2.2.119 */
	if (lcls_bss_status != GSM0808_LCLS_STS_NA)
		msgb_tv_put(msg, GSM0808_IE_LCLS_BSS_STATUS, lcls_bss_status);

	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP Assignment Completed message
 *  \param[in] rr_cause GSM 04.08 RR Cause value
 *  \param[in] chosen_channel Chosen Channel
 *  \param[in] encr_alg_id Encryption Algorithm ID
 *  \param[in] speech_mode Speech Mode
 *  \param[in] ss Socket Address of BSS-side RTP socket
 *  \param[in] sc Speech Codec (current)
 *  \param[in] scl Speech Codec List (permitted)
 *  \returns callee-allocated msgb with BSSMAP Assignment Complete message */
struct msgb *gsm0808_create_ass_compl(uint8_t rr_cause, uint8_t chosen_channel,
				      uint8_t encr_alg_id, uint8_t speech_mode,
				      const struct sockaddr_storage *ss,
				      const struct gsm0808_speech_codec *sc,
				      const struct gsm0808_speech_codec_list *scl)
{
	return gsm0808_create_ass_compl2(rr_cause, chosen_channel, encr_alg_id, speech_mode,
					 ss, sc, scl, GSM0808_LCLS_STS_NA);
}

/*! Create BSSMAP Assignment Completed message
 *  \param[in] rr_cause GSM 04.08 RR Cause value
 *  \param[in] chosen_channel Chosen Channel
 *  \param[in] encr_alg_id Encryption Algorithm ID
 *  \param[in] speech_mode Speech Mode
 *  \returns callee-allocated msgb with BSSMAP Assignment Complete message */
struct msgb *gsm0808_create_assignment_completed(uint8_t rr_cause,
						 uint8_t chosen_channel,
						 uint8_t encr_alg_id,
						 uint8_t speech_mode)
{
	return gsm0808_create_ass_compl2(rr_cause, chosen_channel, encr_alg_id,
					 speech_mode, NULL, NULL, NULL, GSM0808_LCLS_STS_NA);
}

/*! Create BSSMAP Assignment Failure message
 *  \param[in] cause BSSMAP Cause value
 *  \param[in] rr_cause GSM 04.08 RR Cause value
 *  \param[in] scl Optional Speech Cdec List (AoIP)
 *  \returns callee-allocated msgb with BSSMAP Assignment Failure message */
struct msgb *gsm0808_create_ass_fail(uint8_t cause, const uint8_t *rr_cause,
				     const struct gsm0808_speech_codec_list
				     *scl)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "bssmap: ass fail");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_ASSIGMENT_FAILURE);
	gsm0808_enc_cause(msg, cause);

	/* RR cause 3.2.2.22 */
	if (rr_cause)
		msgb_tv_put(msg, GSM0808_IE_RR_CAUSE, *rr_cause);

	/* Circuit pool 3.22.45 */
	/* Circuit pool list 3.2.2.46 */

	/* AoIP: add Codec List (BSS Supported) 3.2.2.103 */
	if (scl)
		gsm0808_enc_speech_codec_list(msg, scl);

	/* update the size */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP Assignment Failure message
 *  \param[in] cause BSSMAP Cause value
 *  \param[in] rr_cause GSM 04.08 RR Cause value
 *  \returns callee-allocated msgb with BSSMAP Assignment Failure message */
struct msgb *gsm0808_create_assignment_failure(uint8_t cause,
					       uint8_t *rr_cause)
{
	return gsm0808_create_ass_fail(cause, rr_cause, NULL);
}

/*! Create BSSMAP Clear Request message
 *  \param[in] cause BSSMAP Cause value
 *  \returns callee-allocated msgb with BSSMAP Clear Request message */
struct msgb *gsm0808_create_clear_rqst(uint8_t cause)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
				  "bssmap: clear rqst");
	if (!msg)
		return NULL;

	msgb_v_put(msg, BSS_MAP_MSG_CLEAR_RQST);
	gsm0808_enc_cause(msg, cause);
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP PAGING message
 *  \param[in] imsi Mandatory paged IMSI in string representation
 *  \param[in] tmsi Optional paged TMSI
 *  \param[in] cil Mandatory Cell Identity List (where to page)
 *  \param[in] chan_needed Channel Type needed
 *  \returns callee-allocated msgb with BSSMAP PAGING message */
struct msgb *gsm0808_create_paging2(const char *imsi, const uint32_t *tmsi,
				    const struct gsm0808_cell_id_list2 *cil,
				    const uint8_t *chan_needed)
{
	struct msgb *msg;
	uint8_t mid_buf[GSM48_MI_SIZE + 2];
	int mid_len;
	uint32_t tmsi_sw;

	/* Mandatory elements! */
	OSMO_ASSERT(imsi);
	OSMO_ASSERT(cil);

	/* Malformed IMSI */
	OSMO_ASSERT(strlen(imsi) <= GSM48_MI_SIZE);

	msg =
	    msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "paging");
	if (!msg)
		return NULL;

	/* Message Type 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_PAGING);

	/* mandatory IMSI 3.2.2.6 */
	mid_len = gsm48_generate_mid_from_imsi(mid_buf, imsi);
	msgb_tlv_put(msg, GSM0808_IE_IMSI, mid_len - 2, mid_buf + 2);

	/* TMSI 3.2.2.7 */
	if (tmsi) {
		tmsi_sw = osmo_htonl(*tmsi);
		msgb_tlv_put(msg, GSM0808_IE_TMSI, sizeof(*tmsi),
			     (uint8_t *) & tmsi_sw);
	}

	/* mandatory Cell Identifier List 3.2.2.27 */
	gsm0808_enc_cell_id_list2(msg, cil);

	/* Channel Needed 3.2.2.36 */
	if (chan_needed) {
		msgb_tv_put(msg, GSM0808_IE_CHANNEL_NEEDED,
			    (*chan_needed) & 0x03);
	}

	/* pre-pend the header */
	msg->l3h =
	    msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! DEPRECATED: Use gsm0808_create_paging2 instead.
 * Create BSSMAP PAGING message.
 *  \param[in] imsi Mandatory paged IMSI in string representation
 *  \param[in] tmsi Optional paged TMSI
 *  \param[in] cil Cell Identity List (where to page)
 *  \param[in] chan_needed Channel Type needed
 *  \returns callee-allocated msgb with BSSMAP PAGING message */
struct msgb *gsm0808_create_paging(const char *imsi, const uint32_t *tmsi,
				   const struct gsm0808_cell_id_list *cil,
				   const uint8_t *chan_needed)
{
	struct gsm0808_cell_id_list2 cil2 = {};

	/* Mandatory emelents! */
	OSMO_ASSERT(cil);

	if (cil->id_list_len > GSM0808_CELL_ID_LIST2_MAXLEN)
		return NULL;

	cil2.id_discr = cil->id_discr;
	memcpy(cil2.id_list, cil->id_list_lac, cil->id_list_len * sizeof(cil2.id_list[0].lac));
	cil2.id_list_len = cil->id_list_len;

	return gsm0808_create_paging2(imsi, tmsi, &cil2, chan_needed);
}

static uint8_t put_old_bss_to_new_bss_information(struct msgb *msg,
						  const struct gsm0808_old_bss_to_new_bss_info *i)
{
	uint8_t *old_tail;
	uint8_t *tlv_len;

	msgb_put_u8(msg, GSM0808_IE_OLD_BSS_TO_NEW_BSS_INFORMATION);
	tlv_len = msgb_put(msg, 1);
	old_tail = msg->tail;

	if (i->extra_information_present) {
		uint8_t val = 0;
		if (i->extra_information.prec)
			val |= 1 << 0;
		if (i->extra_information.lcs)
			val |= 1 << 1;
		if (i->extra_information.ue_prob)
			val |= 1 << 2;
		msgb_tlv_put(msg, GSM0808_FE_IE_EXTRA_INFORMATION, 1, &val);
	}

	if (i->current_channel_type_2_present) {
		uint8_t val[2] = {
			i->current_channel_type_2.mode,
			i->current_channel_type_2.field,
		};
		msgb_tlv_put(msg, GSM0808_FE_IE_CURRENT_CHANNEL_TYPE_2, 2, val);
	}

	*tlv_len = (uint8_t) (msg->tail - old_tail);
	return *tlv_len + 2;
}

/*! Create BSSMAP HANDOVER REQUIRED message.
 * \param[in] params  All information to be encoded.
 * \returns newly allocated msgb with BSSMAP HANDOVER REQUIRED message. */
struct msgb *gsm0808_create_handover_required(const struct gsm0808_handover_required *params)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "BSSMAP-HANDOVER-REQUIRED");
	if (!msg)
		return NULL;

	/* Message Type, 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_HANDOVER_REQUIRED);

	/* Cause, 3.2.2.5 */
	gsm0808_enc_cause(msg, params->cause);

	/* Cell Identifier List, 3.2.2.27 */
	gsm0808_enc_cell_id_list2(msg, &params->cil);

	/* Current Channel Type 1, 3.2.2.49 */
	if (params->current_channel_type_1_present)
		msgb_tv_fixed_put(msg, GSM0808_IE_CURRENT_CHANNEL_TYPE_1, 1, &params->current_channel_type_1);

	/* Speech Version (Used), 3.2.2.51 */
	if (params->speech_version_used_present)
		msgb_tv_put(msg, GSM0808_IE_SPEECH_VERSION, params->speech_version_used);

	if (params->old_bss_to_new_bss_info_present)
		put_old_bss_to_new_bss_information(msg, &params->old_bss_to_new_bss_info);

	/* pre-pend the header */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP HANDOVER REQUIRED REJECT message.
 * \returns newly allocated msgb with BSSMAP HANDOVER REQUIRED REJECT message. */
struct msgb *gsm0808_create_handover_required_reject(const struct gsm0808_handover_required_reject *params)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "BSSMAP-HANDOVER-REQUIRED-REJECT");
	if (!msg)
		return NULL;

	/* Message Type, 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_HANDOVER_REQUIRED_REJECT);

	/* Cause, 3.2.2.5 */
	gsm0808_enc_cause(msg, params->cause);

	/* prepend the header */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP HANDOVER REQUEST message, 3GPP TS 48.008 3.2.1.8.
 * Sent from the MSC to the potential new target cell during inter-BSC handover, or to the target MSC during inter-MSC
 * handover.
 */
struct msgb *gsm0808_create_handover_request(const struct gsm0808_handover_request *params)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "BSSMAP-HANDOVER-REQUEST");
	if (!msg)
		return NULL;

	/* Message Type, 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_HANDOVER_RQST);

	/* Channel Type 3.2.2.11 */
	gsm0808_enc_channel_type(msg, &params->channel_type);

	/* Encryption Information 3.2.2.10 */
	gsm0808_enc_encrypt_info(msg, &params->encryption_information);

	/* Classmark Information 1 3.2.2.30 or Classmark Information 2 3.2.2.19 (Classmark 2 wins) */
	if (params->classmark_information.classmark2_len) {
		msgb_tlv_put(msg, GSM0808_IE_CLASSMARK_INFORMATION_T2,
			     params->classmark_information.classmark2_len,
			     (const uint8_t*)&params->classmark_information.classmark2);
	} else if (params->classmark_information.classmark1_set) {
		msgb_tlv_put(msg, GSM0808_IE_CLASSMARK_INFORMATION_TYPE_1,
			     sizeof(params->classmark_information.classmark1),
			     (const uint8_t*)&params->classmark_information.classmark1);
	}
	/* (Classmark 3 possibly follows below) */

	/* Cell Identifier (Serving) , 3.2.2.17 */
	gsm0808_enc_cell_id(msg, &params->cell_identifier_serving);

	/* Cell Identifier (Target) , 3.2.2.17 */
	gsm0808_enc_cell_id(msg, &params->cell_identifier_target);

	/* Cause, 3.2.2.5 */
	gsm0808_enc_cause(msg, params->cause);

	/* Classmark Information 3 3.2.2.20 */
	if (params->classmark_information.classmark3_len) {
		msgb_tlv_put(msg, GSM0808_IE_CLASSMARK_INFORMATION_T3,
			     params->classmark_information.classmark3_len,
			     (const uint8_t*)&params->classmark_information.classmark3);
	}

	/* Current Channel type 1 3.2.2.49 */
	if (params->current_channel_type_1_present)
		msgb_tv_fixed_put(msg, GSM0808_IE_CURRENT_CHANNEL_TYPE_1, 1, &params->current_channel_type_1);

	/* Speech Version (Used), 3.2.2.51 */
	if (params->speech_version_used) {
		msgb_tv_put(msg, GSM0808_IE_SPEECH_VERSION, params->speech_version_used);
	}

	/* Chosen Encryption Algorithm (Serving) 3.2.2.44 */
	if (params->chosen_encryption_algorithm_serving)
		msgb_tv_put(msg, GSM0808_IE_CHOSEN_ENCR_ALG, params->chosen_encryption_algorithm_serving);

	/* Old BSS to New BSS Information 3.2.2.58 */
	if (params->old_bss_to_new_bss_info_raw && params->old_bss_to_new_bss_info_raw_len) {
		msgb_tlv_put(msg, GSM0808_IE_OLD_BSS_TO_NEW_BSS_INFORMATION,
			     params->old_bss_to_new_bss_info_raw_len,
			     params->old_bss_to_new_bss_info_raw);
	} else if (params->old_bss_to_new_bss_info_present) {
		put_old_bss_to_new_bss_information(msg, &params->old_bss_to_new_bss_info);
	}

	/* IMSI 3.2.2.6 */
	if (params->imsi) {
		uint8_t mid_buf[GSM48_MI_SIZE + 2];
		int mid_len = gsm48_generate_mid_from_imsi(mid_buf, params->imsi);
		msgb_tlv_put(msg, GSM0808_IE_IMSI, mid_len - 2, mid_buf + 2);
	}

	if (params->aoip_transport_layer)
		gsm0808_enc_aoip_trasp_addr(msg, params->aoip_transport_layer);

	if (params->codec_list_msc_preferred)
		gsm0808_enc_speech_codec_list(msg, params->codec_list_msc_preferred);

	if (params->call_id_present) {
		uint8_t val[4];
		osmo_store32le(params->call_id, val);
		msgb_tv_fixed_put(msg, GSM0808_IE_CALL_ID, 4, val);
	}

	if (params->global_call_reference && params->global_call_reference_len) {
		msgb_tlv_put(msg, GSM0808_IE_GLOBAL_CALL_REF,
			     params->global_call_reference_len, params->global_call_reference);
	}

	/* prepend header with final length */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP HANDOVER REQUEST ACKNOWLEDGE message, 3GPP TS 48.008 3.2.1.10.
 * Sent from the MT BSC back to the MSC when it has allocated an lchan to handover to.
 * l3_info is the RR Handover Command that the MO BSC sends to the MS to move over. */
struct msgb *gsm0808_create_handover_request_ack2(const struct gsm0808_handover_request_ack *params)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "BSSMAP-HANDOVER-REQUEST-ACK");
	if (!msg)
		return NULL;

	/* Message Type, 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_HANDOVER_RQST_ACKNOWLEDGE);

	/* Layer 3 Information, 3.2.2.24 -- it is actually mandatory, but rather compose a nonstandard message than
	 * segfault or return NULL without a log message. */
	if (params->l3_info && params->l3_info_len)
		msgb_tlv_put(msg, GSM0808_IE_LAYER_3_INFORMATION, params->l3_info_len, params->l3_info);

	if (params->chosen_channel_present)
		msgb_tv_put(msg, GSM0808_IE_CHOSEN_CHANNEL, params->chosen_channel);
	if (params->chosen_encr_alg)
		msgb_tv_put(msg, GSM0808_IE_CHOSEN_ENCR_ALG, params->chosen_encr_alg);

	if (params->chosen_speech_version != 0)
		msgb_tv_put(msg, GSM0808_IE_SPEECH_VERSION, params->chosen_speech_version);

	if (params->aoip_transport_layer)
		gsm0808_enc_aoip_trasp_addr(msg, params->aoip_transport_layer);

	/* AoIP: Speech Codec (Chosen) 3.2.2.104 */
	if (params->speech_codec_chosen_present)
		gsm0808_enc_speech_codec(msg, &params->speech_codec_chosen);

	/* prepend header with final length */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Same as gsm0808_create_handover_request_ack2() but with less parameters.
 * In particular, this lacks the AoIP Transport Layer address. */
struct msgb *gsm0808_create_handover_request_ack(const uint8_t *l3_info, uint8_t l3_info_len,
						 uint8_t chosen_channel, uint8_t chosen_encr_alg,
						 uint8_t chosen_speech_version)
{
	struct gsm0808_handover_request_ack params = {
		.l3_info = l3_info,
		.l3_info_len = l3_info_len,
		.chosen_channel = chosen_channel,
		.chosen_encr_alg = chosen_encr_alg,
		.chosen_speech_version = chosen_speech_version,
	};

	return gsm0808_create_handover_request_ack2(&params);
}

/*! Create BSSMAP HANDOVER COMMAND message, 3GPP TS 48.008 3.2.1.11.
 * Sent from the MSC to the old BSS to transmit the RR Handover Command received from the new BSS. */
struct msgb *gsm0808_create_handover_command(const struct gsm0808_handover_command *params)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "BSSMAP-HANDOVER-COMMAND");
	if (!msg)
		return NULL;

	/* Message Type, 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_HANDOVER_CMD);

	msgb_tlv_put(msg, GSM0808_IE_LAYER_3_INFORMATION, params->l3_info_len, params->l3_info);

	if (params->cell_identifier.id_discr != CELL_IDENT_NO_CELL)
		gsm0808_enc_cell_id(msg, &params->cell_identifier);

	if (params->new_bss_to_old_bss_info_raw
	    && params->new_bss_to_old_bss_info_raw_len)
		msgb_tlv_put(msg, GSM0808_IE_NEW_BSS_TO_OLD_BSS_INFO, params->new_bss_to_old_bss_info_raw_len,
			     params->new_bss_to_old_bss_info_raw);

	/* prepend header with final length */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP HANDOVER DETECT message, 3GPP TS 48.008 3.2.1.40.
 * Sent from the MT BSC back to the MSC when the MS has sent a handover RACH request and the MT BSC has
 * received the Handover Detect message. */
struct msgb *gsm0808_create_handover_detect()
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "BSSMAP-HANDOVER-DETECT");
	if (!msg)
		return NULL;

	/* Message Type, 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_HANDOVER_DETECT);

	/* prepend header with final length */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP HANDOVER SUCCEEDED message, 3GPP TS 48.008 3.2.1.13.
 * Sent from the MSC back to the old BSS to notify that the MS has successfully accessed the new BSS. */
struct msgb *gsm0808_create_handover_succeeded()
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "BSSMAP-HANDOVER-DETECT");
	if (!msg)
		return NULL;

	/* Message Type, 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_HANDOVER_SUCCEEDED);

	/* prepend header with final length */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP HANDOVER COMPLETE message, 3GPP TS 48.008 3.2.1.12.
 * Sent from the MT BSC back to the MSC when the MS has fully settled into the new lchan. */
struct msgb *gsm0808_create_handover_complete(const struct gsm0808_handover_complete *params)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "BSSMAP-HANDOVER-COMPLETE");
	if (!msg)
		return NULL;

	/* Message Type, 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_HANDOVER_COMPLETE);

	/* RR Cause, 3.2.2.22 */
	if (params->rr_cause_present)
		msgb_tlv_put(msg, GSM0808_IE_RR_CAUSE, 1, &params->rr_cause);

	/* AoIP: Speech Codec (Chosen) 3.2.2.104 */
	if (params->speech_codec_chosen_present)
		gsm0808_enc_speech_codec(msg, &params->speech_codec_chosen);

	/* AoIP: add Codec List (BSS Supported) 3.2.2.103 */
	if (params->codec_list_bss_supported.len)
		gsm0808_enc_speech_codec_list(msg, &params->codec_list_bss_supported);

	/* Chosen Encryption Algorithm 3.2.2.44 */
	if (params->chosen_encr_alg_present)
		msgb_tv_put(msg, GSM0808_IE_CHOSEN_ENCR_ALG, params->chosen_encr_alg);

	/* LCLS-BSS-Status 3.2.2.119 */
	if (params->lcls_bss_status_present)
		msgb_tv_put(msg, GSM0808_IE_LCLS_BSS_STATUS, params->lcls_bss_status);

	/* prepend header with final length */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP HANDOVER FAILURE message, 3GPP TS 48.008 3.2.1.16.
 * Sent from the MT BSC back to the MSC when the handover has failed. */
struct msgb *gsm0808_create_handover_failure(const struct gsm0808_handover_failure *params)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "BSSMAP-HANDOVER-FAILURE");
	if (!msg)
		return NULL;

	/* Message Type, 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_HANDOVER_FAILURE);

	/* Cause, 3.2.2.5 */
	gsm0808_enc_cause(msg, params->cause);

	/* RR Cause, 3.2.2.22 */
	if (params->rr_cause_present)
		msgb_tlv_put(msg, GSM0808_IE_RR_CAUSE, 1, &params->rr_cause);

	/* AoIP: add Codec List (BSS Supported) 3.2.2.103 */
	if (params->codec_list_bss_supported.len)
		gsm0808_enc_speech_codec_list(msg, &params->codec_list_bss_supported);

	/* prepend header with final length */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Create BSSMAP HANDOVER PERFORMED message, 3GPP TS 48.008 3.2.1.25.
 * \param[in] params  All information to be encoded.
 * \returns callee-allocated msgb with BSSMAP HANDOVER PERFORMED message */
struct msgb *gsm0808_create_handover_performed(const struct gsm0808_handover_performed *params)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "BSSMAP-HANDOVER-PERFORMED");
	if (!msg)
		return NULL;

	/* Message Type, 3.2.2.1 */
	msgb_v_put(msg, BSS_MAP_MSG_HANDOVER_PERFORMED);

	/* Cause, 3.2.2.5 */
	gsm0808_enc_cause(msg, params->cause);

	/* Cell Identifier, 3.2.2.17 */
	gsm0808_enc_cell_id(msg, &params->cell_id);

	/* Chosen Channel 3.2.2.33 */
	if (params->chosen_channel_present)
		msgb_tv_put(msg, GSM0808_IE_CHOSEN_CHANNEL, params->chosen_channel);

	/* Chosen Encryption Algorithm 3.2.2.44 */
	if (params->chosen_encr_alg_present)
		msgb_tv_put(msg, GSM0808_IE_CHOSEN_ENCR_ALG, params->chosen_encr_alg);

	/* Speech Version (chosen) 3.2.2.51 */
	if (params->speech_version_chosen_present)
		msgb_tv_put(msg, GSM0808_IE_SPEECH_VERSION, params->speech_version_chosen);

	/* AoIP: Speech Codec (chosen) 3.2.2.104 */
	if (params->speech_codec_chosen_present)
		gsm0808_enc_speech_codec(msg, &params->speech_codec_chosen);

	/* LCLS-BSS-Status 3.2.2.119 */
	if (params->lcls_bss_status_present)
		msgb_tv_put(msg, GSM0808_IE_LCLS_BSS_STATUS, params->lcls_bss_status);

	/* prepend header with final length */
	msg->l3h = msgb_tv_push(msg, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg));

	return msg;
}

/*! Prepend a DTAP header to given Message Buffer
 *  \param[in] msgb Message Buffer
 *  \param[in] link_id Link Identifier */
void gsm0808_prepend_dtap_header(struct msgb *msg, uint8_t link_id)
{
	uint8_t *hh = msgb_push(msg, 3);
	hh[0] = BSSAP_MSG_DTAP;
	hh[1] = link_id;
	hh[2] = msg->len - 3;
}

/*! Create BSSMAP DTAP message
 *  \param[in] msg_l3 Messge Buffer containing Layer3 message
 *  \param[in] link_id Link Identifier
 *  \returns callee-allocated msgb with BSSMAP DTAP message */
struct msgb *gsm0808_create_dtap(struct msgb *msg_l3, uint8_t link_id)
{
	struct dtap_header *header;
	uint8_t *data;
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "dtap");
	if (!msg)
		return NULL;

	/* DTAP header */
	msg->l3h = msgb_put(msg, sizeof(*header));
	header = (struct dtap_header *) &msg->l3h[0];
	header->type = BSSAP_MSG_DTAP;
	header->link_id = link_id;
	header->length = msgb_l3len(msg_l3);

	/* Payload */
	data = msgb_put(msg, header->length);
	memcpy(data, msg_l3->l3h, header->length);

	return msg;
}

/* As per 3GPP TS 48.008 version 11.7.0 Release 11 */
static const struct tlv_definition bss_att_tlvdef = {
	.def = {
		[GSM0808_IE_CIRCUIT_IDENTITY_CODE]  = { TLV_TYPE_FIXED, 2 },
		[GSM0808_IE_CONNECTION_RELEASE_RQSTED]	= { TLV_TYPE_TV },
		[GSM0808_IE_RESOURCE_AVAILABLE]		= { TLV_TYPE_FIXED, 21 },
		[GSM0808_IE_CAUSE]			= { TLV_TYPE_TLV },
		[GSM0808_IE_IMSI]		    = { TLV_TYPE_TLV },
		[GSM0808_IE_TMSI]		    = { TLV_TYPE_TLV },
		[GSM0808_IE_NUMBER_OF_MSS]		= { TLV_TYPE_TV },
		[GSM0808_IE_LAYER_3_HEADER_INFORMATION] = { TLV_TYPE_TLV },
		[GSM0808_IE_ENCRYPTION_INFORMATION] = { TLV_TYPE_TLV },
		[GSM0808_IE_CHANNEL_TYPE]	    = { TLV_TYPE_TLV },
		[GSM0808_IE_PERIODICITY]		= { TLV_TYPE_TV },
		[GSM0808_IE_EXTENDED_RESOURCE_INDICATOR]= { TLV_TYPE_TV },
		[GSM0808_IE_TOTAL_RESOURCE_ACCESSIBLE]	= { TLV_TYPE_FIXED, 4 },
		[GSM0808_IE_LSA_IDENTIFIER]		= { TLV_TYPE_TLV },
		[GSM0808_IE_LSA_IDENTIFIER_LIST]	= { TLV_TYPE_TLV },
		[GSM0808_IE_LSA_INFORMATION]	= { TLV_TYPE_TLV },
		[GSM0808_IE_CELL_IDENTIFIER]	    = { TLV_TYPE_TLV },
		[GSM0808_IE_PRIORITY]		    = { TLV_TYPE_TLV },
		[GSM0808_IE_CLASSMARK_INFORMATION_T2] = { TLV_TYPE_TLV },
		[GSM0808_IE_CLASSMARK_INFORMATION_T3] = { TLV_TYPE_TLV },
		[GSM0808_IE_INTERFERENCE_BAND_TO_USE] = { TLV_TYPE_TV },
		[GSM0808_IE_RR_CAUSE]			= { TLV_TYPE_TV },
		[GSM0808_IE_LAYER_3_INFORMATION]    = { TLV_TYPE_TLV },
		[GSM0808_IE_DLCI]			= { TLV_TYPE_TV },
		[GSM0808_IE_DOWNLINK_DTX_FLAG]	    = { TLV_TYPE_TV },
		[GSM0808_IE_CELL_IDENTIFIER_LIST]   = { TLV_TYPE_TLV },
		[GSM0808_IE_CELL_ID_LIST_SEGMENT]	= { TLV_TYPE_TLV },
		[GSM0808_IE_CELL_ID_LIST_SEG_EST_CELLS]	= { TLV_TYPE_TLV },
		[GSM0808_IE_CELL_ID_LIST_SEG_CELLS_TBE]	= { TLV_TYPE_TLV },
		[GSM0808_IE_CELL_ID_LIST_SEG_REL_CELLS]	= { TLV_TYPE_TLV },
		[GSM0808_IE_CELL_ID_LIST_SEG_NE_CELLS]	= { TLV_TYPE_TLV },
		[GSM0808_IE_RESPONSE_RQST]		= { TLV_TYPE_T },
		[GSM0808_IE_RESOURCE_INDICATION_METHOD]	= { TLV_TYPE_TV },
		[GSM0808_IE_CLASSMARK_INFORMATION_TYPE_1] = { TLV_TYPE_TV },
		[GSM0808_IE_CIRCUIT_IDENTITY_CODE_LIST]	= { TLV_TYPE_TLV },
		[GSM0808_IE_DIAGNOSTIC]			= { TLV_TYPE_TLV },
		[GSM0808_IE_CHOSEN_CHANNEL]	    = { TLV_TYPE_TV },
		[GSM0808_IE_CIPHER_RESPONSE_MODE]   = { TLV_TYPE_TV },
		[GSM0808_IE_LAYER_3_MESSAGE_CONTENTS] = { TLV_TYPE_TLV },
		[GSM0808_IE_CHANNEL_NEEDED]	    = { TLV_TYPE_TV },
		[GSM0808_IE_TRACE_TYPE]			= { TLV_TYPE_TV },
		[GSM0808_IE_TRIGGERID]			= { TLV_TYPE_TLV },
		[GSM0808_IE_TRACE_REFERENCE]		= { TLV_TYPE_TV },
		[GSM0808_IE_TRANSACTIONID]		= { TLV_TYPE_TLV },
		[GSM0808_IE_MOBILE_IDENTITY]		= { TLV_TYPE_TLV },
		[GSM0808_IE_OMCID]			= { TLV_TYPE_TLV },
		[GSM0808_IE_FORWARD_INDICATOR]		= { TLV_TYPE_TV },
		[GSM0808_IE_CHOSEN_ENCR_ALG]        = { TLV_TYPE_TV },
		[GSM0808_IE_CIRCUIT_POOL]		= { TLV_TYPE_TV },
		[GSM0808_IE_CIRCUIT_POOL_LIST]		= { TLV_TYPE_TLV },
		[GSM0808_IE_TIME_INDICATION]		= { TLV_TYPE_TV },
		[GSM0808_IE_RESOURCE_SITUATION]		= { TLV_TYPE_TLV },
		[GSM0808_IE_CURRENT_CHANNEL_TYPE_1]	= { TLV_TYPE_TV },
		[GSM0808_IE_QUEUEING_INDICATOR]		= { TLV_TYPE_TV },
		[GSM0808_IE_SPEECH_VERSION]         = { TLV_TYPE_TV },
		[GSM0808_IE_ASSIGNMENT_REQUIREMENT]	= { TLV_TYPE_TV },
		[GSM0808_IE_TALKER_FLAG]	    = { TLV_TYPE_T },
		[GSM0808_IE_GROUP_CALL_REFERENCE]   = { TLV_TYPE_TLV },
		[GSM0808_IE_EMLPP_PRIORITY]	    = { TLV_TYPE_TV },
		[GSM0808_IE_CONFIG_EVO_INDI]	    = { TLV_TYPE_TV },
		[GSM0808_IE_OLD_BSS_TO_NEW_BSS_INFORMATION] = { TLV_TYPE_TLV },
		[GSM0808_IE_LCS_QOS]			= { TLV_TYPE_TLV },
		[GSM0808_IE_LSA_ACCESS_CTRL_SUPPR]  = { TLV_TYPE_TV },
		[GSM0808_IE_LCS_PRIORITY]		= { TLV_TYPE_TLV },
		[GSM0808_IE_LOCATION_TYPE]		= { TLV_TYPE_TLV },
		[GSM0808_IE_LOCATION_ESTIMATE]		= { TLV_TYPE_TLV },
		[GSM0808_IE_POSITIONING_DATA]		= { TLV_TYPE_TLV },
		[GSM0808_IE_LCS_CAUSE]			= { TLV_TYPE_TLV },
		[GSM0808_IE_APDU]			= { TLV_TYPE_TLV },
		[GSM0808_IE_NETWORK_ELEMENT_IDENTITY]	= { TLV_TYPE_TLV },
		[GSM0808_IE_GPS_ASSISTANCE_DATA]	= { TLV_TYPE_TLV },
		[GSM0808_IE_DECIPHERING_KEYS]		= { TLV_TYPE_TLV },
		[GSM0808_IE_RETURN_ERROR_RQST]		= { TLV_TYPE_TLV },
		[GSM0808_IE_RETURN_ERROR_CAUSE]		= { TLV_TYPE_TLV },
		[GSM0808_IE_SEGMENTATION]		= { TLV_TYPE_TLV },
		[GSM0808_IE_SERVICE_HANDOVER]	    = { TLV_TYPE_TLV },
		[GSM0808_IE_SOURCE_RNC_TO_TARGET_RNC_TRANSPARENT_UMTS]		= { TLV_TYPE_TLV },
		[GSM0808_IE_SOURCE_RNC_TO_TARGET_RNC_TRANSPARENT_CDMA2000]	= { TLV_TYPE_TLV },
		[GSM0808_IE_GERAN_CLASSMARK]		= { TLV_TYPE_TLV },
		[GSM0808_IE_GERAN_BSC_CONTAINER]	= { TLV_TYPE_TLV },
		[GSM0808_IE_NEW_BSS_TO_OLD_BSS_INFO]	= { TLV_TYPE_TLV },
		[GSM0800_IE_INTER_SYSTEM_INFO]		= { TLV_TYPE_TLV },
		[GSM0808_IE_SNA_ACCESS_INFO]		= { TLV_TYPE_TLV },
		[GSM0808_IE_VSTK_RAND_INFO]		= { TLV_TYPE_TLV },
		[GSM0808_IE_PAGING_INFO]		= { TLV_TYPE_TV },
		[GSM0808_IE_IMEI]			= { TLV_TYPE_TLV },
		[GSM0808_IE_VELOCITY_ESTIMATE]		= { TLV_TYPE_TLV },
		[GSM0808_IE_VGCS_FEATURE_FLAGS]		= { TLV_TYPE_TLV },
		[GSM0808_IE_TALKER_PRIORITY]		= { TLV_TYPE_TV },
		[GSM0808_IE_EMERGENCY_SET_INDICATION]	= { TLV_TYPE_T },
		[GSM0808_IE_TALKER_IDENTITY]		= { TLV_TYPE_TLV },
		[GSM0808_IE_SMS_TO_VGCS]		= { TLV_TYPE_TLV },
		[GSM0808_IE_VGCS_TALKER_MODE]		= { TLV_TYPE_TLV },
		[GSM0808_IE_VGCS_VBS_CELL_STATUS]	= { TLV_TYPE_TLV },
		[GSM0808_IE_GANSS_ASSISTANCE_DATA]	= { TLV_TYPE_TLV },
		[GSM0808_IE_GANSS_POSITIONING_DATA]	= { TLV_TYPE_TLV },
		[GSM0808_IE_GANSS_LOCATION_TYPE]	= { TLV_TYPE_TLV },
		[GSM0808_IE_APP_DATA]			= { TLV_TYPE_TLV },
		[GSM0808_IE_DATA_IDENTITY]		= { TLV_TYPE_TLV },
		[GSM0808_IE_APP_DATA_INFO]		= { TLV_TYPE_TLV },
		[GSM0808_IE_MSISDN]			= { TLV_TYPE_TLV },
		[GSM0808_IE_AOIP_TRASP_ADDR]		= { TLV_TYPE_TLV },
		[GSM0808_IE_SPEECH_CODEC_LIST]		= { TLV_TYPE_TLV },
		[GSM0808_IE_SPEECH_CODEC]		= { TLV_TYPE_TLV },
		[GSM0808_IE_CALL_ID]			= { TLV_TYPE_FIXED, 4 },
		[GSM0808_IE_CALL_ID_LIST]		= { TLV_TYPE_TLV },
		[GSM0808_IE_A_IF_SEL_FOR_RESET]		= { TLV_TYPE_TV },
		[GSM0808_IE_KC_128]			= { TLV_TYPE_FIXED, 16 },
		[GSM0808_IE_CSG_IDENTIFIER]		= { TLV_TYPE_TLV },
		[GSM0808_IE_REDIR_ATTEMPT_FLAG]		= { TLV_TYPE_T },
		[GSM0808_IE_REROUTE_REJ_CAUSE]		= { TLV_TYPE_TV },
		[GSM0808_IE_SEND_SEQ_NUM]		= { TLV_TYPE_TV },
		[GSM0808_IE_REROUTE_COMPL_OUTCOME]	= { TLV_TYPE_TV },
		[GSM0808_IE_GLOBAL_CALL_REF]		= { TLV_TYPE_TLV },
		[GSM0808_IE_LCLS_CONFIG]		= { TLV_TYPE_TV },
		[GSM0808_IE_LCLS_CONN_STATUS_CTRL]	= { TLV_TYPE_TV },
		[GSM0808_IE_LCLS_CORR_NOT_NEEDED]	= { TLV_TYPE_TV },
		[GSM0808_IE_LCLS_BSS_STATUS]		= { TLV_TYPE_TV },
		[GSM0808_IE_LCLS_BREAK_REQ]		= { TLV_TYPE_TV },
		[GSM0808_IE_CSFB_INDICATION]		= { TLV_TYPE_T },
		[GSM0808_IE_CS_TO_PS_SRVCC]		= { TLV_TYPE_T },
		[GSM0808_IE_SRC_ENB_TO_TGT_ENB_TRANSP]	= { TLV_TYPE_TLV },
		[GSM0808_IE_CS_TO_PS_SRVCC_IND]		= { TLV_TYPE_T },
		[GSM0808_IE_CN_TO_MS_TRANSP_INFO]	= { TLV_TYPE_TLV },
		[GSM0808_IE_SELECTED_PLMN_ID]		= { TLV_TYPE_FIXED, 3 },
		[GSM0808_IE_LAST_USED_EUTRAN_PLMN_ID]	= { TLV_TYPE_FIXED, 3 },

		/* Osmocom extensions */
		[GSM0808_IE_OSMO_OSMUX_SUPPORT]		= { TLV_TYPE_T },
		[GSM0808_IE_OSMO_OSMUX_CID]		= { TLV_TYPE_TV },
	},
};

const struct tlv_definition *gsm0808_att_tlvdef(void)
{
	return &bss_att_tlvdef;
}

static const struct value_string gsm0808_msgt_names[] = {
	{ BSS_MAP_MSG_ASSIGMENT_RQST,		"ASSIGNMENT REQ" },
	{ BSS_MAP_MSG_ASSIGMENT_COMPLETE,	"ASSIGNMENT COMPL" },
	{ BSS_MAP_MSG_ASSIGMENT_FAILURE,	"ASSIGNMENT FAIL" },
	{ BSS_MAP_MSG_CHAN_MOD_RQST,		"CHANNEL MODIFY REQUEST" },

	{ BSS_MAP_MSG_HANDOVER_RQST,		"HANDOVER REQ" },
	{ BSS_MAP_MSG_HANDOVER_REQUIRED,	"HANDOVER REQUIRED" },
	{ BSS_MAP_MSG_HANDOVER_RQST_ACKNOWLEDGE,"HANDOVER REQ ACK" },
	{ BSS_MAP_MSG_HANDOVER_CMD,		"HANDOVER CMD" },
	{ BSS_MAP_MSG_HANDOVER_COMPLETE,	"HANDOVER COMPLETE" },
	{ BSS_MAP_MSG_HANDOVER_SUCCEEDED,	"HANDOVER SUCCESS" },
	{ BSS_MAP_MSG_HANDOVER_FAILURE,		"HANDOVER FAILURE" },
	{ BSS_MAP_MSG_HANDOVER_PERFORMED,	"HANDOVER PERFORMED" },
	{ BSS_MAP_MSG_HANDOVER_CANDIDATE_ENQUIRE, "HANDOVER CAND ENQ" },
	{ BSS_MAP_MSG_HANDOVER_CANDIDATE_RESPONSE, "HANDOVER CAND RESP" },
	{ BSS_MAP_MSG_HANDOVER_REQUIRED_REJECT,	"HANDOVER REQ REJ" },
	{ BSS_MAP_MSG_HANDOVER_DETECT,		"HANDOVER DETECT" },
	{ BSS_MAP_MSG_INT_HANDOVER_REQUIRED,	"INT HANDOVER REQ" },
	{ BSS_MAP_MSG_INT_HANDOVER_REQUIRED_REJ,"INT HANDOVER REQ REJ" },
	{ BSS_MAP_MSG_INT_HANDOVER_CMD,		"INT HANDOVER CMD" },
	{ BSS_MAP_MSG_INT_HANDOVER_ENQUIRY,	"INT HANDOVER ENQ" },

	{ BSS_MAP_MSG_CLEAR_CMD,		"CLEAR COMMAND" },
	{ BSS_MAP_MSG_CLEAR_COMPLETE,		"CLEAR COMPLETE" },
	{ BSS_MAP_MSG_CLEAR_RQST,		"CLEAR REQUEST" },
	{ BSS_MAP_MSG_SAPI_N_REJECT,		"SAPI N REJECT" },
	{ BSS_MAP_MSG_CONFUSION,		"CONFUSION" },

	{ BSS_MAP_MSG_SUSPEND,			"SUSPEND" },
	{ BSS_MAP_MSG_RESUME,			"RESUME" },
	{ BSS_MAP_MSG_CONNECTION_ORIENTED_INFORMATION, "CONN ORIENT INFO" },
	{ BSS_MAP_MSG_PERFORM_LOCATION_RQST,	"PERFORM LOC REQ" },
	{ BSS_MAP_MSG_LSA_INFORMATION,		"LSA INFORMATION" },
	{ BSS_MAP_MSG_PERFORM_LOCATION_RESPONSE, "PERFORM LOC RESP" },
	{ BSS_MAP_MSG_PERFORM_LOCATION_ABORT,	"PERFORM LOC ABORT" },
	{ BSS_MAP_MSG_COMMON_ID,		"COMMON ID" },
	{ BSS_MAP_MSG_REROUTE_CMD,		"REROUTE COMMAND" },
	{ BSS_MAP_MSG_REROUTE_COMPLETE,		"REROUTE COMPLETE" },

	{ BSS_MAP_MSG_RESET,			"RESET" },
	{ BSS_MAP_MSG_RESET_ACKNOWLEDGE,	"RESET ACK" },
	{ BSS_MAP_MSG_OVERLOAD,			"OVERLOAD" },
	{ BSS_MAP_MSG_RESET_CIRCUIT,		"RESET CIRCUIT" },
	{ BSS_MAP_MSG_RESET_CIRCUIT_ACKNOWLEDGE, "RESET CIRCUIT ACK" },
	{ BSS_MAP_MSG_MSC_INVOKE_TRACE,		"MSC INVOKE TRACE" },
	{ BSS_MAP_MSG_BSS_INVOKE_TRACE,		"BSS INVOKE TRACE" },
	{ BSS_MAP_MSG_CONNECTIONLESS_INFORMATION, "CONNLESS INFO" },
	{ BSS_MAP_MSG_RESET_IP_RSRC,		"RESET IP RESOURCE" },
	{ BSS_MAP_MSG_RESET_IP_RSRC_ACK,	"RESET IP RESOURCE ACK" },

	{ BSS_MAP_MSG_BLOCK,			"BLOCK" },
	{ BSS_MAP_MSG_BLOCKING_ACKNOWLEDGE,	"BLOCK ACK" },
	{ BSS_MAP_MSG_UNBLOCK,			"UNBLOCK" },
	{ BSS_MAP_MSG_UNBLOCKING_ACKNOWLEDGE,	"UNBLOCK ACK" },
	{ BSS_MAP_MSG_CIRCUIT_GROUP_BLOCK,	"CIRC GROUP BLOCK" },
	{ BSS_MAP_MSG_CIRCUIT_GROUP_BLOCKING_ACKNOWLEDGE, "CIRC GORUP BLOCK ACK" },
	{ BSS_MAP_MSG_CIRCUIT_GROUP_UNBLOCK,	"CIRC GROUP UNBLOCK" },
	{ BSS_MAP_MSG_CIRCUIT_GROUP_UNBLOCKING_ACKNOWLEDGE, "CIRC GROUP UNBLOCK ACK" },
	{ BSS_MAP_MSG_UNEQUIPPED_CIRCUIT,	"UNEQUIPPED CIRCUIT" },
	{ BSS_MAP_MSG_CHANGE_CIRCUIT,		"CHANGE CIRCUIT" },
	{ BSS_MAP_MSG_CHANGE_CIRCUIT_ACKNOWLEDGE, "CHANGE CIRCUIT ACK" },

	{ BSS_MAP_MSG_RESOURCE_RQST,		"RESOURCE REQ" },
	{ BSS_MAP_MSG_RESOURCE_INDICATION,	"RESOURCE IND" },
	{ BSS_MAP_MSG_PAGING,			"PAGING" },
	{ BSS_MAP_MSG_CIPHER_MODE_CMD,		"CIPHER MODE CMD" },
	{ BSS_MAP_MSG_CLASSMARK_UPDATE,		"CLASSMARK UPDATE" },
	{ BSS_MAP_MSG_CIPHER_MODE_COMPLETE,	"CIPHER MODE COMPLETE" },
	{ BSS_MAP_MSG_QUEUING_INDICATION,	"QUEUING INDICATION" },
	{ BSS_MAP_MSG_COMPLETE_LAYER_3,		"COMPLETE LAYER 3" },
	{ BSS_MAP_MSG_CLASSMARK_RQST,		"CLASSMARK REQ" },
	{ BSS_MAP_MSG_CIPHER_MODE_REJECT,	"CIPHER MODE REJECT" },
	{ BSS_MAP_MSG_LOAD_INDICATION,		"LOAD IND" },

	{ BSS_MAP_MSG_VGCS_VBS_SETUP,		"VGCS/VBS SETUP" },
	{ BSS_MAP_MSG_VGCS_VBS_SETUP_ACK,	"VGCS/VBS SETUP ACK" },
	{ BSS_MAP_MSG_VGCS_VBS_SETUP_REFUSE,	"VGCS/VBS SETUP REFUSE" },
	{ BSS_MAP_MSG_VGCS_VBS_ASSIGNMENT_RQST,	"VGCS/VBS ASSIGN REQ" },
	{ BSS_MAP_MSG_VGCS_VBS_ASSIGNMENT_RESULT, "VGCS/VBS ASSIGN RES" },
	{ BSS_MAP_MSG_VGCS_VBS_ASSIGNMENT_FAILURE, "VGCS/VBS ASSIGN FAIL" },
	{ BSS_MAP_MSG_VGCS_VBS_QUEUING_INDICATION, "VGCS/VBS QUEUING IND" },
	{ BSS_MAP_MSG_UPLINK_RQST,		"UPLINK REQ" },
	{ BSS_MAP_MSG_UPLINK_RQST_ACKNOWLEDGE,	"UPLINK REQ ACK" },
	{ BSS_MAP_MSG_UPLINK_RQST_CONFIRMATION,	"UPLINK REQ CONF" },
	{ BSS_MAP_MSG_UPLINK_RELEASE_INDICATION,"UPLINK REL IND" },
	{ BSS_MAP_MSG_UPLINK_REJECT_CMD,	"UPLINK REJ CMD" },
	{ BSS_MAP_MSG_UPLINK_RELEASE_CMD,	"UPLINK REL CMD" },
	{ BSS_MAP_MSG_UPLINK_SEIZED_CMD,	"UPLINK SEIZED CMD" },
	{ BSS_MAP_MSG_VGCS_ADDL_INFO,		"VGCS ADDL INFO" },
	{ BSS_MAP_MSG_NOTIFICATION_DATA,	"NOTIF DATA" },
	{ BSS_MAP_MSG_UPLINK_APP_DATA,		"UPLINK APP DATA" },

	{ BSS_MAP_MSG_LCLS_CONNECT_CTRL,	"LCLS-CONNECT-CONTROL" },
	{ BSS_MAP_MSG_LCLS_CONNECT_CTRL_ACK,	"CLS-CONNECT-CONTROL-ACK" },
	{ BSS_MAP_MSG_LCLS_NOTIFICATION,	"LCLS-NOTIFICATION" },

	{ 0, NULL }
};

/*! Return string name of BSSMAP Message Type */
const char *gsm0808_bssmap_name(uint8_t msg_type)
{
	return get_value_string(gsm0808_msgt_names, msg_type);
}

static const struct value_string gsm0808_bssap_names[] = {
	{ BSSAP_MSG_BSS_MANAGEMENT, 		"MANAGEMENT" },
	{ BSSAP_MSG_DTAP,			"DTAP" },
	{ 0, NULL }
};

/*! Return string name of BSSAP Message Type */
const char *gsm0808_bssap_name(uint8_t msg_type)
{
	return get_value_string(gsm0808_bssap_names, msg_type);
}

const struct value_string gsm0808_speech_codec_type_names[] = {
	{ GSM0808_SCT_FR1, "FR1" },
	{ GSM0808_SCT_FR2, "FR2" },
	{ GSM0808_SCT_FR3, "FR3" },
	{ GSM0808_SCT_FR4, "FR4" },
	{ GSM0808_SCT_FR5, "FR5" },
	{ GSM0808_SCT_HR1, "HR1" },
	{ GSM0808_SCT_HR3, "HR3" },
	{ GSM0808_SCT_HR4, "HR4" },
	{ GSM0808_SCT_HR6, "HR6" },
	{ GSM0808_SCT_CSD, "CSD" },
	{ 0, NULL }
};

const struct value_string gsm0808_permitted_speech_names[] = {
	{ GSM0808_PERM_FR1, "FR1" },
	{ GSM0808_PERM_FR2, "FR2" },
	{ GSM0808_PERM_FR3, "FR3" },
	{ GSM0808_PERM_FR4, "FR4" },
	{ GSM0808_PERM_FR5, "FR5" },
	{ GSM0808_PERM_HR1, "HR1" },
	{ GSM0808_PERM_HR2, "HR2" },
	{ GSM0808_PERM_HR3, "HR3" },
	{ GSM0808_PERM_HR4, "HR4" },
	{ GSM0808_PERM_HR6, "HR6" },
	{ 0, NULL }
};

const struct value_string gsm0808_chosen_enc_alg_names[] = {
	{ GSM0808_ALG_ID_A5_0, "A5/0" },
	{ GSM0808_ALG_ID_A5_1, "A5/1" },
	{ GSM0808_ALG_ID_A5_2, "A5/2" },
	{ GSM0808_ALG_ID_A5_3, "A5/3" },
	{ GSM0808_ALG_ID_A5_4, "A5/4" },
	{ GSM0808_ALG_ID_A5_5, "A5/5" },
	{ GSM0808_ALG_ID_A5_6, "A5/6" },
	{ GSM0808_ALG_ID_A5_7, "A5/7" },
	{ 0, NULL }
};

static const struct value_string gsm0808_cause_names[] = {
	{ GSM0808_CAUSE_RADIO_INTERFACE_MESSAGE_FAILURE, "RADIO INTERFACE MESSAGE FAILURE" },
	{ GSM0808_CAUSE_RADIO_INTERFACE_FAILURE, "RADIO INTERFACE FAILURE" },
	{ GSM0808_CAUSE_UPLINK_QUALITY, "UPLINK QUALITY" },
	{ GSM0808_CAUSE_UPLINK_STRENGTH, "UPLINK STRENGTH" },
	{ GSM0808_CAUSE_DOWNLINK_QUALITY, "DOWNLINK QUALITY" },
	{ GSM0808_CAUSE_DOWNLINK_STRENGTH, "DOWNLINK STRENGTH" },
	{ GSM0808_CAUSE_DISTANCE, "DISTANCE" },
	{ GSM0808_CAUSE_O_AND_M_INTERVENTION, "O AND M INTERVENTION" },
	{ GSM0808_CAUSE_RESPONSE_TO_MSC_INVOCATION, "RESPONSE TO MSC INVOCATION" },
	{ GSM0808_CAUSE_CALL_CONTROL, "CALL CONTROL" },
	{ GSM0808_CAUSE_RADIO_INTERFACE_FAILURE_REVERSION, "RADIO INTERFACE FAILURE REVERSION" },
	{ GSM0808_CAUSE_HANDOVER_SUCCESSFUL, "HANDOVER SUCCESSFUL" },
	{ GSM0808_CAUSE_BETTER_CELL, "BETTER CELL" },
	{ GSM0808_CAUSE_DIRECTED_RETRY, "DIRECTED RETRY" },
	{ GSM0808_CAUSE_JOINED_GROUP_CALL_CHANNEL, "JOINED GROUP CALL CHANNEL" },
	{ GSM0808_CAUSE_TRAFFIC, "TRAFFIC" },
	{ GSM0808_CAUSE_REDUCE_LOAD_IN_SERVING_CELL, "REDUCE LOAD IN SERVING CELL" },
	{ GSM0808_CAUSE_TRAFFIC_LOAD_IN_TGT_HIGHER_THAN_IN_SRC_CELL, "TRAFFIC LOAD IN TGT HIGHER THAN IN SRC CELL" },
	{ GSM0808_CAUSE_RELOCATION_TRIGGERED, "RELOCATION TRIGGERED" },
	{ GSM0808_CAUSE_REQUESTED_OPT_NOT_AUTHORISED, "REQUESTED OPT NOT AUTHORISED" },
	{ GSM0808_CAUSE_ALT_CHAN_CONFIG_REQUESTED, "ALT CHAN CONFIG REQUESTED" },
	{ GSM0808_CAUSE_RESP_TO_INT_HO_ENQ_MSG, "RESP TO INT HO ENQ MSG" },
	{ GSM0808_CAUSE_INT_HO_ENQUIRY_REJECT, "INT HO ENQUIRY REJECT" },
	{ GSM0808_CAUSE_REDUNDANCY_LEVEL_NOT_ADEQUATE, "REDUNDANCY LEVEL NOT ADEQUATE" },
	{ GSM0808_CAUSE_EQUIPMENT_FAILURE, "EQUIPMENT FAILURE" },
	{ GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE, "NO RADIO RESOURCE AVAILABLE" },
	{ GSM0808_CAUSE_RQSTED_TERRESTRIAL_RESOURCE_UNAVAILABLE, "RQSTED TERRESTRIAL RESOURCE UNAVAILABLE" },
	{ GSM0808_CAUSE_CCCH_OVERLOAD, "CCCH OVERLOAD" },
	{ GSM0808_CAUSE_PROCESSOR_OVERLOAD, "PROCESSOR OVERLOAD" },
	{ GSM0808_CAUSE_BSS_NOT_EQUIPPED, "BSS NOT EQUIPPED" },
	{ GSM0808_CAUSE_MS_NOT_EQUIPPED, "MS NOT EQUIPPED" },
	{ GSM0808_CAUSE_INVALID_CELL, "INVALID CELL" },
	{ GSM0808_CAUSE_TRAFFIC_LOAD, "TRAFFIC LOAD" },
	{ GSM0808_CAUSE_PREEMPTION, "PREEMPTION" },
	{ GSM0808_CAUSE_DTM_HO_SGSN_FAILURE, "DTM HO SGSN FAILURE" },
	{ GSM0808_CAUSE_DTM_HO_PS_ALLOC_FAILURE, "DTM HO PS ALLOC FAILURE" },
	{ GSM0808_CAUSE_RQSTED_TRANSCODING_RATE_ADAPTION_UNAVAILABLE, "RQSTED TRANSCODING RATE ADAPTION UNAVAILABLE" },
	{ GSM0808_CAUSE_CIRCUIT_POOL_MISMATCH, "CIRCUIT POOL MISMATCH" },
	{ GSM0808_CAUSE_SWITCH_CIRCUIT_POOL, "SWITCH CIRCUIT POOL" },
	{ GSM0808_CAUSE_RQSTED_SPEECH_VERSION_UNAVAILABLE, "RQSTED SPEECH VERSION UNAVAILABLE" },
	{ GSM0808_CAUSE_LSA_NOT_ALLOWED, "LSA NOT ALLOWED" },
	{ GSM0808_CAUSE_REQ_CODEC_TYPE_OR_CONFIG_UNAVAIL, "REQ CODEC TYPE OR CONFIG UNAVAIL" },
	{ GSM0808_CAUSE_REQ_A_IF_TYPE_UNAVAIL, "REQ A IF TYPE UNAVAIL" },
	{ GSM0808_CAUSE_INVALID_CSG_CELL, "INVALID CSG CELL" },
	{ GSM0808_CAUSE_REQ_REDUND_LEVEL_NOT_AVAIL, "REQ REDUND LEVEL NOT AVAIL" },
	{ GSM0808_CAUSE_CIPHERING_ALGORITHM_NOT_SUPPORTED, "CIPHERING ALGORITHM NOT SUPPORTED" },
	{ GSM0808_CAUSE_GERAN_IU_MODE_FAILURE, "GERAN IU MODE FAILURE" },
	{ GSM0808_CAUSE_INC_RELOC_NOT_SUPP_DT_PUESBINE_FEATURE, "INC RELOC NOT SUPP DT PUESBINE FEATURE" },
	{ GSM0808_CAUSE_ACCESS_RESTRICTED_DUE_TO_SHARED_NETWORKS, "ACCESS RESTRICTED DUE TO SHARED NETWORKS" },
	{ GSM0808_CAUSE_REQ_CODEC_TYPE_OR_CONFIG_NOT_SUPP, "REQ CODEC TYPE OR CONFIG NOT SUPP" },
	{ GSM0808_CAUSE_REQ_A_IF_TYPE_NOT_SUPP, "REQ A IF TYPE NOT SUPP" },
	{ GSM0808_CAUSE_REQ_REDUND_LVL_NOT_SUPP, "REQ REDUND LVL NOT SUPP" },
	{ GSM0808_CAUSE_TERRESTRIAL_CIRCUIT_ALREADY_ALLOCATED, "TERRESTRIAL CIRCUIT ALREADY ALLOCATED" },
	{ GSM0808_CAUSE_INVALID_MESSAGE_CONTENTS, "INVALID MESSAGE CONTENTS" },
	{ GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING, "INFORMATION ELEMENT OR FIELD MISSING" },
	{ GSM0808_CAUSE_INCORRECT_VALUE, "INCORRECT VALUE" },
	{ GSM0808_CAUSE_UNKNOWN_MESSAGE_TYPE, "UNKNOWN MESSAGE TYPE" },
	{ GSM0808_CAUSE_UNKNOWN_INFORMATION_ELEMENT, "UNKNOWN INFORMATION ELEMENT" },
	{ GSM0808_CAUSE_DTM_HO_INVALID_PS_IND, "DTM HO INVALID PS IND" },
	{ GSM0808_CAUSE_CALL_ID_ALREADY_ALLOC, "CALL ID ALREADY ALLOC" },
	{ GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC, "PROTOCOL ERROR BETWEEN BSS AND MSC" },
	{ GSM0808_CAUSE_VGCS_VBS_CALL_NON_EXISTENT, "VGCS VBS CALL NON EXISTENT" },
	{ GSM0808_CAUSE_DTM_HO_TIMER_EXPIRY, "DTM HO TIMER EXPIRY" },
	{ 0, NULL }
};

static const struct value_string gsm0808_cause_class_names[] = {
	{ GSM0808_CAUSE_CLASS_NORM0,		"Normal event" },
	{ GSM0808_CAUSE_CLASS_NORM1,		"Normal event" },
	{ GSM0808_CAUSE_CLASS_RES_UNAVAIL,	"Resource unavailable" },
	{ GSM0808_CAUSE_CLASS_SRV_OPT_NA,	"Service or option not available" },
	{ GSM0808_CAUSE_CLASS_SRV_OPT_NIMPL,	"Service or option not implemented" },
	{ GSM0808_CAUSE_CLASS_INVAL,		"Invalid message" },
	{ GSM0808_CAUSE_CLASS_PERR,		"Protocol error" },
	{ GSM0808_CAUSE_CLASS_INTW,		"Interworking" },
	{ 0, NULL }
};

/*! Return string name of BSSMAP Cause Class name */
const char *gsm0808_cause_class_name(enum gsm0808_cause_class class)
{
	return get_value_string(gsm0808_cause_class_names, class);
}

/*! Return string name of BSSMAP Cause name */
const char *gsm0808_cause_name(enum gsm0808_cause cause)
{
	return get_value_string(gsm0808_cause_names, cause);
}

const struct value_string gsm0808_lcls_config_names[] = {
	{ GSM0808_LCLS_CFG_BOTH_WAY, "Connect both-way" },
	{ GSM0808_LCLS_CFG_BOTH_WAY_AND_BICAST_UL,
	  "Connect both-way, bi-cast UL to CN" },
	{ GSM0808_LCLS_CFG_BOTH_WAY_AND_SEND_DL,
	  "Connect both-way, send access DL from CN" },
	{ GSM0808_LCLS_CFG_BOTH_WAY_AND_SEND_DL_BLOCK_LOCAL_DL,
	  "Connect both-way, send access DL from CN, block local DL" },
	{ GSM0808_LCLS_CFG_BOTH_WAY_AND_BICAST_UL_SEND_DL,
	  "Connect both-way, bi-cast UL to CN, send access DL from CN" },
	{ GSM0808_LCLS_CFG_BOTH_WAY_AND_BICAST_UL_SEND_DL_BLOCK_LOCAL_DL,
	  "Connect both-way, bi-cast UL to CN, send access DL from CN, block local DL" },
	{ GSM0808_LCLS_CFG_NA, "Not available" },
	{ 0, NULL }
};

const struct value_string gsm0808_lcls_control_names[] = {
	{ GSM0808_LCLS_CSC_CONNECT,				"Connect" },
	{ GSM0808_LCLS_CSC_DO_NOT_CONNECT,			"Do not connect" },
	{ GSM0808_LCLS_CSC_RELEASE_LCLS,			"Release LCLS" },
	{ GSM0808_LCLS_CSC_BICAST_UL_AT_HANDOVER,		"Bi-cast UL at Handover" },
	{ GSM0808_LCLS_CSC_BICAST_UL_AND_RECV_DL_AT_HANDOVER,	"Bi-cast UL and receive DL at Handover" },
	{ GSM0808_LCLS_CSC_NA,					"Not available" },
	{ 0, NULL }
};

const struct value_string gsm0808_lcls_status_names[] = {
	{ GSM0808_LCLS_STS_NOT_YET_LS,		"Call not yet locally switched" },
	{ GSM0808_LCLS_STS_NOT_POSSIBLE_LS,	"Call not possible to be locally switched" },
	{ GSM0808_LCLS_STS_NO_LONGER_LS,	"Call is no longer locally switched" },
	{ GSM0808_LCLS_STS_REQ_LCLS_NOT_SUPP,	"Requested LCLS configuration is not supported" },
	{ GSM0808_LCLS_STS_LOCALLY_SWITCHED,	"Call is locally switched with requested LCLS config" },
	{ GSM0808_LCLS_STS_NA,			"Not available" },
	{ 0, NULL }
};

/*! @} */
