/*! \defgroup gsm0808 GSM 08.08 / 3GPP TS 48.008 A Interface
 *  @{
 *  \file gsm0808.h */
/*
 * (C) 2009,2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009,2010 by On-Waves
 * All Rights Reserved
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
#pragma once

#include "tlv.h"
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/core/utils.h>

#define BSSMAP_MSG_SIZE 512
#define BSSMAP_MSG_HEADROOM 128

struct sockaddr_storage;

struct msgb;
struct gsm0808_cell_id_list2;

struct msgb *gsm0808_create_layer3(struct msgb *msg_l3, uint16_t nc,
				   uint16_t cc, int lac, uint16_t _ci)
	OSMO_DEPRECATED("Use gsm0808_create_layer3_2() instead, to not lose leading zeros in the MNC");
struct msgb *gsm0808_create_layer3_aoip(const struct msgb *msg_l3, uint16_t nc,
					uint16_t cc, int lac, uint16_t _ci,
					const struct gsm0808_speech_codec_list *scl)
	OSMO_DEPRECATED("Use gsm0808_create_layer3_2() instead, to not lose leading zeros in the MNC");
struct msgb *gsm0808_create_layer3_2(const struct msgb *msg_l3, const struct osmo_cell_global_id *cell,
				     const struct gsm0808_speech_codec_list *scl);
struct msgb *gsm0808_create_reset(void);
struct msgb *gsm0808_create_reset_ack(void);
struct msgb *gsm0808_create_clear_command(uint8_t cause);
struct msgb *gsm0808_create_clear_complete(void);
struct msgb *gsm0808_create_cipher(const struct gsm0808_encrypt_info *ei,
				   const uint8_t *cipher_response_mode);
struct msgb *gsm0808_create_cipher_complete(struct msgb *layer3, uint8_t alg_id);
struct msgb *gsm0808_create_cipher_reject(enum gsm0808_cause cause);
struct msgb *gsm0808_create_cipher_reject_ext(enum gsm0808_cause_class class, uint8_t ext);
struct msgb *gsm0808_create_classmark_request();
struct msgb *gsm0808_create_classmark_update(const uint8_t *cm2, uint8_t cm2_len,
					     const uint8_t *cm3, uint8_t cm3_len);
struct msgb *gsm0808_create_sapi_reject(uint8_t link_id);
struct msgb *gsm0808_create_ass(const struct gsm0808_channel_type *ct,
				const uint16_t *cic,
				const struct sockaddr_storage *ss,
				const struct gsm0808_speech_codec_list *scl,
				const uint32_t *ci);
struct msgb *gsm0808_create_ass2(const struct gsm0808_channel_type *ct,
				 const uint16_t *cic,
				 const struct sockaddr_storage *ss,
				 const struct gsm0808_speech_codec_list *scl,
				 const uint32_t *ci,
				 const uint8_t *kc, const struct osmo_lcls *lcls);
struct msgb *gsm0808_create_ass_compl(uint8_t rr_cause, uint8_t chosen_channel,
				      uint8_t encr_alg_id, uint8_t speech_mode,
				      const struct sockaddr_storage *ss,
				      const struct gsm0808_speech_codec *sc,
				      const struct gsm0808_speech_codec_list
				      *scl);
struct msgb *gsm0808_create_assignment_completed(uint8_t rr_cause,
						 uint8_t chosen_channel,
						 uint8_t encr_alg_id,
						 uint8_t speech_mode);
struct msgb *gsm0808_create_ass_fail(uint8_t cause, const uint8_t *rr_cause,
				     const struct gsm0808_speech_codec_list
				     *scl);
struct msgb *gsm0808_create_assignment_failure(uint8_t cause, uint8_t *rr_cause);
struct msgb *gsm0808_create_clear_rqst(uint8_t cause);
struct msgb *gsm0808_create_paging2(const char *imsi, const uint32_t *tmsi,
				   const struct gsm0808_cell_id_list2 *cil,
				   const uint8_t *chan_needed);
struct msgb *gsm0808_create_paging(const char *imsi, const uint32_t *tmsi,
				   const struct gsm0808_cell_id_list *cil,
				   const uint8_t *chan_needed)
				   OSMO_DEPRECATED("use gsm0808_create_paging2 instead");
struct msgb *gsm0808_create_lcls_conn_ctrl(enum gsm0808_lcls_config *config,
					   enum gsm0808_lcls_control *control);
struct msgb *gsm0808_create_lcls_conn_ctrl_ack(enum gsm0808_lcls_status status);
struct msgb *gsm0808_create_lcls_notification(enum gsm0808_lcls_status status, bool break_req);


/*! 3GPP TS 48.008 §3.2.2.5.8 Old BSS to New BSS information */
struct gsm0808_old_bss_to_new_bss_info {
	bool extra_information_present;
	struct {
		bool prec;
		bool lcs;
		bool ue_prob;
	} extra_information;

	bool current_channel_type_2_present;
	struct {
		uint8_t mode;
		uint8_t field;
	} current_channel_type_2;

	/* more items are defined in the spec and may be added later */
	bool more_items; /*< always set this to false */
};

/*! 3GPP TS 48.008 §3.2.1.9 HANDOVER REQUIRED */
struct gsm0808_handover_required {
	uint16_t cause;
	struct gsm0808_cell_id_list2 cil;

	bool current_channel_type_1_present;
	uint8_t current_channel_type_1;

	bool speech_version_used_present;
	uint8_t speech_version_used;

	bool old_bss_to_new_bss_info_present;
	struct gsm0808_old_bss_to_new_bss_info old_bss_to_new_bss_info;

	/* more items are defined in the spec and may be added later */
	bool more_items; /*< always set this to false */
};
struct msgb *gsm0808_create_handover_required(const struct gsm0808_handover_required *params);

struct msgb *gsm0808_create_handover_request_ack(const uint8_t *l3_info, uint8_t l3_info_len,
						 uint8_t chosen_channel, uint8_t chosen_encr_alg,
						 uint8_t chosen_speech_version);

struct msgb *gsm0808_create_handover_detect();

struct gsm0808_handover_complete {
	bool rr_cause_present;
	uint8_t rr_cause;

	bool speech_codec_chosen_present;
	struct gsm0808_speech_codec speech_codec_chosen;

	struct gsm0808_speech_codec_list codec_list_bss_supported; /*< omit when .len == 0 */

	bool chosen_encr_alg_present;
	uint8_t chosen_encr_alg;
	
	bool chosen_channel_present;
	uint8_t chosen_channel;

	bool lcls_bss_status_present;
	enum gsm0808_lcls_status lcls_bss_status;

	/* more items are defined in the spec and may be added later */
	bool more_items; /*< always set this to false */
};
struct msgb *gsm0808_create_handover_complete(const struct gsm0808_handover_complete *params);

struct gsm0808_handover_failure {
	uint16_t cause;

	bool rr_cause_present;
	uint8_t rr_cause;

	struct gsm0808_speech_codec_list codec_list_bss_supported; /*< omit when .len == 0 */

	/* more items are defined in the spec and may be added later */
	bool more_items; /*< always set this to false */
};
struct msgb *gsm0808_create_handover_failure(const struct gsm0808_handover_failure *params);

struct gsm0808_handover_performed {
	uint16_t cause;
	struct gsm0808_cell_id cell_id;

	bool chosen_channel_present;
	uint8_t chosen_channel;

	bool chosen_encr_alg_present;
	uint8_t chosen_encr_alg;

	bool speech_version_chosen_present;
	uint8_t speech_version_chosen;

	bool speech_codec_chosen_present;
	struct gsm0808_speech_codec speech_codec_chosen;

	bool lcls_bss_status_present;
	enum gsm0808_lcls_status lcls_bss_status;

	/* more items are defined in the spec and may be added later */
	bool more_items; /*< always set this to false */
};
struct msgb *gsm0808_create_handover_performed(const struct gsm0808_handover_performed *params);

struct msgb *gsm0808_create_dtap(struct msgb *msg, uint8_t link_id);
void gsm0808_prepend_dtap_header(struct msgb *msg, uint8_t link_id);

const struct tlv_definition *gsm0808_att_tlvdef(void);

/*! Parse BSSAP TLV structure using \ref tlv_parse */
#define osmo_bssap_tlv_parse(dec, buf, len) tlv_parse(dec, gsm0808_att_tlvdef(), buf, len, 0, 0)

const char *gsm0808_bssmap_name(uint8_t msg_type);
const char *gsm0808_bssap_name(uint8_t msg_type);
const char *gsm0808_cause_name(enum gsm0808_cause cause);
const char *gsm0808_cause_class_name(enum gsm0808_cause_class class);

extern const struct value_string gsm0808_lcls_config_names[];
extern const struct value_string gsm0808_lcls_control_names[];
extern const struct value_string gsm0808_lcls_status_names[];

static inline const char *gsm0808_lcls_config_name(uint8_t val) {
	return get_value_string(gsm0808_lcls_config_names, val);
}
static inline const char *gsm0808_lcls_control_name(uint8_t val) {
	return get_value_string(gsm0808_lcls_control_names, val);
}
static inline const char *gsm0808_lcls_status_name(uint8_t val) {
	return get_value_string(gsm0808_lcls_status_names, val);
}

/*! @} */
