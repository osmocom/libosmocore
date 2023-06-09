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
 */
#pragma once

#include "tlv.h"
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/core/utils.h>

#include <osmocom/core/socket_compat.h>

#define BSSMAP_MSG_SIZE 1024
#define BSSMAP_MSG_HEADROOM 512

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
struct msgb *gsm0808_create_clear_command2(uint8_t cause, bool csfb_ind);
struct msgb *gsm0808_create_clear_complete(void);
struct msgb *gsm0808_create_cipher(const struct gsm0808_encrypt_info *ei,
				   const uint8_t *cipher_response_mode);

struct gsm0808_cipher_mode_command {
	struct gsm0808_encrypt_info ei;

	/*! 3GPP TS 48.008 3.2.2.34 Cipher Response Mode, optional IE */
	bool cipher_response_mode_present;
	/*! 3GPP TS 48.008 3.2.2.34 Cipher Response Mode:
	 * 0 - IMEISV must not be included by the Mobile Station;
	 * 1 - IMEISV must be included by the Mobile Station.
	 */
	uint8_t cipher_response_mode;

	bool kc128_present;
	uint8_t kc128[16];

	/* more items are defined in the spec and may be added later */
	bool more_items; /*< always set this to false */
};
struct msgb *gsm0808_create_cipher2(const struct gsm0808_cipher_mode_command *cmc);

struct msgb *gsm0808_create_cipher_complete(struct msgb *layer3, uint8_t alg_id);
struct msgb *gsm0808_create_cipher_reject(enum gsm0808_cause cause);
struct msgb *gsm0808_create_cipher_reject_ext(enum gsm0808_cause_class class, uint8_t ext);
struct msgb *gsm0808_create_classmark_request(void);
struct msgb *gsm0808_create_classmark_update(const uint8_t *cm2, uint8_t cm2_len,
					     const uint8_t *cm3, uint8_t cm3_len);
struct msgb *gsm0808_create_sapi_reject_cause(uint8_t link_id, uint16_t cause);
struct msgb *gsm0808_create_sapi_reject(uint8_t link_id)
	OSMO_DEPRECATED("Use gsm0808_create_sapi_reject_cause() instead");
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
struct msgb *gsm0808_create_ass_compl2(uint8_t rr_cause, uint8_t chosen_channel,
				       uint8_t encr_alg_id, uint8_t speech_mode,
				       const struct sockaddr_storage *ss,
				       const struct gsm0808_speech_codec *sc,
				       const struct gsm0808_speech_codec_list *scl,
				       enum gsm0808_lcls_status lcls_bss_status);
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
struct msgb *gsm0808_create_lcls_conn_ctrl(enum gsm0808_lcls_config config,
					   enum gsm0808_lcls_control control);
struct msgb *gsm0808_create_lcls_conn_ctrl_ack(enum gsm0808_lcls_status status);
struct msgb *gsm0808_create_lcls_notification(enum gsm0808_lcls_status status, bool break_req);
struct msgb *gsm0808_create_common_id(const char *imsi,
				      const struct osmo_plmn_id *selected_plmn_id,
				      const struct osmo_plmn_id *last_used_eutran_plnm_id);


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

	bool last_eutran_plmn_id_present;
	struct osmo_plmn_id last_eutran_plmn_id;

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
	enum gsm0808_permitted_speech speech_version_used;

	bool old_bss_to_new_bss_info_present;
	struct gsm0808_old_bss_to_new_bss_info old_bss_to_new_bss_info;

	/* more items are defined in the spec and may be added later */
	bool more_items; /*< always set this to false */
};
struct msgb *gsm0808_create_handover_required(const struct gsm0808_handover_required *params);

/*! 3GPP TS 48.008 §3.2.1.37 HANDOVER REQUIRED REJECT */
struct gsm0808_handover_required_reject {
	uint16_t cause;

	/* more items are defined in the spec and may be added later */
	bool more_items; /*< always set this to false */
};
struct msgb *gsm0808_create_handover_required_reject(const struct gsm0808_handover_required_reject *params);

/*! 3GPP TS 48.008 §3.2.1.8 HANDOVER REQUEST */
struct gsm0808_handover_request {
	struct gsm0808_channel_type channel_type;
	struct gsm0808_encrypt_info encryption_information;
	struct osmo_gsm48_classmark classmark_information;
	struct gsm0808_cell_id cell_identifier_serving;
	struct gsm0808_cell_id cell_identifier_target;
	enum gsm0808_cause cause;

	bool current_channel_type_1_present;
	uint8_t current_channel_type_1;

	enum gsm0808_permitted_speech speech_version_used;

	uint8_t chosen_encryption_algorithm_serving;

	/*! Pass either old_bss_to_new_bss_info or old_bss_to_new_bss_info_raw. */
	bool old_bss_to_new_bss_info_present;
	struct gsm0808_old_bss_to_new_bss_info old_bss_to_new_bss_info;
	/*! To feed the Old BSS to New BSS Information IE unchanged from the Handover Required message without having to
	 * decode it. Pass either old_bss_to_new_bss_info or old_bss_to_new_bss_info_raw. Omit the TL part. */
	const uint8_t *old_bss_to_new_bss_info_raw;
	uint8_t old_bss_to_new_bss_info_raw_len;

	const char *imsi;

	const struct sockaddr_storage *aoip_transport_layer;

	const struct gsm0808_speech_codec_list *codec_list_msc_preferred;

	bool call_id_present;
	uint32_t call_id;

	const uint8_t *global_call_reference;
	uint8_t global_call_reference_len;

	/* more items are defined in the spec and may be added later */
	bool more_items; /*!< set this to true iff any fields below are used */

	bool kc128_present;
	uint8_t kc128[16];

	bool more_items2; /*!< always set this to false */
};
struct msgb *gsm0808_create_handover_request(const struct gsm0808_handover_request *params);

struct msgb *gsm0808_create_handover_request_ack(const uint8_t *l3_info, uint8_t l3_info_len,
						 uint8_t chosen_channel, uint8_t chosen_encr_alg,
						 uint8_t chosen_speech_version);

struct gsm0808_handover_request_ack {
	const uint8_t *l3_info;
	uint8_t l3_info_len;

	bool chosen_channel_present;
	uint8_t chosen_channel;

	/*! For A5/N set chosen_encr_alg = N+1, e.g. chosen_encr_alg = 1 means A5/0 (no encryption), 2 means A5/1, 4
	 * means A5/3. Set chosen_encr_alg = 0 to omit the Chosen Encryption Algorithm IE. */
	uint8_t chosen_encr_alg;

	/* chosen_speech_version == 0 omits the IE */
	enum gsm0808_permitted_speech chosen_speech_version;

	bool speech_codec_chosen_present;
	struct gsm0808_speech_codec speech_codec_chosen;

	const struct sockaddr_storage *aoip_transport_layer;

	bool more_items; /*!< set this to true iff any fields below are used */

	struct gsm0808_speech_codec_list codec_list_bss_supported; /*< omit when .len == 0 */

	/* more items are defined in the spec and may be added later */
	bool more_items2; /*!< always set this to false */
};
struct msgb *gsm0808_create_handover_request_ack2(const struct gsm0808_handover_request_ack *params);

struct gsm0808_handover_command {
	const uint8_t *l3_info;
	uint8_t l3_info_len;

	struct gsm0808_cell_id cell_identifier;

	const uint8_t *new_bss_to_old_bss_info_raw;
	size_t new_bss_to_old_bss_info_raw_len;

	/* more items are defined in the spec and may be added later */
	bool more_items; /*!< always set this to false */
};
struct msgb *gsm0808_create_handover_command(const struct gsm0808_handover_command *params);

struct msgb *gsm0808_create_handover_detect(void);
struct msgb *gsm0808_create_handover_succeeded(void);

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
	enum gsm0808_permitted_speech speech_version_chosen;

	bool speech_codec_chosen_present;
	struct gsm0808_speech_codec speech_codec_chosen;

	bool lcls_bss_status_present;
	enum gsm0808_lcls_status lcls_bss_status;

	/* more items are defined in the spec and may be added later */
	bool more_items; /*< always set this to false */
};
struct msgb *gsm0808_create_handover_performed(const struct gsm0808_handover_performed *params);

/*! 3GPP TS 48.008 §3.2.1.50 VGCS/VBS SETUP */
struct gsm0808_vgcs_vbs_setup {
	struct gsm0808_group_callref callref;

	bool priority_present;
	struct gsm0808_priority priority;

	bool vgcs_feature_flags_present;
	struct gsm0808_vgcs_feature_flags flags;
};
struct msgb *gsm0808_create_vgcs_vbs_setup(const struct gsm0808_vgcs_vbs_setup *params);

/*! 3GPP TS 48.008 §3.2.1.51 VGCS/VBS SETUP ACK */
struct gsm0808_vgcs_vbs_setup_ack {
	bool vgcs_feature_flags_present;
	struct gsm0808_vgcs_feature_flags flags;
};
struct msgb *gsm0808_create_vgcs_vbs_setup_ack(const struct gsm0808_vgcs_vbs_setup_ack *params);

/*! 3GPP TS 48.008 §3.2.1.52 VGCS/VBS SETUP REFUSE */
struct msgb *gsm0808_create_vgcs_vbs_setup_refuse(enum gsm0808_cause cause);

/*! 3GPP TS 48.008 §3.2.1.53 VGCS/VBS ASSIGNMENT REQUEST */
struct gsm0808_vgcs_vbs_assign_req {
	struct gsm0808_channel_type channel_type;
	enum gsm0808_assignment_requirement ass_req;
	struct gsm0808_cell_id cell_identifier;
	struct gsm0808_group_callref callref;

	bool priority_present;
	struct gsm0808_priority priority;

	bool cic_present;
	uint16_t cic;

	bool downlink_dtx_flag_present;
	enum gsm0808_downlink_dtx_flag downlink_dtx_flag;

	bool encryption_information_present;
	struct gsm0808_encrypt_info encryption_information;

	bool vstk_rand_present;
	uint8_t vstk_rand[5];

	bool vstk_present;
	uint8_t vstk[16];

	bool cils_present;
	struct gsm0808_cell_id_list_segment cils;

	bool aoip_transport_layer_present;
	struct sockaddr_storage aoip_transport_layer;

	bool call_id_present;
	uint32_t call_id;

	bool codec_list_present;
	struct gsm0808_speech_codec_list codec_list_msc_preferred;
};
struct msgb *gsm0808_create_vgcs_vbs_assign_req(const struct gsm0808_vgcs_vbs_assign_req *params);

/*! 3GPP TS 48.008 §3.2.1.54 VGCS/VBS ASSIGNMENT RESULT */
struct gsm0808_vgcs_vbs_assign_res {
	struct gsm0808_channel_type channel_type;
	struct gsm0808_cell_id cell_identifier;

	bool chosen_channel_present;
	uint8_t chosen_channel;

	bool cic_present;
	uint16_t cic;

	bool circuit_pool_present;
	uint8_t circuit_pool;

	bool aoip_transport_layer_present;
	struct sockaddr_storage aoip_transport_layer;

	bool codec_present;
	struct gsm0808_speech_codec codec_msc_chosen;

	bool call_id_present;
	uint32_t call_id;
};
struct msgb *gsm0808_create_vgcs_vbs_assign_res(const struct gsm0808_vgcs_vbs_assign_res *params);

/*! 3GPP TS 48.008 §3.2.1.55 VGCS/VBS ASSIGNMENT FAILURE */
struct gsm0808_vgcs_vbs_assign_fail {
	enum gsm0808_cause cause;

	bool circuit_pool_present;
	uint8_t circuit_pool;

	bool cpl_present;
	struct gsm0808_circuit_pool_list cpl;

	bool codec_list_present;
	struct gsm0808_speech_codec_list codec_list_bss_supported;
};
struct msgb *gsm0808_create_vgcs_vbs_assign_fail(const struct gsm0808_vgcs_vbs_assign_fail *params);

/*! 3GPP TS 48.008 §3.2.1.57 (VGCS) UPLINK REQUEST */
struct gsm0808_uplink_request {
	bool talker_priority_present;
	enum gsm0808_talker_priority talker_priority;

	bool cell_identifier_present;
	struct gsm0808_cell_id cell_identifier;

	bool l3_present;
	struct gsm0808_layer_3_information l3;

	bool mi_present;
	struct osmo_mobile_identity mi;
};
struct msgb *gsm0808_create_uplink_request(const struct gsm0808_uplink_request *params);

/*! 3GPP TS 48.008 §3.2.1.58 (VGCS) UPLINK REQUEST ACKNOWLEDGE */
struct gsm0808_uplink_request_ack {
	bool talker_priority_present;
	enum gsm0808_talker_priority talker_priority;

	bool emerg_set_ind_present;

	bool talker_identity_present;
	struct gsm0808_talker_identity talker_identity;
};
struct msgb *gsm0808_create_uplink_request_ack(const struct gsm0808_uplink_request_ack *params);

/*! 3GPP TS 48.008 §3.2.1.59 (VGCS) UPLINK REQUEST CONFIRM */
struct gsm0808_uplink_request_cnf {
	struct gsm0808_cell_id cell_identifier;

	bool talker_identity_present;
	struct gsm0808_talker_identity talker_identity;

	/* mandatory! */
	struct gsm0808_layer_3_information l3;
};
struct msgb *gsm0808_create_uplink_request_cnf(const struct gsm0808_uplink_request_cnf *params);

/*! 3GPP TS 48.008 §3.2.1.59a (VGCS) UPLINK APPLICATION DATA */
struct gsm0808_uplink_app_data {
	struct gsm0808_cell_id cell_identifier;
	struct gsm0808_layer_3_information l3;
	bool bt_ind;
};
struct msgb *gsm0808_create_uplink_app_data(const struct gsm0808_uplink_app_data *params);

/*! 3GPP TS 48.008 §3.2.1.60 (VGCS) UPLINK RELEASE INDICATION */
struct gsm0808_uplink_release_ind {
	enum gsm0808_cause cause;

	bool talker_priority_present;
	enum gsm0808_talker_priority talker_priority;
};
struct msgb *gsm0808_create_uplink_release_ind(const struct gsm0808_uplink_release_ind *params);

/*! 3GPP TS 48.008 §3.2.1.61 (VGCS) UPLINK REJECT COMMAND */
struct gsm0808_uplink_reject_cmd {
	enum gsm0808_cause cause;

	bool current_talker_priority_present;
	enum gsm0808_talker_priority current_talker_priority;
	bool rejected_talker_priority_present;
	enum gsm0808_talker_priority rejected_talker_priority;

	bool talker_identity_present;
	struct gsm0808_talker_identity talker_identity;
};
struct msgb *gsm0808_create_uplink_reject_cmd(const struct gsm0808_uplink_reject_cmd *params);

/*! 3GPP TS 48.008 §3.2.1.62 (VGCS) UPLINK RELEASE COMMAND */
struct msgb *gsm0808_create_uplink_release_cmd(const enum gsm0808_cause cause);

/*! 3GPP TS 48.008 §3.2.1.63 (VGCS) UPLINK SEIZED COMMAND */
struct gsm0808_uplink_seized_cmd {
	enum gsm0808_cause cause;

	bool talker_priority_present;
	enum gsm0808_talker_priority talker_priority;

	bool emerg_set_ind_present;

	bool talker_identity_present;
	struct gsm0808_talker_identity talker_identity;
};
struct msgb *gsm0808_create_uplink_seized_cmd(const struct gsm0808_uplink_seized_cmd *params);

/*! 3GPP TS 48.008 §3.2.1.78 VGCS ADDITIONAL INFORMATION */
struct msgb *gsm0808_create_vgcs_additional_info(const struct gsm0808_talker_identity *ti);

/*! 3GPP TS 48.008 §3.2.1.79 VGCS/VBS AREA CELL INFO */
struct gsm0808_vgcs_vbs_area_cell_info {
	struct gsm0808_cell_id_list_segment cils;

	bool ass_req_present;
	enum gsm0808_assignment_requirement ass_req;
};
struct msgb *gsm0808_create_vgcs_vbs_area_cell_info(const struct gsm0808_vgcs_vbs_area_cell_info *params);

/*! 3GPP TS 48.008 §3.2.1.80 VGCS/VBS ASSIGNMENT STATUS */
struct gsm0808_vgcs_vbs_assign_stat {
	/* established cells */
	bool cils_est_present;
	struct gsm0808_cell_id_list_segment cils_est;

	/* cells to be established */
	bool cils_tbe_present;
	struct gsm0808_cell_id_list_segment cils_tbe;

	/* released cells - no user present */
	bool cils_rel_present;
	struct gsm0808_cell_id_list_segment cils_rel;

	/* not established cells - no establishment possible */
	bool cils_ne_present;
	struct gsm0808_cell_id_list_segment cils_ne;

	bool cell_status_present;
	enum gsm0808_vgcs_vbs_cell_status cell_status;
};
struct msgb *gsm0808_create_vgcs_vbs_assign_stat(const struct gsm0808_vgcs_vbs_assign_stat *params);

/*! 3GPP TS 48.008 §3.2.1.81 VGCS SMS */
struct msgb *gsm0808_create_vgcs_sms(const struct gsm0808_sms_to_vgcs *sms);

/*! 3GPP TS 48.008 §3.2.1.82 (VGCS/VBS) NOTIFICATION DATA */
struct gsm0808_notification_data {
	struct gsm0808_application_data app_data;
	struct gsm0808_data_identity data_ident;

	bool msisdn_present;
	char msisdn[MSISDN_MAXLEN + 1];
};
struct msgb *gsm0808_create_notification_data(const struct gsm0808_notification_data *parms);

struct msgb *gsm0808_create_dtap(struct msgb *msg, uint8_t link_id);
void gsm0808_prepend_dtap_header(struct msgb *msg, uint8_t link_id);

const struct tlv_definition *gsm0808_att_tlvdef(void);
extern const struct tlv_definition gsm0808_old_bss_to_new_bss_info_att_tlvdef;

/*! Parse BSSAP TLV structure using \ref tlv_parse */
#define osmo_bssap_tlv_parse(dec, buf, len) tlv_parse(dec, gsm0808_att_tlvdef(), buf, len, 0, 0)
/*! Parse BSSAP TLV structure using \ref tlv_parse2 */
#define osmo_bssap_tlv_parse2(dec, dec_multiples, buf, len) \
	tlv_parse2(dec, dec_multiples, gsm0808_att_tlvdef(), buf, len, 0, 0)

const char *gsm0808_bssmap_name(uint8_t msg_type);
const char *gsm0808_bssap_name(uint8_t msg_type);
const char *gsm0808_cause_name(enum gsm0808_cause cause);
const char *gsm0808_cause_class_name(enum gsm0808_cause_class class);

/*! Parse Cause TLV 3GPP TS 08.08 §3.2.2.5
 * \returns Cause value */
enum gsm0808_cause gsm0808_get_cause(const struct tlv_parsed *tp);

const char *gsm0808_diagnostics_octet_location_str(uint8_t pointer);
const char *gsm0808_diagnostics_bit_location_str(uint8_t bit_pointer);

extern const struct value_string gsm0808_lcls_config_names[];
extern const struct value_string gsm0808_lcls_control_names[];
extern const struct value_string gsm0808_lcls_status_names[];

static inline const char *gsm0808_lcls_config_name(enum gsm0808_lcls_config val) {
	return get_value_string(gsm0808_lcls_config_names, val);
}
static inline const char *gsm0808_lcls_control_name(enum gsm0808_lcls_control val) {
	return get_value_string(gsm0808_lcls_control_names, val);
}
static inline const char *gsm0808_lcls_status_name(enum gsm0808_lcls_status val) {
	return get_value_string(gsm0808_lcls_status_names, val);
}

/*! @} */
