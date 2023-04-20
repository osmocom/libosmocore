/*! \addtogroup gsm0808
 *  @{
 *  \file gsm0808_utils.h */
/*
 * (C) 2016 by sysmocom - s.f.m.c. GmbH, Author: Philipp Maier
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

struct sockaddr_storage;

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm29205.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/core/endian.h>

 /*! (225-1)/2 is the maximum number of elements in a cell identifier list. */
#define GSM0808_CELL_ID_LIST2_MAXLEN		127

/*! Instead of this, use either struct gsm0808_cell_id or gsm0808_cell_id_list2.
 * All elements contain parsed representations of the data in the corresponding IE, in host-byte order.
 */
union gsm0808_cell_id_u {
	struct osmo_cell_global_id		global;
	struct osmo_lac_and_ci_id		lac_and_ci;
	uint16_t				ci;
	struct osmo_location_area_id		lai_and_lac;
	uint16_t				lac;
	struct osmo_service_area_id		sai;
	/* osmocom specific: */
	struct osmo_cell_global_id_ps		global_ps;
};

/*! Parsed representation of Cell Identifier IE (3GPP TS 48.008 3.2.2.17) */
struct gsm0808_cell_id {
	enum CELL_IDENT id_discr;
	union gsm0808_cell_id_u id;
};

/*! Parsed representation of a Cell Identifier List IE (3GPP TS 48.008 3.2.2.27). */
struct gsm0808_cell_id_list2 {
	enum CELL_IDENT id_discr;
	union gsm0808_cell_id_u id_list[GSM0808_CELL_ID_LIST2_MAXLEN];
	unsigned int id_list_len;
};

/*! Packed representation of a Priority IE (GGPP TS 48.008 3.2.2.18) */
struct gsm0808_priority {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t pvi:1,			/* Preemption Vulnerability indicator */
		qa:1,			/* Queuing allowed indicator */
		priority_level:4,	/* Priority level: 1 == hightest, 14 == lowest */
		pci:1,			/* Preemption Capability indicator */
		spare:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t spare:1, pci:1, priority_level:4, qa:1, pvi:1;
#endif
} __attribute__ ((packed));

/*! Packed representation of a VGCS Feature Flags IE (3GPP TS 48.008 3.2.2.88) */
struct gsm0808_vgcs_feature_flags {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t tp_ind:1,		/* Talker priority supported */
		as_ind_circuit:1,	/* A-interface circuit sharing supported */
		as_ind_link:1,		/* A-interface link sharing supported */
		bss_res:1,		/* BSS supports re-establishment */
		tcp:1,			/* Talker channel parameter supported */
		spare:3;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t spare:3, tcp:1, bss_res:1, as_ind_link:1, as_ind_circuit:1, tp_ind:1;
#endif
} __attribute__ ((packed));

/* TS 48.008 3.2.2.52 */
enum gsm0808_assignment_requirement {
	GSM0808_ASRQ_DELAY_ALLOWED		= 0x00,
	GSM0808_ASRQ_IMMEDIATE			= 0x01,
	GSM0808_ASRQ_IMMEDIATE_ON_DEMAND	= 0x02,
};

/* TS 48.008 Table 10.5.8 */
enum gsm0808_service_flag {
	GSM0808_SF_VBS				= 0,
	GSM0808_SF_VGCS				= 1,
};

enum gsm0808_call_priority {
	GSM0808_CALL_PRIORITY_NONE		= 0x00,
	GSM0808_CALL_PRIORITY_LEVEL_4		= 0x01,
	GSM0808_CALL_PRIORITY_LEVEL_3		= 0x02,
	GSM0808_CALL_PRIORITY_LEVEL_2		= 0x03,
	GSM0808_CALL_PRIORITY_LEVEL_1		= 0x04,
	GSM0808_CALL_PRIORITY_LEVEL_0		= 0x05,
	GSM0808_CALL_PRIORITY_LEVEL_B		= 0x06,
	GSM0808_CALL_PRIORITY_LEVEL_A		= 0x07,
};

/*! Packed representation of a Group Call Reference IE (3GPP TS 48.008 3.2.2.55) */
struct gsm0808_group_callref {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t call_ref_hi[3];
	uint8_t call_priority:3,
		af:1,			/* Acknowledgement flag */
		sf:1,			/* Service flag */
		call_ref_lo:3;
	uint8_t spare:4,
		ciphering_info:4;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t call_ref_hi[3];
	uint8_t call_ref_lo:3, sf:1, af:1, call_priority:3;
	uint8_t ciphering_info:4, spare:4;
#endif
} __attribute__ ((packed));

/* TS 48.008 3.2.2.26 */
enum gsm0808_downlink_dtx_flag {
	GSM0808_DTX_FLAG_ALLOW			= 0,
	GSM0808_DTX_FLAG_FORBID			= 1,
};

/*! Parsed representation of a Cell Identifier List Segment IE (3GPP TS 48.008 3.2.2.27a) */
struct gsm0808_cell_id_list_segment {
	uint8_t seq_last;
	uint8_t seq_number;
	struct gsm0808_cell_id_list2 cil;
};

/*! Parsed representation of a Circuit Pool List IE (3GPP TS 48.008 3.2.2.26) */
#define CIRCUIT_POOL_LIST_MAXLEN 252
struct gsm0808_circuit_pool_list {
	uint8_t pool[CIRCUIT_POOL_LIST_MAXLEN];
	unsigned int list_len;
};

/* 3GPP TS 48.008 Table  3.2.2.90.1 Talker Priority */
enum gsm0808_talker_priority {
	GSM0808_TALKER_PRIORITY_NORMAL		= 0x00,
	GSM0808_TALKER_PRIORITY_PRIVILEGED	= 0x01,
	GSM0808_TALKER_PRIORITY_EMERGENCY	= 0x02,
};

/*! Parsed representation of a Layer 3 Information IE (3GPP TS 48.008 3.2.2.24) */
#define LAYER_3_INFORMATION_MAXLEN 252
struct gsm0808_layer_3_information {
	uint8_t l3[LAYER_3_INFORMATION_MAXLEN];
	unsigned int l3_len;
};

/*! Parsed representation of a Talker Identity IE (3GPP TS 48.008 3.2.2.91) */
#define TALKER_IDENTITY_MAXLEN 17
struct gsm0808_talker_identity {
	uint8_t talker_id[TALKER_IDENTITY_MAXLEN];
	unsigned int id_bits;
};

/* 3GPP TS 48.008 3.2.2.94 VGCS/VBS Cell Status */
enum gsm0808_vgcs_vbs_cell_status {
	GSM0808_CSTAT_ESTABLISHED		= 0x00,
	GSM0808_CSTAT_NOT_ESTABLISHED1		= 0x01,
	GSM0808_CSTAT_RELEASED_NO_USER		= 0x02,
	GSM0808_CSTAT_NOT_ESTABLISHED2		= 0x03,
};

/*! Parsed representation of a SMS to VGCS IE (3GPP TS 48.008 3.2.2.92) */
#define SMS_TO_VGCS_MAXLEN 252
struct gsm0808_sms_to_vgcs {
	uint8_t sms[SMS_TO_VGCS_MAXLEN];
	unsigned int sms_len;
};

/*! Parsed representation of a Application Data IE (3GPP TS 48.008 3.2.2.98) */
#define APP_DATA_MAXLEN 9
struct gsm0808_application_data {
	uint8_t data[APP_DATA_MAXLEN];
	unsigned int data_len;
};

/*! Packed representation of a Data Identity IE (GGPP TS 48.008 3.2.2.99) */
enum gsm0808_application_idndicator {
	GSM0808_AI_APP_DATA			= 0x00,
	GSM0808_AI_CONFIRM_APP_DATA		= 0x01,
};

#define GSM0808_DP_MASK_TALKERS_LISTENERS	0x04
#define GSM0808_DP_MASK_DISPATCHERS		0x02
#define GSM0808_DP_MASK_NETWORK_APP		0x01

struct gsm0808_data_identity {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t ai:1,	/* Application Indicator */
		di:4,	/* Data identifier */
		dp:3;	/* Distribution parameter (bit mask) */
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t dp:3, di:4, ai:1;
#endif
} __attribute__ ((packed));

/*! Parsed representation of a MSISDN IE (3GPP TS 48.008 3.2.2.101) */
#define MSISDN_MAXLEN 20

/*! LCLS-related parameters from 3GPP TS 48.008 */
struct osmo_lcls {
	enum gsm0808_lcls_config config;   /**< §3.2.2.116 Configuration */
	enum gsm0808_lcls_control control; /**< §3.2.2.117 Connection Status Control */
	struct osmo_gcr_parsed gcr;        /**< §3.2.2.115 Global Call Reference */
	bool gcr_available;
	bool corr_needed;                  /**< §3.2.2.118 Correlation-Not-Needed */
};

char *osmo_lcls_dump(const struct osmo_lcls *lcls);
char *osmo_lcls_dump_buf(char *buf, size_t buf_len, const struct osmo_lcls *lcls);
char *osmo_lcls_dump_c(void *ctx, const struct osmo_lcls *lcls);
char *osmo_gcr_dump(const struct osmo_lcls *lcls);
char *osmo_gcr_dump_buf(char *buf, size_t buf_len, const struct osmo_lcls *lcls);

extern const struct value_string gsm0808_cell_id_discr_names[];
static inline const char *gsm0808_cell_id_discr_name(enum CELL_IDENT id_discr)
{ return get_value_string(gsm0808_cell_id_discr_names, id_discr); }

const char *gsm0808_cell_id_name(const struct gsm0808_cell_id *cid);
const char *gsm0808_cell_id_name2(const struct gsm0808_cell_id *cid);
char *gsm0808_cell_id_name_buf(char *buf, size_t buflen, const struct gsm0808_cell_id *cid);
char *gsm0808_cell_id_name_c(const void *ctx, const struct gsm0808_cell_id *cid);
const char *gsm0808_cell_id_list_name(const struct gsm0808_cell_id_list2 *cil);
int gsm0808_cell_id_list_name_buf(char *buf, size_t buflen, const struct gsm0808_cell_id_list2 *cil);
char *gsm0808_cell_id_list_name_c(const void *ctx, const struct gsm0808_cell_id_list2 *cil);
int gsm0808_cell_id_u_name(char *buf, size_t buflen,
			   enum CELL_IDENT id_discr, const union gsm0808_cell_id_u *u);
bool gsm0808_cell_ids_match(const struct gsm0808_cell_id *id1, const struct gsm0808_cell_id *id2, bool exact_match);
int gsm0808_cell_id_matches_list(const struct gsm0808_cell_id *id, const struct gsm0808_cell_id_list2 *list,
				 unsigned int match_nr, bool exact_match);
void gsm0808_cell_id_from_cgi(struct gsm0808_cell_id *cid, enum CELL_IDENT id_discr,
			      const struct osmo_cell_global_id *cgi);
int gsm0808_cell_id_to_cgi(struct osmo_cell_global_id *cgi, const struct gsm0808_cell_id *cid);
void gsm0808_msgb_put_cell_id_u(struct msgb *msg, enum CELL_IDENT id_discr, const union gsm0808_cell_id_u *u);
int gsm0808_decode_cell_id_u(union gsm0808_cell_id_u *out, enum CELL_IDENT discr, const uint8_t *buf, unsigned int len);
int gsm0808_cell_id_size(enum CELL_IDENT discr);

uint8_t gsm0808_enc_cause(struct msgb *msg, uint16_t cause);
uint8_t gsm0808_enc_aoip_trasp_addr(struct msgb *msg,
				    const struct sockaddr_storage *ss);
int gsm0808_dec_aoip_trasp_addr(struct sockaddr_storage *ss,
				const uint8_t *elem, uint8_t len);
int gsm0808_dec_osmux_cid(uint8_t *cid, const uint8_t *elem, uint8_t len);

uint8_t gsm0808_enc_lcls(struct msgb *msg, const struct osmo_lcls *lcls);
int gsm0808_dec_lcls(struct osmo_lcls *lcls, const struct tlv_parsed *tp);

uint8_t gsm0808_enc_speech_codec(struct msgb *msg,
				 const struct gsm0808_speech_codec *sc)
	OSMO_DEPRECATED("use gsm0808_enc_speech_codec2() instead");
int gsm0808_enc_speech_codec2(struct msgb *msg,
			      const struct gsm0808_speech_codec *sc);
int gsm0808_dec_speech_codec(struct gsm0808_speech_codec *sc,
			     const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_speech_codec_list(struct msgb *msg,
				      const struct gsm0808_speech_codec_list *scl)
	OSMO_DEPRECATED("use gsm0808_enc_speech_codec_list2() instead");
int gsm0808_enc_speech_codec_list2(struct msgb *msg,
				   const struct gsm0808_speech_codec_list *scl);
int gsm0808_dec_speech_codec_list(struct gsm0808_speech_codec_list *scl,
				  const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_channel_type(struct msgb *msg,
				 const struct gsm0808_channel_type *ct);
int gsm0808_dec_channel_type(struct gsm0808_channel_type *ct,
			     const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_encrypt_info(struct msgb *msg,
				 const struct gsm0808_encrypt_info *ei);
int gsm0808_dec_encrypt_info(struct gsm0808_encrypt_info *ei,
			     const uint8_t *elem, uint8_t len);
int gsm0808_enc_kc128(struct msgb *msg, const uint8_t *kc128);
int gsm0808_dec_kc128(uint8_t *kc128, const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_cell_id_list2(struct msgb *msg, const struct gsm0808_cell_id_list2 *cil);
uint8_t gsm0808_enc_cell_id_list(struct msgb *msg,
				 const struct gsm0808_cell_id_list *cil)
				 OSMO_DEPRECATED("use gsm0808_enc_cell_id_list2 instead");
int gsm0808_dec_cell_id_list2(struct gsm0808_cell_id_list2 *cil, const uint8_t *elem, uint8_t len);
int gsm0808_dec_cell_id_list(struct gsm0808_cell_id_list *cil,
			     const uint8_t *elem, uint8_t len)
			     OSMO_DEPRECATED("use gsm0808_dec_cell_id_list2 instead");
int gsm0808_cell_id_list_add(struct gsm0808_cell_id_list2 *dst, const struct gsm0808_cell_id_list2 *src);
void gsm0808_cell_id_to_list(struct gsm0808_cell_id_list2 *dst, const struct gsm0808_cell_id *src);
uint8_t gsm0808_enc_cell_id(struct msgb *msg, const struct gsm0808_cell_id *ci);
int gsm0808_dec_cell_id(struct gsm0808_cell_id *ci, const uint8_t *elem, uint8_t len);
int gsm0808_chan_type_to_speech_codec(uint8_t perm_spch);
int gsm0808_speech_codec_from_chan_type(struct gsm0808_speech_codec *sc,
					uint8_t perm_spch);
uint16_t gsm0808_sc_cfg_from_gsm48_mr_cfg(const struct gsm48_multi_rate_conf *cfg, bool fr);
int gsm48_mr_cfg_from_gsm0808_sc_cfg(struct gsm48_multi_rate_conf *cfg, uint16_t s15_s0);

/*! \returns 3GPP TS 08.08 §3.2.2.5 Class of a given Cause */
static inline enum gsm0808_cause_class gsm0808_cause_class(enum gsm0808_cause cause)
{
	return (cause >> 4) & 0x7;
}

/*! \returns true if 3GPP TS 08.08 §3.2.2.5 Class has extended bit set */
static inline bool gsm0808_cause_ext(enum gsm0808_cause cause)
{
	/* check that cause looks like 1XXX0000 where XXX represent class */
	return (cause & 0x80) && !(cause & 0x0F);
}

int gsm0808_get_cipher_reject_cause(const struct tlv_parsed *tp)
OSMO_DEPRECATED("Use gsm0808_get_cause() instead");

/*! \returns 3GPP TS 48.008 3.2.2.49 Current Channel Type 1 from enum gsm_chan_t. */
static inline uint8_t gsm0808_current_channel_type_1(enum gsm_chan_t type)
{
	switch (type) {
	default:
		return 0;
	case GSM_LCHAN_SDCCH:
		return 0x01;
	case GSM_LCHAN_TCH_F:
		return 0x18;
	case GSM_LCHAN_TCH_H:
		return 0x19;
	}
}

/*! Return 3GPP TS 48.008 3.2.2.51 Speech Version aka permitted speech version indication in 3.2.2.11
 * Channel Type. */
static inline enum gsm0808_permitted_speech gsm0808_permitted_speech(enum gsm_chan_t type,
								     enum gsm48_chan_mode mode)
{
#define MODE_TYPE(mode, type) ((mode << 16) | type)

	switch (MODE_TYPE(mode, type)) {
	case MODE_TYPE(GSM48_CMODE_SPEECH_V1, GSM_LCHAN_TCH_F):
		return GSM0808_PERM_FR1;
	case MODE_TYPE(GSM48_CMODE_SPEECH_V1, GSM_LCHAN_TCH_H):
		return GSM0808_PERM_HR1;
	case MODE_TYPE(GSM48_CMODE_SPEECH_EFR, GSM_LCHAN_TCH_F):
		return GSM0808_PERM_FR2;
	case MODE_TYPE(GSM48_CMODE_SPEECH_EFR, GSM_LCHAN_TCH_H):
		return GSM0808_PERM_HR2; /* (deprecated) */
	case MODE_TYPE(GSM48_CMODE_SPEECH_AMR, GSM_LCHAN_TCH_F):
		return GSM0808_PERM_FR3;
	case MODE_TYPE(GSM48_CMODE_SPEECH_AMR, GSM_LCHAN_TCH_H):
		return GSM0808_PERM_HR3;
	case MODE_TYPE(GSM48_CMODE_SPEECH_V4, GSM_LCHAN_TCH_F):
		return GSM0808_PERM_FR4;
	case MODE_TYPE(GSM48_CMODE_SPEECH_V4, GSM_LCHAN_TCH_H):
		return GSM0808_PERM_HR4;
	case MODE_TYPE(GSM48_CMODE_SPEECH_V5, GSM_LCHAN_TCH_F):
		return GSM0808_PERM_FR5; /* FR only */
	case MODE_TYPE(GSM48_CMODE_SPEECH_V6, GSM_LCHAN_TCH_H):
		return GSM0808_PERM_HR6; /* HR only */
	default:
		return 0;
	}

#undef MODE_TYPE
}

/*! Return 3GPP TS 48.008 3.2.2.33 Chosen Channel. */
static inline uint8_t gsm0808_chosen_channel(enum gsm_chan_t type, enum gsm48_chan_mode mode)
{
	uint8_t channel_mode = 0, channel = 0;

	switch (mode) {
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_EFR:
	case GSM48_CMODE_SPEECH_AMR:
	case GSM48_CMODE_SPEECH_V4:
	case GSM48_CMODE_SPEECH_V5:
	case GSM48_CMODE_SPEECH_V6:
		channel_mode = 0x9;
		break;
	case GSM48_CMODE_SIGN:
		channel_mode = 0x8;
		break;
	case GSM48_CMODE_DATA_14k5:
		channel_mode = 0xe;
		break;
	case GSM48_CMODE_DATA_12k0:
		channel_mode = 0xb;
		break;
	case GSM48_CMODE_DATA_6k0:
		channel_mode = 0xc;
		break;
	case GSM48_CMODE_DATA_3k6:
		channel_mode = 0xd;
		break;
	case GSM48_CMODE_DATA_29k0:
		channel_mode = 0x1;
		break;
	case GSM48_CMODE_DATA_32k0:
		channel_mode = 0x2;
		break;
	case GSM48_CMODE_DATA_43k5:
		channel_mode = 0x3;
		break;
	case GSM48_CMODE_DATA_43k5_14k5:
		channel_mode = 0x4;
		break;
	case GSM48_CMODE_DATA_29k0_14k5:
		channel_mode = 0x5;
		break;
	case GSM48_CMODE_DATA_43k5_29k0:
		channel_mode = 0x6;
		break;
	case GSM48_CMODE_DATA_14k5_43k5:
		channel_mode = 0x7;
		break;
	case GSM48_CMODE_DATA_14k5_29k0:
		channel_mode = 0xa;
		break;
	case GSM48_CMODE_DATA_29k0_43k5:
		channel_mode = 0xf;
		break;
	default:
		return 0;
	}

	switch (type) {
	case GSM_LCHAN_NONE:
		channel = 0x0;
		break;
	case GSM_LCHAN_SDCCH:
		channel = 0x1;
		break;
	case GSM_LCHAN_TCH_F:
		channel = 0x8;
		break;
	case GSM_LCHAN_TCH_H:
		channel = 0x9;
		break;
	/* TODO: more than 1 TCHs? */
	default:
		return 0;
	}

	return channel_mode << 4 | channel;
}

const char *gsm0808_channel_type_name(const struct gsm0808_channel_type *ct);
char *gsm0808_channel_type_name_buf(char *buf, size_t buf_len, const struct gsm0808_channel_type *ct);
char *gsm0808_channel_type_name_c(const void *ctx, const struct gsm0808_channel_type *ct);

uint8_t gsm0808_enc_group_callref(struct msgb *msg, const struct gsm0808_group_callref *gc);
int gsm0808_dec_group_callref(struct gsm0808_group_callref *gc, const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_priority(struct msgb *msg, const struct gsm0808_priority *pri);
int gsm0808_dec_priority(struct gsm0808_priority *pri, const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_vgcs_feature_flags(struct msgb *msg, const struct gsm0808_vgcs_feature_flags *ff);
int gsm0808_dec_vgcs_feature_flags(struct gsm0808_vgcs_feature_flags *ff, const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_talker_identity(struct msgb *msg, const struct gsm0808_talker_identity *ti);
int gsm0808_dec_talker_identity(struct gsm0808_talker_identity *ti, const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_data_identity(struct msgb *msg, const struct gsm0808_data_identity *ai);
int gsm0808_dec_data_identity(struct gsm0808_data_identity *ai, const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_msisdn(struct msgb *msg, const char *msisdn);
int gsm0808_dec_msisdn(char *msisdn, const char *elem, uint8_t len);
uint8_t gsm0808_enc_assign_req(struct msgb *msg, const enum gsm0808_assignment_requirement ar);
int gsm0808_dec_assign_req(enum gsm0808_assignment_requirement *ar, const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_cell_id_list_segment(struct msgb *msg, uint8_t ie_type,
					 const struct gsm0808_cell_id_list_segment *ci);
int gsm0808_dec_cell_id_list_segment(struct gsm0808_cell_id_list_segment *ci, const uint8_t *elem, uint8_t len);
int gsm0808_dec_call_id(uint32_t *ci, const uint8_t *elem, uint8_t len);

/*! @} */
