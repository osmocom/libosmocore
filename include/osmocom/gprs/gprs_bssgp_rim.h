/*! \file gprs_bssgp.h
 * GPRS BSSGP RIM protocol implementation as per 3GPP TS 48.018. */
/*
 * (C) 2020-2021 by sysmocom - s.f.m.c. GmbH
 * Author: Philipp Maier <pmaier@sysmocom.de>
 *
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

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gprs/protocol/gsm_08_18.h>
#include <osmocom/gprs/protocol/gsm_24_301.h>

enum bssgp_rim_routing_info_discr {
	BSSGP_RIM_ROUTING_INFO_GERAN,
	BSSGP_RIM_ROUTING_INFO_UTRAN,
	BSSGP_RIM_ROUTING_INFO_EUTRAN,
};

extern const struct value_string bssgp_rim_routing_info_discr_strs[];

/*! Obtain a human-readable string for NACC Cause code */
static inline const char *bssgp_rim_routing_info_discr_str(enum bssgp_rim_routing_info_discr val)
{ return get_value_string(bssgp_rim_routing_info_discr_strs, val); }

/*! BSSGP RIM Routing information, see also 3GPP TS 48.018, section 11.3.70 */
struct bssgp_rim_routing_info {
	enum bssgp_rim_routing_info_discr discr;
	union {
		struct {
			struct gprs_ra_id raid;
			uint16_t cid;
		} geran;
		struct {
			struct gprs_ra_id raid;
			uint16_t rncid;
		} utran;
		struct {
			struct osmo_eutran_tai tai;
			/* See also 3GPP TS 36.413 9.2.1.37 and 3GPP TS 36.401 */
			uint8_t global_enb_id[8];
			uint8_t global_enb_id_len;
		} eutran;
	};
};

/* The encoded result of the rim routing information is, depending on the
 * address type (discr) of variable length. */
#define BSSGP_RIM_ROUTING_INFO_MAXLEN 14

char *bssgp_rim_ri_name_buf(char *buf, size_t buf_len, const struct bssgp_rim_routing_info *ri);
const char *bssgp_rim_ri_name(const struct bssgp_rim_routing_info *ri);
int bssgp_parse_rim_ri(struct bssgp_rim_routing_info *ri, const uint8_t *buf, unsigned int len);
int bssgp_create_rim_ri(uint8_t *buf, const struct bssgp_rim_routing_info *ri);

/* 3GPP TS 48.018, table 11.3.63.1.1: RAN-INFORMATION-REQUEST Application Container coding for NACC */
struct bssgp_ran_inf_req_app_cont_nacc {
	struct osmo_cell_global_id_ps reprt_cell;
};

int bssgp_dec_ran_inf_req_app_cont_nacc(struct bssgp_ran_inf_req_app_cont_nacc *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_req_app_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_ran_inf_req_app_cont_nacc *cont);

/* Length of NACC system information, see also: 3GPP TS 48.018 11.3.63.2.1 */
#define BSSGP_RIM_SI_LEN 21
#define BSSGP_RIM_PSI_LEN 22

/* 3GPP TS 48.018, table 11.3.63.2.1.a: RAN-INFORMATION Application Container coding for NACC */
struct bssgp_ran_inf_app_cont_nacc {
	struct osmo_cell_global_id_ps reprt_cell;
	bool type_psi;
	uint8_t num_si;

	/* Pointer to system information messages */
	const uint8_t *si[127];
};

int bssgp_dec_ran_inf_app_cont_nacc(struct bssgp_ran_inf_app_cont_nacc *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_app_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_ran_inf_app_cont_nacc *cont);

/* 3GPP TS 48.018, table 11.3.64.1.b, NACC Cause coding */
enum bssgp_nacc_cause {
	BSSGP_NACC_CAUSE_UNSPEC,
	BSSGP_NACC_CAUSE_SYNTAX_ERR,
	BSSGP_NACC_CAUSE_RPRT_CELL_MISSMTCH,
	BSSGP_NACC_CAUSE_SIPSI_TYPE_ERR,
	BSSGP_NACC_CAUSE_SIPSI_LEN_ERR,
	BSSGP_NACC_CAUSE_SIPSI_SET_ERR,
};

extern const struct value_string bssgp_nacc_cause_strs[];

/*! Obtain a human-readable string for NACC Cause code */
static inline const char *bssgp_nacc_cause_str(enum bssgp_nacc_cause val)
{ return get_value_string(bssgp_nacc_cause_strs, val); }

/* 3GPP TS 48.018, table 11.3.64.1.a, Application Error Container coding for NACC */
struct bssgp_app_err_cont_nacc {
	enum bssgp_nacc_cause nacc_cause;

	/* Pointer to errornous application container */
	const uint8_t *err_app_cont;
	size_t err_app_cont_len;
};

int bssgp_dec_app_err_cont_nacc(struct bssgp_app_err_cont_nacc *cont, const uint8_t *buf, size_t len);
int bssgp_enc_app_err_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_app_err_cont_nacc *cont);

/* 3GPP TS 48.018, table 11.3.61.b: RIM Application Identity coding */
enum bssgp_ran_inf_app_id {
	BSSGP_RAN_INF_APP_ID_NACC = 1,
	BSSGP_RAN_INF_APP_ID_SI3 = 2,
	BSSGP_RAN_INF_APP_ID_MBMS = 3,
	BSSGP_RAN_INF_APP_ID_SON = 4,
	BSSGP_RAN_INF_APP_ID_UTRA_SI = 5,
};

extern const struct value_string bssgp_ran_inf_app_id_strs[];

/*! Obtain a human-readable string for RIM Application Identity code */
static inline const char *bssgp_ran_inf_app_id_str(enum bssgp_ran_inf_app_id val)
{ return get_value_string(bssgp_ran_inf_app_id_strs, val); }

/* 3GPP TS 48.018, table 11.3.62a.1.b: RAN-INFORMATION-REQUEST RIM Container Contents */
struct bssgp_ran_inf_req_rim_cont {
	enum bssgp_ran_inf_app_id app_id;
	uint32_t seq_num;
	struct bssgp_rim_pdu_ind pdu_ind;
	uint8_t prot_ver;

	/* Nested application container */
	union {
		struct bssgp_ran_inf_req_app_cont_nacc app_cont_nacc;
		/* TODO: add containers for Si3, MBMS, SON, UTRA-SI */
	} u;

	/* Pointer to SON-transfer application identity, only present if app_id is indicating "son-transfer",
	 * see also 3GPP TS 48.018, section 11.3.108 and 3GPP TS 36.413 annex B.1.1 */
	const uint8_t *son_trans_app_id;
	size_t son_trans_app_id_len;
};

int bssgp_dec_ran_inf_req_rim_cont(struct bssgp_ran_inf_req_rim_cont *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_req_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_req_rim_cont *cont);

/* 3GPP TS 48.018, table 11.3.62a.2.b: RAN-INFORMATION RIM Container Contents */
struct bssgp_ran_inf_rim_cont {
	enum bssgp_ran_inf_app_id app_id;
	uint32_t seq_num;
	struct bssgp_rim_pdu_ind pdu_ind;
	uint8_t prot_ver;
	bool app_err;

	/* Nested application container */
	union {
		struct bssgp_ran_inf_app_cont_nacc app_cont_nacc;
		struct bssgp_app_err_cont_nacc app_err_cont_nacc;
		/* TODO: add containers for Si3, MBMS, SON, UTRA-SI */
	} u;

	/* Pointer to SON-transfer application identity, only present if app_id is indicating "son-transfer",
	 * see also 3GPP TS 48.018, section 11.3.108 and 3GPP TS 36.413 annex B.1.1 */
	const uint8_t *son_trans_app_id;
	size_t son_trans_app_id_len;
};

int bssgp_dec_ran_inf_rim_cont(struct bssgp_ran_inf_rim_cont *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_rim_cont *cont);

/* 3GPP TS 48.018, table 11.3.62a.3.b: RAN-INFORMATION-ACK RIM Container Contents */
struct bssgp_ran_inf_ack_rim_cont {
	enum bssgp_ran_inf_app_id app_id;
	uint32_t seq_num;
	uint8_t prot_ver;

	/* Pointer to SON-transfer application identity, only present if app_id is indicating "son-transfer",
	 * see also 3GPP TS 48.018, section 11.3.108 and 3GPP TS 36.413 annex B.1.1 */
	const uint8_t *son_trans_app_id;
	size_t son_trans_app_id_len;
};

int bssgp_dec_ran_inf_ack_rim_cont(struct bssgp_ran_inf_ack_rim_cont *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_ack_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_ack_rim_cont *cont);

/* 3GPP TS 48.018, table 11.3.62a.4.b: RAN-INFORMATION-ERROR RIM Container Contents */
struct bssgp_ran_inf_err_rim_cont {
	enum bssgp_ran_inf_app_id app_id;
	uint8_t cause;
	uint8_t prot_ver;

	/* Pointer to (encoded) errornous PDU,
	 * see also: 3GPP TS 48.018, section 11.3.24 */
	const uint8_t *err_pdu;
	size_t err_pdu_len;

	/* Pointer to SON-transfer application identity, only present if app_id is indicating "son-transfer",
	 * see also 3GPP TS 48.018, section 11.3.108 and 3GPP TS 36.413 annex B.1.1 */
	const uint8_t *son_trans_app_id;
	size_t son_trans_app_id_len;
};

int bssgp_dec_ran_inf_err_rim_cont(struct bssgp_ran_inf_err_rim_cont *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_err_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_err_rim_cont *cont);

/* 3GPP TS 48.018, table 11.3.62a.5.b: RAN-INFORMATION-APPLICATION-ERROR RIM Container Contents */
struct bssgp_ran_inf_app_err_rim_cont {
	enum bssgp_ran_inf_app_id app_id;
	uint32_t seq_num;
	struct bssgp_rim_pdu_ind pdu_ind;
	uint8_t prot_ver;

	/* Nested application container */
	union {
		struct bssgp_app_err_cont_nacc app_err_cont_nacc;
		/* TODO: add containers for Si3, MBMS, SON, UTRA-SI */
	} u;
};

int bssgp_dec_ran_inf_app_err_rim_cont(struct bssgp_ran_inf_app_err_rim_cont *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_app_err_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_app_err_rim_cont *cont);

/* Chapter 10.6.1: RAN-INFORMATION-REQUEST */
struct bssgp_ran_information_pdu {
	struct bssgp_rim_routing_info routing_info_dest;
	struct bssgp_rim_routing_info routing_info_src;

	/* Encoded variant of the RIM container */
	uint8_t rim_cont_iei;
	const uint8_t *rim_cont;
	unsigned int rim_cont_len;

	/* Decoded variant of the RIM container */
	bool decoded_present;
	union {
		struct bssgp_ran_inf_req_rim_cont req_rim_cont;
		struct bssgp_ran_inf_rim_cont rim_cont;
		struct bssgp_ran_inf_ack_rim_cont ack_rim_cont;
		struct bssgp_ran_inf_err_rim_cont err_rim_cont;
		struct bssgp_ran_inf_app_err_rim_cont app_err_rim_cont;
	} decoded;

	/* When receiving a PDU from BSSGP the encoded variant of the RIM
	 * container will always be present. The decoded variant will be
	 * present in addition whenever BSSGP was able to decode the container.
	 *
	 * When sending a PDU to BSSGP, then the decoded variant is used when
	 * it is available. The encoded variant (if present) will be ignored
	 * then. */
};

int bssgp_parse_rim_pdu(struct bssgp_ran_information_pdu *pdu, const struct msgb *msg);
struct msgb *bssgp_encode_rim_pdu(const struct bssgp_ran_information_pdu *pdu);

int bssgp_tx_rim(const struct bssgp_ran_information_pdu *pdu, uint16_t nsei);
