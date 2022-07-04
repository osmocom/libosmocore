/*! \file gprs_bssgp.c
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

#include <errno.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp_rim.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include "gprs_bssgp_internal.h"

/* TVLV IEs use a variable length field. To be sure we will do all buffer
 * length checks with the maximum possible header length, which is
 * 1 octet tag + 2 octets length = 3 */
#define TVLV_HDR_MAXLEN 3

/* Usually RIM application containers and their surrounding RIM containers
 * are not likely to exceed 128 octets, so the usual header length will be 2 */
#define TVLV_HDR_LEN 2

/* The reporting cell identifier is encoded as a cell identifier IE
 * (3GPP TS 48.018, sub-clause 11.3.9) but without IE and length octets. */
#define REP_CELL_ID_LEN 8

const struct value_string bssgp_rim_routing_info_discr_strs[] = {
	{ BSSGP_RIM_ROUTING_INFO_GERAN,		"GERAN-cell" },
	{ BSSGP_RIM_ROUTING_INFO_UTRAN,		"UTRAN-RNC" },
	{ BSSGP_RIM_ROUTING_INFO_EUTRAN,	"E-UTRAN-eNodeB/HeNB" },
	{ 0, NULL }
};

/*! Parse a RIM Routing information IE (3GPP TS 48.018, chapter 11.3.70).
 *  \param[out] ri user provided memory to store the parsed results.
 *  \param[in] buf input buffer of the value part of the IE.
 *  \returns length of parsed octets, -EINVAL on error. */
int bssgp_parse_rim_ri(struct bssgp_rim_routing_info *ri, const uint8_t *buf,
		       unsigned int len)
{
	struct gprs_ra_id raid_temp;

	memset(ri, 0, sizeof(*ri));
	if (len < 2)
		return -EINVAL;

	ri->discr = buf[0] & 0x0f;
	buf++;

	switch (ri->discr) {
	case BSSGP_RIM_ROUTING_INFO_GERAN:
		if (len < 9)
			return -EINVAL;
		ri->geran.cid = bssgp_parse_cell_id(&ri->geran.raid, buf);
		return 9;
	case BSSGP_RIM_ROUTING_INFO_UTRAN:
		if (len < 9)
			return -EINVAL;
		gsm48_parse_ra(&ri->utran.raid, buf);
		ri->utran.rncid = osmo_load16be(buf + 6);
		return 9;
	case BSSGP_RIM_ROUTING_INFO_EUTRAN:
		if (len < 7 || len > 14)
			return -EINVAL;
		/* Note: 3GPP TS 24.301 Figure 9.9.3.32.1 and 3GPP TS 24.008
		 * Figure 10.5.130 specify MCC/MNC encoding in the same way,
		 * so we can re-use gsm48_parse_ra() for that. */
		gsm48_parse_ra(&raid_temp, buf);
		ri->eutran.tai.mcc = raid_temp.mcc;
		ri->eutran.tai.mnc = raid_temp.mnc;
		ri->eutran.tai.mnc_3_digits = raid_temp.mnc_3_digits;
		ri->eutran.tai.tac = osmo_load16be(buf + 3);
		memcpy(ri->eutran.global_enb_id, buf + 5, len - 6);
	        ri->eutran.global_enb_id_len = len - 6;
		return len;
	default:
		return -EINVAL;
	}
}

/*! Encode a RIM Routing information IE (3GPP TS 48.018, chapter 11.3.70).
 *  \param[out] buf user provided memory (at least 14 byte) for the generated value part of the IE.
 *  \param[in] ri user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_create_rim_ri(uint8_t *buf, const struct bssgp_rim_routing_info *ri)
{
	int rc;
	struct gprs_ra_id raid_temp;
	int len;

	buf[0] = ri->discr & 0x0f;
	buf++;

	switch (ri->discr) {
	case BSSGP_RIM_ROUTING_INFO_GERAN:
		rc = bssgp_create_cell_id(buf, &ri->geran.raid, ri->geran.cid);
		if (rc < 0)
			return -EINVAL;
		len = rc + 1;
		break;
	case BSSGP_RIM_ROUTING_INFO_UTRAN:
		gsm48_encode_ra((struct gsm48_ra_id *)buf, &ri->utran.raid);
		osmo_store16be(ri->utran.rncid, buf + 6);
		len = 9;
		break;
	case BSSGP_RIM_ROUTING_INFO_EUTRAN:
		/* Note: 3GPP TS 24.301 Figure 9.9.3.32.1 and 3GPP TS 24.008
		 * Figure 10.5.130 specify MCC/MNC encoding in the same way,
		 * so we can re-use gsm48_encode_ra() for that. */
		raid_temp = (struct gprs_ra_id) {
			.mcc = ri->eutran.tai.mcc,
			.mnc = ri->eutran.tai.mnc,
			.mnc_3_digits = ri->eutran.tai.mnc_3_digits,
		};

		gsm48_encode_ra((struct gsm48_ra_id *)buf, &raid_temp);
		osmo_store16be(ri->eutran.tai.tac, buf + 3);
		OSMO_ASSERT(ri->eutran.global_enb_id_len <=
			    sizeof(ri->eutran.global_enb_id));
		memcpy(buf + 5, ri->eutran.global_enb_id,
		       ri->eutran.global_enb_id_len);
		len = ri->eutran.global_enb_id_len + 6;
		break;
	default:
		return -EINVAL;
	}

	OSMO_ASSERT(len <= BSSGP_RIM_ROUTING_INFO_MAXLEN);
	return len;
}

/*! Encode a RIM Routing information into a human readable string.
 *  \param[buf] user provided string buffer to store the resulting string.
 *  \param[buf_len] maximum length of string buffer.
 *  \param[in] ri user provided input data struct.
 *  \returns pointer to the beginning of the resulting string stored in string buffer. */
char *bssgp_rim_ri_name_buf(char *buf, size_t buf_len, const struct bssgp_rim_routing_info *ri)
{
	char plmn_str[16];
	char enb_id_str[16];
	char g_id_ps_str[32];
	struct osmo_plmn_id plmn;
	struct osmo_cell_global_id_ps g_id_ps;

	if (!ri)
		return NULL;

	switch (ri->discr) {
	case BSSGP_RIM_ROUTING_INFO_GERAN:
		g_id_ps.rai.rac = ri->geran.raid.rac;
		g_id_ps.rai.lac.lac = ri->geran.raid.lac;
		g_id_ps.rai.lac.plmn.mcc = ri->geran.raid.mcc;
		g_id_ps.rai.lac.plmn.mnc_3_digits = ri->geran.raid.mnc_3_digits;
		g_id_ps.rai.lac.plmn.mnc = ri->geran.raid.mnc;
		g_id_ps.cell_identity = ri->geran.cid;
		snprintf(buf, buf_len, "%s-%s", bssgp_rim_routing_info_discr_str(ri->discr),
			 osmo_cgi_ps_name_buf(g_id_ps_str, sizeof(g_id_ps_str), &g_id_ps));
		break;
	case BSSGP_RIM_ROUTING_INFO_UTRAN:
		g_id_ps.rai.rac = ri->utran.raid.rac;
		g_id_ps.rai.lac.lac = ri->utran.raid.lac;
		g_id_ps.rai.lac.plmn.mcc = ri->utran.raid.mcc;
		g_id_ps.rai.lac.plmn.mnc_3_digits = ri->utran.raid.mnc_3_digits;
		g_id_ps.rai.lac.plmn.mnc = ri->utran.raid.mnc;
		g_id_ps.cell_identity = ri->utran.rncid;
		snprintf(buf, buf_len, "%s-%s", bssgp_rim_routing_info_discr_str(ri->discr),
			 osmo_cgi_ps_name_buf(g_id_ps_str, sizeof(g_id_ps_str), &g_id_ps));
		break;
	case BSSGP_RIM_ROUTING_INFO_EUTRAN:
		plmn.mcc = ri->eutran.tai.mcc;
		plmn.mnc = ri->eutran.tai.mnc;
		plmn.mnc_3_digits = ri->eutran.tai.mnc_3_digits;
		snprintf(buf, buf_len, "%s-%s-%u-%s", bssgp_rim_routing_info_discr_str(ri->discr),
			 osmo_plmn_name_buf(plmn_str, sizeof(plmn_str), &plmn), ri->eutran.tai.tac,
			 osmo_hexdump_buf(enb_id_str, sizeof(enb_id_str), ri->eutran.global_enb_id,
					  ri->eutran.global_enb_id_len, "", false));
		break;
	default:
		snprintf(buf, buf_len, "invalid");
	}

	return buf;
}

/*! Encode a RIM Routing information into a human readable string.
 *  \param[in] ri user provided input data struct.
 *  \returns pointer to the resulting string. */
const char *bssgp_rim_ri_name(const struct bssgp_rim_routing_info *ri)
{
	static __thread char rim_ri_buf[64];
	return bssgp_rim_ri_name_buf(rim_ri_buf, sizeof(rim_ri_buf), ri);
}

/*! Decode a RAN Information Request Application Container for NACC (3GPP TS 48.018, section 11.3.63.1.1).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_req_app_cont_nacc(struct bssgp_ran_inf_req_app_cont_nacc *cont, const uint8_t *buf, size_t len)
{
	int rc;

	if (len < REP_CELL_ID_LEN)
		return -EINVAL;

	rc = gsm0808_decode_cell_id_u((union gsm0808_cell_id_u*)&cont->reprt_cell,
				      CELL_IDENT_WHOLE_GLOBAL_PS, buf, len);
	if (rc < 0)
		return -EINVAL;

	return 0;
}

/*! Encode a RAN Information Request Application Container for NACC (3GPP TS 48.018, section 11.3.63.1.1).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_req_app_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_ran_inf_req_app_cont_nacc *cont)
{
	int rc;
	struct gprs_ra_id *raid;

	if (len < REP_CELL_ID_LEN)
		return -EINVAL;

	raid = (struct gprs_ra_id *)&cont->reprt_cell.rai;
	rc = bssgp_create_cell_id(buf, raid, cont->reprt_cell.cell_identity);
	if (rc < 0)
		return -EINVAL;
	return rc;
}

/*! Decode a RAN Information Application Container (3GPP TS 48.018, section 11.3.63.2.1).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_app_cont_nacc(struct bssgp_ran_inf_app_cont_nacc *cont, const uint8_t *buf, size_t len)
{
	unsigned int i;
	int remaining_buf_len;
	int rc;

	/* The given buffer must at least contain a reporting cell identifer
	 * plus one octet that defines number/type of attached sysinfo messages. */
	if (len < REP_CELL_ID_LEN + 1)
		return -EINVAL;

	rc = gsm0808_decode_cell_id_u((union gsm0808_cell_id_u*)&cont->reprt_cell,
				      CELL_IDENT_WHOLE_GLOBAL_PS, buf, len);
	if (rc < 0)
		return -EINVAL;

	buf += REP_CELL_ID_LEN;

	cont->type_psi = buf[0] & 1;
	cont->num_si = buf[0] >> 1;
	buf++;

	/* The number of sysinfo messages may be zero */
	if (cont->num_si == 0)
		return 0;

	/* Check if the prospected system information messages fit in the
	 * remaining buffer space */
	remaining_buf_len = len - REP_CELL_ID_LEN - 1;
	if (remaining_buf_len <= 0)
		return -EINVAL;
	if (cont->type_psi && remaining_buf_len / BSSGP_RIM_PSI_LEN < cont->num_si)
		return -EINVAL;
	else if (remaining_buf_len / BSSGP_RIM_SI_LEN < cont->num_si)
		return -EINVAL;

	for (i = 0; i < cont->num_si; i++) {
		cont->si[i] = buf;
		if (cont->type_psi)
			buf += BSSGP_RIM_PSI_LEN;
		else
			buf += BSSGP_RIM_SI_LEN;
	}

	return 0;
}

/*! Encode a RAN Information Application Container (3GPP TS 48.018, section 11.3.63.2.1).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_app_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_ran_inf_app_cont_nacc *cont)
{
	uint8_t *buf_ptr = buf;
	int rc;
	unsigned int silen;
	unsigned int i;
	struct gprs_ra_id *raid;

	if (cont->type_psi)
		silen = BSSGP_RIM_PSI_LEN;
	else
		silen = BSSGP_RIM_SI_LEN;

	/* The buffer must accept the reporting cell id, plus 1 byte to define
	 * the type and number of sysinfo messages. */
	if (len < REP_CELL_ID_LEN + 1 + silen * cont->num_si)
		return -EINVAL;

	raid = (struct gprs_ra_id *)&cont->reprt_cell.rai;
	rc = bssgp_create_cell_id(buf_ptr, raid, cont->reprt_cell.cell_identity);
	if (rc < 0)
		return -EINVAL;
	buf_ptr += rc;

	buf_ptr[0] = 0x00;
	if (cont->type_psi)
		buf_ptr[0] |= 0x01;
	buf_ptr[0] |= (cont->num_si << 1);
	buf_ptr++;

	for (i = 0; i < cont->num_si; i++) {
		memcpy(buf_ptr, cont->si[i], silen);
		buf_ptr += silen;
	}

	return (int)(buf_ptr - buf);
}

/* 3GPP TS 48.018, table 11.3.64.1.b, NACC Cause coding */
const struct value_string bssgp_nacc_cause_strs[] = {
	{ BSSGP_NACC_CAUSE_UNSPEC,		"unspecified error" },
	{ BSSGP_NACC_CAUSE_SYNTAX_ERR,		"syntax error in app container" },
	{ BSSGP_NACC_CAUSE_RPRT_CELL_MISSMTCH,  "reporting cell id mismatch" },
	{ BSSGP_NACC_CAUSE_SIPSI_TYPE_ERR,	"SI/PSI type error" },
	{ BSSGP_NACC_CAUSE_SIPSI_LEN_ERR,	"SI/PSI inconsistent length" },
	{ BSSGP_NACC_CAUSE_SIPSI_SET_ERR,	"inconsistent set of msg" },
	{ 0, NULL }
};

/*! Decode a Application Error Container for NACC (3GPP TS 48.018, section 11.3.64.1).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_app_err_cont_nacc(struct bssgp_app_err_cont_nacc *cont, const uint8_t *buf, size_t len)
{
	/* The buffer must at least contain the NACC cause code, it should also
	 * contain the application container, but we won't error if it is missing. */
	if (len < 1)
		return -EINVAL;

	cont->nacc_cause = buf[0];

	if (len > 1) {
		cont->err_app_cont = buf + 1;
		cont->err_app_cont_len = len - 1;
	} else {
		cont->err_app_cont = NULL;
		cont->err_app_cont_len = 0;
	}

	return 0;
}

/*! Encode Application Error Container for NACC (3GPP TS 48.018, section 11.3.64.1).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_app_err_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_app_err_cont_nacc *cont)
{
	uint8_t *buf_ptr = buf;

	/* The buffer must accept the length of the application container and the NACC
	 * cause code, which is one octet in length. */
	if (len < cont->err_app_cont_len + 1)
		return -EINVAL;

	buf_ptr[0] = cont->nacc_cause;
	buf_ptr++;

	memcpy(buf_ptr, cont->err_app_cont, cont->err_app_cont_len);
	buf_ptr += cont->err_app_cont_len;

	return (int)(buf_ptr - buf);
}

/* The structs bssgp_ran_inf_req_rim_cont, bssgp_ran_inf_rim_cont and bssgp_ran_inf_app_err_rim_cont *cont
 * share four common fields at the beginning, we use the following struct as parameter type for the common
 * encoder/decoder functions. (See also 3GPP TS 48.018 table 11.3.62a.1.b, table 11.3.62a.2.b, and
 * table 11.3.62a.5.b) */
struct bssgp_ran_inf_x_cont {
	enum bssgp_ran_inf_app_id app_id;
	uint32_t seq_num;
	struct bssgp_rim_pdu_ind pdu_ind;
	uint8_t prot_ver;
};

static int dec_rim_cont_common(struct bssgp_ran_inf_x_cont *cont, struct tlv_parsed *tp)
{
	if (TLVP_PRES_LEN(tp, BSSGP_IE_RIM_APP_IDENTITY, sizeof(uint8_t)))
		cont->app_id = TLVP_VAL(tp, BSSGP_IE_RIM_APP_IDENTITY)[0];
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(tp, BSSGP_IE_RIM_SEQ_NR, sizeof(cont->seq_num)))
		cont->seq_num = tlvp_val32be(tp, BSSGP_IE_RIM_SEQ_NR);
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(tp, BSSGP_IE_RIM_PDU_INDICATIONS, sizeof(cont->pdu_ind)))
		memcpy(&cont->pdu_ind, TLVP_VAL(tp, BSSGP_IE_RIM_PDU_INDICATIONS), sizeof(cont->pdu_ind));
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(tp, BSSGP_IE_RIM_PROTOCOL_VERSION, sizeof(cont->prot_ver)))
		cont->prot_ver = TLVP_VAL(tp, BSSGP_IE_RIM_PROTOCOL_VERSION)[0];
	else
		cont->prot_ver = 1;

	return 0;
}

static uint8_t *enc_rim_cont_common(uint8_t *buf, size_t len, const struct bssgp_ran_inf_x_cont *cont)
{

	uint32_t seq_num = osmo_htonl(cont->seq_num);
	uint8_t app_id_temp;
	uint8_t *buf_ptr = buf;

	if (len <
	    TVLV_HDR_MAXLEN * 4 + sizeof(app_id_temp) + sizeof(seq_num) + sizeof(cont->pdu_ind) +
	    sizeof(cont->prot_ver))
		return NULL;

	app_id_temp = cont->app_id;
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_APP_IDENTITY, sizeof(app_id_temp), &app_id_temp);
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_SEQ_NR, sizeof(seq_num), (uint8_t *) & seq_num);
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_PDU_INDICATIONS, sizeof(cont->pdu_ind), (uint8_t *) & cont->pdu_ind);
	if (cont->prot_ver > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_PROTOCOL_VERSION, sizeof(cont->prot_ver), &cont->prot_ver);

	return buf_ptr;
}

/* 3GPP TS 48.018, table 11.3.61.b: RIM Application Identity coding */
const struct value_string bssgp_ran_inf_app_id_strs[] = {
	{ BSSGP_RAN_INF_APP_ID_NACC,	"Network Assisted Cell Change (NACC)" },
	{ BSSGP_RAN_INF_APP_ID_SI3,	"System Information 3 (SI3)" },
	{ BSSGP_RAN_INF_APP_ID_MBMS,	"MBMS data channel" },
	{ BSSGP_RAN_INF_APP_ID_SON,	"SON Transfer" },
	{ BSSGP_RAN_INF_APP_ID_UTRA_SI,	"UTRA System Information (UTRA SI)" },
	{ 0, NULL }
};

/*! Decode a RAN Information Request RIM Container (3GPP TS 48.018, table 11.3.62a.1.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_req_rim_cont(struct bssgp_ran_inf_req_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	rc = dec_rim_cont_common((struct bssgp_ran_inf_x_cont *)cont, &tp);
	if (rc < 0)
		return -EINVAL;

	if (TLVP_PRESENT(&tp, BSSGP_IE_RIM_REQ_APP_CONTAINER)) {
		switch (cont->app_id) {
		case BSSGP_RAN_INF_APP_ID_NACC:
			rc = bssgp_dec_ran_inf_req_app_cont_nacc(&cont->u.app_cont_nacc,
								 TLVP_VAL(&tp, BSSGP_IE_RIM_REQ_APP_CONTAINER),
								 TLVP_LEN(&tp, BSSGP_IE_RIM_REQ_APP_CONTAINER));
			break;
		case BSSGP_RAN_INF_APP_ID_SI3:
		case BSSGP_RAN_INF_APP_ID_MBMS:
		case BSSGP_RAN_INF_APP_ID_SON:
		case BSSGP_RAN_INF_APP_ID_UTRA_SI:
			/* TODO: add parsers for Si3, MBMS, SON, UTRA-SI app containers */
			return -EOPNOTSUPP;
		default:
			return -EINVAL;
		}

		if (rc < 0)
			return rc;
	}

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID, 1)) {
		cont->son_trans_app_id = TLVP_VAL(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
		cont->son_trans_app_id_len = TLVP_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
	}

	return 0;
}

/* Dub a TLVP header into a given buffer. The value part of the IE must start
 * at the 2nd octet. Should the length field make a 3 octet TLVP header
 * necessary (unlikely, but possible) the value part is moved ahead by one
 * octet. The function returns a pointer to the end of value part. */
static uint8_t *dub_tlvp_header(uint8_t *buf, uint8_t iei, uint16_t len)
{
	uint8_t *buf_ptr = buf;

	buf_ptr[0] = iei;
	if (len <= TVLV_MAX_ONEBYTE) {
		buf_ptr[1] = (uint8_t) len;
		buf_ptr[1] |= 0x80;
		buf_ptr += TVLV_HDR_LEN;
	} else {
		memmove(buf_ptr + 1, buf_ptr, len);
		buf_ptr[1] = len >> 8;
		buf_ptr[2] = len & 0xff;
		buf_ptr += TVLV_HDR_MAXLEN;
	}
	buf_ptr += len;

	return buf_ptr;
}

/*! Encode a RAN Information Request RIM Container (3GPP TS 48.018, table 11.3.62a.1.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_req_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_req_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;
	int app_cont_len = 0;
	int remaining_buf_len;

	buf_ptr = enc_rim_cont_common(buf_ptr, len, (struct bssgp_ran_inf_x_cont *)cont);
	if (!buf_ptr)
		return -EINVAL;

	remaining_buf_len = len - (int)(buf_ptr - buf);
	if (remaining_buf_len <= 0)
		return -EINVAL;

	switch (cont->app_id) {
	case BSSGP_RAN_INF_APP_ID_NACC:
		app_cont_len =
		    bssgp_enc_ran_inf_req_app_cont_nacc(buf_ptr + TVLV_HDR_LEN, remaining_buf_len - TVLV_HDR_MAXLEN,
							&cont->u.app_cont_nacc);
		break;
	case BSSGP_RAN_INF_APP_ID_SI3:
	case BSSGP_RAN_INF_APP_ID_MBMS:
	case BSSGP_RAN_INF_APP_ID_SON:
	case BSSGP_RAN_INF_APP_ID_UTRA_SI:
		/* TODO: add encoders for Si3, MBMS, SON, UTRA-SI app containers */
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}

	if (app_cont_len < 0)
		return -EINVAL;
	buf_ptr = dub_tlvp_header(buf_ptr, BSSGP_IE_RIM_REQ_APP_CONTAINER, app_cont_len);

	remaining_buf_len = len - (int)(buf_ptr - buf);
	if (remaining_buf_len < 0)
		return -EINVAL;

	if (cont->son_trans_app_id && cont->son_trans_app_id_len > 0) {
		if (remaining_buf_len < cont->son_trans_app_id_len + TVLV_HDR_MAXLEN)
			return -EINVAL;
		buf_ptr =
		    tvlv_put(buf_ptr, BSSGP_IE_SON_TRANSFER_APP_ID, cont->son_trans_app_id_len, cont->son_trans_app_id);
	}
	return (int)(buf_ptr - buf);
}

/*! Decode a RAN Information RIM Container (3GPP TS 48.018, table 11.3.62a.2.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_rim_cont(struct bssgp_ran_inf_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	rc = dec_rim_cont_common((struct bssgp_ran_inf_x_cont *)cont, &tp);
	if (rc < 0)
		return -EINVAL;

	if (TLVP_PRESENT(&tp, BSSGP_IE_RAN_INFO_APP_CONTAINER)) {
		switch (cont->app_id) {
		case BSSGP_RAN_INF_APP_ID_NACC:
			rc = bssgp_dec_ran_inf_app_cont_nacc(&cont->u.app_cont_nacc,
							     TLVP_VAL(&tp, BSSGP_IE_RAN_INFO_APP_CONTAINER),
							     TLVP_LEN(&tp, BSSGP_IE_RAN_INFO_APP_CONTAINER));
			break;
		case BSSGP_RAN_INF_APP_ID_SI3:
		case BSSGP_RAN_INF_APP_ID_MBMS:
		case BSSGP_RAN_INF_APP_ID_SON:
		case BSSGP_RAN_INF_APP_ID_UTRA_SI:
			/* TODO: add parsers for Si3, MBMS, SON, UTRA-SI app containers */
			return -EOPNOTSUPP;
		default:
			return -EINVAL;
		}

		if (rc < 0)
			return rc;
	} else if (TLVP_PRESENT(&tp, BSSGP_IE_APP_ERROR_CONTAINER)) {
		switch (cont->app_id) {
		case BSSGP_RAN_INF_APP_ID_NACC:
			rc = bssgp_dec_app_err_cont_nacc(&cont->u.app_err_cont_nacc,
							 TLVP_VAL(&tp, BSSGP_IE_APP_ERROR_CONTAINER), TLVP_LEN(&tp,
													       BSSGP_IE_APP_ERROR_CONTAINER));
			break;
		case BSSGP_RAN_INF_APP_ID_SI3:
		case BSSGP_RAN_INF_APP_ID_MBMS:
		case BSSGP_RAN_INF_APP_ID_SON:
		case BSSGP_RAN_INF_APP_ID_UTRA_SI:
			/* TODO: add parsers for Si3, MBMS, SON, UTRA-SI app containers */
			return -EOPNOTSUPP;
		default:
			return -EINVAL;
		}
		if (rc < 0)
			return rc;
		cont->app_err = true;
	}

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID, 1)) {
		cont->son_trans_app_id = TLVP_VAL(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
		cont->son_trans_app_id_len = TLVP_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
	}

	return 0;
}

/*! Encode a RAN Information RIM Container (3GPP TS 48.018, table 11.3.62a.2.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;
	int app_cont_len = 0;
	int remaining_buf_len;

	buf_ptr = enc_rim_cont_common(buf_ptr, len, (struct bssgp_ran_inf_x_cont *)cont);
	if (!buf_ptr)
		return -EINVAL;

	remaining_buf_len = len - (int)(buf_ptr - buf);
	if (remaining_buf_len <= 0)
		return -EINVAL;

	if (cont->app_err) {
		switch (cont->app_id) {
		case BSSGP_RAN_INF_APP_ID_NACC:
			app_cont_len =
			    bssgp_enc_app_err_cont_nacc(buf_ptr + TVLV_HDR_LEN, remaining_buf_len - TVLV_HDR_MAXLEN,
							&cont->u.app_err_cont_nacc);
			break;
		case BSSGP_RAN_INF_APP_ID_SI3:
		case BSSGP_RAN_INF_APP_ID_MBMS:
		case BSSGP_RAN_INF_APP_ID_SON:
		case BSSGP_RAN_INF_APP_ID_UTRA_SI:
			/* TODO: add encoders for Si3, MBMS, SON, UTRA-SI app containers */
			return -EOPNOTSUPP;
		default:
			return -EINVAL;
		}
		if (app_cont_len < 0)
			return -EINVAL;
		buf_ptr = dub_tlvp_header(buf_ptr, BSSGP_IE_APP_ERROR_CONTAINER, app_cont_len);
	} else {
		switch (cont->app_id) {
		case BSSGP_RAN_INF_APP_ID_NACC:
			app_cont_len =
			    bssgp_enc_ran_inf_app_cont_nacc(buf_ptr + TVLV_HDR_LEN, remaining_buf_len - TVLV_HDR_MAXLEN,
							    &cont->u.app_cont_nacc);
			break;
		case BSSGP_RAN_INF_APP_ID_SI3:
		case BSSGP_RAN_INF_APP_ID_MBMS:
		case BSSGP_RAN_INF_APP_ID_SON:
		case BSSGP_RAN_INF_APP_ID_UTRA_SI:
			/* TODO: add encoders for Si3, MBMS, SON, UTRA-SI app containers */
			return -EOPNOTSUPP;
		default:
			return -EINVAL;
		}
		if (app_cont_len < 0)
			return -EINVAL;
		buf_ptr = dub_tlvp_header(buf_ptr, BSSGP_IE_RAN_INFO_APP_CONTAINER, app_cont_len);
	}

	remaining_buf_len = len - (int)(buf_ptr - buf);
	if (remaining_buf_len < 0)
		return -EINVAL;

	if (cont->son_trans_app_id && cont->son_trans_app_id_len > 0) {
		if (remaining_buf_len < cont->son_trans_app_id_len + TVLV_HDR_MAXLEN)
			return -EINVAL;
		buf_ptr =
		    tvlv_put(buf_ptr, BSSGP_IE_SON_TRANSFER_APP_ID, cont->son_trans_app_id_len, cont->son_trans_app_id);
	}
	return (int)(buf_ptr - buf);
}

/*! Decode a RAN Information ACK RIM Container (3GPP TS 48.018, table 11.3.62a.3.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_ack_rim_cont(struct bssgp_ran_inf_ack_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_RIM_APP_IDENTITY, sizeof(uint8_t)))
		cont->app_id = TLVP_VAL(&tp, BSSGP_IE_RIM_APP_IDENTITY)[0];
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_RIM_SEQ_NR, sizeof(cont->seq_num)))
		cont->seq_num = tlvp_val32be(&tp, BSSGP_IE_RIM_SEQ_NR);
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION, sizeof(cont->prot_ver)))
		cont->prot_ver = TLVP_VAL(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION)[0];
	else
		cont->prot_ver = 1;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID, 1)) {
		cont->son_trans_app_id = TLVP_VAL(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
		cont->son_trans_app_id_len = TLVP_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
	}

	return 0;
}

/*! Encode a RAN Information ACK RIM Container (3GPP TS 48.018, table 11.3.62a.3.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_ack_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_ack_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;
	uint32_t seq_num = osmo_htonl(cont->seq_num);
	uint8_t app_id_temp;

	if (len <
	    4 * TVLV_HDR_MAXLEN + sizeof(app_id_temp) + sizeof(seq_num) + sizeof(cont->prot_ver) +
	    cont->son_trans_app_id_len)
		return -EINVAL;

	app_id_temp = cont->app_id;
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_APP_IDENTITY, sizeof(app_id_temp), &app_id_temp);
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_SEQ_NR, sizeof(seq_num), (uint8_t *) & seq_num);

	if (cont->prot_ver > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_PROTOCOL_VERSION, sizeof(cont->prot_ver), &cont->prot_ver);

	if (cont->son_trans_app_id && cont->son_trans_app_id_len > 0)
		buf_ptr =
		    tvlv_put(buf_ptr, BSSGP_IE_SON_TRANSFER_APP_ID, cont->son_trans_app_id_len, cont->son_trans_app_id);

	return (int)(buf_ptr - buf);
}

/*! Decode a RAN Information Error RIM Container (3GPP TS 48.018, table 11.3.62a.4.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_err_rim_cont(struct bssgp_ran_inf_err_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_RIM_APP_IDENTITY, sizeof(uint8_t)))
		cont->app_id = TLVP_VAL(&tp, BSSGP_IE_RIM_APP_IDENTITY)[0];
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_CAUSE, sizeof(cont->cause)))
		cont->cause = TLVP_VAL(&tp, BSSGP_IE_CAUSE)[0];
	else
		return -EINVAL;

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION, sizeof(cont->prot_ver)))
		cont->prot_ver = TLVP_VAL(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION)[0];
	else
		cont->prot_ver = 1;

	if (TLVP_PRESENT(&tp, BSSGP_IE_PDU_IN_ERROR)) {
		cont->err_pdu = TLVP_VAL(&tp, BSSGP_IE_PDU_IN_ERROR);
		cont->err_pdu_len = TLVP_LEN(&tp, BSSGP_IE_PDU_IN_ERROR);
	} else {
		return -EINVAL;
	}

	if (TLVP_PRES_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID, 1)) {
		cont->son_trans_app_id = TLVP_VAL(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
		cont->son_trans_app_id_len = TLVP_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
	}

	return 0;
}

/*! Encode a RAN Information Error RIM Container (3GPP TS 48.018, table 11.3.62a.4.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_err_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_err_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;
	uint8_t app_id_temp;

	if (len <
	    TVLV_HDR_MAXLEN * 5 + sizeof(app_id_temp) + sizeof(cont->cause) + sizeof(cont->prot_ver) +
	    cont->err_pdu_len + cont->son_trans_app_id_len)
		return -EINVAL;

	app_id_temp = cont->app_id;
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_APP_IDENTITY, sizeof(app_id_temp), &app_id_temp);
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_CAUSE, sizeof(cont->cause), &cont->cause);

	if (cont->prot_ver > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_PROTOCOL_VERSION, sizeof(cont->prot_ver), &cont->prot_ver);

	if (cont->err_pdu && cont->err_pdu_len > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_PDU_IN_ERROR, cont->err_pdu_len, cont->err_pdu);
	else
		return -EINVAL;

	if (cont->son_trans_app_id && cont->son_trans_app_id_len > 0)
		buf_ptr =
		    tvlv_put(buf_ptr, BSSGP_IE_SON_TRANSFER_APP_ID, cont->son_trans_app_id_len, cont->son_trans_app_id);

	return (int)(buf_ptr - buf);
}

/*! Decode a RAN Information Application Error RIM Container (3GPP TS 48.018, table 11.3.62a.5.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_app_err_rim_cont(struct bssgp_ran_inf_app_err_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	rc = dec_rim_cont_common((struct bssgp_ran_inf_x_cont *)cont, &tp);
	if (rc < 0)
		return -EINVAL;

	switch (cont->app_id) {
	case BSSGP_RAN_INF_APP_ID_NACC:
		rc = bssgp_dec_app_err_cont_nacc(&cont->u.app_err_cont_nacc,
						 TLVP_VAL(&tp, BSSGP_IE_APP_ERROR_CONTAINER), TLVP_LEN(&tp,
												       BSSGP_IE_APP_ERROR_CONTAINER));
		break;
	case BSSGP_RAN_INF_APP_ID_SI3:
	case BSSGP_RAN_INF_APP_ID_MBMS:
	case BSSGP_RAN_INF_APP_ID_SON:
	case BSSGP_RAN_INF_APP_ID_UTRA_SI:
		/* TODO: add parsers for Si3, MBMS, SON, UTRA-SI app containers */
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}
	if (rc < 0)
		return rc;

	return 0;
}

/*! Encode a RAN Information Application Error RIM Container (3GPP TS 48.018, table 11.3.62a.5.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_app_err_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_app_err_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;
	int app_cont_len = 0;
	int remaining_buf_len;

	buf_ptr = enc_rim_cont_common(buf_ptr, len, (struct bssgp_ran_inf_x_cont *)cont);
	if (!buf_ptr)
		return -EINVAL;

	remaining_buf_len = len - (int)(buf_ptr - buf);
	if (remaining_buf_len <= 0)
		return -EINVAL;

	switch (cont->app_id) {
	case BSSGP_RAN_INF_APP_ID_NACC:
		app_cont_len =
		    bssgp_enc_app_err_cont_nacc(buf_ptr + TVLV_HDR_LEN, remaining_buf_len - TVLV_HDR_MAXLEN,
						&cont->u.app_err_cont_nacc);
		break;
	case BSSGP_RAN_INF_APP_ID_SI3:
	case BSSGP_RAN_INF_APP_ID_MBMS:
	case BSSGP_RAN_INF_APP_ID_SON:
	case BSSGP_RAN_INF_APP_ID_UTRA_SI:
		/* TODO: add encoders for Si3, MBMS, SON, UTRA-SI app containers */
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}
	if (app_cont_len < 0)
		return -EINVAL;
	buf_ptr = dub_tlvp_header(buf_ptr, BSSGP_IE_APP_ERROR_CONTAINER, app_cont_len);

	return (int)(buf_ptr - buf);
}

/*! Parse a given message buffer into a rim-pdu struct.
 *  \param[out] pdu user provided memory for the resulting RAN INFORMATION PDU.
 *  \param[in] msg BSSGP message buffer that contains the encoded RAN INFORMATION PDU.
 *  \returns 0 on sccess, -EINVAL on error. */
int bssgp_parse_rim_pdu(struct bssgp_ran_information_pdu *pdu, const struct msgb *msg)
{
	struct tlv_parsed tp[2];
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *)msgb_bssgph(msg);
	int data_len;
	int rc;
	uint16_t nsei = msgb_nsei(msg);

	memset(pdu, 0, sizeof(*pdu));

	data_len = msgb_bssgp_len(msg) - sizeof(*bgph);
	if (data_len < 0)
		return -EINVAL;

	rc = osmo_tlv_prot_parse(&osmo_pdef_bssgp, tp, ARRAY_SIZE(tp), bgph->pdu_type, bgph->data, data_len, 0, 0,
				 DLBSSGP, __func__);
	if (rc < 0)
		return -EINVAL;

	if (TLVP_PRESENT(&tp[0], BSSGP_IE_RIM_ROUTING_INFO)) {
		rc = bssgp_parse_rim_ri(&pdu->routing_info_dest, TLVP_VAL(&tp[0], BSSGP_IE_RIM_ROUTING_INFO),
					TLVP_LEN(&tp[0], BSSGP_IE_RIM_ROUTING_INFO));
		if (rc < 0) {
			LOGP(DLBSSGP, LOGL_ERROR, "BSSGP RIM (NSEI=%u) invalid Destination Cell Identifier IE\n", nsei);
			return -EINVAL;
		}
	} else {
		LOGP(DLBSSGP, LOGL_ERROR, "BSSGP RIM (NSEI=%u) missing Destination Cell Identifier IE\n", nsei);
		return -EINVAL;
	}

	if (TLVP_PRESENT(&tp[1], BSSGP_IE_RIM_ROUTING_INFO)) {
		rc = bssgp_parse_rim_ri(&pdu->routing_info_src, TLVP_VAL(&tp[1], BSSGP_IE_RIM_ROUTING_INFO),
					TLVP_LEN(&tp[1], BSSGP_IE_RIM_ROUTING_INFO));
		if (rc < 0) {
			LOGP(DLBSSGP, LOGL_ERROR, "BSSGP RIM (NSEI=%u) invalid Destination Cell Identifier IE\n", nsei);
			return -EINVAL;
		}
	} else {
		LOGP(DLBSSGP, LOGL_ERROR, "BSSGP RIM (NSEI=%u) missing Source Cell Identifier IE\n", nsei);
		return -EINVAL;
	}

	if (TLVP_PRESENT(&tp[0], BSSGP_IE_RI_REQ_RIM_CONTAINER))
		pdu->rim_cont_iei = BSSGP_IE_RI_REQ_RIM_CONTAINER;
	else if (TLVP_PRESENT(&tp[0], BSSGP_IE_RI_RIM_CONTAINER))
		pdu->rim_cont_iei = BSSGP_IE_RI_RIM_CONTAINER;
	else if (TLVP_PRESENT(&tp[0], BSSGP_IE_RI_APP_ERROR_RIM_CONT))
		pdu->rim_cont_iei = BSSGP_IE_RI_APP_ERROR_RIM_CONT;
	else if (TLVP_PRESENT(&tp[0], BSSGP_IE_RI_ACK_RIM_CONTAINER))
		pdu->rim_cont_iei = BSSGP_IE_RI_ACK_RIM_CONTAINER;
	else if (TLVP_PRESENT(&tp[0], BSSGP_IE_RI_ERROR_RIM_COINTAINER))
		pdu->rim_cont_iei = BSSGP_IE_RI_ERROR_RIM_COINTAINER;
	else {
		LOGP(DLBSSGP, LOGL_ERROR, "BSSGP RIM (NSEI=%u) missing or wrong RIM Container IE\n", nsei);
		return -EINVAL;
	}

	pdu->rim_cont = TLVP_VAL(&tp[0], pdu->rim_cont_iei);
	pdu->rim_cont_len = TLVP_LEN(&tp[0], pdu->rim_cont_iei);

	/* Make sure the rim container field is not empty */
	if (pdu->rim_cont_len < 1)
		return -EINVAL;
	if (!pdu->rim_cont)
		return -EINVAL;

	/* Note: It is not an error if we fail to parse the RIM container,
	 * since there are applications where parsing the RIM container
	 * is not necessary (routing). It is up to the API user to check
	 * the results. */
	switch (pdu->rim_cont_iei) {
	case BSSGP_IE_RI_REQ_RIM_CONTAINER:
		rc = bssgp_dec_ran_inf_req_rim_cont(&pdu->decoded.req_rim_cont, pdu->rim_cont, pdu->rim_cont_len);
		break;
	case BSSGP_IE_RI_RIM_CONTAINER:
		rc = bssgp_dec_ran_inf_rim_cont(&pdu->decoded.rim_cont, pdu->rim_cont, pdu->rim_cont_len);
		break;
	case BSSGP_IE_RI_APP_ERROR_RIM_CONT:
		rc = bssgp_dec_ran_inf_app_err_rim_cont(&pdu->decoded.app_err_rim_cont, pdu->rim_cont,
							pdu->rim_cont_len);
		break;
	case BSSGP_IE_RI_ACK_RIM_CONTAINER:
		rc = bssgp_dec_ran_inf_ack_rim_cont(&pdu->decoded.ack_rim_cont, pdu->rim_cont, pdu->rim_cont_len);
		break;
	case BSSGP_IE_RI_ERROR_RIM_COINTAINER:
		rc = bssgp_dec_ran_inf_err_rim_cont(&pdu->decoded.err_rim_cont, pdu->rim_cont, pdu->rim_cont_len);
		break;
	default:
		LOGP(DLBSSGP, LOGL_DEBUG, "BSSGP RIM (NSEI=%u) cannot parse unknown RIM container.\n", nsei);
		return 0;
	}
	if (rc < 0) {
		LOGP(DLBSSGP, LOGL_DEBUG, "BSSGP RIM (NSEI=%u) unable to parse RIM container.\n", nsei);
		return 0;
	}
	pdu->decoded_present = true;

	return 0;
}

/*! Encode a given rim-pdu struct into a message buffer.
 *  \param[out] pdu user provided memory that contains the RAN INFORMATION PDU to encode.
 *  \returns BSSGP message buffer on sccess, NULL on error. */
struct msgb *bssgp_encode_rim_pdu(const struct bssgp_ran_information_pdu *pdu)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;
	uint8_t rim_ri_buf[BSSGP_RIM_ROUTING_INFO_MAXLEN];
	int rc;

	if (!msg)
		return NULL;
	bgph = (struct bssgp_normal_hdr *)msgb_put(msg, sizeof(*bgph));

	/* Set PDU type based on RIM container type */
	switch (pdu->rim_cont_iei) {
	case BSSGP_IE_RI_REQ_RIM_CONTAINER:
		bgph->pdu_type = BSSGP_PDUT_RAN_INFO_REQ;
		break;
	case BSSGP_IE_RI_RIM_CONTAINER:
		bgph->pdu_type = BSSGP_PDUT_RAN_INFO;
		break;
	case BSSGP_IE_RI_APP_ERROR_RIM_CONT:
		bgph->pdu_type = BSSGP_PDUT_RAN_INFO_APP_ERROR;
		break;
	case BSSGP_IE_RI_ACK_RIM_CONTAINER:
		bgph->pdu_type = BSSGP_PDUT_RAN_INFO_ACK;
		break;
	case BSSGP_IE_RI_ERROR_RIM_COINTAINER:
		bgph->pdu_type = BSSGP_PDUT_RAN_INFO_ERROR;
		break;
	default:
		/* The caller must correctly specify the container type! */
		OSMO_ASSERT(false);
	}

	/* Put RIM routing information */
	rc = bssgp_create_rim_ri(rim_ri_buf, &pdu->routing_info_dest);
	if (rc < 0 || rc > BSSGP_RIM_ROUTING_INFO_MAXLEN)
		goto error;
	msgb_tvlv_put(msg, BSSGP_IE_RIM_ROUTING_INFO, rc, rim_ri_buf);
	rc = bssgp_create_rim_ri(rim_ri_buf, &pdu->routing_info_src);
	if (rc < 0 || rc > BSSGP_RIM_ROUTING_INFO_MAXLEN)
		goto error;
	msgb_tvlv_put(msg, BSSGP_IE_RIM_ROUTING_INFO, rc, rim_ri_buf);

	/* Put RIM container */
	if (pdu->decoded_present) {
		uint8_t *rim_cont_buf = talloc_zero_size(msg, msg->data_len);
		if (!rim_cont_buf)
			goto error;

		switch (pdu->rim_cont_iei) {
		case BSSGP_IE_RI_REQ_RIM_CONTAINER:
			rc = bssgp_enc_ran_inf_req_rim_cont(rim_cont_buf, msg->data_len, &pdu->decoded.req_rim_cont);
			break;
		case BSSGP_IE_RI_RIM_CONTAINER:
			rc = bssgp_enc_ran_inf_rim_cont(rim_cont_buf, msg->data_len, &pdu->decoded.rim_cont);
			break;
		case BSSGP_IE_RI_APP_ERROR_RIM_CONT:
			rc = bssgp_enc_ran_inf_app_err_rim_cont(rim_cont_buf, msg->data_len,
								&pdu->decoded.app_err_rim_cont);
			break;
		case BSSGP_IE_RI_ACK_RIM_CONTAINER:
			rc = bssgp_enc_ran_inf_ack_rim_cont(rim_cont_buf, msg->data_len, &pdu->decoded.ack_rim_cont);
			break;
		case BSSGP_IE_RI_ERROR_RIM_COINTAINER:
			rc = bssgp_enc_ran_inf_err_rim_cont(rim_cont_buf, msg->data_len, &pdu->decoded.err_rim_cont);
			break;
		default:
			/* The API user must set the iei properly! */
			OSMO_ASSERT(false);
		}
		if (rc < 0) {
			talloc_free(rim_cont_buf);
			goto error;
		}

		msgb_tvlv_put(msg, pdu->rim_cont_iei, rc, rim_cont_buf);
		talloc_free(rim_cont_buf);
	} else {
		/* Make sure the RIM container is actually present. */
		OSMO_ASSERT(pdu->rim_cont_iei != 0 && pdu->rim_cont_len > 0 && pdu->rim_cont);
		msgb_tvlv_put(msg, pdu->rim_cont_iei, pdu->rim_cont_len, pdu->rim_cont);
	}

	return msg;
error:
	msgb_free(msg);
	return 0;
}

/*! Send RIM RAN INFORMATION REQUEST via BSSGP (3GPP TS 48.018, section 10.6.1).
 *  \param[in] pdu user provided memory for the RAN INFORMATION PDU to be sent.
 *  \param[in] nsei BSSGP network service entity identifier (NSEI).
 *  \returns 0 on sccess, -EINVAL on error. */
int bssgp_tx_rim(const struct bssgp_ran_information_pdu *pdu, uint16_t nsei)
{
	struct msgb *msg;
	struct bssgp_normal_hdr *bgph;
	char ri_src_str[64];
	char ri_dest_str[64];

	/* Encode RIM PDU into mesage buffer */
	msg = bssgp_encode_rim_pdu(pdu);
	if (!msg) {
		LOGP(DLBSSGP, LOGL_ERROR,
		     "BSSGP RIM (NSEI=%u) unable to encode BSSGP RIM PDU\n", nsei);
		return -EINVAL;
	}

	msgb_nsei(msg) = nsei;
	msgb_bvci(msg) = 0;	/* Signalling */

	bgph = (struct bssgp_normal_hdr *)msgb_bssgph(msg);
	DEBUGP(DLBSSGP, "BSSGP BVCI=0 Tx RIM-PDU:%s, src=%s, dest=%s\n",
	       bssgp_pdu_str(bgph->pdu_type),
	       bssgp_rim_ri_name_buf(ri_src_str, sizeof(ri_src_str), &pdu->routing_info_src),
	       bssgp_rim_ri_name_buf(ri_dest_str, sizeof(ri_dest_str), &pdu->routing_info_dest));

	return bssgp_ns_send(bssgp_ns_send_data, msg);
}

/* For internal use only (called from gprs_bssgp.c) */
int bssgp_rx_rim(struct msgb *msg, struct tlv_parsed *tp, uint16_t bvci)
{
	struct osmo_bssgp_prim nmp;
	uint16_t nsei = msgb_nsei(msg);
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *)msgb_bssgph(msg);
	enum bssgp_prim prim;
	char ri_src_str[64];
	char ri_dest_str[64];

	/* Specify PRIM type based on the RIM PDU */
	switch (bgph->pdu_type) {
	case BSSGP_PDUT_RAN_INFO:
	case BSSGP_PDUT_RAN_INFO_REQ:
	case BSSGP_PDUT_RAN_INFO_ACK:
	case BSSGP_PDUT_RAN_INFO_ERROR:
	case BSSGP_PDUT_RAN_INFO_APP_ERROR:
		prim = PRIM_BSSGP_RIM_PDU_TRANSFER;
		break;
	default:
		/* Caller already makes sure that this can't happen. */
		OSMO_ASSERT(false);
	}

	/* Send BSSGP RIM indication to NM */
	memset(&nmp, 0, sizeof(nmp));
	nmp.nsei = nsei;
	nmp.bvci = bvci;
	nmp.tp = tp;
	if (bssgp_parse_rim_pdu(&nmp.u.rim_pdu, msg) < 0)
		return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
	DEBUGP(DLBSSGP, "BSSGP BVCI=%u Rx RIM-PDU:%s, src=%s, dest=%s\n",
	       bvci, bssgp_pdu_str(bgph->pdu_type),
	       bssgp_rim_ri_name_buf(ri_src_str, sizeof(ri_src_str), &nmp.u.rim_pdu.routing_info_src),
	       bssgp_rim_ri_name_buf(ri_dest_str, sizeof(ri_dest_str), &nmp.u.rim_pdu.routing_info_dest));
	osmo_prim_init(&nmp.oph, SAP_BSSGP_RIM, prim, PRIM_OP_INDICATION, msg);
	bssgp_prim_cb(&nmp.oph, NULL);

	return 0;
}
