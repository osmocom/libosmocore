/* 3GPP TS 49.031 BSSMAP-LE protocol definitions */
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

#include <string.h>

#include <osmocom/core/byteswap.h>
#include <osmocom/core/endian.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/bssmap_le.h>
#include <osmocom/gsm/bsslap.h>
#include <osmocom/gsm/gad.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0808.h>

/*! \addtogroup bssmap_le
 *  @{
 *  \file bssmap_le.c
 *  Message encoding and decoding for 3GPP TS 49.031 BSSMAP-LE.
 */

#define BSSAP_LE_MSG_SIZE BSSMAP_MSG_SIZE
#define BSSAP_LE_MSG_HEADROOM BSSMAP_MSG_HEADROOM

static const struct tlv_definition osmo_bssmap_le_tlvdef = {
	.def = {
	[BSSMAP_LE_IEI_LCS_QoS] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_LCS_PRIORITY] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_LOCATION_TYPE] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_GANSS_LOCATION_TYPE] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_GEO_LOCATION] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_POSITIONING_DATA] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_GANSS_POS_DATA] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_VELOCITY_DATA] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_LCS_CAUSE] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_LCS_CLIENT_TYPE] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_APDU] = { TLV_TYPE_TL16V },
	[BSSMAP_LE_IEI_NET_ELEM_ID] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_REQ_GPS_ASS_D] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_REQ_GANSS_ASS_D] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_DECIPH_KEYS] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_RET_ERR_REQ] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_RET_ERR_CAUSE] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_SEGMENTATION] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_CLASSMARK3_INFO] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_CAUSE] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_CELL_ID] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_CHOSEN_CHAN] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_IMSI] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_LCS_CAPABILITY] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_PKT_MEAS_REP] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_CELL_ID_LIST] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_IMEI] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_BSS_MLAT_CAP] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_CELL_INFO_LIST] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_BTS_RX_ACC_LVL] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_MLAT_METHOD] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_MLAT_TA] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_MS_SYNC_ACC] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_SHORT_ID_SET] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_RANDOM_ID_SET] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_SHORT_BSS_ID] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_RANDOM_ID] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_SHORT_ID] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_COVERAGE_CLASS] = { TLV_TYPE_TLV },
	[BSSMAP_LE_IEI_MTA_ACC_SEC_RQD] = { TLV_TYPE_TLV },
	},
};

#define DEC_ERR_NO_RETURN(RC, MSG_TYPE, IEI, CAUSE, fmt, args...) do { \
		if (err && !*err) { \
			*err = talloc_zero(err_ctx, struct osmo_bssmap_le_err); \
			**err = (struct osmo_bssmap_le_err){ \
				.rc = (RC), \
				.msg_type = (MSG_TYPE), \
				.iei = (IEI), \
				.cause = (CAUSE), \
			}; \
			(*err)->logmsg = talloc_asprintf(*err, "Error decoding BSSMAP-LE%s%s%s%s%s: " fmt, \
							 (MSG_TYPE) >= 0 ? " " : "", \
							 (MSG_TYPE) >= 0 ? osmo_bssmap_le_msgt_name(MSG_TYPE) : "", \
							 (IEI) >= 0 ? ": " : "", \
							 (IEI) >= 0 ? osmo_bssmap_le_iei_name(IEI) : "", \
							 (IEI) >= 0 ? " IE" : "", \
							 ##args); \
		} \
	} while(0)

#define DEC_ERR(RC, MSG_TYPE, IEI, CAUSE, fmt, args...) do { \
		DEC_ERR_NO_RETURN(RC, MSG_TYPE, IEI, CAUSE, fmt, ##args); \
		return RC; \
	} while(0)

#define DEC_IE_MANDATORY(MSG_TYPE, IEI, DEC_FUN, DEC_FUN_ARG) do { \
		const struct tlv_p_entry *e; \
		int rc; \
		if (!(e = TLVP_GET(tp, IEI))) \
			DEC_ERR(-EINVAL, MSG_TYPE, IEI, LCS_CAUSE_DATA_MISSING_IN_REQ, "missing mandatory IE"); \
		rc = DEC_FUN(DEC_FUN_ARG, MSG_TYPE, IEI, err, err_ctx, e->val, e->len); \
		if (rc) \
			DEC_ERR(rc, MSG_TYPE, IEI, LCS_CAUSE_UNSPECIFIED, "cannot parse IE"); \
	} while (0)

#define DEC_IE_OPTIONAL_FLAG(MSG_TYPE, IEI, DEC_FUN, DEC_FUN_ARG, PRESENCE_FLAG) do { \
		const struct tlv_p_entry *e; \
		int rc; \
		if ((e = TLVP_GET(tp, IEI))) {\
			rc = DEC_FUN(DEC_FUN_ARG, MSG_TYPE, IEI, err, err_ctx, e->val, e->len); \
			if (rc) \
				DEC_ERR(rc, MSG_TYPE, IEI, LCS_CAUSE_UNSPECIFIED, "cannot parse IE"); \
			PRESENCE_FLAG = true; \
		} \
	} while (0)

#define DEC_IE_OPTIONAL(MSG_TYPE, IEI, DEC_FUN, DEC_FUN_ARG) do { \
		const struct tlv_p_entry *e; \
		int rc; \
		if ((e = TLVP_GET(tp, IEI))) {\
			rc = DEC_FUN(DEC_FUN_ARG, MSG_TYPE, IEI, err, err_ctx, e->val, e->len); \
			if (rc) \
				DEC_ERR(rc, MSG_TYPE, IEI, LCS_CAUSE_UNSPECIFIED, "cannot parse IE"); \
		} \
	} while (0)

/*! Encode full BSSMAP-LE Location Type IE, including IEI tag and length.
 * \param[inout] msg  Message buffer to append to.
 * \param[in] location_type  Values to enconde.
 * \returns length of bytes written to the msgb.
 */
uint8_t osmo_bssmap_le_ie_enc_location_type(struct msgb *msg,
					    const struct bssmap_le_location_type *location_type)
{
	uint8_t *old_tail;
	uint8_t *tlv_len;
	OSMO_ASSERT(msg);
	msgb_put_u8(msg, BSSMAP_LE_IEI_LOCATION_TYPE);
	tlv_len = msgb_put(msg, 1);
	old_tail = msg->tail;
	msgb_put_u8(msg, location_type->location_information);

	switch (location_type->location_information) {
	case BSSMAP_LE_LOC_INFO_ASSIST_TARGET_MS:
	case BSSMAP_LE_LOC_INFO_BC_DECIPHER_KEYS:
		msgb_put_u8(msg, location_type->positioning_method);
		break;
	default:
		break;
	}

	*tlv_len = (uint8_t) (msg->tail - old_tail);
	return *tlv_len + 2;
}

/*! Decode BSSMAP-LE Location Type IE value part.
 * \param[out] lt  Buffer to write decoded values to.
 * \param[in] elem  Pointer to the value part, the V of a TLV.
 * \param[in] len  Length, the L of a TLV.
 * \returns 0 on success, negative on error; lt is always overwritten: cleared on error, populated with values on
 * success.
 */
int osmo_bssmap_le_ie_dec_location_type(struct bssmap_le_location_type *lt,
					enum bssmap_le_msgt msgt, enum bssmap_le_iei iei,
					struct osmo_bssmap_le_err **err, void *err_ctx,
					const uint8_t *elem, uint8_t len)
{
	*lt = (struct bssmap_le_location_type){};

	if (!elem || len < 1)
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "zero length");

	lt->location_information = elem[0];
	switch (lt->location_information) {

	case BSSMAP_LE_LOC_INFO_CURRENT_GEOGRAPHIC:
		if (len != 1)
			DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED,
				"location info type 'Current Geographic': length should be 1 byte, got %u", len);
		lt->positioning_method = BSSMAP_LE_POS_METHOD_OMITTED;
		return 0;

	case BSSMAP_LE_LOC_INFO_ASSIST_TARGET_MS:
	case BSSMAP_LE_LOC_INFO_BC_DECIPHER_KEYS:
		if (len != 2)
			DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED,
				"location info type %d: length should be 2 bytes, got %u",
				lt->location_information, len);
		lt->positioning_method = elem[1];
		switch (lt->positioning_method) {
		case BSSMAP_LE_POS_METHOD_MOBILE_ASSISTED_E_OTD:
		case BSSMAP_LE_POS_METHOD_MOBILE_BASED_E_OTD:
		case BSSMAP_LE_POS_METHOD_ASSISTED_GPS:
			return 0;
		default:
			DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED,
				"location info type %d: unknown Positioning Method: %d",
				lt->location_information, lt->positioning_method);
		}

	default:
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "unknown location info type %d",
			lt->location_information);
	}
}

/*! Encode full BSSMAP-LE LCS Client Type IE, including IEI tag and length.
 * \param[inout] msg  Message buffer to append to.
 * \param[in] client_type  Value to enconde.
 * \returns length of bytes written to the msgb.
 */
static uint8_t osmo_bssmap_le_ie_enc_lcs_client_type(struct msgb *msg, enum bssmap_le_lcs_client_type client_type)
{
	OSMO_ASSERT(msg);
	msgb_put_u8(msg, BSSMAP_LE_IEI_LCS_CLIENT_TYPE);
	/* length */
	msgb_put_u8(msg, 1);
	msgb_put_u8(msg, client_type);
	return 3;
}

static int osmo_bssmap_le_ie_dec_lcs_client_type(enum bssmap_le_lcs_client_type *client_type,
						 enum bssmap_le_msgt msgt, enum bssmap_le_iei iei,
						 struct osmo_bssmap_le_err **err, void *err_ctx,
						 const uint8_t *elem, uint8_t len)
{
	*client_type = 0;

	if (!elem || len < 1)
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "zero length");

	*client_type = elem[0];

	switch (*client_type) {
	case BSSMAP_LE_LCS_CTYPE_VALUE_ADDED_UNSPECIFIED:
	case BSSMAP_LE_LCS_CTYPE_PLMN_OPER_UNSPECIFIED:
	case BSSMAP_LE_LCS_CTYPE_PLMN_OPER_BCAST_SERVICE:
	case BSSMAP_LE_LCS_CTYPE_PLMN_OPER_OAM:
	case BSSMAP_LE_LCS_CTYPE_PLMN_OPER_ANON_STATS:
	case BSSMAP_LE_LCS_CTYPE_PLMN_OPER_TGT_MS_SVC:
	case BSSMAP_LE_LCS_CTYPE_EMERG_SVC_UNSPECIFIED:
	case BSSMAP_LE_LCS_CTYPE_LI_UNSPECIFIED:
		return 0;
	default:
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "unknown LCS Client Type: %d", *client_type);
	}
}

/*! Encode full BSSMAP-LE LCS Priority IE, including IEI tag and length.
 * \param[inout] msg  Message buffer to append to.
 * \param[in] priority  Value to enconde.
 * \returns length of bytes written to the msgb.
 */
static uint8_t osmo_bssmap_le_ie_enc_lcs_priority(struct msgb *msg, uint8_t priority)
{
	OSMO_ASSERT(msg);
	msgb_put_u8(msg, BSSMAP_LE_IEI_LCS_PRIORITY);
	/* length */
	msgb_put_u8(msg, 1);
	msgb_put_u8(msg, priority);
	return 3;
}

static int osmo_bssmap_le_ie_dec_lcs_priority(uint8_t *priority,
					      enum bssmap_le_msgt msgt, enum bssmap_le_iei iei,
					      struct osmo_bssmap_le_err **err, void *err_ctx,
					      const uint8_t *elem, uint8_t len)
{
	if (!elem || len != 1)
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "unexpected length");

	*priority = elem[0];
	return 0;
}

/*! Encode full BSSMAP-LE LCS QoS IE, including IEI tag and length.
 * \param[inout] msg  Message buffer to append to.
 * \param[in] priority  Value to enconde.
 * \returns length of bytes written to the msgb.
 */
static uint8_t osmo_bssmap_le_ie_enc_lcs_qos(struct msgb *msg, const struct osmo_bssmap_le_lcs_qos *qos)
{
	OSMO_ASSERT(msg);
	msgb_tlv_put(msg, BSSMAP_LE_IEI_LCS_QoS, sizeof(*qos), (const uint8_t *)qos);
	return 2 + sizeof(*qos);
}

static int osmo_bssmap_le_ie_dec_lcs_qos(struct osmo_bssmap_le_lcs_qos *qos,
					 enum bssmap_le_msgt msgt, enum bssmap_le_iei iei,
					 struct osmo_bssmap_le_err **err, void *err_ctx,
					 const uint8_t *elem, uint8_t len)
{
	if (!elem || len != sizeof(*qos))
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "unexpected length");

	memcpy(qos, elem, len);
	return 0;
}

/*! Encode the value part of 3GPP TS 49.031 10.13 LCS Cause, without IEI and len.
 * Identically used in 3GPP TS 48.008 3.2.2.66. Usage example:
 *
 *  uint8_t *l = msgb_tl_put(msg, BSSMAP_LE_IEI_LCS_CAUSE);
 *  int rc = osmo_lcs_cause_enc(msg, &lcs_cause);
 *  if (rc < 0)
 *      goto error;
 *  *l = rc;
 *
 * \param[inout] msg  Message buffer to append the LCS Cause values to.
 * \param[in] lcs_cause  LCS Cause values to enconde.
 * \returns length of bytes written to the msgb.
 */
int osmo_lcs_cause_enc(struct msgb *msg, const struct lcs_cause_ie *lcs_cause)
{
	msgb_put_u8(msg, lcs_cause->cause_val);
	if (lcs_cause->cause_val == LCS_CAUSE_POS_METH_FAILURE && lcs_cause->diag_val_present) {
		msgb_put_u8(msg, lcs_cause->diag_val);
		return 2;
	}
	return 1;
}

/*! Decode the value part of 3GPP TS 49.031 10.13 LCS Cause, without IEI and len.
 * Identically used in 3GPP TS 48.008 3.2.2.66.
 *
 * \param[out] lcs_cause  Write decoded LCS Cause values here.
 * \param[in] data  Encoded cause bytes.
 * \param[in] len  Length of data in bytes.
 * \returns 0 on success, negative on error.
 */
int osmo_lcs_cause_dec(struct lcs_cause_ie *lcs_cause,
		       enum bssmap_le_msgt msgt, enum bssmap_le_iei iei,
		       struct osmo_bssmap_le_err **err, void *err_ctx,
		       const uint8_t *data, uint8_t len)
{
	*lcs_cause = (struct lcs_cause_ie){};

	if (!data || len < 1)
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "zero length");

	lcs_cause->present = true;
	lcs_cause->cause_val = data[0];
	if (len > 1) {
		lcs_cause->diag_val_present = true;
		lcs_cause->diag_val = data[1];
	}
	if (len > 2)
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "expected length <= 2, got %u", len);

	return 0;
}

static int osmo_bssmap_le_ie_enc_apdu(struct msgb *msg, const struct bsslap_pdu *bsslap)
{
	uint8_t *old_tail;
	void *l;
	msgb_put_u8(msg, BSSMAP_LE_IEI_APDU);
	l = msgb_put(msg, 2);
	old_tail = msg->tail;
	msgb_put_u8(msg, BSSMAP_LE_APDU_PROT_BSSLAP);
	int rc = osmo_bsslap_enc(msg, bsslap);
	if (rc <= 0)
		return -EINVAL;
	osmo_store16be(msg->tail - old_tail, l);
	return 0;
}

static int osmo_bssmap_le_ie_dec_apdu(struct bsslap_pdu *bsslap,
				      enum bssmap_le_msgt msgt, enum bssmap_le_iei iei,
				      struct osmo_bssmap_le_err **err, void *err_ctx,
				      const uint8_t *data, size_t len)
{
	enum bssmap_le_apdu_proto proto;
	struct osmo_bsslap_err *bsslap_err;

	if (!data || len < 1)
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "zero length");

	proto = data[0];

	switch (proto) {
	case BSSMAP_LE_APDU_PROT_BSSLAP:
		if (osmo_bsslap_dec(bsslap, &bsslap_err, err_ctx, data + 1, len - 1)) {
			DEC_ERR_NO_RETURN(bsslap_err ? bsslap_err->rc : -EINVAL,
					  msgt, iei, LCS_CAUSE_UNSPECIFIED,
					  "Error decoding BSSLAP%s%s",
					  bsslap_err && bsslap_err->logmsg ? ": " : "",
					  bsslap_err && bsslap_err->logmsg ? bsslap_err->logmsg : "");
			(*err)->bsslap_err = bsslap_err;
			return (*err)->rc;
		}
		return 0;
	case BSSMAP_LE_APDU_PROT_LLP:
	case BSSMAP_LE_APDU_PROT_SMLCPP:
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "Unimplemented APDU type: %d", proto);
	default:
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "Invalid APDU type: %d", proto);
	}
}

static int osmo_bssmap_le_ie_dec_cell_id(struct gsm0808_cell_id *cell_id,
					 enum bssmap_le_msgt msgt, enum bssmap_le_iei iei,
					 struct osmo_bssmap_le_err **err, void *err_ctx,
					 const uint8_t *elem, uint8_t len)
{
	int rc;
	rc = gsm0808_dec_cell_id(cell_id, elem, len);
	if (rc <= 0)
		DEC_ERR(rc, msgt, iei, LCS_CAUSE_UNSPECIFIED, "Error decoding Cell Identifier %s",
			osmo_hexdump_c(err_ctx, elem, len));
	return 0;
}

static int osmo_bssmap_le_ie_dec_imsi(struct osmo_mobile_identity *imsi,
				      enum bssmap_le_msgt msgt, enum bssmap_le_iei iei,
				      struct osmo_bssmap_le_err **err, void *err_ctx,
				      const uint8_t *elem, uint8_t len)
{
	int rc;
	rc = osmo_mobile_identity_decode(imsi, elem, len, false);
	if (rc || imsi->type != GSM_MI_TYPE_IMSI)
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED,
			"cannot parse IMSI identity %s", osmo_hexdump_c(err_ctx, elem, len));
	return 0;
}

static int osmo_bssmap_le_ie_dec_imei(struct osmo_mobile_identity *imei,
				      enum bssmap_le_msgt msgt, enum bssmap_le_iei iei,
				      struct osmo_bssmap_le_err **err, void *err_ctx,
				      const uint8_t *elem, uint8_t len)
{
	int rc;
	rc = osmo_mobile_identity_decode(imei, elem, len, false);
	if (rc || imei->type != GSM_MI_TYPE_IMEI)
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED,
			"cannot parse IMEI identity %s", osmo_hexdump_c(err_ctx, elem, len));
	return 0;
}

static int osmo_bssmap_le_ie_dec_gad(union gad_raw *gad,
				     enum bssmap_le_msgt msgt, enum bssmap_le_iei iei,
				     struct osmo_bssmap_le_err **err, void *err_ctx,
				     const uint8_t *elem, uint8_t len)
{
	struct osmo_gad_err *gad_err;
	if (osmo_gad_raw_read(gad, &gad_err, err_ctx, elem, len)) {
		DEC_ERR_NO_RETURN(gad_err ? gad_err->rc : -EINVAL,
				  msgt, BSSMAP_LE_IEI_GEO_LOCATION, LCS_CAUSE_UNSPECIFIED,
				  "Error decoding GAD%s%s",
				  gad_err && gad_err->logmsg ? ": " : "",
				  gad_err && gad_err->logmsg ? gad_err->logmsg : "");
		(*err)->gad_err = gad_err;
		return (*err)->rc;
	}
	return 0;
}

struct osmo_bssap_le_header {
	uint8_t type;
	uint8_t length;
	uint8_t data[0];
} __attribute__((packed));

/*! Return the BSSMAP-LE msg_type from a BSSAP-LE PDU, e.g. from a msgb_l3().
 * \param[in] data  BSSAP-LE PDU data, starting with BSSAP-LE discriminator.
 * \param[in] len  Length of data in bytes.
 * \returns bssmap_le_msgt or negative on error or non-BSSMAP-LE discriminator. */
enum bssmap_le_msgt osmo_bssmap_le_msgt(const uint8_t *data, uint8_t len)
{
	const struct osmo_bssap_le_header *h = (void*)data;
	if (!data || len < sizeof(struct osmo_bssap_le_header) + 1)
		return -1;
	if (h->type != BSSAP_LE_MSG_DISCR_BSSMAP_LE)
		return -1;
	return h->data[0];
}

static int osmo_bssmap_le_enc_reset(struct msgb *msg, enum gsm0808_cause cause)
{
	/* The BSSMAP-LE Reset Cause is defined as identical to the 3GPP TS 48.008 Cause. */
	gsm0808_enc_cause(msg, cause);
	return 0;
}

static int osmo_bssmap_le_dec_reset(enum gsm0808_cause *cause,
				    enum bssmap_le_msgt msgt,
				    struct osmo_bssmap_le_err **err, void *err_ctx,
				    const struct tlv_parsed *tp)
{
	const struct tlv_p_entry *e;

	if (!(e = TLVP_GET(tp, BSSMAP_LE_IEI_CAUSE)))
		DEC_ERR(-EINVAL, msgt, BSSMAP_LE_IEI_CAUSE, LCS_CAUSE_DATA_MISSING_IN_REQ, "missing mandatory IE");

	*cause = gsm0808_get_cause(tp);
	if (*cause < 0)
		DEC_ERR(-EINVAL, msgt, BSSMAP_LE_IEI_CAUSE, LCS_CAUSE_UNSPECIFIED, "cannot parse IE");

	return 0;
}

static int osmo_bssmap_le_enc_perform_loc_req(struct msgb *msg, const struct bssmap_le_perform_loc_req *params)
{
	osmo_bssmap_le_ie_enc_location_type(msg, &params->location_type);

	gsm0808_enc_cell_id(msg, &params->cell_id);

	if (params->lcs_client_type_present)
		osmo_bssmap_le_ie_enc_lcs_client_type(msg, params->lcs_client_type);

	if (params->more_items && params->lcs_priority_present)
		osmo_bssmap_le_ie_enc_lcs_priority(msg, params->lcs_priority);

	if (params->more_items && params->lcs_qos_present)
		osmo_bssmap_le_ie_enc_lcs_qos(msg, &params->lcs_qos);

	if (params->apdu_present) {
		int rc = osmo_bssmap_le_ie_enc_apdu(msg, &params->apdu);
		if (rc < 0)
			return rc;
	}

	if (params->imsi.type == GSM_MI_TYPE_IMSI) {
		uint8_t *l = msgb_tl_put(msg, BSSMAP_LE_IEI_IMSI);
		int rc = osmo_mobile_identity_encode_msgb(msg, &params->imsi, false);
		if (rc < 0)
			return rc;
		*l = rc;
	}

	if (params->imei.type == GSM_MI_TYPE_IMEI) {
		uint8_t *l = msgb_tl_put(msg, BSSMAP_LE_IEI_IMEI);
		int rc = osmo_mobile_identity_encode_msgb(msg, &params->imei, false);
		if (rc < 0)
			return rc;
		*l = rc;
	}
	return 0;
}

static int osmo_bssmap_le_dec_perform_loc_req(struct bssmap_le_perform_loc_req *params,
					      enum bssmap_le_msgt msgt,
					      struct osmo_bssmap_le_err **err, void *err_ctx,
					      const struct tlv_parsed *tp)
{
	*params = (struct bssmap_le_perform_loc_req){};

	DEC_IE_MANDATORY(msgt, BSSMAP_LE_IEI_LOCATION_TYPE, osmo_bssmap_le_ie_dec_location_type,
			 &params->location_type);
	DEC_IE_MANDATORY(msgt, BSSMAP_LE_IEI_CELL_ID, osmo_bssmap_le_ie_dec_cell_id,
			 &params->cell_id);
	DEC_IE_OPTIONAL_FLAG(msgt, BSSMAP_LE_IEI_LCS_CLIENT_TYPE, osmo_bssmap_le_ie_dec_lcs_client_type,
			&params->lcs_client_type, params->lcs_client_type_present);
	DEC_IE_OPTIONAL_FLAG(msgt, BSSMAP_LE_IEI_LCS_PRIORITY, osmo_bssmap_le_ie_dec_lcs_priority,
			&params->lcs_priority, params->lcs_priority_present);
	DEC_IE_OPTIONAL_FLAG(msgt, BSSMAP_LE_IEI_LCS_QoS, osmo_bssmap_le_ie_dec_lcs_qos,
			&params->lcs_qos, params->lcs_qos_present);
	DEC_IE_OPTIONAL_FLAG(msgt, BSSMAP_LE_IEI_APDU, osmo_bssmap_le_ie_dec_apdu, &params->apdu,
			params->apdu_present);
	DEC_IE_OPTIONAL(msgt, BSSMAP_LE_IEI_IMSI, osmo_bssmap_le_ie_dec_imsi, &params->imsi);
	DEC_IE_OPTIONAL(msgt, BSSMAP_LE_IEI_IMEI, osmo_bssmap_le_ie_dec_imei, &params->imei);

	if (params->lcs_priority_present || params->lcs_qos_present)
		params->more_items = true;

	return 0;
}

static int osmo_bssmap_le_enc_perform_loc_resp(struct msgb *msg, const struct bssmap_le_perform_loc_resp *params)
{
	if (params->location_estimate_present) {
		uint8_t *l = msgb_tl_put(msg, BSSMAP_LE_IEI_GEO_LOCATION);
		int rc = osmo_gad_raw_write(msg, &params->location_estimate);
		if (rc < 0)
			return rc;
		*l = rc;
	}

	if (params->lcs_cause.present) {
		uint8_t *l = msgb_tl_put(msg, BSSMAP_LE_IEI_LCS_CAUSE);
		int rc = osmo_lcs_cause_enc(msg, &params->lcs_cause);
		if (rc < 0)
			return rc;
		*l = rc;
	}
	return 0;
}

static int osmo_bssmap_le_dec_perform_loc_resp(struct bssmap_le_perform_loc_resp *params,
					       enum bssmap_le_msgt msgt,
					       struct osmo_bssmap_le_err **err, void *err_ctx,
					       const struct tlv_parsed *tp)
{
	*params = (struct bssmap_le_perform_loc_resp){};

	DEC_IE_OPTIONAL_FLAG(msgt, BSSMAP_LE_IEI_GEO_LOCATION, osmo_bssmap_le_ie_dec_gad, &params->location_estimate,
			     params->location_estimate_present);
	DEC_IE_OPTIONAL(msgt, BSSMAP_LE_IEI_LCS_CAUSE, osmo_lcs_cause_dec, &params->lcs_cause);

	return 0;
}

static int osmo_bssmap_le_enc_perform_loc_abort(struct msgb *msg, const struct lcs_cause_ie *params)
{
	uint8_t *l = msgb_tl_put(msg, BSSMAP_LE_IEI_LCS_CAUSE);
	int rc = osmo_lcs_cause_enc(msg, params);
	if (rc < 0)
		return rc;
	*l = rc;
	return 0;
}

static int osmo_bssmap_le_dec_perform_loc_abort(struct lcs_cause_ie *params,
						enum bssmap_le_msgt msgt,
						struct osmo_bssmap_le_err **err, void *err_ctx,
						const struct tlv_parsed *tp)
{
	*params = (struct lcs_cause_ie){};

	DEC_IE_MANDATORY(msgt, BSSMAP_LE_IEI_LCS_CAUSE, osmo_lcs_cause_dec, params);
	return 0;
}

static int osmo_bssmap_le_enc_conn_oriented_info(struct msgb *msg,
						 const struct bssmap_le_conn_oriented_info *params)
{
	return osmo_bssmap_le_ie_enc_apdu(msg, &params->apdu);
}

static int osmo_bssmap_le_dec_conn_oriented_info(struct bssmap_le_conn_oriented_info *params,
						 enum bssmap_le_msgt msgt,
						 struct osmo_bssmap_le_err **err, void *err_ctx,
						 const struct tlv_parsed *tp)
{
	*params = (struct bssmap_le_conn_oriented_info){};
	DEC_IE_MANDATORY(msgt, BSSMAP_LE_IEI_APDU, osmo_bssmap_le_ie_dec_apdu, &params->apdu);
	return 0;
}

/*! Encode BSSMAP-LE PDU and add to msgb (3GPP TS 49.031).
 * See also osmo_bssap_le_enc().
 * \param[out] msg  msgb to append to.
 * \param[in] pdu  PDU data to encode.
 * \return number of bytes written, negative on error.
 */
static int osmo_bssmap_le_enc(struct msgb *msg, const struct bssmap_le_pdu *pdu)
{
	int rc;
	uint8_t *old_tail;
	old_tail = msg->tail;

	msgb_v_put(msg, pdu->msg_type);

	switch (pdu->msg_type) {
	case BSSMAP_LE_MSGT_RESET:
		rc = osmo_bssmap_le_enc_reset(msg, pdu->reset);
		break;
	case BSSMAP_LE_MSGT_RESET_ACK:
		/* Consists only of the message type. */
		rc = 0;
		break;
	case BSSMAP_LE_MSGT_PERFORM_LOC_REQ:
		rc = osmo_bssmap_le_enc_perform_loc_req(msg, &pdu->perform_loc_req);
		break;
	case BSSMAP_LE_MSGT_PERFORM_LOC_RESP:
		rc = osmo_bssmap_le_enc_perform_loc_resp(msg, &pdu->perform_loc_resp);
		break;
	case BSSMAP_LE_MSGT_PERFORM_LOC_ABORT:
		rc = osmo_bssmap_le_enc_perform_loc_abort(msg, &pdu->perform_loc_abort);
		break;
	case BSSMAP_LE_MSGT_CONN_ORIENTED_INFO:
		rc = osmo_bssmap_le_enc_conn_oriented_info(msg, &pdu->conn_oriented_info);
		break;
	default:
		rc = -ENOTSUP;
	}

	if (rc < 0)
		return rc;

	return (msg->tail - old_tail);
}

/*! Decode BSSMAP-LE PDU (3GPP TS 49.031).
 * See also osmo_bssap_le_dec().
 * \param[out] pdu  Write decoded values here.
 * \param[in] data  Pointer to BSSMAP-LE PDU raw data.
 * \param[in] len  Data length to decode.
 * \return NULL upon success, a human readable error message on failure.
 */
static int osmo_bssmap_le_dec(struct bssmap_le_pdu *pdu,
			      struct osmo_bssmap_le_err **err, void *err_ctx,
			      const uint8_t *data, size_t len)
{
	const uint8_t *ies_start;
	int ies_len;
	struct tlv_parsed tp;

	*pdu = (struct bssmap_le_pdu){};

	if (len < 1)
		DEC_ERR(-EINVAL, -1, -1, LCS_CAUSE_UNSPECIFIED, "zero length");
	pdu->msg_type = data[0];

	/* BSSMAP-LE IEs */
	ies_start = &data[1];
	ies_len = len - 1;

	if (tlv_parse(&tp, &osmo_bssmap_le_tlvdef, ies_start, ies_len, 0, 0) < 0)
		DEC_ERR(-EINVAL, pdu->msg_type, -1, LCS_CAUSE_UNSPECIFIED, "failed to parse TLV structure");

	switch (pdu->msg_type) {
	case BSSMAP_LE_MSGT_RESET:
		return osmo_bssmap_le_dec_reset(&pdu->reset, pdu->msg_type, err, err_ctx, &tp);
	case BSSMAP_LE_MSGT_RESET_ACK:
		/* Consists only of the message type. */
		return 0;
	case BSSMAP_LE_MSGT_PERFORM_LOC_REQ:
		return osmo_bssmap_le_dec_perform_loc_req(&pdu->perform_loc_req, pdu->msg_type, err, err_ctx, &tp);
	case BSSMAP_LE_MSGT_PERFORM_LOC_RESP:
		return osmo_bssmap_le_dec_perform_loc_resp(&pdu->perform_loc_resp, pdu->msg_type, err, err_ctx, &tp);
	case BSSMAP_LE_MSGT_PERFORM_LOC_ABORT:
		return osmo_bssmap_le_dec_perform_loc_abort(&pdu->perform_loc_abort, pdu->msg_type, err, err_ctx, &tp);
	case BSSMAP_LE_MSGT_CONN_ORIENTED_INFO:
		return osmo_bssmap_le_dec_conn_oriented_info(&pdu->conn_oriented_info, pdu->msg_type, err, err_ctx,
							     &tp);
	default:
		DEC_ERR(-EINVAL, pdu->msg_type, -1, LCS_CAUSE_UNSPECIFIED, "Unsupported BSSMAP-LE message type");
	}
}

/*! Encode BSSAP-LE PDU returned in new msgb (3GPP TS 49.031).
 * By spec, BSSAP-LE contains either BSSMAP-LE or DTAP.
 * \param[in] pdu  PDU data to encode.
 * \return msgb with encoded data and l2h set to the start.
 */
struct msgb *osmo_bssap_le_enc(const struct bssap_le_pdu *pdu)
{
	struct msgb *msg;
	int rc;

	if (pdu->discr != BSSAP_LE_MSG_DISCR_BSSMAP_LE)
		return NULL;

	msg = msgb_alloc_headroom(BSSAP_LE_MSG_SIZE, BSSAP_LE_MSG_HEADROOM,
				  osmo_bssmap_le_msgt_name(pdu->bssmap_le.msg_type));
	if (!msg)
		return NULL;

	rc = osmo_bssmap_le_enc(msg, &pdu->bssmap_le);
	if (rc <= 0) {
		msgb_free(msg);
		return NULL;
	}

	/* prepend header with final length */
	msg->l2h = msgb_tv_push(msg, pdu->discr, msgb_length(msg));

	return msg;
}

/*! Decode BSSAP-LE PDU (3GPP TS 49.031).
 * \param[out] pdu  Write decoded values here.
 * \param[in] data  Pointer to BSSMAP-LE PDU raw data.
 * \param[in] len  Data length to decode.
 * \return NULL upon success, a human readable error message on failure.
 */
int osmo_bssap_le_dec(struct bssap_le_pdu *pdu, struct osmo_bssap_le_err **err, void *err_ctx, struct msgb *msg)
{
	struct osmo_bssap_le_header *h;
	unsigned int check_len;
	struct osmo_bssmap_le_err *bssmap_le_err = NULL;
	int rc;

#define BSSAP_LE_DEC_ERR(RC, fmt, args...) do { \
		if (err && !*err) { \
			*err = talloc_zero(err_ctx, struct osmo_bssap_le_err); \
			**err = (struct osmo_bssap_le_err){ \
				.rc = (RC), \
				.logmsg = talloc_asprintf(*err, "Error decoding BSSAP-LE: " fmt, ##args), \
			}; \
		} \
		return RC; \
	} while(0)

	*pdu = (struct bssap_le_pdu){};

	h = msgb_l2(msg);
	if (!h)
		BSSAP_LE_DEC_ERR(-EINVAL, "missing msgb_l2() pointer");
	if (msgb_l2len(msg) < sizeof(*h))
		BSSAP_LE_DEC_ERR(-EINVAL, "message too short for header");
	check_len = msgb_l2len(msg) - sizeof(*h);
	if (h->length < check_len)
		BSSAP_LE_DEC_ERR(-EINVAL, "message truncated, header length (%u) longer than message (%u)",
				 h->length, check_len);

	switch (h->type) {
	case BSSAP_LE_MSG_DISCR_BSSMAP_LE:
		break;
	default:
		BSSAP_LE_DEC_ERR(-EINVAL, "unsupported discr %u, only BSSMAP-LE is implemented", h->type);
	}

	rc = osmo_bssmap_le_dec(&pdu->bssmap_le, err ? &bssmap_le_err : NULL, err_ctx,
				h->data, h->length);
	if (rc)
		BSSAP_LE_DEC_ERR(rc, "%s",
				 (bssmap_le_err && bssmap_le_err->logmsg) ?
					 bssmap_le_err->logmsg : "unknown error in BSSMAP-LE part");
	return 0;
}

const struct value_string osmo_bssmap_le_msgt_names[] = {
	{ BSSMAP_LE_MSGT_PERFORM_LOC_REQ, "PERFORM LOCATION REQUEST" },
	{ BSSMAP_LE_MSGT_PERFORM_LOC_RESP, "PERFORM LOCATION RESPONSE" },
	{ BSSMAP_LE_MSGT_PERFORM_LOC_ABORT, "PERFORM LOCATION ABORT" },
	{ BSSMAP_LE_MSGT_PERFORM_LOC_INFO, "PERFORM LOCATION INFO" },
	{ BSSMAP_LE_MSGT_ASSIST_INFO_REQ, "ASSISTANCE INFORMATION REQUEST" },
	{ BSSMAP_LE_MSGT_ASSIST_INFO_RESP, "ASSISTANCE INFORMATION RESPONSE" },
	{ BSSMAP_LE_MSGT_CONN_ORIENTED_INFO, "CONNECTION ORIENTED INFORMATON" },
	{ BSSMAP_LE_MSGT_CONN_LESS_INFO, "CONNECTIONLESS INFORMATION" },
	{ BSSMAP_LE_MSGT_RESET, "RESET" },
	{ BSSMAP_LE_MSGT_RESET_ACK, "RESET ACKNOWLEDGE" },
	{}
};

const struct value_string osmo_bssmap_le_iei_names[] = {
	{ BSSMAP_LE_IEI_LCS_QoS, "LCS_QoS" },
	{ BSSMAP_LE_IEI_LCS_PRIORITY, "LCS_PRIORITY" },
	{ BSSMAP_LE_IEI_LOCATION_TYPE, "LOCATION_TYPE" },
	{ BSSMAP_LE_IEI_GANSS_LOCATION_TYPE, "GANSS_LOCATION_TYPE" },
	{ BSSMAP_LE_IEI_GEO_LOCATION, "GEO_LOCATION" },
	{ BSSMAP_LE_IEI_POSITIONING_DATA, "POSITIONING_DATA" },
	{ BSSMAP_LE_IEI_GANSS_POS_DATA, "GANSS_POS_DATA" },
	{ BSSMAP_LE_IEI_VELOCITY_DATA, "VELOCITY_DATA" },
	{ BSSMAP_LE_IEI_LCS_CAUSE, "LCS_CAUSE" },
	{ BSSMAP_LE_IEI_LCS_CLIENT_TYPE, "LCS_CLIENT_TYPE" },
	{ BSSMAP_LE_IEI_APDU, "APDU" },
	{ BSSMAP_LE_IEI_NET_ELEM_ID, "NET_ELEM_ID" },
	{ BSSMAP_LE_IEI_REQ_GPS_ASS_D, "REQ_GPS_ASS_D" },
	{ BSSMAP_LE_IEI_REQ_GANSS_ASS_D, "REQ_GANSS_ASS_D" },
	{ BSSMAP_LE_IEI_DECIPH_KEYS, "DECIPH_KEYS" },
	{ BSSMAP_LE_IEI_RET_ERR_REQ, "RET_ERR_REQ" },
	{ BSSMAP_LE_IEI_RET_ERR_CAUSE, "RET_ERR_CAUSE" },
	{ BSSMAP_LE_IEI_SEGMENTATION, "SEGMENTATION" },
	{ BSSMAP_LE_IEI_CLASSMARK3_INFO, "CLASSMARK3_INFO" },
	{ BSSMAP_LE_IEI_CAUSE, "CAUSE" },
	{ BSSMAP_LE_IEI_CELL_ID, "CELL_ID" },
	{ BSSMAP_LE_IEI_CHOSEN_CHAN, "CHOSEN_CHAN" },
	{ BSSMAP_LE_IEI_IMSI, "IMSI" },
	{ BSSMAP_LE_IEI_LCS_CAPABILITY, "LCS_CAPABILITY" },
	{ BSSMAP_LE_IEI_PKT_MEAS_REP, "PKT_MEAS_REP" },
	{ BSSMAP_LE_IEI_CELL_ID_LIST, "CELL_ID_LIST" },
	{ BSSMAP_LE_IEI_IMEI, "IMEI" },
	{ BSSMAP_LE_IEI_BSS_MLAT_CAP, "BSS_MLAT_CAP" },
	{ BSSMAP_LE_IEI_CELL_INFO_LIST, "CELL_INFO_LIST" },
	{ BSSMAP_LE_IEI_BTS_RX_ACC_LVL, "BTS_RX_ACC_LVL" },
	{ BSSMAP_LE_IEI_MLAT_METHOD, "MLAT_METHOD" },
	{ BSSMAP_LE_IEI_MLAT_TA, "MLAT_TA" },
	{ BSSMAP_LE_IEI_MS_SYNC_ACC, "MS_SYNC_ACC" },
	{ BSSMAP_LE_IEI_SHORT_ID_SET, "SHORT_ID_SET" },
	{ BSSMAP_LE_IEI_RANDOM_ID_SET, "RANDOM_ID_SET" },
	{ BSSMAP_LE_IEI_SHORT_BSS_ID, "SHORT_BSS_ID" },
	{ BSSMAP_LE_IEI_RANDOM_ID, "RANDOM_ID" },
	{ BSSMAP_LE_IEI_SHORT_ID, "SHORT_ID" },
	{ BSSMAP_LE_IEI_COVERAGE_CLASS, "COVERAGE_CLASS" },
	{ BSSMAP_LE_IEI_MTA_ACC_SEC_RQD, "MTA_ACC_SEC_RQD" },
	{}
};

/*! Return a human readable string describing a BSSAP-LE PDU.
 * \param[out] buf  String buffer to write to.
 * \param[in] buflen  sizeof(buf).
 * \param[in] bssap_le  Decoded BSSAP-LE PDU data.
 * \returns number of chars that would be written, like snprintf().
 */
int osmo_bssap_le_pdu_to_str_buf(char *buf, size_t buflen, const struct bssap_le_pdu *bssap_le)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	const struct bssmap_le_pdu *bssmap_le;

	switch (bssap_le->discr) {
	case BSSAP_LE_MSG_DISCR_BSSMAP_LE:
		bssmap_le = &bssap_le->bssmap_le;
		OSMO_STRBUF_PRINTF(sb, "BSSMAP-LE %s", osmo_bssmap_le_msgt_name(bssmap_le->msg_type));
		switch (bssmap_le->msg_type) {
		case BSSMAP_LE_MSGT_PERFORM_LOC_REQ:
			if (bssmap_le->perform_loc_req.apdu_present)
				OSMO_STRBUF_PRINTF(sb, " with BSSLAP %s",
						   osmo_bsslap_msgt_name(bssmap_le->perform_loc_req.apdu.msg_type));
			break;

		case BSSMAP_LE_MSGT_CONN_ORIENTED_INFO:
			OSMO_STRBUF_PRINTF(sb, " with BSSLAP %s",
					   osmo_bsslap_msgt_name(bssmap_le->conn_oriented_info.apdu.msg_type));
			break;

		default:
			break;
		}
		break;
	default:
		OSMO_STRBUF_PRINTF(sb, "BSSAP-LE discr %d not implemented", bssap_le->discr);
		break;
	}

	return sb.chars_needed;
}

/*! Return a human readable string describing a BSSAP-LE PDU.
 * \param[in] ctx  Talloc context to allocate string buffer from.
 * \param[in] bssap_le  Decoded BSSAP-LE PDU data.
 * \returns string.
 */
char *osmo_bssap_le_pdu_to_str_c(void *ctx, const struct bssap_le_pdu *bssap_le)
{
	OSMO_NAME_C_IMPL(ctx, 32, "ERROR", osmo_bssap_le_pdu_to_str_buf, bssap_le)
}

/*! @} */
