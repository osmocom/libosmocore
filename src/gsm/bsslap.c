/* 3GPP TS 48.071 BSSLAP protocol definitions */
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

#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/bsslap.h>
#include <osmocom/gsm/tlv.h>

#include <osmocom/core/logging.h>

/*! \addtogroup bsslap
 *  @{
 *  \file bsslap.c
 *  Message encoding and decoding for 3GPP TS 48.071 BSSLAP protocol.
 */

static const struct tlv_definition osmo_bsslap_tlvdef = {
	.def = {
	[BSSLAP_IEI_TA] = { TLV_TYPE_TV },
	[BSSLAP_IEI_CELL_ID] = { TLV_TYPE_FIXED, 2 },
	[BSSLAP_IEI_CHAN_DESC] = { TLV_TYPE_FIXED, 3 },
	[BSSLAP_IEI_MEAS_REP] = { TLV_TYPE_TLV },
	[BSSLAP_IEI_CAUSE] = { TLV_TYPE_TV },
	[BSSLAP_IEI_RRLP_FLAG] = { TLV_TYPE_TV },
	[BSSLAP_IEI_RRLP] = { TLV_TYPE_TLV },
	[BSSLAP_IEI_CELL_ID_LIST] = { TLV_TYPE_TLV },
	[BSSLAP_IEI_ENH_MEAS_REP] = { TLV_TYPE_TLV },
	[BSSLAP_IEI_LAC] = { TLV_TYPE_TLV },
	[BSSLAP_IEI_FREQ_LIST] = { TLV_TYPE_TLV },
	[BSSLAP_IEI_MS_POWER] = { TLV_TYPE_TV },
	[BSSLAP_IEI_DELTA_TIMER] = { TLV_TYPE_TV },
	[BSSLAP_IEI_SERVING_CELL_ID] = { TLV_TYPE_TLV },
	[BSSLAP_IEI_ENCR_KEY] = { TLV_TYPE_FIXED, 8 },
	[BSSLAP_IEI_CIPH_MODE_SET] = { TLV_TYPE_TV },
	[BSSLAP_IEI_CHAN_MODE] = { TLV_TYPE_TV, 2 },
	[BSSLAP_IEI_MR_CONFIG] = { TLV_TYPE_TLV },
	[BSSLAP_IEI_POLLING_REPETITION] = { TLV_TYPE_TV },
	[BSSLAP_IEI_PACKET_CHAN_DESC] = { TLV_TYPE_FIXED, 4 },
	[BSSLAP_IEI_TLLI] = { TLV_TYPE_FIXED, 4 },
	[BSSLAP_IEI_TFI] = { TLV_TYPE_TLV },
	[BSSLAP_IEI_TBF_START_TIME] = { TLV_TYPE_FIXED, 2 },
	[BSSLAP_IEI_PWRUP_START_TIME] = { TLV_TYPE_TLV },
	[BSSLAP_IEI_LONG_ENCR_KEY] = { TLV_TYPE_FIXED, 16 },
	[BSSLAP_IEI_CONCUR_POS_PROC_F] = { TLV_TYPE_TV },
	},
};

#define DEC_ERR(RC, MSG_TYPE, IEI, CAUSE, fmt, args...) do { \
		if (err && !*err) { \
			*err = talloc_zero(err_ctx, struct osmo_bsslap_err); \
			**err = (struct osmo_bsslap_err){ \
				.rc = (RC), \
				.msg_type = (MSG_TYPE), \
				.iei = (IEI), \
				.cause = (CAUSE), \
				.logmsg = talloc_asprintf(*err, "Error decoding BSSLAP%s%s%s%s%s: " fmt, \
							  (MSG_TYPE) >= 0 ? " " : "", \
							  (MSG_TYPE) >= 0 ? osmo_bsslap_msgt_name(MSG_TYPE) : "", \
							  (IEI) >= 0 ? ": " : "", \
							  (IEI) >= 0 ? osmo_bsslap_iei_name(IEI) : "", \
							  (IEI) >= 0 ? " IE" : "", \
##args), \
			}; \
		} \
		return RC; \
	} while(0)

static void osmo_bsslap_ie_enc_cell_id(struct msgb *msg, uint16_t cell_id)
{
	msgb_put_u8(msg, BSSLAP_IEI_CELL_ID);
	msgb_put_u16(msg, cell_id);
}

static int osmo_bsslap_ie_dec_cell_id(uint16_t *cell_id,
				      enum bsslap_msgt msgt, enum bsslap_iei iei,
				      struct osmo_bsslap_err **err, void *err_ctx,
				      const uint8_t *data, size_t len)
{
	if (len != 2)
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "Expected 2 bytes, got %zu", len);
	*cell_id = osmo_load16be(data);
	return 0;
}

static void osmo_bsslap_ie_enc_ta(struct msgb *msg, uint8_t ta)
{
	msgb_put_u8(msg, BSSLAP_IEI_TA);
	msgb_put_u8(msg, ta);
}

static int osmo_bsslap_ie_dec_ta(uint8_t *ta,
				 enum bsslap_msgt msgt, enum bsslap_iei iei,
				 struct osmo_bsslap_err **err, void *err_ctx,
				 const uint8_t *data, size_t len)
{
	if (len != 1)
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "Expected 1 byte, got %zu", len);
	*ta = data[0];
	return 0;
}

static void osmo_bsslap_ie_enc_cause(struct msgb *msg, enum bsslap_cause cause)
{
	msgb_put_u8(msg, BSSLAP_IEI_CAUSE);
	msgb_put_u8(msg, cause);
}

static int osmo_bsslap_ie_dec_cause(enum bsslap_cause *cause,
				    enum bsslap_msgt msgt, enum bsslap_iei iei,
				    struct osmo_bsslap_err **err, void *err_ctx,
				    const uint8_t *data, size_t len)
{
	if (len != 1)
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "Expected 1 byte, got %zu", len);
	*cause = data[0];
	return 0;
}

static void osmo_bsslap_ie_enc_chan_desc(struct msgb *msg, const struct gsm48_chan_desc *chan_desc)
{
	struct gsm48_chan_desc *put_chan_desc;
	msgb_put_u8(msg, BSSLAP_IEI_CHAN_DESC);
	put_chan_desc = (void*)msgb_put(msg, sizeof(*chan_desc));
	*put_chan_desc = *chan_desc;
}

static int osmo_bsslap_ie_dec_chan_desc(struct gsm48_chan_desc *chan_desc,
					enum bsslap_msgt msgt, enum bsslap_iei iei,
					struct osmo_bsslap_err **err, void *err_ctx,
					const uint8_t *data, size_t len)
{
	if (len != sizeof(*chan_desc))
		DEC_ERR(-EINVAL, msgt, iei, LCS_CAUSE_UNSPECIFIED, "Expected %zu bytes, got %zu",
			sizeof(*chan_desc), len);
	*chan_desc = *(struct gsm48_chan_desc*)data;
	return 0;
}

/*! Encode BSSLAP PDU and append to msgb (3GPP TS 48.071).
 * \param[out] msg  msgb to append to.
 * \param[in] pdu  PDU data to encode.
 * \return number of bytes written, negative on error.
 */
int osmo_bsslap_enc(struct msgb *msg, const struct bsslap_pdu *pdu)
{
	uint8_t *old_tail = msg->tail;

	msgb_put_u8(msg, pdu->msg_type);

	switch (pdu->msg_type) {
	case BSSLAP_MSGT_TA_REQUEST:
		/* The TA Request message contains only the message type. */
		break;

	case BSSLAP_MSGT_TA_RESPONSE:
		osmo_bsslap_ie_enc_cell_id(msg, pdu->ta_response.cell_id);
		osmo_bsslap_ie_enc_ta(msg, pdu->ta_response.ta);
		break;

	case BSSLAP_MSGT_REJECT:
		osmo_bsslap_ie_enc_cause(msg, pdu->reject);
		break;

	case BSSLAP_MSGT_RESET:
		osmo_bsslap_ie_enc_cell_id(msg, pdu->reset.cell_id);
		osmo_bsslap_ie_enc_ta(msg, pdu->reset.ta);
		osmo_bsslap_ie_enc_chan_desc(msg, &pdu->reset.chan_desc);
		osmo_bsslap_ie_enc_cause(msg, pdu->reset.cause);
		break;

	case BSSLAP_MSGT_ABORT:
		osmo_bsslap_ie_enc_cause(msg, pdu->abort);
		break;

	case BSSLAP_MSGT_TA_LAYER3:
		osmo_bsslap_ie_enc_ta(msg, pdu->ta_layer3.ta);
		break;

	default:
		return -ENOTSUP;
	}
	return (msg->tail - old_tail);
}

/*! Decode BSSLAP PDU (3GPP TS 48.071).
 * \param[out] pdu  Write decoded values here.
 * \param[out] err  Returned pointer to error info, dynamically allocated; NULL to not return any.
 * \param[in] err_ctx  Talloc context to allocate err from, if required.
 * \param[in] data  Pointer to BSSLAP PDU raw data.
 * \param[in] len  Data length to decode.
 * \return 0 on success, negative on error.
 */
int osmo_bsslap_dec(struct bsslap_pdu *pdu,
		    struct osmo_bsslap_err **err, void *err_ctx,
		    const uint8_t *data, size_t len)
{
	const uint8_t *ies_start;
	int ies_len;
	struct tlv_parsed tp;

	*pdu = (struct bsslap_pdu){};
	if (err)
		*err = NULL;

#define DEC_IE_MANDATORY(IEI, DEC_FUN, DEC_FUN_ARG) do { \
		const struct tlv_p_entry *e; \
		int rc; \
		if (!(e = TLVP_GET(&tp, IEI))) \
			DEC_ERR(-EINVAL, pdu->msg_type, IEI, LCS_CAUSE_DATA_MISSING_IN_REQ, "missing mandatory IE"); \
		rc = DEC_FUN(DEC_FUN_ARG, pdu->msg_type, IEI, err, err_ctx, e->val, e->len); \
		if (rc) \
			DEC_ERR(rc, pdu->msg_type, IEI, LCS_CAUSE_UNSPECIFIED, "cannot parse IE"); \
	} while (0)

	if (len < 1)
		DEC_ERR(-EINVAL, -1, -1, LCS_CAUSE_UNSPECIFIED, "PDU too short: %zu b", len);

	pdu->msg_type = data[0];

	if (pdu->msg_type == BSSLAP_MSGT_TA_REQUEST) {
		/* The TA Request message contains only the message type. */
		return 0;
	}

	ies_start = &data[1];
	ies_len = len - 1;

	if (tlv_parse2(&tp, 1, &osmo_bsslap_tlvdef, ies_start, ies_len, 0, 0) <= 0)
		DEC_ERR(-EINVAL, pdu->msg_type, -1, LCS_CAUSE_UNSPECIFIED, "failed to parse TLV structure");

	switch (pdu->msg_type) {

	case BSSLAP_MSGT_TA_RESPONSE:
		DEC_IE_MANDATORY(BSSLAP_IEI_CELL_ID, osmo_bsslap_ie_dec_cell_id, &pdu->ta_response.cell_id);
		DEC_IE_MANDATORY(BSSLAP_IEI_TA, osmo_bsslap_ie_dec_ta, &pdu->ta_response.ta);
		return 0;

	case BSSLAP_MSGT_REJECT:
		DEC_IE_MANDATORY(BSSLAP_IEI_CAUSE, osmo_bsslap_ie_dec_cause, &pdu->reject);
		return 0;

	case BSSLAP_MSGT_RESET:
		DEC_IE_MANDATORY(BSSLAP_IEI_CELL_ID, osmo_bsslap_ie_dec_cell_id, &pdu->reset.cell_id);
		DEC_IE_MANDATORY(BSSLAP_IEI_TA, osmo_bsslap_ie_dec_ta, &pdu->reset.ta);
		DEC_IE_MANDATORY(BSSLAP_IEI_CHAN_DESC, osmo_bsslap_ie_dec_chan_desc, &pdu->reset.chan_desc);
		DEC_IE_MANDATORY(BSSLAP_IEI_CAUSE, osmo_bsslap_ie_dec_cause, &pdu->reset.cause);
		return 0;

	case BSSLAP_MSGT_ABORT:
		DEC_IE_MANDATORY(BSSLAP_IEI_CAUSE, osmo_bsslap_ie_dec_cause, &pdu->abort);
		return 0;

	case BSSLAP_MSGT_TA_LAYER3:
		DEC_IE_MANDATORY(BSSLAP_IEI_TA, osmo_bsslap_ie_dec_ta, &pdu->ta_layer3.ta);
		return 0;

	default:
		DEC_ERR(-EINVAL, pdu->msg_type, -1, LCS_CAUSE_UNSPECIFIED, "Unsupported message type");
	}
}

const struct value_string osmo_bsslap_msgt_names[] = {
	{ BSSLAP_MSGT_TA_REQUEST, "TA Request" },
	{ BSSLAP_MSGT_TA_RESPONSE, "TA Response" },
	{ BSSLAP_MSGT_REJECT, "Reject" },
	{ BSSLAP_MSGT_RESET, "Reset" },
	{ BSSLAP_MSGT_ABORT, "Abort" },
	{ BSSLAP_MSGT_TA_LAYER3, "TA Layer3" },
	{ BSSLAP_MSGT_MS_POS_CMD, "MS Position Command" },
	{ BSSLAP_MSGT_MS_POS_RESP, "MS Position Response" },
	{ BSSLAP_MSGT_UTDOA_REQ, "U-TDOA Request" },
	{ BSSLAP_MSGT_UTDOA_RESP, "U-TDOA Response" },
	{}
};

const struct value_string osmo_bsslap_iei_names[] = {
	{ BSSLAP_IEI_TA, "Timing Advance" },
	{ BSSLAP_IEI_CELL_ID, "Cell Identity" },
	{ BSSLAP_IEI_CHAN_DESC, "Channel Description" },
	{ BSSLAP_IEI_MEAS_REP, "Measurement Report" },
	{ BSSLAP_IEI_CAUSE, "Cause" },
	{ BSSLAP_IEI_RRLP_FLAG, "RRLP Flag" },
	{ BSSLAP_IEI_RRLP, "RRLP" },
	{ BSSLAP_IEI_CELL_ID_LIST, "Cell Identity List" },
	{ BSSLAP_IEI_ENH_MEAS_REP, "Enhanced Measurement Report" },
	{ BSSLAP_IEI_LAC, "Location Area Code" },
	{ BSSLAP_IEI_FREQ_LIST, "Frequency List" },
	{ BSSLAP_IEI_MS_POWER, "MS Power" },
	{ BSSLAP_IEI_DELTA_TIMER, "Delta Timer" },
	{ BSSLAP_IEI_SERVING_CELL_ID, "Serving Cell Identifier" },
	{ BSSLAP_IEI_ENCR_KEY, "Encryption Key" },
	{ BSSLAP_IEI_CIPH_MODE_SET, "Cipher Mode Setting" },
	{ BSSLAP_IEI_CHAN_MODE, "Channel Mode" },
	{ BSSLAP_IEI_MR_CONFIG, "MultiRate Configuration" },
	{ BSSLAP_IEI_POLLING_REPETITION, "Polling Repetition" },
	{ BSSLAP_IEI_PACKET_CHAN_DESC, "Packet Channel Description" },
	{ BSSLAP_IEI_TLLI, "TLLI" },
	{ BSSLAP_IEI_TFI, "TFI" },
	{ BSSLAP_IEI_TBF_START_TIME, "TBF Starting Time" },
	{ BSSLAP_IEI_PWRUP_START_TIME, "Powerup Starting Time" },
	{ BSSLAP_IEI_LONG_ENCR_KEY, "Long Encryption Key" },
	{ BSSLAP_IEI_CONCUR_POS_PROC_F, "Concurrent Positioning Flag" },
	{}
};

/*! @} */
