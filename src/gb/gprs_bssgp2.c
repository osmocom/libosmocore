/* BSSGP2 - second generation of BSSGP library */

/* (C) 2020 Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/utils.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/tlv.h>

#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp2.h>


/*! transmit BSSGP PDU over NS (PTP BVC)
 *  \param[in] nsi NS Instance through which to transmit
 *  \param[in] nsei NSEI of NSE through which to transmit
 *  \param[in] bvci BVCI through which to transmit
 *  \param[in] msg BSSGP PDU to transmit
 *  \returns 0 on success; negative on error */
int bssgp2_nsi_tx_ptp(struct gprs_ns2_inst *nsi, uint16_t nsei, uint16_t bvci,
		      struct msgb *msg, uint32_t lsp)
{
	struct osmo_gprs_ns2_prim nsp = {};
	int rc;

	if (!msg)
		return 0;

	nsp.bvci = bvci;
	nsp.nsei = nsei;
	nsp.u.unitdata.link_selector = lsp;

	osmo_prim_init(&nsp.oph, SAP_NS, GPRS_NS2_PRIM_UNIT_DATA, PRIM_OP_REQUEST, msg);
	rc = gprs_ns2_recv_prim(nsi, &nsp.oph);

	return rc;
}

/*! transmit BSSGP PDU over NS (SIGNALING BVC)
 *  \param[in] nsi NS Instance through which to transmit
 *  \param[in] nsei NSEI of NSE through which to transmit
 *  \param[in] msg BSSGP PDU to transmit
 *  \returns 0 on success; negative on error */
int bssgp2_nsi_tx_sig(struct gprs_ns2_inst *nsi, uint16_t nsei, struct msgb *msg, uint32_t lsp)
{
	return bssgp2_nsi_tx_ptp(nsi, nsei, 0, msg, lsp);
}

/*! Encode BSSGP BVC-BLOCK PDU as per TS 48.018 Section 10.4.8. */
struct msgb *bssgp2_enc_bvc_block(uint16_t bvci, enum gprs_bssgp_cause cause)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;
	uint16_t _bvci = osmo_htons(bvci);

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_BVC_BLOCK;

	msgb_tvlv_put(msg, BSSGP_IE_BVCI, 2, (uint8_t *) &_bvci);
	msgb_tvlv_put(msg, BSSGP_IE_CAUSE, 1, (uint8_t *) &cause);

	return msg;
}

/*! Encode BSSGP BVC-BLOCK-ACK PDU as per TS 48.018 Section 10.4.9. */
struct msgb *bssgp2_enc_bvc_block_ack(uint16_t bvci)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;
	uint16_t _bvci = osmo_htons(bvci);

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_BVC_BLOCK_ACK;

	msgb_tvlv_put(msg, BSSGP_IE_BVCI, 2, (uint8_t *) &_bvci);

	return msg;
}

/*! Encode BSSGP BVC-UNBLOCK PDU as per TS 48.018 Section 10.4.10. */
struct msgb *bssgp2_enc_bvc_unblock(uint16_t bvci)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;
	uint16_t _bvci = osmo_htons(bvci);

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_BVC_UNBLOCK;

	msgb_tvlv_put(msg, BSSGP_IE_BVCI, 2, (uint8_t *) &_bvci);

	return msg;
}

/*! Encode BSSGP BVC-UNBLOCK-ACK PDU as per TS 48.018 Section 10.4.11. */
struct msgb *bssgp2_enc_bvc_unblock_ack(uint16_t bvci)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;
	uint16_t _bvci = osmo_htons(bvci);

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_BVC_UNBLOCK_ACK;

	msgb_tvlv_put(msg, BSSGP_IE_BVCI, 2, (uint8_t *) &_bvci);

	return msg;
}

/*! Encode BSSGP BVC-RESET PDU as per TS 48.018 Section 10.4.12.
 *  \param[in] bvci PTP BVCI to encode into the BVCI IE
 *  \param[in] cause BSSGP Cause value (reason for reset)
 *  \param[in] ra_id Routing Area ID to be encoded to CELL_ID IE (optional)
 *  \param[in] cell_id Cell ID to be encoded to CELL_ID IE (only if ra_id is non-NULL)
 *  \param[in] feat_bm Feature Bitmap (optional)
 *  \param[in] ext_feat_bm Extended Feature Bitmap (optional) */
struct msgb *bssgp2_enc_bvc_reset(uint16_t bvci, enum gprs_bssgp_cause cause,
				  const struct gprs_ra_id *ra_id, uint16_t cell_id,
				  const uint8_t *feat_bm, const uint8_t *ext_feat_bm)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;
	uint16_t _bvci = osmo_htons(bvci);

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_BVC_RESET;

	msgb_tvlv_put(msg, BSSGP_IE_BVCI, 2, (uint8_t *) &_bvci);
	msgb_tvlv_put(msg, BSSGP_IE_CAUSE, 1, (uint8_t *) &cause);
	if (ra_id) {
		uint8_t bssgp_cid[8];
		bssgp_create_cell_id(bssgp_cid, ra_id, cell_id);
		msgb_tvlv_put(msg, BSSGP_IE_CELL_ID, sizeof(bssgp_cid), bssgp_cid);
	}

	if (feat_bm)
		msgb_tvlv_put(msg, BSSGP_IE_FEATURE_BITMAP, 1, feat_bm);

	if (ext_feat_bm)
		msgb_tvlv_put(msg, BSSGP_IE_EXT_FEATURE_BITMAP, 1, feat_bm);

	return msg;
}

/*! Encode BSSGP BVC-RESET-ACK PDU as per TS 48.018 Section 10.4.13.
 *  \param[in] bvci PTP BVCI to encode into the BVCI IE
 *  \param[in] ra_id Routing Area ID to be encoded to CELL_ID IE (optional)
 *  \param[in] cell_id Cell ID to be encoded to CELL_ID IE (only if ra_id is non-NULL)
 *  \param[in] feat_bm Feature Bitmap (optional)
 *  \param[in] ext_feat_bm Extended Feature Bitmap (optional) */
struct msgb *bssgp2_enc_bvc_reset_ack(uint16_t bvci, const struct gprs_ra_id *ra_id, uint16_t cell_id,
				      const uint8_t *feat_bm, const uint8_t *ext_feat_bm)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;
	uint16_t _bvci = osmo_htons(bvci);

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_BVC_RESET_ACK;

	msgb_tvlv_put(msg, BSSGP_IE_BVCI, 2, (uint8_t *) &_bvci);
	if (ra_id) {
		uint8_t bssgp_cid[8];
		bssgp_create_cell_id(bssgp_cid, ra_id, cell_id);
		msgb_tvlv_put(msg, BSSGP_IE_CELL_ID, sizeof(bssgp_cid), bssgp_cid);
	}

	if (feat_bm)
		msgb_tvlv_put(msg, BSSGP_IE_FEATURE_BITMAP, 1, feat_bm);

	if (ext_feat_bm)
		msgb_tvlv_put(msg, BSSGP_IE_EXT_FEATURE_BITMAP, 1, feat_bm);

	return msg;
}

/*! Encode BSSGP STATUS PDU as per TS 48.018 Section 10.4.14.
 *  \param[in] cause BSSGP Cause value
 *  \param[in] bvci optional BVCI - only encoded if non-NULL
 *  \param[in] msg optional message buffer containing PDU in error - only encoded if non-NULL
 *  \param[in] max_pdu_len Maximum BSSGP PDU size the NS layer accepts */
struct msgb *bssgp2_enc_status(uint8_t cause, const uint16_t *bvci, const struct msgb *orig_msg, uint16_t max_pdu_len)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_STATUS;
	msgb_tvlv_put(msg, BSSGP_IE_CAUSE, 1, &cause);
	/* FIXME: Require/encode BVCI only if cause is BVCI unknown/blocked
	 * See 3GPP TS 48.018 Ch. 10.4.14 */
	if (bvci) {
		uint16_t _bvci = osmo_htons(*bvci);
		msgb_tvlv_put(msg, BSSGP_IE_BVCI, 2, (uint8_t *) &_bvci);
	}
	if (orig_msg) {
		uint32_t orig_len, max_orig_len;
		/* Calculate how big the reply would be: the BSSGP msg so far + size of the PDU IN ERROR including tvl */
		orig_len = msgb_bssgp_len(orig_msg);
		max_orig_len = msgb_length(msg) + TVLV_GROSS_LEN(orig_len);
		/* Truncate the difference between max_orig_len and mtu */
		if (max_orig_len > max_pdu_len)
			orig_len -= max_orig_len - max_pdu_len;
		msgb_tvlv_put(msg, BSSGP_IE_PDU_IN_ERROR, orig_len, msgb_bssgph(orig_msg));
	}

	return msg;
}

static const unsigned int bssgp_fc_gran_tbl[] = {
	[BSSGP_FC_GRAN_100]	= 100,
	[BSSGP_FC_GRAN_1000]	= 1000,
	[BSSGP_FC_GRAN_10000]	= 10000,
	[BSSGP_FC_GRAN_100000]	= 100000,
};

/*! Decode a FLOW-CONTROL-BVC PDU as per TS 48.018 Section 10.4.4.
 *  \param[out] fc caller-allocated memory for parsed output
 *  \param[in] tp pre-parsed TLVs; caller must ensure mandatory IE presence/length
 *  \returns 0 on success; negative in case of error */
int bssgp2_dec_fc_bvc(struct bssgp2_flow_ctrl *fc, const struct tlv_parsed *tp)
{
	unsigned int granularity = 100;

	/* optional "Flow Control Granularity IE" (11.3.102); applies to
	 * bucket_size_max, bucket_leak_rate and PFC FC params IE */
	if (TLVP_PRESENT(tp, BSSGP_IE_FLOW_CTRL_GRANULARITY)) {
		uint8_t gran = *TLVP_VAL(tp, BSSGP_IE_FLOW_CTRL_GRANULARITY);
		granularity = bssgp_fc_gran_tbl[gran & 3];
	}

	/* mandatory IEs */
	fc->tag = *TLVP_VAL(tp, BSSGP_IE_TAG);
	fc->bucket_size_max = granularity * tlvp_val16be(tp, BSSGP_IE_BVC_BUCKET_SIZE);
	fc->bucket_leak_rate = (granularity * tlvp_val16be(tp, BSSGP_IE_BUCKET_LEAK_RATE)) / 8;
	fc->u.bvc.bmax_default_ms = granularity * tlvp_val16be(tp, BSSGP_IE_BMAX_DEFAULT_MS);
	fc->u.bvc.r_default_ms = (granularity * tlvp_val16be(tp, BSSGP_IE_R_DEFAULT_MS)) / 8;

	/* optional / conditional */
	if (TLVP_PRESENT(tp, BSSGP_IE_BUCKET_FULL_RATIO)) {
		fc->bucket_full_ratio_present = true;
		fc->bucket_full_ratio = *TLVP_VAL(tp, BSSGP_IE_BUCKET_FULL_RATIO);
	} else {
		fc->bucket_full_ratio_present = false;
	}

	if (TLVP_PRESENT(tp, BSSGP_IE_BVC_MEASUREMENT)) {
		uint16_t val = tlvp_val16be(tp, BSSGP_IE_BVC_MEASUREMENT);
		fc->u.bvc.measurement_present = true;
		/* convert from centi-seconds to milli-seconds */
		if (val == 0xffff)
			fc->u.bvc.measurement = 0xffffffff;
		else
			fc->u.bvc.measurement = val * 10;
	} else {
		fc->u.bvc.measurement_present = false;
	}

	return 0;

}

/*! Encode a FLOW-CONTROL-BVC PDU as per TS 48.018 Section 10.4.4.
 *  \param[in] fc structure describing to-be-encoded FC parameters
 *  \param[in] gran if non-NULL: Encode using specified unit granularity
 *  \returns encoded PDU or NULL in case of error */
struct msgb *bssgp2_enc_fc_bvc(const struct bssgp2_flow_ctrl *fc, enum bssgp_fc_granularity *gran)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;
	unsigned int granularity = 100;

	if (gran)
		granularity = bssgp_fc_gran_tbl[*gran & 3];

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_FLOW_CONTROL_BVC;

	msgb_tvlv_put(msg, BSSGP_IE_TAG, 1, &fc->tag);
	msgb_tvlv_put_16be(msg, BSSGP_IE_BVC_BUCKET_SIZE, fc->bucket_size_max / granularity);
	msgb_tvlv_put_16be(msg, BSSGP_IE_BUCKET_LEAK_RATE, fc->bucket_leak_rate * 8 / granularity);
	msgb_tvlv_put_16be(msg, BSSGP_IE_BMAX_DEFAULT_MS, fc->u.bvc.bmax_default_ms / granularity);
	msgb_tvlv_put_16be(msg, BSSGP_IE_R_DEFAULT_MS, fc->u.bvc.r_default_ms * 8 / granularity);

	if (fc->bucket_full_ratio_present)
		msgb_tvlv_put(msg, BSSGP_IE_BUCKET_FULL_RATIO, 1, &fc->bucket_full_ratio);

	if (fc->u.bvc.measurement_present) {
		uint16_t val;
		/* convert from ms to cs */
		if (fc->u.bvc.measurement == 0xffffffff)
			val = 0xffff;
		else
			val = fc->u.bvc.measurement / 10;
		msgb_tvlv_put_16be(msg, BSSGP_IE_BVC_MEASUREMENT, val);
	}

	if (gran) {
		uint8_t val = *gran & 3;
		msgb_tvlv_put(msg, BSSGP_IE_FLOW_CTRL_GRANULARITY, 1, &val);
	}

	return msg;
}

/*! Encode BSSGP FLUSH-LL PDU as per TS 48.018 Section 10.4.1.
 *  \param[in] tlli - the TLLI of the MS
 *  \param[in] old_bvci BVCI
 *  \param[in] new_bvci2 optional BVCI - only encoded if non-NULL
 *  \param[in] nsei optional - only encoded if non-NULL
 *  \returns encoded PDU or NULL in case of error */
struct msgb *bssgp2_enc_flush_ll(uint32_t tlli, uint16_t old_bvci,
				 const uint16_t *new_bvci, const uint16_t *nsei)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_FLUSH_LL;

	msgb_tvlv_put_32be(msg, BSSGP_IE_TLLI, tlli);
	msgb_tvlv_put_16be(msg, BSSGP_IE_BVCI, old_bvci);
	if (new_bvci)
		msgb_tvlv_put_16be(msg, BSSGP_IE_BVCI, *new_bvci);

	if (nsei)
		msgb_tvlv_put_16be(msg, BSSGP_IE_BVCI, *nsei);

	return msg;
}

/*! Encode a FLOW-CONTROL-BVC-ACK PDU as per TS 48.018 Section 10.4.4.
 *  \param[in] tag the tag IE value to encode
 *  \returns encoded PDU or NULL in case of error */
struct msgb *bssgp2_enc_fc_bvc_ack(uint8_t tag)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_FLOW_CONTROL_BVC_ACK;

	msgb_tvlv_put(msg, BSSGP_IE_TAG, 1, &tag);

	return msg;
}

/*! Decode a FLOW-CONTROL-MS PDU as per TS 48.018 Section 10.4.6.
 *  \param[out] fc caller-allocated memory for parsed output
 *  \param[in] tp pre-parsed TLVs; caller must ensure mandatory IE presence/length
 *  \returns 0 on success; negative in case of error */
int bssgp2_dec_fc_ms(struct bssgp2_flow_ctrl *fc, struct tlv_parsed *tp)
{
	unsigned int granularity = 100;

	/* optional "Flow Control Granularity IE" (11.3.102); applies to
	 * bucket_size_max, bucket_leak_rate and PFC FC params IE */
	if (TLVP_PRESENT(tp, BSSGP_IE_FLOW_CTRL_GRANULARITY)) {
		uint8_t gran = *TLVP_VAL(tp, BSSGP_IE_FLOW_CTRL_GRANULARITY);
		granularity = bssgp_fc_gran_tbl[gran & 3];
	}

	/* mandatory IEs */
	fc->u.ms.tlli = tlvp_val32be(tp, BSSGP_IE_TLLI);
	fc->tag = *TLVP_VAL(tp, BSSGP_IE_TAG);
	fc->bucket_size_max = granularity * tlvp_val16be(tp, BSSGP_IE_MS_BUCKET_SIZE);
	fc->bucket_leak_rate = (granularity * tlvp_val16be(tp, BSSGP_IE_BUCKET_LEAK_RATE)) / 8;

	/* optional / conditional */
	if (TLVP_PRESENT(tp, BSSGP_IE_BUCKET_FULL_RATIO)) {
		fc->bucket_full_ratio_present = true;
		fc->bucket_full_ratio = *TLVP_VAL(tp, BSSGP_IE_BUCKET_FULL_RATIO);
	} else {
		fc->bucket_full_ratio_present = false;
	}

	return 0;
}

/*! Encode a FLOW-CONTROL-MS PDU as per TS 48.018 Section 10.4.6.
 *  \param[in] fc structure describing to-be-encoded FC parameters
 *  \param[in] gran if non-NULL: Encode using specified unit granularity
 *  \returns encoded PDU or NULL in case of error */
struct msgb *bssgp2_enc_fc_ms(const struct bssgp2_flow_ctrl *fc, enum bssgp_fc_granularity *gran)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;
	unsigned int granularity = 100;

	if (gran)
		granularity = bssgp_fc_gran_tbl[*gran & 3];

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_FLOW_CONTROL_MS;

	msgb_tvlv_put_32be(msg, BSSGP_IE_TLLI, fc->u.ms.tlli);
	msgb_tvlv_put(msg, BSSGP_IE_TAG, 1, &fc->tag);
	msgb_tvlv_put_16be(msg, BSSGP_IE_MS_BUCKET_SIZE, fc->bucket_size_max / granularity);
	msgb_tvlv_put_16be(msg, BSSGP_IE_BUCKET_LEAK_RATE, fc->bucket_leak_rate * 8 / granularity);

	if (fc->bucket_full_ratio_present)
		msgb_tvlv_put(msg, BSSGP_IE_BUCKET_FULL_RATIO, 1, &fc->bucket_full_ratio);

	if (gran) {
		uint8_t val = *gran & 3;
		msgb_tvlv_put(msg, BSSGP_IE_FLOW_CTRL_GRANULARITY, 1, &val);
	}

	return msg;
}

/*! Encode a FLOW-CONTROL-BVC-ACK PDU as per TS 48.018 Section 10.4.7.
 *  \param[in] tlli the TLLI IE value to encode
 *  \param[in] tag the tag IE value to encode
 *  \returns encoded PDU or NULL in case of error */
struct msgb *bssgp2_enc_fc_ms_ack(uint32_t tlli, uint8_t tag)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_FLOW_CONTROL_MS_ACK;

	msgb_tvlv_put_32be(msg, BSSGP_IE_TLLI, tlli);
	msgb_tvlv_put(msg, BSSGP_IE_TAG, 1, &tag);

	return msg;
}
