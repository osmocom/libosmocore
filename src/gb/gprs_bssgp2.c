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

	osmo_prim_init(&nsp.oph, SAP_NS, PRIM_NS_UNIT_DATA, PRIM_OP_REQUEST, msg);
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
 *  \param[in] msg optional message buffer containing PDU in error - only encoded if non-NULL */
struct msgb *bssgp2_enc_status(uint8_t cause, const uint16_t *bvci, const struct msgb *orig_msg)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph;

	if (!msg)
		return NULL;

	bgph = (struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	bgph->pdu_type = BSSGP_PDUT_STATUS;
	msgb_tvlv_put(msg, BSSGP_IE_CAUSE, 1, &cause);
	if (bvci) {
		uint16_t _bvci = osmo_htons(*bvci);
		msgb_tvlv_put(msg, BSSGP_IE_BVCI, 2, (uint8_t *) &_bvci);
	}
	if (orig_msg)
		msgb_tvlv_put(msg, BSSGP_IE_PDU_IN_ERROR, msgb_bssgp_len(orig_msg), msgb_bssgph(orig_msg));

	return msg;
}
