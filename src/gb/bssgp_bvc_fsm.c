/* BSSGP per-BVC Finite State Machine */

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

#include <string.h>
#include <stdio.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/tdef.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/tlv.h>

#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp2.h>
#include <osmocom/gprs/bssgp_bvc_fsm.h>

#include "common_vty.h"

#define S(x)	(1 << (x))

/* TODO: Those are not made cofnigurable via a VTY yet */
struct osmo_tdef bssgp_bvc_fsm_tdefs[] = {
	{
		.T = 1,
		.default_val = 5,
		.min_val = 1,
		.max_val = 30,
		.unit = OSMO_TDEF_S,
		.desc = "Guards the BSSGP BVC (un)blocking procedure",
	}, {
		.T = 2,
		.default_val = 10,
		.min_val = 1,
		.max_val = 120,
		.unit = OSMO_TDEF_S,
		.desc = "Guards the BSSGP BVC reset procedure",
	}, {
		.T = 3,
		.default_val = 500,
		.min_val = 100,
		.max_val = 10000,
		.unit = OSMO_TDEF_MS,
		.desc = "Guards the BSSGP SUSPEND procedure",
	}, {
		.T = 4,
		.default_val = 500,
		.min_val = 100,
		.max_val = 10000,
		.unit = OSMO_TDEF_MS,
		.desc = "Guards the BSSGP RESUME procedure",
	}, {
		.T = 5,
		.default_val = 15,
		.min_val = 1,
		.max_val = 30,
		.unit = OSMO_TDEF_S,
		.desc = "Guards the BSSGP Radio Access Capability Update procedure",
	},
	{}
};

#define T1	1
#define T2	2

/* We cannot use osmo_tdef_fsm_* as it makes hard-coded assumptions that
 * each new/target state will always use the same timer and timeout - or
 * a timeout at all */
#define T1_SECS	osmo_tdef_get(bssgp_bvc_fsm_tdefs, 1, OSMO_TDEF_S, 5)
#define T2_SECS	osmo_tdef_get(bssgp_bvc_fsm_tdefs, 2, OSMO_TDEF_S, 10)

/* forward declaration */
static struct osmo_fsm bssgp_bvc_fsm;

static const struct value_string ptp_bvc_event_names[] = {
	{ BSSGP_BVCFSM_E_RX_BLOCK, "RX-BVC-BLOCK" },
	{ BSSGP_BVCFSM_E_RX_BLOCK_ACK, "RX-BVC-BLOCK-ACK" },
	{ BSSGP_BVCFSM_E_RX_UNBLOCK, "RX-BVC-UNBLOCK" },
	{ BSSGP_BVCFSM_E_RX_UNBLOCK_ACK, "RX-BVC-UNBLOCK-ACK" },
	{ BSSGP_BVCFSM_E_RX_RESET, "RX-BVC-RESET" },
	{ BSSGP_BVCFSM_E_RX_RESET_ACK, "RX-BVC-RESET-ACK" },
	{ BSSGP_BVCFSM_E_RX_FC_BVC, "RX-FLOW-CONTROL-BVC" },
	{ BSSGP_BVCFSM_E_RX_FC_BVC_ACK, "RX-FLOW-CONTROL-BVC-ACK" },
	{ BSSGP_BVCFSM_E_REQ_BLOCK, "REQ-BLOCK" },
	{ BSSGP_BVCFSM_E_REQ_UNBLOCK, "REQ-UNBLOCK" },
	{ BSSGP_BVCFSM_E_REQ_RESET, "REQ-RESET" },
	{ BSSGP_BVCFSM_E_REQ_FC_BVC, "REQ-FLOW-CONTROL-BVC" },
	{ 0, NULL }
};

struct bvc_fsm_priv {
	/* NS-instance; defining the scope for NSEI below */
	struct gprs_ns2_inst *nsi;

	/* NSEI of the underlying NS Entity */
	uint16_t nsei;
	/* Maximum size of the BSSGP PDU */
	uint16_t max_pdu_len;

	/* BVCI of this BVC */
	uint16_t bvci;

	/* are we the SGSN (true) or the BSS (false) */
	bool role_sgsn;

	/* BSS side: are we locally marked blocked? */
	bool locally_blocked;
	uint8_t block_cause;

	/* cause value of the last outbound BVC-RESET (for re-transmissions) */
	uint8_t last_reset_cause;

	struct {
		/* Bit 0..7: Features; Bit 8..15: Extended Features */
		uint32_t advertised;
		uint32_t received;
		uint32_t negotiated;
		/* only used if BSSGP_XFEAT_GBIT is negotiated */
		enum bssgp_fc_granularity fc_granularity;
	} features;

	/* Cell Identification used by BSS when
	 * transmitting BVC-RESET / BVC-RESET-ACK, or those received
	 * from BSS in SGSN role */
	struct gprs_ra_id ra_id;
	uint16_t cell_id;

	/* call-backs provided by the user */
	const struct bssgp_bvc_fsm_ops *ops;
	/* private data pointer passed to each call-back invocation */
	void *ops_priv;
};

static int fi_tx_ptp(struct osmo_fsm_inst *fi, struct msgb *msg)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &bssgp_bvc_fsm);

	LOGPFSM(fi, "Tx BSSGP %s\n", osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, bgph->pdu_type));

	return bssgp2_nsi_tx_ptp(bfp->nsi, bfp->nsei, bfp->bvci, msg, 0);
}

static int fi_tx_sig(struct osmo_fsm_inst *fi, struct msgb *msg)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &bssgp_bvc_fsm);

	LOGPFSM(fi, "Tx BSSGP %s\n", osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, bgph->pdu_type));

	return bssgp2_nsi_tx_sig(bfp->nsi, bfp->nsei, msg, 0);
}

/* helper function to transmit BVC-RESET with right combination of conditional/optional IEs */
static void _tx_bvc_reset(struct osmo_fsm_inst *fi, uint8_t cause)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	const uint8_t *features = NULL;
	const uint8_t *features_ext = NULL;
	uint8_t _features[2] = {
		(bfp->features.advertised >> 0) & 0xff,
		(bfp->features.advertised >> 8) & 0xff,
	};
	struct msgb *tx;

	OSMO_ASSERT(fi->fsm == &bssgp_bvc_fsm);

	/* transmit BVC-RESET to peer; RA-ID only present for PTP from BSS */
	if (bfp->bvci == 0) {
		features = &_features[0];
		features_ext = &_features[1];
	}
	tx = bssgp2_enc_bvc_reset(bfp->bvci, cause,
				  bfp->bvci && !bfp->role_sgsn ? &bfp->ra_id : NULL,
				  bfp->cell_id, features, features_ext);
	fi_tx_sig(fi, tx);
}

/* helper function to transmit BVC-RESET-ACK with right combination of conditional/optional IEs */
static void _tx_bvc_reset_ack(struct osmo_fsm_inst *fi)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	const uint8_t *features = NULL;
	const uint8_t *features_ext = NULL;
	uint8_t _features[2] = {
		(bfp->features.advertised >> 0) & 0xff,
		(bfp->features.advertised >> 8) & 0xff,
	};
	struct msgb *tx;

	OSMO_ASSERT(fi->fsm == &bssgp_bvc_fsm);

	/* transmit BVC-RESET-ACK to peer; RA-ID only present for PTP from BSS -> SGSN */
	if (bfp->bvci == 0) {
		features = &_features[0];
		features_ext = &_features[1];
	}
	tx = bssgp2_enc_bvc_reset_ack(bfp->bvci, bfp->bvci && !bfp->role_sgsn ? &bfp->ra_id : NULL,
				     bfp->cell_id, features, features_ext);
	fi_tx_sig(fi, tx);
}

/* helper function to transmit BVC-STATUS with right combination of conditional/optional IEs */
static void _tx_status(struct osmo_fsm_inst *fi, enum gprs_bssgp_cause cause, const struct msgb *rx)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	struct msgb *tx;
	uint16_t *bvci = NULL;

	/* GSM 08.18, 10.4.14.1: The BVCI must be included if (and only if) the
	 * cause is either "BVCI blocked" or "BVCI unknown" */
	if (cause == BSSGP_CAUSE_UNKNOWN_BVCI || cause == BSSGP_CAUSE_BVCI_BLOCKED)
		bvci = &bfp->bvci;

	tx = bssgp2_enc_status(cause, bvci, rx, bfp->max_pdu_len);

	if (msgb_bvci(rx) == 0)
		fi_tx_sig(fi, tx);
	else
		fi_tx_ptp(fi, tx);
}

/* Update the features by bit-wise AND of advertised + received features */
static void update_negotiated_features(struct osmo_fsm_inst *fi, const struct tlv_parsed *tp)
{
	struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &bssgp_bvc_fsm);

	bfp->features.received = 0;

	if (TLVP_PRES_LEN(tp, BSSGP_IE_FEATURE_BITMAP, 1))
		bfp->features.received |= *TLVP_VAL(tp, BSSGP_IE_FEATURE_BITMAP);

	if (TLVP_PRES_LEN(tp, BSSGP_IE_EXT_FEATURE_BITMAP, 1))
		bfp->features.received |= (*TLVP_VAL(tp, BSSGP_IE_EXT_FEATURE_BITMAP) << 8);

	bfp->features.negotiated = bfp->features.advertised & bfp->features.received;

	LOGPFSML(fi, LOGL_NOTICE, "Updating features: Advertised 0x%04x, Received 0x%04x, Negotiated 0x%04x\n",
		 bfp->features.advertised, bfp->features.received, bfp->features.negotiated);
}

/* "tail" of each onenter() handler: Calling the state change notification call-back */
static void _onenter_tail(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bvc_fsm_priv *bfp = fi->priv;

	if (prev_state == fi->state)
		return;

	if (bfp->ops && bfp->ops->state_chg_notification)
		bfp->ops->state_chg_notification(bfp->nsei, bfp->bvci, prev_state, fi->state, bfp->ops_priv);
}

static void bssgp_bvc_fsm_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* we don't really expect anything in this state; all handled via allstate */
	OSMO_ASSERT(0);
}

static void bssgp_bvc_fsm_blocked_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	/* signaling BVC can never be blocked */
	OSMO_ASSERT(bfp->bvci != 0);
	_onenter_tail(fi, prev_state);
}

static void bssgp_bvc_fsm_blocked(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	struct msgb *rx = NULL, *tx;
	const struct tlv_parsed *tp = NULL;
	uint8_t cause;

	switch (event) {
	case BSSGP_BVCFSM_E_RX_BLOCK_ACK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		/* If a BVC-BLOCK-ACK PDU is received by a BSS for the signalling BVC, the PDU is ignored. */
		if (bfp->bvci == 0) {
			LOGPFSML(fi, LOGL_ERROR, "Rx BVC-BLOCK-ACK on BVCI=0 is illegal\n");
			if (!bfp->role_sgsn)
				break;
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		/* stop T1 timer */
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_BLOCKED, 0, 0);
		break;
	case BSSGP_BVCFSM_E_RX_BLOCK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		cause = *TLVP_VAL(tp, BSSGP_IE_CAUSE);
		LOGPFSML(fi, LOGL_NOTICE, "Rx BVC-BLOCK (cause=%s)\n", bssgp_cause_str(cause));
		/* If a BVC-BLOCK PDU is received by an SGSN for a blocked BVC, a BVC-BLOCK-ACK
		 * PDU shall be returned. */
		if (bfp->role_sgsn) {
			/* If a BVC-BLOCK PDU is received by an SGSN for
			 * the signalling BVC, the PDU is ignored */
			if (bfp->bvci == 0)
				break;
			tx = bssgp2_enc_bvc_block_ack(bfp->bvci);
			fi_tx_sig(fi, tx);
		}
		break;
	case BSSGP_BVCFSM_E_RX_UNBLOCK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		LOGPFSML(fi, LOGL_NOTICE, "Rx BVC-UNBLOCK\n");
		if (bfp->bvci == 0) {
			LOGPFSML(fi, LOGL_ERROR, "Rx BVC-UNBLOCK on BVCI=0 is illegal\n");
			/* If BVC-UNBLOCK PDU is received by an SGSN for the signalling BVC, the PDU is ignored.*/
			if (bfp->role_sgsn)
				break;
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		if (!bfp->role_sgsn) {
			LOGPFSML(fi, LOGL_ERROR, "Rx BVC-UNBLOCK on BSS is illegal\n");
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		tx = bssgp2_enc_bvc_unblock_ack(bfp->bvci);
		fi_tx_sig(fi, tx);
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_UNBLOCKED, T1_SECS, T1);
		break;
	case BSSGP_BVCFSM_E_REQ_UNBLOCK:
		if (bfp->role_sgsn) {
			LOGPFSML(fi, LOGL_ERROR, "SGSN side cannot initiate BVC unblock\n");
			break;
		}
		if (bfp->bvci == 0) {
			LOGPFSML(fi, LOGL_ERROR, "BVCI 0 cannot be unblocked\n");
			break;
		}
		bfp->locally_blocked = false;
		tx = bssgp2_enc_bvc_unblock(bfp->bvci);
		fi_tx_sig(fi, tx);
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_UNBLOCKED, 0, 0);
		break;
	}
}

/* Waiting for RESET-ACK: Receive PDUs but don't transmit */
static void bssgp_bvc_fsm_wait_reset_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	const struct tlv_parsed *tp = NULL;
	struct msgb *rx = NULL, *tx;
	uint8_t cause;

	switch (event) {
	case BSSGP_BVCFSM_E_RX_RESET:
		/* 48.018 Section 8.4.3: If the BSS (or SGSN) has sent a BVC-RESET PDU for a BVCI to
		 * the SGSN (or BSS) and is awaiting a BVC-RESET-ACK PDU in response, but instead
		 * receives a BVC-RESET PDU indicating the same BVCI, then this shall be interpreted
		 * as a BVC-RESET ACK PDU and the T2 timer shall be stopped. */
		/* fall-through */
	case BSSGP_BVCFSM_E_RX_RESET_ACK:
		rx = data;
		cause = bfp->last_reset_cause;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		if (bfp->bvci == 0)
			update_negotiated_features(fi, tp);
		if (bfp->role_sgsn && bfp->bvci != 0)
			bfp->cell_id = bssgp_parse_cell_id(&bfp->ra_id, TLVP_VAL(tp, BSSGP_IE_CELL_ID));
		if (!bfp->role_sgsn && bfp->bvci != 0 && bfp->locally_blocked) {
			/* initiate the blocking procedure */
			/* transmit BVC-BLOCK, transition to BLOCKED state and start re-transmit timer */
			tx = bssgp2_enc_bvc_block(bfp->bvci, bfp->block_cause);
			fi_tx_sig(fi, tx);
			osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_BLOCKED, T1_SECS, T1);
		} else
			osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_UNBLOCKED, 0, 0);
		if (bfp->ops && bfp->ops->reset_ack_notification)
			bfp->ops->reset_ack_notification(bfp->nsei, bfp->bvci, &bfp->ra_id, bfp->cell_id, cause, bfp->ops_priv);
		break;
	}
}

static void bssgp_bvc_fsm_unblocked(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bssgp2_flow_ctrl rx_fc, *tx_fc;
	struct bvc_fsm_priv *bfp = fi->priv;
	const struct tlv_parsed *tp = NULL;
	struct msgb *rx = NULL, *tx;
	int rc;

	switch (event) {
	case BSSGP_BVCFSM_E_RX_UNBLOCK_ACK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		/* If BVC-UNBLOCK-ACK PDU is received by an BSS for the signalling BVC, the PDU is ignored. */
		if (bfp->bvci == 0) {
			LOGPFSML(fi, LOGL_ERROR, "Rx BVC-UNBLOCK-ACK on BVCI=0 is illegal\n");
			if (!bfp->role_sgsn)
				break;
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		/* stop T1 timer */
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_UNBLOCKED, 0, 0);
		break;
	case BSSGP_BVCFSM_E_RX_UNBLOCK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		/* If a BVC-UNBLOCK PDU is received by an SGSN for a blocked BVC, a BVC-UNBLOCK-ACK
		 * PDU shall be returned. */
		if (bfp->role_sgsn) {
			/* If a BVC-UNBLOCK PDU is received by an SGSN for
			 * the signalling BVC, the PDU is ignored */
			if (bfp->bvci == 0)
				break;
			bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_UNBLOCK_ACK, bfp->nsei, bfp->bvci, 0);
		}
		break;
	case BSSGP_BVCFSM_E_RX_BLOCK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		LOGPFSML(fi, LOGL_NOTICE, "Rx BVC-BLOCK (cause=%s)\n",
			 bssgp_cause_str(*TLVP_VAL(tp, BSSGP_IE_CAUSE)));
		/* If a BVC-BLOCK PDU is received by an SGSN for the signalling BVC, the PDU is ignored */
		if (bfp->bvci == 0) {
			LOGPFSML(fi, LOGL_ERROR, "Rx BVC-BLOCK on BVCI=0 is illegal\n");
			if (bfp->role_sgsn)
				break;
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		if (!bfp->role_sgsn) {
			LOGPFSML(fi, LOGL_ERROR, "Rx BVC-BLOCK on BSS is illegal\n");
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		/* transmit BVC-BLOCK-ACK, transition to BLOCKED state */
		tx = bssgp2_enc_bvc_block_ack(bfp->bvci);
		fi_tx_sig(fi, tx);
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_BLOCKED, 0, 0);
		break;
	case BSSGP_BVCFSM_E_REQ_BLOCK:
		if (bfp->role_sgsn) {
			LOGPFSML(fi, LOGL_ERROR, "SGSN may not initiate BVC-BLOCK\n");
			break;
		}
		if (bfp->bvci == 0) {
			LOGPFSML(fi, LOGL_ERROR, "BVCI 0 cannot be blocked\n");
			break;
		}
		bfp->locally_blocked = true;
		bfp->block_cause = *(uint8_t *)data;
		/* transmit BVC-BLOCK, transition to BLOCKED state and start re-transmit timer */
		tx = bssgp2_enc_bvc_block(bfp->bvci, bfp->block_cause);
		fi_tx_sig(fi, tx);
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_BLOCKED, T1_SECS, T1);
		break;
	case BSSGP_BVCFSM_E_RX_FC_BVC:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		/* we assume osmo_tlv_prot_* has been used before calling here to ensure this */
		OSMO_ASSERT(bfp->role_sgsn);
		rc = bssgp2_dec_fc_bvc(&rx_fc, tp);
		if (rc < 0) {
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		if (bfp->ops->rx_fc_bvc)
			bfp->ops->rx_fc_bvc(bfp->nsei, bfp->bvci, &rx_fc, bfp->ops_priv);
		tx = bssgp2_enc_fc_bvc_ack(rx_fc.tag);
		fi_tx_ptp(fi, tx);
		break;
	case BSSGP_BVCFSM_E_RX_FC_BVC_ACK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		/* we assume osmo_tlv_prot_* has been used before calling here to ensure this */
		OSMO_ASSERT(!bfp->role_sgsn);
		break;
	case BSSGP_BVCFSM_E_REQ_FC_BVC:
		tx_fc = data;
		tx = bssgp2_enc_fc_bvc(tx_fc, bfp->features.negotiated & (BSSGP_XFEAT_GBIT << 8) ?
					&bfp->features.fc_granularity : NULL);
		fi_tx_ptp(fi, tx);
		break;
	}
}

static void bssgp_bvc_fsm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	uint8_t cause;
	const struct tlv_parsed *tp = NULL;
	struct msgb *rx = NULL;

	switch (event) {
	case BSSGP_BVCFSM_E_REQ_RESET:
		bfp->locally_blocked = false;
		cause = bfp->last_reset_cause = *(uint8_t *) data;
		_tx_bvc_reset(fi, cause);
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_WAIT_RESET_ACK, T2_SECS, T2);
#if 0 /* not sure if we really should notify the application if itself has requested the reset? */
		if (bfp->ops && bfp->ops->reset_notification)
			bfp->ops->reset_notification(bfp->nsei, bfp->bvci, NULL, 0, cause, bfp->ops_priv);
#endif
		break;
	case BSSGP_BVCFSM_E_RX_RESET:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		cause = *TLVP_VAL(tp, BSSGP_IE_CAUSE);
		if (bfp->role_sgsn && bfp->bvci != 0)
			bfp->cell_id = bssgp_parse_cell_id(&bfp->ra_id, TLVP_VAL(tp, BSSGP_IE_CELL_ID));
		LOGPFSML(fi, LOGL_NOTICE, "Rx BVC-RESET (cause=%s)\n", bssgp_cause_str(cause));
		if (bfp->bvci == 0)
			update_negotiated_features(fi, tp);
		_tx_bvc_reset_ack(fi);
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_UNBLOCKED, 0, 0);
		if (bfp->ops && bfp->ops->reset_notification) {
			bfp->ops->reset_notification(bfp->nsei, bfp->bvci, &bfp->ra_id, bfp->cell_id,
						     cause, bfp->ops_priv);
		}
		break;
	}
}

static int bssgp_bvc_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	struct msgb *tx;

	switch (fi->T) {
	case T1:
		switch (fi->state) {
		case BSSGP_BVCFSM_S_BLOCKED:
			/* re-transmit BVC-BLOCK */
			tx = bssgp2_enc_bvc_block(bfp->bvci, bfp->block_cause);
			fi_tx_sig(fi, tx);
			osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_BLOCKED, T1_SECS, T1);
			break;
		case BSSGP_BVCFSM_S_UNBLOCKED:
			/* re-transmit BVC-UNBLOCK */
			tx = bssgp2_enc_bvc_unblock(bfp->bvci);
			fi_tx_sig(fi, tx);
			osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_UNBLOCKED, T1_SECS, T1);
			break;
		}
		break;
	case T2:
		switch (fi->state) {
		case BSSGP_BVCFSM_S_WAIT_RESET_ACK:
			/* re-transmit BVC-RESET */
			_tx_bvc_reset(fi, bfp->last_reset_cause);
			osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_WAIT_RESET_ACK, T2_SECS, T2);
			break;
		case BSSGP_BVCFSM_S_UNBLOCKED:
			/* re-transmit BVC-RESET-ACK */
			_tx_bvc_reset_ack(fi);
			osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_UNBLOCKED, T2_SECS, T2);
			break;
		}
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
	return 0;
}



static const struct osmo_fsm_state bssgp_bvc_fsm_states[] = {
	[BSSGP_BVCFSM_S_NULL] = {
		/* initial state from which we must do a RESET */
		.name = "NULL",
		.in_event_mask = 0,
		.out_state_mask = S(BSSGP_BVCFSM_S_WAIT_RESET_ACK) |
				  S(BSSGP_BVCFSM_S_UNBLOCKED),
		.action = bssgp_bvc_fsm_null,
	},
	[BSSGP_BVCFSM_S_BLOCKED] = {
		.name = "BLOCKED",
		.in_event_mask = S(BSSGP_BVCFSM_E_RX_UNBLOCK) |
				 S(BSSGP_BVCFSM_E_RX_BLOCK) |
				 S(BSSGP_BVCFSM_E_RX_BLOCK_ACK) |
				 S(BSSGP_BVCFSM_E_REQ_UNBLOCK),
		.out_state_mask = S(BSSGP_BVCFSM_S_WAIT_RESET_ACK) |
				  S(BSSGP_BVCFSM_S_UNBLOCKED) |
				  S(BSSGP_BVCFSM_S_BLOCKED),
		.action = bssgp_bvc_fsm_blocked,
		.onenter = bssgp_bvc_fsm_blocked_onenter,
	},
	[BSSGP_BVCFSM_S_WAIT_RESET_ACK]= {
		.name = "WAIT_RESET_ACK",
		.in_event_mask = S(BSSGP_BVCFSM_E_RX_RESET_ACK) |
				 S(BSSGP_BVCFSM_E_RX_RESET),
		.out_state_mask = S(BSSGP_BVCFSM_S_UNBLOCKED) |
				  S(BSSGP_BVCFSM_S_BLOCKED) |
				  S(BSSGP_BVCFSM_S_WAIT_RESET_ACK),
		.action = bssgp_bvc_fsm_wait_reset_ack,
		.onenter = _onenter_tail,
	},

	[BSSGP_BVCFSM_S_UNBLOCKED] = {
		.name = "UNBLOCKED",
		.in_event_mask = S(BSSGP_BVCFSM_E_RX_BLOCK) |
				 S(BSSGP_BVCFSM_E_RX_UNBLOCK) |
				 S(BSSGP_BVCFSM_E_RX_UNBLOCK_ACK) |
				 S(BSSGP_BVCFSM_E_REQ_BLOCK) |
				 S(BSSGP_BVCFSM_E_RX_FC_BVC) |
				 S(BSSGP_BVCFSM_E_RX_FC_BVC_ACK) |
				 S(BSSGP_BVCFSM_E_REQ_FC_BVC),
		.out_state_mask = S(BSSGP_BVCFSM_S_BLOCKED) |
				  S(BSSGP_BVCFSM_S_WAIT_RESET_ACK) |
				  S(BSSGP_BVCFSM_S_UNBLOCKED),
		.action = bssgp_bvc_fsm_unblocked,
		.onenter = _onenter_tail,
	},
};

static struct osmo_fsm bssgp_bvc_fsm = {
	.name = "BSSGP-BVC",
	.states = bssgp_bvc_fsm_states,
	.num_states = ARRAY_SIZE(bssgp_bvc_fsm_states),
	.allstate_event_mask = S(BSSGP_BVCFSM_E_REQ_RESET) |
			       S(BSSGP_BVCFSM_E_RX_RESET),
	.allstate_action = bssgp_bvc_fsm_allstate,
	.timer_cb = bssgp_bvc_fsm_timer_cb,
	.log_subsys = DLBSSGP,
	.event_names = ptp_bvc_event_names,
};

static struct osmo_fsm_inst *
_bvc_fsm_alloc(void *ctx, struct gprs_ns2_inst *nsi, bool role_sgsn, uint16_t nsei, uint16_t bvci)
{
	struct osmo_fsm_inst *fi;
	struct bvc_fsm_priv *bfp;
	char idbuf[64];

	/* TODO: encode our role in the id string? */
	snprintf(idbuf, sizeof(idbuf), "NSE%05u-BVC%05u", nsei, bvci);

	fi = osmo_fsm_inst_alloc(&bssgp_bvc_fsm, ctx, NULL, LOGL_INFO, idbuf);
	if (!fi)
		return NULL;

	bfp = talloc_zero(fi, struct bvc_fsm_priv);
	if (!bfp) {
		osmo_fsm_inst_free(fi);
		return NULL;
	}
	fi->priv = bfp;

	bfp->nsi = nsi;
	bfp->role_sgsn = role_sgsn;
	bfp->nsei = nsei;
	bfp->bvci = bvci;
	bfp->max_pdu_len = UINT16_MAX;

	return fi;
}

/*! Allocate a SIGNALING-BVC FSM for the BSS role (facing a remote SGSN).
 *  \param[in] ctx talloc context from which to allocate
 *  \param[in] nsi NS Instance on which this BVC operates
 *  \param[in] nsei NS Entity Identifier on which this BVC operates
 *  \param[in] features Feature [byte 0] and Extended Feature [byte 1] bitmap
 *  \returns newly-allocated FSM Instance; NULL in case of error */
struct osmo_fsm_inst *
bssgp_bvc_fsm_alloc_sig_bss(void *ctx, struct gprs_ns2_inst *nsi, uint16_t nsei, uint32_t features)
{
	struct osmo_fsm_inst *fi = _bvc_fsm_alloc(ctx, nsi, false, nsei, 0);
	struct bvc_fsm_priv *bfp;

	if (!fi)
		return NULL;

	bfp = fi->priv;
	bfp->features.advertised = features;

	return fi;
}

/*! Allocate a PTP-BVC FSM for the BSS role (facing a remote SGSN).
 *  \param[in] ctx talloc context from which to allocate
 *  \param[in] nsi NS Instance on which this BVC operates
 *  \param[in] nsei NS Entity Identifier on which this BVC operates
 *  \param[in] bvci BVCI of this FSM
 *  \param[in] ra_id Routing Area Identity of the cell (reported to SGSN)
 *  \param[in] cell_id Cell Identifier of the cell (reported to SGSN)
 *  \returns newly-allocated FSM Instance; NULL in case of error */
struct osmo_fsm_inst *
bssgp_bvc_fsm_alloc_ptp_bss(void *ctx, struct gprs_ns2_inst *nsi, uint16_t nsei,
			    uint16_t bvci, const struct gprs_ra_id *ra_id, uint16_t cell_id)
{
	struct osmo_fsm_inst *fi;
	struct bvc_fsm_priv *bfp;

	OSMO_ASSERT(bvci >= 2);
	OSMO_ASSERT(ra_id);

	fi = _bvc_fsm_alloc(ctx, nsi, false, nsei, bvci);
	if (!fi)
		return NULL;

	bfp = fi->priv;
	bfp->ra_id = *ra_id;
	bfp->cell_id = cell_id;

	return fi;
}

/*! Allocate a SIGNALING-BVC FSM for the SGSN role (facing a remote BSS).
 *  \param[in] ctx talloc context from which to allocate
 *  \param[in] nsi NS Instance on which this BVC operates
 *  \param[in] nsei NS Entity Identifier on which this BVC operates
 *  \param[in] features Feature [byte 0] and Extended Feature [byte 1] bitmap
 *  \returns newly-allocated FSM Instance; NULL in case of error */
struct osmo_fsm_inst *
bssgp_bvc_fsm_alloc_sig_sgsn(void *ctx, struct gprs_ns2_inst *nsi, uint16_t nsei, uint32_t features)
{
	struct osmo_fsm_inst *fi = _bvc_fsm_alloc(ctx, nsi, true, nsei, 0);
	struct bvc_fsm_priv *bfp;

	if (!fi)
		return NULL;

	bfp = fi->priv;
	bfp->features.advertised = features;

	return fi;
}

/*! Allocate a PTP-BVC FSM for the SGSN role (facing a remote BSS).
 *  \param[in] ctx talloc context from which to allocate
 *  \param[in] nsi NS Instance on which this BVC operates
 *  \param[in] nsei NS Entity Identifier on which this BVC operates
 *  \param[in] bvci BVCI of this FSM
 *  \returns newly-allocated FSM Instance; NULL in case of error */
struct osmo_fsm_inst *
bssgp_bvc_fsm_alloc_ptp_sgsn(void *ctx, struct gprs_ns2_inst *nsi, uint16_t nsei, uint16_t bvci)
{
	struct osmo_fsm_inst *fi;

	OSMO_ASSERT(bvci >= 2);

	fi = _bvc_fsm_alloc(ctx, nsi, true, nsei, bvci);
	if (!fi)
		return NULL;

	return fi;
}

/*! Set the 'operations' callbacks + private data.
 *  \param[in] fi FSM instance for which the data shall be set
 *  \param[in] ops BSSGP BVC FSM operations (call-back functions) to register
 *  \param[in] ops_priv opaque/private data pointer passed through to call-backs */
void bssgp_bvc_fsm_set_ops(struct osmo_fsm_inst *fi, const struct bssgp_bvc_fsm_ops *ops, void *ops_priv)
{
	struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &bssgp_bvc_fsm);

	bfp->ops = ops;
	bfp->ops_priv = ops_priv;
}

/*! Return if the given BVC FSM is in UNBLOCKED state. */
bool bssgp_bvc_fsm_is_unblocked(struct osmo_fsm_inst *fi)
{
	return fi->state == BSSGP_BVCFSM_S_UNBLOCKED;
}

/*! Determine the cause value why given BVC FSM is blocked. */
uint8_t bssgp_bvc_fsm_get_block_cause(struct osmo_fsm_inst *fi)
{
	struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &bssgp_bvc_fsm);
	return bfp->block_cause;
}

/*! Return the advertised features / extended features. */
uint32_t bssgp_bvc_fsm_get_features_advertised(struct osmo_fsm_inst *fi)
{
	struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &bssgp_bvc_fsm);
	return bfp->features.advertised;
}

/*! Return the received features / extended features. */
uint32_t bssgp_bvc_fsm_get_features_received(struct osmo_fsm_inst *fi)
{
	struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &bssgp_bvc_fsm);
	return bfp->features.received;
}

/*! Return the negotiated features / extended features. */
uint32_t bssgp_bvc_fsm_get_features_negotiated(struct osmo_fsm_inst *fi)
{
	struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &bssgp_bvc_fsm);
	return bfp->features.negotiated;
}

/*! Set the maximum size of a BSSGP PDU.
 *! On the NS layer this corresponds to the size of an NS SDU in NS-UNITDATA (3GPP TS 48.016 Ch. 9.2.10) */
void bssgp_bvc_fsm_set_max_pdu_len(struct osmo_fsm_inst *fi, uint16_t max_pdu_len) {
	struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &bssgp_bvc_fsm);
	bfp->max_pdu_len = max_pdu_len;
}

/*! Return the maximum size of a BSSGP PDU
 *! On the NS layer this corresponds to the size of an NS SDU in NS-UNITDATA (3GPP TS 48.016 Ch. 9.2.10) */
uint16_t bssgp_bvc_fsm_get_max_pdu_len(const struct osmo_fsm_inst *fi)
{
	const struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &bssgp_bvc_fsm);
	return bfp->max_pdu_len;
}


static __attribute__((constructor)) void on_dso_load_bvc_fsm(void)
{
	OSMO_ASSERT(osmo_fsm_register(&bssgp_bvc_fsm) == 0);
}
