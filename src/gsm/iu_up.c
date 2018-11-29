/*! \file iu_up.c
 * IuUP (Iu User Plane) according to 3GPP TS 25.415 */
/*
 * (C) 2017 by Harald Welte <laforge@gnumonks.org>
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301, USA.
 */

#include <errno.h>

#include <osmocom/core/crc8gen.h>
#include <osmocom/core/crc16gen.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/prim.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/logging.h>

#include <osmocom/gsm/prim.h>
#include <osmocom/gsm/protocol/gsm_25_415.h>

/***********************************************************************
 * CRC Calculation
 ***********************************************************************/

/* Section 6.6.3.8 Header CRC */
const struct osmo_crc8gen_code iuup_hdr_crc_code = {
	.bits = 6,
	.poly = 47,
	.init = 0,
	.remainder = 0,
};

/* Section 6.6.3.9 Payload CRC */
const struct osmo_crc16gen_code iuup_data_crc_code = {
	.bits = 10,
	.poly = 563,
	.init = 0,
	.remainder = 0,
};

static int iuup_get_payload_offset(const uint8_t *iuup_pdu)
{
	uint8_t pdu_type = iuup_pdu[0] >> 4;
	switch (pdu_type) {
	case 0:
	case 14:
		return 4;
	case 1:
		return 3;
	default:
		return -1;
	}
}

int osmo_iuup_compute_payload_crc(const uint8_t *iuup_pdu, unsigned int pdu_len)
{
	ubit_t buf[1024*8];
	uint8_t pdu_type;
	int offset, payload_len_bytes;

	if (pdu_len < 1)
		return -1;

	pdu_type = iuup_pdu[0] >> 4;

	/* Type 1 has no CRC */
	if (pdu_type == 1)
		return 0;

	offset = iuup_get_payload_offset(iuup_pdu);
	if (offset < 0)
		return offset;

	if (pdu_len < offset)
		return -1;

	payload_len_bytes = pdu_len - offset;
	osmo_pbit2ubit(buf, iuup_pdu+offset, payload_len_bytes*8);
	return osmo_crc16gen_compute_bits(&iuup_data_crc_code, buf, payload_len_bytes*8);
}

int osmo_iuup_compute_header_crc(const uint8_t *iuup_pdu, unsigned int pdu_len)
{
	ubit_t buf[2*8];

	if (pdu_len < 2)
		return -1;

	osmo_pbit2ubit(buf, iuup_pdu, 2*8);
	return osmo_crc8gen_compute_bits(&iuup_hdr_crc_code, buf, 2*8);
}

/***********************************************************************
 * Primitives towards the lower layers (typically RTP transport)
 ***********************************************************************/
enum osmo_tnl_iuup_prim_type {
	OSMO_TNL_IUUP_UNITDATA,
};

struct osmo_tnl_iuup_prim {
	struct osmo_prim_hdr oph;
};

/***********************************************************************
 * Primitives towards the upper layers at the RNL SAP
 ***********************************************************************/

/* 3GPP TS 25.415 Section 7.2.1 */
enum osmo_rnl_iuup_prim_type {
	OSMO_RNL_IUUP_CONFIG,
	OSMO_RNL_IUUP_DATA,
	OSMO_RNL_IUUP_STATUS,
	OSMO_RNL_IUUP_UNIT_DATA,
};

struct osmo_rnl_iuup_config {
	/* transparent (true) or SMpSDU (false) */
	bool transparent;
	/* should we actively transmit INIT in SmpSDU mode? */
	bool active;
};

struct osmo_rnl_iuup_data {
	uint8_t rfci;
	uint8_t frame_nr;
	uint8_t fqc;
};

struct osmo_rnl_iuup_status {
	enum iuup_procedure procedure;
	union {
		struct {
			enum iuup_error_cause cause;
			enum iuup_error_distance distance;
		} error_event;
		struct {
		} initialization;
		struct {
		} rate_control;
		struct {
		} time_alignment;
	} u;
};

/* SAP on the upper side of IuUP, towards the user */
struct osmo_rnl_iuup_prim {
	struct osmo_prim_hdr oph;
	union {
		struct osmo_rnl_iuup_config config;
		struct osmo_rnl_iuup_data data;
		struct osmo_rnl_iuup_status status;
		//struct osmo_rnl_iuup_unitdata unitdata;
	} u;
};

/***********************************************************************
 * Internal State / FSM (Annex B)
 ***********************************************************************/

#define S(x)	(1 << (x))

struct osmo_timer_nt {
	uint32_t t_ms;	/* time in ms */
	uint32_t n;	/* number of repetitons */
	struct osmo_timer_list timer;
};

struct osmo_iuup_instance {
	struct {
		bool transparent;
		bool active;
		bool use_type0_crc;
	} config;
	struct osmo_fsm_inst *fi;
	struct {
		struct osmo_timer_nt init;
		struct osmo_timer_nt ta;
		struct osmo_timer_nt rc;
	} timer;
	/* call-back function to pass primitives up to the user */
	osmo_prim_cb	user_prim_cb;
	osmo_prim_cb	transport_prim_cb;
};

enum iuup_fsm_state {
	IUUP_FSM_ST_NULL,
	IUUP_FSM_ST_INIT,
	IUUP_FSM_ST_TrM_DATA_XFER_READY,
	IUUP_FSM_ST_SMpSDU_DATA_XFER_READY,
};

enum iuup_fsm_event {
	IUUP_FSM_EVT_IUUP_CONFIG_REQ,
	IUUP_FSM_EVT_IUUP_DATA_REQ,
	IUUP_FSM_EVT_IUUP_DATA_IND,
	IUUP_FSM_EVT_SSASAR_UNITDATA_REQ,
	IUUP_FSM_EVT_SSASAR_UNITDATA_IND,
	IUUP_FSM_EVT_IUUP_UNITDATA_REQ,
	IUUP_FSM_EVT_IUUP_UNITDATA_IND,
	IUUP_FSM_EVT_INIT,
	IUUP_FSM_EVT_LAST_INIT_ACK,
	IUUP_FSM_EVT_INIT_NACK,
};

static const struct value_string iuup_fsm_event_names[] = {
	{ IUUP_FSM_EVT_IUUP_CONFIG_REQ, 	"IuUP-CONFIG.req" },
	{ IUUP_FSM_EVT_IUUP_DATA_REQ, 		"IuUP-DATA.req" },
	{ IUUP_FSM_EVT_IUUP_DATA_IND, 		"IuUP-DATA.ind" },
	{ IUUP_FSM_EVT_SSASAR_UNITDATA_REQ, 	"SSSAR-UNITDATA.req" },
	{ IUUP_FSM_EVT_SSASAR_UNITDATA_IND, 	"SSSAR-UNITDATA.ind" },
	{ IUUP_FSM_EVT_IUUP_UNITDATA_REQ,	"IuUP-UNITDATA.req" },
	{ IUUP_FSM_EVT_IUUP_UNITDATA_IND,	"IuUP-UNITDATA.ind" },
	{ IUUP_FSM_EVT_INIT,			"INIT" },
	{ IUUP_FSM_EVT_LAST_INIT_ACK,		"LAST_INIT_ACK" },
	{ IUUP_FSM_EVT_INIT_NACK,		"INIT_NACK" },
	{ 0, NULL }
};

static inline uint8_t iuup_get_pdu_type(const uint8_t *data)
{
	return data[0] >> 4;
}

static inline uint8_t iuup_get_hdr_crc(const uint8_t *data)
{
	return data[2] >> 2;
}

static void iuup_fsm_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_iuup_instance *iui = fi->priv;
	struct osmo_rnl_iuup_prim *user_prim = NULL;

	switch (event) {
	case IUUP_FSM_EVT_IUUP_CONFIG_REQ:
		user_prim = data;
		if (user_prim->u.config.transparent)
			osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_TrM_DATA_XFER_READY, 0, 0);
		else {
			osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_INIT, 0, 0);
			if (iui->config.active) {
				/* FIXME: Active side: Send Frame + Start timer */
			}
		}
		break;
	}
}

/* transform a RNL primitive into a TNL primitive (down the stack) */
static struct osmo_tnl_iuup_prim *rnl_to_tnl_data(struct osmo_iuup_instance *iui,
						  struct osmo_rnl_iuup_prim *rip)
{
	struct osmo_tnl_iuup_prim *tip;
	struct osmo_rnl_iuup_data dt;
	struct msgb *msg;

	OSMO_ASSERT(OSMO_PRIM_HDR(&rip->oph) == OSMO_PRIM(OSMO_RNL_IUUP_DATA, PRIM_OP_REQUEST));

	msg = rip->oph.msg;
	dt = rip->u.data;

	/* pull up to the IuUP payload and push a new primitive header in front */
	msgb_pull_to_l3(msg);

	/* push the PDU TYPE 0 / 1 header in front of the payload */
	if (iui->config.use_type0_crc) {
		struct iuup_pdutype0_hdr *h0 = msg->l2h = msgb_push(msg, sizeof(*h0));
		h0->frame_nr = dt.frame_nr;
		h0->pdu_type = IUUP_PDU_T_DATA_CRC;
		h0->rfci = dt.rfci;
		h0->fqc = dt.fqc;
		h0->header_crc = osmo_iuup_compute_header_crc(msgb_l2(msg), msgb_l2len(msg));
		h0->payload_crc = osmo_iuup_compute_payload_crc(msgb_l2(msg), msgb_l2len(msg));
	} else {
		struct iuup_pdutype1_hdr *h1 = msg->l2h = msgb_push(msg, sizeof(*h1));
		h1->frame_nr = dt.frame_nr;
		h1->pdu_type = IUUP_PDU_T_DATA_NOCRC;
		h1->rfci = dt.rfci;
		h1->fqc = dt.fqc;
		h1->header_crc = osmo_iuup_compute_header_crc(msgb_l2(msg), msgb_l2len(msg));
		h1->spare = 0;
	}

	tip = (struct osmo_tnl_iuup_prim *) msgb_push(msg, sizeof(*tip));
	osmo_prim_init(&tip->oph, SAP_IUUP_TNL, OSMO_TNL_IUUP_UNITDATA, PRIM_OP_REQUEST, msg);

	return tip;
}

/* transform a TNL primitive into a RNL primitive (up the stack) */
static struct osmo_rnl_iuup_prim *tnl_to_rnl_data(struct osmo_tnl_iuup_prim *tip)
{
	struct msgb *msg;
	struct iuup_pdutype0_hdr *h0;
	struct iuup_pdutype1_hdr *h1;
	struct osmo_rnl_iuup_data dt;
	struct osmo_rnl_iuup_prim *rip;

	msg = tip->oph.msg;

	OSMO_ASSERT(OSMO_PRIM_HDR(&tip->oph) == OSMO_PRIM(OSMO_TNL_IUUP_UNITDATA, PRIM_OP_INDICATION));

	switch (iuup_get_pdu_type(msgb_l2(msg))) {
	case IUUP_PDU_T_DATA_CRC:
		h0 = (struct iuup_pdutype0_hdr *) msgb_l2(msg);
		dt.rfci = h0->rfci;
		dt.frame_nr = h0->frame_nr;
		dt.fqc = h0->frame_nr;
		break;
	case IUUP_PDU_T_DATA_NOCRC:
		h1 = (struct iuup_pdutype1_hdr *) msgb_l2(msg);
		dt.rfci = h1->rfci;
		dt.frame_nr = h1->frame_nr;
		dt.fqc = h1->frame_nr;
		break;
	}

	/* pull up to the IuUP payload and push a new primitive header in front */
	msgb_pull_to_l3(msg);
	rip = (struct osmo_rnl_iuup_prim *) msgb_push(msg, sizeof(*rip));
	osmo_prim_init(&rip->oph, SAP_IUUP_RNL, OSMO_RNL_IUUP_DATA, PRIM_OP_INDICATION, msg);
	rip->u.data = dt;

	return rip;
}

/* transparent mode data transfer */
static void iuup_fsm_trm_data(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct osmo_iuup_instance *iui = fi->priv;

	switch (event) {
	case IUUP_FSM_EVT_IUUP_CONFIG_REQ:
		osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_NULL, 0, 0);
		break;
	case IUUP_FSM_EVT_IUUP_DATA_REQ:
		/* Data coming down from RNL (user) towards TNL (transport) */
		break;
	case IUUP_FSM_EVT_IUUP_DATA_IND:
		/* Data coming up from TNL (transport) towards RNL (user) */
		break;
	case IUUP_FSM_EVT_IUUP_UNITDATA_REQ:
	case IUUP_FSM_EVT_IUUP_UNITDATA_IND:
	case IUUP_FSM_EVT_SSASAR_UNITDATA_REQ:
	case IUUP_FSM_EVT_SSASAR_UNITDATA_IND:
		/* no state change */
		break;
	}
}

static void iuup_fsm_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct osmo_iuup_instance *iui = fi->priv;

	switch (event) {
	case IUUP_FSM_EVT_IUUP_CONFIG_REQ:
		/* the only permitted 'config req' type is the request to release the instance */
		osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_NULL, 0, 0);
		break;
	case IUUP_FSM_EVT_LAST_INIT_ACK:
		/* last INIT ACK was received, transition to DATA_XFER_READY state */
		osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_SMpSDU_DATA_XFER_READY, 0, 0);
		break;
	}
}

static void iuup_fsm_smpsdu_data(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_iuup_instance *iui = fi->priv;
	struct osmo_rnl_iuup_prim *rip = NULL;
	struct osmo_tnl_iuup_prim *tip = NULL;

	switch (event) {
	case IUUP_FSM_EVT_IUUP_CONFIG_REQ:
		rip = data;
		osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_NULL, 0, 0);
		break;
	case IUUP_FSM_EVT_IUUP_DATA_REQ:
		/* Data coming down from RNL (user) towards TNL (transport) */
		rip = data;
		tip = rnl_to_tnl_data(iui, rip);
		iui->transport_prim_cb(&tip->oph, iui);
		break;
	case IUUP_FSM_EVT_IUUP_DATA_IND:
		/* Data coming up from TNL (transport) towards RNL (user) */
		tip = data;
		rip = tnl_to_rnl_data(tip);
		iui->user_prim_cb(&rip->oph, iui);
		break;
	case IUUP_FSM_EVT_IUUP_UNITDATA_REQ:
	case IUUP_FSM_EVT_IUUP_UNITDATA_IND:
	case IUUP_FSM_EVT_SSASAR_UNITDATA_REQ:
	case IUUP_FSM_EVT_SSASAR_UNITDATA_IND:
		/* no state change */
		break;
	}
}

static const struct osmo_fsm_state iuup_fsm_states[] = {
	[IUUP_FSM_ST_NULL] = {
		.in_event_mask = S(IUUP_FSM_EVT_IUUP_CONFIG_REQ),
		.out_state_mask = S(IUUP_FSM_ST_INIT) |
				  S(IUUP_FSM_ST_TrM_DATA_XFER_READY),
		.name = "NULL",
		.action = iuup_fsm_null,
	},
	[IUUP_FSM_ST_TrM_DATA_XFER_READY] = {
		.in_event_mask = S(IUUP_FSM_EVT_IUUP_CONFIG_REQ) |
				 S(IUUP_FSM_EVT_IUUP_DATA_REQ) |
				 S(IUUP_FSM_EVT_IUUP_DATA_IND) |
				 S(IUUP_FSM_EVT_IUUP_UNITDATA_REQ) |
				 S(IUUP_FSM_EVT_IUUP_UNITDATA_IND) |
				 S(IUUP_FSM_EVT_SSASAR_UNITDATA_REQ) |
				 S(IUUP_FSM_EVT_SSASAR_UNITDATA_IND),
		.out_state_mask = S(IUUP_FSM_ST_NULL),
		.name = "TrM Data Transfer Ready",
		.action = iuup_fsm_trm_data,
	},
	[IUUP_FSM_ST_INIT] = {
		//.in_event_mask = ,
		.out_state_mask = S(IUUP_FSM_ST_NULL) |
				  S(IUUP_FSM_ST_SMpSDU_DATA_XFER_READY),
		.name = "Initialisation",
		.action = iuup_fsm_init,
	},
	[IUUP_FSM_ST_SMpSDU_DATA_XFER_READY] = {
		.in_event_mask = S(IUUP_FSM_EVT_IUUP_DATA_REQ) |
				 S(IUUP_FSM_EVT_IUUP_DATA_IND),
		.out_state_mask = S(IUUP_FSM_ST_NULL) |
				  S(IUUP_FSM_ST_INIT),
		.name = "SMpSDU Data Transfer Ready",
		.action = iuup_fsm_smpsdu_data,
	},
};

struct osmo_fsm iuup_fsm = {
	.name = "IuUP",
	.states = iuup_fsm_states,
	.num_states = ARRAY_SIZE(iuup_fsm_states),
	.log_subsys = DLMGCP,
	.event_names = iuup_fsm_event_names,
};

static int iuup_verify_pdu(const uint8_t *data, unsigned int len)
{
	int header_crc_computed, payload_crc_computed;
	uint8_t pdu_type = iuup_get_pdu_type(data);
	struct iuup_pdutype0_hdr *t0h;

	if (len < 3)
		return -EINVAL;

	header_crc_computed = osmo_iuup_compute_header_crc(data, len);
	if (iuup_get_hdr_crc(data) != header_crc_computed) {
		return -EIO;
	}
	switch (pdu_type) {
	case IUUP_PDU_T_DATA_NOCRC:
		if (len < 4)
			return -EINVAL;
		break;
	case IUUP_PDU_T_DATA_CRC:
	case IUUP_PDU_T_CONTROL:
		t0h = (struct iuup_pdutype0_hdr *) data;
		payload_crc_computed = osmo_iuup_compute_payload_crc(data, len);
		if (t0h->payload_crc != payload_crc_computed)
			return -EIO;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/* A IuUP TNL SAP primitive from transport (lower layer) */
int osmo_iuup_tnl_prim_up(struct osmo_iuup_instance *inst, struct osmo_prim_hdr *oph)
{
	struct osmo_tnl_iuup_prim *tnp = (struct osmo_tnl_iuup_prim *) oph;
	struct iuup_pdutype14_hdr *t14h;
	int rc = 0;

	OSMO_ASSERT(oph->sap == SAP_IUUP_TNL);

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_TNL_IUUP_UNITDATA, PRIM_OP_INDICATION):
		if (iuup_verify_pdu(msgb_l2(oph->msg), msgb_l2len(oph->msg)) < 0) {
			LOGPFSML(inst->fi, LOGL_NOTICE, "Discarding invalid IuUP PDU");
			/* don't return error as the caller is not responsible for the PDU which
			 * was transmitted from some remote peer */
			return 0;
		}
		switch (iuup_get_pdu_type(msgb_l2(oph->msg))) {
		case IUUP_PDU_T_DATA_CRC:
			oph->msg->l3h = msgb_l2(oph->msg) + sizeof(struct iuup_pdutype0_hdr);
			rc = osmo_fsm_inst_dispatch(inst->fi, IUUP_FSM_EVT_IUUP_DATA_IND, tnp);
			break;
		case IUUP_PDU_T_DATA_NOCRC:
			oph->msg->l3h = msgb_l2(oph->msg) + sizeof(struct iuup_pdutype1_hdr);
			rc = osmo_fsm_inst_dispatch(inst->fi, IUUP_FSM_EVT_IUUP_DATA_IND, tnp);
			break;
		case IUUP_PDU_T_CONTROL:
			t14h = (struct iuup_pdutype14_hdr *) msgb_l2(oph->msg);
			switch (t14h->ack_nack) {
			case IUUP_AN_PROCEDURE:
				switch (t14h->proc_ind) {
				case IUUP_PROC_INIT:
					rc = osmo_fsm_inst_dispatch(inst->fi, IUUP_FSM_EVT_INIT, tnp);
					break;
				case IUUP_PROC_RATE_CTRL:
				case IUUP_PROC_TIME_ALIGN:
				case IUUP_PROC_ERR_EVENT:
					LOGPFSML(inst->fi, LOGL_NOTICE, "Received Request for "
						"unsupported IuUP procedure %u\n", t14h->proc_ind);
					break;
				default:
					LOGPFSML(inst->fi, LOGL_NOTICE, "Received Request for "
						"unknown IuUP procedure %u\n", t14h->proc_ind);
					break;
				}
				break;
			case IUUP_AN_ACK:
				switch (t14h->proc_ind) {
				case IUUP_PROC_INIT:
					rc = osmo_fsm_inst_dispatch(inst->fi, 
								    IUUP_FSM_EVT_LAST_INIT_ACK, tnp);
					break;
				default:
					LOGPFSML(inst->fi, LOGL_ERROR, "Received ACK for "
						"unknown IuUP procedure %u\n", t14h->proc_ind);
					break;
				}
				break;
			case IUUP_AN_NACK:
				switch (t14h->proc_ind) {
				case IUUP_PROC_INIT:
					rc = osmo_fsm_inst_dispatch(inst->fi,
								    IUUP_FSM_EVT_INIT_NACK, tnp);
					break;
				default:
					LOGPFSML(inst->fi, LOGL_ERROR, "Received NACK for "
						"unknown IuUP procedure %u\n", t14h->proc_ind);
					break;
				}
				break;
			default:
				LOGPFSML(inst->fi, LOGL_ERROR, "Received unknown IuUP ACK/NACK\n");
				break;
			}
			break;
		default:
			LOGPFSML(inst->fi, LOGL_NOTICE, "Received unknown IuUP PDU type %u\n",
				iuup_get_pdu_type(msgb_l2(oph->msg)));
			break;
		}
		break;
	default:
		/* exception: return an error code due to a wrong primitive */
		return -EINVAL;
	}

	return rc;
}

/* A IuUP RNL SAP primitive from user (higher layer) */
int osmo_iuup_rnl_prim_down(struct osmo_iuup_instance *inst, struct osmo_prim_hdr *oph)
{
	struct osmo_rnl_iuup_prim *rnp = (struct osmo_rnl_iuup_prim *) oph;
	int rc;

	OSMO_ASSERT(oph->sap == SAP_IUUP_RNL);

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_RNL_IUUP_CONFIG, PRIM_OP_REQUEST):
		rc = osmo_fsm_inst_dispatch(inst->fi, IUUP_FSM_EVT_IUUP_CONFIG_REQ, rnp);
		break;
	case OSMO_PRIM(OSMO_RNL_IUUP_DATA, PRIM_OP_REQUEST):
		rc = osmo_fsm_inst_dispatch(inst->fi, IUUP_FSM_EVT_IUUP_DATA_REQ, rnp);
		break;
	default:
		rc = -EINVAL;
	}
	return rc;
}
