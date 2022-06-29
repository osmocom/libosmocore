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
 */

#include <errno.h>
#include <inttypes.h>

#include <osmocom/core/crc8gen.h>
#include <osmocom/core/crc16gen.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/prim.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/logging.h>

#include <osmocom/gsm/prim.h>
#include <osmocom/gsm/protocol/gsm_25_415.h>
#include <osmocom/gsm/iuup.h>

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
 * Internal State / FSM (Annex B)
 ***********************************************************************/

#define S(x)	(1 << (x))

#define IUUP_TIMER_INIT 1
#define IUUP_TIMER_TA 2
#define IUUP_TIMER_RC 3

struct osmo_timer_nt {
	uint32_t n;	/* number of repetitions */
	struct osmo_iuup_tnl_prim *retrans_itp;
	struct osmo_timer_list timer;
};

struct osmo_iuup_instance {
	struct osmo_iuup_rnl_config config;
	struct osmo_fsm_inst *fi;

	uint8_t mode_version;

	struct {
		struct osmo_timer_nt init;
		struct osmo_timer_nt ta;
		struct osmo_timer_nt rc;
	} timer;
	/* call-back function to pass primitives up to the user */
	osmo_prim_cb	user_prim_cb;
	void		*user_prim_priv;
	osmo_prim_cb	transport_prim_cb;
	void		*transport_prim_priv;
	uint8_t		type14_fn; /* 2 bits */
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
	IUUP_FSM_EVT_IUUP_STATUS_REQ,
	IUUP_FSM_EVT_IUUP_STATUS_IND,
	IUUP_FSM_EVT_SSASAR_UNITDATA_REQ,
	IUUP_FSM_EVT_SSASAR_UNITDATA_IND,
	IUUP_FSM_EVT_IUUP_UNITDATA_REQ,
	IUUP_FSM_EVT_IUUP_UNITDATA_IND,
	IUUP_FSM_EVT_INIT,
	IUUP_FSM_EVT_LAST_INIT_ACK,
	IUUP_FSM_EVT_INIT_NACK,
};

static const struct value_string iuup_fsm_event_names[] = {
	{ IUUP_FSM_EVT_IUUP_CONFIG_REQ,		"IuUP-CONFIG-req" },
	{ IUUP_FSM_EVT_IUUP_DATA_REQ,		"IuUP-DATA-req" },
	{ IUUP_FSM_EVT_IUUP_DATA_IND,		"IuUP-DATA-ind" },
	{ IUUP_FSM_EVT_IUUP_STATUS_REQ,		"IuUP-STATUS-req" },
	{ IUUP_FSM_EVT_IUUP_STATUS_IND,		"IuUP-STATUS-ind" },
	{ IUUP_FSM_EVT_SSASAR_UNITDATA_REQ,	"SSSAR-UNITDATA-req" },
	{ IUUP_FSM_EVT_SSASAR_UNITDATA_IND,	"SSSAR-UNITDATA-ind" },
	{ IUUP_FSM_EVT_IUUP_UNITDATA_REQ,	"IuUP-UNITDATA-req" },
	{ IUUP_FSM_EVT_IUUP_UNITDATA_IND,	"IuUP-UNITDATA-ind" },
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

/* Helper functions to store non-packed structs in msgb so that pointers are properly aligned: */
#define IUUP_MSGB_SIZE 4096
#define PTR_ALIGNMENT_BYTES 8
#define IUUP_MSGB_HEADROOM_MIN_REQUIRED	(OSMO_MAX(sizeof(struct osmo_iuup_tnl_prim), sizeof(struct osmo_iuup_rnl_prim)) + (PTR_ALIGNMENT_BYTES - 1))
static inline struct msgb *osmo_iuup_msgb_alloc_c(void *ctx, size_t size)
{
	osmo_static_assert(size > IUUP_MSGB_HEADROOM_MIN_REQUIRED, iuup_msgb_alloc_headroom_bigger);
	return msgb_alloc_headroom_c(ctx, size, IUUP_MSGB_HEADROOM_MIN_REQUIRED, "iuup-msgb");
}

/* push data so that the resulting pointer to write to is aligned to 8 byte */
static inline __attribute__((assume_aligned(PTR_ALIGNMENT_BYTES)))
unsigned char *aligned_msgb_push(struct msgb *msg, unsigned int len)
{
	uint8_t *ptr = (msgb_data(msg) - len);
	size_t extra_size = ((uintptr_t)ptr & (PTR_ALIGNMENT_BYTES - 1));

	return msgb_push(msg, len + extra_size);
}

struct osmo_iuup_rnl_prim *osmo_iuup_rnl_prim_alloc(void *ctx, unsigned int primitive, unsigned int operation, unsigned int size)
{
	struct msgb *msg;
	struct osmo_iuup_rnl_prim *irp;

	msg = osmo_iuup_msgb_alloc_c(ctx, size);
	irp = (struct osmo_iuup_rnl_prim *)aligned_msgb_push(msg, sizeof(*irp));
	osmo_prim_init(&irp->oph, SAP_IUUP_RNL, primitive, operation, msg);
	return irp;
}

struct osmo_iuup_tnl_prim *osmo_iuup_tnl_prim_alloc(void *ctx, unsigned int primitive, unsigned int operation, unsigned int size)
{
	struct msgb *msg;
	struct osmo_iuup_tnl_prim *itp;

	msg = osmo_iuup_msgb_alloc_c(ctx, size);
	itp = (struct osmo_iuup_tnl_prim *) aligned_msgb_push(msg, sizeof(*itp));
	osmo_prim_init(&itp->oph, SAP_IUUP_TNL, primitive, operation, msg);
	return itp;
}

/* 6.6.2.3.2 */
static struct osmo_iuup_tnl_prim *itp_ctrl_ack_alloc(struct osmo_iuup_instance *iui, enum iuup_procedure proc_ind, uint8_t fn)
{
	struct osmo_iuup_tnl_prim *itp;
	struct iuup_ctrl_ack *ack;
	itp = osmo_iuup_tnl_prim_alloc(iui, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_REQUEST, IUUP_MSGB_SIZE);
	itp->oph.msg->l2h = msgb_put(itp->oph.msg, sizeof(struct iuup_ctrl_ack));
	ack = (struct iuup_ctrl_ack *) msgb_l2(itp->oph.msg);
	*ack = (struct iuup_ctrl_ack){
		.hdr = {
			.frame_nr = fn,
			.ack_nack = IUUP_AN_ACK,
			.pdu_type = IUUP_PDU_T_CONTROL,
			.proc_ind = proc_ind,
			.mode_version = iui->mode_version,
			.payload_crc_hi = 0,
			.header_crc = 0,
			.payload_crc_lo = 0,
		},
	};
	ack->hdr.header_crc = osmo_iuup_compute_header_crc(msgb_l2(itp->oph.msg), msgb_l2len(itp->oph.msg));
	return itp;
}

/* 6.6.2.3.3 */
static struct osmo_iuup_tnl_prim *tnp_ctrl_nack_alloc(struct osmo_iuup_instance *iui, enum iuup_procedure proc_ind, enum iuup_error_cause error_cause, uint8_t fn)
{
	struct osmo_iuup_tnl_prim *itp;
	struct iuup_ctrl_nack *nack;
	itp = osmo_iuup_tnl_prim_alloc(iui, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_REQUEST, IUUP_MSGB_SIZE);
	itp->oph.msg->l2h = msgb_put(itp->oph.msg, sizeof(struct iuup_ctrl_nack));
	nack = (struct iuup_ctrl_nack *) msgb_l2(itp->oph.msg);
	*nack = (struct iuup_ctrl_nack){
		.hdr = {
			.frame_nr = fn,
			.ack_nack = IUUP_AN_NACK,
			.pdu_type = IUUP_PDU_T_CONTROL,
			.proc_ind = proc_ind,
			.mode_version = iui->mode_version,
			.payload_crc_hi = 0,
			.header_crc = 0,
			.payload_crc_lo = 0,
		},
		.spare = 0,
		.error_cause = error_cause,
	};
	nack->hdr.header_crc = osmo_iuup_compute_header_crc(msgb_l2(itp->oph.msg), msgb_l2len(itp->oph.msg));
	return itp;
}

/* 6.6.2.3.4.1 */
static struct osmo_iuup_tnl_prim *tnp_ctrl_init_alloc(struct osmo_iuup_instance *iui)
{
	struct osmo_iuup_tnl_prim *itp;
	struct iuup_pdutype14_hdr *hdr;
	struct iuup_ctrl_init_hdr *ihdr;
	struct iuup_ctrl_init_rfci_hdr *ihdr_rfci;
	struct iuup_ctrl_init_tail *itail;
	unsigned int i, j;
	uint16_t payload_crc;
	uint8_t rfci_cnt;
	struct msgb *msg;

	itp = osmo_iuup_tnl_prim_alloc(iui, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_REQUEST, IUUP_MSGB_SIZE);
	msg = itp->oph.msg;

	msg->l2h = msgb_put(msg, sizeof(*hdr));
	hdr = (struct iuup_pdutype14_hdr *)msgb_l2(msg);
	hdr->frame_nr = iui->type14_fn++;
	hdr->ack_nack = IUUP_AN_PROCEDURE;
	hdr->pdu_type = IUUP_PDU_T_CONTROL;
	hdr->proc_ind = IUUP_PROC_INIT;
	hdr->mode_version = 0; /* Use here the minimum version required to negotiate */
	hdr->header_crc = osmo_iuup_compute_header_crc(msgb_l2(msg), msgb_l2len(msg));

	ihdr = (struct iuup_ctrl_init_hdr *)msgb_put(msg, sizeof(*ihdr));
	ihdr->chain_ind = 0; /* this frame is the last frame for the procedure. TODO: support several */
	ihdr->num_subflows_per_rfci = iui->config.num_subflows;
	ihdr->ti = iui->config.IPTIs_present ? 1 : 0;
	ihdr->spare = 0;

	/* RFCI + subflow size part: */
	rfci_cnt = 0;
	for (i = 0; i < ARRAY_SIZE(iui->config.rfci); i++) {
		bool last;
		uint8_t len_size;
		struct osmo_iuup_rfci *rfci = &iui->config.rfci[i];
		if (!rfci->used)
			continue;
		rfci_cnt++;
		last = (rfci_cnt == iui->config.num_rfci);

		len_size = 1;
		for (j = 0; j < iui->config.num_subflows; j++) {
			if (rfci->subflow_sizes[j] > UINT8_MAX)
				len_size = 2;
		}

		ihdr_rfci = (struct iuup_ctrl_init_rfci_hdr *)msgb_put(msg, sizeof(*ihdr_rfci) + len_size * iui->config.num_subflows);
		ihdr_rfci->rfci = rfci->id;
		ihdr_rfci->li = len_size - 1;
		ihdr_rfci->lri = last;
		if (len_size == 2) {
			uint16_t *buf = (uint16_t *)&ihdr_rfci->subflow_length[0];
			for (j = 0; j < iui->config.num_subflows; j++)
				osmo_store16be(rfci->subflow_sizes[j], buf++);
		} else {
			for (j = 0; j < iui->config.num_subflows; j++)
				ihdr_rfci->subflow_length[j] = rfci->subflow_sizes[j];
		}
		/* early loop termination: */
		if (last)
			break;
	}
	/* Sanity check: */
	if (rfci_cnt != iui->config.num_rfci) {
		LOGP(DLIUUP, LOGL_ERROR, "rfci_cnt %u != num_rfci %u\n",
			 rfci_cnt, iui->config.num_rfci);
		msgb_free(msg);
		return NULL;
	}

	if (iui->config.IPTIs_present) {
		uint8_t num_bytes = (iui->config.num_rfci + 1) / 2;
		uint8_t *buf = msgb_put(msg, num_bytes);
		rfci_cnt = 0;
		for (i = 0; i < ARRAY_SIZE(iui->config.rfci); i++) {
			struct osmo_iuup_rfci *rfci = &iui->config.rfci[i];
			if (!rfci->used)
				continue;
			if (!(rfci_cnt & 0x01)) /* is even: */
				buf[rfci_cnt / 2] = (((uint8_t)rfci->IPTI) << 4);
			else
				buf[rfci_cnt / 2] |= (rfci->IPTI & 0x0F);
			rfci_cnt++;
			/* early loop termination: */
			if (rfci_cnt == iui->config.num_rfci)
				break;
		}
	}

	itail = (struct iuup_ctrl_init_tail *)msgb_put(msg, sizeof(*itail));
	osmo_store16be(iui->config.supported_versions_mask, &itail->versions_supported);
	itail->spare = 0;
	itail->data_pdu_type = iui->config.data_pdu_type;

	payload_crc = osmo_iuup_compute_payload_crc(msgb_l2(msg), msgb_l2len(msg));
	hdr->payload_crc_hi = (payload_crc >> 8) & 0x03;
	hdr->payload_crc_lo = payload_crc & 0xff;


	return itp;
}

static struct osmo_iuup_rnl_prim *irp_init_ind_alloc(struct osmo_iuup_instance *iui)
{
	struct osmo_iuup_rnl_prim *irp;

	irp = osmo_iuup_rnl_prim_alloc(iui, OSMO_IUUP_RNL_STATUS, PRIM_OP_INDICATION, IUUP_MSGB_SIZE);
	irp->u.status.procedure = IUUP_PROC_INIT;
	irp->u.status.u.initialization.mode_version = iui->mode_version;
	irp->u.status.u.initialization.data_pdu_type = iui->config.data_pdu_type;
	irp->u.status.u.initialization.num_subflows = iui->config.num_subflows;
	irp->u.status.u.initialization.num_rfci = iui->config.num_rfci;
	irp->u.status.u.initialization.IPTIs_present = iui->config.IPTIs_present;
	memcpy(irp->u.status.u.initialization.rfci, iui->config.rfci, sizeof(iui->config.rfci));
	return irp;
}

/* transform a RNL data primitive into a TNL data primitive (down the stack) */
static struct osmo_iuup_tnl_prim *rnl_to_tnl_data(struct osmo_iuup_instance *iui,
						  struct osmo_iuup_rnl_prim *irp)
{
	struct osmo_iuup_tnl_prim *itp;
	struct osmo_iuup_rnl_data dt;
	struct msgb *msg;
	uint16_t payload_crc;
	struct iuup_pdutype0_hdr *h0;
	struct iuup_pdutype1_hdr *h1;

	OSMO_ASSERT(OSMO_PRIM_HDR(&irp->oph) == OSMO_PRIM(OSMO_IUUP_RNL_DATA, PRIM_OP_REQUEST));

	msg = irp->oph.msg;
	dt = irp->u.data;

	/* pull up to the IuUP payload and push a new primitive header in front */
	msgb_pull_to_l3(msg);

	/* push the PDU TYPE 0 / 1 header in front of the payload */
	switch (iui->config.data_pdu_type) {
	case 0:
		msg->l2h = msgb_push(msg, sizeof(*h0));
		h0 = (struct iuup_pdutype0_hdr *)msg->l2h;
		h0->frame_nr = dt.frame_nr;
		h0->pdu_type = IUUP_PDU_T_DATA_CRC;
		h0->rfci = dt.rfci;
		h0->fqc = dt.fqc;
		h0->header_crc = osmo_iuup_compute_header_crc(msgb_l2(msg), msgb_l2len(msg));
		payload_crc = osmo_iuup_compute_payload_crc(msgb_l2(msg), msgb_l2len(msg));
		h0->payload_crc_hi = (payload_crc >> 8) & 0x03;
		h0->payload_crc_lo = payload_crc & 0xff;
		break;
	case 1:
		msg->l2h = msgb_push(msg, sizeof(*h1));
		h1 = (struct iuup_pdutype1_hdr *)msg->l2h;
		h1->frame_nr = dt.frame_nr;
		h1->pdu_type = IUUP_PDU_T_DATA_NOCRC;
		h1->rfci = dt.rfci;
		h1->fqc = dt.fqc;
		h1->header_crc = osmo_iuup_compute_header_crc(msgb_l2(msg), msgb_l2len(msg));
		h1->spare = 0;
		break;
	default:
		OSMO_ASSERT(0);
	}

	/* Avoid allocating irp out of 8byte-aligned address, Asan is not happy with it */
	itp = (struct osmo_iuup_tnl_prim *) aligned_msgb_push(msg, sizeof(*itp));
	osmo_prim_init(&itp->oph, SAP_IUUP_TNL, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_REQUEST, msg);

	return itp;
}

/* transform a TNL primitive into a RNL primitive (up the stack) */
static struct osmo_iuup_rnl_prim *tnl_to_rnl_data(struct osmo_iuup_tnl_prim *itp)
{
	struct msgb *msg;
	struct iuup_pdutype0_hdr *h0;
	struct iuup_pdutype1_hdr *h1;
	struct osmo_iuup_rnl_data dt;
	struct osmo_iuup_rnl_prim *irp;

	msg = itp->oph.msg;

	OSMO_ASSERT(OSMO_PRIM_HDR(&itp->oph) == OSMO_PRIM(OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION));

	switch (iuup_get_pdu_type(msgb_l2(msg))) {
	case IUUP_PDU_T_DATA_CRC:
		h0 = (struct iuup_pdutype0_hdr *) msgb_l2(msg);
		dt.rfci = h0->rfci;
		dt.frame_nr = h0->frame_nr;
		dt.fqc = h0->fqc;
		break;
	case IUUP_PDU_T_DATA_NOCRC:
		h1 = (struct iuup_pdutype1_hdr *) msgb_l2(msg);
		dt.rfci = h1->rfci;
		dt.frame_nr = h1->frame_nr;
		dt.fqc = h1->fqc;
		break;
	default:
		OSMO_ASSERT(0);
	}

	/* pull up to the IuUP payload and push a new primitive header in front */
	msgb_pull_to_l3(msg);

	/* Avoid allocating irp out of 8byte-aligned address, Asan is not happy with it */
	irp = (struct osmo_iuup_rnl_prim *) aligned_msgb_push(msg, sizeof(*irp));
	osmo_prim_init(&irp->oph, SAP_IUUP_RNL, OSMO_IUUP_RNL_DATA, PRIM_OP_INDICATION, msg);
	irp->u.data = dt;

	return irp;
}

static struct osmo_iuup_rnl_prim *irp_error_event_alloc_c(void *ctx, enum iuup_error_cause cause, enum iuup_error_distance distance)
{
	struct osmo_iuup_rnl_prim *irp;
	struct msgb *msg;
	msg = msgb_alloc_c(ctx, sizeof(*irp), "iuup-tx");
	irp = (struct osmo_iuup_rnl_prim *) msgb_put(msg, sizeof(*irp));
	osmo_prim_init(&irp->oph, SAP_IUUP_RNL, OSMO_IUUP_RNL_STATUS, PRIM_OP_INDICATION, msg);
	irp->u.status.procedure = IUUP_PROC_ERR_EVENT;
	irp->u.status.u.error_event.cause = cause;
	irp->u.status.u.error_event.distance = distance;
	return irp;
}

static struct osmo_iuup_tnl_prim *itp_copy_c(void *ctx, const struct osmo_iuup_tnl_prim *src_itp)
{
	struct msgb *msg;
	struct osmo_iuup_tnl_prim *dst_itp;

	msg = msgb_copy_c(ctx, src_itp->oph.msg, "iuup-tx-retrans");
	dst_itp = (struct osmo_iuup_tnl_prim *)msgb_data(msg);
	dst_itp->oph.msg = msg;
	return dst_itp;
}

static void retransmit_initialization(struct osmo_iuup_instance *iui)
{
	struct osmo_iuup_tnl_prim *itp;
	iui->fi->T = IUUP_TIMER_INIT;
	osmo_timer_schedule(&iui->fi->timer, iui->config.t_init.t_ms / 1000, (iui->config.t_init.t_ms % 1000) * 1000);
	itp = itp_copy_c(iui, iui->timer.init.retrans_itp);
	iui->transport_prim_cb(&itp->oph, iui->transport_prim_priv);
}

/* return: whether the last Init was Acked correctly and hence can transition to next state */
static bool iuup_rx_initialization(struct osmo_iuup_instance *iui, struct osmo_iuup_tnl_prim *itp)
{
	struct iuup_pdutype14_hdr *hdr;
	struct iuup_ctrl_init_hdr *ihdr;
	struct iuup_ctrl_init_rfci_hdr *ihdr_rfci;
	struct iuup_ctrl_init_tail *itail;
	enum iuup_error_cause err_cause;
	uint8_t num_rfci = 0;
	int i;
	bool is_last;
	uint16_t remote_mask, match_mask;
	struct osmo_iuup_rnl_prim *irp;
	struct osmo_iuup_tnl_prim *resp;

	/* TODO: whenever we check message boundaries, length, etc. and we fail, send NACK */

	hdr = (struct iuup_pdutype14_hdr *)msgb_l2(itp->oph.msg);
	ihdr = (struct iuup_ctrl_init_hdr *)hdr->payload;
	if (ihdr->num_subflows_per_rfci == 0) {
		LOGPFSML(iui->fi, LOGL_NOTICE, "Initialization: Unexpected num_subflows=0 received\n");
		err_cause = IUUP_ERR_CAUSE_UNEXPECTED_VALUE;
		goto send_nack;
	}
	ihdr_rfci = (struct iuup_ctrl_init_rfci_hdr *)ihdr->rfci_data;

	do {
		struct osmo_iuup_rfci *rfci = &iui->config.rfci[num_rfci];
		uint8_t l_size_bytes = ihdr_rfci->li + 1;
		is_last = ihdr_rfci->lri;
		if (num_rfci >= IUUP_MAX_RFCIS) {
			LOGPFSML(iui->fi, LOGL_NOTICE, "Initialization: Too many RFCIs received (%u)\n",
					 num_rfci);
			err_cause = IUUP_ERR_CAUSE_UNEXPECTED_RFCI;
			goto send_nack;
		}
		rfci->used = 1;
		rfci->id = ihdr_rfci->rfci;
		if (l_size_bytes == 2) {
			uint16_t *subflow_size = (uint16_t *)ihdr_rfci->subflow_length;
			for (i = 0; i < ihdr->num_subflows_per_rfci; i++) {
				rfci->subflow_sizes[i] = osmo_load16be(subflow_size);
				subflow_size++;
			}
		} else {
			uint8_t *subflow_size = ihdr_rfci->subflow_length;
			for (i = 0; i < ihdr->num_subflows_per_rfci; i++) {
				rfci->subflow_sizes[i] = *subflow_size;
				subflow_size++;
			}
		}
		num_rfci++;
		ihdr_rfci++;
		ihdr_rfci = (struct iuup_ctrl_init_rfci_hdr *)(((uint8_t *)ihdr_rfci) + ihdr->num_subflows_per_rfci * l_size_bytes);
	} while (!is_last);

	if (ihdr->ti) { /* Timing information present */
		uint8_t *buf = (uint8_t *)ihdr_rfci;
		uint8_t num_bytes = (num_rfci + 1) / 2;
		iui->config.IPTIs_present = true;
		for (i = 0; i < num_bytes - 1; i++) {
			iui->config.rfci[i*2].IPTI = *buf >> 4;
			iui->config.rfci[i*2 + 1].IPTI = *buf & 0x0f;
			buf++;
		}
		iui->config.rfci[i*2].IPTI = *buf >> 4;
		if (!(num_rfci & 0x01)) /* is even: */
			iui->config.rfci[i*2 + 1].IPTI = *buf & 0x0f;
		buf++;
		itail = (struct iuup_ctrl_init_tail *)buf;
	} else {
		iui->config.IPTIs_present = false;
		itail = (struct iuup_ctrl_init_tail *)ihdr_rfci;
	}
	if (itail->data_pdu_type > 1) {
		LOGPFSML(iui->fi, LOGL_NOTICE, "Initialization: Unexpected Data PDU Type %u received\n", itail->data_pdu_type);
		err_cause = IUUP_ERR_CAUSE_UNEXPECTED_VALUE;
		goto send_nack;
	}

	remote_mask = osmo_load16be(&itail->versions_supported);
	match_mask = (remote_mask & iui->config.supported_versions_mask);
	if (match_mask == 0x0000) {
		LOGPFSML(iui->fi, LOGL_NOTICE,
			 "Initialization: No match in supported versions local=0x%04x vs remote=0x%04x\n",
			 iui->config.supported_versions_mask, remote_mask);
		err_cause = IUUP_ERR_CAUSE_UNEXPECTED_VALUE;
		goto send_nack;
	}
	for (i = 15; i >= 0; i--) {
		if (match_mask & (1<<i)) {
			iui->mode_version = i;
			break;
		}
	}

	iui->config.num_rfci = num_rfci;
	iui->config.num_subflows = ihdr->num_subflows_per_rfci;
	iui->config.data_pdu_type = itail->data_pdu_type;

	irp = irp_init_ind_alloc(iui);
	iui->user_prim_cb(&irp->oph, iui->user_prim_priv);

	LOGPFSML(iui->fi, LOGL_DEBUG, "Tx Initialization ACK\n");
	resp = itp_ctrl_ack_alloc(iui, IUUP_PROC_INIT, hdr->frame_nr);
	iui->transport_prim_cb(&resp->oph, iui->transport_prim_priv);
	return ihdr->chain_ind == 0;
send_nack:
	LOGPFSML(iui->fi, LOGL_NOTICE, "Tx Initialization NACK cause=%u orig_message=%s\n",
		 err_cause, osmo_hexdump((const unsigned char *) msgb_l2(itp->oph.msg), msgb_l2len(itp->oph.msg)));
	resp = tnp_ctrl_nack_alloc(iui, IUUP_PROC_INIT, err_cause, hdr->frame_nr);
	iui->transport_prim_cb(&resp->oph, iui->transport_prim_priv);
	return false;
}

/**********************
 * FSM STATE FUNCTIONS
 **********************/
static void iuup_fsm_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_iuup_instance *iui = fi->priv;
	struct osmo_iuup_rnl_prim *user_prim = NULL;

	switch (event) {
	case IUUP_FSM_EVT_IUUP_CONFIG_REQ:
		user_prim = data;
		iui->config = user_prim->u.config;
		iui->config.supported_versions_mask &= 0x0003; /* We only support versions 1 and 2 ourselves */
		//TODO: if supported_versions_mask == 0x0000,no supported versions, send error to upper layers

		if (iui->config.transparent)
			osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_TrM_DATA_XFER_READY, 0, 0);
		else {
			osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_INIT, 0, 0);
		}
		break;
	}
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

static void iuup_fsm_init_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct osmo_iuup_instance *iui = fi->priv;

	iui->type14_fn = 0;
	if (iui->config.active) {
		iui->timer.init.n = 0;
		iui->timer.init.retrans_itp = tnp_ctrl_init_alloc(iui);
		retransmit_initialization(iui);
	}
}

static void iuup_fsm_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_iuup_instance *iui = fi->priv;
	struct osmo_iuup_rnl_prim *irp;
	struct osmo_iuup_tnl_prim *itp;

	switch (event) {
	case IUUP_FSM_EVT_IUUP_CONFIG_REQ:
		/* the only permitted 'config req' type is the request to release the instance */
		osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_NULL, 0, 0);
		break;
	case IUUP_FSM_EVT_INIT:
		itp = data;
		if (iuup_rx_initialization(iui, itp))
			osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_SMpSDU_DATA_XFER_READY, 0, 0);
		break;
	case IUUP_FSM_EVT_LAST_INIT_ACK:
		/* last INIT ACK was received, transition to DATA_XFER_READY state */
		osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_SMpSDU_DATA_XFER_READY, 0, 0);
		break;
	case IUUP_FSM_EVT_INIT_NACK:
		LOGPFSML(fi, LOGL_NOTICE, "Rx Initialization NACK N=%" PRIu32 "/%" PRIu32 "\n",
			 iui->timer.init.n, iui->config.t_init.n_max);
		osmo_timer_del(&fi->timer);
		if (iui->timer.init.n == iui->config.t_init.n_max) {
			irp = irp_error_event_alloc_c(iui, IUUP_ERR_CAUSE_INIT_FAILURE_REP_NACK, IUUP_ERR_DIST_SECOND_FWD);
			iui->user_prim_cb(&irp->oph, iui->user_prim_priv);
			return;
		}
		iui->timer.init.n++;
		retransmit_initialization(iui);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

/* 3GPP TS 25.415 B.2.3 "Support Mode Data Transfer Ready State" */
static void iuup_fsm_smpsdu_data(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_iuup_instance *iui = fi->priv;
	struct osmo_iuup_rnl_prim *irp = NULL;
	struct osmo_iuup_tnl_prim *itp = NULL;

	switch (event) {
	case IUUP_FSM_EVT_IUUP_CONFIG_REQ:
		irp = data;
		osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_NULL, 0, 0);
		break;
	case IUUP_FSM_EVT_INIT:
		/* "In case of handover or relocation, Initialisation procedures
		 * may have to be performed and Iu UP instance may have to enter
		 * the initialisation state." */
		itp = data;
		if (!iuup_rx_initialization(iui, itp))
			osmo_fsm_inst_state_chg(fi, IUUP_FSM_ST_INIT, 0, 0);
		break;
	case IUUP_FSM_EVT_IUUP_DATA_REQ:
		/* Data coming down from RNL (user) towards TNL (transport) */
		irp = data;
		itp = rnl_to_tnl_data(iui, irp);
		iui->transport_prim_cb(&itp->oph, iui->transport_prim_priv);
		break;
	case IUUP_FSM_EVT_IUUP_DATA_IND:
		/* Data coming up from TNL (transport) towards RNL (user) */
		itp = data;
		irp = tnl_to_rnl_data(itp);
		iui->user_prim_cb(&irp->oph, iui->user_prim_priv);
		break;
	}
}

static int iuup_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct osmo_iuup_instance *iui = fi->priv;
	struct osmo_iuup_rnl_prim *irp;

	switch (fi->T) {
	case IUUP_TIMER_INIT:
		OSMO_ASSERT(fi->state == IUUP_FSM_ST_INIT);
		if (iui->timer.init.n == iui->config.t_init.n_max) {
			irp = irp_error_event_alloc_c(iui, IUUP_ERR_CAUSE_INIT_FAILURE_NET_TMR, IUUP_ERR_DIST_LOCAL);
			iui->user_prim_cb(&irp->oph, iui->user_prim_priv);
			return 0;
		}
		iui->timer.init.n++;
		retransmit_initialization(iui);
		break;
	case IUUP_TIMER_TA:
		break;
	case IUUP_TIMER_RC:
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
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
				 S(IUUP_FSM_EVT_IUUP_STATUS_REQ) |
				 S(IUUP_FSM_EVT_IUUP_DATA_REQ) |
				 S(IUUP_FSM_EVT_IUUP_DATA_IND) |
				 S(IUUP_FSM_EVT_IUUP_UNITDATA_REQ) |
				 S(IUUP_FSM_EVT_IUUP_UNITDATA_IND) |
				 S(IUUP_FSM_EVT_SSASAR_UNITDATA_REQ) |
				 S(IUUP_FSM_EVT_SSASAR_UNITDATA_IND),
		.out_state_mask = S(IUUP_FSM_ST_NULL),
		.name = "TrM_Data_Transfer_Ready",
		.action = iuup_fsm_trm_data,
	},
	[IUUP_FSM_ST_INIT] = {
		.in_event_mask =  S(IUUP_FSM_EVT_IUUP_CONFIG_REQ) |
				  S(IUUP_FSM_EVT_INIT) |
				  S(IUUP_FSM_EVT_LAST_INIT_ACK) |
				  S(IUUP_FSM_EVT_INIT_NACK),
		.out_state_mask = S(IUUP_FSM_ST_NULL) |
				  S(IUUP_FSM_ST_SMpSDU_DATA_XFER_READY),
		.name = "Initialisation",
		.onenter = iuup_fsm_init_on_enter,
		.action = iuup_fsm_init,
	},
	[IUUP_FSM_ST_SMpSDU_DATA_XFER_READY] = {
		.in_event_mask = S(IUUP_FSM_EVT_IUUP_CONFIG_REQ) |
				 S(IUUP_FSM_EVT_INIT) |
				 S(IUUP_FSM_EVT_IUUP_DATA_REQ) |
				 S(IUUP_FSM_EVT_IUUP_DATA_IND),
		.out_state_mask = S(IUUP_FSM_ST_NULL) |
				  S(IUUP_FSM_ST_INIT),
		.name = "SMpSDU_Data_Transfer_Ready",
		.action = iuup_fsm_smpsdu_data,
	},
};

static struct osmo_fsm iuup_fsm = {
	.name = "IuUP",
	.states = iuup_fsm_states,
	.num_states = ARRAY_SIZE(iuup_fsm_states),
	.timer_cb = iuup_fsm_timer_cb,
	.log_subsys = DLIUUP,
	.event_names = iuup_fsm_event_names,
};

static int iuup_verify_pdu(const uint8_t *data, unsigned int len)
{
	int header_crc_computed, payload_crc_computed;
	uint16_t payload_crc;
	uint8_t pdu_type = iuup_get_pdu_type(data);
	struct iuup_pdutype0_hdr *t0h;
	struct iuup_pdutype14_hdr *t14h;

	if (len < 3)
		return -EINVAL;

	header_crc_computed = osmo_iuup_compute_header_crc(data, len);
	if (iuup_get_hdr_crc(data) != header_crc_computed) {
		LOGP(DLIUUP, LOGL_NOTICE, "Header Checksum error: rx 0x%02x vs exp 0x%02x\n",
		     iuup_get_hdr_crc(data), header_crc_computed);
		return -EIO;
	}
	switch (pdu_type) {
	case IUUP_PDU_T_DATA_NOCRC:
		if (len < 4)
			return -EINVAL;
		break;
	case IUUP_PDU_T_DATA_CRC:
		t0h = (struct iuup_pdutype0_hdr *) data;
		payload_crc = ((uint16_t)t0h->payload_crc_hi << 8) | t0h->payload_crc_lo;
		payload_crc_computed = osmo_iuup_compute_payload_crc(data, len);
		if (payload_crc != payload_crc_computed)
			goto payload_crc_err;
		break;
	case IUUP_PDU_T_CONTROL:
		t14h = (struct iuup_pdutype14_hdr *) data;
		if (t14h->ack_nack == IUUP_AN_PROCEDURE) {
			payload_crc = ((uint16_t)t14h->payload_crc_hi << 8) | t14h->payload_crc_lo;
			payload_crc_computed = osmo_iuup_compute_payload_crc(data, len);
			if (payload_crc != payload_crc_computed)
				goto payload_crc_err;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;

payload_crc_err:
	LOGP(DLIUUP, LOGL_NOTICE, "Payload Checksum error (pdu type %u): rx 0x%02x vs exp 0x%02x\n",
	     pdu_type, payload_crc, payload_crc_computed);
	return -EIO;
}

/* A IuUP TNL SAP primitive from transport (lower layer) */
int osmo_iuup_tnl_prim_up(struct osmo_iuup_instance *inst, struct osmo_iuup_tnl_prim *itp)
{
	struct osmo_prim_hdr *oph = &itp->oph;
	struct iuup_pdutype14_hdr *t14h;
	int rc = 0;

	OSMO_ASSERT(oph->sap == SAP_IUUP_TNL);

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION):
		if (iuup_verify_pdu(msgb_l2(oph->msg), msgb_l2len(oph->msg)) < 0) {
			LOGPFSML(inst->fi, LOGL_NOTICE, "Discarding invalid IuUP PDU: %s\n",
				 osmo_hexdump((const unsigned char *) msgb_l2(oph->msg), msgb_l2len(oph->msg)));
			/* don't return error as the caller is not responsible for the PDU which
			 * was transmitted from some remote peer */
			return 0;
		}
		switch (iuup_get_pdu_type(msgb_l2(oph->msg))) {
		case IUUP_PDU_T_DATA_CRC:
			oph->msg->l3h = msgb_l2(oph->msg) + sizeof(struct iuup_pdutype0_hdr);
			rc = osmo_fsm_inst_dispatch(inst->fi, IUUP_FSM_EVT_IUUP_DATA_IND, itp);
			break;
		case IUUP_PDU_T_DATA_NOCRC:
			oph->msg->l3h = msgb_l2(oph->msg) + sizeof(struct iuup_pdutype1_hdr);
			rc = osmo_fsm_inst_dispatch(inst->fi, IUUP_FSM_EVT_IUUP_DATA_IND, itp);
			break;
		case IUUP_PDU_T_CONTROL:
			t14h = (struct iuup_pdutype14_hdr *) msgb_l2(oph->msg);
			switch (t14h->ack_nack) {
			case IUUP_AN_PROCEDURE:
				switch (t14h->proc_ind) {
				case IUUP_PROC_INIT:
					rc = osmo_fsm_inst_dispatch(inst->fi, IUUP_FSM_EVT_INIT, itp);
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
								    IUUP_FSM_EVT_LAST_INIT_ACK, itp);
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
								    IUUP_FSM_EVT_INIT_NACK, itp);
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
int osmo_iuup_rnl_prim_down(struct osmo_iuup_instance *inst, struct osmo_iuup_rnl_prim *irp)
{
	struct osmo_prim_hdr *oph = &irp->oph;
	int rc;

	OSMO_ASSERT(oph->sap == SAP_IUUP_RNL);

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_IUUP_RNL_CONFIG, PRIM_OP_REQUEST):
		rc = osmo_fsm_inst_dispatch(inst->fi, IUUP_FSM_EVT_IUUP_CONFIG_REQ, irp);
		msgb_free(irp->oph.msg);
		break;
	case OSMO_PRIM(OSMO_IUUP_RNL_DATA, PRIM_OP_REQUEST):
		rc = osmo_fsm_inst_dispatch(inst->fi, IUUP_FSM_EVT_IUUP_DATA_REQ, irp);
		if (rc != 0)
			msgb_free(irp->oph.msg);
		break;
	case OSMO_PRIM(OSMO_IUUP_RNL_STATUS, PRIM_OP_REQUEST):
		rc = osmo_fsm_inst_dispatch(inst->fi, IUUP_FSM_EVT_IUUP_STATUS_REQ, irp);
		msgb_free(irp->oph.msg);
		break;
	default:
		rc = -EINVAL;
		msgb_free(irp->oph.msg);
	}
	return rc;
}

struct osmo_iuup_instance *osmo_iuup_instance_alloc(void *ctx, const char *id)
{
	struct osmo_iuup_instance *iui;
	iui = talloc_zero(ctx, struct osmo_iuup_instance);
	if (!iui)
		return NULL;

	iui->fi = osmo_fsm_inst_alloc(&iuup_fsm, NULL, iui, LOGL_DEBUG, id);
	if (!iui->fi)
		goto free_ret;

	return iui;
free_ret:
	talloc_free(iui);
	return NULL;
}

void osmo_iuup_instance_free(struct osmo_iuup_instance *iui)
{
	if (!iui)
		return;

	if (iui->fi)
		osmo_fsm_inst_free(iui->fi);
	iui->fi = NULL;
	talloc_free(iui);
}

void osmo_iuup_instance_set_user_prim_cb(struct osmo_iuup_instance *iui, osmo_prim_cb func, void *priv)
{
	iui->user_prim_cb = func;
	iui->user_prim_priv = priv;
}
void osmo_iuup_instance_set_transport_prim_cb(struct osmo_iuup_instance *iui, osmo_prim_cb func, void *priv)
{
	iui->transport_prim_cb = func;
	iui->transport_prim_priv = priv;
}

static __attribute__((constructor)) void on_dso_load_iuup_fsm(void)
{
	OSMO_ASSERT(osmo_fsm_register(&iuup_fsm) == 0);
}
