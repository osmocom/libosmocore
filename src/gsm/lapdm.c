/*! \file lapdm.c
 * GSM LAPDm (TS 04.06) implementation. */
/*
 * (C) 2010-2019 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010-2011 by Andreas Eversberg <jolly@eversberg.eu>
 * (C) 2014-2016 by sysmocom - s.f.m.c GmbH
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
 */

/*! \addtogroup lapdm
 *  @{
 * \file lapdm.c */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>

#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/gsm/prim.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/lapdm.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>

#define LAPD_U_SABM 0x7

/* TS 04.06 Figure 4 / Section 3.2 */
#define LAPDm_LPD_NORMAL  0
#define LAPDm_LPD_SMSCB	  1
#define LAPDm_SAPI_NORMAL 0
#define LAPDm_SAPI_SMS	  3
#define LAPDm_ADDR(lpd, sapi, cr) ((((lpd) & 0x3) << 5) | (((sapi) & 0x7) << 2) | (((cr) & 0x1) << 1) | 0x1)

#define LAPDm_ADDR_LPD(addr) (((addr) >> 5) & 0x3)
#define LAPDm_ADDR_SAPI(addr) (((addr) >> 2) & 0x7)
#define LAPDm_ADDR_CR(addr) (((addr) >> 1) & 0x1)
#define LAPDm_ADDR_EA(addr) ((addr) & 0x1)
#define LAPDm_ADDR_SHORT_L2(addr) ((addr) & 0x3)

/* TS 04.06 Table 3 / Section 3.4.3 */
#define LAPDm_CTRL_I(nr, ns, p)	((((nr) & 0x7) << 5) | (((p) & 0x1) << 4) | (((ns) & 0x7) << 1))
#define LAPDm_CTRL_S(nr, s, p)	((((nr) & 0x7) << 5) | (((p) & 0x1) << 4) | (((s) & 0x3) << 2) | 0x1)
#define LAPDm_CTRL_U(u, p)	((((u) & 0x1c) << (5-2)) | (((p) & 0x1) << 4) | (((u) & 0x3) << 2) | 0x3)

#define LAPDm_CTRL_is_I(ctrl)	(((ctrl) & 0x1) == 0)
#define LAPDm_CTRL_is_S(ctrl)	(((ctrl) & 0x3) == 1)
#define LAPDm_CTRL_is_U(ctrl)	(((ctrl) & 0x3) == 3)

#define LAPDm_CTRL_U_BITS(ctrl)	((((ctrl) & 0xC) >> 2) | ((ctrl) & 0xE0) >> 3)
#define LAPDm_CTRL_PF_BIT(ctrl)	(((ctrl) >> 4) & 0x1)

#define LAPDm_CTRL_S_BITS(ctrl)	(((ctrl) & 0xC) >> 2)

#define LAPDm_CTRL_I_Ns(ctrl)	(((ctrl) & 0xE) >> 1)
#define LAPDm_CTRL_Nr(ctrl)	(((ctrl) & 0xE0) >> 5)

#define LAPDm_LEN(len)	((len << 2) | 0x1)
#define LAPDm_MORE	0x2
#define LAPDm_EL	0x1

#define LAPDm_U_UI	0x0

/* TS 04.06 Section 5.8.3 */
#define N201_AB_SACCH		18
#define N201_AB_SDCCH		20
#define N201_AB_FACCH		20
#define N201_Bbis		23
#define N201_Bter_SACCH		21
#define N201_Bter_SDCCH		23
#define N201_Bter_FACCH		23
#define N201_B4			19

/* 5.8.2.1 N200 during establish and release */
#define N200_EST_REL		5
/* 5.8.2.1 N200 during timer recovery state */
#define N200_TR_SACCH		5
#define N200_TR_SDCCH		23
#define N200_TR_FACCH_FR	34
#define N200_TR_EFACCH_FR	48
#define N200_TR_FACCH_HR	29
/* FIXME: set N200 depending on chan_nr */
#define N200 N200_TR_SDCCH

enum lapdm_format {
	LAPDm_FMT_A,
	LAPDm_FMT_B,
	LAPDm_FMT_Bbis,
	LAPDm_FMT_Bter,
	LAPDm_FMT_B4,
};

const struct value_string osmo_ph_prim_names[] = {
	{ PRIM_PH_DATA,		"PH-DATA" },
	{ PRIM_PH_RACH,		"PH-RANDOM_ACCESS" },
	{ PRIM_PH_CONN,		"PH-CONNECT" },
	{ PRIM_PH_EMPTY_FRAME,	"PH-EMPTY_FRAME" },
	{ PRIM_PH_RTS,		"PH-RTS" },
	{ PRIM_MPH_INFO,	"MPH-INFO" },
	{ PRIM_TCH,		"TCH" },
	{ PRIM_TCH_RTS,		"TCH-RTS" },
	{ 0,			NULL }
};

extern void *tall_lapd_ctx;

static int lapdm_send_ph_data_req(struct lapd_msg_ctx *lctx, struct msgb *msg);
static int send_rslms_dlsap(struct osmo_dlsap_prim *dp,
	struct lapd_msg_ctx *lctx);
static int update_pending_frames(struct lapd_msg_ctx *lctx);

static void lapdm_dl_init(struct lapdm_datalink *dl,
			  struct lapdm_entity *entity, int t200_ms, uint32_t n200,
			  const char *name)
{
	memset(dl, 0, sizeof(*dl));
	dl->entity = entity;
	lapd_dl_init2(&dl->dl, 1, 8, 251, name); /* Section 5.8.5 of TS 04.06 */
	dl->dl.reestablish = 0; /* GSM uses no reestablish */
	dl->dl.send_ph_data_req = lapdm_send_ph_data_req;
	dl->dl.send_dlsap = send_rslms_dlsap;
	dl->dl.update_pending_frames = update_pending_frames;
	dl->dl.n200_est_rel = N200_EST_REL;
	dl->dl.n200 = n200;
	dl->dl.t203_sec = 0; dl->dl.t203_usec = 0;
	dl->dl.t200_sec = t200_ms / 1000; dl->dl.t200_usec = (t200_ms % 1000) * 1000;
}

/*! initialize a LAPDm entity and all datalinks inside
 *  \param[in] le LAPDm entity
 *  \param[in] mode \ref lapdm_mode (BTS/MS)
 *  \param[in] t200 T200 re-transmission timer for all SAPIs in seconds
 *
 *  Don't use this function; It doesn't support different T200 values per API
 *  and doesn't permit the caller to specify the N200 counter, both of which
 *  are required by GSM specs and supported by lapdm_entity_init2().
 */
void lapdm_entity_init(struct lapdm_entity *le, enum lapdm_mode mode, int t200)
{
	/* convert from single full-second value to per-SAPI milli-second value */
	int t200_ms_sapi_arr[_NR_DL_SAPI];
	int i;

	for (i = 0; i < ARRAY_SIZE(t200_ms_sapi_arr); i++)
		t200_ms_sapi_arr[i] = t200 * 1000;

	return lapdm_entity_init3(le, mode, t200_ms_sapi_arr, N200, NULL);
}

/*! initialize a LAPDm entity and all datalinks inside
 *  \param[in] le LAPDm entity
 *  \param[in] mode lapdm_mode (BTS/MS)
 *  \param[in] t200_ms per-SAPI array of T200 re-transmission timer in milli-seconds
 *  \param[in] n200 N200 re-transmisison count
 */
void lapdm_entity_init2(struct lapdm_entity *le, enum lapdm_mode mode,
			const int *t200_ms, int n200)
{
	lapdm_entity_init3(le, mode, t200_ms, n200, NULL);
}

/*! initialize a LAPDm entity and all datalinks inside
 *  \param[in] le LAPDm entity
 *  \param[in] mode lapdm_mode (BTS/MS)
 *  \param[in] t200_ms per-SAPI array of T200 re-transmission timer in milli-seconds
 *  \param[in] n200 N200 re-transmisison count
 *  \param[in] name human-readable name (will be copied internally + extended with SAPI)
 */
void lapdm_entity_init3(struct lapdm_entity *le, enum lapdm_mode mode,
			const int *t200_ms, int n200, const char *name_pfx)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(le->datalink); i++) {
		char name[256];
		if (name_pfx) {
			snprintf(name, sizeof(name), "%s[%s]", name_pfx, i == 0 ? "0" : "3");
			lapdm_dl_init(&le->datalink[i], le, (t200_ms) ? t200_ms[i] : 0, n200, name);
		} else
			lapdm_dl_init(&le->datalink[i], le, (t200_ms) ? t200_ms[i] : 0, n200, NULL);
		INIT_LLIST_HEAD(&le->datalink[i].tx_ui_queue);
	}

	lapdm_entity_set_mode(le, mode);
}

static int get_n200_dcch(enum gsm_chan_t chan_t)
{
	switch (chan_t) {
	case GSM_LCHAN_SDCCH:
		return N200_TR_SDCCH;
	case GSM_LCHAN_TCH_F:
		return N200_TR_FACCH_FR;
	case GSM_LCHAN_TCH_H:
		return N200_TR_FACCH_HR;
	default:
		return -1;
	}
}

/*! initialize a LAPDm channel and all its channels
 *  \param[in] lc lapdm_channel to be initialized
 *  \param[in] mode lapdm_mode (BTS/MS)
 *
 *  Don't use this function; It doesn't support different T200 values per API
 *  and doesn't set the correct N200 counter, both of which
 *  are required by GSM specs and supported by lapdm_channel_init2().
 */
void lapdm_channel_init(struct lapdm_channel *lc, enum lapdm_mode mode)
{
	/* emulate old backwards-compatible behavior with 1s/2s */
	const int t200_ms_dcch[_NR_DL_SAPI] = { 1000, 1000 };
	const int t200_ms_acch[_NR_DL_SAPI] = { 2000, 2000 };

	lapdm_channel_init3(lc, mode, t200_ms_dcch, t200_ms_acch, GSM_LCHAN_SDCCH, NULL);
}

/*! initialize a LAPDm channel and all its channels
 *  \param[in] lc \ref lapdm_channel to be initialized
 *  \param[in] mode \ref lapdm_mode (BTS/MS)
 *  \param[in] t200_ms_dcch per-SAPI array of T200 in milli-seconds for DCCH
 *  \param[in] t200_ms_acch per-SAPI array of T200 in milli-seconds for SACCH
 *  \param[in] chan_t GSM channel type (to correctly set N200)
 */
int lapdm_channel_init2(struct lapdm_channel *lc, enum lapdm_mode mode,
			const int *t200_ms_dcch, const int *t200_ms_acch, enum gsm_chan_t chan_t)
{
	return lapdm_channel_init3(lc, mode, t200_ms_dcch, t200_ms_acch, chan_t, NULL);
}

/*! initialize a LAPDm channel and all its channels
 *  \param[in] lc \ref lapdm_channel to be initialized
 *  \param[in] mode \ref lapdm_mode (BTS/MS)
 *  \param[in] t200_ms_dcch per-SAPI array of T200 in milli-seconds for DCCH
 *  \param[in] t200_ms_acch per-SAPI array of T200 in milli-seconds for SACCH
 *  \param[in] chan_t GSM channel type (to correctly set N200)
 *  \param[in] name_pfx human-readable name (copied by function + extended with ACCH/DCCH)
 */
int lapdm_channel_init3(struct lapdm_channel *lc, enum lapdm_mode mode,
			const int *t200_ms_dcch, const int *t200_ms_acch, enum gsm_chan_t chan_t,
			const char *name_pfx)
{
	int n200_dcch = get_n200_dcch(chan_t);
	char namebuf[256];
	char *name = NULL;

	if (n200_dcch < 0)
		return -EINVAL;

	osmo_talloc_replace_string(tall_lapd_ctx, &lc->name, name_pfx);

	if (name_pfx) {
		snprintf(namebuf, sizeof(namebuf), "%s[ACCH]", name_pfx);
		name = namebuf;
	}
	lapdm_entity_init3(&lc->lapdm_acch, mode, t200_ms_acch, N200_TR_SACCH, name);
	lc->lapdm_acch.lapdm_ch = lc;

	if (name_pfx) {
		snprintf(namebuf, sizeof(namebuf), "%s[DCCH]", name_pfx);
		name = namebuf;
	}
	lapdm_entity_init3(&lc->lapdm_dcch, mode, t200_ms_dcch, n200_dcch, name);
	lc->lapdm_dcch.lapdm_ch = lc;

	return 0;
}

/*! flush and release all resoures in LAPDm entity */
void lapdm_entity_exit(struct lapdm_entity *le)
{
	unsigned int i;
	struct lapdm_datalink *dl;

	for (i = 0; i < ARRAY_SIZE(le->datalink); i++) {
		dl = &le->datalink[i];
		lapd_dl_exit(&dl->dl);
		msgb_queue_free(&dl->tx_ui_queue);
	}
}

/* lfush and release all resources in LAPDm channel
 *
 * A convenience wrapper calling \ref lapdm_entity_exit on both
 * entities inside the \ref lapdm_channel
 */
void lapdm_channel_exit(struct lapdm_channel *lc)
{
	lapdm_entity_exit(&lc->lapdm_acch);
	lapdm_entity_exit(&lc->lapdm_dcch);
}

struct lapdm_datalink *lapdm_datalink_for_sapi(struct lapdm_entity *le, uint8_t sapi)
{
	switch (sapi) {
	case LAPDm_SAPI_NORMAL:
		return &le->datalink[0];
	case LAPDm_SAPI_SMS:
		return &le->datalink[1];
	default:
		return NULL;
	}
}

/* Append padding (if required) */
static void lapdm_pad_msgb(struct msgb *msg, uint8_t n201)
{
	int pad_len = n201 - msgb_l2len(msg);
	uint8_t *data;

	if (pad_len < 0) {
		LOGP(DLLAPD, LOGL_ERROR,
		     "cannot pad message that is already too big!\n");
		return;
	}

	data = msgb_put(msg, pad_len); /* TODO: random padding */
	memset(data, GSM_MACBLOCK_PADDING, pad_len);
}

/* input function that L2 calls when sending messages up to L3 */
static int rslms_sendmsg(struct msgb *msg, struct lapdm_entity *le)
{
	if (!le->l3_cb) {
		msgb_free(msg);
		return -EIO;
	}

	/* call the layer2 message handler that is registered */
	return le->l3_cb(msg, le, le->l3_ctx);
}

/* write a frame into the tx queue */
static int tx_ph_data_enqueue(struct lapdm_datalink *dl, struct msgb *msg,
				uint8_t chan_nr, uint8_t link_id, uint8_t pad)
{
	struct lapdm_entity *le = dl->entity;
	struct osmo_phsap_prim pp;

	/* if there is a pending message, queue it */
	if (le->tx_pending || le->flags & LAPDM_ENT_F_POLLING_ONLY) {
		struct msgb *old_msg;

		/* In 'RTS' mode there can be only one message. */
		if (le->flags & LAPDM_ENT_F_RTS) {
			/* Overwrite existing message by removing it first. */
			if ((old_msg = msgb_dequeue(&dl->dl.tx_queue))) {
				msgb_free(old_msg);
				/* Reset V(S) to V(A), because there is no outstanding message now. */
				dl->dl.v_send = dl->dl.v_ack;
			}
		}

		*msgb_push(msg, 1) = pad;
		*msgb_push(msg, 1) = link_id;
		*msgb_push(msg, 1) = chan_nr;
		msgb_enqueue(&dl->dl.tx_queue, msg);
		return 0;
	}

	osmo_prim_init(&pp.oph, SAP_GSM_PH, PRIM_PH_DATA,
			PRIM_OP_REQUEST, msg);
	pp.u.data.chan_nr = chan_nr;
	pp.u.data.link_id = link_id;

	/* send the frame now */
	le->tx_pending = 0; /* disabled flow control */
	lapdm_pad_msgb(msg, pad);

	return le->l1_prim_cb(&pp.oph, le->l1_ctx);
}

static int tx_ph_data_enqueue_ui(struct lapdm_datalink *dl, struct msgb *msg,
				 uint8_t chan_nr, uint8_t link_id, uint8_t pad)
{
	struct lapdm_entity *le = dl->entity;
	struct osmo_phsap_prim pp;

	/* if there is a pending message, queue it */
	if (le->tx_pending || le->flags & LAPDM_ENT_F_POLLING_ONLY) {
		*msgb_push(msg, 1) = pad;
		*msgb_push(msg, 1) = link_id;
		*msgb_push(msg, 1) = chan_nr;
		msgb_enqueue(&dl->tx_ui_queue, msg);
		return 0;
	}

	osmo_prim_init(&pp.oph, SAP_GSM_PH, PRIM_PH_DATA,
			PRIM_OP_REQUEST, msg);
	pp.u.data.chan_nr = chan_nr;
	pp.u.data.link_id = link_id;

	/* send the frame now */
	le->tx_pending = 0; /* disabled flow control */
	lapdm_pad_msgb(msg, pad);

	return le->l1_prim_cb(&pp.oph, le->l1_ctx);
}

/* Get transmit frame from queue, if any. In polling mode, indicate RTS to LAPD and start T200, if pending. */
static struct msgb *tx_dequeue_msgb(struct lapdm_datalink *dl, uint32_t fn)
{
	struct msgb *msg;

	/* Call RTS function of LAPD, to queue next frame. */
	if (dl->entity->flags & LAPDM_ENT_F_RTS) {
		struct lapd_msg_ctx lctx;
		int rc;

		/* Poll next frame. */
		lctx.dl = &dl->dl;
		rc = lapd_ph_rts_ind(&lctx);

		/* If T200 has been started, calculate timeout FN. */
		if (rc == 1) {
			/* Set T200 in advance. */
			dl->t200_timeout = fn;
			ADD_MODULO(dl->t200_timeout, dl->t200_fn, GSM_MAX_FN);

			LOGDL(&dl->dl, LOGL_INFO,
			      "T200 running from FN %"PRIu32" to FN %"PRIu32" (%"PRIu32" frames).\n",
			      fn, dl->t200_timeout, dl->t200_fn);
		}
	}

	/* If there is no frame from LAPD, send UI frame, if any. */
	msg = msgb_dequeue(&dl->dl.tx_queue);
	if (msg)
		LOGDL(&dl->dl, LOGL_INFO, "Sending frame from TX queue. (FN %"PRIu32")\n", fn);
	else {
		msg = msgb_dequeue(&dl->tx_ui_queue);
		if (msg)
			LOGDL(&dl->dl, LOGL_INFO, "Sending UI frame from TX queue. (FN %"PRIu32")\n", fn);
	}
	return msg;
}

/* Dequeue a Downlink message for DCCH (dedicated channel) */
static struct msgb *tx_dequeue_dcch_msgb(struct lapdm_entity *le, uint32_t fn)
{
	struct msgb *msg;

	/* SAPI=0 always has higher priority than SAPI=3 */
	msg = tx_dequeue_msgb(&le->datalink[DL_SAPI0], fn);
	if (msg == NULL) { /* no SAPI=0 messages, dequeue SAPI=3 (if any) */
		msg = tx_dequeue_msgb(&le->datalink[DL_SAPI3], fn);
	}

	return msg;
}

/* Dequeue a Downlink message for ACCH (associated channel) */
static struct msgb *tx_dequeue_acch_msgb(struct lapdm_entity *le, uint32_t fn)
{
	struct lapdm_datalink *dl;
	int last = le->last_tx_dequeue;
	int i = last, n = ARRAY_SIZE(le->datalink);
	struct msgb *msg = NULL;

	/* round-robin dequeue */
	do {
		/* next */
		i = (i + 1) % n;
		dl = &le->datalink[i];
		if ((msg = tx_dequeue_msgb(dl, fn)))
			break;
	} while (i != last);

	if (msg) {
		/* Set last dequeue position */
		le->last_tx_dequeue = i;
	}

	return msg;
}

/*! dequeue a msg that's pending transmission via L1 and wrap it into
 * a osmo_phsap_prim */
int lapdm_phsap_dequeue_prim_fn(struct lapdm_entity *le, struct osmo_phsap_prim *pp, uint32_t fn)
{
	struct msgb *msg;
	uint8_t pad;

	/* Dequeue depending on channel type: DCCH or ACCH.
	 * See 3GPP TS 44.005, section 4.2.2 "Priority". */
	if (le == &le->lapdm_ch->lapdm_dcch)
		msg = tx_dequeue_dcch_msgb(le, fn);
	else
		msg = tx_dequeue_acch_msgb(le, fn);
	if (!msg)
		return -ENODEV;

	/* if we have a message, send PH-DATA.req */
	osmo_prim_init(&pp->oph, SAP_GSM_PH, PRIM_PH_DATA,
			PRIM_OP_REQUEST, msg);

	/* Pull chan_nr and link_id */
	pp->u.data.chan_nr = *msg->data;
	msgb_pull(msg, 1);
	pp->u.data.link_id = *msg->data;
	msgb_pull(msg, 1);
	pad = *msg->data;
	msgb_pull(msg, 1);

	/* Pad the frame, we can transmit now */
	lapdm_pad_msgb(msg, pad);

	return 0;
}

static void lapdm_t200_fn_dl(struct lapdm_datalink *dl, uint32_t fn)
{
	uint32_t diff;

	OSMO_ASSERT((dl->dl.lapd_flags & LAPD_F_RTS));

	/* If T200 is running, check if it has fired. */
	if (dl->dl.t200_rts != LAPD_T200_RTS_RUNNING)
		return;

	/* Calculate how many frames fn is behind t200_timeout.
	 * If it is negative (>= GSM_MAX_FN / 2), we have not reached t200_timeout yet.
	 * If it is 0 or positive, we reached it or we are a bit too late, which is not a problem.
	 */
	diff = fn;
	ADD_MODULO(diff, GSM_MAX_FN - dl->t200_timeout, GSM_MAX_FN);
	if (diff >= GSM_MAX_FN / 2)
		return;

	LOGDL(&dl->dl, LOGL_INFO, "T200 timeout at FN %"PRIu32", detected at FN %"PRIu32".\n", dl->t200_timeout, fn);

	lapd_t200_timeout(&dl->dl);
}

/*! Get receive frame number from L1. It is used to check the T200 timeout.
 * This function is used if LAPD is in RTS mode only. (Applies if the LAPDM_ENT_F_POLLING_ONLY flag is set.)
 * This function must be called for every valid or invalid data frame received.
 * The frame number fn must be the frame number of the first burst of a data frame.
 * This function must be called after the frame is delivered to layer 2.
 * In case of TCH, this this function must be called for every speech frame received, meaning that there was no valid
 * data frame. */
void lapdm_t200_fn(struct lapdm_entity *le, uint32_t fn)
{
	unsigned int i;

	if (!(le->flags & LAPDM_ENT_F_POLLING_ONLY)) {
		LOGP(DLLAPD, LOGL_ERROR, "Function call not allowed on timer based T200.\n");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(le->datalink); i++)
		lapdm_t200_fn_dl(&le->datalink[i], fn);
}

/*! dequeue a msg that's pending transmission via L1 and wrap it into
 * a osmo_phsap_prim */
int lapdm_phsap_dequeue_prim(struct lapdm_entity *le, struct osmo_phsap_prim *pp)
{
	return lapdm_phsap_dequeue_prim_fn(le, pp, 0);
}

/* get next frame from the tx queue. because the ms has multiple datalinks,
 * each datalink's queue is read round-robin.
 */
static int l2_ph_data_conf(struct msgb *msg, struct lapdm_entity *le)
{
	struct osmo_phsap_prim pp;

	/* we may send again */
	le->tx_pending = 0;

	/* free confirm message */
	if (msg)
		msgb_free(msg);

	if (lapdm_phsap_dequeue_prim(le, &pp) < 0) {
		/* no message in all queues */

		/* If user didn't request PH-EMPTY_FRAME.req, abort */
		if (!(le->flags & LAPDM_ENT_F_EMPTY_FRAME))
			return 0;

		/* otherwise, send PH-EMPTY_FRAME.req */
		osmo_prim_init(&pp.oph, SAP_GSM_PH,
				PRIM_PH_EMPTY_FRAME,
				PRIM_OP_REQUEST, NULL);
	} else {
		le->tx_pending = 1;
	}

	return le->l1_prim_cb(&pp.oph, le->l1_ctx);
}

/* Is a given msg_type "transparent" as per TS 48.058 Section 8.1 */
static int rsl_is_transparent(uint8_t msg_type)
{
	switch (msg_type) {
	case RSL_MT_DATA_IND:
	case RSL_MT_UNIT_DATA_IND:
		return 1;
	case RSL_MT_DATA_REQ:
	case RSL_MT_UNIT_DATA_REQ:
		return 1;
	default:
		return 0;
	}
}

/* Create RSLms various RSLms messages */
static int send_rslms_rll_l3(uint8_t msg_type, struct lapdm_msg_ctx *mctx,
			     struct msgb *msg)
{
	int transparent = rsl_is_transparent(msg_type);

	/* Add the RSL + RLL header */
	rsl_rll_push_l3(msg, msg_type, mctx->chan_nr, mctx->link_id, transparent);

	/* send off the RSLms message to L3 */
	return rslms_sendmsg(msg, mctx->dl->entity);
}

/* Take a B4 format message from L1 and create RSLms UNIT DATA IND */
static int send_rslms_rll_l3_ui(struct lapdm_msg_ctx *mctx, struct msgb *msg)
{
	uint8_t l3_len = msg->tail - (uint8_t *)msgb_l3(msg);

	/* Add the RSL + RLL header */
	msgb_tv16_push(msg, RSL_IE_L3_INFO, l3_len);

	/* Add two non-standard IEs carrying MS power and TA values for B4 (SACCH) */
	if (mctx->lapdm_fmt == LAPDm_FMT_B4) {
		msgb_tv_push(msg, RSL_IE_MS_POWER, mctx->tx_power_ind);
		msgb_tv_push(msg, RSL_IE_TIMING_ADVANCE, mctx->ta_ind);
	}

	rsl_rll_push_hdr(msg, RSL_MT_UNIT_DATA_IND, mctx->chan_nr,
		mctx->link_id, 1);

	return rslms_sendmsg(msg, mctx->dl->entity);
}

static int send_rll_simple(uint8_t msg_type, struct lapdm_msg_ctx *mctx)
{
	struct msgb *msg;
	int transparent = rsl_is_transparent(msg_type);

	msg = rsl_rll_simple(msg_type, mctx->chan_nr, mctx->link_id, transparent);

	/* send off the RSLms message to L3 */
	return rslms_sendmsg(msg, mctx->dl->entity);
}

static int rsl_rll_error(uint8_t cause, struct lapdm_msg_ctx *mctx)
{
	struct msgb *msg;

	LOGDL(&mctx->dl->dl, LOGL_NOTICE, "sending MDL-ERROR-IND %d\n", cause);
	msg = rsl_rll_simple(RSL_MT_ERROR_IND, mctx->chan_nr, mctx->link_id, 0);
	msgb_tlv_put(msg, RSL_IE_RLM_CAUSE, 1, &cause);
	return rslms_sendmsg(msg, mctx->dl->entity);
}

/* DLSAP L2 -> L3 (RSLms) */
static int send_rslms_dlsap(struct osmo_dlsap_prim *dp,
	struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	struct lapdm_datalink *mdl =
		container_of(dl, struct lapdm_datalink, dl);
	struct lapdm_msg_ctx *mctx = &mdl->mctx;
	uint8_t rll_msg = 0;

	switch (OSMO_PRIM_HDR(&dp->oph)) {
	case OSMO_PRIM(PRIM_DL_EST, PRIM_OP_INDICATION):
		rll_msg = RSL_MT_EST_IND;
		break;
	case OSMO_PRIM(PRIM_DL_EST, PRIM_OP_CONFIRM):
		rll_msg = RSL_MT_EST_CONF;
		break;
	case OSMO_PRIM(PRIM_DL_DATA, PRIM_OP_INDICATION):
		rll_msg = RSL_MT_DATA_IND;
		break;
	case OSMO_PRIM(PRIM_DL_UNIT_DATA, PRIM_OP_INDICATION):
		return send_rslms_rll_l3_ui(mctx, dp->oph.msg);
	case OSMO_PRIM(PRIM_DL_REL, PRIM_OP_INDICATION):
		rll_msg = RSL_MT_REL_IND;
		break;
	case OSMO_PRIM(PRIM_DL_REL, PRIM_OP_CONFIRM):
		rll_msg = RSL_MT_REL_CONF;
		break;
	case OSMO_PRIM(PRIM_DL_SUSP, PRIM_OP_CONFIRM):
		rll_msg = RSL_MT_SUSP_CONF;
		break;
	case OSMO_PRIM(PRIM_MDL_ERROR, PRIM_OP_INDICATION):
		rsl_rll_error(dp->u.error_ind.cause, mctx);
		if (dp->oph.msg)
			msgb_free(dp->oph.msg);
		return 0;
	}

	if (!rll_msg) {
		LOGDL(dl, LOGL_ERROR, "Unsupported op %d, prim %d. Please "
			"fix!\n", dp->oph.primitive, dp->oph.operation);
		return -EINVAL;
	}

	if (!dp->oph.msg)
		return send_rll_simple(rll_msg, mctx);

	return send_rslms_rll_l3(rll_msg, mctx, dp->oph.msg);
}

/* send a data frame to layer 1 */
static int lapdm_send_ph_data_req(struct lapd_msg_ctx *lctx, struct msgb *msg)
{
	uint8_t l3_len = msg->tail - msg->data;
	struct lapd_datalink *dl = lctx->dl;
	struct lapdm_datalink *mdl =
		container_of(dl, struct lapdm_datalink, dl);
	struct lapdm_msg_ctx *mctx = &mdl->mctx;
	int format = lctx->format;

	/* prepend l2 header */
	msg->l2h = msgb_push(msg, 3);
	msg->l2h[0] = LAPDm_ADDR(lctx->lpd, lctx->sapi, lctx->cr);
					/* EA is set here too */
	switch (format) {
	case LAPD_FORM_I:
		msg->l2h[1] = LAPDm_CTRL_I(lctx->n_recv, lctx->n_send,
						lctx->p_f);
		break;
	case LAPD_FORM_S:
		msg->l2h[1] = LAPDm_CTRL_S(lctx->n_recv, lctx->s_u, lctx->p_f);
		break;
	case LAPD_FORM_U:
		msg->l2h[1] = LAPDm_CTRL_U(lctx->s_u, lctx->p_f);
		break;
	default:
		msgb_free(msg);
		return -EINVAL;
	}
	msg->l2h[2] = LAPDm_LEN(l3_len); /* EL is set here too */
	if (lctx->more)
		msg->l2h[2] |= LAPDm_MORE;

	/* add ACCH header with last indicated tx-power and TA */
	if ((mctx->link_id & 0x40)) {
		struct lapdm_entity *le = mdl->entity;

		msg->l2h = msgb_push(msg, 2);
		msg->l2h[0] = le->tx_power;
		msg->l2h[1] = le->ta;
	}

	return tx_ph_data_enqueue(mctx->dl, msg, mctx->chan_nr, mctx->link_id,
			23);
}

static int update_pending_frames(struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	struct msgb *msg;
	int rc = -1;

	llist_for_each_entry(msg, &dl->tx_queue, list) {
		if (LAPDm_CTRL_is_I(msg->l2h[1])) {
			msg->l2h[1] = LAPDm_CTRL_I(dl->v_recv, LAPDm_CTRL_I_Ns(msg->l2h[1]),
					LAPDm_CTRL_PF_BIT(msg->l2h[1]));
			rc = 0;
		} else if (LAPDm_CTRL_is_S(msg->l2h[1])) {
			msg->l2h[1] = LAPDm_CTRL_S(dl->v_recv, LAPDm_CTRL_S_BITS(msg->l2h[1]),
						   LAPDm_CTRL_PF_BIT(msg->l2h[1]));
		}
	}

	return rc;
}

/* determine if receiving a given LAPDm message is not permitted */
static int lapdm_rx_not_permitted(const struct lapdm_entity *le,
				  const struct lapd_msg_ctx *lctx)
{
	/* we currently only implement SABM related checks here */
	if (lctx->format != LAPD_FORM_U || lctx->s_u != LAPD_U_SABM)
		return 0;

	if (le->mode == LAPDM_MODE_BTS) {
		if (le == &le->lapdm_ch->lapdm_acch) {
			/* no contention resolution on SACCH */
			if (lctx->length > 0)
				return RLL_CAUSE_SABM_INFO_NOTALL;
		} else {
			switch (lctx->sapi) {
			case 3:
				/* SAPI3 doesn't support contention resolution */
				if (lctx->length > 0)
					return RLL_CAUSE_SABM_INFO_NOTALL;
				break;
			default:
				break;
			}
		}
	} else if (le->mode == LAPDM_MODE_MS) {
		/* contention resolution (L3 present) is only sent by MS, but
		 * never received by it */
		if (lctx->length > 0)
			return RLL_CAUSE_SABM_INFO_NOTALL;
	}
	return 0;
}

/* input into layer2 (from layer 1) */
static int l2_ph_data_ind(struct msgb *msg, struct lapdm_entity *le,
	uint8_t chan_nr, uint8_t link_id, uint32_t fn)
{
	uint8_t cbits = chan_nr >> 3;
	uint8_t sapi; /* we cannot take SAPI from link_id, as L1 has no clue */
	struct lapdm_msg_ctx mctx;
	struct lapd_msg_ctx lctx;
	int rc = 0;
	int n201;

	/* when we reach here, we have a msgb with l2h pointing to the raw
	 * 23byte mac block. The l1h has already been purged. */

	memset(&mctx, 0, sizeof(mctx));
	mctx.chan_nr = chan_nr;
	mctx.link_id = link_id;
	mctx.fn = fn;

	/* check for L1 chan_nr/link_id and determine LAPDm hdr format */
	if (cbits == 0x10 || cbits == 0x12) {
		/* Format Bbis is used on BCCH and CCCH(PCH, NCH and AGCH) */
		mctx.lapdm_fmt = LAPDm_FMT_Bbis;
		n201 = N201_Bbis;
		sapi = 0;
	} else {
		if (mctx.link_id & 0x40) {
			/* It was received from network on SACCH */

			/* A Short L3 header has both bits == 0. */
			if (LAPDm_ADDR_SHORT_L2(msg->l2h[2]) == 0) {
				mctx.lapdm_fmt = LAPDm_FMT_Bter;
				n201 = N201_Bter_SACCH;
				sapi = 0;
			} else if (le->mode == LAPDM_MODE_MS
				&& LAPDm_CTRL_is_U(msg->l2h[3])
				&& LAPDm_CTRL_U_BITS(msg->l2h[3]) == 0) {
				/* If UI on SACCH sent by BTS, lapdm_fmt must be B4 */
				mctx.lapdm_fmt = LAPDm_FMT_B4;
				n201 = N201_B4;
				/* sapi is found after two-btyte L1 header */
				sapi = (msg->l2h[2] >> 2) & 7;
			} else {
				mctx.lapdm_fmt = LAPDm_FMT_B;
				n201 = N201_AB_SACCH;
				/* sapi is found after two-btyte L1 header */
				sapi = (msg->l2h[2] >> 2) & 7;
			}
			/* SACCH frames have a two-byte L1 header that
			 * OsmocomBB L1 doesn't strip */
			mctx.tx_power_ind = msg->l2h[0] & 0x1f;
			mctx.ta_ind = msg->l2h[1];
			msgb_pull(msg, 2);
			msg->l2h += 2;
		} else {
			/* A Short L3 header has both bits == 0. */
			if (LAPDm_ADDR_SHORT_L2(msg->l2h[0]) == 0) {
				mctx.lapdm_fmt = LAPDm_FMT_Bter;
				n201 = N201_Bter_SDCCH;
				sapi = 0;
			} else {
				mctx.lapdm_fmt = LAPDm_FMT_B;
				n201 = N201_AB_SDCCH;
				sapi = (msg->l2h[0] >> 2) & 7;
			}
		}
	}

	mctx.dl = lapdm_datalink_for_sapi(le, sapi);
	/* G.2.1 No action on frames containing an unallocated SAPI. */
	if (!mctx.dl) {
		LOGP(DLLAPD, LOGL_NOTICE, "Received frame for unsupported SAPI %d!\n", sapi);
		msgb_free(msg);
		return -EIO;
	}

	switch (mctx.lapdm_fmt) {
	case LAPDm_FMT_A:
	case LAPDm_FMT_B:
	case LAPDm_FMT_B4:
		lctx.dl = &mctx.dl->dl;
		/* obtain SAPI from address field */
		mctx.link_id |= LAPDm_ADDR_SAPI(msg->l2h[0]);
		/* G.2.3 EA bit set to "0" is not allowed in GSM */
		if (!LAPDm_ADDR_EA(msg->l2h[0])) {
			LOGDL(lctx.dl, LOGL_NOTICE, "EA bit 0 is not allowed in GSM\n");
			msgb_free(msg);
			rsl_rll_error(RLL_CAUSE_FRM_UNIMPL, &mctx);
			return -EINVAL;
		}
		/* adress field */
		lctx.lpd = LAPDm_ADDR_LPD(msg->l2h[0]);
		lctx.sapi = LAPDm_ADDR_SAPI(msg->l2h[0]);
		lctx.cr = LAPDm_ADDR_CR(msg->l2h[0]);
		/* command field */
		if (LAPDm_CTRL_is_I(msg->l2h[1])) {
			lctx.format = LAPD_FORM_I;
			lctx.n_send = LAPDm_CTRL_I_Ns(msg->l2h[1]);
			lctx.n_recv = LAPDm_CTRL_Nr(msg->l2h[1]);
		} else if (LAPDm_CTRL_is_S(msg->l2h[1])) {
			lctx.format = LAPD_FORM_S;
			lctx.n_recv = LAPDm_CTRL_Nr(msg->l2h[1]);
			lctx.s_u = LAPDm_CTRL_S_BITS(msg->l2h[1]);
		} else if (LAPDm_CTRL_is_U(msg->l2h[1])) {
			lctx.format = LAPD_FORM_U;
			lctx.s_u = LAPDm_CTRL_U_BITS(msg->l2h[1]);
		} else
			lctx.format = LAPD_FORM_UKN;
		lctx.p_f = LAPDm_CTRL_PF_BIT(msg->l2h[1]);
		if (lctx.sapi != LAPDm_SAPI_NORMAL
		 && lctx.sapi != LAPDm_SAPI_SMS
		 && lctx.format == LAPD_FORM_U
		 && lctx.s_u == LAPDm_U_UI) {
			/* 5.3.3 UI frames with invalid SAPI values shall be
			 * discarded
			 */
			LOGDL(lctx.dl, LOGL_INFO, "sapi=%u (discarding)\n", lctx.sapi);
			msgb_free(msg);
			return 0;
		}
		if (mctx.lapdm_fmt == LAPDm_FMT_B4) {
			lctx.n201 = n201;
			lctx.length = n201;
			lctx.more = 0;
			msg->l3h = msg->l2h + 2;
			msgb_pull_to_l3(msg);
		} else {
			/* length field */
			if (!(msg->l2h[2] & LAPDm_EL)) {
				/* G.4.1 If the EL bit is set to "0", an
				 * MDL-ERROR-INDICATION primitive with cause
				 * "frame not implemented" is sent to the
				 * mobile management entity. */
				LOGDL(lctx.dl, LOGL_NOTICE, "we don't support multi-octet length\n");
				msgb_free(msg);
				rsl_rll_error(RLL_CAUSE_FRM_UNIMPL, &mctx);
				return -EINVAL;
			}
			lctx.n201 = n201;
			lctx.length = msg->l2h[2] >> 2;
			lctx.more = !!(msg->l2h[2] & LAPDm_MORE);
			msg->l3h = msg->l2h + 3;
			msgb_pull_to_l3(msg);
		}
		/* store context for messages from lapd */
		memcpy(&mctx.dl->mctx, &mctx, sizeof(mctx.dl->mctx));
		rc =lapdm_rx_not_permitted(le, &lctx);
		if (rc > 0) {
			LOGDL(lctx.dl, LOGL_NOTICE, "received message not permitted\n");
			msgb_free(msg);
			rsl_rll_error(rc, &mctx);
			return -EINVAL;
		}
		/* send to LAPD */
		LOGDL(lctx.dl, LOGL_DEBUG, "Frame received at FN %"PRIu32".\n", fn);
		rc = lapd_ph_data_ind(msg, &lctx);
		break;
	case LAPDm_FMT_Bter:
		/* fall-through */
	case LAPDm_FMT_Bbis:
		/* Update context so that users can read fields like fn: */
		memcpy(&mctx.dl->mctx, &mctx, sizeof(mctx.dl->mctx));
		/* directly pass up to layer3 */
		msg->l3h = msg->l2h;
		msgb_pull_to_l3(msg);
		rc = send_rslms_rll_l3(RSL_MT_UNIT_DATA_IND, &mctx, msg);
		break;
	default:
		msgb_free(msg);
	}

	return rc;
}

/* input into layer2 (from layer 1) */
static int l2_ph_rach_ind(struct lapdm_entity *le, uint8_t ra, uint32_t fn, uint8_t acc_delay)
{
	struct abis_rsl_cchan_hdr *ch;
	struct gsm48_req_ref req_ref;
	struct gsm_time gt;
	struct msgb *msg = msgb_alloc_headroom(512, 64, "RSL CHAN RQD");

	if (!msg)
		return -ENOMEM;

	msg->l2h = msgb_push(msg, sizeof(*ch));
	ch = (struct abis_rsl_cchan_hdr *)msg->l2h;
	rsl_init_cchan_hdr(ch, RSL_MT_CHAN_RQD);
	ch->chan_nr = RSL_CHAN_RACH;

	/* generate a RSL CHANNEL REQUIRED message */
	gsm_fn2gsmtime(&gt, fn);
	req_ref.ra = ra;
	req_ref.t1 = gt.t1; /* FIXME: modulo? */
	req_ref.t2 = gt.t2;
	req_ref.t3_low = gt.t3 & 7;
	req_ref.t3_high = gt.t3 >> 3;

	msgb_tv_fixed_put(msg, RSL_IE_REQ_REFERENCE, 3, (uint8_t *) &req_ref);
	msgb_tv_put(msg, RSL_IE_ACCESS_DELAY, acc_delay);

	return rslms_sendmsg(msg, le);
}

static int l2_ph_chan_conf(struct msgb *msg, struct lapdm_entity *le, uint32_t frame_nr);

/*! Receive a PH-SAP primitive from L1 */
int lapdm_phsap_up(struct osmo_prim_hdr *oph, struct lapdm_entity *le)
{
	struct osmo_phsap_prim *pp = (struct osmo_phsap_prim *) oph;
	int rc = 0;

	if (oph->sap != SAP_GSM_PH) {
		LOGP(DLLAPD, LOGL_ERROR, "primitive for unknown SAP %u\n",
			oph->sap);
		msgb_free(oph->msg);
		return -ENODEV;
	}

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(PRIM_PH_DATA, PRIM_OP_INDICATION):
		rc = l2_ph_data_ind(oph->msg, le, pp->u.data.chan_nr,
				    pp->u.data.link_id, pp->u.data.fn);
		break;
	case OSMO_PRIM(PRIM_PH_RTS, PRIM_OP_INDICATION):
		rc = l2_ph_data_conf(oph->msg, le);
		break;
	case OSMO_PRIM(PRIM_PH_RACH, PRIM_OP_INDICATION):
		rc = l2_ph_rach_ind(le, pp->u.rach_ind.ra, pp->u.rach_ind.fn,
				    pp->u.rach_ind.acc_delay);
		break;
	case OSMO_PRIM(PRIM_PH_RACH, PRIM_OP_CONFIRM):
		rc = l2_ph_chan_conf(oph->msg, le, pp->u.rach_ind.fn);
		break;
	default:
		LOGP(DLLAPD, LOGL_ERROR, "Unknown primitive %u\n",
			oph->primitive);
		msgb_free(oph->msg);
		return -EINVAL;
	}

	return rc;
}


/* L3 -> L2 / RSLMS -> LAPDm */

/* Set LAPDm context for established connection */
static int set_lapdm_context(struct lapdm_datalink *dl, uint8_t chan_nr,
	uint8_t link_id, int n201, uint8_t sapi)
{
	memset(&dl->mctx, 0, sizeof(dl->mctx));
	dl->mctx.dl = dl;
	dl->mctx.chan_nr = chan_nr;
	dl->mctx.link_id = link_id;
	dl->dl.lctx.dl = &dl->dl;
	dl->dl.lctx.n201 = n201;
	dl->dl.lctx.sapi = sapi;

	return 0;
}

/* L3 requests establishment of data link */
static int rslms_rx_rll_est_req(struct msgb *msg, struct lapdm_datalink *dl)
{
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	uint8_t chan_nr = rllh->chan_nr;
	uint8_t link_id = rllh->link_id;
	uint8_t sapi = rllh->link_id & 7;
	struct tlv_parsed tv;
	uint8_t length;
	uint8_t n201 = (rllh->link_id & 0x40) ? N201_AB_SACCH : N201_AB_SDCCH;
	struct osmo_dlsap_prim dp;

	/* Set LAPDm context for established connection */
	set_lapdm_context(dl, chan_nr, link_id, n201, sapi);

	rsl_tlv_parse(&tv, rllh->data, msgb_l2len(msg) - sizeof(*rllh));
	if (TLVP_PRESENT(&tv, RSL_IE_L3_INFO)) {
		msg->l3h = (uint8_t *) TLVP_VAL(&tv, RSL_IE_L3_INFO);
		/* contention resolution establishment procedure */
		if (sapi != 0) {
			/* According to clause 6, the contention resolution
			 * procedure is only permitted with SAPI value 0 */
			LOGDL(&dl->dl, LOGL_ERROR, "SAPI != 0 but contention"
				"resolution (discarding)\n");
			msgb_free(msg);
			return send_rll_simple(RSL_MT_REL_IND, &dl->mctx);
		}
		/* transmit a SABM command with the P bit set to "1". The SABM
		 * command shall contain the layer 3 message unit */
		length = TLVP_LEN(&tv, RSL_IE_L3_INFO);
	} else {
		/* normal establishment procedure */
		msg->l3h = msg->l2h + sizeof(*rllh);
		length = 0;
	}

	/* check if the layer3 message length exceeds N201 */
	if (length > n201) {
		LOGDL(&dl->dl, LOGL_ERROR, "frame too large: %d > N201(%d) "
			"(discarding)\n", length, n201);
		msgb_free(msg);
		return send_rll_simple(RSL_MT_REL_IND, &dl->mctx);
	}

	/* Remove RLL header from msgb and set length to L3-info */
	msgb_pull_to_l3(msg);
	msgb_trim(msg, length);

	/* prepare prim */
	osmo_prim_init(&dp.oph, 0, PRIM_DL_EST, PRIM_OP_REQUEST, msg);

	/* send to L2 */
	return lapd_recv_dlsap(&dp, &dl->dl.lctx);
}

/* L3 requests transfer of unnumbered information */
static int rslms_rx_rll_udata_req(struct msgb *msg, struct lapdm_datalink *dl)
{
	struct lapdm_entity *le = dl->entity;
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	uint8_t chan_nr = rllh->chan_nr;
	uint8_t link_id = rllh->link_id;
	uint8_t sapi = link_id & 7;
	struct tlv_parsed tv;
	int length, ui_bts;
	bool use_b_ter;

	if (!le) {
		LOGDL(&dl->dl, LOGL_ERROR, "lapdm_datalink without entity error\n");
		msgb_free(msg);
		return -EMLINK;
	}
	ui_bts = (le->mode == LAPDM_MODE_BTS && (link_id & 0x40));

	/* check if the layer3 message length exceeds N201 */

	rsl_tlv_parse(&tv, rllh->data, msgb_l2len(msg)-sizeof(*rllh));

	if (TLVP_PRESENT(&tv, RSL_IE_TIMING_ADVANCE)) {
		le->ta = *TLVP_VAL(&tv, RSL_IE_TIMING_ADVANCE);
	}
	if (TLVP_PRESENT(&tv, RSL_IE_MS_POWER)) {
		le->tx_power = *TLVP_VAL(&tv, RSL_IE_MS_POWER);
	}
	if (!TLVP_PRESENT(&tv, RSL_IE_L3_INFO)) {
		LOGDL(&dl->dl, LOGL_ERROR, "unit data request without message error\n");
		msgb_free(msg);
		return -EINVAL;
	}
	msg->l3h = (uint8_t *) TLVP_VAL(&tv, RSL_IE_L3_INFO);
	length = TLVP_LEN(&tv, RSL_IE_L3_INFO);
	/* check for Bter frame */
	use_b_ter = (length == ((link_id & 0x40) ? 21 : 23) && sapi == 0);
	/* check if the layer3 message length exceeds N201 */
	if (length + ((link_id & 0x40) ? 4 : 2) + !ui_bts > 23 && !use_b_ter) {
		LOGDL(&dl->dl, LOGL_ERROR, "frame too large: %d > N201(%d) "
			"(discarding)\n", length,
			((link_id & 0x40) ? 18 : 20) + ui_bts);
		msgb_free(msg);
		return -EIO;
	}

	LOGDL(&dl->dl, LOGL_INFO, "sending unit data (tx_power=%d, ta=%d)\n", le->tx_power, le->ta);

	/* Remove RLL header from msgb and set length to L3-info */
	msgb_pull_to_l3(msg);
	msgb_trim(msg, length);

	/* Push L1 + LAPDm header on msgb */
	if (!use_b_ter) {
		msg->l2h = msgb_push(msg, 2 + !ui_bts);
		msg->l2h[0] = LAPDm_ADDR(LAPDm_LPD_NORMAL, sapi, dl->dl.cr.loc2rem.cmd);
		msg->l2h[1] = LAPDm_CTRL_U(LAPDm_U_UI, 0);
		if (!ui_bts)
			msg->l2h[2] = LAPDm_LEN(length);
	} else
		msg->l2h = msg->data;
	if (link_id & 0x40) {
		msg->l2h = msgb_push(msg, 2);
		msg->l2h[0] = le->tx_power;
		msg->l2h[1] = le->ta;
	}

	/* Tramsmit */
	return tx_ph_data_enqueue_ui(dl, msg, chan_nr, link_id, 23);
}

/* L3 requests transfer of acknowledged information */
static int rslms_rx_rll_data_req(struct msgb *msg, struct lapdm_datalink *dl)
{
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	struct tlv_parsed tv;
	int length;
	struct osmo_dlsap_prim dp;

	rsl_tlv_parse(&tv, rllh->data, msgb_l2len(msg)-sizeof(*rllh));
	if (!TLVP_PRESENT(&tv, RSL_IE_L3_INFO)) {
		LOGDL(&dl->dl, LOGL_ERROR, "data request without message error\n");
		msgb_free(msg);
		return -EINVAL;
	}
	msg->l3h = (uint8_t *) TLVP_VAL(&tv, RSL_IE_L3_INFO);
	length = TLVP_LEN(&tv, RSL_IE_L3_INFO);

	/* Remove RLL header from msgb and set length to L3-info */
	msgb_pull_to_l3(msg);
	msgb_trim(msg, length);

	/* prepare prim */
	osmo_prim_init(&dp.oph, 0, PRIM_DL_DATA, PRIM_OP_REQUEST, msg);

	/* send to L2 */
	return lapd_recv_dlsap(&dp, &dl->dl.lctx);
}

/* L3 requests suspension of data link */
static int rslms_rx_rll_susp_req(struct msgb *msg, struct lapdm_datalink *dl)
{
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	uint8_t sapi = rllh->link_id & 7;
	struct osmo_dlsap_prim dp;

	if (sapi != 0) {
		LOGDL(&dl->dl, LOGL_ERROR, "SAPI != 0 while suspending\n");
		msgb_free(msg);
		return -EINVAL;
	}

	/* prepare prim */
	osmo_prim_init(&dp.oph, 0, PRIM_DL_SUSP, PRIM_OP_REQUEST, msg);

	/* send to L2 */
	return lapd_recv_dlsap(&dp, &dl->dl.lctx);
}

/* L3 requests resume of data link */
static int rslms_rx_rll_res_req(struct msgb *msg, struct lapdm_datalink *dl)
{
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	int msg_type = rllh->c.msg_type;
	uint8_t chan_nr = rllh->chan_nr;
	uint8_t link_id = rllh->link_id;
	uint8_t sapi = rllh->link_id & 7;
	struct tlv_parsed tv;
	uint8_t length;
	uint8_t n201 = (rllh->link_id & 0x40) ? N201_AB_SACCH : N201_AB_SDCCH;
	struct osmo_dlsap_prim dp;

	/* Set LAPDm context for established connection */
	set_lapdm_context(dl, chan_nr, link_id, n201, sapi);

	rsl_tlv_parse(&tv, rllh->data, msgb_l2len(msg)-sizeof(*rllh));
	if (!TLVP_PRESENT(&tv, RSL_IE_L3_INFO)) {
		LOGDL(&dl->dl, LOGL_ERROR, "resume without message error\n");
		msgb_free(msg);
		return send_rll_simple(RSL_MT_REL_IND, &dl->mctx);
	}
	msg->l3h = (uint8_t *) TLVP_VAL(&tv, RSL_IE_L3_INFO);
	length = TLVP_LEN(&tv, RSL_IE_L3_INFO);

	/* Remove RLL header from msgb and set length to L3-info */
	msgb_pull_to_l3(msg);
	msgb_trim(msg, length);

	/* prepare prim */
	osmo_prim_init(&dp.oph, 0, (msg_type == RSL_MT_RES_REQ) ? PRIM_DL_RES
		: PRIM_DL_RECON, PRIM_OP_REQUEST, msg);

	/* send to L2 */
	return lapd_recv_dlsap(&dp, &dl->dl.lctx);
}

/* L3 requests release of data link */
static int rslms_rx_rll_rel_req(struct msgb *msg, struct lapdm_datalink *dl)
{
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	uint8_t mode = 0;
	struct osmo_dlsap_prim dp;

	/* get release mode */
	if (rllh->data[0] == RSL_IE_RELEASE_MODE)
		mode = rllh->data[1] & 1;

	/* Pull rllh */
	msgb_pull_to_l3(msg);

	/* 04.06 3.8.3: No information field is permitted with the DISC
	 * command. */
	msgb_trim(msg, 0);

	/* prepare prim */
	osmo_prim_init(&dp.oph, 0, PRIM_DL_REL, PRIM_OP_REQUEST, msg);
	dp.u.rel_req.mode = mode;

	/* send to L2 */
	return lapd_recv_dlsap(&dp, &dl->dl.lctx);
}

/* L3 requests channel in idle state */
static int rslms_rx_chan_rqd(struct lapdm_channel *lc, struct msgb *msg)
{
	struct abis_rsl_cchan_hdr *cch = msgb_l2(msg);
	void *l1ctx = lc->lapdm_dcch.l1_ctx;
	struct osmo_phsap_prim pp;

	osmo_prim_init(&pp.oph, SAP_GSM_PH, PRIM_PH_RACH,
			PRIM_OP_REQUEST, NULL);

	if (msgb_l2len(msg) < sizeof(*cch) + 4 + 2 + 2) {
		LOGP(DLLAPD, LOGL_ERROR, "Message too short for CHAN RQD!\n");
		return -EINVAL;
	}
	if (cch->data[0] != RSL_IE_REQ_REFERENCE) {
		LOGP(DLLAPD, LOGL_ERROR, "Missing REQ REFERENCE IE\n");
		return -EINVAL;
	}
	pp.u.rach_req.ra = cch->data[1];
	pp.u.rach_req.offset = ((cch->data[2] & 0x7f) << 8) | cch->data[3];
	pp.u.rach_req.is_combined_ccch = cch->data[2] >> 7;

	if (cch->data[4] != RSL_IE_ACCESS_DELAY) {
		LOGP(DLLAPD, LOGL_ERROR, "Missing ACCESS_DELAY IE\n");
		return -EINVAL;
	}
	/* TA = 0 - delay */
	pp.u.rach_req.ta = 0 - cch->data[5];

	if (cch->data[6] != RSL_IE_MS_POWER) {
		LOGP(DLLAPD, LOGL_ERROR, "Missing MS POWER IE\n");
		return -EINVAL;
	}
	pp.u.rach_req.tx_power = cch->data[7];

	msgb_free(msg);

	return lc->lapdm_dcch.l1_prim_cb(&pp.oph, l1ctx);
}

/* L1 confirms channel request */
static int l2_ph_chan_conf(struct msgb *msg, struct lapdm_entity *le, uint32_t frame_nr)
{
	struct abis_rsl_cchan_hdr *ch;
	struct gsm_time tm;
	struct gsm48_req_ref *ref;

	gsm_fn2gsmtime(&tm, frame_nr);

	msgb_pull_to_l3(msg);
	msg->l2h = msgb_push(msg, sizeof(*ch) + sizeof(*ref));
	ch = (struct abis_rsl_cchan_hdr *)msg->l2h;
	rsl_init_cchan_hdr(ch, RSL_MT_CHAN_CONF);
	ch->chan_nr = RSL_CHAN_RACH;
	ch->data[0] = RSL_IE_REQ_REFERENCE;
	ref = (struct gsm48_req_ref *) (ch->data + 1);
	ref->t1 = tm.t1;
	ref->t2 = tm.t2;
	ref->t3_low = tm.t3 & 0x7;
	ref->t3_high = tm.t3 >> 3;

	return rslms_sendmsg(msg, le);
}

/* incoming RSLms RLL message from L3 */
static int rslms_rx_rll(struct msgb *msg, struct lapdm_channel *lc)
{
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	int msg_type = rllh->c.msg_type;
	uint8_t sapi = rllh->link_id & 7;
	struct lapdm_entity *le;
	struct lapdm_datalink *dl;
	int rc = 0;

	if (msgb_l2len(msg) < sizeof(*rllh)) {
		LOGP(DLLAPD, LOGL_ERROR, "Message too short for RLL hdr!\n");
		msgb_free(msg);
		return -EINVAL;
	}

	if (rllh->link_id & 0x40)
		le = &lc->lapdm_acch;
	else
		le = &lc->lapdm_dcch;

	/* 4.1.1.5 / 4.1.1.6 / 4.1.1.7 all only exist on MS side, not
	 * BTS side */
	if (le->mode == LAPDM_MODE_BTS) {
		switch (msg_type) {
		case RSL_MT_SUSP_REQ:
		case RSL_MT_RES_REQ:
		case RSL_MT_RECON_REQ:
			LOGP(DLLAPD, LOGL_NOTICE, "(%s) RLL Message '%s' unsupported in BTS side LAPDm\n",
				lc->name, rsl_msg_name(msg_type));
			msgb_free(msg);
			return -EINVAL;
			break;
		default:
			break;
		}
	}

	/* G.2.1 No action shall be taken on frames containing an unallocated
	 * SAPI.
	 */
	dl = lapdm_datalink_for_sapi(le, sapi);
	if (!dl) {
		LOGP(DLLAPD, LOGL_ERROR, "No instance for SAPI %d!\n", sapi);
		msgb_free(msg);
		return -EINVAL;
	}

	switch (msg_type) {
	case RSL_MT_DATA_REQ:
	case RSL_MT_SUSP_REQ:
	case RSL_MT_REL_REQ:
		/* This is triggered in abnormal error conditions where
		 * set_lapdm_context() was not called for the channel earlier. */
		if (!dl->dl.lctx.dl) {
			LOGP(DLLAPD, LOGL_NOTICE, "(%s) RLL Message '%s' received without LAPDm context. (sapi %d)\n",
					lc->name, rsl_msg_name(msg_type), sapi);
			msgb_free(msg);
			return -EINVAL;
		}
		break;
	default:
		LOGP(DLLAPD, LOGL_INFO, "(%s) RLL Message '%s' received. (sapi %d)\n",
			lc->name, rsl_msg_name(msg_type), sapi);
	}

	switch (msg_type) {
	case RSL_MT_UNIT_DATA_REQ:
		rc = rslms_rx_rll_udata_req(msg, dl);
		break;
	case RSL_MT_EST_REQ:
		rc = rslms_rx_rll_est_req(msg, dl);
		break;
	case RSL_MT_DATA_REQ:
		rc = rslms_rx_rll_data_req(msg, dl);
		break;
	case RSL_MT_SUSP_REQ:
		rc = rslms_rx_rll_susp_req(msg, dl);
		break;
	case RSL_MT_RES_REQ:
		rc = rslms_rx_rll_res_req(msg, dl);
		break;
	case RSL_MT_RECON_REQ:
		rc = rslms_rx_rll_res_req(msg, dl);
		break;
	case RSL_MT_REL_REQ:
		rc = rslms_rx_rll_rel_req(msg, dl);
		break;
	default:
		LOGP(DLLAPD, LOGL_NOTICE, "Message unsupported.\n");
		msgb_free(msg);
		rc = -EINVAL;
	}

	return rc;
}

/* incoming RSLms COMMON CHANNEL message from L3 */
static int rslms_rx_com_chan(struct msgb *msg, struct lapdm_channel *lc)
{
	struct abis_rsl_cchan_hdr *cch = msgb_l2(msg);
	int msg_type = cch->c.msg_type;
	int rc = 0;

	if (msgb_l2len(msg) < sizeof(*cch)) {
		LOGP(DLLAPD, LOGL_ERROR, "Message too short for COM CHAN hdr!\n");
		return -EINVAL;
	}

	switch (msg_type) {
	case RSL_MT_CHAN_RQD:
		/* create and send RACH request */
		rc = rslms_rx_chan_rqd(lc, msg);
		break;
	default:
		LOGP(DLLAPD, LOGL_NOTICE, "Unknown COMMON CHANNEL msg %d!\n",
			msg_type);
		msgb_free(msg);
		return 0;
	}

	return rc;
}

/*! Receive a RSLms \ref msgb from Layer 3. 'msg' ownership is transferred,
 *  i.e. caller must not free it */
int lapdm_rslms_recvmsg(struct msgb *msg, struct lapdm_channel *lc)
{
	struct abis_rsl_common_hdr *rslh = msgb_l2(msg);
	int rc = 0;

	if (msgb_l2len(msg) < sizeof(*rslh)) {
		LOGP(DLLAPD, LOGL_ERROR, "Message too short RSL hdr!\n");
		msgb_free(msg);
		return -EINVAL;
	}

	switch (rslh->msg_discr & 0xfe) {
	case ABIS_RSL_MDISC_RLL:
		rc = rslms_rx_rll(msg, lc);
		break;
	case ABIS_RSL_MDISC_COM_CHAN:
		rc = rslms_rx_com_chan(msg, lc);
		break;
	default:
		LOGP(DLLAPD, LOGL_ERROR, "unknown RSLms message "
			"discriminator 0x%02x", rslh->msg_discr);
		msgb_free(msg);
		return -EINVAL;
	}

	return rc;
}

/*! Set the \ref lapdm_mode of a LAPDm entity */
int lapdm_entity_set_mode(struct lapdm_entity *le, enum lapdm_mode mode)
{
	int i;
	enum lapd_mode lm;

	switch (mode) {
	case LAPDM_MODE_MS:
		lm = LAPD_MODE_USER;
		break;
	case LAPDM_MODE_BTS:
		lm = LAPD_MODE_NETWORK;
		break;
	default:
		return -EINVAL;
	}

	for (i = 0; i < ARRAY_SIZE(le->datalink); i++) {
		lapd_set_mode(&le->datalink[i].dl, lm);
	}

	le->mode = mode;

	return 0;
}

/*! Set the \ref lapdm_mode of a LAPDm channel*/
int lapdm_channel_set_mode(struct lapdm_channel *lc, enum lapdm_mode mode)
{
	int rc;

	rc = lapdm_entity_set_mode(&lc->lapdm_dcch, mode);
	if (rc < 0)
		return rc;

	return lapdm_entity_set_mode(&lc->lapdm_acch, mode);
}

/*! Set the L1 callback and context of a LAPDm channel */
void lapdm_channel_set_l1(struct lapdm_channel *lc, osmo_prim_cb cb, void *ctx)
{
	lc->lapdm_dcch.l1_prim_cb = cb;
	lc->lapdm_acch.l1_prim_cb = cb;
	lc->lapdm_dcch.l1_ctx = ctx;
	lc->lapdm_acch.l1_ctx = ctx;
}

/*! Set the L3 callback and context of a LAPDm channel */
void lapdm_channel_set_l3(struct lapdm_channel *lc, lapdm_cb_t cb, void *ctx)
{
	lc->lapdm_dcch.l3_cb = cb;
	lc->lapdm_acch.l3_cb = cb;
	lc->lapdm_dcch.l3_ctx = ctx;
	lc->lapdm_acch.l3_ctx = ctx;
}

/*! Reset an entire LAPDm entity and all its datalinks */
void lapdm_entity_reset(struct lapdm_entity *le)
{
	struct lapdm_datalink *dl;
	int i;

	for (i = 0; i < ARRAY_SIZE(le->datalink); i++) {
		dl = &le->datalink[i];
		lapd_dl_reset(&dl->dl);
		msgb_queue_free(&dl->tx_ui_queue);
	}
}

/*! Reset a LAPDm channel with all its entities */
void lapdm_channel_reset(struct lapdm_channel *lc)
{
	lapdm_entity_reset(&lc->lapdm_dcch);
	lapdm_entity_reset(&lc->lapdm_acch);
}

/*! Set the flags of a LAPDm entity */
void lapdm_entity_set_flags(struct lapdm_entity *le, unsigned int flags)
{
	unsigned int dl_flags = 0;
	struct lapdm_datalink *dl;
	int i;

	le->flags = flags;

	/* Set flags at LAPD. */
	if (le->flags & LAPDM_ENT_F_RTS)
		dl_flags |= LAPD_F_RTS;
	if (le->flags & LAPDM_ENT_F_DROP_2ND_REJ)
		dl_flags |= LAPD_F_DROP_2ND_REJ;

	for (i = 0; i < ARRAY_SIZE(le->datalink); i++) {
		dl = &le->datalink[i];
		lapd_dl_set_flags(&dl->dl, dl_flags);
	}
}

/*! Set the flags of all LAPDm entities in a LAPDm channel */
void lapdm_channel_set_flags(struct lapdm_channel *lc, unsigned int flags)
{
	lapdm_entity_set_flags(&lc->lapdm_dcch, flags);
	lapdm_entity_set_flags(&lc->lapdm_acch, flags);
}

/*! Set the T200 FN timer of a LAPDm entity
 *  \param[in] \ref lapdm_entity
 *  \param[in] t200_fn Array of T200 timeout in frame numbers for all SAPIs (0, 3) */
void lapdm_entity_set_t200_fn(struct lapdm_entity *le, const uint32_t *t200_fn)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(le->datalink); i++)
		le->datalink[i].t200_fn = t200_fn[i];
}

/*! Set the T200 FN timer of all LAPDm entities in a LAPDm channel
 *  \param[in] \ref lapdm_channel
 *  \param[in] t200_fn_dcch Array of T200 timeout in frame numbers for all SAPIs (0, 3) on SDCCH/FACCH
 *  \param[in] t200_fn_acch Array of T200 timeout in frame numbers for all SAPIs (0, 3) on SACCH */
void lapdm_channel_set_t200_fn(struct lapdm_channel *lc, const uint32_t *t200_fn_dcch, const uint32_t *t200_fn_acch)
{
	lapdm_entity_set_t200_fn(&lc->lapdm_dcch, t200_fn_dcch);
	lapdm_entity_set_t200_fn(&lc->lapdm_acch, t200_fn_acch);
}

/*! @} */
