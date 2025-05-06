/*! \file lapd_core.c
 * LAPD core implementation */
/*
 * (C) 2010-2020 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010-2011 by Andreas Eversberg <jolly@eversberg.eu>
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

/*! \addtogroup lapd
 *  @{
 *
 * Osmocom LAPD core, used for Q.921, LAPDm and others.
 *
 * Notes on Buffering: rcv_buffer, tx_queue, tx_hist, send_buffer, send_queue
 *
 * RX data is stored in the rcv_buffer (pointer). If the message is complete, it
 * is removed from rcv_buffer pointer and forwarded to L3. If the RX data is
 * received while there is an incomplete rcv_buffer, it is appended to it.
 *
 * TX data is stored in the send_queue first. When transmitting a frame,
 * the first message in the send_queue is moved to the send_buffer. There it
 * resides until all fragments are acknowledged. Fragments to be sent by I
 * frames are stored in the tx_hist buffer for resend, if required. Also the
 * current fragment is copied into the tx_queue. There it resides until it is
 * forwarded to layer 1.
 *
 * In case we have SAPI 0, we only have a window size of 1, so the unack-
 * nowledged message resides always in the send_buffer. In case of a suspend,
 * it can be written back to the first position of the send_queue.
 *
 * The layer 1 normally sends a PH-READY-TO-SEND. But because we use
 * asynchronous transfer between layer 1 and layer 2 (serial link), we must
 * send a frame before layer 1 reaches the right timeslot to send it. So we
 * move the tx_queue to layer 1 when there is not already a pending frame, and
 * wait until acknowledge after the frame has been sent. If we receive an
 * acknowledge, we can send the next frame from the buffer, if any.
 *
 * The moving of tx_queue to layer 1 may also trigger T200, if desired. Also it
 * will trigger next I frame, if possible.
 *
 * T203 is optional. It will be stated when entering MF EST state. It will also
 * be started when I or S frame is received in that state . It will be
 * restarted in the lapd_acknowledge() function, in case outstanding frames
 * will not trigger T200. It will be stoped, when T200 is started in MF EST
 * state. It will also be stoped when leaving MF EST state.
 *
 * \file lapd_core.c
 */

/* Enable this to test content resolution on network side:
 * - The first SABM is received, UA is dropped.
 * - The phone repeats SABM, but it's content is wrong, so it is ignored
 * - The phone repeats SABM again, content is right, so UA is sent.
 */
//#define TEST_CONTENT_RESOLUTION_NETWORK

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/isdn/lapd_core.h>
#include <osmocom/gsm/rsl.h>

/* TS 04.06 Table 4 / Section 3.8.1 */
#define LAPD_U_SABM	0x7
#define LAPD_U_SABME	0xf
#define LAPD_U_DM	0x3
#define LAPD_U_UI	0x0
#define LAPD_U_DISC	0x8
#define LAPD_U_UA	0xC
#define LAPD_U_FRMR	0x11

#define LAPD_S_RR	0x0
#define LAPD_S_RNR	0x1
#define LAPD_S_REJ	0x2

#define CR_USER2NET_CMD		0
#define CR_USER2NET_RESP	1
#define CR_NET2USER_CMD		1
#define CR_NET2USER_RESP	0

#define LAPD_HEADROOM	56
#define LAPD_TAILROOM	16

#define SBIT(a) (1 << a)
#define ALL_STATES 0xffffffff

static void lapd_t200_cb(void *data);
static void lapd_t203_cb(void *data);
static int lapd_send_i(struct lapd_datalink *dl, int line, bool rts);
static int lapd_est_req(struct osmo_dlsap_prim *dp, struct lapd_msg_ctx *lctx);

/* UTILITY FUNCTIONS */

struct msgb *lapd_msgb_alloc(int length, const char *name)
{
	/* adding space for padding, FIXME: add as an option */
	if (length < 21)
		length = 21;
	return msgb_alloc_headroom(length + LAPD_HEADROOM + LAPD_TAILROOM, LAPD_HEADROOM, name);
}

static inline uint8_t do_mod(uint8_t x, uint8_t m)
{
	return x & (m - 1);
}

static inline uint8_t inc_mod(uint8_t x, uint8_t m)
{
	return (x + 1) & (m - 1);
}

static inline uint8_t add_mod(uint8_t x, uint8_t y, uint8_t m)
{
	return (x + y) & (m - 1);
}

static inline uint8_t sub_mod(uint8_t x, uint8_t y, uint8_t m)
{
	return (x - y) & (m - 1); /* handle negative results correctly */
}

static void lapd_dl_flush_send(struct lapd_datalink *dl)
{
	struct msgb *msg;

	/* Flush send-queue */
	while ((msg = msgb_dequeue(&dl->send_queue)))
		msgb_free(msg);

	/* Clear send-buffer */
	msgb_free(dl->send_buffer);
	dl->send_buffer = NULL;
}

static void lapd_dl_flush_hist(struct lapd_datalink *dl)
{
	unsigned int i;

	if (!dl->range_hist || !dl->tx_hist)
		return;

	for (i = 0; i < dl->range_hist; i++) {
		if (dl->tx_hist[i].msg) {
			msgb_free(dl->tx_hist[i].msg);
			dl->tx_hist[i].msg = NULL;
		}
	}
}

static void lapd_dl_flush_tx_queue(struct lapd_datalink *dl)
{
	struct msgb *msg;

	while ((msg = msgb_dequeue(&dl->tx_queue)))
		msgb_free(msg);
}

static void lapd_dl_flush_tx(struct lapd_datalink *dl)
{
	lapd_dl_flush_tx_queue(dl);
	lapd_dl_flush_hist(dl);
}

/* Figure B.2/Q.921 */
const struct value_string lapd_state_names[] = {
	OSMO_VALUE_STRING(LAPD_STATE_NULL),
	OSMO_VALUE_STRING(LAPD_STATE_TEI_UNASS),
	OSMO_VALUE_STRING(LAPD_STATE_ASS_TEI_WAIT),
	OSMO_VALUE_STRING(LAPD_STATE_EST_TEI_WAIT),
	OSMO_VALUE_STRING(LAPD_STATE_IDLE),
	OSMO_VALUE_STRING(LAPD_STATE_SABM_SENT),
	OSMO_VALUE_STRING(LAPD_STATE_DISC_SENT),
	OSMO_VALUE_STRING(LAPD_STATE_MF_EST),
	OSMO_VALUE_STRING(LAPD_STATE_TIMER_RECOV),
	{ 0, NULL }
};

static inline const char *lapd_state_name(enum lapd_state state)
{
	return get_value_string(lapd_state_names, state);
}

static void lapd_start_t200(struct lapd_datalink *dl)
{
	if ((dl->lapd_flags & LAPD_F_RTS)) {
		if (dl->t200_rts != LAPD_T200_RTS_OFF)
			return;
		LOGDL(dl, LOGL_INFO, "Start T200. (pending until triggered by RTS)\n");
		dl->t200_rts = LAPD_T200_RTS_PENDING;
	} else {
		if (osmo_timer_pending(&dl->t200))
			return;
		LOGDL(dl, LOGL_INFO, "Start T200 (timeout=%d.%06ds).\n", dl->t200_sec, dl->t200_usec);
		osmo_timer_schedule(&dl->t200, dl->t200_sec, dl->t200_usec);
	}
}

/*! Handle timeout condition of T200 in RTS mode.
 * The caller (LAPDm code) implements the T200 timer and must detect timeout condition.
 * The function gets called by LAPDm code when it detects a timeout of T200.
 *  \param[in] dl caller-allocated datalink structure */
int lapd_t200_timeout(struct lapd_datalink *dl)
{
	OSMO_ASSERT((dl->lapd_flags & LAPD_F_RTS));

	if (dl->t200_rts != LAPD_T200_RTS_RUNNING)
		return -EINVAL;

	dl->t200_rts = LAPD_T200_RTS_OFF;

	lapd_t200_cb(dl);

	return 0;
}

static void lapd_start_t203(struct lapd_datalink *dl)
{
	if (osmo_timer_pending(&dl->t203))
		return;
	LOGDL(dl, LOGL_INFO, "start T203\n");
	osmo_timer_schedule(&dl->t203, dl->t203_sec, dl->t203_usec);
}

static void lapd_stop_t200(struct lapd_datalink *dl)
{
	if ((dl->lapd_flags & LAPD_F_RTS)) {
		if (dl->t200_rts == LAPD_T200_RTS_OFF)
			return;
		dl->t200_rts = LAPD_T200_RTS_OFF;
	} else {
		if (!osmo_timer_pending(&dl->t200))
			return;
		osmo_timer_del(&dl->t200);
	}
	LOGDL(dl, LOGL_INFO, "stop T200\n");
}

static bool lapd_is_t200_started(struct lapd_datalink *dl)
{
	if ((dl->lapd_flags & LAPD_F_RTS))
		return (dl->t200_rts != LAPD_T200_RTS_OFF);
	else
		return osmo_timer_pending(&dl->t200);
}

static void lapd_stop_t203(struct lapd_datalink *dl)
{
	if (!osmo_timer_pending(&dl->t203))
		return;
	LOGDL(dl, LOGL_INFO, "stop T203\n");
	osmo_timer_del(&dl->t203);
}

static void lapd_dl_newstate(struct lapd_datalink *dl, uint32_t state)
{
	LOGDL(dl, LOGL_INFO, "new state %s -> %s\n",
		lapd_state_name(dl->state), lapd_state_name(state));

	if (state != LAPD_STATE_MF_EST && dl->state == LAPD_STATE_MF_EST) {
		/* stop T203 on leaving MF EST state, if running */
		lapd_stop_t203(dl);
		/* remove content res. (network side) on leaving MF EST state */
		msgb_free(dl->cont_res);
		dl->cont_res = NULL;
	}

	/* start T203 on entering MF EST state, if enabled */
	if ((dl->t203_sec || dl->t203_usec)
	 && state == LAPD_STATE_MF_EST && dl->state != LAPD_STATE_MF_EST)
		lapd_start_t203(dl);

	dl->state = state;
}

void *tall_lapd_ctx = NULL;

/*! Initialize LAPD datalink instance and allocate history
 *  \param[in] dl caller-allocated datalink structure
 *  \param[in] k maximum number of unacknowledged frames
 *  \param[in] v_range range of sequence numbers
 *  \param[in] maxf maximum frame size (after defragmentation)
 *  \param[in] name human-readable name for this LAPD datalink */
void lapd_dl_init2(struct lapd_datalink *dl, uint8_t k, uint8_t v_range, int maxf,
		   const char *name)
{
	int m;

	memset(dl, 0, sizeof(*dl));
	INIT_LLIST_HEAD(&dl->send_queue);
	INIT_LLIST_HEAD(&dl->tx_queue);
	dl->reestablish = 1;
	dl->n200_est_rel = 3;
	dl->n200 = 3;
	dl->t200_sec = 1;
	dl->t200_usec = 0;
	osmo_timer_setup(&dl->t200, lapd_t200_cb, dl);
	dl->t203_sec = 10;
	dl->t203_usec = 0;
	osmo_timer_setup(&dl->t203, lapd_t203_cb, dl);
	dl->maxf = maxf;
	if (k > v_range - 1)
		k = v_range - 1;
	dl->k = k;
	dl->v_range = v_range;

	/* Calculate modulo for history array:
	 * - The history range must be at least k+1.
	 * - The history range must be 2^x, where x is as low as possible.
	 */
	k++;
	for (m = 0x80; m; m >>= 1) {
		if ((m & k)) {
			if (k > m)
				m <<= 1;
			dl->range_hist = m;
			break;
		}
	}

	if (!tall_lapd_ctx) {
		tall_lapd_ctx = talloc_named_const(NULL, 1, "lapd context");
		OSMO_ASSERT(tall_lapd_ctx);
	}

	talloc_free(dl->name);
	if (name)
		dl->name = talloc_strdup(tall_lapd_ctx, name);
	else
		dl->name = talloc_asprintf(tall_lapd_ctx, "dl=%p", dl);

	LOGDL(dl, LOGL_INFO, "Init DL layer: sequence range = %d, k = %d, "
		"history range = %d\n", dl->v_range, dl->k, dl->range_hist);

	lapd_dl_newstate(dl, LAPD_STATE_IDLE);

	dl->tx_hist = talloc_zero_array(tall_lapd_ctx,
					struct lapd_history, dl->range_hist);
}

/*! Initialize LAPD datalink instance and allocate history
 *  \param[in] dl caller-allocated datalink structure
 *  \param[in] k maximum number of unacknowledged frames
 *  \param[in] v_range range of sequence numbers
 *  \param[in] maxf maximum frame size (after defragmentation) */
void lapd_dl_init(struct lapd_datalink *dl, uint8_t k, uint8_t v_range, int maxf)
{
	lapd_dl_init2(dl, k, v_range, maxf, NULL);
}

void lapd_dl_set_name(struct lapd_datalink *dl, const char *name)
{
	if (!name)
		return;
	osmo_talloc_replace_string(tall_lapd_ctx, &dl->name, name);
}

/* reset to IDLE state */
void lapd_dl_reset(struct lapd_datalink *dl)
{
	LOGDL(dl, LOGL_INFO, "Resetting LAPD instance\n");
	/* enter idle state (and remove eventual cont_res) */
	lapd_dl_newstate(dl, LAPD_STATE_IDLE);
	/* flush buffer */
	lapd_dl_flush_tx(dl);
	lapd_dl_flush_send(dl);
	/* Discard partly received L3 message */
	msgb_free(dl->rcv_buffer);
	dl->rcv_buffer = NULL;
	/* stop Timers */
	lapd_stop_t200(dl);
	lapd_stop_t203(dl);
	if (dl->state == LAPD_STATE_IDLE)
		return;
	/* enter idle state (and remove eventual cont_res) */
	lapd_dl_newstate(dl, LAPD_STATE_IDLE);
}

/*! Set lapd_flags to change behaviour
 *  \param[in] dl \ref lapd_datalink instance
 *  \param[in] flags \ref lapd_flags */
int lapd_dl_set_flags(struct lapd_datalink *dl, unsigned int flags)
{
	if (lapd_is_t200_started(dl) && (flags & LAPD_F_RTS) != (dl->lapd_flags & LAPD_F_RTS)) {
		LOGDL(dl, LOGL_ERROR, "Changing RTS flag not allowed while T200 is running.\n");
		return -EINVAL;
	}

	dl->lapd_flags = flags;

	return 0;
}

/* reset and de-allocate history buffer */
void lapd_dl_exit(struct lapd_datalink *dl)
{
	/* free all ressources except history buffer */
	lapd_dl_reset(dl);

	/* enter null state */
	lapd_dl_newstate(dl, LAPD_STATE_NULL);

	/* free history buffer list */
	talloc_free(dl->tx_hist);
	dl->tx_hist = NULL;
	talloc_free(dl->name);
	dl->name = NULL;
}

/*! Set the \ref lapdm_mode of a LAPDm entity */
int lapd_set_mode(struct lapd_datalink *dl, enum lapd_mode mode)
{
	switch (mode) {
	case LAPD_MODE_USER:
		dl->cr.loc2rem.cmd = CR_USER2NET_CMD;
		dl->cr.loc2rem.resp = CR_USER2NET_RESP;
		dl->cr.rem2loc.cmd = CR_NET2USER_CMD;
		dl->cr.rem2loc.resp = CR_NET2USER_RESP;
		break;
	case LAPD_MODE_NETWORK:
		dl->cr.loc2rem.cmd = CR_NET2USER_CMD;
		dl->cr.loc2rem.resp = CR_NET2USER_RESP;
		dl->cr.rem2loc.cmd = CR_USER2NET_CMD;
		dl->cr.rem2loc.resp = CR_USER2NET_RESP;
		break;
	default:
		return -EINVAL;
	}
	dl->mode = mode;

	return 0;
}

/* send DL message with optional msgb */
static int send_dl_l3(uint8_t prim, uint8_t op, struct lapd_msg_ctx *lctx,
	struct msgb *msg)
{
	struct lapd_datalink *dl = lctx->dl;
	struct osmo_dlsap_prim dp;

	osmo_prim_init(&dp.oph, 0, prim, op, msg);
	return dl->send_dlsap(&dp, lctx);
}

/* send simple DL message */
static inline int send_dl_simple(uint8_t prim, uint8_t op,
	struct lapd_msg_ctx *lctx)
{
	return send_dl_l3(prim, op, lctx, NULL);
}

/* send MDL-ERROR INDICATION */
static int mdl_error(uint8_t cause, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	struct osmo_dlsap_prim dp;

	LOGDL(dl, LOGL_NOTICE,
	     "sending MDL-ERROR-IND cause %d from state %s\n",
	     cause, lapd_state_name(dl->state));
	osmo_prim_init(&dp.oph, 0, PRIM_MDL_ERROR, PRIM_OP_INDICATION, NULL);
	dp.u.error_ind.cause = cause;
	return dl->send_dlsap(&dp, lctx);
}

/* send UA response */
static int lapd_send_ua(struct lapd_msg_ctx *lctx, uint8_t len, uint8_t *data)
{
	struct msgb *msg = lapd_msgb_alloc(len, "LAPD UA");
	struct lapd_msg_ctx nctx;
	struct lapd_datalink *dl = lctx->dl;

	memcpy(&nctx, lctx, sizeof(nctx));
	msg->l3h = msgb_put(msg, len);
	if (len)
		memcpy(msg->l3h, data, len);
	/* keep nctx.ldp */
	/* keep nctx.sapi */
	/* keep nctx.tei */
	nctx.cr = dl->cr.loc2rem.resp;
	nctx.format = LAPD_FORM_U;
	nctx.s_u = LAPD_U_UA;
	/* keep nctx.p_f */
	nctx.length = len;
	nctx.more = 0;

	return dl->send_ph_data_req(&nctx, msg);
}

/* send DM response */
static int lapd_send_dm(struct lapd_msg_ctx *lctx)
{
	struct msgb *msg = lapd_msgb_alloc(0, "LAPD DM");
	struct lapd_msg_ctx nctx;
	struct lapd_datalink *dl = lctx->dl;

	memcpy(&nctx, lctx, sizeof(nctx));
	/* keep nctx.ldp */
	/* keep nctx.sapi */
	/* keep nctx.tei */
	nctx.cr = dl->cr.loc2rem.resp;
	nctx.format = LAPD_FORM_U;
	nctx.s_u = LAPD_U_DM;
	/* keep nctx.p_f */
	nctx.length = 0;
	nctx.more = 0;

	return dl->send_ph_data_req(&nctx, msg);
}

/* send RR response / command */
static int lapd_send_rr(struct lapd_msg_ctx *lctx, uint8_t f_bit, uint8_t cmd)
{
	struct msgb *msg = lapd_msgb_alloc(0, "LAPD RR");
	struct lapd_msg_ctx nctx;
	struct lapd_datalink *dl = lctx->dl;

	memcpy(&nctx, lctx, sizeof(nctx));
	/* keep nctx.ldp */
	/* keep nctx.sapi */
	/* keep nctx.tei */
	nctx.cr = (cmd) ? dl->cr.loc2rem.cmd : dl->cr.loc2rem.resp;
	nctx.format = LAPD_FORM_S;
	nctx.s_u = LAPD_S_RR;
	nctx.p_f = f_bit;
	nctx.n_recv = dl->v_recv;
	nctx.length = 0;
	nctx.more = 0;

	return dl->send_ph_data_req(&nctx, msg);
}

/* send RNR response / command */
static int lapd_send_rnr(struct lapd_msg_ctx *lctx, uint8_t f_bit, uint8_t cmd)
{
	struct msgb *msg = lapd_msgb_alloc(0, "LAPD RNR");
	struct lapd_msg_ctx nctx;
	struct lapd_datalink *dl = lctx->dl;

	memcpy(&nctx, lctx, sizeof(nctx));
	/* keep nctx.ldp */
	/* keep nctx.sapi */
	/* keep nctx.tei */
	nctx.cr = (cmd) ? dl->cr.loc2rem.cmd : dl->cr.loc2rem.resp;
	nctx.format = LAPD_FORM_S;
	nctx.s_u = LAPD_S_RNR;
	nctx.p_f = f_bit;
	nctx.n_recv = dl->v_recv;
	nctx.length = 0;
	nctx.more = 0;

	return dl->send_ph_data_req(&nctx, msg);
}

/* send REJ response */
static int lapd_send_rej(struct lapd_msg_ctx *lctx, uint8_t f_bit)
{
	struct msgb *msg = lapd_msgb_alloc(0, "LAPD REJ");
	struct lapd_msg_ctx nctx;
	struct lapd_datalink *dl = lctx->dl;

	memcpy(&nctx, lctx, sizeof(nctx));
	/* keep nctx.ldp */
	/* keep nctx.sapi */
	/* keep nctx.tei */
	nctx.cr = dl->cr.loc2rem.resp;
	nctx.format = LAPD_FORM_S;
	nctx.s_u = LAPD_S_REJ;
	nctx.p_f = f_bit;
	nctx.n_recv = dl->v_recv;
	nctx.length = 0;
	nctx.more = 0;

	return dl->send_ph_data_req(&nctx, msg);
}

/* resend SABM or DISC message */
static int lapd_send_resend(struct lapd_datalink *dl)
{
	struct msgb *msg;
	uint8_t h = do_mod(dl->v_send, dl->range_hist);
	int length = dl->tx_hist[h].msg->len;
	struct lapd_msg_ctx nctx;

	/* assemble message */
	memcpy(&nctx, &dl->lctx, sizeof(nctx));
	/* keep nctx.ldp */
	/* keep nctx.sapi */
	/* keep nctx.tei */
	nctx.cr = dl->cr.loc2rem.cmd;
	nctx.format = LAPD_FORM_U;
	if (dl->state == LAPD_STATE_SABM_SENT)
		nctx.s_u = (dl->use_sabme) ? LAPD_U_SABME : LAPD_U_SABM;
	else
		nctx.s_u = LAPD_U_DISC;
	nctx.p_f = 1;
	nctx.length = length;
	nctx.more = 0;

	/* Resend SABM/DISC from tx_hist */
	msg = lapd_msgb_alloc(length, "LAPD resend");
	msg->l3h = msgb_put(msg, length);
	if (length)
		memcpy(msg->l3h, dl->tx_hist[h].msg->data, length);

	return dl->send_ph_data_req(&nctx, msg);
}

/* reestablish link */
static int lapd_reestablish(struct lapd_datalink *dl)
{
	struct osmo_dlsap_prim dp;
	struct msgb *msg;

	LOGDL(dl, LOGL_DEBUG, "LAPD reestablish\n");

	msg = lapd_msgb_alloc(0, "DUMMY");
	osmo_prim_init(&dp.oph, 0, PRIM_DL_EST, PRIM_OP_REQUEST, msg);

	return lapd_est_req(&dp, &dl->lctx);
}

/* Timer callback on T200 expiry */
static void lapd_t200_cb(void *data)
{
	struct lapd_datalink *dl = data;

	LOGDL(dl, LOGL_INFO, "Timeout T200 state=%s\n", lapd_state_name(dl->state));

	switch (dl->state) {
	case LAPD_STATE_SABM_SENT:
		/* 5.4.1.3 */
		/* increment re-transmission counter */
		dl->retrans_ctr++;
		if (dl->retrans_ctr >= dl->n200_est_rel + 1) {
			/* flush tx and send buffers */
			lapd_dl_flush_tx(dl);
			lapd_dl_flush_send(dl);
			/* go back to idle state */
			lapd_dl_newstate(dl, LAPD_STATE_IDLE);
			/* NOTE: we must not change any other states or buffers
			 * and queues, since we may reconnect after handover
			 * failure. the buffered messages is replaced there */
			/* send MDL ERROR INIDCATION to L3 */
			mdl_error(MDL_CAUSE_T200_EXPIRED, &dl->lctx);
			/* send RELEASE INDICATION to L3 */
			send_dl_simple(PRIM_DL_REL, PRIM_OP_INDICATION,
				&dl->lctx);
			break;
		}
		/* retransmit SABM command */
		lapd_send_resend(dl);
		/* restart T200 (PH-READY-TO-SEND) */
		lapd_start_t200(dl);
		break;
	case LAPD_STATE_DISC_SENT:
		/* 5.4.4.3 */
		/* increment re-transmission counter */
		dl->retrans_ctr++;
		if (dl->retrans_ctr >= dl->n200_est_rel + 1) {
			/* send MDL ERROR INIDCATION to L3 */
			mdl_error(MDL_CAUSE_T200_EXPIRED, &dl->lctx);
			/* flush tx and send buffers */
			lapd_dl_flush_tx(dl);
			lapd_dl_flush_send(dl);
			/* go back to idle state */
			lapd_dl_newstate(dl, LAPD_STATE_IDLE);
			/* NOTE: we must not change any other states or buffers
			 * and queues, since we may reconnect after handover
			 * failure. the buffered messages is replaced there */
			/* send RELEASE INDICATION to L3 */
			send_dl_simple(PRIM_DL_REL, PRIM_OP_CONFIRM, &dl->lctx);
			break;
		}
		/* retransmit DISC command */
		lapd_send_resend(dl);
		/* restart T200 (PH-READY-TO-SEND) */
		lapd_start_t200(dl);
		break;
	case LAPD_STATE_MF_EST:
		/* 5.5.7 */
		dl->retrans_ctr = 0;
		lapd_dl_newstate(dl, LAPD_STATE_TIMER_RECOV);
		/* fall through */
	case LAPD_STATE_TIMER_RECOV:
		dl->retrans_ctr++;
		if (dl->retrans_ctr <= dl->n200) {
			uint8_t vs = sub_mod(dl->v_send, 1, dl->v_range);
			uint8_t h = do_mod(vs, dl->range_hist);
			/* retransmit I frame (V_s-1) with P=1, if any */
			if (dl->tx_hist[h].msg) {
				struct msgb *msg;
				int length = dl->tx_hist[h].msg->len;
				struct lapd_msg_ctx nctx;

				LOGDL(dl, LOGL_INFO, "retransmit last frame V(S)=%d\n", vs);
				/* Create I frame (segment) from tx_hist */
				memcpy(&nctx, &dl->lctx, sizeof(nctx));
				/* keep nctx.ldp */
				/* keep nctx.sapi */
				/* keep nctx.tei */
				nctx.cr = dl->cr.loc2rem.cmd;
				nctx.format = LAPD_FORM_I;
				nctx.p_f = 1;
				nctx.n_send = vs;
				nctx.n_recv = dl->v_recv;
				nctx.length = length;
				nctx.more = dl->tx_hist[h].more;
				msg = lapd_msgb_alloc(length, "LAPD I resend");
				msg->l3h = msgb_put(msg, length);
				memcpy(msg->l3h, dl->tx_hist[h].msg->data,
					length);
				dl->send_ph_data_req(&nctx, msg);
			} else {
			/* OR send appropriate supervision frame with P=1 */
				if (!dl->own_busy && !dl->seq_err_cond) {
					lapd_send_rr(&dl->lctx, 1, 1);
					/* NOTE: In case of sequence error
					 * condition, the REJ frame has been
					 * transmitted when entering the
					 * condition, so it has not be done
					 * here
				 	 */
				} else if (dl->own_busy) {
					lapd_send_rnr(&dl->lctx, 1, 1);
				} else {
					LOGDL(dl, LOGL_INFO, "unhandled, pls. fix\n");
				}
			}
			/* restart T200 (PH-READY-TO-SEND) */
			lapd_start_t200(dl);
		} else {
			/* send MDL ERROR INIDCATION to L3 */
			mdl_error(MDL_CAUSE_T200_EXPIRED, &dl->lctx);
			/* reestablish */
			if (!dl->reestablish)
				break;
			LOGDL(dl, LOGL_NOTICE, "N200+1 reached, performingreestablishment\n");
			lapd_reestablish(dl);
		}
		break;
	default:
		LOGDL(dl, LOGL_INFO, "T200 expired in unexpected dl->state %s)\n",
			lapd_state_name(dl->state));
	}
}

/* Timer callback on T203 expiry */
static void lapd_t203_cb(void *data)
{
	struct lapd_datalink *dl = data;

	LOGDL(dl, LOGL_INFO, "Timeout T203 state=%s\n", lapd_state_name(dl->state));

	if (dl->state != LAPD_STATE_MF_EST) {
		LOGDL(dl, LOGL_ERROR, "T203 fired outside MF EST state, please fix!\n");
		return;
	}

	/* set retransmission counter to 0 */
	dl->retrans_ctr = 0;
	/* enter timer recovery state */
	lapd_dl_newstate(dl, LAPD_STATE_TIMER_RECOV);
	/* transmit a supervisory command with P bit set to 1 as follows: */
	if (!dl->own_busy) {
		LOGDL(dl, LOGL_INFO, "transmit an RR poll command\n");
		/* Send RR with P=1 */
		lapd_send_rr(&dl->lctx, 1, 1);
	} else {
		LOGDL(dl, LOGL_INFO, "transmit an RNR poll command\n");
		/* Send RNR with P=1 */
		lapd_send_rnr(&dl->lctx, 1, 1);
	}
	/* start T200 */
	lapd_start_t200(dl);
}

/* 5.5.3.1: Common function to acknowlege frames up to the given N(R) value
 * In case of a sequence error, the cause is returned with negative sign. */
static int lapd_acknowledge(struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	uint8_t nr = lctx->n_recv;
	int s = 0, rej = 0;
	bool t200_reset = false;
	int i, h;

	/* supervisory frame ? */
	if (lctx->format == LAPD_FORM_S)
		s = 1;
	/* REJ frame ? */
	if (s && lctx->s_u == LAPD_S_REJ)
	 	rej = 1;

	/* Flush all transmit buffers of acknowledged frames */
	for (i = dl->v_ack; i != nr; i = inc_mod(i, dl->v_range)) {
		h = do_mod(i, dl->range_hist);
		if (dl->tx_hist[h].msg) {
			msgb_free(dl->tx_hist[h].msg);
			dl->tx_hist[h].msg = NULL;
			LOGDL(dl, LOGL_INFO, "ack frame %d\n", i);
		}
	}

	if (dl->state != LAPD_STATE_TIMER_RECOV) {
		/* When not in the timer recovery condition, the data
		 * link layer entity shall reset the timer T200 on
		 * receipt of a valid I frame with N(R) higher than V(A),
		 * or an REJ with an N(R) equal to V(A). */
		if ((!rej && nr != dl->v_ack) || (rej && nr == dl->v_ack)) {
			t200_reset = true;
			lapd_stop_t200(dl);
			/* 5.5.3.1 Note 1 + 2 imply timer recovery cond. */
		}
		/* 5.7.4: N(R) sequence error
		 * N(R) is called valid, if and only if
		 * (N(R)-V(A)) mod 8 <= (V(S)-V(A)) mod 8.
		 */
		if (sub_mod(nr, dl->v_ack, dl->v_range) > sub_mod(dl->v_send, dl->v_ack, dl->v_range)) {
			LOGDL(dl, LOGL_NOTICE, "N(R) sequence error\n");
			return -MDL_CAUSE_SEQ_ERR;
		}
	}

	/* V(A) shall be set to the value of N(R) */
	dl->v_ack = nr;

	/* If T200 has been stopped by the receipt of an I, RR or RNR frame,
	 * and if there are outstanding I frames, restart T200 */
	if (t200_reset && !rej) {
		if (dl->tx_hist[sub_mod(dl->v_send, 1, dl->range_hist)].msg) {
			LOGDL(dl, LOGL_INFO, "start T200, due to unacked I frame(s)\n");
			lapd_start_t200(dl);
		}
	}

	/* This also does a restart, when I or S frame is received */

	/* Stop T203, if running */
	lapd_stop_t203(dl);
	/* Start T203, if T200 is not running in MF EST state, if enabled */
	if (!lapd_is_t200_started(dl) && (dl->t203_sec || dl->t203_usec) && (dl->state == LAPD_STATE_MF_EST))
		lapd_start_t203(dl);

	return 0;
}

/* L1 -> L2 */

/* Receive a LAPD U SABM(E) message from L1 */
static int lapd_rx_u_sabm(struct msgb *msg, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	int length = lctx->length;
	int rc = 0;
	uint8_t prim, op;

	prim = PRIM_DL_EST;
	op = PRIM_OP_INDICATION;

	LOGDL(dl, LOGL_INFO, "SABM(E) received in state %s\n", lapd_state_name(dl->state));
	/* 5.7.1 */
	dl->seq_err_cond = 0;
	/* G.2.2 Wrong value of the C/R bit */
	if (lctx->cr == dl->cr.rem2loc.resp) {
		LOGDL(dl, LOGL_ERROR, "SABM response error\n");
		msgb_free(msg);
		mdl_error(MDL_CAUSE_FRM_UNIMPL, lctx);
		return -EINVAL;
	}

	/* G.4.5 If SABM is received with L>N201 or with M bit
	 * set, AN MDL-ERROR-INDICATION is sent to MM.
	 */
	if (lctx->more || length > lctx->n201) {
		LOGDL(dl, LOGL_ERROR, "SABM too large error\n");
		msgb_free(msg);
		mdl_error(MDL_CAUSE_UFRM_INC_PARAM, lctx);
		return -EIO;
	}

	switch (dl->state) {
	case LAPD_STATE_IDLE:
		break;
	case LAPD_STATE_TIMER_RECOV:
		LOGDL(dl, LOGL_INFO, "SABM command, timer recovery state\n");
		/* If link is lost on the remote side, we start over
		* and send DL-ESTABLISH indication again. */
		/* 3GPP TS 44.006 8.6.3 "Procedures for re-establishment" */
		if (length) {
			/* check for contention resoultion */
			LOGDL(dl, LOGL_ERROR, "SABM L>0 not expected in timer "
			      "recovery state\n");
			mdl_error(MDL_CAUSE_SABM_INFO_NOTALL, lctx);
			lapd_send_dm(lctx);
			msgb_free(msg);
			return 0;
		}
		/* re-establishment, continue below */
		lapd_stop_t200(dl);
		break;
	case LAPD_STATE_MF_EST:
		LOGDL(dl, LOGL_INFO, "SABM command, multiple frame established state\n");
		/* If link is lost on the remote side, we start over
		 * and send DL-ESTABLISH indication again. */
		/* Additionally, continue in case of content resoltion
		 * (GSM network). This happens, if the mobile has not
		 * yet received UA or another mobile (collision) tries
		 * to establish connection. The mobile must receive
		 * UA again. */
		/* 5.4.2.1 */
		if (!length) {
			/* If no content resolution, this is a
			 * re-establishment. */
			LOGDL(dl, LOGL_INFO, "Remote reestablish\n");
			break;
		}
		if (!dl->cont_res) {
			LOGDL(dl, LOGL_INFO, "SABM command not allowed in state %s\n",
			      lapd_state_name(dl->state));
			mdl_error(MDL_CAUSE_SABM_MF, lctx);
			msgb_free(msg);
			return 0;
		}
		/* Ignore SABM if content differs from first SABM. */
		if (dl->mode == LAPD_MODE_NETWORK && length) {
#ifdef TEST_CONTENT_RESOLUTION_NETWORK
			dl->cont_res->data[0] ^= 0x01;
#endif
			if (memcmp(dl->cont_res->data, msg->data,
							length)) {
				LOGDL(dl, LOGL_INFO, "Another SABM with different content - "
				     "ignoring!\n");
				msgb_free(msg);
				return 0;
			}
		}
		/* send UA again */
		lapd_send_ua(lctx, length, msg->l3h);
		msgb_free(msg);
		return 0;
	case LAPD_STATE_DISC_SENT:
		/* 5.4.6.2 send DM with F=P */
		lapd_send_dm(lctx);
		/* stop Timer T200 */
		lapd_stop_t200(dl);
		msgb_free(msg);
		return send_dl_simple(prim, op, lctx);
	default:
		/* collision: Send UA, but still wait for rx UA, then
		 * change to MF_EST state.
		 */
		/* check for contention resoultion */
		if (dl->tx_hist[0].msg && dl->tx_hist[0].msg->len) {
			LOGDL(dl, LOGL_NOTICE, "SABM not allowed during contention "
			      "resolution (state=%s)\n", lapd_state_name(dl->state));
			mdl_error(MDL_CAUSE_SABM_INFO_NOTALL, lctx);
		}
		lapd_send_ua(lctx, length, msg->l3h);
		msgb_free(msg);
		return 0;
	}
	/* save message context for further use */
	memcpy(&dl->lctx, lctx, sizeof(dl->lctx));
#ifndef TEST_CONTENT_RESOLUTION_NETWORK
	/* send UA response */
	lapd_send_ua(lctx, length, msg->l3h);
#endif
	/* set Vs, Vr and Va to 0 */
	dl->v_send = dl->v_recv = dl->v_ack = 0;
	/* clear tx_hist */
	lapd_dl_flush_hist(dl);
	/* enter multiple-frame-established state */
	lapd_dl_newstate(dl, LAPD_STATE_MF_EST);
	/* store content resolution data on network side
	 * Note: cont_res will be removed when changing state again,
	 * so it must be allocated AFTER lapd_dl_newstate(). */
	if (dl->mode == LAPD_MODE_NETWORK && length) {
		dl->cont_res = lapd_msgb_alloc(length, "CONT RES");
		memcpy(msgb_put(dl->cont_res, length), msg->l3h,
			length);
		LOGDL(dl, LOGL_INFO, "Store content res.\n");
	}
	/* send notification to L3 */
	if (length == 0) {
		/* 5.4.1.2 Normal establishment procedures */
		rc = send_dl_simple(prim, op, lctx);
		msgb_free(msg);
	} else {
		/* 5.4.1.4 Contention resolution establishment */
		msgb_trim(msg, length);
		rc = send_dl_l3(prim, op, lctx, msg);
	}
	return rc;
}

/* Receive a LAPD U DM message from L1 */
static int lapd_rx_u_dm(struct msgb *msg, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	int rc = 0;

	LOGDL(dl, LOGL_INFO, "DM received in state %s\n", lapd_state_name(dl->state));
	/* G.2.2 Wrong value of the C/R bit */
	if (lctx->cr == dl->cr.rem2loc.cmd) {
		LOGDL(dl, LOGL_ERROR, "DM command error\n");
		msgb_free(msg);
		mdl_error(MDL_CAUSE_FRM_UNIMPL, lctx);
		return -EINVAL;
	}
	if (!lctx->p_f) {
		/* 5.4.1.2 DM responses with the F bit set to "0"
		 * shall be ignored.
		 */
		msgb_free(msg);
		return 0;
	}
	switch (dl->state) {
	case LAPD_STATE_SABM_SENT:
		break;
	case LAPD_STATE_MF_EST:
		if (lctx->p_f) {
			LOGDL(dl, LOGL_INFO, "unsolicited DM response\n");
			mdl_error(MDL_CAUSE_UNSOL_DM_RESP, lctx);
		} else {
			LOGDL(dl, LOGL_INFO, "unsolicited DM response, "
				"multiple frame established state\n");
			mdl_error(MDL_CAUSE_UNSOL_DM_RESP_MF, lctx);
			/* reestablish */
			if (!dl->reestablish) {
				msgb_free(msg);
				return 0;
			}
			LOGDL(dl, LOGL_NOTICE, "Performing reestablishment\n");
			lapd_reestablish(dl);
		}
		msgb_free(msg);
		return 0;
	case LAPD_STATE_TIMER_RECOV:
		/* FP = 0 (DM is normal in case PF = 1) */
		if (!lctx->p_f) {
			LOGDL(dl, LOGL_INFO, "unsolicited DM response, multiple frame "
			      "established state\n");
			mdl_error(MDL_CAUSE_UNSOL_DM_RESP_MF, lctx);
			msgb_free(msg);
			/* reestablish */
			if (!dl->reestablish)
				return 0;
			LOGDL(dl, LOGL_NOTICE, "Performing reestablishment\n");
			return lapd_reestablish(dl);
		}
		break;
	case LAPD_STATE_DISC_SENT:
		/* stop Timer T200 */
		lapd_stop_t200(dl);
		/* go to idle state */
		lapd_dl_flush_tx(dl);
		lapd_dl_flush_send(dl);
		lapd_dl_newstate(dl, LAPD_STATE_IDLE);
		rc = send_dl_simple(PRIM_DL_REL, PRIM_OP_CONFIRM, lctx);
		msgb_free(msg);
		return 0;
	case LAPD_STATE_IDLE:
		/* 5.4.5 all other frame types shall be discarded */
	default:
		LOGDL(dl, LOGL_INFO, "unsolicited DM response! (discarding)\n");
		msgb_free(msg);
		return 0;
	}
	/* stop timer T200 */
	lapd_stop_t200(dl);
	/* go to idle state */
	lapd_dl_newstate(dl, LAPD_STATE_IDLE);
	rc = send_dl_simple(PRIM_DL_REL, PRIM_OP_INDICATION, lctx);
	msgb_free(msg);
	return rc;
}

/* Receive a LAPD U UI message from L1 */
static int lapd_rx_u_ui(struct msgb *msg, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	int length = lctx->length;

	LOGDL(dl, LOGL_INFO, "UI received\n");
	/* G.2.2 Wrong value of the C/R bit */
	if (lctx->cr == dl->cr.rem2loc.resp) {
		LOGDL(dl, LOGL_ERROR, "UI indicates response error\n");
		msgb_free(msg);
		mdl_error(MDL_CAUSE_FRM_UNIMPL, lctx);
		return -EINVAL;
	}

	/* G.4.5 If UI is received with L>N201 or with M bit
	 * set, AN MDL-ERROR-INDICATION is sent to MM.
	 */
	if (length > lctx->n201 || lctx->more) {
		LOGDL(dl, LOGL_ERROR, "UI too large error (%d > N201(%d) or M=%d)\n",
		      length, lctx->n201, lctx->more);
		msgb_free(msg);
		mdl_error(MDL_CAUSE_UFRM_INC_PARAM, lctx);
		return -EIO;
	}

	/* do some length checks */
	if (length == 0) {
		/* 5.3.3 UI frames received with the length indicator
		 * set to "0" shall be ignored
		 */
		LOGDL(dl, LOGL_INFO, "length=0 (discarding)\n");
		msgb_free(msg);
		return 0;
	}
	msgb_trim(msg, length);
	return send_dl_l3(PRIM_DL_UNIT_DATA, PRIM_OP_INDICATION, lctx, msg);
}

/* Receive a LAPD U DISC message from L1 */
static int lapd_rx_u_disc(struct msgb *msg, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	int length = lctx->length;
	int rc = 0;
	uint8_t prim, op;

	prim = PRIM_DL_REL;
	op = PRIM_OP_INDICATION;

	LOGDL(dl, LOGL_INFO, "DISC received in state %s\n", lapd_state_name(dl->state));
	/* flush tx and send buffers */
	lapd_dl_flush_tx(dl);
	lapd_dl_flush_send(dl);
	/* 5.7.1 */
	dl->seq_err_cond = 0;
	/* G.2.2 Wrong value of the C/R bit */
	if (lctx->cr == dl->cr.rem2loc.resp) {
		LOGDL(dl, LOGL_ERROR, "DISC response error\n");
		msgb_free(msg);
		mdl_error(MDL_CAUSE_FRM_UNIMPL, lctx);
		return -EINVAL;
	}
	if (length > 0 || lctx->more) {
		/* G.4.4 If a DISC or DM frame is received with L>0 or
		 * with the M bit set to "1", an MDL-ERROR-INDICATION
		 * primitive with cause "U frame with incorrect
		 * parameters" is sent to the mobile management entity.
		 */
		LOGDL(dl, LOGL_ERROR, "U frame iwth incorrect parameters\n");
		msgb_free(msg);
		mdl_error(MDL_CAUSE_UFRM_INC_PARAM, lctx);
		return -EIO;
	}
	switch (dl->state) {
	case LAPD_STATE_IDLE:
		LOGDL(dl, LOGL_INFO, "DISC in idle state\n");
		/* send DM with F=P */
		msgb_free(msg);
		return lapd_send_dm(lctx);
	case LAPD_STATE_SABM_SENT:
		LOGDL(dl, LOGL_INFO, "DISC in SABM state\n");
		/* 5.4.6.2 send DM with F=P */
		lapd_send_dm(lctx);
		/* stop Timer T200 */
		lapd_stop_t200(dl);
		/* go to idle state */
		lapd_dl_newstate(dl, LAPD_STATE_IDLE);
		msgb_free(msg);
		return send_dl_simple(PRIM_DL_REL, PRIM_OP_INDICATION,
			lctx);
	case LAPD_STATE_MF_EST:
	case LAPD_STATE_TIMER_RECOV:
		LOGDL(dl, LOGL_INFO, "DISC in est state\n");
		break;
	case LAPD_STATE_DISC_SENT:
		LOGDL(dl, LOGL_INFO, "DISC in disc state\n");
		prim = PRIM_DL_REL;
		op = PRIM_OP_CONFIRM;
		break;
	default:
		lapd_send_ua(lctx, length, msg->l3h);
		msgb_free(msg);
		return 0;
	}
	/* send UA response */
	lapd_send_ua(lctx, length, msg->l3h);
	/* stop Timer T200 */
	lapd_stop_t200(dl);
	/* enter idle state, keep tx-buffer with UA response */
	lapd_dl_newstate(dl, LAPD_STATE_IDLE);
	/* send notification to L3 */
	rc = send_dl_simple(prim, op, lctx);
	msgb_free(msg);
	return rc;
}

/* Receive a LAPD U UA message from L1 */
static int lapd_rx_u_ua(struct msgb *msg, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	int length = lctx->length;
	int rc = 0;

	LOGDL(dl, LOGL_INFO, "UA received in state %s\n", lapd_state_name(dl->state));
	/* G.2.2 Wrong value of the C/R bit */
	if (lctx->cr == dl->cr.rem2loc.cmd) {
		LOGDL(dl, LOGL_ERROR, "UA indicates command error\n");
		msgb_free(msg);
		mdl_error(MDL_CAUSE_FRM_UNIMPL, lctx);
		return -EINVAL;
	}

	/* G.4.5 If UA is received with L>N201 or with M bit
	 * set, AN MDL-ERROR-INDICATION is sent to MM.
	 */
	if (lctx->more || length > lctx->n201) {
		LOGDL(dl, LOGL_ERROR, "UA too large error\n");
		msgb_free(msg);
		mdl_error(MDL_CAUSE_UFRM_INC_PARAM, lctx);
		return -EIO;
	}

	if (!lctx->p_f) {
		/* 5.4.1.2 A UA response with the F bit set to "0"
		 * shall be ignored.
		 */
		LOGDL(dl, LOGL_INFO, "F=0 (discarding)\n");
		msgb_free(msg);
		return 0;
	}
	switch (dl->state) {
	case LAPD_STATE_SABM_SENT:
		break;
	case LAPD_STATE_MF_EST:
	case LAPD_STATE_TIMER_RECOV:
		LOGDL(dl, LOGL_INFO, "unsolicited UA response! (discarding)\n");
		mdl_error(MDL_CAUSE_UNSOL_UA_RESP, lctx);
		msgb_free(msg);
		return 0;
	case LAPD_STATE_DISC_SENT:
		LOGDL(dl, LOGL_INFO, "UA in disconnect state\n");
		/* stop Timer T200 */
		lapd_stop_t200(dl);
		/* go to idle state */
		lapd_dl_flush_tx(dl);
		lapd_dl_flush_send(dl);
		lapd_dl_newstate(dl, LAPD_STATE_IDLE);
		rc = send_dl_simple(PRIM_DL_REL, PRIM_OP_CONFIRM, lctx);
		msgb_free(msg);
		return 0;
	case LAPD_STATE_IDLE:
		/* 5.4.5 all other frame types shall be discarded */
	default:
		LOGDL(dl, LOGL_INFO, "unsolicited UA response! (discarding)\n");
		msgb_free(msg);
		return 0;
	}
	LOGDL(dl, LOGL_INFO, "UA in SABM state\n");
	/* stop Timer T200 */
	lapd_stop_t200(dl);
	/* compare UA with SABME if contention resolution is applied */
	if (dl->tx_hist[0].msg->len) {
		if (length != (dl->tx_hist[0].msg->len)
		 || !!memcmp(dl->tx_hist[0].msg->data, msg->l3h,
							length)) {
			LOGDL(dl, LOGL_INFO, "**** UA response mismatches ****\n");
			/* go to idle state */
			lapd_dl_flush_tx(dl);
			lapd_dl_flush_send(dl);
			lapd_dl_newstate(dl, LAPD_STATE_IDLE);
			rc = send_dl_simple(PRIM_DL_REL, PRIM_OP_INDICATION, lctx);
			msgb_free(msg);
			return 0;
		}
	}
	/* set Vs, Vr and Va to 0 */
	dl->v_send = dl->v_recv = dl->v_ack = 0;
	/* clear tx_hist */
	lapd_dl_flush_hist(dl);
	/* enter multiple-frame-established state */
	lapd_dl_newstate(dl, LAPD_STATE_MF_EST);
	/* send outstanding frames, if any (resume / reconnect) */
	lapd_send_i(dl, __LINE__, false);
	/* send notification to L3 */
	rc = send_dl_simple(PRIM_DL_EST, PRIM_OP_CONFIRM, lctx);
	msgb_free(msg);
	return rc;
}

/* Receive a LAPD U FRMR message from L1 */
static int lapd_rx_u_frmr(struct msgb *msg, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;

	LOGDL(dl, LOGL_NOTICE, "Frame reject received\n");
	/* send MDL ERROR INIDCATION to L3 */
	mdl_error(MDL_CAUSE_FRMR, lctx);
	msgb_free(msg);
	/* reestablish */
	if (!dl->reestablish)
		return 0;
	LOGDL(dl, LOGL_NOTICE, "Performing reestablishment\n");
	return lapd_reestablish(dl);
}

/* Receive a LAPD U (Unnumbered) message from L1 */
static int lapd_rx_u(struct msgb *msg, struct lapd_msg_ctx *lctx)
{
	switch (lctx->s_u) {
	case LAPD_U_SABM:
	case LAPD_U_SABME:
		return lapd_rx_u_sabm(msg, lctx);
	case LAPD_U_DM:
		return lapd_rx_u_dm(msg, lctx);
	case LAPD_U_UI:
		return lapd_rx_u_ui(msg, lctx);
	case LAPD_U_DISC:
		return lapd_rx_u_disc(msg, lctx);
	case LAPD_U_UA:
		return lapd_rx_u_ua(msg, lctx);
	case LAPD_U_FRMR:
		return lapd_rx_u_frmr(msg, lctx);
	default:
		/* G.3.1 */
		LOGDL(lctx->dl, LOGL_NOTICE, "Unnumbered frame not allowed\n");
		msgb_free(msg);
		mdl_error(MDL_CAUSE_FRM_UNIMPL, lctx);
		return -EINVAL;
	}
}

/* Receive a LAPD S (Supervisory) message from L1 */
static int lapd_rx_s(struct msgb *msg, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	int length = lctx->length;

	if (length > 0 || lctx->more) {
		/* G.4.3 If a supervisory frame is received with L>0 or
		 * with the M bit set to "1", an MDL-ERROR-INDICATION
		 * primitive with cause "S frame with incorrect
		 * parameters" is sent to the mobile management entity. */
		LOGDL(dl, LOGL_ERROR, "S frame with incorrect parameters\n");
		msgb_free(msg);
		mdl_error(MDL_CAUSE_SFRM_INC_PARAM, lctx);
		return -EIO;
	}

	if (lctx->cr == dl->cr.rem2loc.resp
	 && lctx->p_f
	 && dl->state != LAPD_STATE_TIMER_RECOV) {
		/* 5.4.2.2: Inidcate error on supervisory reponse F=1 */
		LOGDL(dl,  LOGL_NOTICE, "S frame response with F=1 error\n");
		mdl_error(MDL_CAUSE_UNSOL_SPRV_RESP, lctx);
	}

	switch (dl->state) {
	case LAPD_STATE_IDLE:
		/* if P=1, respond DM with F=1 (5.2.2) */
		/* 5.4.5 all other frame types shall be discarded */
		if (lctx->p_f)
			lapd_send_dm(lctx); /* F=P */
		/* fall though */
	case LAPD_STATE_SABM_SENT:
	case LAPD_STATE_DISC_SENT:
		LOGDL(dl, LOGL_NOTICE, "S frame ignored in this state\n");
		msgb_free(msg);
		return 0;
	}
	switch (lctx->s_u) {
	case LAPD_S_RR:
		LOGDL(dl, LOGL_INFO, "RR received in state %s\n", lapd_state_name(dl->state));
		/* 5.5.3.1: Acknowlege all tx frames up the the N(R)-1 */
		lapd_acknowledge(lctx);

		/* 5.5.3.2 */
		if (lctx->cr == dl->cr.rem2loc.cmd
		 && lctx->p_f) {
		 	if (!dl->own_busy && !dl->seq_err_cond) {
				LOGDL(dl, LOGL_INFO, "RR frame command with polling bit set and "
				      "we are not busy, so we reply with RR frame response\n");
				lapd_send_rr(lctx, 1, 0);
				/* NOTE: In case of sequence error condition,
				 * the REJ frame has been transmitted when
				 * entering the condition, so it has not be
				 * done here
				 */
			} else if (dl->own_busy) {
				LOGDL(dl, LOGL_INFO, "RR frame command with polling bit set and "
				      "we are busy, so we reply with RR frame response\n");
				lapd_send_rnr(lctx, 1, 0);
			}
		} else if (lctx->cr == dl->cr.rem2loc.resp
			&& lctx->p_f
			&& dl->state == LAPD_STATE_TIMER_RECOV) {
			LOGDL(dl, LOGL_INFO, "RR response with F==1, and we are in timer recovery "
				"state, so we leave that state\n");
			/* V(S) to the N(R) in the RR frame */
			dl->v_send = lctx->n_recv;
			/* stop Timer T200 */
			lapd_stop_t200(dl);
			/* 5.5.7 Clear timer recovery condition */
			lapd_dl_newstate(dl, LAPD_STATE_MF_EST);
		}
		/* Send message, if possible due to acknowledged data */
		lapd_send_i(dl, __LINE__, false);

		break;
	case LAPD_S_RNR:
		LOGDL(dl, LOGL_INFO, "RNR received in state %s\n", lapd_state_name(dl->state));
		/* 5.5.3.1: Acknowlege all tx frames up the the N(R)-1 */
		lapd_acknowledge(lctx);

		/* 5.5.5 */
		/* Set peer receiver busy condition */
		dl->peer_busy = 1;
		/* Flush pending messages in TX queue. */
		lapd_dl_flush_tx_queue(dl);
		/* stop Timer T200 */
		lapd_stop_t200(dl);

		if (lctx->p_f) {
			if (lctx->cr == dl->cr.rem2loc.cmd) {
				if (!dl->own_busy) {
					LOGDL(dl, LOGL_INFO, "RNR poll command and we are not busy, "
					      "so we reply with RR final response\n");
					/* Send RR with F=1 */
					lapd_send_rr(lctx, 1, 0);
				} else {
					LOGDL(dl, LOGL_INFO, "RNR poll command and we are busy, so "
					      "we reply with RNR final response\n");
					/* Send RNR with F=1 */
					lapd_send_rnr(lctx, 1, 0);
				}
			} else if (dl->state == LAPD_STATE_TIMER_RECOV) {
				LOGDL(dl, LOGL_INFO, "RNR poll response and we in timer recovery "
				      "state, so we leave that state\n");
				/* 5.5.7 Clear timer recovery condition */
				lapd_dl_newstate(dl, LAPD_STATE_MF_EST);
				/* V(S) to the N(R) in the RNR frame */
				dl->v_send = lctx->n_recv;
			}
		} else
			LOGDL(dl, LOGL_INFO, "RNR not polling/final state received\n");

		/* Send message, if possible due to acknowledged data */
		lapd_send_i(dl, __LINE__, false);

		break;
	case LAPD_S_REJ:
		LOGDL(dl, LOGL_INFO, "REJ received in state %s\n", lapd_state_name(dl->state));
		/* 5.5.3.1: Acknowlege all tx frames up the the N(R)-1 */
		lapd_acknowledge(lctx);

		/* 5.5.4.1 */
		if (dl->state != LAPD_STATE_TIMER_RECOV) {
			/* Clear an existing peer receiver busy condition */
			dl->peer_busy = 0;
			/* V(S) and V(A) to the N(R) in the REJ frame */
			dl->v_send = dl->v_ack = lctx->n_recv;
			/* Flush pending messages in TX queue. */
			lapd_dl_flush_tx_queue(dl);
			/* stop Timer T200 */
			lapd_stop_t200(dl);
			/* 5.5.3.2 */
			if (lctx->cr == dl->cr.rem2loc.cmd && lctx->p_f) {
				if (!dl->own_busy && !dl->seq_err_cond) {
					LOGDL(dl, LOGL_INFO, "REJ poll command not in timer recovery "
					      "state and not in own busy condition received, so we "
					      "respond with RR final response\n");
					lapd_send_rr(lctx, 1, 0);
					/* NOTE: In case of sequence error
					 * condition, the REJ frame has been
					 * transmitted when entering the
					 * condition, so it has not be done
					 * here
				 	 */
				} else if (dl->own_busy) {
					LOGDL(dl, LOGL_INFO, "REJ poll command not in timer recovery "
					      "state and in own busy condition received, so we "
					      "respond with RNR final response\n");
					lapd_send_rnr(lctx, 1, 0);
				}
			} else
				LOGDL(dl, LOGL_INFO, "REJ response or not polling command not "
				      "in timer recovery state received\n");
			/* send MDL ERROR INIDCATION to L3 */
			if (lctx->cr == dl->cr.rem2loc.resp && lctx->p_f) {
				LOGDL(dl, LOGL_ERROR, "unsolicited supervisory response!\n");
				mdl_error(MDL_CAUSE_UNSOL_SPRV_RESP, lctx);
			}

		} else if (lctx->cr == dl->cr.rem2loc.resp && lctx->p_f) {
			LOGDL(dl, LOGL_INFO, "REJ poll response in timer recovery state received\n");
			/* Clear an existing peer receiver busy condition */
			dl->peer_busy = 0;
			/* V(S) and V(A) to the N(R) in the REJ frame */
			dl->v_send = dl->v_ack = lctx->n_recv;
			/* Flush pending messages in TX queue. */
			lapd_dl_flush_tx_queue(dl);
			/* stop Timer T200 */
			lapd_stop_t200(dl);
			/* 5.5.7 Clear timer recovery condition */
			lapd_dl_newstate(dl, LAPD_STATE_MF_EST);
		} else {
			/* Clear an existing peer receiver busy condition */
			dl->peer_busy = 0;
			/* V(S) and V(A) to the N(R) in the REJ frame */
			dl->v_send = dl->v_ack = lctx->n_recv;
			/* Flush pending messages in TX queue. */
			lapd_dl_flush_tx_queue(dl);
			/* 5.5.3.2 */
			if (lctx->cr == dl->cr.rem2loc.cmd && lctx->p_f) {
				if (!dl->own_busy && !dl->seq_err_cond) {
					LOGDL(dl, LOGL_INFO, "REJ poll command in timer recovery "
					      "state and not in own busy condition received, so we "
					      "respond with RR final response\n");
					lapd_send_rr(lctx, 1, 0);
					/* NOTE: In case of sequence error
					 * condition, the REJ frame has been
					 * transmitted when entering the
					 * condition, so it has not be done
					 * here
				 	 */
				} else if (dl->own_busy) {
					LOGDL(dl, LOGL_INFO, "REJ poll command in timer recovery "
					      "state and in own busy condition received, so we "
					      "respond with RNR final response\n");
					lapd_send_rnr(lctx, 1, 0);
				}
			} else
				LOGDL(dl, LOGL_INFO, "REJ response or not polling command in "
				      "timer recovery state received\n");
		}

		/* FIXME: 5.5.4.2 2) */

		/* Send message, if possible due to acknowledged data and new V(S) and V(A). */
		lapd_send_i(dl, __LINE__, false);

		break;
	default:
		/* G.3.1 */
		LOGDL(dl, LOGL_ERROR, "Supervisory frame not allowed\n");
		msgb_free(msg);
		mdl_error(MDL_CAUSE_FRM_UNIMPL, lctx);
		return -EINVAL;
	}
	msgb_free(msg);
	return 0;
}

/* Receive a LAPD I (Information) message from L1 */
static int lapd_rx_i(struct msgb *msg, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	//uint8_t nr = lctx->n_recv;
	uint8_t ns = lctx->n_send;
	int length = lctx->length;
	int rc;
	bool i_frame_in_queue = false;
	int mdl_cause = 0;

	LOGDL(dl, LOGL_INFO, "I received in state %s on SAPI(%u)\n",
	      lapd_state_name(dl->state), lctx->sapi);

	/* G.2.2 Wrong value of the C/R bit */
	if (lctx->cr == dl->cr.rem2loc.resp) {
		LOGDL(dl, LOGL_ERROR, "I frame response not allowed (state %s)\n",
		      lapd_state_name(dl->state));
		msgb_free(msg);
		mdl_error(MDL_CAUSE_FRM_UNIMPL, lctx);
		return -EINVAL;
	}

	if (length == 0 || length > lctx->n201) {
		/* G.4.2 If the length indicator of an I frame is set
		 * to a numerical value L>N201 or L=0, an MDL-ERROR-INDICATION
		 * primitive with cause "I frame with incorrect length"
		 * is sent to the mobile management entity. */
		LOGDL(dl, LOGL_ERROR, "I frame length not allowed (state %s)\n",
		      lapd_state_name(dl->state));
		msgb_free(msg);
		mdl_error(MDL_CAUSE_IFRM_INC_LEN, lctx);
		return -EIO;
	}

	/* G.4.2 If the numerical value of L is L<N201 and the M
	 * bit is set to "1", then an MDL-ERROR-INDICATION primitive with
	 * cause "I frame with incorrect use of M bit" is sent to the
	 * mobile management entity. */
	if (lctx->more && length < lctx->n201) {
		LOGDL(dl, LOGL_ERROR, "I frame with M bit too short (state %s)\n",
		      lapd_state_name(dl->state));
		msgb_free(msg);
		mdl_error(MDL_CAUSE_IFRM_INC_MBITS, lctx);
		return -EIO;
	}

	switch (dl->state) {
	case LAPD_STATE_IDLE:
		/* if P=1, respond DM with F=1 (5.2.2) */
		/* 5.4.5 all other frame types shall be discarded */
		if (lctx->p_f)
			lapd_send_dm(lctx); /* F=P */
		/* fall though */
	case LAPD_STATE_SABM_SENT:
	case LAPD_STATE_DISC_SENT:
		LOGDL(dl, LOGL_NOTICE, "I frame ignored in state %s\n", lapd_state_name(dl->state));
		msgb_free(msg);
		return 0;
	}

	/* 5.7.1: N(s) sequence error */
	if (ns != dl->v_recv) {
		LOGDL(dl, LOGL_NOTICE, "N(S) sequence error: N(S)=%u, V(R)=%u (state %s)\n",
		      ns, dl->v_recv, lapd_state_name(dl->state));
		/* discard data */
		msgb_free(msg);
		/* Send reject, but suppress second reject if LAPD_F_DROP_2ND_REJ flag is set. */
		if (dl->seq_err_cond != 1 || !(dl->lapd_flags & LAPD_F_DROP_2ND_REJ)) {
			dl->seq_err_cond = 1;
			lapd_send_rej(lctx, lctx->p_f);
		} else {
			/* If there are two subsequent sequence errors received,
			 * ignore it. (Ignore every second subsequent error.)
			 * This happens if our reply with the REJ is too slow,
			 * so the remote gets a T200 timeout and sends another
			 * frame with a sequence error.
			 * Test showed that replying with two subsequent REJ
			 * messages could the remote L2 process to abort.
			 * Replying too slow shouldn't happen, but may happen
			 * over serial link between BB and LAPD.
			 */
			dl->seq_err_cond = 2;
		}
		/* Even if N(s) sequence error, acknowledge to N(R)-1 */
		/* 5.5.3.1: Acknowlege all transmitted frames up the N(R)-1 */
		mdl_cause = lapd_acknowledge(lctx); /* V(A) is also set here */
		if (mdl_cause < 0)
			mdl_error(-mdl_cause, lctx);

		/* Send message, if possible due to acknowledged data */
		lapd_send_i(dl, __LINE__, false);

		return 0;
	}
	dl->seq_err_cond = 0;

	/* Increment receiver state */
	dl->v_recv = inc_mod(dl->v_recv, dl->v_range);
	LOGDL(dl, LOGL_INFO, "incrementing V(R) to %u\n", dl->v_recv);

	/* Update all pending frames in the queue to the new V(R) state. */
	if (dl->update_pending_frames) {
		rc = dl->update_pending_frames(lctx);
		if (!rc)
			i_frame_in_queue = true;
	}

	/* 5.5.3.1: Acknowlege all transmitted frames up the the N(R)-1 */
	mdl_cause = lapd_acknowledge(lctx); /* V(A) is also set here */

	/* Only if we are not in own receiver busy condition */
	if (!dl->own_busy) {
		/* if the frame carries a complete segment */
		if (!lctx->more && !dl->rcv_buffer) {
			LOGDL(dl, LOGL_INFO, "message in single I frame\n");
			/* send a DATA INDICATION to L3 */
			msgb_trim(msg, length);
			rc = send_dl_l3(PRIM_DL_DATA, PRIM_OP_INDICATION, lctx,
				msg);
		} else {
			/* create rcv_buffer */
			if (!dl->rcv_buffer) {
				LOGDL(dl, LOGL_INFO, "message in multiple I frames (first message)\n");
				dl->rcv_buffer = lapd_msgb_alloc(dl->maxf,
					"LAPD RX");
				dl->rcv_buffer->l3h = dl->rcv_buffer->data;
			}
			/* concat. rcv_buffer */
			if (msgb_l3len(dl->rcv_buffer) + length > dl->maxf) {
				LOGDL(dl, LOGL_NOTICE, "Received frame overflow!\n");
			} else {
				memcpy(msgb_put(dl->rcv_buffer, length),
					msg->l3h, length);
			}
			/* if the last segment was received */
			if (!lctx->more) {
				LOGDL(dl, LOGL_INFO, "message in multiple I frames (last message)\n");
				rc = send_dl_l3(PRIM_DL_DATA,
					PRIM_OP_INDICATION, lctx,
					dl->rcv_buffer);
				dl->rcv_buffer = NULL;
			} else
				LOGDL(dl, LOGL_INFO, "message in multiple I frames (next message)\n");
			msgb_free(msg);

		}
		/* the L3 or higher (called in-line above via send_dl_l3) might have destroyed the
		 * data link meanwhile. See OS#1761 */
		if (dl->state == LAPD_STATE_NULL)
			return 0;
	} else
		LOGDL(dl, LOGL_INFO, "I frame ignored during own receiver busy condition\n");

	/* Indicate sequence error, if exists. */
	if (mdl_cause < 0)
		mdl_error(-mdl_cause, lctx);

	/* Check for P bit */
	if (lctx->p_f) {
		/* 5.5.2.1 */
		/* check if we are not in own receiver busy */
		if (!dl->own_busy) {
			LOGDL(dl, LOGL_INFO, "we are not busy, send RR\n");
			/* Send RR with F=1 */
			rc = lapd_send_rr(lctx, 1, 0);
		} else {
			LOGDL(dl, LOGL_INFO, "we are busy, send RNR\n");
			/* Send RNR with F=1 */
			rc = lapd_send_rnr(lctx, 1, 0);
		}
	} else {
		/* 5.5.2.2 */
		/* check if we are not in own receiver busy */
		if (!dl->own_busy) {
			/* NOTE: V(R) is already set above */
			rc = lapd_send_i(dl, __LINE__, false);
			if (rc && !i_frame_in_queue) {
				LOGDL(dl, LOGL_INFO, "we are not busy and have no pending data, "
				      "send RR\n");
				/* Send RR with F=0 */
				return lapd_send_rr(lctx, 0, 0);
			}
			/* all I or one RR is sent, we are done */
			return 0;
		} else {
			LOGDL(dl, LOGL_INFO, "we are busy, send RNR\n");
			/* Send RNR with F=0 */
			rc = lapd_send_rnr(lctx, 0, 0);
		}
	}

	/* Send message, if possible due to acknowledged data */
	lapd_send_i(dl, __LINE__, false);

	return rc;
}

/* Receive a LAPD message from L1 */
int lapd_ph_data_ind(struct msgb *msg, struct lapd_msg_ctx *lctx)
{
	int rc;

	switch (lctx->format) {
	case LAPD_FORM_U:
		rc = lapd_rx_u(msg, lctx);
		break;
	case LAPD_FORM_S:
		rc = lapd_rx_s(msg, lctx);
		break;
	case LAPD_FORM_I:
		rc = lapd_rx_i(msg, lctx);
		break;
	default:
		LOGDL(lctx->dl, LOGL_NOTICE, "unknown LAPD format 0x%02x\n", lctx->format);
		msgb_free(msg);
		rc = -EINVAL;
	}
	return rc;
}

/*! Enqueue next LAPD frame and run pending T200. (Must be called when frame is ready to send.)
 * The caller (LAPDm code) calls this function before it sends the next frame.
 * If there is no frame in the TX queue, LAPD will enqueue next I-frame, if possible.
 * If the T200 is pending, it is changed to running state.
 *  \param[in] lctx LAPD context
 *  \param[out] rc set to 1, if timer T200 state changed to running, set to 0, if not. */
int lapd_ph_rts_ind(struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;

	/* If there is no pending frame, try to enqueue next I frame. */
	if (llist_empty(&dl->tx_queue) && (dl->state == LAPD_STATE_MF_EST || dl->state == LAPD_STATE_TIMER_RECOV)) {
		/* Send an I frame, if there are pending outgoing messages. */
		lapd_send_i(dl, __LINE__, true);
	}

	/* Run T200 at RTS, if pending. Tell caller that is has been started. (rc = 1) */
	if (dl->t200_rts == LAPD_T200_RTS_PENDING) {
		dl->t200_rts = LAPD_T200_RTS_RUNNING;
		return 1;
	}

	return 0;
}

/* L3 -> L2 */

/* send unit data */
static int lapd_udata_req(struct osmo_dlsap_prim *dp, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	struct msgb *msg = dp->oph.msg;
	struct lapd_msg_ctx nctx;

	memcpy(&nctx, lctx, sizeof(nctx));
	/* keep nctx.ldp */
	/* keep nctx.sapi */
	/* keep nctx.tei */
	nctx.cr = dl->cr.loc2rem.cmd;
	nctx.format = LAPD_FORM_U;
	nctx.s_u = LAPD_U_UI;
	/* keep nctx.p_f */
	nctx.length = msg->len;
	nctx.more = 0;

	return dl->send_ph_data_req(&nctx, msg);
}

static void msg_to_tx_hist(struct lapd_history *tx_hist, const struct msgb *msg, int length, int more)
{
	tx_hist->msg = lapd_msgb_alloc(msg->len, "HIST");
	tx_hist->more = more;
	msgb_put(tx_hist->msg, msg->len);
	if (length)
		memcpy(tx_hist->msg->data, msg->l3h, msg->len);
}

static void msg_to_tx_hist0(struct lapd_datalink *dl, const struct msgb *msg)
{
	return msg_to_tx_hist(&dl->tx_hist[0], msg, msg->len, 0);
}

/* request link establishment */
static int lapd_est_req(struct osmo_dlsap_prim *dp, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	struct msgb *msg = dp->oph.msg;
	struct lapd_msg_ctx nctx;

	if (msg->len)
		LOGDL(dl, LOGL_INFO, "perform establishment with content (SABM)\n");
	else
		LOGDL(dl, LOGL_INFO, "perform normal establishm. (SABM)\n");

	/* Flush send-queue */
	/* Clear send-buffer */
	lapd_dl_flush_send(dl);
	/* be sure that history is empty */
	lapd_dl_flush_hist(dl);

	/* save message context for further use */
	memcpy(&dl->lctx, lctx, sizeof(dl->lctx));

	/* Discard partly received L3 message */
	msgb_free(dl->rcv_buffer);
	dl->rcv_buffer = NULL;

	/* assemble message */
	memcpy(&nctx, &dl->lctx, sizeof(nctx));
	/* keep nctx.ldp */
	/* keep nctx.sapi */
	/* keep nctx.tei */
	nctx.cr = dl->cr.loc2rem.cmd;
	nctx.format = LAPD_FORM_U;
	nctx.s_u = (dl->use_sabme) ? LAPD_U_SABME : LAPD_U_SABM;
	nctx.p_f = 1;
	nctx.length = msg->len;
	nctx.more = 0;

	/* Transmit-buffer carries exactly one segment */
	msg_to_tx_hist0(dl, msg);

	/* set Vs to 0, because it is used as index when resending SABM */
	dl->v_send = 0;

	/* Set states */
	dl->own_busy = dl->peer_busy = 0;
	dl->retrans_ctr = 0;
	lapd_dl_newstate(dl, LAPD_STATE_SABM_SENT);

	/* Tramsmit and start T200 */
	dl->send_ph_data_req(&nctx, msg);
	lapd_start_t200(dl);

	return 0;
}

/* send data */
static int lapd_data_req(struct osmo_dlsap_prim *dp, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	struct msgb *msg = dp->oph.msg;

	if (msgb_l3len(msg) == 0) {
		LOGDL(dl, LOGL_ERROR, "writing an empty message is not possible\n");
		msgb_free(msg);
		return -1;
	}

	LOGDL(dl, LOGL_INFO, "writing message to send-queue: l3len: %d\n", msgb_l3len(msg));

	/* Take ownership of msg, since we are keeping it around in this layer: */
	talloc_steal(tall_lapd_ctx, msg);
	/* Write data into the send queue */
	msgb_enqueue(&dl->send_queue, msg);

	/* Send message, if possible */
	lapd_send_i(dl, __LINE__, false);

	return 0;
}

/* Send next I frame from queued/buffered data */
static int lapd_send_i(struct lapd_datalink *dl, int line, bool rts)
{
	struct lapd_msg_ctx *lctx = &dl->lctx;
	uint8_t k = dl->k;
	uint8_t h;
	struct msgb *msg;
	int length, left;
	int rc = - 1; /* we sent nothing */
	struct lapd_msg_ctx nctx;

	if (!rts)
		LOGDL(dl, LOGL_INFO, "%s() called from line %d\n", __func__, line);

	if ((dl->lapd_flags & LAPD_F_RTS) && !llist_empty(&dl->tx_queue)) {
		if (!rts)
			LOGDL(dl, LOGL_INFO, "There is a frame in the TX queue, not checking for sending I frame.\n");
		return rc;
	}

	next_frame:

	if (dl->peer_busy) {
		if (!rts)
			LOGDL(dl, LOGL_INFO, "Peer busy, not sending.\n");
		return rc;
	}

	if (dl->state == LAPD_STATE_TIMER_RECOV) {
		if (!rts)
			LOGDL(dl, LOGL_INFO, "Timer recovery, not sending.\n");
		return rc;
	}

	/* If the send state variable V(S) is equal to V(A) plus k
	 * (where k is the maximum number of outstanding I frames - see
	 * subclause 5.8.4), the data link layer entity shall not transmit any
	 * new I frames, but shall retransmit an I frame as a result
	 * of the error recovery procedures as described in subclauses 5.5.4 and
	 * 5.5.7. */
	if (dl->v_send == add_mod(dl->v_ack, k, dl->v_range)) {
		if (!rts)
			LOGDL(dl, LOGL_INFO, "k frames outstanding, not sending more. (k=%u V(S)=%u V(A)=%u)\n",
			      k, dl->v_send, dl->v_ack);
		return rc;
	}

	h = do_mod(dl->v_send, dl->range_hist);

	/* if we have no tx_hist yet, we create it */
	if (!dl->tx_hist[h].msg) {
		/* Get next message into send-buffer, if any */
		if (!dl->send_buffer) {
			next_message:
			dl->send_out = 0;
			dl->send_buffer = msgb_dequeue(&dl->send_queue);
			/* No more data to be sent */
			if (!dl->send_buffer)
				return rc;
			LOGDL(dl, LOGL_INFO, "get message from send-queue\n");
		}

		/* How much is left in the send-buffer? */
		left = msgb_l3len(dl->send_buffer) - dl->send_out;
		/* Segment, if data exceeds N201 */
		length = left;
		if (length > lctx->n201)
			length = lctx->n201;
		LOGDL(dl, LOGL_INFO, "msg-len %d sent %d left %d N201 %d length %d "
		      "first byte %02x\n", msgb_l3len(dl->send_buffer), dl->send_out, left,
		      lctx->n201, length, dl->send_buffer->l3h[0]);
		/* If message in send-buffer is completely sent */
		if (left == 0) {
			msgb_free(dl->send_buffer);
			dl->send_buffer = NULL;
			goto next_message;
		}

		LOGDL(dl, LOGL_INFO, "send I frame %sV(S)=%d\n",
		      (left > length) ? "segment " : "", dl->v_send);

		/* Create I frame (segment) and transmit-buffer content */
		msg = lapd_msgb_alloc(length, "LAPD I");
		msg->l3h = msgb_put(msg, length);
		/* assemble message */
		memcpy(&nctx, lctx, sizeof(nctx));
		/* keep nctx.ldp */
		/* keep nctx.sapi */
		/* keep nctx.tei */
		nctx.cr = dl->cr.loc2rem.cmd;
		nctx.format = LAPD_FORM_I;
		nctx.p_f = 0;
		nctx.n_send = dl->v_send;
		nctx.n_recv = dl->v_recv;
		nctx.length = length;
		if (left > length)
			nctx.more = 1;
		else
			nctx.more = 0;
		if (length)
			memcpy(msg->l3h, dl->send_buffer->l3h + dl->send_out,
				length);
		/* store in tx_hist */
		msg_to_tx_hist(&dl->tx_hist[h], msg, length, nctx.more);

		/* Add length to track how much is already in the tx buffer */
		dl->send_out += length;
	} else {
		LOGDL(dl, LOGL_INFO, "resend I frame from tx buffer V(S)=%d\n", dl->v_send);

		/* Create I frame (segment) from tx_hist */
		length = dl->tx_hist[h].msg->len;
		msg = lapd_msgb_alloc(length, "LAPD I resend");
		msg->l3h = msgb_put(msg, length);
		/* assemble message */
		memcpy(&nctx, lctx, sizeof(nctx));
		/* keep nctx.ldp */
		/* keep nctx.sapi */
		/* keep nctx.tei */
		nctx.cr = dl->cr.loc2rem.cmd;
		nctx.format = LAPD_FORM_I;
		nctx.p_f = 0;
		nctx.n_send = dl->v_send;
		nctx.n_recv = dl->v_recv;
		nctx.length = length;
		nctx.more = dl->tx_hist[h].more;
		if (length)
			memcpy(msg->l3h, dl->tx_hist[h].msg->data, length);
	}

	/* The value of the send state variable V(S) shall be incremented by 1
	 * at the end of the transmission of the I frame */
	dl->v_send = inc_mod(dl->v_send, dl->v_range);

	/* If timer T200 is not running at the time right before transmitting a
	 * frame, when the PH-READY-TO-SEND primitive is received from the
	 * physical layer., it shall be set. */
	if (!lapd_is_t200_started(dl)) {
		/* stop Timer T203, if running */
		lapd_stop_t203(dl);
		/* start Timer T200 */
		lapd_start_t200(dl);
	}

	dl->send_ph_data_req(&nctx, msg);

	/* When using RTS, we send only one frame. */
	if ((dl->lapd_flags & LAPD_F_RTS))
		return 0;

	rc = 0; /* We sent an I frame, so sending RR frame is not required. */
	goto next_frame;
}

/* request link suspension */
static int lapd_susp_req(struct osmo_dlsap_prim *dp, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	struct msgb *msg = dp->oph.msg;

	LOGDL(dl, LOGL_INFO, "perform suspension\n");

	/* put back the send-buffer to the send-queue (first position) */
	if (dl->send_buffer) {
		LOGDL(dl, LOGL_INFO, "put frame in sendbuffer back to queue\n");
		llist_add(&dl->send_buffer->list, &dl->send_queue);
		dl->send_buffer = NULL;
	} else
		LOGDL(dl, LOGL_INFO, "no frame in sendbuffer\n");

	/* Clear transmit buffer, but keep send buffer */
	lapd_dl_flush_tx(dl);
	/* Stop timers (there is no state change, so we must stop all timers */
	lapd_stop_t200(dl);
	lapd_stop_t203(dl);

	msgb_free(msg);

	return send_dl_simple(PRIM_DL_SUSP, PRIM_OP_CONFIRM, &dl->lctx);
}

/* request, resume or reconnect of link */
static int lapd_res_req(struct osmo_dlsap_prim *dp, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	struct msgb *msg = dp->oph.msg;
	struct lapd_msg_ctx nctx;

	LOGDL(dl, LOGL_INFO, "perform re-establishment (SABM) length=%d\n", msg->len);

	/* be sure that history is empty */
	lapd_dl_flush_hist(dl);

	/* save message context for further use */
	memcpy(&dl->lctx, lctx, sizeof(dl->lctx));

	/* Replace message in the send-buffer (reconnect) */
	msgb_free(dl->send_buffer);
	dl->send_buffer = NULL;

	dl->send_out = 0;
	if (msg->len) {
		/* Write data into the send buffer, to be sent first */
		dl->send_buffer = msg;
	} else {
		msgb_free(msg);
		msg = NULL;
		dl->send_buffer = NULL;
	}

	/* Discard partly received L3 message */
	msgb_free(dl->rcv_buffer);
	dl->rcv_buffer = NULL;

	/* Create new msgb (old one is now free) */
	msg = lapd_msgb_alloc(0, "LAPD SABM");
	msg->l3h = msg->data;
	/* assemble message */
	memcpy(&nctx, &dl->lctx, sizeof(nctx));
	/* keep nctx.ldp */
	/* keep nctx.sapi */
	/* keep nctx.tei */
	nctx.cr = dl->cr.loc2rem.cmd;
	nctx.format = LAPD_FORM_U;
	nctx.s_u = (dl->use_sabme) ? LAPD_U_SABME : LAPD_U_SABM;
	nctx.p_f = 1;
	nctx.length = 0;
	nctx.more = 0;

	msg_to_tx_hist0(dl, msg);

	/* set Vs to 0, because it is used as index when resending SABM */
	dl->v_send = 0;

	/* Set states */
	dl->own_busy = dl->peer_busy = 0;
	dl->retrans_ctr = 0;
	lapd_dl_newstate(dl, LAPD_STATE_SABM_SENT);

	/* Tramsmit and start T200 */
	dl->send_ph_data_req(&nctx, msg);
	lapd_start_t200(dl);

	return 0;
}

/* requesst release of link */
static int lapd_rel_req(struct osmo_dlsap_prim *dp, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	struct msgb *msg = dp->oph.msg;
	struct lapd_msg_ctx nctx;

	/* local release */
	if (dp->u.rel_req.mode) {
		LOGDL(dl, LOGL_INFO, "perform local release\n");
		msgb_free(msg);
		/* stop Timer T200 */
		lapd_stop_t200(dl);
		/* enter idle state, T203 is stopped here, if running */
		lapd_dl_newstate(dl, LAPD_STATE_IDLE);
		/* flush buffers */
		lapd_dl_flush_tx(dl);
		lapd_dl_flush_send(dl);
		/* send notification to L3 */
		return send_dl_simple(PRIM_DL_REL, PRIM_OP_CONFIRM, &dl->lctx);
	}

	/* in case we are already disconnecting */
	if (dl->state == LAPD_STATE_DISC_SENT)
		return -EBUSY;

	/* flush tx_hist */
	lapd_dl_flush_hist(dl);

	LOGDL(dl, LOGL_INFO, "perform normal release (DISC)\n");

	/* Push LAPD header on msgb */
	/* assemble message */
	memcpy(&nctx, &dl->lctx, sizeof(nctx));
	/* keep nctx.ldp */
	/* keep nctx.sapi */
	/* keep nctx.tei */
	nctx.cr = dl->cr.loc2rem.cmd;
	nctx.format = LAPD_FORM_U;
	nctx.s_u = LAPD_U_DISC;
	nctx.p_f = 1;
	nctx.length = 0;
	nctx.more = 0;

	msg_to_tx_hist0(dl, msg);

	/* set Vs to 0, because it is used as index when resending DISC */
	dl->v_send = 0;

	/* Set states */
	dl->own_busy = dl->peer_busy = 0;
	dl->retrans_ctr = 0;
	lapd_dl_newstate(dl, LAPD_STATE_DISC_SENT);

	/* Tramsmit and start T200 */
	dl->send_ph_data_req(&nctx, msg);
	lapd_start_t200(dl);

	return 0;
}

/* request release of link in idle state */
static int lapd_rel_req_idle(struct osmo_dlsap_prim *dp,
	struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	struct msgb *msg = dp->oph.msg;

	msgb_free(msg);

	/* send notification to L3 */
	return send_dl_simple(PRIM_DL_REL, PRIM_OP_CONFIRM, &dl->lctx);
}

/* statefull handling for DL SAP messages from L3 */
static const struct l2downstate {
	uint32_t	states;
	int		prim, op;
	const char 	*name;
	int		(*rout) (struct osmo_dlsap_prim *dp,
					struct lapd_msg_ctx *lctx);
} l2downstatelist[] = {
	/* create and send UI command */
	{ALL_STATES,
	 PRIM_DL_UNIT_DATA, PRIM_OP_REQUEST,
	 "DL-UNIT-DATA-REQUEST", lapd_udata_req},

	/* create and send SABM command */
	{SBIT(LAPD_STATE_IDLE),
	 PRIM_DL_EST, PRIM_OP_REQUEST,
	 "DL-ESTABLISH-REQUEST", lapd_est_req},

	/* create and send I command */
	{SBIT(LAPD_STATE_MF_EST) |
	 SBIT(LAPD_STATE_TIMER_RECOV),
	 PRIM_DL_DATA, PRIM_OP_REQUEST,
	 "DL-DATA-REQUEST", lapd_data_req},

	/* suspend datalink */
	{SBIT(LAPD_STATE_MF_EST) |
	 SBIT(LAPD_STATE_TIMER_RECOV),
	 PRIM_DL_SUSP, PRIM_OP_REQUEST,
	 "DL-SUSPEND-REQUEST", lapd_susp_req},

	/* create and send SABM command (resume) */
	{SBIT(LAPD_STATE_MF_EST) |
	 SBIT(LAPD_STATE_TIMER_RECOV),
	 PRIM_DL_RES, PRIM_OP_REQUEST,
	 "DL-RESUME-REQUEST", lapd_res_req},

	/* create and send SABM command (reconnect) */
	{SBIT(LAPD_STATE_IDLE) |
	 SBIT(LAPD_STATE_MF_EST) |
	 SBIT(LAPD_STATE_TIMER_RECOV),
	 PRIM_DL_RECON, PRIM_OP_REQUEST,
	 "DL-RECONNECT-REQUEST", lapd_res_req},

	/* create and send DISC command */
	{SBIT(LAPD_STATE_SABM_SENT) |
	 SBIT(LAPD_STATE_MF_EST) |
	 SBIT(LAPD_STATE_TIMER_RECOV) |
	 SBIT(LAPD_STATE_DISC_SENT),
	 PRIM_DL_REL, PRIM_OP_REQUEST,
	 "DL-RELEASE-REQUEST", lapd_rel_req},

	/* release in idle state */
	{SBIT(LAPD_STATE_IDLE),
	 PRIM_DL_REL, PRIM_OP_REQUEST,
	 "DL-RELEASE-REQUEST", lapd_rel_req_idle},
};

#define L2DOWNSLLEN \
	(sizeof(l2downstatelist) / sizeof(struct l2downstate))

int lapd_recv_dlsap(struct osmo_dlsap_prim *dp, struct lapd_msg_ctx *lctx)
{
	struct lapd_datalink *dl = lctx->dl;
	int i, supported = 0;
	struct msgb *msg = dp->oph.msg;
	int rc;

	/* find function for current state and message */
	for (i = 0; i < L2DOWNSLLEN; i++) {
		if (dp->oph.primitive == l2downstatelist[i].prim
		 && dp->oph.operation == l2downstatelist[i].op) {
			supported = 1;
		 	if ((SBIT(dl->state) & l2downstatelist[i].states))
				break;
		}
	}
	if (!supported) {
		LOGDL(dl, LOGL_NOTICE, "Message %u/%u unsupported\n",
		      dp->oph.primitive, dp->oph.operation);
		msgb_free(msg);
		return 0;
	}
	if (i == L2DOWNSLLEN) {
		LOGDL(dl, LOGL_NOTICE, "Message %u/%u unhandled at this state %s\n",
		      dp->oph.primitive, dp->oph.operation, lapd_state_name(dl->state));
		msgb_free(msg);
		return 0;
	}

	LOGDL(dl, LOGL_INFO, "Message %s received in state %s\n",
		l2downstatelist[i].name, lapd_state_name(dl->state));

	rc = l2downstatelist[i].rout(dp, lctx);

	return rc;
}

/*! @} */
