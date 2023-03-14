/*! \file v110_ta.c
 *  TA (Terminal Adapter) implementation as per ITU-T V.110. */
/*
 * (C) 2022 by Harald Welte <laforge@gnumonks.org>
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Initial (Work-in-Progress) implementation by Harald Welte,
 * completed and co-authored by Vadim Yanitskiy.
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

#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/bits.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/fsm.h>

#include <osmocom/isdn/v110.h>
#include <osmocom/isdn/v110_ta.h>

#define S(x) (1 << (x))

#define V24_FLAGMASK_IS_ON(flags, circuit) \
	(((flags) & S(circuit)) != 0)

#define V24_FLAGMASK_IS_OFF(flags, circuit) \
	(((flags) & S(circuit)) == 0)

#define V24_FLAGMASK_SET_ON(flags, circuit) \
	(flags) |= S(circuit)

#define V24_FLAGMASK_SET_OFF(flags, circuit) \
	(flags) &= ~S(circuit)

/* inverse logic: ON = binary 0; OFF = binary 1 */
#define V110_SX_BIT_ON		0
#define V110_SX_BIT_OFF		1

const struct value_string osmo_v110_ta_circuit_names[] = {
	{ OSMO_V110_TA_C_105,	"105/RTS" },
	{ OSMO_V110_TA_C_106,	"106/CTS" },
	{ OSMO_V110_TA_C_107,	"107/DSR" },
	{ OSMO_V110_TA_C_108,	"108/DTR" },
	{ OSMO_V110_TA_C_109,	"109/DCD" },
	{ OSMO_V110_TA_C_133,	"133" },
	{ 0, NULL }
};

const struct value_string osmo_v110_ta_circuit_descs[] = {
	{ OSMO_V110_TA_C_105,	"Request to Send" },
	{ OSMO_V110_TA_C_106,	"Clear to Send" },
	{ OSMO_V110_TA_C_107,	"Data Set Ready" },
	{ OSMO_V110_TA_C_108,	"Data Terminal Ready" },
	{ OSMO_V110_TA_C_109,	"Data Carrier Detect" },
	{ OSMO_V110_TA_C_133,	"Ready for receiving" },
	{ 0, NULL }
};

static const struct osmo_tdef v110_ta_tdef[] = {
	{ .T = OSMO_V110_TA_TIMER_X1,
	  .unit = OSMO_TDEF_MS, .default_val = 3000, /* suggested in 7.1.5 e) */
	  .desc = "ITU-T V.110 7.1.5 Loss of frame synchronization: sync recovery timer" },
	{ .T = OSMO_V110_TA_TIMER_T1,
	  .unit = OSMO_TDEF_MS, .default_val = 10000, /* suggested in 7.1.2.2 */
	  .desc = "ITU-T V.110 7.1.2 Connect TA to line: sync establishment timer" },
	{ .T = OSMO_V110_TA_TIMER_T2,
	  .unit = OSMO_TDEF_MS, .default_val = 5000, /* suggested in 7.1.4.1 */
	  .desc = "ITU-T V.110 7.1.4 Disconnect mode: disconnect confirmation timer" },
	{ /* end of list */ }
};

/*********************************************************************************
 * V.110 TERMINAL ADAPTER FSM
 *********************************************************************************/

enum v110_ta_fsm_state {
	V110_TA_ST_IDLE_READY,		/* 7.1.1 Idle (or ready) state */
	V110_TA_ST_CON_TA_TO_LINE,	/* 7.1.2 Connect TA to line state */
	V110_TA_ST_DATA_TRANSFER,	/* 7.1.3 Data transfer state */
	V110_TA_ST_DISCONNECTING,	/* 7.1.4 Disconnect mode */
	V110_TA_ST_RESYNCING,		/* 7.1.5 Re-synchronizing state */
};

enum v110_ta_fsm_event {
	V110_TA_EV_RX_FRAME_IND,	/* a V.110 frame was received by the lower layer */
	V110_TA_EV_TX_FRAME_RTS,	/* a V.110 frame is to be sent by the lower layer */
	V110_TA_EV_V24_STATUS_CHG,	/* V.24 flag-mask has been updated by TE */
	V110_TA_EV_SYNC_IND,		/* the lower layer has synchronized to the frame clock */
	V110_TA_EV_DESYNC_IND,		/* the lower layer has lost frame clock synchronization */
	V110_TA_EV_TIMEOUT,		/* generic event for handling a timeout condition */
};

static const struct value_string v110_ta_fsm_event_names[] = {
	{ V110_TA_EV_RX_FRAME_IND,	"RX_FRAME_IND" },
	{ V110_TA_EV_TX_FRAME_RTS,	"TX_FRAME_RTS" },
	{ V110_TA_EV_V24_STATUS_CHG,	"V24_STATUS_CHG" },
	{ V110_TA_EV_SYNC_IND,		"SYNC_IND" },
	{ V110_TA_EV_DESYNC_IND,	"DESYNC_IND" },
	{ V110_TA_EV_TIMEOUT,		"TIMEOUT" },
	{ 0, NULL }
};

enum v110_ta_d_bit_mode {
	V110_TA_DBIT_M_ALL_ZERO		= 0,	/* set all bits to binary '0' */
	V110_TA_DBIT_M_ALL_ONE		= 1,	/* set all bits to binary '1' */
	V110_TA_DBIT_M_FORWARD,			/* forward D-bits to/from DTE */
};

struct v110_ta_state {
	/*! V.24 status flags shared between DTE (user) and DCE (TA, us) */
	unsigned int v24_flags;
	struct {
		/* what kind of D-bits to transmit in V.110 frames */
		enum v110_ta_d_bit_mode d_bit_mode;
		/* what to put in S-bits of transmitted V.110 frames */
		ubit_t s_bits;
		/* what to put in X-bits of transmitted V.110 frames */
		ubit_t x_bits;
	} tx;
	struct {
		enum v110_ta_d_bit_mode d_bit_mode;
	} rx;
};

struct osmo_v110_ta {
	const char *name;
	struct osmo_tdef *Tdefs;
	struct osmo_fsm_inst *fi;
	struct osmo_v110_ta_cfg *cfg;
	struct v110_ta_state state;
};

static inline bool v110_df_x_bits_are(const struct osmo_v110_decoded_frame *df, ubit_t cmp)
{
	return (df->x_bits[0] == cmp) && (df->x_bits[1] == cmp);
}

static inline bool v110_df_s_bits_are(const struct osmo_v110_decoded_frame *df, ubit_t cmp)
{
	/* ITU-T Table 2/V.110 (see also 5.1.2.3) defines the following S-bits:
	 * S1, S3, S4, S6, S8, S9 (6 bits total).  However, fr->s_bits[] contains
	 * 9 (MAX_S_BITS) bits, including the undefined bits S2, S5, S7.
	 * Hence we must skip those undefined bits. */
	static const uint8_t sbit_map[] = { 0, 2, 3, 5, 7, 8 };

	for (unsigned int i = 0; i < ARRAY_SIZE(sbit_map); i++) {
		uint8_t idx = sbit_map[i];
		if (df->s_bits[idx] != cmp)
			return false;
	}

	return true;
}

static inline bool v110_df_d_bits_are(const struct osmo_v110_decoded_frame *df, ubit_t cmp)
{
	for (unsigned int i = 0; i < MAX_D_BITS; i++) {
		if (df->d_bits[i] != cmp)
			return false;
	}

	return true;
}

/* handle one V.110 frame and forward user bits to the application */
static void v110_ta_handle_frame(const struct osmo_v110_ta *ta,
				 const struct osmo_v110_decoded_frame *df)
{
	const struct osmo_v110_ta_cfg *cfg = ta->cfg;
	const struct v110_ta_state *ts = &ta->state;
	ubit_t user_bits[MAX_D_BITS];
	int num_user_bits;
	int rc;

	switch (ts->rx.d_bit_mode) {
	case V110_TA_DBIT_M_ALL_ZERO:
	case V110_TA_DBIT_M_ALL_ONE:
		/* generate as many user bits as needed for the configured rate */
		num_user_bits = osmo_v110_sync_ra1_get_user_data_chunk_bitlen(cfg->rate);
		OSMO_ASSERT(num_user_bits > 0);
		/* set them all to binary '0' or binary '1' */
		memset(&user_bits[0], (int)ts->rx.d_bit_mode, num_user_bits);
		cfg->rx_cb(cfg->priv, &user_bits[0], num_user_bits);
		break;
	case V110_TA_DBIT_M_FORWARD:
		rc = osmo_v110_sync_ra1_ir_to_user(cfg->rate, &user_bits[0], sizeof(user_bits), df);
		if (rc > 0)
			cfg->rx_cb(cfg->priv, &user_bits[0], rc);
		/* XXX else: indicate an error somehow? */
		break;
	}
}

/* build one V.110 frame to transmit */
static void v110_ta_build_frame(const struct osmo_v110_ta *ta,
				struct osmo_v110_decoded_frame *df)
{
	const struct osmo_v110_ta_cfg *cfg = ta->cfg;
	const struct v110_ta_state *ts = &ta->state;
	ubit_t user_bits[MAX_D_BITS];
	int num_user_bits;
	int rc;

	/* E-bits (E1/E2/E3 may be overwritten below) */
	memset(df->e_bits, 1, sizeof(df->e_bits));
	/* S-bits */
	memset(df->s_bits, ts->tx.s_bits, sizeof(df->s_bits));
	/* X-bits */
	memset(df->x_bits, ts->tx.x_bits, sizeof(df->x_bits));

	/* D-bits */
	switch (ts->tx.d_bit_mode) {
	case V110_TA_DBIT_M_ALL_ZERO:
	case V110_TA_DBIT_M_ALL_ONE:
		/* set them all to binary '0' or binary '1' */
		memset(df->d_bits, (int)ts->tx.d_bit_mode, sizeof(df->d_bits));
		break;
	case V110_TA_DBIT_M_FORWARD:
		/* how many user bits to retrieve */
		num_user_bits = osmo_v110_sync_ra1_get_user_data_chunk_bitlen(cfg->rate);
		OSMO_ASSERT(num_user_bits > 0);
		/* retrieve user bits from the application */
		cfg->tx_cb(cfg->priv, &user_bits[0], num_user_bits);
		/* convert user bits to intermediate rate (store to df) */
		rc = osmo_v110_sync_ra1_user_to_ir(cfg->rate, df, &user_bits[0], num_user_bits);
		OSMO_ASSERT(rc == 0);
		break;
	}
}

static void v110_ta_flags_updated(const struct osmo_v110_ta *ta)
{
	const struct osmo_v110_ta_cfg *cfg = ta->cfg;

	if (cfg->status_update_cb != NULL)
		cfg->status_update_cb(cfg->priv, ta->state.v24_flags);
}

static const struct osmo_tdef_state_timeout v110_ta_fsm_timeouts[32] = {
	[V110_TA_ST_RESYNCING]		= { .T = OSMO_V110_TA_TIMER_X1 },
	[V110_TA_ST_CON_TA_TO_LINE]	= { .T = OSMO_V110_TA_TIMER_T1 },
	[V110_TA_ST_DISCONNECTING]	= { .T = OSMO_V110_TA_TIMER_T2 },
};

#define v110_ta_fsm_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(fi, state, \
				     v110_ta_fsm_timeouts, \
				     ((struct osmo_v110_ta *)(fi->priv))->Tdefs, \
				     0)

/* ITU-T V.110 Section 7.1.1 */
static void v110_ta_fsm_idle_ready_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct osmo_v110_ta *ta = (struct osmo_v110_ta *)fi->priv;
	struct v110_ta_state *ts = &ta->state;

	/* 7.1.1.2 During the idle (or ready) state the TA will transmit continuous binary 1s into the B-channel */
	ts->tx.d_bit_mode = V110_TA_DBIT_M_ALL_ONE; /* circuit 103: continuous binary '1' */
	ts->tx.s_bits = V110_SX_BIT_OFF; /* OFF is binary '1' */
	ts->tx.x_bits = V110_SX_BIT_OFF; /* OFF is binary '1' */

	/* 7.1.1.3 During the idle (or ready) state the TA (DCE) will transmit the following toward the DTE: */
	/* - circuit 104: continuous binary '1' */
	ts->rx.d_bit_mode = V110_TA_DBIT_M_ALL_ONE;
	/* - circuits 107, 106, 109 = OFF */
	V24_FLAGMASK_SET_OFF(ts->v24_flags, OSMO_V110_TA_C_106);
	V24_FLAGMASK_SET_OFF(ts->v24_flags, OSMO_V110_TA_C_107);
	V24_FLAGMASK_SET_OFF(ts->v24_flags, OSMO_V110_TA_C_109);
	v110_ta_flags_updated(ta);
}

/* ITU-T V.110 Section 7.1.1 */
static void v110_ta_fsm_idle_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_v110_ta *ta = (struct osmo_v110_ta *)fi->priv;
	struct v110_ta_state *ts = &ta->state;

	switch (event) {
	case V110_TA_EV_V24_STATUS_CHG:
		/* When the TA is to be switched to the data mode, circuit 108 must be ON */
		if (V24_FLAGMASK_IS_ON(ts->v24_flags, OSMO_V110_TA_C_108)) {
			/* 7.12.2: Start timer T1 when switching to CON_TA_LINE */
			v110_ta_fsm_state_chg(V110_TA_ST_CON_TA_TO_LINE);
		}
		break;
	case V110_TA_EV_RX_FRAME_IND:
		v110_ta_handle_frame(ta, (const struct osmo_v110_decoded_frame *)data);
		break;
	case V110_TA_EV_TX_FRAME_RTS:
		v110_ta_build_frame(ta, (struct osmo_v110_decoded_frame *)data);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* ITU-T V.110 Section 7.1.2 */
static void v110_ta_fsm_connect_ta_to_line_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct osmo_v110_ta *ta = (struct osmo_v110_ta *)fi->priv;
	struct v110_ta_state *ts = &ta->state;

	/* 7.1.2.1 Switching to the data mode causes the TA to transmit the following towards the ISDN: */
	/*  a) frame synchronization pattern as described in 5.1.3.1 and 5.2.1 (done by the API user) */
	/*  b) circuit 103: continuous binary '1' */
	ts->tx.d_bit_mode = V110_TA_DBIT_M_ALL_ONE;
	/*  c) status bits S = OFF and X = OFF */
	ts->tx.s_bits = V110_SX_BIT_OFF; /* OFF is binary '1' */
	ts->tx.x_bits = V110_SX_BIT_OFF; /* OFF is binary '1' */

	/* 7.1.2.2 ... the receiver in the TA will begin to search for the frame synchronization
	 * pattern in the received bit stream (see 5.1.3.1 and 5.2.1) and start timer T1. */
	OSMO_ASSERT(fi->T == OSMO_V110_TA_TIMER_T1);
}

/* ITU-T V.110 Section 7.1.2 */
static void v110_ta_fsm_connect_ta_to_line(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_v110_ta *ta = (struct osmo_v110_ta *)fi->priv;
	struct v110_ta_state *ts = &ta->state;

	switch (event) {
	case V110_TA_EV_V24_STATUS_CHG:
		/* If circuit 108 is OFF, we go back to IDLE/READY */
		if (V24_FLAGMASK_IS_OFF(ts->v24_flags, OSMO_V110_TA_C_108))
			v110_ta_fsm_state_chg(V110_TA_ST_IDLE_READY);
		break;
	case V110_TA_EV_SYNC_IND:
		/* 7.1.2.3 When the receiver recognizes the frame synchronization pattern, it causes the S-
		 * and X-bits in the transmitted frames to be turned ON (provided that circuit 108 is ON). */
		OSMO_ASSERT(V24_FLAGMASK_IS_ON(ts->v24_flags, OSMO_V110_TA_C_108));
		ts->tx.s_bits = V110_SX_BIT_ON;
		ts->tx.x_bits = V110_SX_BIT_ON;
		break;
	case V110_TA_EV_RX_FRAME_IND:
	{
		const struct osmo_v110_decoded_frame *df = data;

		/* 7.1.2.4 When the receiver recognizes that the status of bits S and X are ON */
		if (v110_df_s_bits_are(df, V110_SX_BIT_ON) &&
		    v110_df_x_bits_are(df, V110_SX_BIT_ON)) {
			/* ... it will perform the following functions: */
			/*  a) Turn ON circuit 107 toward the DTE and stop timer T1 */
			V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V110_TA_C_107);
			osmo_timer_del(&fi->timer);
			/*  b) Then, circuit 103 may be connected to the data bits in the frame; however, the
			 *  DTE must maintain a binary 1 condition on circuit 103 until circuit 106 is turned
			 *  ON in the next portion of the sequence. */
			/*  c) Turn ON circuit 109 and connect the data bits to circuit 104. */
			V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V110_TA_C_109);
			ts->rx.d_bit_mode = V110_TA_DBIT_M_FORWARD;
			/*  d) After an interval of N bits (see 6.3), it will turn ON circuit 106. */
			V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V110_TA_C_106);
			ts->tx.d_bit_mode = V110_TA_DBIT_M_FORWARD;
			v110_ta_flags_updated(ta);
			/*  Circuit 106 transitioning from OFF to ON will cause the transmitted data to
			 *  transition from binary 1 to the data mode. */
			v110_ta_fsm_state_chg(V110_TA_ST_DATA_TRANSFER);
		}

		v110_ta_handle_frame(ta, df);
		break;
	}
	case V110_TA_EV_TX_FRAME_RTS:
		v110_ta_build_frame(ta, (struct osmo_v110_decoded_frame *)data);
		break;
	case V110_TA_EV_TIMEOUT:
		v110_ta_fsm_state_chg(V110_TA_ST_IDLE_READY);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* ITU-T V.110 Section 7.1.3 */
static void v110_ta_fsm_data_transfer_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct osmo_v110_ta *ta = (struct osmo_v110_ta *)fi->priv;
	struct v110_ta_state *ts = &ta->state;

	/* 7.1.3.1 While in the data transfer state, the following circuit conditions exist:
	 *  a): 105, 107, 108, and 109 are in the ON condition */
	/* XXX: OSMO_ASSERT(V24_FLAGMASK_IS_ON(ts->v24_flags, OSMO_V110_TA_C_105)); */
	V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V110_TA_C_107);
	/* XXX: OSMO_ASSERT(V24_FLAGMASK_IS_ON(ts->v24_flags, OSMO_V110_TA_C_108)); */
	V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V110_TA_C_109);
	/*  b) data is being transmitted on circuit 103 and received on circuit 104 */
	ts->rx.d_bit_mode = V110_TA_DBIT_M_FORWARD;
	ts->tx.d_bit_mode = V110_TA_DBIT_M_FORWARD;
	/*  c) circuits 133 (when implemented) and 106 are in the ON condition unless local out-of-band
	 *  flow control is being used, either or both circuits may be in the ON or the OFF condition. */
	if (!ta->cfg->flow_ctrl.end_to_end) {
		/* XXX: OSMO_ASSERT(V24_FLAGMASK_IS_ON(ts->v24_flags, OSMO_V110_TA_C_133)); */
		V24_FLAGMASK_SET_ON(ts->v24_flags, OSMO_V110_TA_C_106);
	}
	v110_ta_flags_updated(ta);

	/* 7.1.3.2 While in the data transfer state, the following status bit conditions exist: */
	/*  a) status bits S in both directions are in the ON condition; */
	ts->tx.s_bits = V110_SX_BIT_ON;
	/*  b) status bits X in both directions are in the ON condition unless end-to-end flow control
	 *  is being used, in which case status bit X in either or both directions may be in the
	 *  ON or the OFF condition. */
	if (!ta->cfg->flow_ctrl.end_to_end)
		ts->tx.x_bits = V110_SX_BIT_ON;
}

/* ITU-T V.110 Section 7.1.3 */
static void v110_ta_fsm_data_transfer(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_v110_ta *ta = (struct osmo_v110_ta *)fi->priv;
	struct v110_ta_state *ts = &ta->state;

	/* 7.1.3.3 While in the data transfer state: */
	/*  a) the S status bits shall *not* be mapped to/from the interchange circuits */
	/*  b) the X status bits shall *not* be mapped according to Table 3,
	 *  unless end-to-end flow control is implemented */
	/* TODO: if (ta->cfg->flow_ctrl.end_to_end) { ... } */

	switch (event) {
	case V110_TA_EV_V24_STATUS_CHG:
		/* 7.1.4.1 At the completion of the data transfer phase, the local DTE will indicate a
		 * disconnect request by turning OFF circuit 108 */
		if (V24_FLAGMASK_IS_ON(ts->v24_flags, OSMO_V110_TA_C_108))
			break;
		v110_ta_fsm_state_chg(V110_TA_ST_DISCONNECTING);
		break;
	case V110_TA_EV_DESYNC_IND:
		v110_ta_fsm_state_chg(V110_TA_ST_RESYNCING);
		break;
	case V110_TA_EV_TX_FRAME_RTS:
		v110_ta_build_frame(ta, (struct osmo_v110_decoded_frame *)data);
		break;
	case V110_TA_EV_RX_FRAME_IND:
	{
		const struct osmo_v110_decoded_frame *df = data;

		/* 7.1.4.2 ... this TA will recognize the transition of the status bits S from
		 * ON to OFF and the data bits from data to binary 0 as a disconnect request */
		if (v110_df_s_bits_are(df, V110_SX_BIT_OFF) && v110_df_d_bits_are(df, 0)) {
			/* ... and it will turn OFF circuits 107 and 109. */
			V24_FLAGMASK_SET_OFF(ts->v24_flags, OSMO_V110_TA_C_107);
			V24_FLAGMASK_SET_OFF(ts->v24_flags, OSMO_V110_TA_C_109);
			v110_ta_flags_updated(ta);
			/* DTE should respond by turning OFF circuit 108 */
			break; /* XXX: shall we forward D-bits to DTE anyway? */
		}

		v110_ta_handle_frame(ta, df);
		break;
	}
	default:
		OSMO_ASSERT(0);
	}
}

/* ITU-T V.110 Section 7.1.4 */
static void v110_ta_fsm_disconnect_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct osmo_v110_ta *ta = (struct osmo_v110_ta *)fi->priv;
	struct v110_ta_state *ts = &ta->state;

	/* 7.1.4.1 At the completion of the data transfer phase, the local DTE will indicate a
	 * disconnect request by turning OFF circuit 108. This will cause the following to occur: */
	/*  a) the status bits S in the frame toward ISDN will turn OFF, status bits X are kept ON */
	ts->tx.s_bits = V110_SX_BIT_OFF;
	/*  b) circuit 106 will be turned OFF */
	V24_FLAGMASK_SET_OFF(ts->v24_flags, OSMO_V110_TA_C_106);
	v110_ta_flags_updated(ta);
	/*  c) the data bits in the frame will be set to binary 0. */
	ts->tx.d_bit_mode = V110_TA_DBIT_M_ALL_ZERO;

	/* To guard against the failure of the remote TA to respond to the disconnect request,
	 * the local TA may start a timer T2 (suggested value 5 s) which is stopped by the
	 * reception or transmission of any D-channel clearing message (DISCONNECT, RELEASE,
	 * RELEASE COMPLETE). */
	OSMO_ASSERT(fi->T == OSMO_V110_TA_TIMER_T2);
}

/* ITU-T V.110 Section 7.1.4 */
static void v110_ta_fsm_disconnect(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_v110_ta *ta = (struct osmo_v110_ta *)fi->priv;

	switch (event) {
	case V110_TA_EV_V24_STATUS_CHG:
		break; /* nothing to do */
	case V110_TA_EV_TX_FRAME_RTS:
		v110_ta_build_frame(ta, (struct osmo_v110_decoded_frame *)data);
		break;
	case V110_TA_EV_RX_FRAME_IND:
	{
		const struct osmo_v110_decoded_frame *df = data;

		/* 7.1.4.3 The TA at the station that originated the disconnect request will
		 * recognize reception of S = OFF or the loss of framing signals as a disconnect
		 * acknowledgement and turn OFF circuits 107 and 109. */
		if (v110_df_s_bits_are(df, V110_SX_BIT_OFF)) {
			/* circuits 107 and 109 set to off in .onenter() */
			v110_ta_fsm_state_chg(V110_TA_ST_IDLE_READY);
		}

		v110_ta_handle_frame(ta, df);
		break;
	}
	case V110_TA_EV_DESYNC_IND:
	case V110_TA_EV_TIMEOUT:
		/* circuits 107 and 109 set to off in .onenter() */
		v110_ta_fsm_state_chg(V110_TA_ST_IDLE_READY);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* ITU-T V.110 Section 7.1.5 */
static void v110_ta_fsm_resyncing_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct osmo_v110_ta *ta = (struct osmo_v110_ta *)fi->priv;
	struct v110_ta_state *ts = &ta->state;

	/* 7.1.5 In the event of loss of frame synchronization, the (local) TA should
	 * attempt to resynchronize as follows: */
	/*  a) Place circuit 104 in binary 1 condition (passes from the data mode) */
	ts->rx.d_bit_mode = V110_TA_DBIT_M_ALL_ONE;
	/*  b) Turn OFF status bit X in the transmitted frame */
	ts->tx.x_bits = V110_SX_BIT_OFF;

	/* guard timeout, see 7.1.5 e) */
	OSMO_ASSERT(fi->T == OSMO_V110_TA_TIMER_X1);
}

/* ITU-T V.110 Section 7.1.5 */
static void v110_ta_fsm_resyncing(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_v110_ta *ta = (struct osmo_v110_ta *)fi->priv;
	struct v110_ta_state *ts = &ta->state;

	switch (event) {
	case V110_TA_EV_V24_STATUS_CHG:
		break; /* TODO: handle circuit 108 being set to OFF? */
	case V110_TA_EV_TX_FRAME_RTS:
		v110_ta_build_frame(ta, (struct osmo_v110_decoded_frame *)data);
		break;
	case V110_TA_EV_SYNC_IND:
		/* f) If resynchronization is achieved, the local TA should turn ON status bit X */
		ts->tx.x_bits = V110_SX_BIT_ON;
		v110_ta_fsm_state_chg(V110_TA_ST_DATA_TRANSFER);
		break;
	case V110_TA_EV_TIMEOUT:
		/* e) If after an interval of X1 seconds the local TA cannot attain synchronization,
		 * it should send a disconnect request by turning OFF all of the status bits for several
		 * (at least three) frames with data bits set to binary 0 and then disconnect by turning
		 * OFF circuit 107 and transferring to the disconnected mode as discussed in 7.1.4.2. */
		ts->tx.s_bits = V110_SX_BIT_OFF;
		ts->tx.x_bits = V110_SX_BIT_OFF;
		ts->tx.d_bit_mode = V110_TA_DBIT_M_ALL_ZERO;
		/* TODO: actually Tx those frames (delay state transition) */
		V24_FLAGMASK_SET_OFF(ts->v24_flags, OSMO_V110_TA_C_107);
		v110_ta_flags_updated(ta);
		v110_ta_fsm_state_chg(V110_TA_ST_DISCONNECTING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int v110_ta_timer_cb(struct osmo_fsm_inst *fi)
{
	osmo_fsm_inst_dispatch(fi, V110_TA_EV_TIMEOUT, NULL);
	return 0;
}

static const struct osmo_fsm_state v110_ta_states[] = {
	[V110_TA_ST_IDLE_READY] = {
		.name = "IDLE_READY",
		.in_event_mask  = S(V110_TA_EV_V24_STATUS_CHG)
				| S(V110_TA_EV_TX_FRAME_RTS)
				| S(V110_TA_EV_RX_FRAME_IND),
		.out_state_mask = S(V110_TA_ST_IDLE_READY)
				| S(V110_TA_ST_CON_TA_TO_LINE),
		.action = &v110_ta_fsm_idle_ready,
		.onenter = &v110_ta_fsm_idle_ready_onenter,
	},
	[V110_TA_ST_CON_TA_TO_LINE] = {
		.name = "CONNECT_TA_TO_LINE",
		.in_event_mask  = S(V110_TA_EV_V24_STATUS_CHG)
				| S(V110_TA_EV_TIMEOUT)
				| S(V110_TA_EV_SYNC_IND)
				| S(V110_TA_EV_TX_FRAME_RTS)
				| S(V110_TA_EV_RX_FRAME_IND),
		.out_state_mask = S(V110_TA_ST_DATA_TRANSFER)
				| S(V110_TA_ST_IDLE_READY),
		.action = &v110_ta_fsm_connect_ta_to_line,
		.onenter = &v110_ta_fsm_connect_ta_to_line_onenter,
	},
	[V110_TA_ST_DATA_TRANSFER] = {
		.name = "DATA_TRANSFER",
		.in_event_mask  = S(V110_TA_EV_V24_STATUS_CHG)
				| S(V110_TA_EV_DESYNC_IND)
				| S(V110_TA_EV_TX_FRAME_RTS)
				| S(V110_TA_EV_RX_FRAME_IND),
		.out_state_mask = S(V110_TA_ST_RESYNCING)
				| S(V110_TA_ST_DISCONNECTING),
		.action = &v110_ta_fsm_data_transfer,
		.onenter = &v110_ta_fsm_data_transfer_onenter,
	},
	[V110_TA_ST_DISCONNECTING] = {
		.name = "DISCONNECTING",
		.in_event_mask  = S(V110_TA_EV_V24_STATUS_CHG)
				| S(V110_TA_EV_TIMEOUT)
				| S(V110_TA_EV_TX_FRAME_RTS)
				| S(V110_TA_EV_RX_FRAME_IND)
				| S(V110_TA_EV_DESYNC_IND),
		.out_state_mask = S(V110_TA_ST_IDLE_READY),
		.action = &v110_ta_fsm_disconnect,
		.onenter = &v110_ta_fsm_disconnect_onenter,
	},
	[V110_TA_ST_RESYNCING] = {
		.name = "RESYNCING",
		.in_event_mask  = S(V110_TA_EV_V24_STATUS_CHG)
				| S(V110_TA_EV_TIMEOUT)
				| S(V110_TA_EV_TX_FRAME_RTS)
				| S(V110_TA_EV_SYNC_IND),
		.out_state_mask = S(V110_TA_ST_IDLE_READY)
				| S(V110_TA_ST_DATA_TRANSFER),
		.action = &v110_ta_fsm_resyncing,
		.onenter = &v110_ta_fsm_resyncing_onenter,
	},
};

static struct osmo_fsm osmo_v110_ta_fsm = {
	.name = "V110-TA",
	.states = v110_ta_states,
	.num_states = ARRAY_SIZE(v110_ta_states),
	.timer_cb = v110_ta_timer_cb,
	.log_subsys = DLGLOBAL,
	.event_names = v110_ta_fsm_event_names,
};

static __attribute__((constructor)) void on_dso_load(void)
{
	OSMO_ASSERT(osmo_fsm_register(&osmo_v110_ta_fsm) == 0);
}

/*! Allocate a V.110 TA (Terminal Adapter) instance.
 * \param[in] ctx parent talloc context.
 * \param[in] name name of the TA instance.
 * \param[in] cfg initial configuration of the TA instance.
 * \returns pointer to allocated TA instance; NULL on error. */
struct osmo_v110_ta *osmo_v110_ta_alloc(void *ctx, const char *name,
					const struct osmo_v110_ta_cfg *cfg)
{
	struct osmo_v110_ta *ta;

	OSMO_ASSERT(cfg != NULL);
	OSMO_ASSERT(cfg->rx_cb != NULL);
	OSMO_ASSERT(cfg->tx_cb != NULL);

	/* local (TE-TA) flow control is not implemented */
	if (cfg->flow_ctrl.local != OSMO_V110_LOCAL_FLOW_CTRL_NONE) {
		LOGP(DLGLOBAL, LOGL_ERROR, "Local (TE-TA) flow control is not implemented\n");
		return NULL;
	}

	ta = talloc_zero(ctx, struct osmo_v110_ta);
	if (ta == NULL)
		return NULL;

	ta->name = talloc_strdup(ta, name);
	ta->cfg = talloc_memdup(ta, cfg, sizeof(*cfg));
	if (ta->name == NULL || ta->cfg == NULL)
		goto exit_free;

	ta->Tdefs = talloc_memdup(ta, v110_ta_tdef, sizeof(v110_ta_tdef));
	if (ta->Tdefs == NULL)
		goto exit_free;
	osmo_tdefs_reset(ta->Tdefs); /* apply default values */

	ta->fi = osmo_fsm_inst_alloc(&osmo_v110_ta_fsm, ta, ta, LOGL_DEBUG, name);
	if (ta->fi == NULL)
		goto exit_free;

	/* perform a loop transition to init the internal state */
	osmo_fsm_inst_state_chg(ta->fi, V110_TA_ST_IDLE_READY, 0, 0);

	return ta;

exit_free:
	if (ta->fi != NULL)
		osmo_fsm_inst_free(ta->fi);
	talloc_free(ta);
	return NULL;
}

/*! Release memory taken by the given V.110 TA instance.
 * \param[in] ta TA instance to be free()d. */
void osmo_v110_ta_free(struct osmo_v110_ta *ta)
{
	if (ta == NULL)
		return;
	if (ta->fi != NULL)
		osmo_fsm_inst_free(ta->fi);
	talloc_free(ta); /* also free()s name and cfg */
}

/*! Configure a timer of the given V.110 TA instance.
 * \param[in] ta TA instance to be configured.
 * \param[in] timer a timer to be configured.
 * \param[in] val_ms the new timeout value to set (in milliseconds).
 * \returns 0 in case of success; negative on error. */
int osmo_v110_ta_set_timer_val_ms(struct osmo_v110_ta *ta,
				  enum osmo_v110_ta_timer timer,
				  unsigned long val_ms)
{
	return osmo_tdef_set(ta->Tdefs, (int)timer, val_ms, OSMO_TDEF_MS);
}

/*! Feed a [decoded] V.110 frame into the given TA instance.
 *
 * This function, like its _out counterpart, is intended to be used by the lower layers
 * receiving V.110 frames over some medium.  The caller of this function is responsible
 * for finding the synchronization pattern (if needed), aligning to the frame boundaries,
 * and decoding frames using osmo_v110_decode_frame() or osmo_csd_*_decode_frame().
 *
 * Bits E1/E2/E3 are expected to be set by the caller (if not being transmitted
 * over the medium) in accordance with the configured synchronous user rate.
 *
 * Bits D1..D48 are passed to the bit rate adaption function RA1.  The resulting output
 * is then passed to the upper layer (application) via the configured .rx_cb().  Though,
 * in certain states of the TA's FSM, bits D1..D48 are ignored and the upper layer
 * gets a sequence of binary '0' or '1'.
 *
 * \param[in] ta TA instance to feed the given frame into.
 * \param[in] in pointer to a [decoded] V.110 frame.
 * \returns 0 in case of success; negative on error. */
int osmo_v110_ta_frame_in(struct osmo_v110_ta *ta, const struct osmo_v110_decoded_frame *in)
{
	return osmo_fsm_inst_dispatch(ta->fi, V110_TA_EV_RX_FRAME_IND, (void *)in);
}

/*! Pull a [decoded] V.110 frame out of the given TA instance.
 *
 * This function, like its _in counterpart, is intended to be used by the lower layers
 * transmitting V.110 frames over some medium.  The caller of this function is responsible
 * for encoding the output frame using osmo_v110_encode_frame() or osmo_csd_*_encode_frame().
 *
 * Bits E1/E2/E3 are set in accordance with the configured synchronous user rate.
 * Bits E4/E5/E6/E7 are unconditionally set to binary '1'.
 *
 * Bits D1..D48 are set depending on the state of TA's FSM:
 *
 * - In data transfer mode, the user bits are obtained from the upper layer (application)
 *   via the configured .tx_cb(), and then passed to the bit rate adaption function RA1,
 *   which generates bits D1..D48.
 * - In other modes, bits D1..D48 are all set to binary '0' or '1'.
 *
 * \param[in] ta TA instance to pull a frame from.
 * \param[out] out where to store a [decoded] V.110 frame.
 * \returns 0 in case of success; negative on error. */
int osmo_v110_ta_frame_out(struct osmo_v110_ta *ta, struct osmo_v110_decoded_frame *out)
{
	return osmo_fsm_inst_dispatch(ta->fi, V110_TA_EV_TX_FRAME_RTS, (void *)out);
}

/*! Indicate a synchronization establishment event.
 *
 * This function is intended to be called when the lower layer
 * achieves synchronization to the frame clock.
 *
 * \param[in] ta TA instance to indicate the event to.
 * \returns 0 in case of success; negative on error. */
int osmo_v110_ta_sync_ind(struct osmo_v110_ta *ta)
{
	return osmo_fsm_inst_dispatch(ta->fi, V110_TA_EV_SYNC_IND, NULL);
}

/*! Indicate a synchronization loss event.
 *
 * This function is intended to be called when the lower layer
 * experiences a loss of synchronization with the frame clock.
 *
 * \param[in] ta TA instance to indicate the event to.
 * \returns 0 in case of success; negative on error. */
int osmo_v110_ta_desync_ind(struct osmo_v110_ta *ta)
{
	return osmo_fsm_inst_dispatch(ta->fi, V110_TA_EV_DESYNC_IND, NULL);
}

/*! Get the V.24 status bit-mask of the given TA instance.
 * \param[in] ta TA instance to get the circuit bit-mask.
 * \returns bitmask of OSMO_V110_TA_C_*. */
unsigned int osmo_v110_ta_get_status(const struct osmo_v110_ta *ta)
{
	return ta->state.v24_flags;
}

/*! Set the V.24 status bit-mask of the given TA instance.
 * \param[in] ta TA instance to update the circuit state.
 * \param[in] status bit-mask of OSMO_V110_TA_C_*.
 * \returns 0 on success; negative on error. */
static int v110_ta_set_status(struct osmo_v110_ta *ta, unsigned int status)
{
	const unsigned int old_status = ta->state.v24_flags;
	int rc = 0;

	ta->state.v24_flags = status;
	if (status != old_status)
		rc = osmo_fsm_inst_dispatch(ta->fi, V110_TA_EV_V24_STATUS_CHG, NULL);

	return rc;
}

/*! Get state of a V.24 circuit of the given TA instance.
 * \param[in] ta TA instance to get the circuit state.
 * \param[in] circuit a V.24 circuit, one of OSMO_V110_TA_C_*.
 * \returns circuit state: active (true) or inactive (false). */
bool osmo_v110_ta_get_circuit(const struct osmo_v110_ta *ta,
			      enum osmo_v110_ta_circuit circuit)
{
	return V24_FLAGMASK_IS_ON(ta->state.v24_flags, circuit);
}

/*! Activate/deactivate a V.24 circuit of the given TA instance.
 * \param[in] ta TA instance to update the circuit state.
 * \param[in] circuit a V.24 circuit, one of OSMO_V110_TA_C_* (DTE->DCE).
 * \param[in] active activate (true) or deactivate (false) the circuit.
 * \returns 0 on success; negative on error. */
int osmo_v110_ta_set_circuit(struct osmo_v110_ta *ta,
			     enum osmo_v110_ta_circuit circuit, bool active)
{
	unsigned int status = ta->state.v24_flags;

	/* permit setting only DTE->DCE circuits */
	switch (circuit) {
	case OSMO_V110_TA_C_105:
	case OSMO_V110_TA_C_108:
	case OSMO_V110_TA_C_133:
		break;
	default:
		LOGPFSML(ta->fi, LOGL_ERROR,
			 "Setting circuit %s is not permitted (wrong direction?)\n",
			 osmo_v110_ta_circuit_name(circuit));
		return -EACCES;
	}

	if (active)
		V24_FLAGMASK_SET_ON(status, circuit);
	else
		V24_FLAGMASK_SET_OFF(status, circuit);

	return v110_ta_set_status(ta, status);
}
