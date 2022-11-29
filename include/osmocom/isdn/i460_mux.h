/*! \file i460_mux.h
 * ITU-T I.460 sub-channel multiplexer + demultiplexer */
/*
 * (C) 2020 by Harald Welte <laforge@gnumonks.org>
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

#pragma once
#include <stdint.h>
#include <osmocom/core/bits.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>

/* I.460 sub-slot rate */
enum osmo_i460_rate {
	OSMO_I460_RATE_NONE,		/* disabled */
	OSMO_I460_RATE_64k,
	OSMO_I460_RATE_32k,
	OSMO_I460_RATE_16k,
	OSMO_I460_RATE_8k,
};

struct osmo_i460_subchan;

typedef void (*out_cb_bits_t)(struct osmo_i460_subchan *schan, void *user_data,
			      const ubit_t *bits, unsigned int num_bits);
typedef void (*out_cb_bytes_t)(struct osmo_i460_subchan *schan, void *user_data,
			       const uint8_t *bytes, unsigned int num_bytes);

struct osmo_i460_subchan_demux {
	/*! bit-buffer for output bits */
	uint8_t *out_bitbuf;
	/*! size of out_bitbuf in bytes */
	unsigned int out_bitbuf_size;
	/*! offset of next bit to be written in out_bitbuf */
	unsigned int out_idx;
	/*! callback to be called once we have received out_bitbuf_size bits */
	out_cb_bits_t out_cb_bits;
	out_cb_bytes_t out_cb_bytes;
	void *user_data;
};

typedef void (*in_cb_queue_empty_t)(struct osmo_i460_subchan *schan, void *user_data);

struct osmo_i460_subchan_mux {
	/*! list of to-be-transmitted message buffers */
	struct llist_head tx_queue;
	in_cb_queue_empty_t in_cb_queue_empty;
	void *user_data;
};

struct osmo_i460_subchan {
	struct osmo_i460_timeslot *ts;	/* back-pointer */
	enum osmo_i460_rate rate;		/* 8/16/32/64k */
	uint8_t bit_offset;		/* bit offset inside each byte of the B-channel */
	struct osmo_i460_subchan_demux demux;
	struct osmo_i460_subchan_mux mux;
};

struct osmo_i460_timeslot {
	struct osmo_i460_subchan schan[8];
};

/*! description of a sub-channel; passed by caller */
struct osmo_i460_schan_desc {
	enum osmo_i460_rate rate;
	uint8_t bit_offset;
	struct {
		/* size (in bits) of the internal buffer; determines granularity */
		size_t num_bits;
		/*! call-back function called whenever we received num_bits */
		out_cb_bits_t out_cb_bits;
		/*! out_cb_bytes call-back function called whenever we received num_bits.
		 * The user is usually expected to provide either out_cb_bits or out_cb_bytes.  If only
		 * out_cb_bits is provided, output data will always be provided as unpacked bits;  if only
		 * out_cb_bytes is provided, output data will always be provided as packet bits (bytes).  If
		 * both are provided, it is up to the I.460 multiplex to decide if it calls either of the two,
		 * depending on what can be provided without extra conversion. */
		out_cb_bytes_t out_cb_bytes;
		/* opaque user data pointer to pass to out_cb */
		void *user_data;
	} demux;

	struct {
		/* call-back function whenever the muxer requires more input data from the sub-channels,
		 * but has nothing enqueued yet. A typical function would then call osmo_i460_mux_enqueue() */
		in_cb_queue_empty_t in_cb_queue_empty;
		/* opaque user data pointer to pass to in_cb */
		void *user_data;
	} mux;
};

void osmo_i460_demux_in(struct osmo_i460_timeslot *ts, const uint8_t *data, size_t data_len);

void osmo_i460_mux_enqueue(struct osmo_i460_subchan *schan, struct msgb *msg);
int osmo_i460_mux_out(struct osmo_i460_timeslot *ts, uint8_t *out, size_t out_len);

void osmo_i460_ts_init(struct osmo_i460_timeslot *ts);

struct osmo_i460_subchan *
osmo_i460_subchan_add(void *ctx, struct osmo_i460_timeslot *ts, const struct osmo_i460_schan_desc *chd);

void osmo_i460_subchan_del(struct osmo_i460_subchan *schan);

/*! @} */
