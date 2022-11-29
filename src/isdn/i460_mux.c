/*! \file i460_mux.c
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

#include <errno.h>

#include <osmocom/core/bits.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/isdn/i460_mux.h>

/* count the number of sub-channels in this I460 slot */
static int osmo_i460_subchan_count(struct osmo_i460_timeslot *ts)
{
	int i, num_used = 0;

	for (i = 0; i < ARRAY_SIZE(ts->schan); i++) {
		if (ts->schan[i].rate != OSMO_I460_RATE_NONE)
			num_used++;
	}

	return num_used;
}

/* does this channel have no sub-streams (single 64k subchannel)? */
static bool osmo_i460_has_single_64k_schan(struct osmo_i460_timeslot *ts)
{
	if (osmo_i460_subchan_count(ts) != 1)
		return false;

	if (ts->schan[0].rate != OSMO_I460_RATE_64k)
		return false;

	return true;
}

/***********************************************************************
 * Demultiplexer
 ***********************************************************************/

/* append a single bit to a sub-channel */
static void demux_subchan_append_bit(struct osmo_i460_subchan *schan, uint8_t bit)
{
	struct osmo_i460_subchan_demux *demux = &schan->demux;

	OSMO_ASSERT(demux->out_bitbuf);
	OSMO_ASSERT(demux->out_idx < demux->out_bitbuf_size);

	demux->out_bitbuf[demux->out_idx++] = bit ? 1 : 0;

	if (demux->out_idx >= demux->out_bitbuf_size) {
		if (demux->out_cb_bits)
			demux->out_cb_bits(schan, demux->user_data, demux->out_bitbuf, demux->out_idx);
		else {
			/* pack bits into bytes */
			OSMO_ASSERT((demux->out_idx % 8) == 0);
			unsigned int num_bytes = demux->out_idx / 8;
			uint8_t bytes[num_bytes];
			osmo_ubit2pbit(bytes, demux->out_bitbuf, demux->out_idx);
			demux->out_cb_bytes(schan, demux->user_data, bytes, num_bytes);
		}
		demux->out_idx = 0;
	}
}

/* extract those bits relevant to this schan of each byte in 'data' */
static void demux_subchan_extract_bits(struct osmo_i460_subchan *schan, const uint8_t *data, size_t data_len)
{
	int i;

	for (i = 0; i < data_len; i++) {
		uint8_t inbyte = data[i];
		/* I.460 defines sub-channel 0 is using bit positions 1+2 (the two
		 * most significant bits, hence we extract msb-first */
		uint8_t inbits = inbyte << schan->bit_offset;

		/* extract the bits relevant to the given schan */
		switch (schan->rate) {
		case OSMO_I460_RATE_8k:
			demux_subchan_append_bit(schan, inbits & 0x80);
			break;
		case OSMO_I460_RATE_16k:
			demux_subchan_append_bit(schan, inbits & 0x80);
			demux_subchan_append_bit(schan, inbits & 0x40);
			break;
		case OSMO_I460_RATE_32k:
			demux_subchan_append_bit(schan, inbits & 0x80);
			demux_subchan_append_bit(schan, inbits & 0x40);
			demux_subchan_append_bit(schan, inbits & 0x20);
			demux_subchan_append_bit(schan, inbits & 0x10);
			break;
		case OSMO_I460_RATE_64k:
			demux_subchan_append_bit(schan, inbits & 0x80);
			demux_subchan_append_bit(schan, inbits & 0x40);
			demux_subchan_append_bit(schan, inbits & 0x20);
			demux_subchan_append_bit(schan, inbits & 0x10);
			demux_subchan_append_bit(schan, inbits & 0x08);
			demux_subchan_append_bit(schan, inbits & 0x04);
			demux_subchan_append_bit(schan, inbits & 0x02);
			demux_subchan_append_bit(schan, inbits & 0x01);
			break;
		default:
			OSMO_ASSERT(0);
		}
	}
}

/*! Data from E1 timeslot into de-multiplexer
 *  \param[in] ts timeslot state
 *  \param[in] data input data bytes as received from E1/T1
 *  \param[in] data_len length of data in bytes */
void osmo_i460_demux_in(struct osmo_i460_timeslot *ts, const uint8_t *data, size_t data_len)
{
	struct osmo_i460_subchan *schan;
	struct osmo_i460_subchan_demux *demux;
	int i;

	/* fast path if entire 64k slot is used */
	if (osmo_i460_has_single_64k_schan(ts)) {
		schan = &ts->schan[0];
		demux = &schan->demux;
		if (demux->out_cb_bytes)
			demux->out_cb_bytes(schan, demux->user_data, data, data_len);
		else {
			ubit_t bits[data_len*8];
			osmo_pbit2ubit(bits, data, data_len*8);
			demux->out_cb_bits(schan, demux->user_data, bits, data_len*8);
		}
		return;
	}

	/* Slow path iterating over all lchans */
	for (i = 0; i < ARRAY_SIZE(ts->schan); i++) {
		schan = &ts->schan[i];
		if (schan->rate == OSMO_I460_RATE_NONE)
			continue;
		demux_subchan_extract_bits(schan, data, data_len);
	}
}


/***********************************************************************
 * Multiplexer
 ***********************************************************************/

/*! enqueue a to-be-transmitted message buffer containing unpacked bits */
void osmo_i460_mux_enqueue(struct osmo_i460_subchan *schan, struct msgb *msg)
{
	OSMO_ASSERT(msgb_length(msg) > 0);
	msgb_enqueue(&schan->mux.tx_queue, msg);
}

/* mux: pull the next bit out of the given sub-channel */
static ubit_t mux_schan_provide_bit(struct osmo_i460_subchan *schan)
{
	struct osmo_i460_subchan_mux *mux = &schan->mux;
	struct msgb *msg;
	ubit_t bit;

	/* if we don't have anything to transmit, return '1' bits */
	if (llist_empty(&mux->tx_queue)) {
		/* User code now has a last chance to put something into the queue. */
		if (mux->in_cb_queue_empty)
			mux->in_cb_queue_empty(schan, mux->user_data);

		/* If the queue is still empty, return idle bits */
		if (llist_empty(&mux->tx_queue))
			return 0x01;
	}
	msg = llist_entry(mux->tx_queue.next, struct msgb, list);
	bit = msgb_pull_u8(msg);

	/* free msgb if we have pulled the last bit */
	if (msgb_length(msg) <= 0) {
		llist_del(&msg->list);
		talloc_free(msg);
	}

	return bit;
}

/*! provide one byte with the subchan-specific bits of given sub-channel.
 *  \param[in] schan sub-channel that is to provide bits
 *  \parma[out] mask bitmask of those bits filled in
 *  \returns bits of given sub-channel */
static uint8_t mux_subchan_provide_bits(struct osmo_i460_subchan *schan, uint8_t *mask)
{
	uint8_t outbits = 0;
	uint8_t outmask;

	/* I.460 defines sub-channel 0 is using bit positions 1+2 (the two
	 * most significant bits, hence we provide msb-first */

	switch (schan->rate) {
	case OSMO_I460_RATE_8k:
		outbits = mux_schan_provide_bit(schan) << 7;
		outmask = 0x80;
		break;
	case OSMO_I460_RATE_16k:
		outbits |= mux_schan_provide_bit(schan) << 7;
		outbits |= mux_schan_provide_bit(schan) << 6;
		outmask = 0xC0;
		break;
	case OSMO_I460_RATE_32k:
		outbits |= mux_schan_provide_bit(schan) << 7;
		outbits |= mux_schan_provide_bit(schan) << 6;
		outbits |= mux_schan_provide_bit(schan) << 5;
		outbits |= mux_schan_provide_bit(schan) << 4;
		outmask = 0xF0;
		break;
	case OSMO_I460_RATE_64k:
		outbits |= mux_schan_provide_bit(schan) << 7;
		outbits |= mux_schan_provide_bit(schan) << 6;
		outbits |= mux_schan_provide_bit(schan) << 5;
		outbits |= mux_schan_provide_bit(schan) << 4;
		outbits |= mux_schan_provide_bit(schan) << 3;
		outbits |= mux_schan_provide_bit(schan) << 2;
		outbits |= mux_schan_provide_bit(schan) << 1;
		outbits |= mux_schan_provide_bit(schan) << 0;
		outmask = 0xFF;
		break;
	default:
		OSMO_ASSERT(0);
	}
	*mask = outmask >> schan->bit_offset;
	return outbits >> schan->bit_offset;
}

/* provide one byte of multiplexed I.460 bits */
static uint8_t mux_timeslot_provide_bits(struct osmo_i460_timeslot *ts)
{
	int i, count = 0;
	uint8_t ret = 0xff; /* unused bits must be '1' as per I.460 */

	for (i = 0; i < ARRAY_SIZE(ts->schan); i++) {
		struct osmo_i460_subchan *schan = &ts->schan[i];
		uint8_t bits, mask;

		if (schan->rate == OSMO_I460_RATE_NONE)
			continue;
		count++;
		bits = mux_subchan_provide_bits(schan, &mask);
		ret &= ~mask;
		ret |= bits;
	}

	return ret;
}


/*! Data from E1 timeslot into de-multiplexer
 *  \param[in] ts timeslot state
 *  \param[out] out caller-provided buffer where to store generated output bytes
 *  \param[in] out_len number of bytes to be stored at out
 */
int osmo_i460_mux_out(struct osmo_i460_timeslot *ts, uint8_t *out, size_t out_len)
{
	int i;

	/* fast path if entire 64k slot is used */
	//if (osmo_i460_has_single_64k_schan(ts)) { }

	for (i = 0; i < out_len; i++)
		out[i] = mux_timeslot_provide_bits(ts);

	return out_len;
}


/***********************************************************************
 * Initialization / Control
 ***********************************************************************/


static int alloc_bitbuf(void *ctx, struct osmo_i460_subchan *schan, size_t num_bits)
{
	struct osmo_i460_subchan_demux *demux = &schan->demux;

	talloc_free(demux->out_bitbuf);
	demux->out_bitbuf = talloc_zero_size(ctx, num_bits);
	if (!demux->out_bitbuf)
		return -ENOMEM;
	demux->out_bitbuf_size = num_bits;

	return 0;
}


static int find_unused_subchan_idx(const struct osmo_i460_timeslot *ts)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ts->schan); i++) {
		const struct osmo_i460_subchan *schan = &ts->schan[i];
		if (schan->rate == OSMO_I460_RATE_NONE)
			return i;
	}
	return -1;
}

/* reset subchannel struct into a defined state */
static void subchan_reset(struct osmo_i460_subchan *schan, bool first_time)
{
	/* Before we zero out the subchannel struct, we must be sure that the
	 * tx_queue is cleared and all dynamically allocated memory is freed.
	 * However, on an uninitalized subchannel struct we can not be sure
	 * that the pointers are valid. If the subchannel is reset the first
	 * time the caller must set first_time to true. */
	if (!first_time) {
		if (schan->demux.out_bitbuf)
			talloc_free(schan->demux.out_bitbuf);
		msgb_queue_free(&schan->mux.tx_queue);
	}

	/* Reset subchannel to a defined state */
	memset(schan, 0, sizeof(*schan));
	schan->rate = OSMO_I460_RATE_NONE;
	INIT_LLIST_HEAD(&schan->mux.tx_queue);
}

/*! initialize an I.460 timeslot */
void osmo_i460_ts_init(struct osmo_i460_timeslot *ts)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ts->schan); i++) {
		struct osmo_i460_subchan *schan = &ts->schan[i];
		schan->ts = ts;
		subchan_reset(schan, true);
	}
}

/*! add a new sub-channel to the given timeslot
 *  \param[in] ctx talloc context from where to allocate the internal buffer
 *  \param[in] ts timeslot to which to add a sub-channel
 *  \param[in] chd description of the sub-channel to be added
 *  \return pointer to sub-channel on success, NULL on error */
struct osmo_i460_subchan *
osmo_i460_subchan_add(void *ctx, struct osmo_i460_timeslot *ts, const struct osmo_i460_schan_desc *chd)
{
	struct osmo_i460_subchan *schan;
	int idx, rc;

	idx = find_unused_subchan_idx(ts);
	if (idx < 0)
		return NULL;

	schan = &ts->schan[idx];

	schan->rate = chd->rate;
	schan->bit_offset = chd->bit_offset;

	schan->demux.out_cb_bits = chd->demux.out_cb_bits;
	schan->demux.out_cb_bytes = chd->demux.out_cb_bytes;
	schan->demux.user_data = chd->demux.user_data;
	schan->mux.in_cb_queue_empty = chd->mux.in_cb_queue_empty;
	schan->mux.user_data = chd->mux.user_data;
	rc = alloc_bitbuf(ctx, schan, chd->demux.num_bits);
	if (rc < 0) {
		subchan_reset(schan, false);
		return NULL;
	}

	/* return number of schan in use */
	return schan;
}

/* remove a su-channel from the multiplex */
void osmo_i460_subchan_del(struct osmo_i460_subchan *schan)
{
	subchan_reset(schan, false);
}

/*! @} */
