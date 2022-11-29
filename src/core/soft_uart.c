/*! \file soft_uart.c
 *  Software UART implementation. */
/*
 * (C) 2022 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/timer.h>
#include <osmocom/core/soft_uart.h>

/*! one instance of a soft-uart */
struct osmo_soft_uart {
	struct osmo_soft_uart_cfg cfg;
	const char *name;
	struct {
		bool running;
		uint8_t bit_count;
		uint8_t shift_reg;
		struct msgb *msg;
		ubit_t parity_bit;
		unsigned int flags;
		unsigned int status;
		struct osmo_timer_list timer;
	} rx;
	struct {
		bool running;
		uint8_t bit_count;
		uint8_t shift_reg;
		struct msgb *msg;
		struct llist_head queue;
	} tx;
};

static struct osmo_soft_uart_cfg suart_default_cfg = {
	.num_data_bits = 8,
	.num_stop_bits = 1,
	.parity_mode = OSMO_SUART_PARITY_NONE,
	.rx_buf_size = 1024,
	.rx_timeout_ms = 100,
	.priv = NULL,
	.rx_cb = NULL,
	.status_change_cb = NULL,
};

/*************************************************************************
 * Receiver
 *************************************************************************/

/* flush the receive buffer + allocate new one, as needed */
static void suart_flush_rx(struct osmo_soft_uart *sua)
{
	if ((sua->rx.msg && msgb_length(sua->rx.msg)) || sua->rx.flags) {
		osmo_timer_del(&sua->rx.timer);
		if (sua->cfg.rx_cb) {
			sua->cfg.rx_cb(sua->cfg.priv, sua->rx.msg, sua->rx.flags);
			/* call-back has taken ownership of msgb, no need to free() here */
			sua->rx.msg = msgb_alloc_c(sua, sua->cfg.rx_buf_size, "soft_uart rx");
		} else {
			msgb_reset(sua->rx.msg);
		}
	}
}

/* one character was received; add to receive buffer and notify user, if needed */
static void suart_rx_ch(struct osmo_soft_uart *sua, uint8_t ch)
{
	unsigned int msg_len;

	OSMO_ASSERT(sua->rx.msg);
	msgb_put_u8(sua->rx.msg, ch);
	msg_len = msgb_length(sua->rx.msg);

	/* first character in new message: start timer */
	if (msg_len == 1) {
		osmo_timer_schedule(&sua->rx.timer, sua->cfg.rx_timeout_ms/1000,
				    (sua->cfg.rx_timeout_ms % 1000) * 1000);
	} else if (msg_len >= sua->cfg.rx_buf_size || sua->rx.flags) {
		suart_flush_rx(sua);
	}
}

/* receive a single bit */
static inline void osmo_uart_rx_bit(struct osmo_soft_uart *sua, const ubit_t bit)
{
	unsigned int num_parity_bits = 0;

	if (!sua->rx.running)
		return;

	if (sua->rx.bit_count == 0) {
		/* start bit is 0.  Wait if there is none */
		if (bit == 0) {
			/* START bit */
			sua->rx.flags = 0;
			sua->rx.shift_reg = 0;
			sua->rx.bit_count++;
		}
		return;
	}

	if (sua->cfg.parity_mode != OSMO_SUART_PARITY_NONE)
		num_parity_bits = 1;

	sua->rx.bit_count++;
	if (sua->rx.bit_count <= 1 + sua->cfg.num_data_bits) {
		/* DATA bit */
		sua->rx.shift_reg = sua->rx.shift_reg >> 1;
		if (bit)
			sua->rx.shift_reg |= 0x80;
	} else if (sua->cfg.parity_mode != OSMO_SUART_PARITY_NONE &&
		   sua->rx.bit_count == 1 + sua->cfg.num_data_bits + 1) {
		/* PARITY bit */
		sua->rx.parity_bit = bit;
		/* TODO: verify parity */
		//sua->rx.flags |= OSMO_SUART_F_PARITY_ERROR;
	} else if (sua->rx.bit_count <=
		   1 + sua->cfg.num_data_bits + num_parity_bits + sua->cfg.num_stop_bits) {
		/* STOP bit */
		if (bit != 1) {
			fprintf(stderr, "framing error: stop bit %u != 1\n", sua->rx.bit_count);
			sua->rx.flags |= OSMO_SUART_F_FRAMING_ERROR;
		}

		if (sua->rx.bit_count == 1 + sua->cfg.num_data_bits + num_parity_bits + sua->cfg.num_stop_bits) {
			//printf("Rx: 0x%02x %c\n", sua->rx.shift_reg, sua->rx.shift_reg);
			suart_rx_ch(sua, sua->rx.shift_reg);
			sua->rx.bit_count = 0;
		}
	}
}

/* receive timer expiration: flush rx-buffer to user call-back */
static void suart_rx_timer_cb(void *data)
{
	struct osmo_soft_uart *suart = data;
	suart_flush_rx(suart);
}

/*! feed a number of unpacked bits into the soft-uart receiver */
int osmo_soft_uart_rx_ubits(struct osmo_soft_uart *sua, const ubit_t *ubits, size_t n_ubits)
{
	for (size_t i = 0; i < n_ubits; i++) {
		osmo_uart_rx_bit(sua, ubits[i]);
	}
	return 0;
}

/*************************************************************************
 * Transmitter
 *************************************************************************/

/*! enqueue the given message buffer into the transmit queue of the UART. */
void osmo_soft_uart_tx(struct osmo_soft_uart *sua, struct msgb *tx_data)
{
	if (!sua->tx.msg)
		sua->tx.msg = tx_data;
	else
		msgb_enqueue(&sua->tx.queue, tx_data);
}

/* pull a single bit out of the UART transmitter */
static inline ubit_t osmo_uart_tx_bit(struct osmo_soft_uart *sua)
{
	if (!sua->tx.running)
		return 1;

	if (sua->tx.bit_count == 0) {
		/* do we have anything to transmit? */
		/* FIXME */
	}
	/* FIXME */
	return 1;
}

/*! pull then number of specified unpacked bits out of the UART Transmitter */
int osmo_soft_uart_tx_ubits(struct osmo_soft_uart *sua, ubit_t *ubits, size_t n_ubits)
{
	for (size_t i = 0; i < n_ubits; i++) {
		ubits[i] = osmo_uart_tx_bit(sua);
	}
	return n_ubits;
}

/*! Set the modem status lines of the UART */
int osmo_soft_uart_set_status(struct osmo_soft_uart *sua, unsigned int status)
{
	/* FIXME: Tx */
	return 0;
}


/*************************************************************************
 * Management / Initialization
 *************************************************************************/

struct osmo_soft_uart *osmo_soft_uart_alloc(void *ctx, const char *name)
{
	struct osmo_soft_uart *suart = talloc_zero(ctx, struct osmo_soft_uart);
	if (!suart)
		return NULL;
	suart->name = talloc_strdup(suart, name);
	suart->cfg = suart_default_cfg;

	return suart;
}

/*! change soft-UART configuration to user-provided config */
int osmo_soft_uart_configure(struct osmo_soft_uart *suart, const struct osmo_soft_uart_cfg *cfg)
{
	/* consistency checks on the configuration */
	if (cfg->num_data_bits > 8 || cfg->num_data_bits == 0)
		return -EINVAL;
	if (cfg->num_stop_bits == 0)
		return -EINVAL;
	if (cfg->parity_mode < 0 || cfg->parity_mode >= NUM_OSMO_SUART_PARITY)
		return -EINVAL;
	if (cfg->rx_buf_size == 0)
		return -EINVAL;

	if (suart->cfg.rx_buf_size > cfg->rx_buf_size ||
	    suart->cfg.rx_timeout_ms > cfg->rx_timeout_ms) {
		suart_flush_rx(suart);
	}

	suart->cfg = *cfg;

	osmo_timer_setup(&suart->rx.timer, suart_rx_timer_cb, suart);
	INIT_LLIST_HEAD(&suart->tx.queue);

	return 0;
}

int osmo_soft_uart_enable(struct osmo_soft_uart *suart, bool rx, bool tx)
{
	if (!rx && suart->rx.running) {
		suart_flush_rx(suart);
		suart->rx.running = false;
	} else if (rx && !suart->rx.running) {
		if (!suart->rx.msg)
			suart->rx.msg = msgb_alloc_c(suart, suart->cfg.rx_buf_size, "soft_uart rx");
		suart->rx.running = true;
	}

	if (!tx && suart->tx.running) {
		/* FIXME: Tx */
		suart->tx.running = false;
	} else if (tx && !suart->tx.running) {
		suart->tx.running = true;
	}

	return 0;
}
