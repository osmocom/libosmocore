/*! \file soft_uart.c
 *  Software UART implementation. */
/*
 * (C) 2022 by Harald Welte <laforge@gnumonks.org>
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

/*! Rx/Tx flow state of a soft-UART */
enum suart_flow_state {
	SUART_FLOW_ST_IDLE,	/*!< waiting for a start bit or Tx data */
	SUART_FLOW_ST_DATA,	/*!< receiving/transmitting data bits */
	SUART_FLOW_ST_PARITY,	/*!< receiving/transmitting parity bits */
	SUART_FLOW_ST_STOP,	/*!< receiving/transmitting stop bits */
};

/*! Internal state of a soft-UART */
struct osmo_soft_uart {
	struct osmo_soft_uart_cfg cfg;
	const char *name;
	struct {
		bool running;
		uint8_t bit_count;
		uint8_t shift_reg;
		struct msgb *msg;
		ubit_t parity_bit; /* 0 (even) / 1 (odd) */
		unsigned int flags;
		unsigned int status;
		struct osmo_timer_list timer;
		enum suart_flow_state flow_state;
	} rx;
	struct {
		bool running;
		uint8_t bit_count;
		uint8_t shift_reg;
		ubit_t parity_bit; /* 0 (even) / 1 (odd) */
		enum suart_flow_state flow_state;
	} tx;
};

/*! Default soft-UART configuration (8-N-1) */
const struct osmo_soft_uart_cfg osmo_soft_uart_default_cfg = {
	.num_data_bits = 8,
	.num_stop_bits = 1,
	.parity_mode = OSMO_SUART_PARITY_NONE,
	.rx_buf_size = 1024,
	.rx_timeout_ms = 100,
};

/*************************************************************************
 * Receiver
 *************************************************************************/

/* flush the receive buffer + allocate new one, as needed */
static void suart_flush_rx(struct osmo_soft_uart *suart)
{
	if ((suart->rx.msg && msgb_length(suart->rx.msg)) || suart->rx.flags) {
		osmo_timer_del(&suart->rx.timer);
		if (suart->cfg.rx_cb) {
			suart->cfg.rx_cb(suart->cfg.priv, suart->rx.msg, suart->rx.flags);
			/* call-back has taken ownership of msgb, no need to free() here */
			suart->rx.msg = msgb_alloc_c(suart, suart->cfg.rx_buf_size, "soft_uart_rx");
		} else {
			msgb_reset(suart->rx.msg);
		}
	}
}

/* one character was received; add to receive buffer and notify user, if needed */
static void suart_rx_ch(struct osmo_soft_uart *suart, uint8_t ch)
{
	unsigned int msg_len;

	OSMO_ASSERT(suart->rx.msg);
	msgb_put_u8(suart->rx.msg, ch);
	msg_len = msgb_length(suart->rx.msg);

	/* first character in new message: start timer */
	if (msg_len == 1) {
		osmo_timer_schedule(&suart->rx.timer, suart->cfg.rx_timeout_ms / 1000,
				    (suart->cfg.rx_timeout_ms % 1000) * 1000);
	} else if (msg_len >= suart->cfg.rx_buf_size || suart->rx.flags) {
		suart_flush_rx(suart);
	}
}

/* receive a single bit */
static inline void osmo_uart_rx_bit(struct osmo_soft_uart *suart, const ubit_t bit)
{
	if (!suart->rx.running)
		return;

	switch (suart->rx.flow_state) {
	case SUART_FLOW_ST_IDLE:
		if (bit == 0) { /* start bit condition */
			suart->rx.flow_state = SUART_FLOW_ST_DATA;
			suart->rx.flags = 0x00;
			suart->rx.shift_reg = 0;
			suart->rx.bit_count = 0;
			suart->rx.parity_bit = 0;
		}
		break;
	case SUART_FLOW_ST_DATA:
		suart->rx.bit_count++;
		suart->rx.shift_reg >>= 1;
		if (bit != 0) {
			suart->rx.parity_bit = !suart->rx.parity_bit; /* flip */
			suart->rx.shift_reg |= 0x80;
		}
		if (suart->rx.bit_count >= suart->cfg.num_data_bits) {
			/* we have accumulated enough data bits */
			if (suart->cfg.parity_mode != OSMO_SUART_PARITY_NONE)
				suart->rx.flow_state = SUART_FLOW_ST_PARITY;
			else
				suart->rx.flow_state = SUART_FLOW_ST_STOP;
		}
		break;
	case SUART_FLOW_ST_PARITY:
		switch (suart->cfg.parity_mode) {
		case OSMO_SUART_PARITY_EVEN:
			/* number of 1-bits (in both data and parity) shall be even */
			if (suart->rx.parity_bit != bit)
				suart->rx.flags |= OSMO_SUART_F_PARITY_ERROR;
			break;
		case OSMO_SUART_PARITY_ODD:
			/* number of 1-bits (in both data and parity) shall be odd */
			if (suart->rx.parity_bit == bit)
				suart->rx.flags |= OSMO_SUART_F_PARITY_ERROR;
			break;
		case OSMO_SUART_PARITY_NONE: /* shall not happen */
		default:
			OSMO_ASSERT(0);
		}

		suart->rx.flow_state = SUART_FLOW_ST_STOP;
		break;
	case SUART_FLOW_ST_STOP:
		suart->rx.bit_count++;
		if (bit != 1)
			suart->rx.flags |= OSMO_SUART_F_FRAMING_ERROR;

		if (suart->rx.bit_count >= (suart->cfg.num_data_bits + suart->cfg.num_stop_bits)) {
			/* we have accumulated enough stop bits */
			suart_rx_ch(suart, suart->rx.shift_reg);
			suart->rx.flow_state = SUART_FLOW_ST_IDLE;
		}
		break;
	}
}

/* receive timer expiration: flush rx-buffer to user call-back */
static void suart_rx_timer_cb(void *data)
{
	struct osmo_soft_uart *suart = data;
	suart_flush_rx(suart);
}

/*! Feed a number of unpacked bits into the soft-UART receiver.
 * \param[in] suart soft-UART instance to feed bits into.
 * \param[in] ubits pointer to the unpacked bits.
 * \param[in] n_ubits number of unpacked bits to be fed.
 * \returns 0 on success; negative on error. */
int osmo_soft_uart_rx_ubits(struct osmo_soft_uart *suart, const ubit_t *ubits, size_t n_ubits)
{
	for (size_t i = 0; i < n_ubits; i++)
		osmo_uart_rx_bit(suart, ubits[i]);
	return 0;
}

/*************************************************************************
 * Transmitter
 *************************************************************************/

/* pull a single bit out of the UART transmitter */
static inline ubit_t osmo_uart_tx_bit(struct osmo_soft_uart *suart, struct msgb *msg)
{
	ubit_t tx_bit = 1;

	if (!suart->tx.running)
		return tx_bit;

	switch (suart->tx.flow_state) {
	case SUART_FLOW_ST_IDLE:
		if (msgb_length(msg) > 0) { /* if we have pending data */
			suart->tx.shift_reg = msgb_pull_u8(msg);
			suart->tx.flow_state = SUART_FLOW_ST_DATA;
			suart->tx.bit_count = 0;
			suart->tx.parity_bit = 0;
			tx_bit = 0;
		}
		break;
	case SUART_FLOW_ST_DATA:
		tx_bit = suart->tx.shift_reg & 1;
		suart->tx.parity_bit ^= tx_bit;
		suart->tx.shift_reg >>= 1;
		suart->tx.bit_count++;
		if (suart->tx.bit_count >= suart->cfg.num_data_bits) {
			/* we have transmitted all data bits */
			if (suart->cfg.parity_mode != OSMO_SUART_PARITY_NONE)
				suart->tx.flow_state = SUART_FLOW_ST_PARITY;
			else
				suart->tx.flow_state = SUART_FLOW_ST_STOP;
		}
		break;
	case SUART_FLOW_ST_PARITY:
		switch (suart->cfg.parity_mode) {
		case OSMO_SUART_PARITY_EVEN:
			/* number of 1-bits (in both data and parity) shall be even */
			tx_bit = suart->tx.parity_bit;
			break;
		case OSMO_SUART_PARITY_ODD:
			/* number of 1-bits (in both data and parity) shall be odd */
			tx_bit = !suart->tx.parity_bit;
			break;
		case OSMO_SUART_PARITY_NONE:
		default: /* shall not happen */
			OSMO_ASSERT(0);
		}

		suart->tx.flow_state = SUART_FLOW_ST_STOP;
		break;
	case SUART_FLOW_ST_STOP:
		suart->tx.bit_count++;
		if (suart->tx.bit_count >= (suart->cfg.num_data_bits + suart->cfg.num_stop_bits)) {
			/* we have transmitted all stop bits, we're done */
			suart->tx.flow_state = SUART_FLOW_ST_IDLE;
		}
		break;
	}

	return tx_bit;
}

/*! Pull a number of unpacked bits out of the soft-UART transmitter.
 * \param[in] suart soft-UART instance to pull the bits from.
 * \param[out] ubits pointer to a buffer where to store pulled bits.
 * \param[in] n_ubits number of unpacked bits to be pulled.
 * \returns number of unpacked bits pulled; negative on error. */
int osmo_soft_uart_tx_ubits(struct osmo_soft_uart *suart, ubit_t *ubits, size_t n_ubits)
{
	const struct osmo_soft_uart_cfg *cfg = &suart->cfg;
	size_t n_frame_bits;
	struct msgb *msg;

	/* calculate UART frame size for the effective config */
	n_frame_bits = 1 + cfg->num_data_bits + cfg->num_stop_bits;
	if (cfg->parity_mode != OSMO_SUART_PARITY_NONE)
		n_frame_bits += 1;

	/* allocate a Tx buffer msgb */
	msg = msgb_alloc_c(suart, n_ubits / n_frame_bits, "soft_uart_tx");
	OSMO_ASSERT(msg != NULL);

	/* call the .tx_cb() to populate the Tx buffer */
	OSMO_ASSERT(cfg->tx_cb != NULL);
	suart->cfg.tx_cb(cfg->priv, msg);

	for (size_t i = 0; i < n_ubits; i++)
		ubits[i] = osmo_uart_tx_bit(suart, msg);
	msgb_free(msg);

	return 0;
}

/*! Set the modem status lines of the given soft-UART.
 * \param[in] suart soft-UART instance to update the modem status.
 * \param[in] status mask of osmo_soft_uart_status.
 * \returns 0 on success; negative on error. */
int osmo_soft_uart_set_status(struct osmo_soft_uart *suart, unsigned int status)
{
	/* FIXME: Tx */
	return 0;
}


/*************************************************************************
 * Management / Initialization
 *************************************************************************/

/*! Allocate a soft-UART instance.
 * \param[in] ctx parent talloc context.
 * \param[in] name name of the soft-UART instance.
 * \param[in] cfg initial configuration of the soft-UART instance.
 * \returns pointer to allocated soft-UART instance; NULL on error. */
struct osmo_soft_uart *osmo_soft_uart_alloc(void *ctx, const char *name,
					    const struct osmo_soft_uart_cfg *cfg)
{
	struct osmo_soft_uart *suart = talloc_zero(ctx, struct osmo_soft_uart);
	if (!suart)
		return NULL;
	suart->name = talloc_strdup(suart, name);

	OSMO_ASSERT(cfg != NULL);
	suart->cfg = *cfg;

	return suart;
}

/*! Release memory taken by the given soft-UART.
 * \param[in] suart soft-UART instance to be free()d. */
void osmo_soft_uart_free(struct osmo_soft_uart *suart)
{
	if (suart == NULL)
		return;

	osmo_timer_del(&suart->rx.timer);
	msgb_free(suart->rx.msg);

	talloc_free((void *)suart->name);
	talloc_free(suart);
}

/*! Change soft-UART configuration to the user-provided config.
 * \param[in] suart soft-UART instance to be re-configured.
 * \param[in] cfg the user-provided config to be applied.
 * \returns 0 on success; negative on error. */
int osmo_soft_uart_configure(struct osmo_soft_uart *suart, const struct osmo_soft_uart_cfg *cfg)
{
	/* consistency checks on the configuration */
	if (cfg->num_data_bits > 8 || cfg->num_data_bits == 0)
		return -EINVAL;
	if (cfg->num_stop_bits == 0)
		return -EINVAL;
	if (cfg->parity_mode < 0 || cfg->parity_mode >= _OSMO_SUART_PARITY_NUM)
		return -EINVAL;
	if (cfg->rx_buf_size == 0)
		return -EINVAL;

	if (suart->cfg.rx_buf_size > cfg->rx_buf_size ||
	    suart->cfg.rx_timeout_ms > cfg->rx_timeout_ms) {
		suart_flush_rx(suart);
	}

	suart->cfg = *cfg;

	osmo_timer_setup(&suart->rx.timer, suart_rx_timer_cb, suart);

	return 0;
}

/*! Enable/disable receiver of the given soft-UART.
 * \param[in] suart soft-UART instance to be re-configured.
 * \param[in] enable enable/disable state of the receiver.
 * \returns 0 on success; negative on error. */
int osmo_soft_uart_set_rx(struct osmo_soft_uart *suart, bool enable)
{
	if (!enable && suart->rx.running) {
		suart_flush_rx(suart);
		suart->rx.running = false;
		suart->rx.flow_state = SUART_FLOW_ST_IDLE;
	} else if (enable && !suart->rx.running) {
		if (!suart->rx.msg)
			suart->rx.msg = msgb_alloc_c(suart, suart->cfg.rx_buf_size, "soft_uart rx");
		suart->rx.running = true;
		suart->rx.flow_state = SUART_FLOW_ST_IDLE;
	}

	return 0;
}

/*! Enable/disable transmitter of the given soft-UART.
 * \param[in] suart soft-UART instance to be re-configured.
 * \param[in] enable enable/disable state of the transmitter.
 * \returns 0 on success; negative on error. */
int osmo_soft_uart_set_tx(struct osmo_soft_uart *suart, bool enable)
{
	if (!enable && suart->tx.running) {
		suart->tx.running = false;
		suart->tx.flow_state = SUART_FLOW_ST_IDLE;
	} else if (enable && !suart->tx.running) {
		suart->tx.running = true;
		suart->tx.flow_state = SUART_FLOW_ST_IDLE;
	}

	return 0;
}
