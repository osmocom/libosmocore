#pragma once

/*! \file soft_uart.h
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

#include <stdint.h>
#include <osmocom/core/bits.h>
#include <osmocom/core/msgb.h>

/*! Parity mode.
 * https://en.wikipedia.org/wiki/Parity_bit */
enum osmo_soft_uart_parity_mode {
	OSMO_SUART_PARITY_NONE,		/*!< No parity bit */
	OSMO_SUART_PARITY_EVEN,		/*!< Even parity */
	OSMO_SUART_PARITY_ODD,		/*!< Odd parity */
	OSMO_SUART_PARITY_MARK,		/*!< Always 1 */
	OSMO_SUART_PARITY_SPACE,	/*!< Always 0 */
	_OSMO_SUART_PARITY_NUM
};

/*! Flags passed to the application. */
enum osmo_soft_uart_flags {
	OSMO_SUART_F_FRAMING_ERROR	= (1 << 0),	/*!< Framing error occurred */
	OSMO_SUART_F_PARITY_ERROR	= (1 << 1),	/*!< Parity error occurred */
	OSMO_SUART_F_BREAK		= (1 << 2),	/*!< Break condition (not implemented) */
};

#if 0
enum osmo_soft_uart_status {
	/* RTS, CTS, ... */
	_fixme,
};
#endif

/*! Configuration for a soft-UART. */
struct osmo_soft_uart_cfg {
	/*! Number of data bits (typically 5, 6, 7 or 8). */
	uint8_t num_data_bits;
	/*! Number of stop bits (typically 1 or 2). */
	uint8_t num_stop_bits;
	/*! Parity mode (none, even, odd, space, mark). */
	enum osmo_soft_uart_parity_mode parity_mode;
	/*! Size of the receive buffer; UART will buffer up to that number
	 * of characters before calling the receive call-back. */
	unsigned int rx_buf_size;
	/*! Receive timeout; UART will flush the receive buffer via the receive call-back
	 * after indicated number of milliseconds, even if it is not full yet. */
	unsigned int rx_timeout_ms;

	/*! Opaque application-private data; passed to call-backs. */
	void *priv;

	/*! Receive call-back of the application.
	 *
	 * Called if at least one of the following conditions is met:
	 * a) rx_buf_size characters were received (Rx buffer is full);
	 * b) rx_timeout_ms expired and Rx buffer is not empty;
	 * c) a parity or framing error is occurred.
	 *
	 * \param[in] priv opaque application-private data.
	 * \param[in] rx_data msgb holding the received data.
	 *                    Must be free()ed by the application.
	 * \param[in] flags bit-mask of OSMO_SUART_F_*. */
	void (*rx_cb)(void *priv, struct msgb *rx_data, unsigned int flags);

	/*! Transmit call-back of the application.
	 *
	 * The implementation is expected to provide at most tx_data->data_len
	 * characters (the actual amount is determined by the number of requested
	 * bits and the effective UART configuration).
	 *
	 * \param[in] priv opaque application-private data.
	 * \param[inout] tx_data msgb for writing to be transmitted data. */
	void (*tx_cb)(void *priv, struct msgb *tx_data);

	/*! Modem status line change call-back.
	 *
	 * FIXME: flow control is not implemented, so it's never called.
	 *
	 * \param[in] priv opaque application-private data.
	 * \param[in] status bit-mask of osmo_soft_uart_status. */
	void (*status_change_cb)(void *priv, unsigned int status);
};

extern const struct osmo_soft_uart_cfg osmo_soft_uart_default_cfg;

struct osmo_soft_uart;

struct osmo_soft_uart *osmo_soft_uart_alloc(void *ctx, const char *name,
					    const struct osmo_soft_uart_cfg *cfg);
void osmo_soft_uart_free(struct osmo_soft_uart *suart);
int osmo_soft_uart_configure(struct osmo_soft_uart *suart, const struct osmo_soft_uart_cfg *cfg);

const char *osmo_soft_uart_get_name(const struct osmo_soft_uart *suart);
void osmo_soft_uart_set_name(struct osmo_soft_uart *suart, const char *name);

int osmo_soft_uart_set_rx(struct osmo_soft_uart *suart, bool enable);
int osmo_soft_uart_set_tx(struct osmo_soft_uart *suart, bool enable);

int osmo_soft_uart_rx_ubits(struct osmo_soft_uart *suart, const ubit_t *ubits, size_t n_ubits);
int osmo_soft_uart_tx_ubits(struct osmo_soft_uart *suart, ubit_t *ubits, size_t n_ubits);

int osmo_soft_uart_set_status(struct osmo_soft_uart *suart, unsigned int status);
void osmo_soft_uart_flush_rx(struct osmo_soft_uart *suart);
