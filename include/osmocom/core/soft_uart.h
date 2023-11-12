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

enum osmo_soft_uart_parity_mode {
	OSMO_SUART_PARITY_NONE,
	OSMO_SUART_PARITY_EVEN,
	OSMO_SUART_PARITY_ODD,
	_OSMO_SUART_PARITY_NUM
};

enum osmo_soft_uart_flags {
	OSMO_SUART_F_FRAMING_ERROR	= (1 << 0),
	OSMO_SUART_F_PARITY_ERROR	= (1 << 1),
	OSMO_SUART_F_BREAK		= (1 << 2),
};

#if 0
enum osmo_soft_uart_status {
	/* RTS, CTS, ... */
	_fixme,
};
#endif

/* configuration for a soft-uart */
struct osmo_soft_uart_cfg {
	/*! number of data bits (typically 5, 6, 7 or 8) */
	uint8_t num_data_bits;
	/*! number of stop bots (typically 1 or 2) */
	uint8_t num_stop_bits;
	/*! parity mode (none, even, odd) */
	enum osmo_soft_uart_parity_mode parity_mode;
	/*! size of receive buffer; UART will buffer up to that number of characters
	 *  before calling the receive call-back */
	unsigned int rx_buf_size;
	/*! receive timeout; UART will flush receive buffer via the receive call-back
	 * after indicated number of milli-seconds even if it is not full yet */
	unsigned int rx_timeout_ms;

	/*! opaque application-private data; passed to call-backs */
	void *priv;

	/*! receive call-back. Either rx_buf_size characters were received or rx_timeout_ms
	 * expired, or an error flag was detected (related to last byte received).
	 * 'flags' is a bit-mask of osmo_soft_uart_flags,  */
	void (*rx_cb)(void *priv, struct msgb *rx_data, unsigned int flags);

	/*! modem status line change call-back. gets bitmask of osmo_soft_uart_status */
	void (*status_change_cb)(void *priv, unsigned int status);
};

struct osmo_soft_uart;

struct osmo_soft_uart *osmo_soft_uart_alloc(void *ctx, const char *name);
void osmo_soft_uart_free(struct osmo_soft_uart *suart);
int osmo_soft_uart_configure(struct osmo_soft_uart *suart, const struct osmo_soft_uart_cfg *cfg);
int osmo_soft_uart_enable(struct osmo_soft_uart *suart, bool rx, bool tx);

int osmo_soft_uart_rx_ubits(struct osmo_soft_uart *suart, const ubit_t *ubits, size_t n_ubits);
int osmo_soft_uart_tx_ubits(struct osmo_soft_uart *suart, ubit_t *ubits, size_t n_ubits);

void osmo_soft_uart_tx(struct osmo_soft_uart *suart, struct msgb *tx_data);
int osmo_soft_uart_set_status(struct osmo_soft_uart *suart, unsigned int status);
