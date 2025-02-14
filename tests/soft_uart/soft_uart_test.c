/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Vadim Yanitskiy <vyanitskiy@sysmocom.de>
 *
 * All Rights Reserved
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

#include <errno.h>
#include <stdio.h>
#include <stdint.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/soft_uart.h>

#define SUART_TEST_BEGIN \
	do { \
		printf("\nExecuting %s\n", __func__); \
	} while (0)

static struct {
	size_t data_len;
	const uint8_t *data;
} g_tx_cb_cfg;

static void suart_rx_cb(void *priv, struct msgb *msg, unsigned int flags)
{
	fprintf(stdout, "%s(flags=%02x): %s\n",
		__func__, flags, msgb_hexdump(msg));
	msgb_free(msg);
}

static void suart_tx_cb(void *priv, struct msgb *msg)
{
	size_t n_bytes;

	n_bytes = OSMO_MIN(g_tx_cb_cfg.data_len, msg->data_len);
	if (g_tx_cb_cfg.data != NULL && n_bytes > 0)
		memcpy(msgb_put(msg, n_bytes), g_tx_cb_cfg.data, n_bytes);

	fprintf(stdout, "%s(len=%u/%u): %s\n",
		__func__, msg->len, msg->data_len, msgb_hexdump(msg));
}

static void suart_status_change_cb(void *priv, unsigned int status)
{
	fprintf(stdout, "%s(status=0x%08x)\n", __func__, status);
}

static const struct osmo_soft_uart_cfg suart_test_default_cfg = {
	.num_data_bits = 8,
	.num_stop_bits = 1,
	.parity_mode = OSMO_SUART_PARITY_NONE,
	.rx_buf_size = 128,
	.rx_cb = &suart_rx_cb,
	.tx_cb = &suart_tx_cb,
	.status_change_cb = &suart_status_change_cb,
};

static void test_rx_exec(struct osmo_soft_uart *suart,
			 const char *input)
{
	for (unsigned int i = 0; input[i] != '\0'; i++) {
		ubit_t ubit;
		int rc;

		switch (input[i]) {
		case '0':
		case '1':
			ubit = input[i] - '0';
			rc = osmo_soft_uart_rx_ubits(suart, &ubit, 1);
			OSMO_ASSERT(rc == 0); /* 0 on success */
			break;
		case 'F':
			printf("%s() @ %u: flush the Rx buffer\n", __func__, i);
			osmo_soft_uart_flush_rx(suart);
			break;
		case ' ': /* padding */
			continue;
		default:
			printf("%s() @ %u: unknown opcode '%c'\n",
			       __func__, i, input[i]);
			break;
		}
	}
}

static void test_rx(void)
{
	struct osmo_soft_uart_cfg cfg;
	struct osmo_soft_uart *suart;

	SUART_TEST_BEGIN;

	suart = osmo_soft_uart_alloc(NULL, __func__, &suart_test_default_cfg);
	OSMO_ASSERT(suart != NULL);

	osmo_soft_uart_set_rx(suart, true);

	printf("======== testing 8-N-1 (no data)\n");
	test_rx_exec(suart, "F11111F11111F");

	printf("======== testing 8-N-1 (fill up flush)\n");
	cfg = suart_test_default_cfg;
	cfg.rx_buf_size = 4;
	osmo_soft_uart_configure(suart, &cfg);
	test_rx_exec(suart, "11111" /* no data */
		     "0 01111011 1"
		     "0 10110101 1"
		     "0 01111101 1"
		     "0 11110111 1" /* filled up, expect flush */
		     "0 00000000 1"
		     "0 01010101 1"
		     "0 10101010 1"
		     "0 11111111 1" /* filled up, expect flush */
		     "F" /* flush! (for sanity) */
		     );

	printf("======== testing 8-N-1 (HELLO)\n");
	cfg = suart_test_default_cfg;
	cfg.num_stop_bits = 1;
	osmo_soft_uart_configure(suart, &cfg);
	test_rx_exec(suart, "111111" /* no data */
		     "0 00010010 1F" /* 'H', flush! */
		     "0 10100010 1F" /* 'E', flush! */
		     "1111111111111" /* no data */
		     "0 00110010 1F" /* 'L', flush! */
		     "0 00110010 1F" /* 'L', flush! */
		     "1111111111111" /* no data */
		     "0 11110010 1F" /* 'O', flush! */
		     );

	printf("======== testing 8-N-1 (framing errors)\n");
	test_rx_exec(suart, "11111" /* no data */
		     "0 00000000 0" /* stop bit != 1, expect flush */
		     "0 01010101 0" /* stop bit != 1, expect flush */
		     "0 11111111 1" /* stop bit == 1, recovery */
		     "F" /* flush! */
		     );

	printf("======== testing 8-N-2 (HELLO)\n");
	cfg = suart_test_default_cfg;
	cfg.num_stop_bits = 2;
	osmo_soft_uart_configure(suart, &cfg);
	test_rx_exec(suart, "11111111" /* no data */
		     "0 00010010 1F1F" /* 'H', flush! */
		     "0 10100010 1F1F" /* 'E', flush! */
		     "111111111111111" /* no data */
		     "0 00110010 1F1F" /* 'L', flush! */
		     "0 00110010 1F1F" /* 'L', flush! */
		     "111111111111111" /* no data */
		     "0 11110010 1F1F" /* 'O', flush! */
		     );

	printf("======== testing 8-N-2 (framing errors)\n");
	test_rx_exec(suart, "11111" /* no data */
		     "0 00000000 00" /* stop bit != 1, expect flush */
		     "0 01010101 01" /* stop bit != 1, expect flush */
		     "0 10101010 10" /* stop bit != 1, expect flush */
		     "0 11111111 11" /* stop bit == 1, recovery */
		     "F" /* flush! (for sanity) */
		     );


	printf("======== testing 8-E-1 (invalid parity)\n");
	cfg = suart_test_default_cfg;
	cfg.parity_mode = OSMO_SUART_PARITY_EVEN;
	osmo_soft_uart_configure(suart, &cfg);
	test_rx_exec(suart, "1111111" /* no data */
		     "0 00000000 1 1" /* odd parity, expect flush */
		     "0 10000000 0 1" /* odd parity, expect flush */
		     "0 11111111 1 1" /* odd parity, expect flush */
		     "F" /* flush! (for sanity) */
		     );
	printf("======== testing 8-E-1 (valid parity)\n");
	test_rx_exec(suart, "1111111" /* no data */
		     "0 00000000 0 1"
		     "0 11111111 0 1"
		     "0 01010101 0 1"
		     "0 10101010 0 1"
		     "F" /* flush! */
		     "0 00000001 1 1"
		     "0 00000111 1 1"
		     "0 00011111 1 1"
		     "0 01111111 1 1"
		     "F" /* flush! */
		     );

	printf("======== testing 8-O-1 (invalid parity)\n");
	cfg = suart_test_default_cfg;
	cfg.parity_mode = OSMO_SUART_PARITY_ODD;
	osmo_soft_uart_configure(suart, &cfg);
	test_rx_exec(suart,
		     "0 00000000 0 1" /* even parity, expect flush */
		     "0 10000000 1 1" /* even parity, expect flush */
		     "0 11111111 0 1" /* even parity, expect flush */
		     "F" /* flush! (for sanity) */
		     );
	printf("======== testing 8-O-1 (valid parity)\n");
	test_rx_exec(suart, "1111111" /* no data */
		     "0 00000000 1 1"
		     "0 11111111 1 1"
		     "0 01010101 1 1"
		     "0 10101010 1 1"
		     "F" /* flush! */
		     "0 00000001 0 1"
		     "0 00000111 0 1"
		     "0 00011111 0 1"
		     "0 01111111 0 1"
		     "F" /* flush! */
		     );

	osmo_soft_uart_free(suart);
}

static void test_rx_flush(void)
{
	struct osmo_soft_uart_cfg cfg;
	struct osmo_soft_uart *suart;

	SUART_TEST_BEGIN;

	suart = osmo_soft_uart_alloc(NULL, __func__, &suart_test_default_cfg);
	OSMO_ASSERT(suart != NULL);

	printf("calling osmo_soft_uart_flush_rx() while Rx disabled\n");
	osmo_soft_uart_flush_rx(suart);

	printf("enabling the receiver\n");
	osmo_soft_uart_set_rx(suart, true);

	printf("calling osmo_soft_uart_flush_rx() while Rx enabled, but no data\n");
	osmo_soft_uart_flush_rx(suart);

	/* FIXME: this scenario demonstrates a problem that may occur when the user
	 * flushes the Rx buffer manually while the soft-UART state reflects flags
	 * of an incomplete symbol, for which we're waiting the stop bit. */
	printf("testing corner case: manual flushing during a parity error (8-E-1)\n");
	cfg = suart_test_default_cfg;
	cfg.parity_mode = OSMO_SUART_PARITY_EVEN;
	osmo_soft_uart_configure(suart, &cfg);
	test_rx_exec(suart, "1111111" /* no data */
		     "0 01010101 0 1" /* even parity, correct */
		     "0 10101010 0 1" /* even parity, correct */
		     "0 11111111 1"   /* odd parity, incorrect, but stop bit is pending */
		     "F" /* manual flush happens before receiving the stop bit */
		     "1" /* finally, the stop bit is received */
		     );
	/* test_rx_exec() @ 47: flush the Rx buffer
	 * suart_rx_cb(flags=02): aa 55   <--- this is wrong, should be flags=00
	 * suart_rx_cb(flags=02): ff      <--- this is expected due to odd parity */


	osmo_soft_uart_free(suart);
}

static void test_tx_rx_exec_one(struct osmo_soft_uart *suart,
				size_t n_bits_total, size_t n_bits_frame)
{
	ubit_t tx_buf[n_bits_total];
	ubit_t *ptr = &tx_buf[0];
	int rc;

	rc = osmo_soft_uart_tx_ubits(suart, &tx_buf[0], n_bits_total);
	OSMO_ASSERT(rc == n_bits_total);

	rc = osmo_soft_uart_rx_ubits(suart, &tx_buf[0], n_bits_total);
	OSMO_ASSERT(rc == 0);
	osmo_soft_uart_flush_rx(suart);

	printf("%s(n_bits_total=%zu):", __func__, n_bits_total);
	while (n_bits_total > 0) {
		size_t n_bits = OSMO_MIN(n_bits_frame, n_bits_total);
		printf(" %s", osmo_ubit_dump(ptr, n_bits));
		n_bits_total -= n_bits;
		ptr += n_bits;
	}
	printf("\n");
}

static void test_tx_rx_exec(struct osmo_soft_uart *suart, size_t n_bits_frame)
{
	const uint8_t tx_data[][4] = {
		{ 0xde, 0xad, 0xbe, 0xef },
		{ 0x00, 0xaa, 0x55, 0xff },
		{ 0x01, 0x02, 0x04, 0x08 },
		{ 0x10, 0x20, 0x40, 0x80 },
	};

	for (size_t i = 0; i < ARRAY_SIZE(tx_data); i++) {
		g_tx_cb_cfg.data_len = 4;
		g_tx_cb_cfg.data = tx_data[i];
		test_tx_rx_exec_one(suart, 4 * n_bits_frame, n_bits_frame);
	}

	g_tx_cb_cfg.data_len = 0;
	g_tx_cb_cfg.data = NULL;
	test_tx_rx_exec_one(suart, 4 * n_bits_frame, n_bits_frame);
}

static void test_tx_rx(void)
{
	struct osmo_soft_uart_cfg cfg;
	struct osmo_soft_uart *suart;
	int rc;

	SUART_TEST_BEGIN;

	suart = osmo_soft_uart_alloc(NULL, __func__, &suart_test_default_cfg);
	OSMO_ASSERT(suart != NULL);

	/* expect -EAGAIN when the transmitter is not enabled */
	rc = osmo_soft_uart_tx_ubits(suart, NULL, 42);
	OSMO_ASSERT(rc == -EAGAIN);
	/* expect -EAGAIN when the receiver is not enabled */
	rc = osmo_soft_uart_rx_ubits(suart, NULL, 42);
	OSMO_ASSERT(rc == -EAGAIN);

	osmo_soft_uart_set_tx(suart, true);
	osmo_soft_uart_set_rx(suart, true);

	printf("======== testing 8-N-1\n");
	test_tx_rx_exec(suart, (1 + 8 + 1));

	printf("======== testing 8-N-2\n");
	cfg = suart_test_default_cfg;
	cfg.num_stop_bits = 2;
	osmo_soft_uart_configure(suart, &cfg);
	test_tx_rx_exec(suart, (1 + 8 + 2));

	printf("======== testing 8-E-1\n");
	cfg = suart_test_default_cfg;
	cfg.parity_mode = OSMO_SUART_PARITY_EVEN;
	osmo_soft_uart_configure(suart, &cfg);
	test_tx_rx_exec(suart, (1 + 8 + 1 + 1));

	printf("======== testing 8-O-1\n");
	cfg = suart_test_default_cfg;
	cfg.parity_mode = OSMO_SUART_PARITY_ODD;
	osmo_soft_uart_configure(suart, &cfg);
	test_tx_rx_exec(suart, (1 + 8 + 1 + 1));

	printf("======== testing 8-M-1\n");
	cfg = suart_test_default_cfg;
	cfg.parity_mode = OSMO_SUART_PARITY_MARK;
	osmo_soft_uart_configure(suart, &cfg);
	test_tx_rx_exec(suart, (1 + 8 + 1 + 1));

	printf("======== testing 8-S-1\n");
	cfg = suart_test_default_cfg;
	cfg.parity_mode = OSMO_SUART_PARITY_SPACE;
	osmo_soft_uart_configure(suart, &cfg);
	test_tx_rx_exec(suart, (1 + 8 + 1 + 1));

	printf("======== testing 6-N-1\n");
	cfg = suart_test_default_cfg;
	cfg.num_data_bits = 6;
	osmo_soft_uart_configure(suart, &cfg);
	test_tx_rx_exec(suart, (1 + 6 + 1));

	osmo_soft_uart_free(suart);
}

static void test_tx_rx_pull_n(unsigned int n)
{
	struct osmo_soft_uart *suart;
	ubit_t tx_buf[32];
	int rc;

	SUART_TEST_BEGIN;

	suart = osmo_soft_uart_alloc(NULL, __func__, &suart_test_default_cfg);
	OSMO_ASSERT(suart != NULL);

	osmo_soft_uart_set_tx(suart, true);
	osmo_soft_uart_set_rx(suart, true);

	g_tx_cb_cfg.data = (void *)"\x55";
	g_tx_cb_cfg.data_len = 1;

	printf("======== pulling %zu bits (%u at a time)\n", sizeof(tx_buf), n);
	for (unsigned int i = 0; i < sizeof(tx_buf); i += n) {
		rc = osmo_soft_uart_tx_ubits(suart, &tx_buf[i], n);
		OSMO_ASSERT(rc == n);
	}
	printf("%s\n", osmo_ubit_dump(&tx_buf[0], sizeof(tx_buf)));

	printf("======== feeding %zu bits into the receiver\n", sizeof(tx_buf));
	rc = osmo_soft_uart_rx_ubits(suart, &tx_buf[0], sizeof(tx_buf));
	OSMO_ASSERT(rc == 0);
	osmo_soft_uart_flush_rx(suart);

	osmo_soft_uart_free(suart);
}

static void test_modem_status(void)
{
	struct osmo_soft_uart *suart;
	unsigned int status;

	SUART_TEST_BEGIN;

	suart = osmo_soft_uart_alloc(NULL, __func__, &suart_test_default_cfg);
	OSMO_ASSERT(suart != NULL);

	printf("initial status=0x%08x\n", osmo_soft_uart_get_status(suart));

	printf("de-asserting DCD, which was not asserted\n");
	osmo_soft_uart_set_status_line(suart, OSMO_SUART_STATUS_F_DCD, false);
	OSMO_ASSERT(osmo_soft_uart_get_status(suart) == 0x00); /* no change */

	printf("asserting both RI and DCD, expecting the callback to be called twice\n");
	osmo_soft_uart_set_status_line(suart, OSMO_SUART_STATUS_F_RI, true);
	osmo_soft_uart_set_status_line(suart, OSMO_SUART_STATUS_F_DCD, true);
	status = osmo_soft_uart_get_status(suart);
	OSMO_ASSERT(status == (OSMO_SUART_STATUS_F_RI | OSMO_SUART_STATUS_F_DCD));

	printf("de-asserting RI, expecting the callback to be called\n");
	osmo_soft_uart_set_status_line(suart, OSMO_SUART_STATUS_F_RI, false);
	status = osmo_soft_uart_get_status(suart);
	OSMO_ASSERT(status == (OSMO_SUART_STATUS_F_DCD));

	printf("resetting to 0x00, expecting the callback to be called\n");
	osmo_soft_uart_set_status(suart, 0x00);
	OSMO_ASSERT(osmo_soft_uart_get_status(suart) == 0x00);

	osmo_soft_uart_free(suart);
}

static void test_flow_control_dtr_dsr(void)
{
	struct osmo_soft_uart_cfg cfg;
	struct osmo_soft_uart *suart;
	ubit_t tx_buf[40];
	int rc;

	SUART_TEST_BEGIN;

	g_tx_cb_cfg.data = (void *)"\x42\x42\x42\x42";
	g_tx_cb_cfg.data_len = 4;

	cfg = suart_test_default_cfg;
	cfg.flow_ctrl_mode = OSMO_SUART_FLOW_CTRL_DTR_DSR;

	suart = osmo_soft_uart_alloc(NULL, __func__, &cfg);
	OSMO_ASSERT(suart != NULL);

	osmo_soft_uart_set_tx(suart, true);
	osmo_soft_uart_set_rx(suart, true);

	/* expect the initial status to be 0 (all lines de-asserted) */
	printf("initial status=0x%08x\n", osmo_soft_uart_get_status(suart));

	memset(&tx_buf[0], 1, sizeof(tx_buf)); /* pre-initialize */

	printf("expecting osmo_soft_uart_tx_ubits() to yield nothing\n");
	rc = osmo_soft_uart_tx_ubits(suart, &tx_buf[0], sizeof(tx_buf));
	OSMO_ASSERT(rc == 0);

	printf("expecting osmo_soft_uart_rx_ubits() to yield nothing\n");
	rc = osmo_soft_uart_rx_ubits(suart, &tx_buf[0], sizeof(tx_buf));
	OSMO_ASSERT(rc == 0);
	osmo_soft_uart_flush_rx(suart);

	/* both DTR and DSR are asserted, expect both Rx and Tx to work */
	printf("======== asserting both DTR and DSR\n");
	osmo_soft_uart_set_status_line(suart, OSMO_SUART_STATUS_F_DTR, true);
	osmo_soft_uart_set_status_line(suart, OSMO_SUART_STATUS_F_DSR, true);

	memset(&tx_buf[0], 1, sizeof(tx_buf)); /* pre-initialize */

	printf("expecting osmo_soft_uart_tx_ubits() to "
	       "yield %zu bits (requesting %zu bits)\n",
	       sizeof(tx_buf), sizeof(tx_buf));
	rc = osmo_soft_uart_tx_ubits(suart, &tx_buf[0], sizeof(tx_buf));
	OSMO_ASSERT(rc == sizeof(tx_buf));
	printf("%s\n", osmo_ubit_dump(&tx_buf[0], sizeof(tx_buf)));

	printf("expecting osmo_soft_uart_rx_ubits() to "
	       "consume %zu bits and yield %zu chars\n",
	       sizeof(tx_buf), sizeof(tx_buf) / 10);
	rc = osmo_soft_uart_rx_ubits(suart, &tx_buf[0], sizeof(tx_buf));
	OSMO_ASSERT(rc == 0);
	osmo_soft_uart_flush_rx(suart);

	memset(&tx_buf[0], 1, sizeof(tx_buf)); /* pre-initialize */

	/* make the transmitter consume one char, but pull only 2 bits */
	printf("expecting osmo_soft_uart_tx_ubits() to "
	       "yield 2 bits (requesting 2 bits)\n");
	rc = osmo_soft_uart_tx_ubits(suart, &tx_buf[0], 2);
	OSMO_ASSERT(rc == 2);

	/* CTS gets de-asserted, the transmitter is shutting down */
	printf("======== de-asserting DSR\n");
	osmo_soft_uart_set_status_line(suart, OSMO_SUART_STATUS_F_DSR, false);

	/* expect only the remaining 8 bits to be pulled out */
	printf("expecting osmo_soft_uart_tx_ubits() to "
	       "yield 8 bits (requesting %zu bits)\n", sizeof(tx_buf));
	rc = osmo_soft_uart_tx_ubits(suart, &tx_buf[2], sizeof(tx_buf) - 2);
	OSMO_ASSERT(rc == 8);

	printf("expecting osmo_soft_uart_rx_ubits() to "
	       "consume %zu bits and yield a pending char\n", sizeof(tx_buf));
	rc = osmo_soft_uart_rx_ubits(suart, &tx_buf[0], sizeof(tx_buf));
	OSMO_ASSERT(rc == 0);
	osmo_soft_uart_flush_rx(suart);

	osmo_soft_uart_free(suart);
}

static void test_flow_control_rts_cts(void)
{
	struct osmo_soft_uart_cfg cfg;
	struct osmo_soft_uart *suart;
	ubit_t tx_buf[40];
	int rc;

	SUART_TEST_BEGIN;

	g_tx_cb_cfg.data = (void *)"\x42\x42\x42\x42";
	g_tx_cb_cfg.data_len = 4;

	cfg = suart_test_default_cfg;
	cfg.flow_ctrl_mode = OSMO_SUART_FLOW_CTRL_RTS_CTS;

	suart = osmo_soft_uart_alloc(NULL, __func__, &cfg);
	OSMO_ASSERT(suart != NULL);

	osmo_soft_uart_set_tx(suart, true);
	osmo_soft_uart_set_rx(suart, true);

	/* expect the initial status to be 0 (all lines de-asserted) */
	printf("initial status=0x%08x\n", osmo_soft_uart_get_status(suart));

	memset(&tx_buf[0], 1, sizeof(tx_buf)); /* pre-initialize */

	printf("expecting osmo_soft_uart_tx_ubits() to yield nothing\n");
	rc = osmo_soft_uart_tx_ubits(suart, &tx_buf[0], sizeof(tx_buf));
	OSMO_ASSERT(rc == 0);

	printf("expecting osmo_soft_uart_rx_ubits() to yield nothing\n");
	rc = osmo_soft_uart_rx_ubits(suart, &tx_buf[0], sizeof(tx_buf));
	OSMO_ASSERT(rc == 0);
	osmo_soft_uart_flush_rx(suart);

	/* both RTS/RTR and CTS are asserted, expect both Rx and Tx to work */
	printf("======== asserting both CTS and RTS/RTR\n");
	osmo_soft_uart_set_status_line(suart, OSMO_SUART_STATUS_F_CTS, true);
	osmo_soft_uart_set_status_line(suart, OSMO_SUART_STATUS_F_RTS_RTR, true);

	memset(&tx_buf[0], 1, sizeof(tx_buf)); /* pre-initialize */

	printf("expecting osmo_soft_uart_tx_ubits() to "
	       "yield %zu bits (requesting %zu bits)\n",
	       sizeof(tx_buf), sizeof(tx_buf));
	rc = osmo_soft_uart_tx_ubits(suart, &tx_buf[0], sizeof(tx_buf));
	OSMO_ASSERT(rc == sizeof(tx_buf));
	printf("%s\n", osmo_ubit_dump(&tx_buf[0], sizeof(tx_buf)));

	printf("expecting osmo_soft_uart_rx_ubits() to "
	       "consume %zu bits and yield %zu chars\n",
	       sizeof(tx_buf), sizeof(tx_buf) / 10);
	rc = osmo_soft_uart_rx_ubits(suart, &tx_buf[0], sizeof(tx_buf));
	OSMO_ASSERT(rc == 0);
	osmo_soft_uart_flush_rx(suart);

	memset(&tx_buf[0], 1, sizeof(tx_buf)); /* pre-initialize */

	/* make the transmitter consume one char, but pull only 2 bits */
	printf("expecting osmo_soft_uart_tx_ubits() to "
	       "yield 2 bits (requesting 2 bits)\n");
	rc = osmo_soft_uart_tx_ubits(suart, &tx_buf[0], 2);
	OSMO_ASSERT(rc == 2);

	/* CTS gets de-asserted, the transmitter is shutting down */
	printf("======== de-asserting CTS\n");
	osmo_soft_uart_set_status_line(suart, OSMO_SUART_STATUS_F_CTS, false);

	/* expect only the remaining 8 bits to be pulled out */
	printf("expecting osmo_soft_uart_tx_ubits() to "
	       "yield 8 bits (requesting %zu bits)\n", sizeof(tx_buf));
	rc = osmo_soft_uart_tx_ubits(suart, &tx_buf[2], sizeof(tx_buf) - 2);
	OSMO_ASSERT(rc == 8);

	printf("expecting osmo_soft_uart_rx_ubits() to "
	       "consume %zu bits and yield a pending char\n", sizeof(tx_buf));
	rc = osmo_soft_uart_rx_ubits(suart, &tx_buf[0], sizeof(tx_buf));
	OSMO_ASSERT(rc == 0);
	osmo_soft_uart_flush_rx(suart);

	osmo_soft_uart_free(suart);
}

static void test_tx_pull(void)
{
	struct osmo_soft_uart *suart;
	ubit_t tx_buf[25 * 2];
	int rc;

	SUART_TEST_BEGIN;

	g_tx_cb_cfg.data = (void *)"\x42\x42\x42\x42\x42";
	g_tx_cb_cfg.data_len = 5;

	suart = osmo_soft_uart_alloc(NULL, __func__, &suart_test_default_cfg);
	OSMO_ASSERT(suart != NULL);

	osmo_soft_uart_set_tx(suart, true);

	printf("pulling 25 bits (first time) out of the transmitter\n");
	rc = osmo_soft_uart_tx_ubits(suart, &tx_buf[0], sizeof(tx_buf) / 2);
	OSMO_ASSERT(rc == 25);

	printf("pulling 25 bits (second time) out of the transmitter\n");
	rc = osmo_soft_uart_tx_ubits(suart, &tx_buf[25], sizeof(tx_buf) / 2);
	OSMO_ASSERT(rc == 25);

	/* FIXME: we pull total 25 + 25 == 50 bits out of the transmitter, which is enough
	 * to fit 5 characters (assuming 8-N-1).  However, the current impelementation would
	 * pull only 2 + 2 == characters total, wasting 5 + 5 == 10 bits for padding. */

	osmo_soft_uart_free(suart);
}

int main(int argc, char **argv)
{
	test_rx();
	test_rx_flush();
	test_tx_rx();

	/* test pulling small number of bits at a time */
	test_tx_rx_pull_n(1);
	test_tx_rx_pull_n(2);
	test_tx_rx_pull_n(4);
	test_tx_rx_pull_n(8);

	test_tx_pull();

	/* test flow control */
	test_modem_status();
	test_flow_control_dtr_dsr();
	test_flow_control_rts_cts();

	return 0;
}
