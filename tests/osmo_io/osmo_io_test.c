/*
 * (C) 2023 by sysmocom s.f.m.c
 * Author: Daniel Willmann <daniel@sysmocom.de>
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

#include <osmocom/core/application.h>
#include <osmocom/core/bits.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/osmo_io.h>
#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>

#include "config.h"

#define TEST_START() printf("Running %s\n", __func__)

static uint8_t TESTDATA[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};


static void *ctx = NULL;

static void read_cb(struct osmo_io_fd *iofd, int rc, struct msgb *msg)
{
	printf("%s: read() msg with len=%d\n", osmo_iofd_get_name(iofd), rc);
	if (msg)
		printf("%s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));

	talloc_free(msg);
}

static void write_cb(struct osmo_io_fd *iofd, int rc, struct msgb *msg)
{
	uint8_t *buf;
	printf("%s: write() returned rc=%d\n", osmo_iofd_get_name(iofd), rc);
	if (rc == 0) {
		msg = msgb_alloc(1024, "Test data");
		buf = msgb_put(msg, sizeof(TESTDATA));
		memcpy(buf, TESTDATA, sizeof(TESTDATA));

		osmo_iofd_write_msgb(iofd, msg);
	}
}

struct osmo_io_ops ioops_conn_read_write = {
	.read_cb = read_cb,
	.write_cb = write_cb,
};

static void test_connected(void)
{
	int fds[2] = {0, 0}, rc;
	struct osmo_io_fd *iofd1, *iofd2;

	TEST_START();

	rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	OSMO_ASSERT(rc == 0);

	iofd1 = osmo_iofd_setup(ctx, fds[0], "ep1", OSMO_IO_FD_MODE_READ_WRITE, &ioops_conn_read_write, NULL);
	osmo_iofd_register(iofd1, fds[0]);
	iofd2 = osmo_iofd_setup(ctx, fds[1], "ep2", OSMO_IO_FD_MODE_READ_WRITE, &ioops_conn_read_write, NULL);
	osmo_iofd_register(iofd2, fds[1]);
	// Explicitly check if ep1 is connected through write_cb
	osmo_iofd_notify_connected(iofd1);

	/* Allow enough cycles to handle the messages */
	for (int i = 0; i < 128; i++)
		osmo_select_main(1);

	osmo_iofd_free(iofd1);
	osmo_iofd_free(iofd2);

	for (int i = 0; i < 128; i++)
		osmo_select_main(1);
}

static void recvfrom_cb(struct osmo_io_fd *iofd, int rc, struct msgb *msg,
			const struct osmo_sockaddr *saddr)
{
	printf("%s: recvfrom() msg with len=%d\n", osmo_iofd_get_name(iofd), rc);
	if (msg)
		printf("%s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));

	talloc_free(msg);
}

static void sendto_cb(struct osmo_io_fd *iofd, int rc, struct msgb *msg,
		      const struct osmo_sockaddr *daddr)
{
	printf("%s: sendto() returned rc=%d\n", osmo_iofd_get_name(iofd), rc);
}

struct osmo_io_ops ioops_conn_recvfrom_sendto = {
	.sendto_cb = sendto_cb,
	.recvfrom_cb = recvfrom_cb,
};

static void test_unconnected(void)
{
	int fds[2] = {0, 0}, rc;
	struct osmo_io_fd *iofd1, *iofd2;
	struct msgb *msg;
	uint8_t *buf;

	TEST_START();

	rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);
	OSMO_ASSERT(rc == 0);

	iofd1 = osmo_iofd_setup(ctx, fds[0], "ep1", OSMO_IO_FD_MODE_RECVFROM_SENDTO, &ioops_conn_recvfrom_sendto, NULL);
	osmo_iofd_register(iofd1, fds[0]);
	iofd2 = osmo_iofd_setup(ctx, fds[1], "ep2", OSMO_IO_FD_MODE_RECVFROM_SENDTO, &ioops_conn_recvfrom_sendto, NULL);
	osmo_iofd_register(iofd2, fds[1]);

	msg = msgb_alloc(1024, "Test data");
	buf = msgb_put(msg, sizeof(TESTDATA));
	memcpy(buf, TESTDATA, sizeof(TESTDATA));

	osmo_iofd_sendto_msgb(iofd1, msg, 0, NULL);

	/* Allow enough cycles to handle the messages */
	for (int i = 0; i < 128; i++)
		osmo_select_main(1);

	osmo_iofd_free(iofd1);
	osmo_iofd_free(iofd2);

	for (int i = 0; i < 128; i++)
		osmo_select_main(1);
}
static const struct log_info_cat default_categories[] = {
};

static struct log_info info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char *argv[])
{
	ctx = talloc_named_const(NULL, 0, "osmo_io_test");
	osmo_init_logging2(ctx, &info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);

	test_connected();
	test_unconnected();

	return EXIT_SUCCESS;
}
