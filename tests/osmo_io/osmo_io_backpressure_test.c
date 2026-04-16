/*
 * (C) 2026 by sysmocom s.f.m.c GmbH <info@sysmocom.de>
 * Author: Vadim Yanitskiy <vyanitskiy@sysmocom.de>
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

#define _GNU_SOURCE
#include <fcntl.h>

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/osmo_io.h>
#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>

#include "config.h"

#define TEST_START() printf("Running %s\n", __func__)

static void *ctx = NULL;
static unsigned file_bytes_write_compl = 0;

/* Shared infrastructure - same as main test file */
static void file_write_cb(struct osmo_io_fd *iofd, int rc, struct msgb *msg)
{
	printf("%s: write() returned rc=%d\n", osmo_iofd_get_name(iofd), rc);
	if (rc < 0)
		printf("%s: error: %s\n", osmo_iofd_get_name(iofd), strerror(-rc));
	if (msg) {
		printf("%s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
		file_bytes_write_compl += msgb_length(msg);
	}
}

/* Test osmo_io behavior under network backpressure conditions.
 * Simulates a scenario where an application sends data faster than the peer
 * can consume it, causing the OS socket buffers to fill up and creating
 * backpressure. Tests that osmo_io correctly handles internal message queueing
 * when write operations return EAGAIN, and properly drains the queue when
 * the backpressure clears. Uses multiple I/O buffers to exercise the
 * dequeue fill-up logic that attempts to merge multiple queued messages. */
static void test_backpressure_queue_handling(void)
{
	struct osmo_io_ops ioops;
	struct osmo_io_fd *iofd;
	struct msgb *msg;
	int fd[2] = { 0, 0 };
	int rc;

	TEST_START();

	printf("Testing backpressure scenario with queue management\n");

	/* Create a socketpair */
	rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
	OSMO_ASSERT(rc == 0);

	/* Make both ends non-blocking */
	rc = fcntl(fd[0], F_SETFL, O_NONBLOCK);
	OSMO_ASSERT(rc == 0);
	rc = fcntl(fd[1], F_SETFL, O_NONBLOCK);
	OSMO_ASSERT(rc == 0);

	/* Set small socket buffer to force queueing */
	int sndbuf = 1024;
	rc = setsockopt(fd[1], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	if (rc < 0)
		printf("Warning: failed to set SO_SNDBUF: %s\n", strerror(errno));

	/* Set up iofd with multiple write buffers to enable fill-up logic */
	ioops = (struct osmo_io_ops){ .write_cb = file_write_cb };
	iofd = osmo_iofd_setup(ctx, fd[1], "backpressure_test", OSMO_IO_FD_MODE_READ_WRITE, &ioops, NULL);
	OSMO_ASSERT(iofd);

	/* Use multiple buffers to enable dequeue fill-up logic */
	rc = osmo_iofd_set_io_buffers(iofd, OSMO_IO_OP_WRITE, 8);
	OSMO_ASSERT(rc == 0);

	osmo_iofd_register(iofd, fd[1]);

	printf("Queueing messages to simulate network backpressure\n");
	file_bytes_write_compl = 0;

	char drain_buffer[512];
	int messages_queued = 0;

	for (int i = 0; i < 10; i++) {
		/* Add a message */
		msg = msgb_alloc(1024, "qmsg");
		memset(msgb_put(msg, 1024), 0xAA + (i % 16), 1024);

		rc = osmo_iofd_write_msgb(iofd, msg);
		if (rc == 0)
			messages_queued++;
		else
			msgb_free(msg);

		/* Process events with explicit timeout */
		for (int j = 0; j < 3; j++)
			osmo_select_main(1);

		/* Drain to prevent saturation */
		if (i % 3 == 0)
			read(fd[0], drain_buffer, sizeof(drain_buffer));

		/* Stop if we have sufficient queue buildup */
		if (osmo_iofd_txqueue_len(iofd) >= 10)
			break;

		/* Add small delay to prevent overwhelming */
		usleep(5000);  /* 5ms */
	}

	/* Add varied message sizes */

	/* Add tiny messages that might create partially-filled msghdrs */
	for (int i = 0; i < 10; i++) {
		msg = msgb_alloc(50, "Tiny msg");
		memset(msgb_put(msg, 50), 0xBB + i, 50);
		rc = osmo_iofd_write_msgb(iofd, msg);
		if (rc < 0)
			msgb_free(msg);
	}

	/* Add medium messages */
	for (int i = 0; i < 10; i++) {
		msg = msgb_alloc(500, "Medium msg");
		memset(msgb_put(msg, 500), 0xCC + i, 500);
		rc = osmo_iofd_write_msgb(iofd, msg);
		if (rc < 0)
			msgb_free(msg);
	}

	/* Add large messages */
	for (int i = 0; i < 5; i++) {
		msg = msgb_alloc(1500, "qmsg_1500");
		memset(msgb_put(msg, 1500), 0xDD + i, 1500);
		rc = osmo_iofd_write_msgb(iofd, msg);
		if (rc < 0)
			msgb_free(msg);
	}

	printf("Queueing messages completed\n");

	/* Controlled draining to trigger dequeue with fill-up logic */
	for (int iteration = 0; iteration < 500; iteration++) {
		/* Drain TINY amounts to slowly unblock writes */
		ssize_t drained = read(fd[0], drain_buffer, sizeof(drain_buffer));
		if (drained > 0 && iteration % 20 == 0)
			printf("Iteration %d: drained %zd bytes\n", iteration, drained);

		/* Process events to trigger dequeue operations */
		for (int j = 0; j < 3; j++)
			osmo_select_main(1);

		if (iteration % 25 == 0) {
			printf("Iter %d: queue_len=%u, bytes_completed=%u\n",
			       iteration, osmo_iofd_txqueue_len(iofd),
			       file_bytes_write_compl);
		}

		/* Are we done yet? */
		if (osmo_iofd_txqueue_len(iofd) == 0 && file_bytes_write_compl > 0) {
			printf("Queue emptied at iteration %d\n", iteration);
			break;
		}

		usleep(1000);  /* 1ms delay to control rate */
	}

	printf("Final: queue_len=%u, bytes_completed=%u\n",
	       osmo_iofd_txqueue_len(iofd), file_bytes_write_compl);

	/* Clean up */
	osmo_iofd_free(iofd);
	close(fd[0]);

	for (int i = 0; i < 128; i++)
		osmo_select_main(1);
}

int main(int argc, char **argv)
{
	ctx = talloc_named_const(NULL, 0, __FILE__);
	osmo_init_logging2(ctx, NULL);

	test_backpressure_queue_handling();

	return EXIT_SUCCESS;
}
