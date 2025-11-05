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
#include <stdbool.h>
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

static unsigned file_bytes_read = 0;
static unsigned file_bytes_write_compl = 0;
static bool file_eof_read = false;
static void file_read_cb(struct osmo_io_fd *iofd, int rc, struct msgb *msg)
{
	printf("%s: read() msg with rc=%d\n", osmo_iofd_get_name(iofd), rc);
	if (rc < 0)
		printf("%s: error: %s\n", osmo_iofd_get_name(iofd), strerror(-rc));
	if (msg) {
		printf("%s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
		file_bytes_read += msgb_length(msg);
		talloc_free(msg);
	}
	if (rc == 0) {
		file_eof_read = true;
		osmo_iofd_close(iofd);
	}
}

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

static void test_file(void)
{
	struct osmo_io_fd *iofd;
	struct msgb *msg;
	uint8_t *buf;
	int fd;
	int rc;
	struct osmo_io_ops ioops;

	TEST_START();

	/* Create temporary file and pass fd to iofd: */
	FILE *fp = tmpfile();
	OSMO_ASSERT(fp);
	fd = fileno(fp);

	/* First test writing to the file: */
	printf("Enable write\n");
	ioops = (struct osmo_io_ops){ .write_cb = file_write_cb };
	iofd = osmo_iofd_setup(ctx, fd, "file-iofd", OSMO_IO_FD_MODE_READ_WRITE, &ioops, NULL);
	osmo_iofd_register(iofd, fd);

	msg = msgb_alloc(1024, "Test data");
	buf = msgb_put(msg, sizeof(TESTDATA));
	memcpy(buf, TESTDATA, sizeof(TESTDATA));
	osmo_iofd_write_msgb(iofd, msg);
	/* Allow enough cycles to handle the messages */
	for (int i = 0; i < 128; i++) {
		OSMO_ASSERT(file_bytes_write_compl <= sizeof(TESTDATA));
		if (file_bytes_write_compl == sizeof(TESTDATA))
			break;
		osmo_select_main(1);
		usleep(100 * 1000);
	}
	fflush(stdout);
	OSMO_ASSERT(file_bytes_write_compl == sizeof(TESTDATA));

	/* Now, re-configure iofd to only read from the fd. Adjust the read/write offset beforehand: */
	printf("Enable read\n");
	rc = lseek(fd, 0, SEEK_SET);
	OSMO_ASSERT(rc == 0);
	ioops = (struct osmo_io_ops){ .read_cb = file_read_cb };
	rc = osmo_iofd_set_ioops(iofd, &ioops);
	OSMO_ASSERT(rc == 0);
	/* Allow enough cycles to handle the message. We expect 2 reads, 2nd read will return 0. */
	for (int i = 0; i < 128; i++) {
		OSMO_ASSERT(file_bytes_read <= sizeof(TESTDATA));
		if (file_bytes_read == sizeof(TESTDATA) && file_eof_read)
			break;
		osmo_select_main(1);
		usleep(100 * 1000);
	}
	fflush(stdout);
	OSMO_ASSERT(file_bytes_read == sizeof(TESTDATA));
	OSMO_ASSERT(file_eof_read);

	osmo_iofd_free(iofd);

	for (int i = 0; i < 128; i++)
		osmo_select_main(1);
}

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

int segmentation_cb(struct osmo_io_fd *iofd, struct msgb *msg)
{
	printf("%s: segmentation_cb() returning %d\n", osmo_iofd_get_name(iofd), 4);
	return 4;
}

static void segment_read_cb(struct osmo_io_fd *iofd, int rc, struct msgb *msg)
{
	static int seg_number = 0;

	printf("%s: read() msg with rc=%d\n", osmo_iofd_get_name(iofd), rc);
	if (rc < 0) {
		printf("%s: error: %s\n", osmo_iofd_get_name(iofd), strerror(-rc));
		OSMO_ASSERT(0);
	}
	OSMO_ASSERT(msg);
	if (seg_number < 3) {
		printf("%s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
		printf("tailroom = %d\n", msgb_tailroom(msg));
		/* Our read buffer is 6 bytes, Our segment is 4 bytes, this results in tailroom of 2 bytes.
		 * When the pending 2 bytes are combined with subsequent read of 6 bytes, an extra buffer
		 * with 8 bytes is allocated. Our segment is 4 byte, then this results in a tailroom of 4
		 * bytes. */
		if (seg_number == 1)
			OSMO_ASSERT(msgb_tailroom(msg) == 4)
		else
			OSMO_ASSERT(msgb_tailroom(msg) == 2)
		OSMO_ASSERT(msgb_length(msg) == sizeof(TESTDATA) / 4);
		seg_number++;
	} else {
		OSMO_ASSERT(rc == 0);
		file_eof_read = true;
	}
	talloc_free(msg);
}

static void test_segmentation(void)
{
	struct osmo_io_fd *iofd;
	struct msgb *msg;
	uint8_t *buf;
	int fd[2] = { 0, 0 };
	int rc;
	struct osmo_io_ops ioops;

	TEST_START();

	/* Create pipe */
	rc = pipe(fd);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(fd[0]);
	OSMO_ASSERT(fd[1]);

	/* First test writing to the pipe: */
	printf("Enable write\n");
	ioops = (struct osmo_io_ops){ .write_cb = file_write_cb };
	iofd = osmo_iofd_setup(ctx, fd[1], "seg_iofd", OSMO_IO_FD_MODE_READ_WRITE, &ioops, NULL);
	osmo_iofd_register(iofd, fd[1]);

	msg = msgb_alloc(12, "Test data");
	buf = msgb_put(msg, 12);
	memcpy(buf, TESTDATA, 12);
	osmo_iofd_write_msgb(iofd, msg);
	/* Allow enough cycles to handle the messages */
	file_bytes_write_compl = 0;
	for (int i = 0; i < 128; i++) {
		OSMO_ASSERT(file_bytes_write_compl <= 12);
		if (file_bytes_write_compl == 12)
			break;
		osmo_select_main(1);
		usleep(100 * 1000);
	}
	fflush(stdout);
	OSMO_ASSERT(file_bytes_write_compl == 12);

	osmo_iofd_close(iofd);

	/* Now, re-configure iofd to only read from the pipe.
	 * Reduce the read buffer size, to verify correct segmentation operation: */
	printf("Enable read\n");
	osmo_iofd_set_alloc_info(iofd, 6, 0);
	osmo_iofd_register(iofd, fd[0]);
	ioops = (struct osmo_io_ops){ .read_cb = segment_read_cb, .segmentation_cb2 = segmentation_cb };
	rc = osmo_iofd_set_ioops(iofd, &ioops);
	OSMO_ASSERT(rc == 0);
	/* Allow enough cycles to handle the message. We expect 3 reads, 4th read will return 0. */
	file_bytes_read = 0;
	file_eof_read = false;
	for (int i = 0; i < 128; i++) {
		if (file_eof_read)
			break;
		osmo_select_main(1);
		usleep(100 * 1000);
	}
	fflush(stdout);
	OSMO_ASSERT(file_eof_read);

	osmo_iofd_free(iofd);

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

	test_file();
	test_connected();
	test_unconnected();
	test_segmentation();

	return EXIT_SUCCESS;
}
