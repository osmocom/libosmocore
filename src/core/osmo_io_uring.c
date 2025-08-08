/*! \file osmo_io_uring.c
 * io_uring backend for osmo_io.
 *
 * (C) 2022-2023 by sysmocom s.f.m.c.
 * Author: Daniel Willmann <daniel@sysmocom.de>
 * (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
 *
 * All Rights Reserved.
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

/* TODO:
 * Parameters:
 * - number of simultaneous read/write in uring for given fd
 *
 */

#include "../config.h"
#if defined(__linux__)

#include <stdio.h>
#include <talloc.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>

#include <netinet/in.h>
#include <netinet/sctp.h>
#include <sys/eventfd.h>
#include <liburing.h>

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>

#include "osmo_io_internal.h"

#define IOFD_URING_INITIAL_SIZE 4096
/* 32768 refers to the IORING_MAX_ENTRIES of the kernel (io_uring/io_uring.h). */
#define IOFD_URING_MAXIMUM_SIZE 32768

#define OSMO_IO_URING_BATCH "LIBOSMO_IO_URING_BATCH"

#define OSMO_IO_URING_INITIAL_SIZE "LIBOSMO_IO_URING_INITIAL_SIZE"

#define OSMO_IO_URING_READ_SQE "LIBOSMO_IO_URING_READ_SQE"

bool g_io_uring_batch = false;
bool g_io_uring_submit_needed = false;

static int g_io_uring_size = IOFD_URING_INITIAL_SIZE;

static int g_io_uring_read_sqes = 1;

struct osmo_io_uring {
	struct osmo_fd event_ofd;
	struct io_uring ring;
	struct llist_head cancel_queue;
	unsigned int num_pending_submissions;
};

static __thread struct osmo_io_uring *g_ring = NULL;

static void iofd_uring_cqe(struct io_uring *ring);

void osmo_io_uring_submit(void);

/*! read call-back for eventfd notifying us if entries are in the completion queue */
static int iofd_uring_poll_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct io_uring *ring = ofd->data;
	eventfd_t val;
	int rc;

	if (what & OSMO_FD_READ) {
		rc = eventfd_read(ofd->fd, &val);
		if (rc < 0) {
			LOGP(DLIO, LOGL_ERROR, "eventfd_read() returned error\n");
			return rc;
		}

		iofd_uring_cqe(ring);
	}
	if (what & OSMO_FD_WRITE)
		OSMO_ASSERT(0);

	return 0;
}

/*! initialize the uring and tie it into our event loop */
void osmo_iofd_uring_init(void)
{
	const char *env;
	int rc, evfd;

	if ((env = getenv(OSMO_IO_URING_BATCH)))
		g_io_uring_batch = true;

	if (!g_ring && (env = getenv(OSMO_IO_URING_INITIAL_SIZE))) {
		int env_value;
		rc = osmo_str_to_int(&env_value, env, 10, 1, IOFD_URING_MAXIMUM_SIZE);
		if (rc < 0) {
			fprintf(stderr, "Error: Initial io_uring size out of range (1..%d).\n",
				IOFD_URING_MAXIMUM_SIZE);
			exit(1);
		}
		if ((env_value & (env_value - 1))) {
			fprintf(stderr, "Error: Initial io_uring size must be a positive power of two.\n");
			exit(1);
		}
		g_io_uring_size = env_value;
	}

	g_ring = talloc_zero(OTC_GLOBAL, struct osmo_io_uring);
	INIT_LLIST_HEAD(&g_ring->cancel_queue);

	rc = io_uring_queue_init(g_io_uring_size, &g_ring->ring, 0);
	if (rc < 0)
		osmo_panic("failure during io_uring_queue_init(): %s\n", strerror(-rc));

	if ((env = getenv(OSMO_IO_URING_READ_SQE))) {
		g_io_uring_read_sqes = atoi(env);
		if (g_io_uring_read_sqes < 1 || g_io_uring_read_sqes > IOFD_MSGHDR_MAX_READ_SQES) {
			fprintf(stderr, "Invalid osmo_uring read SQEs requested: \"%s\"\n Allowed range: 1..%d\n",
				env, IOFD_MSGHDR_MAX_READ_SQES);
			exit(1);
		}
	}

	rc = eventfd(0, 0);
	if (rc < 0) {
		io_uring_queue_exit(&g_ring->ring);
		osmo_panic("failure creating eventfd(0, 0) for io_uring: %s\n", strerror(-rc));
	}
	evfd = rc;

	osmo_fd_setup(&g_ring->event_ofd, evfd, OSMO_FD_READ, iofd_uring_poll_cb, &g_ring->ring, 0);
	rc = osmo_fd_register(&g_ring->event_ofd);
	if (rc < 0) {
		close(evfd);
		io_uring_queue_exit(&g_ring->ring);
		osmo_panic("failure registering io_uring-eventfd as osmo_fd: %d\n", rc);
	}
	rc = io_uring_register_eventfd(&g_ring->ring, evfd);
	if (rc < 0) {
		osmo_fd_unregister(&g_ring->event_ofd);
		close(evfd);
		io_uring_queue_exit(&g_ring->ring);
		osmo_panic("failure registering eventfd with io_uring: %s\n", strerror(-rc));
	}
}

static void osmo_iofd_uring_exit(struct osmo_io_uring *ring)
{
	LOGP(DLIO, LOGL_DEBUG, "Old empty io_uring will be destroyed.");

	io_uring_queue_exit(&ring->ring);

	osmo_fd_unregister(&ring->event_ofd);
	close(ring->event_ofd.fd);

	talloc_free(ring);
}

static inline struct io_uring_sqe *io_uring_get_sqe_and_count(struct osmo_io_uring *ring)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&ring->ring);
	if (sqe)
		ring->num_pending_submissions++;

	return sqe;
}

static struct io_uring_sqe *iofd_uring_get_sqe(struct osmo_io_fd *iofd, bool read)
{
	struct io_uring_sqe *sqe;

	/* All subsequent read SQEs must be on the same ring. */
	if (read && iofd->u.uring.read.sqes_submitted > 0 && iofd->u.uring.read.ring != &g_ring->ring)
		return NULL;

	sqe = io_uring_get_sqe_and_count(g_ring);
	if (sqe)
		return sqe;

	/* The current ring is full, subsequent read SQEs on different ring are not allowed. */
	if (read && iofd->u.uring.read.sqes_submitted > 0)
		return NULL;

	if (g_io_uring_size < IOFD_URING_MAXIMUM_SIZE) {
		LOGP(DLIO, LOGL_NOTICE, "io_uring too small to handle all SQEs with its current size of %d. "
		     "Increasing io_uring size to %d.\n", g_io_uring_size, g_io_uring_size * 2);
		g_io_uring_size <<= 1;
	} else {
		LOGP(DLIO, LOGL_NOTICE, "io_uring too small to handle all SQEs with its maximum size of %d. "
		     "adding another one.\n", g_io_uring_size);
	}

	/* Submit all SQEs of current ring and create a new ring, if needed.
	 * The old ring will be kept, as there are uncompleted submissions.
	 * TODO: Destroy old ring, once all submissions are completed. */
	osmo_io_uring_submit();

	osmo_iofd_uring_init();

	sqe = io_uring_get_sqe_and_count(g_ring);
	OSMO_ASSERT(sqe);
	return sqe;
}

static inline void iofd_io_uring_submit(void)
{
	if (OSMO_LIKELY(!g_io_uring_batch))
		io_uring_submit(&g_ring->ring);
	else
		g_io_uring_submit_needed = true;
}

static inline int iofd_uring_submit_recv_sqe(struct osmo_io_fd *iofd, enum iofd_msg_action action)
{
	struct msgb *msg;
	struct iofd_msghdr *msghdr;
	struct io_uring_sqe *sqe;
	uint8_t idx;

	/* Tell iofd_uring_get_sqe() not to allocate a new ring, if we want to enqueue multiple read SQEs. */
	sqe = iofd_uring_get_sqe(iofd, true);
	if (!sqe) {
		if (iofd->u.uring.read.sqes_submitted > 0)
			return -EINVAL;
		LOGPIO(iofd, LOGL_ERROR, "Could not get io_uring_sqe\n");
		OSMO_ASSERT(0);
	}

	msg = iofd_msgb_alloc(iofd);
	if (!msg) {
		LOGPIO(iofd, LOGL_ERROR, "Could not allocate msgb for reading\n");
		OSMO_ASSERT(0);
	}

	msghdr = iofd_msghdr_alloc(iofd, action, msg, iofd->cmsg_size);
	if (!msghdr) {
		LOGPIO(iofd, LOGL_ERROR, "Could not allocate msghdr for reading\n");
		OSMO_ASSERT(0);
	}

	for (idx = 0; idx < msghdr->io_len; idx++) {
		msghdr->iov[idx].iov_base = msghdr->msg[idx]->tail;
		msghdr->iov[idx].iov_len = msgb_tailroom(msghdr->msg[idx]);
	}

	switch (action) {
	case IOFD_ACT_RECVMSG:
		msghdr->hdr.msg_control = msghdr->cmsg;
		msghdr->hdr.msg_controllen = iofd->cmsg_size;
		/* fall-through */
	case IOFD_ACT_RECVFROM:
		msghdr->hdr.msg_name = &msghdr->osa.u.sa;
		msghdr->hdr.msg_namelen = osmo_sockaddr_size(&msghdr->osa);
		/* fall-through */
	case IOFD_ACT_READ:
		msghdr->hdr.msg_iov = &msghdr->iov[0];
		msghdr->hdr.msg_iovlen = msghdr->io_len;
		break;
	default:
		OSMO_ASSERT(0);
	}

	switch (action) {
	case IOFD_ACT_READ:
		io_uring_prep_readv(sqe, iofd->fd, msghdr->iov, msghdr->hdr.msg_iovlen, -1);
		break;
	case IOFD_ACT_RECVMSG:
	case IOFD_ACT_RECVFROM:
		io_uring_prep_recvmsg(sqe, iofd->fd, &msghdr->hdr, msghdr->flags);
		break;
	default:
		OSMO_ASSERT(0);
	}
	io_uring_sqe_set_data(sqe, msghdr);

	iofd_io_uring_submit();

	iofd->u.uring.read.msghdr[iofd->u.uring.read.sqes_submitted] = msghdr;
	iofd->u.uring.read.sqes_submitted++;
	iofd->u.uring.read.ring = &g_ring->ring;

	return 0;
}

static void iofd_uring_submit_recv(struct osmo_io_fd *iofd, enum iofd_msg_action action)
{
	int rc;

	/* Submit more read SQEs in advance, if requested. */
	while (iofd->u.uring.read.sqes_submitted < iofd->u.uring.read.num_sqes) {
		rc = iofd_uring_submit_recv_sqe(iofd, action);
		/* Stop, if we cannot enqueue multiple read SQEs in the same ring. */
		if (rc < 0)
			break;
	}
}

/*! completion call-back for READ/RECVFROM */
static void iofd_uring_handle_recv(struct iofd_msghdr *msghdr, int rc)
{
	struct osmo_io_fd *iofd = msghdr->iofd;
	uint8_t idx, i;

	/* Find which read_msghdr is completed and remove from list. */
	for (idx = 0; idx < iofd->u.uring.read.sqes_submitted; idx++) {
		if (iofd->u.uring.read.msghdr[idx] == msghdr)
			break;
	}
	if (idx == iofd->u.uring.read.sqes_submitted) {
		LOGP(DLIO, LOGL_FATAL, "Read SQE completion, but msghdr not found, please fix!\n");
		return;
	}
	/* Remove entry at idx. */
	iofd->u.uring.read.sqes_submitted--;
	for (i = idx; i < iofd->u.uring.read.sqes_submitted; i++)
		iofd->u.uring.read.msghdr[i] = iofd->u.uring.read.msghdr[i + 1];
	iofd->u.uring.read.msghdr[i] = NULL;

	for (idx = 0; idx < msghdr->io_len; idx++) {
		struct msgb *msg = msghdr->msg[idx];
		int chunk;

		msghdr->msg[idx] = NULL;
		if (rc > 0) {
			if (rc > msghdr->iov[idx].iov_len)
				chunk = msghdr->iov[idx].iov_len;
			else
				chunk = rc;
			rc -= chunk;
			msgb_put(msg, chunk);
		} else {
			chunk = rc;
		}

		/* Check for every iteration, because iofd might get unregistered/closed during receive function. */
		if (iofd->u.uring.read.enabled && !IOFD_FLAG_ISSET(iofd, IOFD_FLAG_CLOSED))
			iofd_handle_recv(iofd, msg, chunk, msghdr);
		else
			msgb_free(msg);

		if (rc <= 0)
			break;
	}
	while (++idx < msghdr->io_len) {
		msgb_free(msghdr->msg[idx]);
		msghdr->msg[idx] = NULL;
	}

	if (iofd->u.uring.read.enabled && !IOFD_FLAG_ISSET(iofd, IOFD_FLAG_CLOSED))
		iofd_uring_submit_recv(iofd, msghdr->action);

	iofd_msghdr_free(msghdr);
}

static int iofd_uring_submit_tx(struct osmo_io_fd *iofd);

/*! completion call-back for WRITE/SENDTO */
static void iofd_uring_handle_tx(struct iofd_msghdr *msghdr, int rc)
{
	struct osmo_io_fd *iofd = msghdr->iofd;

	/* Detach msghdr from iofd. It might get freed here or it is freed during iofd_handle_send_completion().
	 * If there is pending data to send, iofd_uring_submit_tx() will attach it again.
	 * iofd_handle_send_completion() will invoke a callback function to signal the possibility of write/send.
	 * This callback function might close iofd, leading to the potential freeing of iofd->u.uring.write.msghdr if
	 * still attached. Since iofd_handle_send_completion() frees msghdr at the end of the function, detaching
	 * msghdr here prevents a double-free bug. */
	if (iofd->u.uring.write.msghdr == msghdr) {
		iofd->u.uring.write.msghdr = NULL;
		iofd->u.uring.write.ring = NULL;
	}

	if (OSMO_UNLIKELY(IOFD_FLAG_ISSET(iofd, IOFD_FLAG_CLOSED))) {
		for (int idx = 0; idx < msghdr->io_len; idx++) {
			msgb_free(msghdr->msg[idx]);
			msghdr->msg[idx] = NULL;
		}
		iofd_msghdr_free(msghdr);
	} else {
		iofd_handle_send_completion(iofd, rc, msghdr);
	}

	/* submit the next to-be-transmitted message for this file descriptor */
	if (iofd->u.uring.write.enabled && !IOFD_FLAG_ISSET(iofd, IOFD_FLAG_CLOSED))
		iofd_uring_submit_tx(iofd);
}

/*! handle completion of a single I/O message */
static void iofd_uring_handle_completion(struct iofd_msghdr *msghdr, int res)
{
	struct osmo_io_fd *iofd = msghdr->iofd;

	IOFD_FLAG_SET(iofd, IOFD_FLAG_IN_CALLBACK);

	switch (msghdr->action) {
	case IOFD_ACT_READ:
	case IOFD_ACT_RECVFROM:
	case IOFD_ACT_RECVMSG:
		iofd_uring_handle_recv(msghdr, res);
		break;
	case IOFD_ACT_WRITE:
	case IOFD_ACT_SENDTO:
	case IOFD_ACT_SENDMSG:
		iofd_uring_handle_tx(msghdr, res);
		break;
	default:
		OSMO_ASSERT(0)
	}

	IOFD_FLAG_UNSET(iofd, IOFD_FLAG_IN_CALLBACK);

	if (IOFD_FLAG_ISSET(iofd, IOFD_FLAG_TO_FREE) && !iofd->u.uring.read.sqes_submitted && !iofd->u.uring.write.msghdr)
		talloc_free(iofd);
}

/*! process all pending completion queue entries in given io_uring */
static void iofd_uring_cqe(struct io_uring *ring)
{
	int rc;
	struct io_uring_cqe *cqe;
	struct iofd_msghdr *msghdr, *msghdr2;
	struct osmo_io_uring *orig_ring = container_of(ring, struct osmo_io_uring, ring);

	while (io_uring_peek_cqe(ring, &cqe) == 0) {
		orig_ring->num_pending_submissions--;

		msghdr = io_uring_cqe_get_data(cqe);
		if (!msghdr) {
			LOGP(DLIO, LOGL_DEBUG, "Cancellation returned\n");
			io_uring_cqe_seen(ring, cqe);
			continue;
		}
		if (!msghdr->iofd) {
			io_uring_cqe_seen(ring, cqe);
			if (msghdr->in_cancel_queue)
				llist_del(&msghdr->list);
			iofd_msghdr_free(msghdr);
			continue;
		}

		rc = cqe->res;
		/* Hand the entry back to the kernel before */
		io_uring_cqe_seen(ring, cqe);

		iofd_uring_handle_completion(msghdr, rc);

	}

	/* If there are unsubmitted cancel SQEs, try to queue them now. */
	if (OSMO_LIKELY(llist_empty(&orig_ring->cancel_queue))) {
		/* Old ring is empty, remove it. */
		if (OSMO_UNLIKELY(orig_ring != g_ring && orig_ring->num_pending_submissions == 0))
			osmo_iofd_uring_exit(orig_ring);
		return;
	}
	llist_for_each_entry_safe(msghdr, msghdr2, &orig_ring->cancel_queue, list) {
		struct io_uring_sqe *sqe;
		sqe = io_uring_get_sqe_and_count(orig_ring);
		if (!sqe)
			break;
		io_uring_sqe_set_data(sqe, NULL);
		LOGP(DLIO, LOGL_DEBUG, "Cancelling queued read/write\n");
		io_uring_prep_cancel(sqe, msghdr, 0);
		llist_del(&msghdr->list);
		msghdr->in_cancel_queue = false;
	}
	io_uring_submit(&orig_ring->ring);
}

/*! will submit the next to-be-transmitted message for given iofd */
static int iofd_uring_submit_tx(struct osmo_io_fd *iofd)
{
	struct io_uring_sqe *sqe;
	struct iofd_msghdr *msghdr;

	msghdr = iofd_txqueue_dequeue(iofd);
	if (!msghdr)
		return -ENODATA;

	sqe = iofd_uring_get_sqe(iofd, false);
	if (!sqe) {
		LOGPIO(iofd, LOGL_ERROR, "Could not get io_uring_sqe\n");
		OSMO_ASSERT(0);
	}

	io_uring_sqe_set_data(sqe, msghdr);

	switch (msghdr->action) {
	case IOFD_ACT_WRITE:
		io_uring_prep_writev(sqe, msghdr->iofd->fd, msghdr->iov, msghdr->io_len, -1);
		break;
	case IOFD_ACT_SENDTO:
	case IOFD_ACT_SENDMSG:
		io_uring_prep_sendmsg(sqe, msghdr->iofd->fd, &msghdr->hdr, msghdr->flags);
		break;
	default:
		OSMO_ASSERT(0);
	}

	iofd_io_uring_submit();

	iofd->u.uring.write.msghdr = msghdr;
	iofd->u.uring.write.ring = &g_ring->ring;

	return 0;
}

static void iofd_uring_write_enable(struct osmo_io_fd *iofd);
static void iofd_uring_read_enable(struct osmo_io_fd *iofd);


/* called via osmocom poll/select main handling once outbound non-blocking connect() completes */
static int iofd_uring_connected_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_io_fd *iofd = ofd->data;

	LOGPIO(iofd, LOGL_DEBUG, "Socket connected or failed.\n");

	if (!(what & OSMO_FD_WRITE))
		return 0;

	/* Unregister from poll/select handling. */
	osmo_fd_unregister(ofd);
	IOFD_FLAG_UNSET(iofd, IOFD_FLAG_NOTIFY_CONNECTED);

	/* Notify the application about this via a zero-length write completion call-back. */
	IOFD_FLAG_SET(iofd, IOFD_FLAG_IN_CALLBACK);
	switch (iofd->mode) {
	case OSMO_IO_FD_MODE_READ_WRITE:
		iofd->io_ops.write_cb(iofd, 0, NULL);
		break;
	case OSMO_IO_FD_MODE_RECVFROM_SENDTO:
		iofd->io_ops.sendto_cb(iofd, 0, NULL, NULL);
		break;
	case OSMO_IO_FD_MODE_RECVMSG_SENDMSG:
		iofd->io_ops.sendmsg_cb(iofd, 0, NULL);
		break;
	}
	IOFD_FLAG_UNSET(iofd, IOFD_FLAG_IN_CALLBACK);

	/* If write/read notifications are pending, enable it now. */
	if (iofd->u.uring.write.enabled && !IOFD_FLAG_ISSET(iofd, IOFD_FLAG_CLOSED))
		iofd_uring_write_enable(iofd);
	if (iofd->u.uring.read.enabled && !IOFD_FLAG_ISSET(iofd, IOFD_FLAG_CLOSED))
		iofd_uring_read_enable(iofd);

	if (IOFD_FLAG_ISSET(iofd, IOFD_FLAG_TO_FREE) && !iofd->u.uring.read.sqes_submitted && !iofd->u.uring.write.msghdr)
		talloc_free(iofd);
	return 0;
}

static int iofd_uring_setup(struct osmo_io_fd *iofd)
{
	iofd->u.uring.read.num_sqes = g_io_uring_read_sqes;

	return 0;
}

static int iofd_uring_register(struct osmo_io_fd *iofd)
{
	if (iofd->mode != OSMO_IO_FD_MODE_RECVMSG_SENDMSG)
		return 0; /* Nothing to be done */

	/* OSMO_IO_FD_MODE_RECVMSG_SENDMSG:
	 * Use a temporary osmo_fd which we can use to notify us once the connection is established
	 * or failed (indicated by FD becoming writable). This is needed as (at least for SCTP sockets)
	 * one cannot submit a zero-length writev/sendmsg in order to get notification when the socekt
	 * is writable.*/
	if (IOFD_FLAG_ISSET(iofd, IOFD_FLAG_NOTIFY_CONNECTED)) {
		osmo_fd_setup(&iofd->u.uring.connect_ofd, iofd->fd, OSMO_FD_WRITE,
			      iofd_uring_connected_cb, iofd, 0);
		if (osmo_fd_register(&iofd->u.uring.connect_ofd) < 0) {
			LOGPIO(iofd, LOGL_ERROR, "Failed to register FD for connect event.\n");
			return -EBADFD;
		}
	}
	return 0;
}

static int iofd_uring_unregister(struct osmo_io_fd *iofd)
{
	struct io_uring_sqe *sqe;
	struct iofd_msghdr *msghdr;
	uint8_t idx;

	for (idx = 0; idx < iofd->u.uring.read.sqes_submitted; idx++) {
		struct osmo_io_uring *ring = container_of(iofd->u.uring.read.ring, struct osmo_io_uring, ring);
		msghdr = iofd->u.uring.read.msghdr[idx];
		iofd->u.uring.read.msghdr[idx] = NULL;
		/* Submit SQEs of the current ring, if needed. */
		if (&ring->ring == &g_ring->ring)
			osmo_io_uring_submit();
		/* If the submission queue is full, use cancel queue. We cannot cancel SQEs on the new ring. */
		sqe = io_uring_get_sqe_and_count(ring);
		if (sqe) {
			io_uring_sqe_set_data(sqe, NULL);
			LOGPIO(iofd, LOGL_DEBUG, "Cancelling read\n");
			io_uring_prep_cancel(sqe, msghdr, 0);
			io_uring_submit(&ring->ring);
		} else {
			llist_add_tail(&msghdr->list, &ring->cancel_queue);
			msghdr->in_cancel_queue = true;
		}
		talloc_steal(OTC_GLOBAL, msghdr);
		msghdr->iofd = NULL;
	}
	if (iofd->u.uring.read.sqes_submitted) {
		iofd->u.uring.read.ring = NULL;
		iofd->u.uring.read.sqes_submitted = 0;
	}

	if (iofd->u.uring.write.msghdr) {
		struct osmo_io_uring *ring = container_of(iofd->u.uring.write.ring, struct osmo_io_uring, ring);
		msghdr = iofd->u.uring.write.msghdr;
		iofd->u.uring.write.msghdr = NULL;
		for (int idx = 0; idx < msghdr->io_len; idx++) {
			msgb_free(msghdr->msg[idx]);
			msghdr->msg[idx] = NULL;
		}
		/* Submit SQEs of the current ring, if needed. */
		if (&ring->ring == &g_ring->ring)
			osmo_io_uring_submit();
		/* If the submission queue is full, use cancel queue. We cannot cancel SQEs on the new ring. */
		sqe = io_uring_get_sqe_and_count(ring);
		if (sqe) {
			io_uring_sqe_set_data(sqe, NULL);
			LOGPIO(iofd, LOGL_DEBUG, "Cancelling write\n");
			io_uring_prep_cancel(sqe, msghdr, 0);
			io_uring_submit(&ring->ring);
		} else {
			llist_add_tail(&msghdr->list, &ring->cancel_queue);
			msghdr->in_cancel_queue = true;
		}
		talloc_steal(OTC_GLOBAL, msghdr);
		msghdr->iofd = NULL;
		iofd->u.uring.write.ring = NULL;
	}

	if (IOFD_FLAG_ISSET(iofd, IOFD_FLAG_NOTIFY_CONNECTED)) {
		osmo_fd_unregister(&iofd->u.uring.connect_ofd);
		IOFD_FLAG_UNSET(iofd, IOFD_FLAG_NOTIFY_CONNECTED);
	}

	return 0;
}

static void iofd_uring_write_enable(struct osmo_io_fd *iofd)
{
	iofd->u.uring.write.enabled = true;

	if (iofd->u.uring.write.msghdr)
		return;

	/* This function is called again, once the socket is connected. */
	if (IOFD_FLAG_ISSET(iofd, IOFD_FLAG_NOTIFY_CONNECTED))
		return;

	if (osmo_iofd_txqueue_len(iofd) > 0)
		iofd_uring_submit_tx(iofd);
	else if (iofd->mode == OSMO_IO_FD_MODE_READ_WRITE) {
		/* Empty write request to check when the socket is connected */
		struct iofd_msghdr *msghdr;
		struct io_uring_sqe *sqe;
		struct msgb *msg = msgb_alloc_headroom(0, 0, "io_uring write dummy");
		if (!msg) {
			LOGPIO(iofd, LOGL_ERROR, "Could not allocate msgb for writing\n");
			OSMO_ASSERT(0);
		}
		msghdr = iofd_msghdr_alloc(iofd, IOFD_ACT_WRITE, msg, 0);
		if (!msghdr) {
			LOGPIO(iofd, LOGL_ERROR, "Could not allocate msghdr for writing\n");
			OSMO_ASSERT(0);
		}

		msghdr->iov[0].iov_base = msgb_data(msg);
		msghdr->iov[0].iov_len = msgb_length(msg);

		sqe = iofd_uring_get_sqe(iofd, false);
		if (!sqe) {
			LOGPIO(iofd, LOGL_ERROR, "Could not get io_uring_sqe\n");
			OSMO_ASSERT(0);
		}
		io_uring_prep_writev(sqe, iofd->fd, msghdr->iov, 1, 0);
		io_uring_sqe_set_data(sqe, msghdr);

		iofd_io_uring_submit();

		iofd->u.uring.write.msghdr = msghdr;
		iofd->u.uring.write.ring = &g_ring->ring;
	}
}

static void iofd_uring_write_disable(struct osmo_io_fd *iofd)
{
	iofd->u.uring.write.enabled = false;
}

static void iofd_uring_read_enable(struct osmo_io_fd *iofd)
{
	iofd->u.uring.read.enabled = true;

	if (iofd->u.uring.read.sqes_submitted)
		return;

	/* This function is called again, once the socket is connected. */
	if (IOFD_FLAG_ISSET(iofd, IOFD_FLAG_NOTIFY_CONNECTED))
		return;

	switch (iofd->mode) {
	case OSMO_IO_FD_MODE_READ_WRITE:
		iofd_uring_submit_recv(iofd, IOFD_ACT_READ);
		break;
	case OSMO_IO_FD_MODE_RECVFROM_SENDTO:
		iofd_uring_submit_recv(iofd, IOFD_ACT_RECVFROM);
		break;
	case OSMO_IO_FD_MODE_RECVMSG_SENDMSG:
		iofd_uring_submit_recv(iofd, IOFD_ACT_RECVMSG);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void iofd_uring_read_disable(struct osmo_io_fd *iofd)
{
	iofd->u.uring.read.enabled = false;
}

static int iofd_uring_close(struct osmo_io_fd *iofd)
{
	return close(iofd->fd);
}

static void iofd_uring_notify_connected(struct osmo_io_fd *iofd)
{
	if (iofd->mode != OSMO_IO_FD_MODE_RECVMSG_SENDMSG) {
		iofd_uring_write_enable(iofd);
		return;
	}

	/* OSMO_IO_FD_MODE_RECVMSG_SENDMSG: Don't call this function after enabling read or write. */
	OSMO_ASSERT(!iofd->u.uring.write.enabled && !iofd->u.uring.read.enabled);

	/* Set flag to enable temporary osmo_fd during register() time: */
	IOFD_FLAG_SET(iofd, IOFD_FLAG_NOTIFY_CONNECTED);
}

const struct iofd_backend_ops iofd_uring_ops = {
	.setup = iofd_uring_setup,
	.register_fd = iofd_uring_register,
	.unregister_fd = iofd_uring_unregister,
	.close = iofd_uring_close,
	.write_enable = iofd_uring_write_enable,
	.write_disable = iofd_uring_write_disable,
	.read_enable = iofd_uring_read_enable,
	.read_disable = iofd_uring_read_disable,
	.notify_connected = iofd_uring_notify_connected,
};

void osmo_io_uring_submit(void)
{
	if (OSMO_LIKELY(g_io_uring_submit_needed)) {
		io_uring_submit(&g_ring->ring);
		g_io_uring_submit_needed = false;
	}
}

#endif /* defined(__linux__) */
