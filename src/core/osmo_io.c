/*
 * New osmocom async I/O API.
 *
 * (C) 2022-2024 by Harald Welte <laforge@osmocom.org>
 * (C) 2022-2024 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Daniel Willmann <dwillmann@sysmocom.de>
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

#include "../config.h"
#ifndef EMBEDDED

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <talloc.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include "osmo_io_internal.h"

/*! \addtogroup osmo_io
 *  @{
 *
 * \file osmo_io.c */

/*! This environment variable can be set to manually set the backend used in osmo_io */
#define OSMO_IO_BACKEND_ENV "LIBOSMO_IO_BACKEND"

const struct value_string osmo_io_backend_names[] = {
	{ OSMO_IO_BACKEND_POLL, "poll" },
	{ OSMO_IO_BACKEND_IO_URING, "io_uring" },
	{ 0, NULL }
};

const struct value_string osmo_iofd_mode_names[] = {
	{ OSMO_IO_FD_MODE_READ_WRITE, "read/write" },
	{ OSMO_IO_FD_MODE_RECVFROM_SENDTO, "recvfrom/sendto" },
	{ OSMO_IO_FD_MODE_RECVMSG_SENDMSG, "recvmsg/sendmsg" },
	{ 0, NULL }
};

static enum osmo_io_backend g_io_backend;

/* Used by some tests, can't be static */
struct iofd_backend_ops osmo_iofd_ops;

/*! initialize osmo_io for the current thread */
void osmo_iofd_init(void)
{
	switch (g_io_backend) {
	case OSMO_IO_BACKEND_POLL:
		break;
#if defined(HAVE_URING)
	case OSMO_IO_BACKEND_IO_URING:
		osmo_iofd_uring_init();
		break;
#endif
	default:
		OSMO_ASSERT(0);
		break;
	}
}

/* ensure main thread always has pre-initialized osmo_io
 * priority 103: run after on_dso_load_select */
static __attribute__((constructor(103))) void on_dso_load_osmo_io(void)
{
	char *backend = getenv(OSMO_IO_BACKEND_ENV);
	if (backend == NULL)
		backend = OSMO_IO_BACKEND_DEFAULT;

	if (!strcmp("POLL", backend)) {
		g_io_backend = OSMO_IO_BACKEND_POLL;
		osmo_iofd_ops = iofd_poll_ops;
#if defined(HAVE_URING)
	} else if (!strcmp("IO_URING", backend)) {
		g_io_backend = OSMO_IO_BACKEND_IO_URING;
		osmo_iofd_ops = iofd_uring_ops;
#endif
	} else {
		fprintf(stderr, "Invalid osmo_io backend requested: \"%s\"\nCheck the environment variable %s\n", backend, OSMO_IO_BACKEND_ENV);
		exit(1);
	}

	OSMO_ASSERT(osmo_iofd_ops.close);
	OSMO_ASSERT(osmo_iofd_ops.register_fd);
	OSMO_ASSERT(osmo_iofd_ops.unregister_fd);
	OSMO_ASSERT(osmo_iofd_ops.write_enable);
	OSMO_ASSERT(osmo_iofd_ops.write_disable);
	OSMO_ASSERT(osmo_iofd_ops.read_enable);
	OSMO_ASSERT(osmo_iofd_ops.read_disable);
	OSMO_ASSERT(osmo_iofd_ops.notify_connected);

	osmo_iofd_init();
}

/*! Obtain the osmo_io_backend in use by the process
 *  \returns The osmo_io backend which was configured at startup time */
enum osmo_io_backend osmo_io_get_backend(void)
{
	return g_io_backend;
}

/*! Allocate the msghdr.
 *  \param[in] iofd the osmo_io file structure
 *  \param[in] action the action this msg(hdr) is for (read, write, ..)
 *  \param[in] msg the msg buffer to use. Will allocate a new one if NULL
 *  \param[in] cmsg_size size (in bytes) of iofd_msghdr.cmsg buffer. Can be 0 if cmsg is not used.
 *  \returns the newly allocated msghdr or NULL in case of error */
struct iofd_msghdr *iofd_msghdr_alloc(struct osmo_io_fd *iofd, enum iofd_msg_action action, struct msgb *msg,
				      size_t cmsg_size)
{
	struct iofd_msghdr *hdr;
	uint8_t idx, io_len;


	hdr = talloc_zero_size(iofd, sizeof(struct iofd_msghdr) + cmsg_size);
	if (!hdr)
		return NULL;

	hdr->action = action;
	hdr->iofd = iofd;

	/* Allocate the number of read buffers, configured by the user. Use msg as first buffer, if not NULL.
	 * Only READ may have multiple buffers, because packets will only be written to the first buffer. */
	io_len = (action == IOFD_ACT_READ) ? iofd->io_read_buffers : 1;
	for (idx = 0; idx < io_len; idx++) {
		if (msg) {
			talloc_steal(iofd, msg);
			hdr->msg[idx] = msg;
			msg = NULL;
		} else {
			hdr->msg[idx] = iofd_msgb_alloc(iofd);
			if (!hdr->msg[idx])
				break;
		}
	}
	/* If at least one msgb is allocated, we can continue with only one msgb, instead of completely failing. */
	if (idx == 0) {
		talloc_free(hdr);
		return NULL;
	}

	hdr->io_len = idx;

	return hdr;
}

/*! Free the msghdr.
 *  \param[in] msghdr the msghdr to free
 */
void iofd_msghdr_free(struct iofd_msghdr *msghdr)
{
	/* msghdr->msg is never owned by msghdr, it will either be freed in the send path or
	 * or passed on to the read callback which takes ownership. */
	talloc_free(msghdr);
}

/*! convenience wrapper to call msgb_alloc with parameters from osmo_io_fd (of given size) */
struct msgb *iofd_msgb_alloc2(struct osmo_io_fd *iofd, size_t size)
{
	size_t headroom = iofd->msgb_alloc.headroom;

	OSMO_ASSERT(size + headroom <= 0xffff);
	return msgb_alloc_headroom_c(iofd, (uint16_t)(size + headroom), (uint16_t)headroom, "osmo_io_msgb");
}

/*! convenience wrapper to call msgb_alloc with parameters from osmo_io_fd */
struct msgb *iofd_msgb_alloc(struct osmo_io_fd *iofd)
{
	return iofd_msgb_alloc2(iofd, iofd->msgb_alloc.size);
}

/*! Enqueue a message to be sent.
 *
 *  Enqueues the message at the back of the queue provided there is enough space.
 *  \param[in] iofd the file descriptor
 *  \param[in] msghdr the message to enqueue
 *  \returns 0 if the message was enqueued succcessfully,
 *    -ENOSPC if the queue already contains the maximum number of messages
 */
int iofd_txqueue_enqueue(struct osmo_io_fd *iofd, struct iofd_msghdr *msghdr)
{
	if (iofd->tx_queue.current_length >= iofd->tx_queue.max_length) {
		LOGPIO(iofd, LOGL_ERROR, "enqueueing message failed (queue full, %u msgs). Rejecting msgb\n",
		       iofd->tx_queue.current_length);
		return -ENOSPC;
	}

	llist_add_tail(&msghdr->list, &iofd->tx_queue.msg_queue);
	iofd->tx_queue.current_length++;

	if (iofd->tx_queue.current_length == 1 && !IOFD_FLAG_ISSET(iofd, IOFD_FLAG_CLOSED))
		osmo_iofd_ops.write_enable(iofd);

	return 0;
}

/*! Enqueue a message at the front.
 *
 *  Used to enqueue a msgb from a partial send again. This function will always
 *  enqueue the message, even if the maximum number of messages is reached.
 *  \param[in] iofd the file descriptor
 *  \param[in] msghdr the message to enqueue
 */
void iofd_txqueue_enqueue_front(struct osmo_io_fd *iofd, struct iofd_msghdr *msghdr)
{
	llist_add(&msghdr->list, &iofd->tx_queue.msg_queue);
	iofd->tx_queue.current_length++;

	if (iofd->tx_queue.current_length == 1 && !IOFD_FLAG_ISSET(iofd, IOFD_FLAG_CLOSED))
		osmo_iofd_ops.write_enable(iofd);
}

/*! Dequeue a message from the front.
 *
 *  \param[in] iofd the file descriptor
 *  \returns the msghdr from the front of the queue or NULL if the queue is empty
 */
struct iofd_msghdr *iofd_txqueue_dequeue(struct osmo_io_fd *iofd)
{
	struct iofd_msghdr *msghdr;

	if (iofd->tx_queue.current_length == 0)
		return NULL;

	msghdr = llist_first_entry_or_null(&iofd->tx_queue.msg_queue, struct iofd_msghdr, list);

	OSMO_ASSERT(msghdr);
	iofd->tx_queue.current_length--;
	llist_del(&msghdr->list);

	/* Fill up empty buffers in dequeued msghdr with buffers from the next msghdr.
	 * There can be empty buffers, when a msghdr is queued to the front with incomplete write. */
	while (OSMO_UNLIKELY(msghdr->io_len < iofd->io_write_buffers)) {
		struct iofd_msghdr *next;
		int i;

		if (iofd->tx_queue.current_length == 0)
			break;
		next = llist_first_entry_or_null(&iofd->tx_queue.msg_queue, struct iofd_msghdr, list);
		OSMO_ASSERT(next->io_len > 0);
		/* Get first message buffer from next msghdr and store them in the dequeued one. */
		msghdr->iov[msghdr->io_len] = next->iov[0];
		msghdr->msg[msghdr->io_len] = next->msg[0];
		msghdr->hdr.msg_iovlen = ++msghdr->io_len;
		/* Remove the message buffer from the next msghdr and free, if empty. */
		next->io_len--;
		for (i = 0; i < next->io_len; i++) {
			next->iov[i] = next->iov[i + 1];
			next->msg[i] = next->msg[i + 1];
		}
		if (next->io_len == 0) {
			iofd->tx_queue.current_length--;
			llist_del(&next->list);
			iofd_msghdr_free(next);
		} else {
			memset(&next->iov[next->io_len], 0, sizeof(struct iovec));
			next->msg[next->io_len] = NULL;
			next->hdr.msg_iovlen = --next->io_len;
		}
	}

	if (iofd->tx_queue.current_length == 0)
		osmo_iofd_ops.write_disable(iofd);

	return msghdr;
}

/*! Handle segmentation of the msg. If this function returns *_HANDLE_ONE or MORE then the data in msg will contain
 * one complete message.
 * If there are bytes left over, *pending_out will point to a msgb with the remaining data.
 * Upon IOFD_SEG_ACT_DEFER is returned, errno is set to error value providing reason:
 * EAGAIN is returned when data is still missing to fill the segment; other error codes are
 * propagated through read_cb().
*/
static enum iofd_seg_act iofd_handle_segmentation(struct osmo_io_fd *iofd, struct msgb *msg, struct msgb **pending_out)
{
	int extra_len, received_len, expected_len;
	struct msgb *msg_pending;

	/* Save the start of message before segmentation_cb (which could change it) */
	uint8_t *data = msg->data;

	received_len = msgb_length(msg);

	if (iofd->io_ops.segmentation_cb2) {
		expected_len = iofd->io_ops.segmentation_cb2(iofd, msg);
	} else if (iofd->io_ops.segmentation_cb) {
		expected_len = iofd->io_ops.segmentation_cb(msg);
	} else {
		*pending_out = NULL;
		return IOFD_SEG_ACT_HANDLE_ONE;
	}

	if (expected_len < 0) {
		if (expected_len != -EAGAIN)
			LOGPIO(iofd, LOGL_ERROR, "segmentation_cb returned error (%d), skipping msg of size %d\n",
			       expected_len, received_len);
		errno = -expected_len;
		goto defer;
	}

	extra_len = received_len - expected_len;
	/* No segmentation needed, return the whole msgb */
	if (extra_len == 0) {
		*pending_out = NULL;
		return IOFD_SEG_ACT_HANDLE_ONE;
	}

	/* segment is incomplete */
	if (extra_len < 0) {
		errno = EAGAIN;
		goto defer;
	}

	/* msgb contains more than one segment */
	/* Copy the trailing data over */
	msg_pending = iofd_msgb_alloc(iofd);
	memcpy(msgb_data(msg_pending), data + expected_len, extra_len);
	msgb_put(msg_pending, extra_len);
	*pending_out = msg_pending;

	/* Trim the original msgb to size. Don't use msgb_trim because we need to reference
	 * msg->data from before it might have been modified by the segmentation_cb(). */
	msg->tail = data + expected_len;
	msg->len = msg->tail - msg->data;
	return IOFD_SEG_ACT_HANDLE_MORE;

defer:
	*pending_out = msg;
	return IOFD_SEG_ACT_DEFER;
}

static void _call_read_cb(struct osmo_io_fd *iofd, int rc, struct msgb *msg)
{
	talloc_steal(iofd->msgb_alloc.ctx, msg);
	iofd->io_ops.read_cb(iofd, rc, msg);
}

static inline uint16_t iofd_msgb_length_max(const struct osmo_io_fd *iofd)
{
	return UINT16_MAX - iofd->msgb_alloc.headroom;
}

/* Update iofd->pending copying as much data as possible from in_msg.
 * Return unprocessed tail of in_msg, or NULL if all in_msg was copied into iofd->pending.
*/
static struct msgb *iofd_prepare_handle_segmentation(struct osmo_io_fd *iofd, struct msgb *in_msg)
{
	if (OSMO_LIKELY(msgb_tailroom(iofd->pending) >= msgb_length(in_msg))) {
		/* Append incoming msg into iofd->pending. */
		memcpy(msgb_put(iofd->pending, msgb_length(in_msg)),
		       msgb_data(in_msg),
		       msgb_length(in_msg));
		msgb_free(in_msg);
		return NULL;
	}

	/* Data of msg does not fit into pending message. Allocate a new message that is larger.
	 * This implies that msgb_length(iofd->pending) + msgb_length(msg) > iofd.msgb_alloc.size.
	 * Limit allowed segment size to maximum a msgb can contain. */
	uint16_t append_bytes = OSMO_MIN(msgb_length(in_msg), iofd_msgb_length_max(iofd) - msgb_length(iofd->pending));

	/* Recreate iofd->pending to contain as much data as possible: */
	struct msgb *new_pending = iofd_msgb_alloc2(iofd, msgb_length(iofd->pending) + append_bytes);
	OSMO_ASSERT(new_pending);
	memcpy(msgb_put(new_pending, msgb_length(iofd->pending)),
	       msgb_data(iofd->pending),
	       msgb_length(iofd->pending));
	msgb_free(iofd->pending);
	iofd->pending = new_pending;

	/* Append as much new data as possible into iofd->pending: */
	memcpy(msgb_put(iofd->pending, append_bytes),
	       msgb_data(in_msg),
	       append_bytes);
	if (OSMO_LIKELY(msgb_length(in_msg) == 0)) {
		msgb_free(in_msg);
		return NULL;
	}
	msgb_pull(in_msg, append_bytes);
	return in_msg;
}

/*! Restore message boundaries on read() and pass individual messages to the read callback
 */
static void iofd_handle_segmented_read(struct osmo_io_fd *iofd, int rc, struct msgb *msg)
{
	int res;
	struct msgb *tail_msg;

	OSMO_ASSERT(iofd->mode == OSMO_IO_FD_MODE_READ_WRITE);

	if (rc <= 0) {
		_call_read_cb(iofd, rc, msg);
		return;
	}

	/* Base case: our tail msg is the just received chunk */
	tail_msg = msg;
	do {
		if (OSMO_UNLIKELY(iofd->pending)) {
			/* If we have a pending message, append the received message.
			 * If the pending message is not large enough, create a larger message. */
			if (tail_msg)
				tail_msg = iofd_prepare_handle_segmentation(iofd, tail_msg);
			msg = iofd->pending;
			iofd->pending = NULL;
		} else {
			OSMO_ASSERT(tail_msg);
			msg = tail_msg;
			tail_msg = NULL;
		}

		/* At this point:
		 * iofd->pending is NULL.
		 * "msg" points to the chunk to be segmented.
		 * "tail_msg" may contain extra data to be appended and processed later (or NULL). */

		res = iofd_handle_segmentation(iofd, msg, &iofd->pending);
		if (res != IOFD_SEG_ACT_DEFER) {
			/* It it expected as per API spec that we return the
			 * return value of read here. The amount of bytes in msg is
			 * available to the user in msg itself. */
			_call_read_cb(iofd, rc, msg);
			/* The user could unregister/close the iofd during read_cb() above.
			 * Once that's done, it doesn't expect to receive any more events,
			 * so discard it: */
			if (!IOFD_FLAG_ISSET(iofd, IOFD_FLAG_FD_REGISTERED))
				return;

		} else { /* IOFD_SEG_ACT_DEFER */
			if (OSMO_UNLIKELY(errno != EAGAIN)) {
				/* Pass iofd->Pending to user app for debugging purposes: */
				msg = iofd->pending;
				iofd->pending = NULL;
				_call_read_cb(iofd, -errno, iofd->pending);
				return;
			}
			if (OSMO_UNLIKELY(msgb_length(iofd->pending) == iofd_msgb_length_max(iofd))) {
				LOGPIO(iofd, LOGL_ERROR,
				       "Rx segment msgb of > %" PRIu16 " bytes (headroom %u bytes) is unsupported, check your segment_cb!\n",
				       msgb_length(msg), iofd->msgb_alloc.headroom);
				/* Pass iofd->Pending to user app for debugging purposes: */
				msg = iofd->pending;
				iofd->pending = NULL;
				_call_read_cb(iofd, -EPROTO, msg);
				return;
			}
		}
	} while (res == IOFD_SEG_ACT_HANDLE_MORE || OSMO_UNLIKELY(tail_msg));
}

/*! completion handler: Internal function called by osmo_io_backend after a given I/O operation has completed
 *  \param[in] iofd I/O file-descriptor on which I/O has completed
 *  \param[in] msg message buffer containing data related to completed I/O
 *  \param[in] rc result code with read size or error (-errno)
 *  \param[in] hdr serialized msghdr containing state of completed I/O */
void iofd_handle_recv(struct osmo_io_fd *iofd, struct msgb *msg, int rc, struct iofd_msghdr *hdr)
{
	switch (iofd->mode) {
	case OSMO_IO_FD_MODE_READ_WRITE:
		iofd_handle_segmented_read(iofd, rc, msg);
		break;
	case OSMO_IO_FD_MODE_RECVFROM_SENDTO:
		talloc_steal(iofd->msgb_alloc.ctx, msg);
		iofd->io_ops.recvfrom_cb(iofd, rc, msg, &hdr->osa);
		break;
	case OSMO_IO_FD_MODE_RECVMSG_SENDMSG:
		talloc_steal(iofd->msgb_alloc.ctx, msg);
		iofd->io_ops.recvmsg_cb(iofd, rc, msg, &hdr->hdr);
		break;
	default:
		OSMO_ASSERT(false);
		break;
	}
}

/*! completion handler: Internal function called by osmo_io_backend after a given I/O operation has completed
 *  \param[in] iofd I/O file-descriptor on which I/O has completed
 *  \param[in] rc return value of the I/O operation
 *  \param[in] msghdr serialized msghdr containing state of completed I/O
 */
void iofd_handle_send_completion(struct osmo_io_fd *iofd, int rc, struct iofd_msghdr *msghdr)
{
	int idx, i;

	/* Re-enqueue the complete msgb. */
	if (rc == -EAGAIN) {
		iofd_txqueue_enqueue_front(iofd, msghdr);
		return;
	}

	for (idx = 0; idx < msghdr->io_len; idx++) {
		struct msgb *msg = msghdr->msg[idx];
		int chunk;

		/* Incomplete write */
		if (rc > 0 && rc < msgb_length(msg)) {
			/* Keep msg with unsent data only. */
			msgb_pull(msg, rc);
			msghdr->iov[idx].iov_len = msgb_length(msg);
			/* Shift all existing buffers down. */
			if (idx) {
				msghdr->io_len -= idx;
				for (i = 0; i < msghdr->io_len; i++) {
					msghdr->iov[i] = msghdr->iov[idx + i];
					msghdr->msg[i] = msghdr->msg[idx + i];
				}
				for (i = 0; i < idx; i++) {
					memset(&msghdr->iov[msghdr->io_len + i], 0, sizeof(struct iovec));
					msghdr->msg[msghdr->io_len + i] = NULL;
				}
				msghdr->hdr.msg_iovlen = msghdr->io_len;
			}
			/* Re-enqueue remaining buffers. */
			iofd_txqueue_enqueue_front(iofd, msghdr);
			return;
		}

		if (rc >= 0) {
			chunk = msgb_length(msg);
			if (rc < chunk)
				chunk = rc;
		} else {
			chunk = rc;
		}

		/* All other failure and success cases are handled here */
		switch (msghdr->action) {
		case IOFD_ACT_WRITE:
			if (iofd->io_ops.write_cb)
				iofd->io_ops.write_cb(iofd, chunk, msg);
			break;
		case IOFD_ACT_SENDTO:
			if (iofd->io_ops.sendto_cb)
				iofd->io_ops.sendto_cb(iofd, chunk, msg, &msghdr->osa);
			break;
		case IOFD_ACT_SENDMSG:
			if (iofd->io_ops.sendmsg_cb)
				iofd->io_ops.sendmsg_cb(iofd, chunk, msg);
			break;
		default:
			OSMO_ASSERT(0);
		}

		msgb_free(msghdr->msg[idx]);
		msghdr->msg[idx] = NULL;

		/* The user can unregister/close the iofd during callback above. */
		if (!IOFD_FLAG_ISSET(iofd, IOFD_FLAG_FD_REGISTERED))
			break;
	}
	iofd_msghdr_free(msghdr);
}

/* Public functions */

/*! Write a message to a file descriptor / connected socket.
 *  The osmo_io_fd must be using OSMO_IO_FD_MODE_READ_WRITE.
 *
 *  Appends the message to the internal transmit queue for eventual non-blocking
 *  write to the underlying socket/file descriptor.
 *
 *  If the function returns success (0) it will take ownership of the msgb and
 *  internally call msgb_free() after the write request completes.
 *  In case of an error, the msgb needs to be freed by the caller.
 *
 *  \param[in] iofd osmo_io_fd file descriptor to write data to
 *  \param[in] msg message buffer containing the data to write
 *  \returns 0 in case of success; a negative value in case of error
 */
int osmo_iofd_write_msgb(struct osmo_io_fd *iofd, struct msgb *msg)
{
	int rc;
	struct iofd_msghdr *msghdr;
	int idx;

	if (OSMO_UNLIKELY(msgb_length(msg) == 0)) {
		LOGPIO(iofd, LOGL_ERROR, "Length is 0, rejecting msgb.\n");
		return -EINVAL;
	}

	OSMO_ASSERT(iofd->mode == OSMO_IO_FD_MODE_READ_WRITE);

	/* Always try to add msg to last msghdr. Only if it is completely filled, allocate a new msghdr.
	 * This way all the previous meghdrs in the queue are completely filled. */
	msghdr = llist_last_entry_or_null(&iofd->tx_queue.msg_queue, struct iofd_msghdr, list);
	if (msghdr && msghdr->io_len < iofd->io_write_buffers) {
		/* Add msg to existing msghdr. */
		msghdr->msg[msghdr->io_len++] = msg;
	} else {
		/* Create new msghdr with msg. */
		msghdr = iofd_msghdr_alloc(iofd, IOFD_ACT_WRITE, msg, 0);
		if (!msghdr)
			return -ENOMEM;
		msghdr->hdr.msg_iov = &msghdr->iov[0];
		msghdr->flags = MSG_NOSIGNAL;
	}

	/* Add set IO vector to msg. */
	idx = msghdr->io_len - 1;
	msghdr->iov[idx].iov_base = msgb_data(msg);
	msghdr->iov[idx].iov_len = msgb_length(msg);
	msghdr->hdr.msg_iovlen = msghdr->io_len;

	/* Only new msghdr will be enqueued. */
	if (msghdr->io_len == 1) {
		rc = iofd_txqueue_enqueue(iofd, msghdr);
		if (rc < 0) {
			iofd_msghdr_free(msghdr);
			LOGPIO(iofd, LOGL_ERROR, "enqueueing message failed (%d). Rejecting msgb\n", rc);
			return rc;
		}
	}

	return 0;
}

/*! Send a message through an unconnected socket.
 *  The osmo_io_fd must be using OSMO_IO_FD_MODE_RECVFROM_SENDTO.
 *
 *  Appends the message to the internal transmit queue for eventual non-blocking
 *  sendto on the underlying socket/file descriptor.
 *
 *  If the function returns success (0), it will take ownership of the msgb and
 *  internally call msgb_free() after the sendto request completes.
 *  In case of an error the msgb needs to be freed by the caller.
 *
 *  \param[in] iofd file descriptor to write to
 *  \param[in] msg message buffer to send
 *  \param[in] sendto_flags Flags to pass to the send call
 *  \param[in] dest destination address to send the message to
 *  \returns 0 in case of success; a negative value in case of error
 */
int osmo_iofd_sendto_msgb(struct osmo_io_fd *iofd, struct msgb *msg, int sendto_flags, const struct osmo_sockaddr *dest)
{
	int rc;

	if (OSMO_UNLIKELY(msgb_length(msg) == 0)) {
		LOGPIO(iofd, LOGL_ERROR, "Length is 0, rejecting msgb.\n");
		return -EINVAL;
	}

	OSMO_ASSERT(iofd->mode == OSMO_IO_FD_MODE_RECVFROM_SENDTO);

	struct iofd_msghdr *msghdr = iofd_msghdr_alloc(iofd, IOFD_ACT_SENDTO, msg, 0);
	if (!msghdr)
		return -ENOMEM;

	if (dest) {
		msghdr->osa = *dest;
		msghdr->hdr.msg_name = &msghdr->osa.u.sa;
		msghdr->hdr.msg_namelen = osmo_sockaddr_size(&msghdr->osa);
	}
	msghdr->flags = sendto_flags;
	msghdr->iov[0].iov_base = msgb_data(msghdr->msg[0]);
	msghdr->iov[0].iov_len = msgb_length(msghdr->msg[0]);
	msghdr->hdr.msg_iov = &msghdr->iov[0];
	msghdr->hdr.msg_iovlen = 1;

	rc = iofd_txqueue_enqueue(iofd, msghdr);
	if (rc < 0) {
		iofd_msghdr_free(msghdr);
		return rc;
	}

	return 0;
}

/*! osmo_io equivalent of the sendmsg(2) socket API call.
 *  The osmo_io_fd must be using OSMO_IO_FD_MODE_RECVMSG_SENDMSG.
 *
 *  Appends the message to the internal transmit queue for eventual non-blocking
 *  sendmsg on the underlying socket/file descriptor.
 *
 *  If the function returns success (0), it will take ownership of the msgb and
 *  internally call msgb_free() after the sendmsg request completes.
 *  In case of an error the msgb needs to be freed by the caller.
 *
 *  \param[in] iofd file descriptor to write to
 *  \param[in] msg message buffer to send; is used to fill msgh->iov[]
 *  \param[in] sendmsg_flags Flags to pass to the send call
 *  \param[in] msgh 'struct msghdr' for name/control/flags. iov must be empty!
 *  \returns 0 in case of success; a negative value in case of error
 */
int osmo_iofd_sendmsg_msgb(struct osmo_io_fd *iofd, struct msgb *msg, int sendmsg_flags, const struct msghdr *msgh)
{
	int rc;
	struct iofd_msghdr *msghdr;

	if (OSMO_UNLIKELY(msgb_length(msg) == 0)) {
		LOGPIO(iofd, LOGL_ERROR, "Length is 0, rejecting msgb.\n");
		return -EINVAL;
	}

	OSMO_ASSERT(iofd->mode == OSMO_IO_FD_MODE_RECVMSG_SENDMSG);

	if (OSMO_UNLIKELY(msgh->msg_namelen > sizeof(msghdr->osa))) {
		LOGPIO(iofd, LOGL_ERROR, "osmo_iofd_sendmsg msg_namelen (%u) > supported %zu bytes\n",
			msgh->msg_namelen, sizeof(msghdr->osa));
		return -EINVAL;
	}

	if (OSMO_UNLIKELY(msgh->msg_iovlen)) {
		LOGPIO(iofd, LOGL_ERROR, "osmo_iofd_sendmsg must have all in 'struct msgb', not in 'msg_iov'\n");
		return -EINVAL;
	}

	msghdr = iofd_msghdr_alloc(iofd, IOFD_ACT_SENDMSG, msg, msgh->msg_controllen);
	if (!msghdr)
		return -ENOMEM;

	/* copy over optional address */
	if (msgh->msg_name) {
		memcpy(&msghdr->osa, msgh->msg_name, msgh->msg_namelen);
		msghdr->hdr.msg_name = &msghdr->osa.u.sa;
		msghdr->hdr.msg_namelen = msgh->msg_namelen;
	}

	/* build iov from msgb */
	msghdr->iov[0].iov_base = msgb_data(msghdr->msg[0]);
	msghdr->iov[0].iov_len = msgb_length(msghdr->msg[0]);
	msghdr->hdr.msg_iov = &msghdr->iov[0];
	msghdr->hdr.msg_iovlen = 1;

	/* copy over the cmsg from the msghdr */
	if (msgh->msg_control && msgh->msg_controllen) {
		msghdr->hdr.msg_control = msghdr->cmsg;
		msghdr->hdr.msg_controllen = msgh->msg_controllen;
		memcpy(msghdr->cmsg, msgh->msg_control, msgh->msg_controllen);
	}

	/* copy over msg_flags */
	msghdr->hdr.msg_flags = sendmsg_flags;

	rc = iofd_txqueue_enqueue(iofd, msghdr);
	if (rc < 0) {
		iofd_msghdr_free(msghdr);
		return rc;
	}

	return 0;
}

static int check_mode_callback_compat(enum osmo_io_fd_mode mode, const struct osmo_io_ops *ops)
{
	switch (mode) {
	case OSMO_IO_FD_MODE_READ_WRITE:
		if (ops->recvfrom_cb || ops->sendto_cb)
			return false;
		if (ops->recvmsg_cb || ops->sendmsg_cb)
			return false;
		/* Forbid both segementation_cb set, something is wrong: */
		if (ops->segmentation_cb && ops->segmentation_cb2)
			return false;
		break;
	case OSMO_IO_FD_MODE_RECVFROM_SENDTO:
		if (ops->read_cb || ops->write_cb)
			return false;
		if (ops->recvmsg_cb || ops->sendmsg_cb)
			return false;
		break;
	case OSMO_IO_FD_MODE_RECVMSG_SENDMSG:
		if (ops->recvfrom_cb || ops->sendto_cb)
			return false;
		if (ops->read_cb || ops->write_cb)
			return false;
		break;
	default:
		break;
	}

	return true;
}

/*! Allocate and setup a new iofd.
 *
 *  Use this to create a new osmo_io_fd, specifying the osmo_io_fd_mode and osmo_io_ops, as well as optionally
 *  the file-descriptor number and a human-readable name.  This is the first function you call for any
 *  osmo_io_fd.
 *
 *  The created osmo_io_fd is not yet registered, and hence can not be used for any I/O until a subsequent
 *  call to osmo_iofd_register().
 *
 *  The created osmo_io_fd is initialized with some default settings:
 *  * msgb allocations size: OSMO_IO_DEFAULT_MSGB_SIZE (1024)
 *  * msgb headroom: OSMO_IO_DEFAULT_MSGB_HEADROOM (128)
 *  * tx_queue depth: 1024
 *
 *  Those values may be adjusted from their defaults by using osmo_iofd_set_alloc_info() and
 *  osmo_iofd_set_txqueue_max_length() on the osmo_io_fd.
 *
 *  \param[in] ctx the parent context from which to allocate
 *  \param[in] fd the underlying system file descriptor. May be -1 if not known yet; must then be specified
 *  at subsequent osmo_iofd_register() time.
 *  \param[in] name the optional human-readable name of the iofd; may be NULL
 *  \param[in] mode the osmo_io_fd_mode of the iofd, whether it should use read()/write(), sendto()/recvfrom()
 *  semantics.
 *  \param[in] ioops structure specifying the read/write/send/recv callbacks. Will be copied to the iofd, so
 *  the caller does not have to keep it around after issuing the osmo_iofd_setup call.
 *  \param[in] data opaque user data pointer accessible by the ioops callbacks
 *  \returns The newly allocated osmo_io_fd struct or NULL on failure
 */
struct osmo_io_fd *osmo_iofd_setup(const void *ctx, int fd, const char *name, enum osmo_io_fd_mode mode,
		  const struct osmo_io_ops *ioops, void *data)
{
	struct osmo_io_fd *iofd;

	/* reject unsupported/unknown modes */
	switch (mode) {
	case OSMO_IO_FD_MODE_READ_WRITE:
	case OSMO_IO_FD_MODE_RECVFROM_SENDTO:
	case OSMO_IO_FD_MODE_RECVMSG_SENDMSG:
		break;
	default:
		return NULL;
	}

	if (ioops && !check_mode_callback_compat(mode, ioops)) {
		LOGP(DLIO, LOGL_ERROR, "iofd(%s): rejecting call-backs incompatible with mode %s\n",
			name ? name : "unknown", osmo_iofd_mode_name(mode));
		return NULL;
	}

	iofd = talloc_zero(ctx, struct osmo_io_fd);
	if (!iofd)
		return NULL;

	iofd->fd = fd;
	iofd->mode = mode;
	IOFD_FLAG_SET(iofd, IOFD_FLAG_CLOSED);

	if (name)
		iofd->name = talloc_strdup(iofd, name);

	if (ioops)
		iofd->io_ops = *ioops;

	iofd->pending = NULL;

	iofd->data = data;

	iofd->msgb_alloc.ctx = ctx;
	iofd->msgb_alloc.size = OSMO_IO_DEFAULT_MSGB_SIZE;
	iofd->msgb_alloc.headroom = OSMO_IO_DEFAULT_MSGB_HEADROOM;

	iofd->tx_queue.max_length = 1024;
	INIT_LLIST_HEAD(&iofd->tx_queue.msg_queue);

	iofd->io_read_buffers = 1;
	iofd->io_write_buffers = 1;

	if (osmo_iofd_ops.setup) {
		int rc = osmo_iofd_ops.setup(iofd);
		if (rc < 0)  {
			osmo_iofd_free(iofd);
			return NULL;
		}
	}

	return iofd;
}

/*! Set the size of the control message buffer allocated when submitting recvmsg.
 *
 * If your osmo_io_fd is in OSMO_IO_FD_MODE_RECVMSG_SENDMSG mode, this API function can be used to tell the
 * osmo_io code how much memory should be allocated for the cmsg (control message) buffer when performing
 * recvmsg(). */
int osmo_iofd_set_cmsg_size(struct osmo_io_fd *iofd, size_t cmsg_size)
{
	if (iofd->mode != OSMO_IO_FD_MODE_RECVMSG_SENDMSG)
		return -EINVAL;

	iofd->cmsg_size = cmsg_size;
	return 0;
}

/*! Set the number of buffers that can be used in a single read or write operation.
 *
 *  If the osmo_io_fd is in OSMO_IO_FD_MODE_READ_WRITE mode, this API function can be used to tell the
 *  osmo_io proecess how many buffers should be read or written with a single read or write operation.
 *
 *  \param[in] iofd the iofd file descriptor
 *  \param[in] op the osmo_io_op (read or write) to set the number of IO buffers for
 *  \param[in] buffers the number of IO buffer for each specified operation
 *  \returns zero on success, a negative value on error
 *
 * The minimum valid buffers to set is always 1.
 * The maximum valid buffers is implementation defined, and trying to set a
 * value greater than the maximum will return an error.
 * Passing \ref buffers with a value of 0 can be used to fetch the maximum value allowed.
 */
int osmo_iofd_set_io_buffers(struct osmo_io_fd *iofd, enum osmo_io_op op, uint8_t buffers)
{
	if (iofd->mode != OSMO_IO_FD_MODE_READ_WRITE)
		return -EINVAL;

	if (buffers > IOFD_MSGHDR_IO_BUFFERS)
		return -EINVAL;

	if (buffers == 0)
		return IOFD_MSGHDR_IO_BUFFERS;

	switch (op) {
	case OSMO_IO_OP_READ:
		iofd->io_read_buffers = buffers;
		break;
	case OSMO_IO_OP_WRITE:
		iofd->io_write_buffers = buffers;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/*! Set the number of SQEs that are submitted to an io_unring before completion is received.
 *
 *  If the io_using backend is selected, this API function can be used to tell the osmo_io process how many SQE are
 *  scheduled in advance.
 *  The feature is currently supports scheduling read SQEs only.
 *
 *  \param[in] iofd the iofd file descriptor
 *  \param[in] op the osmo_io_op (read) to set the number of IO buffers for
 *  \param[in] number of scheduled SQEs
 *  \returns zero on success, a negative value on error
 */
int osmo_iofd_set_sqes(struct osmo_io_fd *iofd, enum osmo_io_op op, uint8_t sqes)
{
	if (iofd->mode != OSMO_IO_FD_MODE_READ_WRITE)
		return -EINVAL;

	if (g_io_backend != OSMO_IO_BACKEND_IO_URING)
		return -EINVAL;

	if (op != OSMO_IO_OP_READ)
		return -EINVAL;

	if (sqes < 1 || sqes > IOFD_MSGHDR_MAX_READ_SQES)
		return -EINVAL;

	iofd->u.uring.read.num_sqes = sqes;
	return 0;
}

/*! Register the osmo_io_fd for active I/O.
 *
 *  Calling this function will register a previously initialized osmo_io_fd for performing I/O.
 *
 *  If the osmo_iofd has a read_cb/recvfrom_cb_recvmsg_cb set in its osmo_io_ops, read/receive will be
 *  automatically enabled and the respective call-back is called at any time data becomes available.
 *
 *  If there is to-be-transmitted data in the transmit queue, write will be automatically enabled, allowing
 *  the transmit queue to be drained as soon as the fd/socket becomes writable.
 *
 *  \param[in] iofd the iofd file descriptor
 *  \param[in] fd the system fd number that will be registered. If you did not yet specify the file descriptor
 *  number during osmo_fd_setup(), or if it has changed since then, you can state the [new] file descriptor
 *  number as argument.  If you wish to proceed with the previously specified file descriptor number, pass -1.
 *  \returns zero on success, a negative value on error
*/
int osmo_iofd_register(struct osmo_io_fd *iofd, int fd)
{
	int rc = 0;

	if (IOFD_FLAG_ISSET(iofd, IOFD_FLAG_FD_REGISTERED)) {
		/* If re-registering same fd, handle as NO-OP.
		 * And it is an even more explicit NO-OP
		 * if the caller passed in -1. */
		if (fd < 0 || fd == iofd->fd)
			return 0;
		/* New FD should go through unregister() first. */
		return -ENOTSUP;
	}

	if (fd >= 0)
		iofd->fd = fd;
	if (iofd->fd < 0) {
		/* this might happen if both osmo_iofd_setup() and osmo_iofd_register() are called with -1 */
		LOGPIO(iofd, LOGL_ERROR, "Cannot register io_fd using invalid fd == %d\n", iofd->fd);
		return -EBADF;
	}

	rc = osmo_iofd_ops.register_fd(iofd);
	if (rc)
		return rc;

	IOFD_FLAG_UNSET(iofd, IOFD_FLAG_CLOSED);
	IOFD_FLAG_SET(iofd, IOFD_FLAG_FD_REGISTERED);

	if ((iofd->mode == OSMO_IO_FD_MODE_READ_WRITE && iofd->io_ops.read_cb) ||
	    (iofd->mode == OSMO_IO_FD_MODE_RECVFROM_SENDTO && iofd->io_ops.recvfrom_cb) ||
	    (iofd->mode == OSMO_IO_FD_MODE_RECVMSG_SENDMSG && iofd->io_ops.recvmsg_cb)) {
		osmo_iofd_ops.read_enable(iofd);
	}

	if (iofd->tx_queue.current_length > 0)
		osmo_iofd_ops.write_enable(iofd);

	return rc;
}

/*! Unregister the given osmo_io_fd from osmo_io.
 *
 *  After an osmo_io_fd has been successfully unregistered, it can no longer perform any I/O via osmo_io.
 *  However, it can be subsequently re-registered using osmo_iofd_register().
 *
 *  \param[in] iofd the file descriptor
 *  \returns zero on success, a negative value on error
 */
int osmo_iofd_unregister(struct osmo_io_fd *iofd)
{
	int rc;

	if (!IOFD_FLAG_ISSET(iofd, IOFD_FLAG_FD_REGISTERED))
		return 0;

	rc = osmo_iofd_ops.unregister_fd(iofd);
	IOFD_FLAG_UNSET(iofd, IOFD_FLAG_FD_REGISTERED);
	return rc;
}

/*! Retrieve the number of messages pending in the transmit queue.
 *
 *  \param[in] iofd the file descriptor
 */
unsigned int osmo_iofd_txqueue_len(struct osmo_io_fd *iofd)
{
	return iofd->tx_queue.current_length;
}

/*! Clear the transmit queue of the given osmo_io_fd.
 *
 *  This function frees all messages currently pending in the transmit queue
 *  \param[in] iofd the file descriptor
 */
void osmo_iofd_txqueue_clear(struct osmo_io_fd *iofd)
{
	struct iofd_msghdr *hdr;
	while ((hdr = iofd_txqueue_dequeue(iofd))) {
		for (int idx = 0; idx < hdr->io_len; idx++) {
			msgb_free(hdr->msg[idx]);
			hdr->msg[idx] = NULL;
		}
		iofd_msghdr_free(hdr);
	}
}

/*! Free the given osmo_io_fd.
 *
 *  The iofd will be automatically closed before via osmo_iofd_close() [which in turn will unregister
 *  it and clear any pending transmit queue items].  You must not reference the iofd
 *  after calling this function.  However, it is safe to call this function from any of osmo_io
 *  call-backs; in this case, actual free will be internally delayed until that call-back completes.
 *
 *  \param[in] iofd the file descriptor
 */
void osmo_iofd_free(struct osmo_io_fd *iofd)
{
	if (!iofd)
		return;

	osmo_iofd_close(iofd);

	if (!IOFD_FLAG_ISSET(iofd, IOFD_FLAG_IN_CALLBACK)) {
		talloc_free(iofd);
	} else {
		/* Prevent our parent context from freeing us prematurely */
		talloc_steal(NULL, iofd);
		IOFD_FLAG_SET(iofd, IOFD_FLAG_TO_FREE);
	}
}

/*! Close the given osmo_io_fd.
 *
 *  This function closes the underlying fd, unregisters it from osmo_io and clears any messages in the tx
 *  queue.  The iofd itself is not freed and can be assigned a new file descriptor with osmo_iofd_register()
 *  \param[in] iofd the file descriptor
 *  \returns 0 on success, a negative value otherwise
 */
int osmo_iofd_close(struct osmo_io_fd *iofd)
{
	int rc = 0;

	if (IOFD_FLAG_ISSET(iofd, IOFD_FLAG_CLOSED))
		return rc;

	IOFD_FLAG_SET(iofd, IOFD_FLAG_CLOSED);

	/* Free pending msgs in tx queue */
	osmo_iofd_txqueue_clear(iofd);
	msgb_free(iofd->pending);

	iofd->pending = NULL;

	osmo_iofd_ops.read_disable(iofd);
	osmo_iofd_ops.write_disable(iofd);
	osmo_iofd_unregister(iofd);

	rc = osmo_iofd_ops.close(iofd);
	iofd->fd = -1;
	return rc;
}

/*! Set the size and headroom of the msgb allocated when receiving messages.
 *  \param[in] iofd the file descriptor
 *  \param[in] size the size of the msgb when receiving data
 *  \param[in] headroom the headroom of the msgb when receiving data
 */
void osmo_iofd_set_alloc_info(struct osmo_io_fd *iofd, unsigned int size, unsigned int headroom)
{
	OSMO_ASSERT(size + headroom <= 0xffff);
	iofd->msgb_alloc.headroom = headroom;
	iofd->msgb_alloc.size = size;
}

/*! Set the maximum number of messages enqueued for sending.
 *  \param[in] iofd the file descriptor
 *  \param[in] size the maximum size of the transmit queue
 */
void osmo_iofd_set_txqueue_max_length(struct osmo_io_fd *iofd, unsigned int max_length)
{
	iofd->tx_queue.max_length = max_length;
}


/*! Get the maximum number of messages enqueued for sending.
 *  \param[in] iofd the file descriptor
 *  \returns the maximum size of the transmit queue
 */
unsigned int osmo_iofd_get_txqueue_max_length(const struct osmo_io_fd *iofd)
{
	return iofd->tx_queue.max_length;
}

/*! Retrieve the associated user-data from an osmo_io_fd.
 *
 *  A call to this function will return the opaque user data pointer which was specified previously
 *  via osmo_iofd_setup() or via osmo_iofd_set_data().
 *
 *  \param[in] iofd the file descriptor
 *  \returns the data that was previously set with \ref osmo_iofd_setup()
 */
void *osmo_iofd_get_data(const struct osmo_io_fd *iofd)
{
	return iofd->data;
}

/*! Set the associated user-data from an osmo_io_fd.
 *
 *  Calling this function will set/overwrite the opaque user data pointer, which can later be retrieved using
 *  osmo_iofd_get_data().
 *
 *  \param[in] iofd the file descriptor
 *  \param[in] data the data to set
 */
void osmo_iofd_set_data(struct osmo_io_fd *iofd, void *data)
{
	iofd->data = data;
}

/*! Retrieve the private number from an osmo_io_fd.
 *  Calling this function will retrieve the private user number previously set via osmo_iofd_set_priv_nr().
 *  \param[in] iofd the file descriptor
 *  \returns the private number that was previously set with \ref osmo_iofd_set_priv_nr()
 */
unsigned int osmo_iofd_get_priv_nr(const struct osmo_io_fd *iofd)
{
	return iofd->priv_nr;
}

/*! Set the private number of an osmo_io_fd.
 *  The priv_nr passed in via this call can later be retrieved via osmo_iofd_get_priv_nr().  It provides
 *  a way how additional context can be stored in the osmo_io_fd beyond the opaque 'data' pointer.
 *  \param[in] iofd the file descriptor
 *  \param[in] priv_nr the private number to set
 */
void osmo_iofd_set_priv_nr(struct osmo_io_fd *iofd, unsigned int priv_nr)
{
	iofd->priv_nr = priv_nr;
}

/*! Retrieve the underlying file descriptor from an osmo_io_fd.
 *  \param[in] iofd the file descriptor
 *  \returns the underlying file descriptor number */
int osmo_iofd_get_fd(const struct osmo_io_fd *iofd)
{
	return iofd->fd;
}

/*! Retrieve the human-readable name of the given osmo_io_fd.
 *  \param[in] iofd the file descriptor
 *  \returns the name of the iofd as given in \ref osmo_iofd_setup() */
const char *osmo_iofd_get_name(const struct osmo_io_fd *iofd)
{
	return iofd->name;
}

/*! Set the human-readable name of the file descriptor.
 *  The given name will be used as context by all related logging and future calls to osmo_iofd_get_name().
 *  \param[in] iofd the file descriptor
 *  \param[in] name the name to set on the file descriptor */
void osmo_iofd_set_name(struct osmo_io_fd *iofd, const char *name)
{
	osmo_talloc_replace_string(iofd, &iofd->name, name);
}

/*! Set the human-readable name of the file descriptor using arguments like printf()
 *  \param[in] iofd the file descriptor
 *  \param[in] fmt the fmt to set on the file descriptor */
void osmo_iofd_set_name_f(struct osmo_io_fd *iofd, const char *fmt, ...)
{
	char *name = NULL;

	if (fmt) {
		va_list ap;

		va_start(ap, fmt);
		name = talloc_vasprintf(iofd, fmt, ap);
		va_end(ap);
	}
	talloc_free((void *)iofd->name);
	iofd->name = name;
}

/*! Set the osmo_io_ops calbacks for an osmo_io_fd.
 *  This function can be used to update/overwrite the call-back functions for the given osmo_io_fd; it
 *  replaces the currently-set call-back function pointers from a previous call to osmo_iofd_set_ioops()
 *  or the original osmo_iofd_setup().
 *  \param[in] iofd Target iofd file descriptor
 *  \param[in] ioops osmo_io_ops structure to be copied to the osmo_io_fd.
 *  \returns 0 on success, negative on error */
int osmo_iofd_set_ioops(struct osmo_io_fd *iofd, const struct osmo_io_ops *ioops)
{
	if (!check_mode_callback_compat(iofd->mode, ioops)) {
		LOGPIO(iofd, LOGL_ERROR, "rejecting call-backs incompatible with mode %s\n",
			osmo_iofd_mode_name(iofd->mode));
		return -EINVAL;
	}

	iofd->io_ops = *ioops;

	switch (iofd->mode) {
	case OSMO_IO_FD_MODE_READ_WRITE:
		if (iofd->io_ops.read_cb)
			osmo_iofd_ops.read_enable(iofd);
		else
			osmo_iofd_ops.read_disable(iofd);
		break;
	case OSMO_IO_FD_MODE_RECVFROM_SENDTO:
		if (iofd->io_ops.recvfrom_cb)
			osmo_iofd_ops.read_enable(iofd);
		else
			osmo_iofd_ops.read_disable(iofd);
		break;
	case OSMO_IO_FD_MODE_RECVMSG_SENDMSG:
		if (iofd->io_ops.recvmsg_cb)
			osmo_iofd_ops.read_enable(iofd);
		else
			osmo_iofd_ops.read_disable(iofd);
		break;
	default:
		OSMO_ASSERT(0);
	}

	return 0;
}

/*! Retrieve the osmo_io_ops for an iofd.
 *  \param[in] iofd Target iofd file descriptor
 *  \param[in] ioops caller-allocated osmo_io_ops structure to be filled */
void osmo_iofd_get_ioops(struct osmo_io_fd *iofd, struct osmo_io_ops *ioops)
{
	*ioops = iofd->io_ops;
}

/*! Request notification of the user if/when a client socket is connected.
 *  Calling this function will request osmo_io to notify the user (via
 *  write call-back with res=0 and msgb=NULL) once a non-blocking outbound
 *  connect() of the socket completes.
 *
 *  This only works for connection oriented sockets in either
 *  OSMO_IO_FD_MODE_READ_WRITE or OSMO_IO_FD_MODE_RECVMSG_SENDMSG mode.
 *
 * The fact that the write call-back is called with msgb=NULL can be used to
 * distinguish before this "connected" notification and a socket write failure.
 *
 * If the server transmits data quick enough after accepting the connection,
 * it may happen that a read call-back is triggered towards the user before this
 * special write-callback, since both events may come together from the kernel.
 * Hence under those scenarios where server starts the communication, it is
 * important not to assume or require that the write-callback(res=0, msgb=NULL)
 * will be the first one triggered.
 *
 *  \param[in] iofd the file descriptor */
void osmo_iofd_notify_connected(struct osmo_io_fd *iofd)
{
	OSMO_ASSERT(iofd->mode == OSMO_IO_FD_MODE_READ_WRITE ||
		    iofd->mode == OSMO_IO_FD_MODE_RECVMSG_SENDMSG);
	osmo_iofd_ops.notify_connected(iofd);
}

/*! @} */

#endif /* ifndef(EMBEDDED) */
