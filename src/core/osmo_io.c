/*! \file osmo_io.c
 * New osmocom async I/O API.
 *
 * (C) 2022 by Harald Welte <laforge@osmocom.org>
 * (C) 2022-2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
#if defined(__linux__)

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <talloc.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include "osmo_io_internal.h"

/*! This environment variable can be set to manually set the backend used in osmo_io */
#define OSMO_IO_BACKEND_ENV "LIBOSMO_IO_BACKEND"

const struct value_string osmo_io_backend_names[] = {
	{ OSMO_IO_BACKEND_POLL, "poll" },
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
	} else {
		fprintf(stderr, "Invalid osmo_io backend requested: \"%s\"\nCheck the environment variable %s\n", backend, OSMO_IO_BACKEND_ENV);
		exit(1);
	}

	osmo_iofd_init();
}

/*! Allocate the msghdr.
 *  \param[in] iofd the osmo_io file structure
 *  \param[in] action the action this msg(hdr) is for (read, write, ..)
 *  \param[in] msg the msg buffer to use. Will allocate a new one if NULL
 *  \returns the newly allocated msghdr or NULL in case of error */
struct iofd_msghdr *iofd_msghdr_alloc(struct osmo_io_fd *iofd, enum iofd_msg_action action, struct msgb *msg)
{
	struct iofd_msghdr *hdr = talloc_zero(iofd, struct iofd_msghdr);
	if (!hdr)
		return NULL;
	if (!msg) {
		msg = iofd_msgb_alloc(iofd);
		if (!msg) {
			talloc_free(hdr);
			return NULL;
		}
	}

	hdr->action = action;
	hdr->iofd = iofd;
	hdr->msg = msg;

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

/*! convenience wrapper to call msgb_alloc with parameters from osmo_io_fd */
struct msgb *iofd_msgb_alloc(struct osmo_io_fd *iofd)
{
	uint16_t headroom = iofd->msgb_alloc.headroom;

	OSMO_ASSERT(iofd->msgb_alloc.size < 0xffff - headroom);
	return msgb_alloc_headroom_c(iofd->msgb_alloc.ctx,
				     iofd->msgb_alloc.size + headroom, headroom,
				     iofd->name ? : "iofd_msgb");
}

/*! return the pending msgb in iofd or NULL if there is none*/
struct msgb *iofd_msgb_pending(struct osmo_io_fd *iofd)
{
	struct msgb *msg = NULL;

	msg = iofd->pending;
	iofd->pending = NULL;

	return msg;
}

/*! Return the pending msgb or allocate and return a new one */
struct msgb *iofd_msgb_pending_or_alloc(struct osmo_io_fd *iofd)
{
	struct msgb *msg = NULL;

	msg = iofd_msgb_pending(iofd);
	if (!msg)
		msg = iofd_msgb_alloc(iofd);

	return msg;
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
	if (iofd->tx_queue.current_length >= iofd->tx_queue.max_length)
		return -ENOSPC;

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
	struct llist_head *lh;

	if (iofd->tx_queue.current_length == 0)
		return NULL;

	lh = iofd->tx_queue.msg_queue.next;

	OSMO_ASSERT(lh);
	iofd->tx_queue.current_length--;
	llist_del(lh);

	if (iofd->tx_queue.current_length == 0)
		osmo_iofd_ops.write_disable(iofd);

	return llist_entry(lh, struct iofd_msghdr, list);
}

/*! Handle segmentation of the msg. If this function returns *_HANDLE_ONE or MORE then the data in msg will contain
 *  one complete message.
 *  If there are bytes left over, *pending_out will point to a msgb with the remaining data.
*/
static enum iofd_seg_act iofd_handle_segmentation(struct osmo_io_fd *iofd, struct msgb *msg, struct msgb **pending_out)
{
	int extra_len, received_len;
	struct msgb *msg_pending;

	/* Save the start of message before segmentation_cb (which could change it) */
	uint8_t *data = msg->data;

	received_len = msgb_length(msg);

	if (!iofd->io_ops.segmentation_cb) {
		*pending_out = NULL;
		return IOFD_SEG_ACT_HANDLE_ONE;
	}

	int expected_len = iofd->io_ops.segmentation_cb(msg);
	if (expected_len == -EAGAIN) {
		goto defer;
	} else if (expected_len < 0) {
		/* Something is wrong, skip this msgb */
		LOGPIO(iofd, LOGL_ERROR, "segmentation_cb returned error (%d), skipping msg of size %d\n",
		       expected_len, received_len);
		*pending_out = NULL;
		msgb_free(msg);
		return IOFD_SEG_ACT_DEFER;
	}

	extra_len = received_len - expected_len;
	/* No segmentation needed, return the whole msgb */
	if (extra_len == 0) {
		*pending_out = NULL;
		return IOFD_SEG_ACT_HANDLE_ONE;
	/* segment is incomplete */
	} else if (extra_len < 0) {
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

/*! Restore message boundaries on read() and pass individual messages to the read callback
 */
void iofd_handle_segmented_read(struct osmo_io_fd *iofd, struct msgb *msg, int rc)
{
	int res;
	struct msgb *pending = NULL;

	if (rc <= 0) {
		iofd->io_ops.read_cb(iofd, rc, msg);
		return;
	}

	do {
		res = iofd_handle_segmentation(iofd, msg, &pending);
		if (res != IOFD_SEG_ACT_DEFER || rc < 0)
			iofd->io_ops.read_cb(iofd, rc, msg);
		if (res == IOFD_SEG_ACT_HANDLE_MORE)
			msg = pending;
	} while (res == IOFD_SEG_ACT_HANDLE_MORE);

	OSMO_ASSERT(iofd->pending == NULL);
	iofd->pending = pending;
}

/* Public functions */

/*! Send a message through a connected socket.
 *
 *  Appends the message to the internal transmit queue.
 *  If the function returns success (0) it will take ownership of the msgb and
 *  internally call msgb_free() after the write request completes.
 *  In case of an error the msgb needs to be freed by the caller.
 *  \param[in] iofd file descriptor to write to
 *  \param[in] msg message buffer to write
 *  \returns 0 in case of success; a negative value in case of error
 */
int osmo_iofd_write_msgb(struct osmo_io_fd *iofd, struct msgb *msg)
{
	int rc;
	struct iofd_msghdr *msghdr = iofd_msghdr_alloc(iofd, IOFD_ACT_WRITE, msg);
	if (!msghdr)
		return -ENOMEM;

	msghdr->flags = 0;
	msghdr->iov[0].iov_base = msgb_data(msghdr->msg);
	msghdr->iov[0].iov_len = msgb_length(msghdr->msg);
	msghdr->hdr.msg_iov = &msghdr->iov[0];
	msghdr->hdr.msg_iovlen = 1;

	rc = iofd_txqueue_enqueue(iofd, msghdr);
	if (rc < 0) {
		iofd_msghdr_free(msghdr);
		LOGPIO(iofd, LOGL_ERROR, "enqueueing message failed (%d). Rejecting msgb\n", rc);
		return rc;
	}

	return 0;
}

/*! Send a message through an unconnected socket.
 *
 *  Appends the message to the internal transmit queue.
 *  If the function returns success (0), it will take ownership of the msgb and
 *  internally call msgb_free() after the write request completes.
 *  In case of an error the msgb needs to be freed by the caller.
 *  \param[in] iofd file descriptor to write to
 *  \param[in] msg message buffer to send
 *  \param[in] sendto_flags Flags to pass to the send call
 *  \param[in] dest destination address to send the message to
 *  \returns 0 in case of success; a negative value in case of error
 */
int osmo_iofd_sendto_msgb(struct osmo_io_fd *iofd, struct msgb *msg, int sendto_flags, const struct osmo_sockaddr *dest)
{
	int rc;

	OSMO_ASSERT(iofd->mode == OSMO_IO_FD_MODE_RECVFROM_SENDTO);

	struct iofd_msghdr *msghdr = iofd_msghdr_alloc(iofd, IOFD_ACT_SENDTO, msg);
	if (!msghdr)
		return -ENOMEM;

	if (dest) {
		msghdr->osa = *dest;
		msghdr->hdr.msg_name = &msghdr->osa.u.sa;
		msghdr->hdr.msg_namelen = osmo_sockaddr_size(&msghdr->osa);
	}
	msghdr->flags = sendto_flags;
	msghdr->iov[0].iov_base = msgb_data(msghdr->msg);
	msghdr->iov[0].iov_len = msgb_length(msghdr->msg);
	msghdr->hdr.msg_iov = &msghdr->iov[0];
	msghdr->hdr.msg_iovlen = 1;

	rc = iofd_txqueue_enqueue(iofd, msghdr);
	if (rc < 0) {
		iofd_msghdr_free(msghdr);
		LOGPIO(iofd, LOGL_ERROR, "enqueueing message failed (%d). Rejecting msgb\n", rc);
		return rc;
	}

	return 0;
}

/*! Allocate and setup a new iofd.
 *  \param[in] ctx the parent context from which to allocate
 *  \param[in] fd the underlying system file descriptor
 *  \param[in] name the name of the iofd
 *  \param[in] mode the mode of the iofd, whether it should use read()/write(), sendto()/recvfrom()
 *  \param[in] ioops structure with read/write/send/recv callbacks
 *  \param[in] data user data pointer accessible by the ioops callbacks
 *  \returns The newly allocated osmo_io_fd struct or NULL on failure
 */
struct osmo_io_fd *osmo_iofd_setup(const void *ctx, int fd, const char *name, enum osmo_io_fd_mode mode,
		  const struct osmo_io_ops *ioops, void *data)
{
	struct osmo_io_fd *iofd = talloc_zero(ctx, struct osmo_io_fd);
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

	iofd->tx_queue.max_length = 32;
	INIT_LLIST_HEAD(&iofd->tx_queue.msg_queue);

	return iofd;
}

/*! Register the fd with the underlying backend.
 *
 *  \param[in] iofd the iofd file descriptor
 *  \param[in] fd the system fd number that will be registeres. If negative will use the one already set.
 *  \returns zero on success, a negative value on error
*/
int osmo_iofd_register(struct osmo_io_fd *iofd, int fd)
{
	int rc = 0;

	if (fd >= 0)
		iofd->fd = fd;

	if (osmo_iofd_ops.register_fd)
		rc = osmo_iofd_ops.register_fd(iofd);
	if (rc)
		return rc;

	IOFD_FLAG_UNSET(iofd, IOFD_FLAG_CLOSED);
	osmo_iofd_ops.read_enable(iofd);

	if (iofd->tx_queue.current_length > 0)
		osmo_iofd_ops.write_enable(iofd);

	return rc;
}

/*! Unregister the fd from the underlying backend.
 *
 *  \param[in] iofd the file descriptor
 *  \returns zero on success, a negative value on error
 */
int osmo_iofd_unregister(struct osmo_io_fd *iofd)
{
	if (osmo_iofd_ops.unregister_fd)
		return osmo_iofd_ops.unregister_fd(iofd);
	IOFD_FLAG_SET(iofd, IOFD_FLAG_CLOSED);

	return 0;
}

/*! Get the number of messages in the tx queue.
 *
 *  \param[in] iofd the file descriptor
 */
unsigned int osmo_iofd_txqueue_len(struct osmo_io_fd *iofd)
{
	return iofd->tx_queue.current_length;
}

/*! Clear the transmit queue of the the iofd.
 *
 *  This function frees all messages currently pending in the transmit queue
 *  \param[in] iofd the file descriptor
 */
void osmo_iofd_txqueue_clear(struct osmo_io_fd *iofd)
{
	struct iofd_msghdr *hdr;
	while ((hdr = iofd_txqueue_dequeue(iofd))) {
		msgb_free(hdr->msg);
		iofd_msghdr_free(hdr);
	}
}

/*! Free the iofd.
 *
 *  This function is safe to use in the read/write callbacks and will defer freeing it until safe to do so.
 *  The iofd will be closed before.
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

/*! Close the iofd.
 *
 *  This function closes the underlying fd and clears any messages in the tx queue
 *  The iofd is not freed and can be assigned a new file descriptor with osmo_iofd_register()
 *  \param[in] iofd the file descriptor
 *  \ returns 0 on success, a negative value otherwise
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

	if (osmo_iofd_ops.close)
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

/*! Get the associated user-data from an iofd.
 *  \param[in] iofd the file descriptor
 *  \returns the data that was previously set with \ref osmo_iofd_setup()
 */
void *osmo_iofd_get_data(const struct osmo_io_fd *iofd)
{
	return iofd->data;
}

/*! Set the associated user-data from an iofd.
 *  \param[in] iofd the file descriptor
 *  \param[in] data the data to set
 */
void osmo_iofd_set_data(struct osmo_io_fd *iofd, void *data)
{
	iofd->data = data;
}

/*! Get the private number from an iofd.
 *  \param[in] iofd the file descriptor
 *  \returns the private number that was previously set with \ref osmo_iofd_set_priv_nr()
 */
unsigned int osmo_iofd_get_priv_nr(const struct osmo_io_fd *iofd)
{
	return iofd->priv_nr;
}

/*! Set the private number from an iofd.
 *  \param[in] iofd the file descriptor
 *  \param[in] priv_nr the private number to set
 */
void osmo_iofd_set_priv_nr(struct osmo_io_fd *iofd, unsigned int priv_nr)
{
	iofd->priv_nr = priv_nr;
}

/*! Get the underlying file descriptor from an iofd.
 *  \param[in] iofd the file descriptor
 *  \returns the underlying file descriptor number */
int osmo_iofd_get_fd(const struct osmo_io_fd *iofd)
{
	return iofd->fd;
}

/*! Get the name of the file descriptor.
 *  \param[in] iofd the file descriptor
 *  \returns the name of the iofd as given in \ref osmo_iofd_setup() */
const char *osmo_iofd_get_name(const struct osmo_io_fd *iofd)
{
	return iofd->name;
}

/*! Set the name of the file descriptor.
 *  \param[in] iofd the file descriptor
 *  \param[in] name the name to set on the file descriptor */
void osmo_iofd_set_name(struct osmo_io_fd *iofd, const char *name)
{
	osmo_talloc_replace_string(iofd, &iofd->name, name);
}

/*! Set the osmo_io_ops for an iofd.
 *  \param[in] iofd Target iofd file descriptor
 *  \param[in] ioops osmo_io_ops structure to be set */
void osmo_iofd_set_ioops(struct osmo_io_fd *iofd, const struct osmo_io_ops *ioops)
{
	iofd->io_ops = *ioops;
}

/*! Notify the user if/when the socket is connected.
 *  When the socket is connected the write_cb will be called.
 *  \param[in] iofd the file descriptor */
void osmo_iofd_notify_connected(struct osmo_io_fd *iofd)
{
	OSMO_ASSERT(iofd->mode == OSMO_IO_FD_MODE_READ_WRITE);
	osmo_iofd_ops.write_enable(iofd);
}


#endif /* defined(__linux__) */
