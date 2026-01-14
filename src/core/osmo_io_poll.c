/*! \file osmo_io_poll.c
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
#ifndef EMBEDDED

#include <errno.h>
#include <stdio.h>
#include <talloc.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include "osmo_io_internal.h"

/*! completion call-back for READ */
static void iofd_poll_handle_recv(struct iofd_msghdr *msghdr, int rc)
{
	struct osmo_io_fd *iofd = msghdr->iofd;
	uint8_t idx;

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
		if (IOFD_FLAG_ISSET(iofd, IOFD_FLAG_FD_REGISTERED) && (iofd->u.poll.ofd.when & OSMO_FD_READ))
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

	iofd_msghdr_free(msghdr);
}

static void iofd_poll_ofd_cb_recvmsg_sendmsg(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_io_fd *iofd = ofd->data;
	enum iofd_msg_action action;
	struct iofd_msghdr *msghdr;
	int rc;
	uint8_t idx;

	if (what & OSMO_FD_READ) {

		switch (iofd->mode) {
		case OSMO_IO_FD_MODE_READ_WRITE:
			action = IOFD_ACT_READ;
			break;
		case OSMO_IO_FD_MODE_RECVFROM_SENDTO:
			action = IOFD_ACT_RECVFROM;
			break;
		case OSMO_IO_FD_MODE_RECVMSG_SENDMSG:
			action = IOFD_ACT_RECVMSG;
			break;
		default:
			OSMO_ASSERT(0);
		}

		msghdr = iofd_msghdr_alloc(iofd, action, NULL, iofd->cmsg_size);
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
			rc = readv(ofd->fd, msghdr->hdr.msg_iov, msghdr->hdr.msg_iovlen);
			break;
		case IOFD_ACT_RECVFROM:
		case IOFD_ACT_RECVMSG:
			rc = recvmsg(ofd->fd, &msghdr->hdr, msghdr->flags);
			break;
		default:
			OSMO_ASSERT(0);
		}

		iofd_poll_handle_recv(msghdr, (rc < 0 && errno > 0) ? -errno : rc);
	}

	if (IOFD_FLAG_ISSET(iofd, IOFD_FLAG_CLOSED))
		return;

	if (what & OSMO_FD_WRITE) {
		msghdr = iofd_txqueue_dequeue(iofd);
		if (msghdr) {
			switch (iofd->mode) {
			case OSMO_IO_FD_MODE_READ_WRITE:
				rc = writev(ofd->fd, msghdr->iov, msghdr->io_len);
				break;
			case OSMO_IO_FD_MODE_RECVFROM_SENDTO:
			case OSMO_IO_FD_MODE_RECVMSG_SENDMSG:
				rc = sendmsg(ofd->fd, &msghdr->hdr, msghdr->flags);
				break;
			default:
				OSMO_ASSERT(0);
			}
			iofd_handle_send_completion(iofd, (rc < 0 && errno > 0) ? -errno : rc, msghdr);
		} else {
			/* Socket is writable, but we have no data to send. A non-blocking/async
			   connect() is signalled this way. */
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
			default:
				break;
			}
			if (osmo_iofd_txqueue_len(iofd) == 0)
				iofd_poll_ops.write_disable(iofd);
		}
	}
}

static int iofd_poll_ofd_cb_dispatch(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_io_fd *iofd = ofd->data;

	IOFD_FLAG_SET(iofd, IOFD_FLAG_IN_CALLBACK);
	iofd_poll_ofd_cb_recvmsg_sendmsg(ofd, what);
	IOFD_FLAG_UNSET(iofd, IOFD_FLAG_IN_CALLBACK);

	if (IOFD_FLAG_ISSET(iofd, IOFD_FLAG_TO_FREE)) {
		talloc_free(iofd);
		return 0;
	}

	return 0;
}

static int iofd_poll_register(struct osmo_io_fd *iofd)
{
	struct osmo_fd *ofd = &iofd->u.poll.ofd;
	int rc;

	osmo_fd_setup(ofd, iofd->fd, 0, &iofd_poll_ofd_cb_dispatch, iofd, 0);
	if (IOFD_FLAG_ISSET(iofd, IOFD_FLAG_NOTIFY_CONNECTED))
		osmo_fd_write_enable(&iofd->u.poll.ofd);

	rc = osmo_fd_register(ofd);
	return rc;
}

static int iofd_poll_unregister(struct osmo_io_fd *iofd)
{
	struct osmo_fd *ofd = &iofd->u.poll.ofd;
	osmo_fd_unregister(ofd);
	return 0;
}

static int iofd_poll_close(struct osmo_io_fd *iofd)
{
	osmo_fd_close(&iofd->u.poll.ofd);
	return 0;
}

static void iofd_poll_read_enable(struct osmo_io_fd *iofd)
{
	osmo_fd_read_enable(&iofd->u.poll.ofd);
}

static void iofd_poll_read_disable(struct osmo_io_fd *iofd)
{
	osmo_fd_read_disable(&iofd->u.poll.ofd);
}

static void iofd_poll_write_enable(struct osmo_io_fd *iofd)
{
	osmo_fd_write_enable(&iofd->u.poll.ofd);
}

static void iofd_poll_write_disable(struct osmo_io_fd *iofd)
{
	osmo_fd_write_disable(&iofd->u.poll.ofd);
}

static void iofd_poll_notify_connected(struct osmo_io_fd *iofd)
{
	/* Set flag to enable during register() time: */
	IOFD_FLAG_SET(iofd, IOFD_FLAG_NOTIFY_CONNECTED);

	osmo_fd_write_enable(&iofd->u.poll.ofd);
}

const struct iofd_backend_ops iofd_poll_ops = {
	.register_fd = iofd_poll_register,
	.unregister_fd = iofd_poll_unregister,
	.close = iofd_poll_close,
	.write_enable = iofd_poll_write_enable,
	.write_disable = iofd_poll_write_disable,
	.read_enable = iofd_poll_read_enable,
	.read_disable = iofd_poll_read_disable,
	.notify_connected = iofd_poll_notify_connected,
};

#endif /* ifndef EMBEDDED */
