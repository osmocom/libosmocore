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
#if defined(__linux__)

#include <errno.h>
#include <stdio.h>
#include <talloc.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include "osmo_io_internal.h"

static void iofd_poll_ofd_cb_recvmsg_sendmsg(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_io_fd *iofd = ofd->data;
	struct msgb *msg;
	int rc, flags = 0;

	if (what & OSMO_FD_READ) {
		struct iofd_msghdr hdr;
		msg = iofd_msgb_pending_or_alloc(iofd);
		if (!msg) {
			LOGP(DLIO, LOGL_ERROR, "iofd(%s): Could not get msgb for reading\n", iofd->name);
			OSMO_ASSERT(0);
		}

		hdr.msg = msg;
		hdr.iov[0].iov_base = msgb_data(msg);
		hdr.iov[0].iov_len = msgb_tailroom(msg);
		hdr.hdr.msg_iov = &hdr.iov[0];
		hdr.hdr.msg_iovlen = 1;
		hdr.hdr.msg_name = &hdr.osa.u.sa;
		hdr.hdr.msg_namelen = sizeof(struct osmo_sockaddr);

		rc = recvmsg(ofd->fd, &hdr.hdr, flags);
		if (rc > 0)
			msgb_put(msg, rc);

		switch (iofd->mode) {
		case OSMO_IO_FD_MODE_READ_WRITE:
			iofd_handle_segmented_read(iofd, msg, rc);
			break;
		case OSMO_IO_FD_MODE_RECVFROM_SENDTO:
			iofd->io_ops.recvfrom_cb(iofd, rc, msg, &hdr.osa);
			break;
		case OSMO_IO_FD_MODE_SCTP_RECVMSG_SENDMSG:
			/* TODO Implement */
			OSMO_ASSERT(false);
			break;
		}
	}

	if (iofd->closed)
		return;

	if (what & OSMO_FD_WRITE) {
		struct iofd_msghdr *msghdr = iofd_txqueue_dequeue(iofd);
		if (msghdr) {
			msg = msghdr->msg;

			rc = sendmsg(ofd->fd, &msghdr->hdr, msghdr->flags);
			if (rc > 0 && rc < msgb_length(msg)) {
				msgb_pull(msg, rc);
				iofd_txqueue_enqueue_front(iofd, msghdr);
				return;
			}

			switch (iofd->mode) {
			case OSMO_IO_FD_MODE_READ_WRITE:
				iofd->io_ops.write_cb(iofd, rc, msg);
				break;
			case OSMO_IO_FD_MODE_RECVFROM_SENDTO:
				iofd->io_ops.sendto_cb(iofd, rc, msg, &msghdr->osa);
				break;
			case OSMO_IO_FD_MODE_SCTP_RECVMSG_SENDMSG:
				OSMO_ASSERT(false);
				break;
			}

			talloc_free(msghdr);
			msgb_free(msg);
		} else {
			if (iofd->mode == OSMO_IO_FD_MODE_READ_WRITE)
				/* Socket is writable, but we have no data to send. A non-blocking/async
				   connect() is signalled this way. */
				iofd->io_ops.write_cb(iofd, 0, NULL);
			if (osmo_iofd_txqueue_len(iofd) == 0)
				iofd_poll_ops.write_disable(iofd);
		}

	}
}

static int iofd_poll_ofd_cb_dispatch(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_io_fd *iofd = ofd->data;

	iofd->in_callback = true;
	iofd_poll_ofd_cb_recvmsg_sendmsg(ofd, what);
	iofd->in_callback = false;

	if (iofd->to_free) {
		talloc_free(iofd);
		return 0;
	}

	return 0;
}

int iofd_poll_register(struct osmo_io_fd *iofd)
{
	struct osmo_fd *ofd = &iofd->u.poll.ofd;
	osmo_fd_setup(ofd, iofd->fd, 0, &iofd_poll_ofd_cb_dispatch, iofd, 0);
	return osmo_fd_register(ofd);
}

int iofd_poll_unregister(struct osmo_io_fd *iofd)
{
	struct osmo_fd *ofd = &iofd->u.poll.ofd;
	osmo_fd_unregister(ofd);

	return 0;
}

int iofd_poll_close(struct osmo_io_fd *iofd)
{
	osmo_fd_close(&iofd->u.poll.ofd);

	return 0;
}

void iofd_poll_read_enable(struct osmo_io_fd *iofd)
{
	osmo_fd_read_enable(&iofd->u.poll.ofd);
}

void iofd_poll_read_disable(struct osmo_io_fd *iofd)
{
	osmo_fd_read_disable(&iofd->u.poll.ofd);
}

void iofd_poll_write_enable(struct osmo_io_fd *iofd)
{
	osmo_fd_write_enable(&iofd->u.poll.ofd);
}

void iofd_poll_write_disable(struct osmo_io_fd *iofd)
{
	osmo_fd_write_disable(&iofd->u.poll.ofd);
}

const struct iofd_backend_ops iofd_poll_ops = {
	.register_fd = iofd_poll_register,
	.unregister_fd = iofd_poll_unregister,
	.close = iofd_poll_close,
	.write_enable = iofd_poll_write_enable,
	.write_disable = iofd_poll_write_disable,
	.read_enable = iofd_poll_read_enable,
	.read_disable = iofd_poll_read_disable,
};

#endif /* defined(__linux__) */
