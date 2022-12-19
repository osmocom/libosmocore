/* (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by Sylvain Munaut <tnt@246tNt.com>
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/signal.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/command.h>

/*! \file telnet_interface.c
 *  Telnet interface towards Osmocom VTY
 *
 *  This module contains the code implementing a telnet server for VTY
 *  access.  This telnet server gets linked into each libosmovty-using
 *  process in order to enable interactive command-line introspection,
 *  interaction and configuration.
 *
 *  You typically call telnet_init_default once
 *  from your application code to enable this.
 */

/* per connection data */
LLIST_HEAD(active_connections);

static void *tall_telnet_ctx;

/* per network data */
static int telnet_new_connection(struct osmo_fd *fd, unsigned int what);

static struct osmo_fd server_socket = {
	.when	    = OSMO_FD_READ,
	.cb	    = telnet_new_connection,
	.priv_nr    = 0,
};

/* Helper for deprecating telnet_init_dynif(), which previously held this code */
static int _telnet_init_dynif(void *tall_ctx, void *priv, const char *ip, int port)
{
	int rc;

	if (port < 0)
		return -EINVAL;

	tall_telnet_ctx = talloc_named_const(tall_ctx, 1,
			"telnet_connection");

	rc = osmo_sock_init_ofd(
			&server_socket,
			AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP,
			ip, port, OSMO_SOCK_F_BIND
			);

	server_socket.data = priv;

	if (rc < 0) {
		LOGP(DLGLOBAL, LOGL_ERROR, "Cannot bind telnet at %s %d\n",
		     ip, port);
		return rc;
	}

	LOGP(DLGLOBAL, LOGL_NOTICE, "Available via telnet %s %d\n", ip, port);
	return 0;
}

/*! Initialize telnet based VTY interface listening to 127.0.0.1
 *  \param[in] tall_ctx \ref talloc context
 *  \param[in] priv private data to be passed to callback
 *  \param[in] port TCP port number to bind to
 *  \deprecated use telnet_init_default() instead
 */
int telnet_init(void *tall_ctx, void *priv, int port)
{
	return _telnet_init_dynif(tall_ctx, priv, "127.0.0.1", port);
}

/*! Initialize telnet based VTY interface
 *  \param[in] tall_ctx \ref talloc context
 *  \param[in] priv private data to be passed to callback
 *  \param[in] ip IP to listen to ('::1' for localhost, '::0' for all, ...)
 *  \param[in] port TCP port number to bind to
 *  \deprecated use telnet_init_default() instead
 */
int telnet_init_dynif(void *tall_ctx, void *priv, const char *ip, int port)
{
	return _telnet_init_dynif(tall_ctx, priv, ip, port);
}

/*! Initializes telnet based VTY interface using the configured bind addr/port.
 *  \param[in] tall_ctx \ref talloc context
 *  \param[in] priv private data to be passed to callback
 *  \param[in] default_port TCP port number to bind to if not explicitly configured
 */
int telnet_init_default(void *tall_ctx, void *priv, int default_port)
{
	return _telnet_init_dynif(tall_ctx, priv, vty_get_bind_addr(),
				  vty_get_bind_port(default_port));
}


extern struct host host;

/*! close a telnet connection */
int telnet_close_client(struct osmo_fd *fd)
{
	struct telnet_connection *conn = (struct telnet_connection*)fd->data;
	char sock_name_buf[OSMO_SOCK_NAME_MAXLEN];
	int rc;

	/* FIXME: getsockname() always fails: "Bad file descriptor" */
	rc = osmo_sock_get_name_buf(sock_name_buf, OSMO_SOCK_NAME_MAXLEN, fd->fd);
	LOGP(DLGLOBAL, LOGL_INFO, "Closing telnet connection %s\n",
	     (rc <= 0) ? "r=NULL<->l=NULL" : sock_name_buf);

	close(fd->fd);
	osmo_fd_unregister(fd);

	if (conn->dbg) {
		log_del_target(conn->dbg);
		talloc_free(conn->dbg);
	}

	llist_del(&conn->entry);
	talloc_free(conn);
	return 0;
}

static int client_data(struct osmo_fd *fd, unsigned int what)
{
	struct telnet_connection *conn = fd->data;
	int rc = 0;

	if (what & OSMO_FD_READ) {
		conn->fd.when &= ~OSMO_FD_READ;
		rc = vty_read(conn->vty);
	}

	/* vty might have been closed from vithin vty_read() */
	if (rc == -EBADF)
		return rc;

	if (what & OSMO_FD_WRITE) {
		rc = buffer_flush_all(conn->vty->obuf, fd->fd);
		if (rc == BUFFER_EMPTY)
			conn->fd.when &= ~OSMO_FD_WRITE;
	}

	return rc;
}

static int telnet_new_connection(struct osmo_fd *fd, unsigned int what)
{
	struct telnet_connection *connection;
	struct sockaddr_in sockaddr;
	socklen_t len = sizeof(sockaddr);
	int new_connection = accept(fd->fd, (struct sockaddr*)&sockaddr, &len);
	char sock_name_buf[OSMO_SOCK_NAME_MAXLEN];
	int rc;

	if (new_connection < 0) {
		LOGP(DLGLOBAL, LOGL_ERROR, "telnet accept failed\n");
		return new_connection;
	}

	rc = osmo_sock_get_name_buf(sock_name_buf, OSMO_SOCK_NAME_MAXLEN, new_connection);
	LOGP(DLGLOBAL, LOGL_INFO, "Accept()ed new telnet connection %s\n",
	     (rc <= 0) ? "r=NULL<->l=NULL" : sock_name_buf);

	connection = talloc_zero(tall_telnet_ctx, struct telnet_connection);
	connection->priv = fd->data;
	connection->fd.data = connection;
	connection->fd.fd = new_connection;
	connection->fd.when = OSMO_FD_READ;
	connection->fd.cb = client_data;
	rc = osmo_fd_register(&connection->fd);
	if (rc < 0) {
		talloc_free(connection);
		return rc;
	}
	llist_add_tail(&connection->entry, &active_connections);

	connection->vty = vty_create(new_connection, connection);
	if (!connection->vty) {
		LOGP(DLGLOBAL, LOGL_ERROR, "couldn't create VTY\n");
		/* vty_create() is already closing the fd if it returns NULL */
		talloc_free(connection);
		return -1;
	}

	return 0;
}

bool vty_is_active(struct vty *vty)
{
	struct telnet_connection *connection;
	llist_for_each_entry(connection, &active_connections, entry) {
		if (connection->vty == vty)
			return true;
	}
	return false;
}

/*! callback from core VTY code about VTY related events */
void vty_event(enum event event, int sock, struct vty *vty)
{
	struct vty_signal_data sig_data;
	struct telnet_connection *connection = vty->priv;
	struct osmo_fd *bfd;

	if (vty->type != VTY_TERM)
		return;

	sig_data.event = event;
	sig_data.sock = sock;
	sig_data.vty = vty;
	osmo_signal_dispatch(SS_L_VTY, S_VTY_EVENT, &sig_data);

	if (!connection)
		return;

	bfd = &connection->fd;

	switch (event) {
	case VTY_READ:
		bfd->when |= OSMO_FD_READ;
		break;
	case VTY_WRITE:
		bfd->when |= OSMO_FD_WRITE;
		break;
	case VTY_CLOSED:
		/* vty layer is about to free() vty */
		telnet_close_client(bfd);
		break;
	default:
		break;
	}
}

/*! Close all telnet connections and release the telnet socket */
void telnet_exit(void)
{
	struct telnet_connection *tc, *tc2;

	llist_for_each_entry_safe(tc, tc2, &active_connections, entry)
		telnet_close_client(&tc->fd);

	osmo_fd_unregister(&server_socket);
	close(server_socket.fd);
	talloc_free(tall_telnet_ctx);
}
