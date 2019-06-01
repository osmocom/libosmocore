/*
 * (C) 2011-2017 by Harald Welte <laforge@gnumonks.org>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "../config.h"

/*! \addtogroup socket
 *  @{
 *  Osmocom socket convenience functions.
 *
 * \file socket.c */

#ifdef HAVE_SYS_SOCKET_H

#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>

static struct addrinfo *addrinfo_helper(uint16_t family, uint16_t type, uint8_t proto,
					const char *host, uint16_t port, bool passive)
{
	struct addrinfo hints, *result;
	char portbuf[6];
	int rc;

	snprintf(portbuf, sizeof(portbuf), "%u", port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = family;
	if (type == SOCK_RAW) {
		/* Workaround for glibc, that returns EAI_SERVICE (-8) if
		 * SOCK_RAW and IPPROTO_GRE is used.
		 */
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	} else {
		hints.ai_socktype = type;
		hints.ai_protocol = proto;
	}

	if (passive)
		hints.ai_flags |= AI_PASSIVE;

	rc = getaddrinfo(host, portbuf, &hints, &result);
	if (rc != 0) {
		LOGP(DLGLOBAL, LOGL_ERROR, "getaddrinfo returned NULL: %s:%u: %s\n",
			host, port, strerror(errno));
		return NULL;
	}

	return result;
}

static int socket_helper(const struct addrinfo *rp, unsigned int flags)
{
	int sfd, on = 1;

	sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
	if (sfd == -1) {
		LOGP(DLGLOBAL, LOGL_ERROR,
			"unable to create socket: %s\n", strerror(errno));
		return sfd;
	}
	if (flags & OSMO_SOCK_F_NONBLOCK) {
		if (ioctl(sfd, FIONBIO, (unsigned char *)&on) < 0) {
			LOGP(DLGLOBAL, LOGL_ERROR,
				"cannot set this socket unblocking: %s\n",
				strerror(errno));
			close(sfd);
			sfd = -EINVAL;
		}
	}
	return sfd;
}


static int osmo_sock_init_tail(int fd, uint16_t type, unsigned int flags)
{
	int rc;

	/* Make sure to call 'listen' on a bound, connection-oriented sock */
	if ((flags & (OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT)) == OSMO_SOCK_F_BIND) {
		switch (type) {
		case SOCK_STREAM:
		case SOCK_SEQPACKET:
			rc = listen(fd, 10);
			if (rc < 0) {
				LOGP(DLGLOBAL, LOGL_ERROR, "unable to listen on socket: %s\n",
					strerror(errno));
				return rc;
			}
			break;
		}
	}

	if (flags & OSMO_SOCK_F_NO_MCAST_LOOP) {
		rc = osmo_sock_mcast_loop_set(fd, false);
		if (rc < 0) {
			LOGP(DLGLOBAL, LOGL_ERROR, "unable to disable multicast loop: %s\n",
				strerror(errno));
			return rc;
		}
	}

	if (flags & OSMO_SOCK_F_NO_MCAST_ALL) {
		rc = osmo_sock_mcast_all_set(fd, false);
		if (rc < 0) {
			LOGP(DLGLOBAL, LOGL_ERROR, "unable to disable receive of all multicast: %s\n",
				strerror(errno));
			/* do not abort here, as this is just an
			 * optional additional optimization that only
			 * exists on Linux only */
		}
	}
	return 0;
}

/*! Initialize a socket (including bind and/or connect)
 *  \param[in] family Address Family like AF_INET, AF_INET6, AF_UNSPEC
 *  \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM
 *  \param[in] proto Protocol like IPPROTO_TCP, IPPROTO_UDP
 *  \param[in] local_host local host name or IP address in string form
 *  \param[in] local_port local port number in host byte order
 *  \param[in] remote_host remote host name or IP address in string form
 *  \param[in] remote_port remote port number in host byte order
 *  \param[in] flags flags like \ref OSMO_SOCK_F_CONNECT
 *  \returns socket file descriptor on success; negative on error
 *
 * This function creates a new socket of the designated \a family, \a
 * type and \a proto and optionally binds it to the \a local_host and \a
 * local_port as well as optionally connects it to the \a remote_host
 * and \q remote_port, depending on the value * of \a flags parameter.
 *
 * As opposed to \ref osmo_sock_init(), this function allows to combine
 * the \ref OSMO_SOCK_F_BIND and \ref OSMO_SOCK_F_CONNECT flags.  This
 * is useful if you want to connect to a remote host/port, but still
 * want to bind that socket to either a specific local alias IP and/or a
 * specific local source port.
 *
 * You must specify either \ref OSMO_SOCK_F_BIND, or \ref
 * OSMO_SOCK_F_CONNECT, or both.
 *
 * If \ref OSMO_SOCK_F_NONBLOCK is specified, the socket will be set to
 * non-blocking mode.
 */
int osmo_sock_init2(uint16_t family, uint16_t type, uint8_t proto,
		   const char *local_host, uint16_t local_port,
		   const char *remote_host, uint16_t remote_port, unsigned int flags)
{
	struct addrinfo *result, *rp;
	int sfd = -1, rc, on = 1;

	if ((flags & (OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT)) == 0) {
		LOGP(DLGLOBAL, LOGL_ERROR, "invalid: you have to specify either "
			"BIND or CONNECT flags\n");
		return -EINVAL;
	}

	/* figure out local side of socket */
	if (flags & OSMO_SOCK_F_BIND) {
		result = addrinfo_helper(family, type, proto, local_host, local_port, true);
		if (!result)
			return -EINVAL;

		for (rp = result; rp != NULL; rp = rp->ai_next) {
			/* Workaround for glibc again */
			if (type == SOCK_RAW) {
				rp->ai_socktype = SOCK_RAW;
				rp->ai_protocol = proto;
			}

			sfd = socket_helper(rp, flags);
			if (sfd < 0)
				continue;

			if (proto != IPPROTO_UDP || flags & OSMO_SOCK_F_UDP_REUSEADDR) {
				rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,
						&on, sizeof(on));
				if (rc < 0) {
					LOGP(DLGLOBAL, LOGL_ERROR,
					     "cannot setsockopt socket:"
					     " %s:%u: %s\n",
					     local_host, local_port,
					     strerror(errno));
					close(sfd);
					continue;
				}
			}

			if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == -1) {
				LOGP(DLGLOBAL, LOGL_ERROR, "unable to bind socket: %s:%u: %s\n",
					local_host, local_port, strerror(errno));
				close(sfd);
				continue;
			}
			break;
		}
		freeaddrinfo(result);
		if (rp == NULL) {
			LOGP(DLGLOBAL, LOGL_ERROR, "no suitable local addr found for: %s:%u\n",
				local_host, local_port);
			return -ENODEV;
		}
	}

	/* Reached this point, if OSMO_SOCK_F_BIND then sfd is valid (>=0) or it
	   was already closed and func returned. If OSMO_SOCK_F_BIND is not
	   set, then sfd = -1 */

	/* figure out remote side of socket */
	if (flags & OSMO_SOCK_F_CONNECT) {
		result = addrinfo_helper(family, type, proto, remote_host, remote_port, false);
		if (!result) {
			if (sfd >= 0)
				close(sfd);
			return -EINVAL;
		}

		for (rp = result; rp != NULL; rp = rp->ai_next) {
			/* Workaround for glibc again */
			if (type == SOCK_RAW) {
				rp->ai_socktype = SOCK_RAW;
				rp->ai_protocol = proto;
			}

			if (sfd < 0) {
				sfd = socket_helper(rp, flags);
				if (sfd < 0)
					continue;
			}

			rc = connect(sfd, rp->ai_addr, rp->ai_addrlen);
			if (rc != 0 && errno != EINPROGRESS) {
				LOGP(DLGLOBAL, LOGL_ERROR, "unable to connect socket: %s:%u: %s\n",
					remote_host, remote_port, strerror(errno));
				/* We want to maintain the bind socket if bind was enabled */
				if (!(flags & OSMO_SOCK_F_BIND)) {
					close(sfd);
					sfd = -1;
				}
				continue;
			}
			break;
		}
		freeaddrinfo(result);
		if (rp == NULL) {
			LOGP(DLGLOBAL, LOGL_ERROR, "no suitable remote addr found for: %s:%u\n",
				remote_host, remote_port);
			if (sfd >= 0)
				close(sfd);
			return -ENODEV;
		}
	}

	rc = osmo_sock_init_tail(sfd, type, flags);
	if (rc < 0) {
		close(sfd);
		sfd = -1;
	}

	return sfd;
}


/*! Initialize a socket (including bind/connect)
 *  \param[in] family Address Family like AF_INET, AF_INET6, AF_UNSPEC
 *  \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM
 *  \param[in] proto Protocol like IPPROTO_TCP, IPPROTO_UDP
 *  \param[in] host remote host name or IP address in string form
 *  \param[in] port remote port number in host byte order
 *  \param[in] flags flags like \ref OSMO_SOCK_F_CONNECT
 *  \returns socket file descriptor on success; negative on error
 *
 * This function creates a new socket of the designated \a family, \a
 * type and \a proto and optionally binds or connects it, depending on
 * the value of \a flags parameter.
 */
int osmo_sock_init(uint16_t family, uint16_t type, uint8_t proto,
		   const char *host, uint16_t port, unsigned int flags)
{
	struct addrinfo *result, *rp;
	int sfd, rc, on = 1;

	if ((flags & (OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT)) ==
		     (OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT)) {
		LOGP(DLGLOBAL, LOGL_ERROR, "invalid: both bind and connect flags set:"
			" %s:%u\n", host, port);
		return -EINVAL;
	}

	result = addrinfo_helper(family, type, proto, host, port, flags & OSMO_SOCK_F_BIND);
	if (!result) {
		LOGP(DLGLOBAL, LOGL_ERROR, "getaddrinfo returned NULL: %s:%u: %s\n",
			host, port, strerror(errno));
		return -EINVAL;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		/* Workaround for glibc again */
		if (type == SOCK_RAW) {
			rp->ai_socktype = SOCK_RAW;
			rp->ai_protocol = proto;
		}

		sfd = socket_helper(rp, flags);
		if (sfd == -1)
			continue;

		if (flags & OSMO_SOCK_F_CONNECT) {
			rc = connect(sfd, rp->ai_addr, rp->ai_addrlen);
			if (rc != 0 && errno != EINPROGRESS) {
				close(sfd);
				continue;
			}
		} else {
			if (proto != IPPROTO_UDP || flags & OSMO_SOCK_F_UDP_REUSEADDR) {
				rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,
						&on, sizeof(on));
				if (rc < 0) {
					LOGP(DLGLOBAL, LOGL_ERROR,
					     "cannot setsockopt socket:"
					     " %s:%u: %s\n",
					     host, port, strerror(errno));
					close(sfd);
					continue;
				}
			}
			if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == -1) {
				LOGP(DLGLOBAL, LOGL_ERROR, "unable to bind socket:"
					"%s:%u: %s\n",
					host, port, strerror(errno));
				close(sfd);
				continue;
			}
		}
		break;
	}
	freeaddrinfo(result);

	if (rp == NULL) {
		LOGP(DLGLOBAL, LOGL_ERROR, "no suitable addr found for: %s:%u\n",
			host, port);
		return -ENODEV;
	}

	if (proto != IPPROTO_UDP || flags & OSMO_SOCK_F_UDP_REUSEADDR) {
		rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		if (rc < 0) {
			LOGP(DLGLOBAL, LOGL_ERROR,
			     "cannot setsockopt socket: %s:%u: %s\n", host,
			     port, strerror(errno));
			close(sfd);
			sfd = -1;
		}
	}

	rc = osmo_sock_init_tail(sfd, type, flags);
	if (rc < 0) {
		close(sfd);
		sfd = -1;
	}

	return sfd;
}

/*! fill \ref osmo_fd for a give sfd
 *  \param[out] ofd file descriptor (will be filled in)
 *  \param[in] sfd socket file descriptor
 *  \returns socket fd on success; negative on error
 *
 * This function fills the \a ofd structure.
 */
static inline int osmo_fd_init_ofd(struct osmo_fd *ofd, int sfd)
{
	int rc;

	if (sfd < 0)
		return sfd;

	ofd->fd = sfd;
	ofd->when = OSMO_FD_READ;

	rc = osmo_fd_register(ofd);
	if (rc < 0) {
		close(sfd);
		return rc;
	}

	return sfd;
}

/*! Initialize a socket and fill \ref osmo_fd
 *  \param[out] ofd file descriptor (will be filled in)
 *  \param[in] family Address Family like AF_INET, AF_INET6, AF_UNSPEC
 *  \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM
 *  \param[in] proto Protocol like IPPROTO_TCP, IPPROTO_UDP
 *  \param[in] host remote host name or IP address in string form
 *  \param[in] port remote port number in host byte order
 *  \param[in] flags flags like \ref OSMO_SOCK_F_CONNECT
 *  \returns socket fd on success; negative on error
 *
 * This function creates (and optionall binds/connects) a socket using
 * \ref osmo_sock_init, but also fills the \a ofd structure.
 */
int osmo_sock_init_ofd(struct osmo_fd *ofd, int family, int type, int proto,
			const char *host, uint16_t port, unsigned int flags)
{
	return osmo_fd_init_ofd(ofd, osmo_sock_init(family, type, proto, host, port, flags));
}

/*! Initialize a socket and fill \ref osmo_fd
 *  \param[out] ofd file descriptor (will be filled in)
 *  \param[in] family Address Family like AF_INET, AF_INET6, AF_UNSPEC
 *  \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM
 *  \param[in] proto Protocol like IPPROTO_TCP, IPPROTO_UDP
 *  \param[in] local_host local host name or IP address in string form
 *  \param[in] local_port local port number in host byte order
 *  \param[in] remote_host remote host name or IP address in string form
 *  \param[in] remote_port remote port number in host byte order
 *  \param[in] flags flags like \ref OSMO_SOCK_F_CONNECT
 *  \returns socket fd on success; negative on error
 *
 * This function creates (and optionall binds/connects) a socket using
 * \ref osmo_sock_init2, but also fills the \a ofd structure.
 */
int osmo_sock_init2_ofd(struct osmo_fd *ofd, int family, int type, int proto,
			const char *local_host, uint16_t local_port,
			const char *remote_host, uint16_t remote_port, unsigned int flags)
{
	return osmo_fd_init_ofd(ofd, osmo_sock_init2(family, type, proto, local_host,
					local_port, remote_host, remote_port, flags));
}

/*! Initialize a socket and fill \ref sockaddr
 *  \param[out] ss socket address (will be filled in)
 *  \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM
 *  \param[in] proto Protocol like IPPROTO_TCP, IPPROTO_UDP
 *  \param[in] flags flags like \ref OSMO_SOCK_F_CONNECT
 *  \returns socket fd on success; negative on error
 *
 * This function creates (and optionall binds/connects) a socket using
 * \ref osmo_sock_init, but also fills the \a ss structure.
 */
int osmo_sock_init_sa(struct sockaddr *ss, uint16_t type,
		      uint8_t proto, unsigned int flags)
{
	char host[NI_MAXHOST];
	uint16_t port;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int s, sa_len;

	/* determine port and host from ss */
	switch (ss->sa_family) {
	case AF_INET:
		sin = (struct sockaddr_in *) ss;
		sa_len = sizeof(struct sockaddr_in);
		port = ntohs(sin->sin_port);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *) ss;
		sa_len = sizeof(struct sockaddr_in6);
		port = ntohs(sin6->sin6_port);
		break;
	default:
		return -EINVAL;
	}

	s = getnameinfo(ss, sa_len, host, NI_MAXHOST,
			NULL, 0, NI_NUMERICHOST);
	if (s != 0) {
		LOGP(DLGLOBAL, LOGL_ERROR, "getnameinfo failed:"
		     " %s\n", strerror(errno));
		return s;
	}

	return osmo_sock_init(ss->sa_family, type, proto, host, port, flags);
}

static int sockaddr_equal(const struct sockaddr *a,
			  const struct sockaddr *b, unsigned int len)
{
	struct sockaddr_in *sin_a, *sin_b;
	struct sockaddr_in6 *sin6_a, *sin6_b;

	if (a->sa_family != b->sa_family)
		return 0;

	switch (a->sa_family) {
	case AF_INET:
		sin_a = (struct sockaddr_in *)a;
		sin_b = (struct sockaddr_in *)b;
		if (!memcmp(&sin_a->sin_addr, &sin_b->sin_addr,
			    sizeof(struct in_addr)))
			return 1;
		break;
	case AF_INET6:
		sin6_a = (struct sockaddr_in6 *)a;
		sin6_b = (struct sockaddr_in6 *)b;
		if (!memcmp(&sin6_a->sin6_addr, &sin6_b->sin6_addr,
			    sizeof(struct in6_addr)))
			return 1;
		break;
	}
	return 0;
}

/*! Determine if the given address is a local address
 *  \param[in] addr Socket Address
 *  \param[in] addrlen Length of socket address in bytes
 *  \returns 1 if address is local, 0 otherwise.
 */
int osmo_sockaddr_is_local(struct sockaddr *addr, unsigned int addrlen)
{
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) == -1) {
		LOGP(DLGLOBAL, LOGL_ERROR, "getifaddrs:"
		     " %s\n", strerror(errno));
		return -EIO;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;
		if (sockaddr_equal(ifa->ifa_addr, addr, addrlen)) {
			freeifaddrs(ifaddr);
			return 1;
		}
	}

	freeifaddrs(ifaddr);
	return 0;
}

/*! Convert sockaddr_in to IP address as char string and port as uint16_t.
 *  \param[out] addr  String buffer to write IP address to, or NULL.
 *  \param[out] addr_len  Size of \a addr.
 *  \param[out] port  Pointer to uint16_t to write the port number to, or NULL.
 *  \param[in] sin  Sockaddr to convert.
 *  \returns the required string buffer size, like osmo_strlcpy(), or 0 if \a addr is NULL.
 */
size_t osmo_sockaddr_in_to_str_and_uint(char *addr, unsigned int addr_len, uint16_t *port,
					const struct sockaddr_in *sin)
{
	if (port)
		*port = ntohs(sin->sin_port);

	if (addr)
		return osmo_strlcpy(addr, inet_ntoa(sin->sin_addr), addr_len);

	return 0;
}

/*! Convert sockaddr to IP address as char string and port as uint16_t.
 *  \param[out] addr  String buffer to write IP address to, or NULL.
 *  \param[out] addr_len  Size of \a addr.
 *  \param[out] port  Pointer to uint16_t to write the port number to, or NULL.
 *  \param[in] sa  Sockaddr to convert.
 *  \returns the required string buffer size, like osmo_strlcpy(), or 0 if \a addr is NULL.
 */
unsigned int osmo_sockaddr_to_str_and_uint(char *addr, unsigned int addr_len, uint16_t *port,
					   const struct sockaddr *sa)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;

	return osmo_sockaddr_in_to_str_and_uint(addr, addr_len, port, sin);
}

/*! Initialize a unix domain socket (including bind/connect)
 *  \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM
 *  \param[in] proto Protocol like IPPROTO_TCP, IPPROTO_UDP
 *  \param[in] socket_path path to identify the socket
 *  \param[in] flags flags like \ref OSMO_SOCK_F_CONNECT
 *  \returns socket fd on success; negative on error
 *
 * This function creates a new unix domain socket, \a
 * type and \a proto and optionally binds or connects it, depending on
 * the value of \a flags parameter.
 */
int osmo_sock_unix_init(uint16_t type, uint8_t proto,
			const char *socket_path, unsigned int flags)
{
	struct sockaddr_un local;
	int sfd, rc, on = 1;
	unsigned int namelen;

	if ((flags & (OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT)) ==
		     (OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT))
		return -EINVAL;

	local.sun_family = AF_UNIX;
	/* When an AF_UNIX socket is bound, sun_path should be NUL-terminated. See unix(7) man page. */
	if (osmo_strlcpy(local.sun_path, socket_path, sizeof(local.sun_path)) >= sizeof(local.sun_path)) {
		LOGP(DLGLOBAL, LOGL_ERROR, "Socket path exceeds maximum length of %zd bytes: %s\n",
		     sizeof(local.sun_path), socket_path);
		return -ENOSPC;
	}

#if defined(BSD44SOCKETS) || defined(__UNIXWARE__)
	local.sun_len = strlen(local.sun_path);
#endif
#if defined(BSD44SOCKETS) || defined(SUN_LEN)
	namelen = SUN_LEN(&local);
#else
	namelen = strlen(local.sun_path) +
		  offsetof(struct sockaddr_un, sun_path);
#endif

	sfd = socket(AF_UNIX, type, proto);
	if (sfd < 0)
		return -1;

	if (flags & OSMO_SOCK_F_CONNECT) {
		rc = connect(sfd, (struct sockaddr *)&local, namelen);
		if (rc < 0)
			goto err;
	} else {
		unlink(local.sun_path);
		rc = bind(sfd, (struct sockaddr *)&local, namelen);
		if  (rc < 0)
			goto err;
	}

	if (flags & OSMO_SOCK_F_NONBLOCK) {
		if (ioctl(sfd, FIONBIO, (unsigned char *)&on) < 0) {
			LOGP(DLGLOBAL, LOGL_ERROR,
			     "cannot set this socket unblocking: %s\n",
			     strerror(errno));
			close(sfd);
			return -EINVAL;
		}
	}

	rc = osmo_sock_init_tail(sfd, type, flags);
	if (rc < 0) {
		close(sfd);
		sfd = -1;
	}

	return sfd;
err:
	close(sfd);
	return -1;
}

/*! Initialize a unix domain socket and fill \ref osmo_fd
 *  \param[out] ofd file descriptor (will be filled in)
 *  \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM
 *  \param[in] proto Protocol like IPPROTO_TCP, IPPROTO_UDP
 *  \param[in] socket_path path to identify the socket
 *  \param[in] flags flags like \ref OSMO_SOCK_F_CONNECT
 *  \returns socket fd on success; negative on error
 *
 * This function creates (and optionally binds/connects) a socket
 * using osmo_sock_unix_init, but also fills the ofd structure.
 */
int osmo_sock_unix_init_ofd(struct osmo_fd *ofd, uint16_t type, uint8_t proto,
			    const char *socket_path, unsigned int flags)
{
	return osmo_fd_init_ofd(ofd, osmo_sock_unix_init(type, proto, socket_path, flags));
}

/*! Get the IP and/or port number on socket in separate string buffers.
 *  \param[in] fd file descriptor of socket
 *  \param[out] ip IP address (will be filled in when not NULL)
 *  \param[in] ip_len length of the ip buffer
 *  \param[out] port number (will be filled in when not NULL)
 *  \param[in] port_len length of the port buffer
 *  \param[in] local (true) or remote (false) name will get looked at
 *  \returns 0 on success; negative otherwise
 */
int osmo_sock_get_ip_and_port(int fd, char *ip, size_t ip_len, char *port, size_t port_len, bool local)
{
	struct sockaddr sa;
	socklen_t len = sizeof(sa);
	char ipbuf[INET6_ADDRSTRLEN], portbuf[6];
	int rc;

	rc = local ? getsockname(fd, &sa, &len) : getpeername(fd, &sa, &len);
	if (rc < 0)
		return rc;

	rc = getnameinfo(&sa, len, ipbuf, sizeof(ipbuf),
			 portbuf, sizeof(portbuf),
			 NI_NUMERICHOST | NI_NUMERICSERV);
	if (rc < 0)
		return rc;

	if (ip)
		strncpy(ip, ipbuf, ip_len);
	if (port)
		strncpy(port, portbuf, port_len);
	return 0;
}

/*! Get local IP address on socket
 *  \param[in] fd file descriptor of socket
 *  \param[out] ip IP address (will be filled in)
 *  \param[in] len length of the output buffer
 *  \returns 0 on success; negative otherwise
 */
int osmo_sock_get_local_ip(int fd, char *ip, size_t len)
{
	return osmo_sock_get_ip_and_port(fd, ip, len, NULL, 0, true);
}

/*! Get local port on socket
 *  \param[in] fd file descriptor of socket
 *  \param[out] port number (will be filled in)
 *  \param[in] len length of the output buffer
 *  \returns 0 on success; negative otherwise
 */
int osmo_sock_get_local_ip_port(int fd, char *port, size_t len)
{
	return osmo_sock_get_ip_and_port(fd, NULL, 0, port, len, true);
}

/*! Get remote IP address on socket
 *  \param[in] fd file descriptor of socket
 *  \param[out] ip IP address (will be filled in)
 *  \param[in] len length of the output buffer
 *  \returns 0 on success; negative otherwise
 */
int osmo_sock_get_remote_ip(int fd, char *ip, size_t len)
{
	return osmo_sock_get_ip_and_port(fd, ip, len, NULL, 0, false);
}

/*! Get remote port on socket
 *  \param[in] fd file descriptor of socket
 *  \param[out] port number (will be filled in)
 *  \param[in] len length of the output buffer
 *  \returns 0 on success; negative otherwise
 */
int osmo_sock_get_remote_ip_port(int fd, char *port, size_t len)
{
	return osmo_sock_get_ip_and_port(fd, NULL, 0, port, len, false);
}

/*! Get address/port information on socket in dyn-alloc string like "(r=1.2.3.4:5<->l=6.7.8.9:10)".
 * Usually, it is better to use osmo_sock_get_name2() for a static string buffer or osmo_sock_get_name_buf() for a
 * caller provided string buffer, to avoid the dynamic talloc allocation.
 *  \param[in] ctx talloc context from which to allocate string buffer
 *  \param[in] fd file descriptor of socket
 *  \returns string identifying the connection of this socket, talloc'd from ctx.
 */
char *osmo_sock_get_name(const void *ctx, int fd)
{
	char str[OSMO_SOCK_NAME_MAXLEN];
	int rc;
	rc = osmo_sock_get_name_buf(str, sizeof(str), fd);
	if (rc <= 0)
		return NULL;
	return talloc_asprintf(ctx, "(%s)", str);
}

/*! Get address/port information on socket in provided string buffer, like "r=1.2.3.4:5<->l=6.7.8.9:10".
 * This does not include braces like osmo_sock_get_name().
 *  \param[out] str  Destination string buffer.
 *  \param[in] str_len  sizeof(str).
 *  \param[in] fd  File descriptor of socket.
 *  \return String length as returned by snprintf(), or negative on error.
 */
int osmo_sock_get_name_buf(char *str, size_t str_len, int fd)
{
	char hostbuf_l[INET6_ADDRSTRLEN], hostbuf_r[INET6_ADDRSTRLEN];
	char portbuf_l[6], portbuf_r[6];
	int rc;

	/* get local */
	if ((rc = osmo_sock_get_ip_and_port(fd, hostbuf_l, sizeof(hostbuf_l), portbuf_l, sizeof(portbuf_l), true))) {
		osmo_strlcpy(str, "<error-in-getsockname>", str_len);
		return rc;
	}

	/* get remote */
	if (osmo_sock_get_ip_and_port(fd, hostbuf_r, sizeof(hostbuf_r), portbuf_r, sizeof(portbuf_r), false) != 0)
		return snprintf(str, str_len, "r=NULL<->l=%s:%s", hostbuf_l, portbuf_l);

	return snprintf(str, str_len, "r=%s:%s<->l=%s:%s", hostbuf_r, portbuf_r, hostbuf_l, portbuf_l);
}

/*! Get address/port information on socket in static string, like "r=1.2.3.4:5<->l=6.7.8.9:10".
 * This does not include braces like osmo_sock_get_name().
 *  \param[in] fd  File descriptor of socket.
 *  \return Static string buffer containing the result.
 */
const char *osmo_sock_get_name2(int fd)
{
	static char str[OSMO_SOCK_NAME_MAXLEN];
	osmo_sock_get_name_buf(str, sizeof(str), fd);
	return str;
}

/*! Get address/port information on socket in static string, like "r=1.2.3.4:5<->l=6.7.8.9:10".
 * This does not include braces like osmo_sock_get_name().
 *  \param[in] fd  File descriptor of socket.
 *  \return Static string buffer containing the result.
 */
char *osmo_sock_get_name2_c(const void *ctx, int fd)
{
	char *str = talloc_size(ctx, OSMO_SOCK_NAME_MAXLEN);
	if (!str)
		return NULL;
	osmo_sock_get_name_buf(str, OSMO_SOCK_NAME_MAXLEN, fd);
	return str;
}

static int sock_get_domain(int fd)
{
	int domain;
#ifdef SO_DOMAIN
	socklen_t dom_len = sizeof(domain);
	int rc;

	rc = getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &dom_len);
	if (rc < 0)
		return rc;
#else
	/* This of course sucks, but what shall we do on OSs like
	 * FreeBSD that don't seem to expose a method by which one can
	 * learn the address family of a socket? */
	domain = AF_INET;
#endif
	return domain;
}


/*! Activate or de-activate local loop-back of transmitted multicast packets
 *  \param[in] fd file descriptor of related socket
 *  \param[in] enable Enable (true) or disable (false) loop-back
 *  \returns 0 on success; negative otherwise */
int osmo_sock_mcast_loop_set(int fd, bool enable)
{
	int domain, loop = 0;

	if (enable)
		loop = 1;

	domain = sock_get_domain(fd);
	if (domain < 0)
		return domain;

	switch (domain) {
	case AF_INET:
		return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
	case AF_INET6:
		return setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop));
	default:
		return -EINVAL;
	}
}

/*! Set the TTL of outbound multicast packets
 *  \param[in] fd file descriptor of related socket
 *  \param[in] ttl TTL of to-be-sent multicast packets
 *  \returns 0 on success; negative otherwise */
int osmo_sock_mcast_ttl_set(int fd,  uint8_t ttl)
{
	int domain, ttli = ttl;

	domain = sock_get_domain(fd);
	if (domain < 0)
		return domain;

	switch (domain) {
	case AF_INET:
		return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttli, sizeof(ttli));
	case AF_INET6:
		return setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttli, sizeof(ttli));
	default:
		return -EINVAL;
	}
}

/*! Enable/disable receiving all multicast packets, even for non-subscribed groups
 *  \param[in] fd file descriptor of related socket
 *  \param[in] enable Enable or Disable receiving of all packets
 *  \returns 0 on success; negative otherwise */
int osmo_sock_mcast_all_set(int fd, bool enable)
{
	int domain, all = 0;

	if (enable)
		all = 1;

	domain = sock_get_domain(fd);
	if (domain < 0)
		return domain;

	switch (domain) {
	case AF_INET:
#ifdef IP_MULTICAST_ALL
		return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_ALL, &all, sizeof(all));
#endif
	case AF_INET6:
		/* there seems no equivalent ?!? */
	default:
		return -EINVAL;
	}
}

/* FreeBSD calls the socket option differently */
#if !defined(IPV6_ADD_MEMBERSHIP) && defined(IPV6_JOIN_GROUP)
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif

/*! Subscribe to the given IP multicast group
 *  \param[in] fd file descriptor of related scoket
 *  \param[in] grp_addr ASCII representation of the multicast group address
 *  \returns 0 on success; negative otherwise */
int osmo_sock_mcast_subscribe(int fd, const char *grp_addr)
{
	int rc, domain;
	struct ip_mreq mreq;
	struct ipv6_mreq mreq6;
	struct in6_addr i6a;

	domain = sock_get_domain(fd);
	if (domain < 0)
		return domain;

	switch (domain) {
	case AF_INET:
		memset(&mreq, 0, sizeof(mreq));
		mreq.imr_multiaddr.s_addr = inet_addr(grp_addr);
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		return setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
#ifdef IPV6_ADD_MEMBERSHIP
	case AF_INET6:
		memset(&mreq6, 0, sizeof(mreq6));
		rc = inet_pton(AF_INET6, grp_addr, (void *)&i6a);
		if (rc < 0)
			return -EINVAL;
		mreq6.ipv6mr_multiaddr = i6a;
		return setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6));
#endif
	default:
		return -EINVAL;
	}
}

/*! Determine the matching local IP-address for a given remote IP-Address.
 *  \param[out] local_ip caller provided memory for resulting local IP-address
 *  \param[in] remote_ip remote IP-address
 *  \param[in] fd file descriptor of related scoket
 *  \returns 0 on success; negative otherwise
 *
 *  The function accepts IPv4 and IPv6 address strings. The caller must provide
 *  at least INET6_ADDRSTRLEN bytes for local_ip if an IPv6 is expected as
 *  as result. For IPv4 addresses the required amount is INET_ADDRSTRLEN. */
int osmo_sock_local_ip(char *local_ip, const char *remote_ip)
{
	int sfd;
	int rc;
	struct addrinfo addrinfo_hint;
	struct addrinfo *addrinfo = NULL;
	struct sockaddr_in local_addr;
	socklen_t local_addr_len;
	uint16_t family;

	/* Find out the address family (AF_INET or AF_INET6?) */
	memset(&addrinfo_hint, '\0', sizeof(addrinfo_hint));
	addrinfo_hint.ai_family = PF_UNSPEC;
	addrinfo_hint.ai_flags = AI_NUMERICHOST;
	rc = getaddrinfo(remote_ip, NULL, &addrinfo_hint, &addrinfo);
	if (rc)
		return -EINVAL;
	family = addrinfo->ai_family;
	freeaddrinfo(addrinfo);

	/* Connect a dummy socket to trick the kernel into determining the
	 * ip-address of the interface that would be used if we would send
	 * out an actual packet */
	sfd = osmo_sock_init2(family, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, remote_ip, 0, OSMO_SOCK_F_CONNECT);
	if (sfd < 0)
		return -EINVAL;

	/* Request the IP address of the interface that the kernel has
	 * actually choosen. */
	memset(&local_addr, 0, sizeof(local_addr));
	local_addr_len = sizeof(local_addr);
	rc = getsockname(sfd, (struct sockaddr *)&local_addr, &local_addr_len);
	close(sfd);
	if (rc < 0)
		return -EINVAL;
	if (local_addr.sin_family == AF_INET)
		inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, INET_ADDRSTRLEN);
	else if (local_addr.sin_family == AF_INET6)
		inet_ntop(AF_INET6, &local_addr.sin_addr, local_ip, INET6_ADDRSTRLEN);
	else
		return -EINVAL;

	return 0;
}

#endif /* HAVE_SYS_SOCKET_H */

/*! @} */
