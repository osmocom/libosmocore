/*
 * (C) 2011-2017 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
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
 *  \brief Osmocom socket convenience functions
 */

/*! \file socket.c */

#ifdef HAVE_SYS_SOCKET_H

#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <netinet/in.h>

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
	char portbuf[16];
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
	if (sfd == -1)
		return sfd;
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


/*! \brief Initialize a socket (including bind and/or connect)
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

			rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,
							&on, sizeof(on));
			if (rc < 0) {
				LOGP(DLGLOBAL, LOGL_ERROR,
					"cannot setsockopt socket:"
					" %s:%u: %s\n",
					local_host, local_port, strerror(errno));
				break;
			}
			if (bind(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
				break;
			close(sfd);
		}
		freeaddrinfo(result);
		if (rp == NULL) {
			LOGP(DLGLOBAL, LOGL_ERROR, "unable to bind socket: %s:%u: %s\n",
				local_host, local_port, strerror(errno));
			return -ENODEV;
		}
	}

	/* figure out remote side of socket */
	if (flags & OSMO_SOCK_F_CONNECT) {
		result = addrinfo_helper(family, type, proto, remote_host, remote_port, false);
		if (!result) {
			close(sfd);
			return -EINVAL;
		}

		for (rp = result; rp != NULL; rp = rp->ai_next) {
			/* Workaround for glibc again */
			if (type == SOCK_RAW) {
				rp->ai_socktype = SOCK_RAW;
				rp->ai_protocol = proto;
			}

			if (!sfd) {
				sfd = socket_helper(rp, flags);
				if (sfd < 0)
					continue;
			}

			rc = connect(sfd, rp->ai_addr, rp->ai_addrlen);
			if (rc != -1 || (rc == -1 && errno == EINPROGRESS))
				break;

			close(sfd);
			sfd = -1;
		}
		freeaddrinfo(result);
		if (rp == NULL) {
			LOGP(DLGLOBAL, LOGL_ERROR, "unable to connect socket: %s:%u: %s\n",
				remote_host, remote_port, strerror(errno));
			return -ENODEV;
		}
	}

	/* Make sure to call 'listen' on a bound, connection-oriented sock */
	if ((flags & (OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT)) == OSMO_SOCK_F_BIND) {
		switch (type) {
		case SOCK_STREAM:
		case SOCK_SEQPACKET:
			listen(sfd, 10);
			break;
		}
	}
	return sfd;
}


/*! \brief Initialize a socket (including bind/connect)
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
			if (rc != -1 || (rc == -1 && errno == EINPROGRESS))
				break;
		} else {
			rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,
							&on, sizeof(on));
			if (rc < 0) {
				LOGP(DLGLOBAL, LOGL_ERROR,
					"cannot setsockopt socket:"
					" %s:%u: %s\n",
					host, port, strerror(errno));
				break;
			}
			if (bind(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
				break;
		}
		close(sfd);
	}
	freeaddrinfo(result);

	if (rp == NULL) {
		LOGP(DLGLOBAL, LOGL_ERROR, "unable to connect/bind socket: %s:%u: %s\n",
			host, port, strerror(errno));
		return -ENODEV;
	}

	setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	/* Make sure to call 'listen' on a bound, connection-oriented sock */
	if (flags & OSMO_SOCK_F_BIND) {
		switch (type) {
		case SOCK_STREAM:
		case SOCK_SEQPACKET:
			listen(sfd, 10);
			break;
		}
	}
	return sfd;
}

/*! \brief fill \ref osmo_fd for a give sfd
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
	ofd->when = BSC_FD_READ;

	rc = osmo_fd_register(ofd);
	if (rc < 0) {
		close(sfd);
		return rc;
	}

	return sfd;
}

/*! \brief Initialize a socket and fill \ref osmo_fd
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

/*! \brief Initialize a socket and fill \ref osmo_fd
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

/*! \brief Initialize a socket and fill \ref sockaddr
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

/*! \brief Determine if the given address is a local address
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
		if (sockaddr_equal(ifa->ifa_addr, addr, addrlen))
			return 1;
	}

	return 0;
}

/*! \brief Initialize a unix domain socket (including bind/connect)
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
	strncpy(local.sun_path, socket_path, sizeof(local.sun_path));
	local.sun_path[sizeof(local.sun_path) - 1] = '\0';

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

	if (flags & OSMO_SOCK_F_BIND) {
		rc = listen(sfd, 10);
		if (rc < 0)
			goto err;
	}

	return sfd;
err:
	close(sfd);
	return -1;
}

/*! \brief Initialize a unix domain socket and fill \ref osmo_fd
 *  \param[out] ofd file descriptor (will be filled in)
 *  \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM
 *  \param[in] proto Protocol like IPPROTO_TCP, IPPROTO_UDP
 *  \param[in] socket_path path to identify the socket
 *  \param[in] flags flags like \ref OSMO_SOCK_F_CONNECT
 *  \returns socket fd on success; negative on error
 *
 * This function creates (and optionall binds/connects) a socket using
 * \ref osmo_sock_unix_init, but also fills the \a ofd structure.
 */
int osmo_sock_unix_init_ofd(struct osmo_fd *ofd, uint16_t type, uint8_t proto,
			    const char *socket_path, unsigned int flags)
{
	return osmo_fd_init_ofd(ofd, osmo_sock_unix_init(type, proto, socket_path, flags));
}

/*! \brief Get address/port information on soocket in dyn-alloc string
 *  \param[in] ctx talloc context from which to allocate string buffer
 *  \param[in] fd file descriptor of socket
 *  \returns string identifying the connection of this socket
 */
char *osmo_sock_get_name(void *ctx, int fd)
{
	struct sockaddr sa_l, sa_r;
	socklen_t sa_len_l = sizeof(sa_l);
	socklen_t sa_len_r = sizeof(sa_r);
	char hostbuf_l[64], hostbuf_r[64];
	char portbuf_l[16], portbuf_r[16];
	int rc;

	rc = getsockname(fd, &sa_l, &sa_len_l);
	if (rc < 0)
		return NULL;

	rc = getnameinfo(&sa_l, sa_len_l, hostbuf_l, sizeof(hostbuf_l),
			 portbuf_l, sizeof(portbuf_l),
			 NI_NUMERICHOST | NI_NUMERICSERV);
	if (rc < 0)
		return NULL;

	rc = getpeername(fd, &sa_r, &sa_len_r);
	if (rc < 0)
		goto local_only;

	rc = getnameinfo(&sa_r, sa_len_r, hostbuf_r, sizeof(hostbuf_r),
			 portbuf_r, sizeof(portbuf_r),
			 NI_NUMERICHOST | NI_NUMERICSERV);
	if (rc < 0)
		goto local_only;

	return talloc_asprintf(ctx, "(%s:%s<->%s:%s)", hostbuf_r, portbuf_r,
				hostbuf_l, portbuf_l);

local_only:
	return talloc_asprintf(ctx, "(NULL<->%s:%s)", hostbuf_l, portbuf_l);
}

#endif /* HAVE_SYS_SOCKET_H */

/*! @} */
