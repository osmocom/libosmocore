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
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <net/if.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>

#ifdef HAVE_LIBSCTP
#include <netinet/sctp.h>
#endif

static struct addrinfo *addrinfo_helper(uint16_t family, uint16_t type, uint8_t proto,
					const char *host, uint16_t port, bool passive)
{
	struct addrinfo hints, *result, *rp;
	char portbuf[6];
	int rc;

	snprintf(portbuf, sizeof(portbuf), "%u", port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = family;
	if (type == SOCK_RAW) {
		/* Workaround for glibc, that returns EAI_SERVICE (-8) if
		 * SOCK_RAW and IPPROTO_GRE is used.
		 * http://sourceware.org/bugzilla/show_bug.cgi?id=15015
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
		LOGP(DLGLOBAL, LOGL_ERROR, "getaddrinfo(%s, %u) failed: %s\n",
			host, port, gai_strerror(rc));
		return NULL;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		/* Workaround for glibc again */
		if (type == SOCK_RAW) {
			rp->ai_socktype = SOCK_RAW;
			rp->ai_protocol = proto;
		}
	}

	return result;
}

#ifdef HAVE_LIBSCTP
/*! Retrieve an array of addrinfo with specified hints, one for each host in the hosts array.
 *  \param[out] addrinfo array of addrinfo pointers, will be filled by the function on success.
 *		Its size must be at least the one of hosts.
 *  \param[in] family Socket family like AF_INET, AF_INET6.
 *  \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM.
 *  \param[in] proto Protocol like IPPROTO_TCP, IPPROTO_UDP.
 *  \param[in] hosts array of char pointers (strings) containing the addresses to query.
 *  \param[in] host_cnt length of the hosts array (in items).
 *  \param[in] port port number in host byte order.
 *  \param[in] passive whether to include the AI_PASSIVE flag in getaddrinfo() hints.
 *  \returns 0 is returned on success together with a filled addrinfo array; negative on error
 */
static int addrinfo_helper_multi(struct addrinfo **addrinfo, uint16_t family, uint16_t type, uint8_t proto,
					const char **hosts, size_t host_cnt, uint16_t port, bool passive)
{
	unsigned int i, j;

	for (i = 0; i < host_cnt; i++) {
		addrinfo[i] = addrinfo_helper(family, type, proto, hosts[i], port, passive);
		if (!addrinfo[i]) {
			for (j = 0; j < i; j++)
				freeaddrinfo(addrinfo[j]);
			return -EINVAL;
		}
	}
	return 0;
}
#endif /* HAVE_LIBSCTP*/

static int socket_helper_tail(int sfd, unsigned int flags)
{
	int rc, on = 1;
	uint8_t dscp = GET_OSMO_SOCK_F_DSCP(flags);
	uint8_t prio = GET_OSMO_SOCK_F_PRIO(flags);

	if (flags & OSMO_SOCK_F_NONBLOCK) {
		if (ioctl(sfd, FIONBIO, (unsigned char *)&on) < 0) {
			LOGP(DLGLOBAL, LOGL_ERROR,
				"cannot set this socket unblocking: %s\n",
				strerror(errno));
			close(sfd);
			return -EINVAL;
		}
	}

	if (dscp) {
		rc = osmo_sock_set_dscp(sfd, dscp);
		if (rc) {
			LOGP(DLGLOBAL, LOGL_ERROR, "cannot set IP DSCP of socket to %u: %s\n",
			     dscp, strerror(errno));
			/* we consider this a non-fatal error */
		}
	}

	if (prio) {
		rc = osmo_sock_set_priority(sfd, prio);
		if (rc) {
			LOGP(DLGLOBAL, LOGL_ERROR, "cannot set priority of socket to %u: %s\n",
			     prio, strerror(errno));
			/* we consider this a non-fatal error */
		}
	}

	return 0;
}

static int socket_helper(const struct addrinfo *rp, unsigned int flags)
{
	int sfd, rc;

	sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
	if (sfd == -1) {
		LOGP(DLGLOBAL, LOGL_ERROR,
			"unable to create socket: %s\n", strerror(errno));
		return sfd;
	}

	rc = socket_helper_tail(sfd, flags);
	if (rc < 0)
		return rc;

	return sfd;
}

static int socket_helper_osa(const struct osmo_sockaddr *addr, uint16_t type, uint8_t proto, unsigned int flags)
{
	int sfd, rc;

	sfd = socket(addr->u.sa.sa_family, type, proto);
	if (sfd == -1) {
		LOGP(DLGLOBAL, LOGL_ERROR,
			"unable to create socket: %s\n", strerror(errno));
		return sfd;
	}

	rc = socket_helper_tail(sfd, flags);
	if (rc < 0)
		return rc;

	return sfd;
}

#ifdef HAVE_LIBSCTP
/* Fill buf with a string representation of the address set, in the form:
 * buf_len == 0: "()"
 * buf_len == 1: "hostA"
 * buf_len >= 2: (hostA|hostB|...|...)
 */
static int multiaddr_snprintf(char* buf, size_t buf_len, const char **hosts, size_t host_cnt)
{
	int len = 0, offset = 0, rem = buf_len;
	size_t i;
	int ret;
	char *after;

	if (buf_len < 3)
		return -EINVAL;

	if (host_cnt != 1) {
		ret = snprintf(buf, rem, "(");
		if (ret < 0)
			return ret;
		OSMO_SNPRINTF_RET(ret, rem, offset, len);
	}
	for (i = 0; i < host_cnt; i++) {
		if (host_cnt == 1)
			after = "";
		else
			after = (i == (host_cnt - 1)) ? ")" : "|";
		ret = snprintf(buf + offset, rem, "%s%s", hosts[i] ? : "0.0.0.0", after);
		OSMO_SNPRINTF_RET(ret, rem, offset, len);
	}

	return len;
}
#endif /* HAVE_LIBSCTP */

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
	struct addrinfo *local = NULL, *remote = NULL, *rp;
	int sfd = -1, rc, on = 1;

	bool local_ipv4 = false, local_ipv6 = false;
	bool remote_ipv4 = false, remote_ipv6 = false;

	if ((flags & (OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT)) == 0) {
		LOGP(DLGLOBAL, LOGL_ERROR, "invalid: you have to specify either "
			"BIND or CONNECT flags\n");
		return -EINVAL;
	}

	/* figure out local address infos */
	if (flags & OSMO_SOCK_F_BIND) {
		local = addrinfo_helper(family, type, proto, local_host, local_port, true);
		if (!local)
			return -EINVAL;
	}

	/* figure out remote address infos */
	if (flags & OSMO_SOCK_F_CONNECT) {
		remote = addrinfo_helper(family, type, proto, remote_host, remote_port, false);
		if (!remote) {
			if (local)
				freeaddrinfo(local);

			return -EINVAL;
		}
	}

	/* It must do a full run to ensure AF_UNSPEC does not fail.
	 * In case first local valid entry is IPv4 and only remote valid entry
	 * is IPv6 or vice versa */
	if (family == AF_UNSPEC) {
		for (rp = local; rp != NULL; rp = rp->ai_next) {
			switch (rp->ai_family) {
				case AF_INET:
					local_ipv4 = true;
					break;
				case AF_INET6:
					local_ipv6 = true;
					break;
			}
		}

		for (rp = remote; rp != NULL; rp = rp->ai_next) {
			switch (rp->ai_family) {
				case AF_INET:
					remote_ipv4 = true;
					break;
				case AF_INET6:
					remote_ipv6 = true;
					break;
			}
		}

		if ((flags & OSMO_SOCK_F_BIND) && (flags & OSMO_SOCK_F_CONNECT)) {
			/* prioritize ipv6 as per RFC */
			if (local_ipv6 && remote_ipv6)
				family = AF_INET6;
			else if (local_ipv4 && remote_ipv4)
				family = AF_INET;
			else {
				if (local)
					freeaddrinfo(local);
				if (remote)
					freeaddrinfo(remote);
				LOGP(DLGLOBAL, LOGL_ERROR,
				     "Unable to find a common protocol (IPv4 or IPv6) "
				     "for local host: %s and remote host: %s.\n",
				     local_host, remote_host);
				return -ENODEV;
			}
		} else if ((flags & OSMO_SOCK_F_BIND)) {
			family = local_ipv6 ? AF_INET6 : AF_INET;
		} else if ((flags & OSMO_SOCK_F_CONNECT)) {
			family = remote_ipv6 ? AF_INET6 : AF_INET;
		}
	}

	/* figure out local side of socket */
	if (flags & OSMO_SOCK_F_BIND) {
		for (rp = local; rp != NULL; rp = rp->ai_next) {
			/* When called with AF_UNSPEC, family will set to IPv4 or IPv6 */
			if (rp->ai_family != family)
				continue;

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

		freeaddrinfo(local);
		if (rp == NULL) {
			if (remote)
				freeaddrinfo(remote);
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
		for (rp = remote; rp != NULL; rp = rp->ai_next) {
			/* When called with AF_UNSPEC, family will set to IPv4 or IPv6 */
			if (rp->ai_family != family)
				continue;

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

		freeaddrinfo(remote);
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

#define _SOCKADDR_TO_STR(dest, sockaddr) do { \
		if (osmo_sockaddr_str_from_sockaddr(dest, &sockaddr->u.sas)) \
			osmo_strlcpy((dest)->ip, "Invalid IP", 11); \
	} while (0)

/*! Initialize a socket (including bind and/or connect)
 *  \param[in] family Address Family like AF_INET, AF_INET6, AF_UNSPEC
 *  \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM
 *  \param[in] proto Protocol like IPPROTO_TCP, IPPROTO_UDP
 *  \param[in] local local address
 *  \param[in] remote remote address
 *  \param[in] flags flags like \ref OSMO_SOCK_F_CONNECT
 *  \returns socket file descriptor on success; negative on error
 *
 * This function creates a new socket of the
 * \a type and \a proto and optionally binds it to the \a local
 * as well as optionally connects it to the \a remote
 * depending on the value * of \a flags parameter.
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
int osmo_sock_init_osa(uint16_t type, uint8_t proto,
		        const struct osmo_sockaddr *local,
		        const struct osmo_sockaddr *remote,
		        unsigned int flags)
{
	int sfd = -1, rc, on = 1;
	struct osmo_sockaddr_str _sastr = {};
	struct osmo_sockaddr_str *sastr = &_sastr;

	if ((flags & (OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT)) == 0) {
		LOGP(DLGLOBAL, LOGL_ERROR, "invalid: you have to specify either "
			"BIND or CONNECT flags\n");
		return -EINVAL;
	}

	if ((flags & OSMO_SOCK_F_BIND) && !local) {
		LOGP(DLGLOBAL, LOGL_ERROR, "invalid argument. Cannot BIND when local is NULL\n");
		return -EINVAL;
	}

	if ((flags & OSMO_SOCK_F_CONNECT) && !remote) {
		LOGP(DLGLOBAL, LOGL_ERROR, "invalid argument. Cannot CONNECT when remote is NULL\n");
		return -EINVAL;
	}

	if ((flags & OSMO_SOCK_F_BIND) &&
	    (flags & OSMO_SOCK_F_CONNECT) &&
	    local->u.sa.sa_family != remote->u.sa.sa_family) {
		LOGP(DLGLOBAL, LOGL_ERROR, "invalid: the family for "
		     "local and remote endpoint must be same.\n");
		return -EINVAL;
	}

	/* figure out local side of socket */
	if (flags & OSMO_SOCK_F_BIND) {
		sfd = socket_helper_osa(local, type, proto, flags);
		if (sfd < 0) {
			_SOCKADDR_TO_STR(sastr, local);
			LOGP(DLGLOBAL, LOGL_ERROR, "no suitable local addr found for: " OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(sastr));
			return -ENODEV;
		}

		if (proto != IPPROTO_UDP || (flags & OSMO_SOCK_F_UDP_REUSEADDR)) {
			rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,
					&on, sizeof(on));
			if (rc < 0) {
				_SOCKADDR_TO_STR(sastr, local);
				LOGP(DLGLOBAL, LOGL_ERROR,
				     "cannot setsockopt socket: " OSMO_SOCKADDR_STR_FMT ": %s\n",
				     OSMO_SOCKADDR_STR_FMT_ARGS(sastr), strerror(errno));
				close(sfd);
				return rc;
			}
		}

		if (bind(sfd, &local->u.sa, sizeof(struct osmo_sockaddr)) == -1) {
			_SOCKADDR_TO_STR(sastr, local);
			LOGP(DLGLOBAL, LOGL_ERROR, "unable to bind socket: " OSMO_SOCKADDR_STR_FMT ": %s\n",
				     OSMO_SOCKADDR_STR_FMT_ARGS(sastr), strerror(errno));
			close(sfd);
			return -1;
		}
	}

	/* Reached this point, if OSMO_SOCK_F_BIND then sfd is valid (>=0) or it
	   was already closed and func returned. If OSMO_SOCK_F_BIND is not
	   set, then sfd = -1 */

	/* figure out remote side of socket */
	if (flags & OSMO_SOCK_F_CONNECT) {
		if (sfd < 0) {
			sfd = socket_helper_osa(remote, type, proto, flags);
			if (sfd < 0) {
				return sfd;
			}
		}

		rc = connect(sfd, &remote->u.sa, sizeof(struct osmo_sockaddr));
		if (rc != 0 && errno != EINPROGRESS) {
			_SOCKADDR_TO_STR(sastr, remote);
			LOGP(DLGLOBAL, LOGL_ERROR, "unable to connect socket: " OSMO_SOCKADDR_STR_FMT ": %s\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(sastr), strerror(errno));
			close(sfd);
			return rc;
		}
	}

	rc = osmo_sock_init_tail(sfd, type, flags);
	if (rc < 0) {
		close(sfd);
		sfd = -1;
	}

	return sfd;
}

#ifdef HAVE_LIBSCTP

/* Check whether there's an IPv6 Addr as first option of any addrinfo item in the addrinfo set */
static void addrinfo_has_v4v6addr(const struct addrinfo **result, size_t result_count, bool *has_v4, bool *has_v6)
{
	size_t host_idx;
	*has_v4 = false;
	*has_v6 = false;

	for (host_idx = 0; host_idx < result_count; host_idx++) {
		if (result[host_idx]->ai_family == AF_INET)
			*has_v4 = true;
		else if (result[host_idx]->ai_family == AF_INET6)
			*has_v6 = true;
	}
}

/* Check whether there's an IPv6 with IN6ADDR_ANY_INIT ("::") */
static bool addrinfo_has_in6addr_any(const struct addrinfo **result, size_t result_count)
{
	size_t host_idx;
	struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;

	for (host_idx = 0; host_idx < result_count; host_idx++) {
		if (result[host_idx]->ai_family != AF_INET6)
			continue;
		if (memcmp(&((struct sockaddr_in6 *)result[host_idx]->ai_addr)->sin6_addr,
			   &in6addr_any, sizeof(in6addr_any)) == 0)
			return true;
	}
	return false;
}

static int socket_helper_multiaddr(uint16_t family, uint16_t type, uint8_t proto, unsigned int flags)
{
	int sfd, rc;

	sfd = socket(family, type, proto);
	if (sfd == -1) {
		LOGP(DLGLOBAL, LOGL_ERROR,
			"Unable to create socket: %s\n", strerror(errno));
		return sfd;
	}

	rc = socket_helper_tail(sfd, flags);
	if (rc < 0)
		return rc;

	return sfd;
}

/* Build array of addresses taking first addrinfo result of the requested family
 * for each host in addrs_buf. */
static int addrinfo_to_sockaddr(uint16_t family, const struct addrinfo **result,
				const char **hosts, unsigned int host_cont,
				uint8_t *addrs_buf, size_t addrs_buf_len) {
	size_t host_idx, offset = 0;
	const struct addrinfo *rp;

	for (host_idx = 0; host_idx < host_cont; host_idx++) {
		/* Addresses are ordered based on RFC 3484, see man getaddrinfo */
		for (rp = result[host_idx]; rp != NULL; rp = rp->ai_next) {
			if (family != AF_UNSPEC && rp->ai_family != family)
				continue;
			if (offset + rp->ai_addrlen > addrs_buf_len) {
				LOGP(DLGLOBAL, LOGL_ERROR, "Output buffer to small: %zu\n",
				     addrs_buf_len);
				return -ENOSPC;
			}
			memcpy(addrs_buf + offset, rp->ai_addr, rp->ai_addrlen);
			offset += rp->ai_addrlen;
			break;
		}
		if (!rp) { /* No addr could be bound for this host! */
			LOGP(DLGLOBAL, LOGL_ERROR, "No suitable remote address found for host: %s\n",
			     hosts[host_idx]);
			return -ENODEV;
		}
	}
	return 0;
}

/*! Initialize a socket (including bind and/or connect) with multiple local or remote addresses.
 *  \param[in] family Address Family like AF_INET, AF_INET6, AF_UNSPEC
 *  \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM
 *  \param[in] proto Protocol like IPPROTO_TCP, IPPROTO_UDP
 *  \param[in] local_hosts array of char pointers (strings), each containing local host name or IP address in string form
 *  \param[in] local_hosts_cnt length of local_hosts (in items)
 *  \param[in] local_port local port number in host byte order
 *  \param[in] remote_host array of char pointers (strings), each containing remote host name or IP address in string form
 *  \param[in] remote_hosts_cnt length of remote_hosts (in items)
 *  \param[in] remote_port remote port number in host byte order
 *  \param[in] flags flags like \ref OSMO_SOCK_F_CONNECT
 *  \returns socket file descriptor on success; negative on error
 *
 * This function is similar to \ref osmo_sock_init2(), but can be passed an
 * array of local or remote addresses for protocols supporting multiple
 * addresses per socket, like SCTP (currently only one supported). This function
 * should not be used by protocols not supporting this kind of features, but
 * rather \ref osmo_sock_init2() should be used instead.
 * See \ref osmo_sock_init2() for more information on flags and general behavior.
 */
int osmo_sock_init2_multiaddr(uint16_t family, uint16_t type, uint8_t proto,
		   const char **local_hosts, size_t local_hosts_cnt, uint16_t local_port,
		   const char **remote_hosts, size_t remote_hosts_cnt, uint16_t remote_port,
		   unsigned int flags)

{
	struct addrinfo *res_loc[OSMO_SOCK_MAX_ADDRS], *res_rem[OSMO_SOCK_MAX_ADDRS];
	int sfd = -1, rc, on = 1;
	unsigned int i;
	bool loc_has_v4addr, rem_has_v4addr;
	bool loc_has_v6addr, rem_has_v6addr;
	struct sockaddr_in6 addrs_buf[OSMO_SOCK_MAX_ADDRS];
	char strbuf[512];

	/* updated later in case of AF_UNSPEC */
	loc_has_v4addr = rem_has_v4addr = (family == AF_INET);
	loc_has_v6addr = rem_has_v6addr = (family == AF_INET6);

	/* TODO: So far this function is only aimed for SCTP, but could be
	   reused in the future for other protocols with multi-addr support */
	if (proto != IPPROTO_SCTP)
		return -ENOTSUP;

	if ((flags & (OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT)) == 0) {
		LOGP(DLGLOBAL, LOGL_ERROR, "invalid: you have to specify either "
			"BIND or CONNECT flags\n");
		return -EINVAL;
	}

	if (((flags & OSMO_SOCK_F_BIND) && !local_hosts_cnt) ||
	    ((flags & OSMO_SOCK_F_CONNECT) && !remote_hosts_cnt) ||
	    local_hosts_cnt > OSMO_SOCK_MAX_ADDRS ||
	    remote_hosts_cnt > OSMO_SOCK_MAX_ADDRS)
		return -EINVAL;

	/* figure out local side of socket */
	if (flags & OSMO_SOCK_F_BIND) {
		rc = addrinfo_helper_multi(res_loc, family, type, proto, local_hosts,
					   local_hosts_cnt, local_port, true);
		if (rc < 0)
			return -EINVAL;
		/* Figure out if there's any IPV4 or IPv6 addr in the set */
		if (family == AF_UNSPEC)
			addrinfo_has_v4v6addr((const struct addrinfo **)res_loc, local_hosts_cnt,
					      &loc_has_v4addr, &loc_has_v6addr);
	}
	/* figure out remote side of socket */
	if (flags & OSMO_SOCK_F_CONNECT) {
		rc = addrinfo_helper_multi(res_rem, family, type, proto, remote_hosts,
					   remote_hosts_cnt, remote_port, false);
		if (rc < 0) {
			rc = -EINVAL;
			goto ret_freeaddrinfo_loc;
		}
		/* Figure out if there's any IPv4 or IPv6  addr in the set */
		if (family == AF_UNSPEC)
			addrinfo_has_v4v6addr((const struct addrinfo **)res_rem, remote_hosts_cnt,
					      &rem_has_v4addr, &rem_has_v6addr);
	}

	if (((flags & OSMO_SOCK_F_BIND) && (flags & OSMO_SOCK_F_CONNECT)) &&
	    !addrinfo_has_in6addr_any((const struct addrinfo **)res_loc, local_hosts_cnt) &&
	    (loc_has_v4addr != rem_has_v4addr || loc_has_v6addr != rem_has_v6addr)) {
		LOGP(DLGLOBAL, LOGL_ERROR, "Invalid v4 vs v6 in local vs remote addresses\n");
		rc = -EINVAL;
		goto ret_freeaddrinfo;
	}

	sfd = socket_helper_multiaddr(loc_has_v6addr ? AF_INET6 : AF_INET,
				      type, proto, flags);
	if (sfd < 0) {
		rc = sfd;
		goto ret_freeaddrinfo;
	}

	if (flags & OSMO_SOCK_F_BIND) {
		/* Since so far we only allow IPPROTO_SCTP in this function,
		   no need to check below for "proto != IPPROTO_UDP || flags & OSMO_SOCK_F_UDP_REUSEADDR" */
		rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,
				&on, sizeof(on));
		if (rc < 0) {
			multiaddr_snprintf(strbuf, sizeof(strbuf), local_hosts, local_hosts_cnt);
			LOGP(DLGLOBAL, LOGL_ERROR,
			     "cannot setsockopt socket:"
			     " %s:%u: %s\n",
			     strbuf, local_port,
			     strerror(errno));
			goto ret_close;
		}

		/* Build array of addresses taking first entry for each host.
		   TODO: Ideally we should use backtracking storing last used
		   indexes and trying next combination if connect() fails .*/
		/* We could alternatively use v4v6 mapped addresses and call sctp_bindx once with an array od sockaddr_in6 */
		rc = addrinfo_to_sockaddr(family, (const struct addrinfo **)res_loc,
					  local_hosts, local_hosts_cnt,
					  (uint8_t*)addrs_buf, sizeof(addrs_buf));
		if (rc < 0) {
			rc = -ENODEV;
			goto ret_close;
		}

		rc = sctp_bindx(sfd, (struct sockaddr *)addrs_buf, local_hosts_cnt, SCTP_BINDX_ADD_ADDR);
		if (rc == -1) {
			multiaddr_snprintf(strbuf, sizeof(strbuf), local_hosts, local_hosts_cnt);
			LOGP(DLGLOBAL, LOGL_NOTICE, "unable to bind socket: %s:%u: %s\n",
			     strbuf, local_port, strerror(errno));
			rc = -ENODEV;
			goto ret_close;
		}
	}

	if (flags & OSMO_SOCK_F_CONNECT) {
		/* Build array of addresses taking first of same family for each host.
		   TODO: Ideally we should use backtracking storing last used
		   indexes and trying next combination if connect() fails .*/
		rc = addrinfo_to_sockaddr(family, (const struct addrinfo **)res_rem,
					  remote_hosts, remote_hosts_cnt,
					  (uint8_t*)addrs_buf, sizeof(addrs_buf));
		if (rc < 0) {
			rc = -ENODEV;
			goto ret_close;
		}

		rc = sctp_connectx(sfd, (struct sockaddr *)addrs_buf, remote_hosts_cnt, NULL);
		if (rc != 0 && errno != EINPROGRESS) {
			multiaddr_snprintf(strbuf, sizeof(strbuf), remote_hosts, remote_hosts_cnt);
			LOGP(DLGLOBAL, LOGL_ERROR, "unable to connect socket: %s:%u: %s\n",
				strbuf, remote_port, strerror(errno));
			rc = -ENODEV;
			goto ret_close;
		}
	}

	rc = osmo_sock_init_tail(sfd, type, flags);
	if (rc < 0) {
		close(sfd);
		sfd = -1;
	}

	rc = sfd;
	goto ret_freeaddrinfo;

ret_close:
	if (sfd >= 0)
		close(sfd);
ret_freeaddrinfo:
	if (flags & OSMO_SOCK_F_CONNECT) {
		for (i = 0; i < remote_hosts_cnt; i++)
			freeaddrinfo(res_rem[i]);
	}
ret_freeaddrinfo_loc:
	if (flags & OSMO_SOCK_F_BIND) {
		for (i = 0; i < local_hosts_cnt; i++)
			freeaddrinfo(res_loc[i]);
	}
	return rc;
}
#endif /* HAVE_LIBSCTP */

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
	int sfd = -1; /* initialize to avoid uninitialized false warnings on some gcc versions (11.1.0) */
	int on = 1;
	int rc;

	if ((flags & (OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT)) ==
		     (OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT)) {
		LOGP(DLGLOBAL, LOGL_ERROR, "invalid: both bind and connect flags set:"
			" %s:%u\n", host, port);
		return -EINVAL;
	}

	result = addrinfo_helper(family, type, proto, host, port, flags & OSMO_SOCK_F_BIND);
	if (!result)
		return -EINVAL;

	for (rp = result; rp != NULL; rp = rp->ai_next) {
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
 *  \param[in] flags flags like \ref OSMO_SOCK_F_CONNECT
 *  \returns socket fd on success; negative on error
 *
 * This function fills the \a ofd structure.
 */
static inline int osmo_fd_init_ofd(struct osmo_fd *ofd, int sfd, unsigned int flags)
{
	int rc;

	if (sfd < 0)
		return sfd;

	ofd->fd = sfd;
	ofd->when = OSMO_FD_READ;

	/* if we're doing a non-blocking connect, the completion will be signaled
	 * by marking the fd as WRITE-able.  So in this exceptional case, we're
	 * also interested in when the socket becomes write-able */
	if ((flags & (OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_NONBLOCK)) ==
	     (OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_NONBLOCK)) {
		ofd->when |= OSMO_FD_WRITE;
	}

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
	return osmo_fd_init_ofd(ofd, osmo_sock_init(family, type, proto, host, port, flags), flags);
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
					local_port, remote_host, remote_port, flags), flags);
}

int osmo_sock_init_osa_ofd(struct osmo_fd *ofd, int type, int proto,
			const struct osmo_sockaddr *local,
			const struct osmo_sockaddr *remote, unsigned int flags)
{
	return osmo_fd_init_ofd(ofd, osmo_sock_init_osa(type, proto, local, remote, flags), flags);
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

/* linux has a default route:
local 127.0.0.0/8 dev lo  proto kernel  scope host  src 127.0.0.1
*/
static int sockaddr_is_local_routed(const struct sockaddr *a)
{
#if __linux__
	if (a->sa_family != AF_INET)
		return 0;

	uint32_t address = ((struct sockaddr_in *)a)->sin_addr.s_addr; /* already BE */
	uint32_t eightmask = htonl(0xff000000); /* /8 mask */
	uint32_t local_prefix_127 = htonl(0x7f000000); /* 127.0.0.0 */

	if ((address & eightmask) == local_prefix_127)
		return 1;
#endif
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

	if (sockaddr_is_local_routed(addr))
		return 1;

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

	const struct sockaddr_in6 *sin6;

	switch (sa->sa_family) {
	case AF_INET:
		return osmo_sockaddr_in_to_str_and_uint(addr, addr_len, port,
							(const struct sockaddr_in *)sa);
	case AF_INET6:
		sin6 = (const struct sockaddr_in6 *)sa;
		if (port)
			*port = ntohs(sin6->sin6_port);
		if (addr && inet_ntop(sa->sa_family, &sin6->sin6_addr, addr, addr_len))
			return strlen(addr);
		break;
	}
	return 0;
}

/*! inet_ntop() wrapper for a struct sockaddr.
 *  \param[in] sa  source sockaddr to get the address from.
 *  \param[out] dst  string buffer of at least INET6_ADDRSTRLEN size.
 *  \returns returns a non-null pointer to dst. NULL is returned if there was an
 *  error, with errno set to indicate the error.
 */
const char *osmo_sockaddr_ntop(const struct sockaddr *sa, char *dst)
{
	const struct osmo_sockaddr *osa = (const struct osmo_sockaddr *)sa;
	return inet_ntop(osa->u.sa.sa_family,
			 osa->u.sa.sa_family == AF_INET6 ?
				(const void *)&osa->u.sin6.sin6_addr :
				(const void *)&osa->u.sin.sin_addr,
			 dst, INET6_ADDRSTRLEN);
}

/*! Get sockaddr port content (in host byte order)
 *  \param[in] sa  source sockaddr to get the port from.
 *  \returns returns the sockaddr port in host byte order
 */
uint16_t osmo_sockaddr_port(const struct sockaddr *sa)
{
	const struct osmo_sockaddr *osa = (const struct osmo_sockaddr *)sa;
	switch (osa->u.sa.sa_family) {
	case AF_INET6:
		return ntohs(osa->u.sin6.sin6_port);
	case AF_INET:
		return ntohs(osa->u.sin.sin_port);
	}
	return 0;
}

/*! Set sockaddr port content (to network byte order).
 *  \param[out] sa  sockaddr to set the port of.
 *  \param[in] port  port nr to set.
 */
void osmo_sockaddr_set_port(struct sockaddr *sa, uint16_t port)
{
	struct osmo_sockaddr *osa = (struct osmo_sockaddr *)sa;
	switch (osa->u.sa.sa_family) {
	case AF_INET6:
		osa->u.sin6.sin6_port = htons(port);
		return;
	case AF_INET:
		osa->u.sin.sin_port = htons(port);
		return;
	}
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
#if defined(__clang__) && defined(SUN_LEN)
__attribute__((no_sanitize("undefined")))
#endif
int osmo_sock_unix_init(uint16_t type, uint8_t proto,
			const char *socket_path, unsigned int flags)
{
	struct sockaddr_un local;
	int sfd, rc;
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

	rc = socket_helper_tail(sfd, flags);
	if (rc < 0)
		return rc;

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
	return osmo_fd_init_ofd(ofd, osmo_sock_unix_init(type, proto, socket_path, flags), flags);
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
	struct sockaddr_storage sa;
	socklen_t len = sizeof(sa);
	char ipbuf[INET6_ADDRSTRLEN], portbuf[6];
	int rc;

	rc = local ? getsockname(fd, (struct sockaddr*)&sa, &len) : getpeername(fd, (struct sockaddr*)&sa, &len);
	if (rc < 0)
		return rc;

	rc = getnameinfo((const struct sockaddr*)&sa, len, ipbuf, sizeof(ipbuf),
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
	static __thread char str[OSMO_SOCK_NAME_MAXLEN];
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

/*! Set the network device to which we should bind the multicast socket
 *  \param[in] fd file descriptor of related socket
 *  \param[in] ifname name of network interface to user for multicast
 *  \returns 0 on success; negative otherwise */
int osmo_sock_mcast_iface_set(int fd, const char *ifname)
{
	unsigned int ifindex;
	struct ip_mreqn mr;

	/* first, resolve interface name to ifindex */
	ifindex = if_nametoindex(ifname);
	if (ifindex == 0)
		return -errno;

	/* next, configure kernel to use that ifindex for this sockets multicast traffic */
	memset(&mr, 0, sizeof(mr));
	mr.imr_ifindex = ifindex;
	return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mr, sizeof(mr));
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
	struct sockaddr_storage local_addr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	socklen_t local_addr_len;
	uint16_t family;

	/* Find out the address family (AF_INET or AF_INET6?) */
	memset(&addrinfo_hint, '\0', sizeof(addrinfo_hint));
	addrinfo_hint.ai_family = AF_UNSPEC;
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

	switch (local_addr.ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in*)&local_addr;
		if (!inet_ntop(AF_INET, &sin->sin_addr, local_ip, INET_ADDRSTRLEN))
			return -EINVAL;
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6*)&local_addr;
		if (!inet_ntop(AF_INET6, &sin6->sin6_addr, local_ip, INET6_ADDRSTRLEN))
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/*! Determine the matching local address for a given remote address.
 *  \param[out] local_ip caller provided memory for resulting local address
 *  \param[in] remote_ip remote address
 *  \returns 0 on success; negative otherwise
 */
int osmo_sockaddr_local_ip(struct osmo_sockaddr *local_ip, const struct osmo_sockaddr *remote_ip)
{
	int sfd;
	int rc;
	socklen_t local_ip_len;

	sfd = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP, NULL, remote_ip, OSMO_SOCK_F_CONNECT);
	if (sfd < 0)
		return -EINVAL;

	memset(local_ip, 0, sizeof(*local_ip));
	local_ip_len = sizeof(*local_ip);
	rc = getsockname(sfd, (struct sockaddr *)local_ip, &local_ip_len);
	close(sfd);

	return rc;
}

/*! Copy the addr part, the IP address octets in network byte order, to a buffer.
 * Useful for encoding network protocols.
 * \param[out] dst  Write octets to this buffer.
 * \param[in] dst_maxlen  Space available in buffer.
 * \param[in] os  Sockaddr to copy IP of.
 * \return nr of octets written on success, negative on error.
 */
int osmo_sockaddr_to_octets(uint8_t *dst, size_t dst_maxlen, const struct osmo_sockaddr *os)
{
	const void *addr;
	size_t len;
	switch (os->u.sa.sa_family) {
	case AF_INET:
		addr = &os->u.sin.sin_addr;
		len = sizeof(os->u.sin.sin_addr);
		break;
	case AF_INET6:
		addr = &os->u.sin6.sin6_addr;
		len = sizeof(os->u.sin6.sin6_addr);
		break;
	default:
		return -ENOTSUP;
	}
	if (dst_maxlen < len)
		return -ENOSPC;
	memcpy(dst, addr, len);
	return len;
}

/*! Copy the addr part, the IP address octets in network byte order, from a buffer.
 * Useful for decoding network protocols.
 * \param[out] os  Write IP address to this sockaddr.
 * \param[in] src  Source buffer to read IP address octets from.
 * \param[in] src_len  Number of octets to copy.
 * \return number of octets read on success, negative on error.
 */
int osmo_sockaddr_from_octets(struct osmo_sockaddr *os, const void *src, size_t src_len)
{
	void *addr;
	size_t len;
	*os = (struct osmo_sockaddr){0};
	switch (src_len) {
	case sizeof(os->u.sin.sin_addr):
		os->u.sa.sa_family = AF_INET;
		addr = &os->u.sin.sin_addr;
		len = sizeof(os->u.sin.sin_addr);
		break;
	case sizeof(os->u.sin6.sin6_addr):
		os->u.sin6.sin6_family = AF_INET6;
		addr = &os->u.sin6.sin6_addr;
		len = sizeof(os->u.sin6.sin6_addr);
		break;
	default:
		return -ENOTSUP;
	}
	memcpy(addr, src, len);
	return len;
}

/*! Compare two osmo_sockaddr.
 * \param[in] a
 * \param[in] b
 * \return 0 if a and b are equal. Otherwise it follows memcmp()
 */
int osmo_sockaddr_cmp(const struct osmo_sockaddr *a,
		      const struct osmo_sockaddr *b)
{
	if (a == b)
		return 0;
	if (!a)
		return 1;
	if (!b)
		return -1;

	if (a->u.sa.sa_family != b->u.sa.sa_family) {
		return OSMO_CMP(a->u.sa.sa_family, b->u.sa.sa_family);
	}

	switch (a->u.sa.sa_family) {
	case AF_INET:
		return memcmp(&a->u.sin, &b->u.sin, sizeof(struct sockaddr_in));
	case AF_INET6:
		return memcmp(&a->u.sin6, &b->u.sin6, sizeof(struct sockaddr_in6));
	default:
		/* fallback to memcmp for remaining AF over the full osmo_sockaddr length */
		return memcmp(a, b, sizeof(struct osmo_sockaddr));
	}
}

/*! string-format a given osmo_sockaddr address
 *  \param[in] sockaddr the osmo_sockaddr to print
 *  \return pointer to the string on success; NULL on error
 */
const char *osmo_sockaddr_to_str(const struct osmo_sockaddr *sockaddr)
{
	/* INET6_ADDRSTRLEN contains already a null termination,
	 * adding '[' ']' ':' '16 bit port' */
	static __thread char buf[INET6_ADDRSTRLEN + 8];
	return osmo_sockaddr_to_str_buf(buf, sizeof(buf), sockaddr);
}

/*! string-format a given osmo_sockaddr address into a user-supplied buffer.
 * Same as osmo_sockaddr_to_str_buf() but returns a would-be length in snprintf() style.
 *  \param[in] buf user-supplied output buffer
 *  \param[in] buf_len size of the user-supplied output buffer in bytes
 *  \param[in] sockaddr the osmo_sockaddr to print
 *  \return number of characters that would be written if the buffer is large enough, like snprintf().
 */
int osmo_sockaddr_to_str_buf2(char *buf, size_t buf_len, const struct osmo_sockaddr *sockaddr)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buf_len };
	uint16_t port = 0;

	if (!sockaddr) {
		OSMO_STRBUF_PRINTF(sb, "NULL");
		return sb.chars_needed;
	}

	switch (sockaddr->u.sa.sa_family) {
	case AF_INET:
		OSMO_STRBUF_APPEND(sb, osmo_sockaddr_to_str_and_uint, &port, &sockaddr->u.sa);
		if (port)
			OSMO_STRBUF_PRINTF(sb, ":%u", port);
		break;
	case AF_INET6:
		OSMO_STRBUF_PRINTF(sb, "[");
		OSMO_STRBUF_APPEND(sb, osmo_sockaddr_to_str_and_uint, &port, &sockaddr->u.sa);
		OSMO_STRBUF_PRINTF(sb, "]");
		if (port)
			OSMO_STRBUF_PRINTF(sb, ":%u", port);
		break;
	default:
		OSMO_STRBUF_PRINTF(sb, "unsupported family %d", sockaddr->u.sa.sa_family);
		break;
	}

	return sb.chars_needed;
}

/*! string-format a given osmo_sockaddr address into a talloc allocated buffer.
 * Like osmo_sockaddr_to_str_buf2() but returns a talloc allocated string.
 *  \param[in] ctx  talloc context to allocate from, e.g. OTC_SELECT.
 *  \param[in] sockaddr  the osmo_sockaddr to print.
 *  \return human readable string.
 */
char *osmo_sockaddr_to_str_c(void *ctx, const struct osmo_sockaddr *sockaddr)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", osmo_sockaddr_to_str_buf2, sockaddr)
}

/*! string-format a given osmo_sockaddr address into a user-supplied buffer.
 * Like osmo_sockaddr_to_str_buf2() but returns buf, or NULL if too short.
 *  \param[in] buf user-supplied output buffer
 *  \param[in] buf_len size of the user-supplied output buffer in bytes
 *  \param[in] sockaddr the osmo_sockaddr to print
 *  \return pointer to the string on success; NULL on error
 */
char *osmo_sockaddr_to_str_buf(char *buf, size_t buf_len,
			    const struct osmo_sockaddr *sockaddr)
{
	int chars_needed = osmo_sockaddr_to_str_buf2(buf, buf_len, sockaddr);
	if (chars_needed >= buf_len)
		return NULL;
	return buf;
}

/*! Set the DSCP (differentiated services code point) of a socket.
 *  \param[in] dscp DSCP value in range 0..63
 *  \returns 0 on success; negative on error. */
int osmo_sock_set_dscp(int fd, uint8_t dscp)
{
	struct sockaddr_storage local_addr;
	socklen_t local_addr_len = sizeof(local_addr);
	uint8_t tos;
	socklen_t tos_len = sizeof(tos);
	int tclass;
	socklen_t tclass_len = sizeof(tclass);
	int rc;

	/* DSCP is a 6-bit value stored in the upper 6 bits of the 8-bit TOS */
	if (dscp > 63)
		return -EINVAL;

	rc = getsockname(fd, (struct sockaddr *)&local_addr, &local_addr_len);
	if (rc < 0)
		return rc;

	switch (local_addr.ss_family) {
	case AF_INET:
		/* read the original value */
		rc = getsockopt(fd, IPPROTO_IP, IP_TOS, &tos, &tos_len);
		if (rc < 0)
			return rc;
		/* mask-in the DSCP into the upper 6 bits */
		tos &= 0x03;
		tos |= dscp << 2;
		/* and write it back to the kernel */
		rc = setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
		break;
	case AF_INET6:
		/* read the original value */
		rc = getsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tclass, &tclass_len);
		if (rc < 0)
			return rc;
		/* mask-in the DSCP into the upper 6 bits */
		tclass &= 0x03;
		tclass |= dscp << 2;
		/* and write it back to the kernel */
		rc = setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof(tclass));
		break;
	case AF_UNSPEC:
	default:
		LOGP(DLGLOBAL, LOGL_ERROR, "No DSCP support for socket family %u\n",
		     local_addr.ss_family);
		rc = -1;
		break;
	}

	return rc;
}

/*! Set the priority value of a socket.
 *  \param[in] prio priority value. Values outside 0..6 require CAP_NET_ADMIN.
 *  \returns 0 on success; negative on error. */
int osmo_sock_set_priority(int fd, int prio)
{
	/* and write it back to the kernel */
	return setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
}

#endif /* HAVE_SYS_SOCKET_H */

/*! @} */
