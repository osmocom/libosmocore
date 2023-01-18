/*
 * (C) 2017 by Harald Welte <laforge@gnumonks.org>
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/bits.h>

#include "config.h"

void *ctx = NULL;

#ifdef HAVE_LIBSCTP
static uint16_t sock_get_local_port(int fd, bool is_v6) {
	struct sockaddr_storage sa;
	struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
	socklen_t len = sizeof(sa);
	int local_port;

	OSMO_ASSERT(getsockname(fd, (struct sockaddr*)&sa, &len) == 0);
	if(!is_v6)
		local_port = osmo_load16be(&sin->sin_port);
	else
		local_port = osmo_load16be(&sin6->sin6_port);
	//printf("Checking osmo_sock_init2_multiaddr() port: %" PRIu16 "\n", listen_port_v4);
	return local_port;
}

/* Test API osmo_sock_init2_multiaddr with 1 local/remote address */
static int test_sockinit2_multiaddr(const char **addrv4_loc, const char **addrv6_loc,
				    const char **addrv4_rem, const char **addrv6_rem,
				    size_t addrv4_size, size_t addrv6_size)
{
	int fd, rc;
	int listen_fd_v4, listen_fd_v6;
	int listen_port_v4, listen_port_v6;

	printf("Checking osmo_sock_init2_multiaddr() with bind to a random local SCTP IPv4 port\n");

	listen_fd_v4 = osmo_sock_init2_multiaddr(AF_INET, SOCK_STREAM, IPPROTO_SCTP,
				       addrv4_loc, addrv4_size, 0,
				       NULL, 0, 0, OSMO_SOCK_F_BIND);
	OSMO_ASSERT(listen_fd_v4 >= 0);
	/* expect it to be blocking */
	rc = fcntl(listen_fd_v4, F_GETFL);
	OSMO_ASSERT(!(rc & O_NONBLOCK));

	listen_port_v4 = sock_get_local_port(listen_fd_v4, false);

	printf("Checking osmo_sock_init2_multiaddr() with bind to a random local SCTP IPv6 port\n");

	listen_fd_v6 = osmo_sock_init2_multiaddr(AF_INET6, SOCK_STREAM, IPPROTO_SCTP,
				       addrv6_loc, addrv6_size, 0,
				       NULL, 0, 0, OSMO_SOCK_F_BIND);
	OSMO_ASSERT(listen_fd_v6 >= 0);
	/* expect it to be blocking */
	rc = fcntl(listen_fd_v6, F_GETFL);
	OSMO_ASSERT(!(rc & O_NONBLOCK));

	listen_port_v6 = sock_get_local_port(listen_fd_v6, true);

	printf("Checking osmo_sock_init2_multiaddr() for OSMO_SOCK_F_NONBLOCK\n");
	fd = osmo_sock_init2_multiaddr(AF_INET, SOCK_STREAM, IPPROTO_SCTP,
				       addrv4_loc, addrv4_size, 0,
				       NULL, 0, 0, OSMO_SOCK_F_BIND|OSMO_SOCK_F_NONBLOCK);
	OSMO_ASSERT(fd >= 0);
	/* expect it to be blocking */
	rc = fcntl(fd, F_GETFL);
	OSMO_ASSERT(rc & O_NONBLOCK);
	close(fd);

	printf("Checking osmo_sock_init2_multiaddr() for invalid flags\n");
	fd = osmo_sock_init2_multiaddr(AF_INET, SOCK_STREAM, IPPROTO_SCTP,
				       addrv4_loc, addrv4_size, 0,
				       NULL, 0, 0, 0);
	OSMO_ASSERT(fd < 0);

	printf("Checking osmo_sock_init2_multiaddr() for combined BIND + CONNECT\n");
	fd = osmo_sock_init2_multiaddr(AF_INET, SOCK_STREAM, IPPROTO_SCTP,
				       addrv4_rem, addrv4_size, 0,
				       addrv4_rem, addrv4_size, listen_port_v4,
				       OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd >= 0);

	printf("Checking osmo_sock_init2_multiaddr(AF_UNSPEC) must fail on mixed IPv4 & IPv6\n");
	fd = osmo_sock_init2_multiaddr(AF_UNSPEC, SOCK_STREAM, IPPROTO_SCTP,
				       addrv4_rem, addrv4_size, 0,
				       addrv6_rem, addrv6_size, listen_port_v6,
				       OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd < 0);

	printf("Checking osmo_sock_init2_multiaddr(AF_UNSPEC) must fail on mixed IPv6 & IPv4\n");
	fd = osmo_sock_init2_multiaddr(AF_UNSPEC, SOCK_STREAM, IPPROTO_SCTP,
				       addrv6_rem, addrv6_size, 0,
				       addrv4_rem, addrv4_size, listen_port_v4,
				       OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd < 0);

	printf("Checking osmo_sock_init2_multiaddr(AF_UNSPEC) BIND + CONNECT on IPv4\n");
	fd = osmo_sock_init2_multiaddr(AF_UNSPEC, SOCK_STREAM, IPPROTO_SCTP,
				       addrv4_rem, addrv4_size, 0,
				       addrv4_rem, addrv4_size, listen_port_v4,
				       OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd >= 0);

	printf("Checking osmo_sock_init2_multiaddr(AF_UNSPEC) BIND + CONNECT on IPv6\n");
	fd = osmo_sock_init2_multiaddr(AF_UNSPEC, SOCK_STREAM, IPPROTO_SCTP,
				       addrv6_rem, addrv6_size, 0,
				       addrv6_rem, addrv6_size, listen_port_v6,
				       OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd >= 0);

	close(listen_fd_v4);
	close(listen_fd_v6);
	printf("Done\n");
	return 0;
}

/* Test API osmo_sock_init2_multiaddr with 1 local/remote address */
static int test_sockinit2_multiaddr_simple(void)
{
	const char *addrv4_loc[] = { "0.0.0.0" };
	const char *addrv6_loc[] = { "::" };
	const char *addrv4_rem[] = { "127.0.0.1" };
	const char *addrv6_rem[] = { "::1" };

	return test_sockinit2_multiaddr(addrv4_loc, addrv6_loc,
					addrv4_rem, addrv6_rem, 1, 1);
}

/* Test API osmo_sock_init2_multiaddr with several local/remote address */
static int test_sockinit2_multiaddr_several(void)
{
	const char *addrv4_localhost[] = { "127.0.0.1", "127.0.0.2" };
	const char *addrv6_localhost[] = { "::1" };

	return test_sockinit2_multiaddr(addrv4_localhost, addrv6_localhost,
					addrv4_localhost, addrv6_localhost, 2, 1);
}

/* Test API osmo_sock_init2_multiaddr with several local/remote address, using both ipv4+v6 */
static int test_sockinit2_multiaddr_mixed(void)
{
	const char *addr_localhost[] = { "127.0.0.1", "127.0.0.2", "::1" };
	size_t addr_size = ARRAY_SIZE(addr_localhost);

	int listen_fd, listen_port, fd;

	printf("Checking osmo_sock_init2_multiaddr(AF_UNSPEC) BIND on AF_INET IPv4+v6 fails\n");
	listen_fd = osmo_sock_init2_multiaddr(AF_INET, SOCK_STREAM, IPPROTO_SCTP,
				       addr_localhost, addr_size, 0,
				       NULL, 0, 0, OSMO_SOCK_F_BIND);
	OSMO_ASSERT(listen_fd < 0);

	printf("Checking osmo_sock_init2_multiaddr(AF_UNSPEC) BIND on AF_INET6 IPv4+v6 fails\n");
	listen_fd = osmo_sock_init2_multiaddr(AF_INET6, SOCK_STREAM, IPPROTO_SCTP,
				       addr_localhost, addr_size, 0,
				       NULL, 0, 0, OSMO_SOCK_F_BIND);
	OSMO_ASSERT(listen_fd < 0);

	printf("Checking osmo_sock_init2_multiaddr(AF_UNSPEC) BIND on AF_UNSPEC IPv4+v6 succeeds\n");
	listen_fd = osmo_sock_init2_multiaddr(AF_UNSPEC, SOCK_STREAM, IPPROTO_SCTP,
				       addr_localhost, addr_size, 0,
				       NULL, 0, 0, OSMO_SOCK_F_BIND);
	OSMO_ASSERT(listen_fd >= 0);

	listen_port = sock_get_local_port(listen_fd, true);

	printf("Checking osmo_sock_init2_multiaddr(AF_UNSPEC) BIND + CONNECT on IPv4\n");
	fd = osmo_sock_init2_multiaddr(AF_UNSPEC, SOCK_STREAM, IPPROTO_SCTP,
				       addr_localhost, addr_size, 0,
				       addr_localhost, addr_size, listen_port,
				       OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd >= 0);
	close(fd);

	close(listen_fd);
	return 0;
}
#endif /* ifdef HAVE_LIBSCTP */

const struct log_info_cat default_categories[] = {
};

static struct log_info info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char *argv[])
{
	ctx = talloc_named_const(NULL, 0, "socket_test_sctp");
	osmo_init_logging2(ctx, &info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);
#ifdef HAVE_LIBSCTP
	test_sockinit2_multiaddr_simple();
	test_sockinit2_multiaddr_several();
	test_sockinit2_multiaddr_mixed();
#endif /* ifdef HAVE_LIBSCTP */

	return EXIT_SUCCESS;
}
