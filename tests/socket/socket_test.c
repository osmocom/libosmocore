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
#include <errno.h>

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

static int test_sockinit(void)
{
	int fd, rc;
	char *name;

	printf("Checking osmo_sock_init() with bind to a random local UDP port\n");
	fd = osmo_sock_init(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			    "0.0.0.0", 0, OSMO_SOCK_F_BIND);
	OSMO_ASSERT(fd >= 0);
	name = osmo_sock_get_name(ctx, fd);
	/* expect it to be not connected. We cannot match on INADDR_ANY,
	 * as apparently that won't work on FreeBSD if there's only one
	 * address (e.g. 127.0.0.1) assigned to the entire system, like
	 * the Osmocom FreeBSD build slaves */
	OSMO_ASSERT(!strncmp(name, "(r=NULL<->", 9));
	talloc_free(name);
	/* expect it to be blocking */
	rc = fcntl(fd, F_GETFL);
	OSMO_ASSERT(!(rc & O_NONBLOCK));
	close(fd);

	printf("Checking for OSMO_SOCK_F_NONBLOCK\n");
	fd = osmo_sock_init(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			    "0.0.0.0", 0, OSMO_SOCK_F_BIND|OSMO_SOCK_F_NONBLOCK);
	OSMO_ASSERT(fd >= 0);
	/* expect it to be blocking */
	rc = fcntl(fd, F_GETFL);
	OSMO_ASSERT(rc & O_NONBLOCK);
	close(fd);

	printf("Checking for invalid flags\n");
	fd = osmo_sock_init(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			    "0.0.0.0", 0, OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd < 0);

	return 0;
}

static int test_sockinit2(void)
{
	int fd, rc;
	char *name;

	printf("Checking osmo_sock_init2() with bind to a random local UDP port\n");
	fd = osmo_sock_init2(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			    "0.0.0.0", 0, NULL, 0, OSMO_SOCK_F_BIND);
	OSMO_ASSERT(fd >= 0);
	name = osmo_sock_get_name(ctx, fd);
	/* expect it to be not connected. We cannot match on INADDR_ANY,
	 * as apparently that won't work on FreeBSD if there's only one
	 * address (e.g. 127.0.0.1) assigned to the entire system, like
	 * the Osmocom FreeBSD build slaves */
	OSMO_ASSERT(!strncmp(name, "(r=NULL<->", 9));
	talloc_free(name);
	/* expect it to be blocking */
	rc = fcntl(fd, F_GETFL);
	OSMO_ASSERT(!(rc & O_NONBLOCK));
	close(fd);

	printf("Checking osmo_sock_init2() for OSMO_SOCK_F_NONBLOCK\n");
	fd = osmo_sock_init2(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			    "0.0.0.0", 0, NULL, 0, OSMO_SOCK_F_BIND|OSMO_SOCK_F_NONBLOCK);
	OSMO_ASSERT(fd >= 0);
	/* expect it to be blocking */
	rc = fcntl(fd, F_GETFL);
	OSMO_ASSERT(rc & O_NONBLOCK);
	close(fd);

	printf("Checking osmo_sock_init2() for invalid flags\n");
	fd = osmo_sock_init2(AF_INET, SOCK_DGRAM, IPPROTO_UDP, "0.0.0.0", 0, NULL, 0, 0);
	OSMO_ASSERT(fd < 0);

	printf("Checking osmo_sock_init2() for combined BIND + CONNECT\n");
	fd = osmo_sock_init2(AF_INET, SOCK_DGRAM, IPPROTO_UDP, "127.0.0.1", 0, "127.0.0.1", 53,
			     OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd >= 0);
	name = osmo_sock_get_name(ctx, fd);
#ifndef __FreeBSD__
	/* For some reason, on the jenkins.osmocom.org build slave with
	 * FreeBSD 10 inside a jail, it fails.  Works fine on laforge's
	 * FreeBSD 10 or 11 VM at home */
	OSMO_ASSERT(!strncmp(name, "(r=127.0.0.1:53<->l=127.0.0.1", 29));
#endif

	printf("Checking osmo_sock_init2(AF_UNSPEC) must fail on mixed IPv4 & IPv6\n");
	fd = osmo_sock_init2(AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, "127.0.0.1", 0, "::1", 53,
			     OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd < 0);

	printf("Checking osmo_sock_init2(AF_UNSPEC) must fail on mixed IPv6 & IPv4\n");
	fd = osmo_sock_init2(AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, "::1", 0, "127.0.0.1", 53,
			     OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd < 0);

	printf("Checking osmo_sock_init2(AF_UNSPEC) BIND + CONNECT on IPv4\n");
	fd = osmo_sock_init2(AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, "127.0.0.1", 0, "127.0.0.1", 53,
			     OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd >= 0);

	printf("Checking osmo_sock_init2(AF_UNSPEC) BIND + CONNECT on IPv6\n");
	fd = osmo_sock_init2(AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, "::1", 0, "::1", 53,
			     OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd >= 0);

	printf("Checking osmo_sock_init2(AF_UNSPEC) BIND on IPv4\n");
	fd = osmo_sock_init2(AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, "127.0.0.1", 0, NULL, 0,
			     OSMO_SOCK_F_BIND);
	OSMO_ASSERT(fd >= 0);

	talloc_free(name);

	return 0;
}

static int test_get_ip_and_port(void)
{
	int fd, rc;
	char ip[INET6_ADDRSTRLEN] = { };
	char port[6] = { };

	printf("Checking test_get_ip_and_port() for combined BIND + CONNECT on IPv4\n");
	fd = osmo_sock_init2(AF_INET, SOCK_DGRAM, IPPROTO_UDP, "127.0.0.1", 0, "127.0.0.1", 55,
			     OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);

	OSMO_ASSERT(fd >= 0);

	/* get the remote */
	rc = osmo_sock_get_ip_and_port(fd, ip, sizeof(ip), port, sizeof(port), false);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(strncmp(ip, "127.0.0.1", INET6_ADDRSTRLEN) == 0);
	OSMO_ASSERT(strncmp(port, "55", 6) == 0);

	printf("Checking test_get_ip_and_port() for combined BIND + CONNECT on IPv6\n");
	fd = osmo_sock_init2(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, "::1", 0, "::1", 55,
			     OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd >= 0);

	/* get the remote */
	rc = osmo_sock_get_ip_and_port(fd, ip, sizeof(ip), port, sizeof(port), false);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(strncmp(ip, "::1", INET6_ADDRSTRLEN) == 0);
	OSMO_ASSERT(strncmp(port, "55", 6) == 0);

	return 0;
}

static int test_sockinit_osa(void)
{
	int fd, rc;
	char *name;

	struct osmo_sockaddr localhost4 = {};
	struct osmo_sockaddr localhost6 = {};
	struct osmo_sockaddr localhost4_noport = {};
	struct osmo_sockaddr localhost6_noport = {};
	struct osmo_sockaddr any4 = {};
	struct osmo_sockaddr any6 = {};
	struct osmo_sockaddr invalid = {};

	localhost4.u.sin = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
		.sin_port = htons(42),
	};

	localhost6.u.sin6 = (struct sockaddr_in6){
		.sin6_family = AF_INET6,
		.sin6_port = htons(42),
	};
	inet_pton(AF_INET6, "::1", &localhost6.u.sin6.sin6_addr);

	localhost4_noport = localhost4;
	localhost4_noport.u.sin.sin_port = htons(0);
	localhost6_noport = localhost6;
	localhost6_noport.u.sin6.sin6_port = htons(0);

	any4.u.sin = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr("0.0.0.0"),
		.sin_port = htons(0),
	};
	any6.u.sin6 = (struct sockaddr_in6){
		.sin6_family = AF_INET6,
		.sin6_port = htons(0),
	};
	inet_pton(AF_INET6, "::", &any6.u.sin6.sin6_addr);

	invalid.u.sa.sa_family = AF_UNSPEC;

	printf("Checking osmo_sock_init_osa() with bind to a random local UDP port\n");
	fd = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP,
			    &any4, NULL, OSMO_SOCK_F_BIND);
	OSMO_ASSERT(fd >= 0);
	name = osmo_sock_get_name(ctx, fd);
	/* expect it to be not connected. We cannot match on INADDR_ANY,
	 * as apparently that won't work on FreeBSD if there's only one
	 * address (e.g. 137.0.0.1) assigned to the entire system, like
	 * the Osmocom FreeBSD build slaves */
	OSMO_ASSERT(!strncmp(name, "(r=NULL<->", 9));
	talloc_free(name);
	/* expect it to be blocking */
	rc = fcntl(fd, F_GETFL);
	OSMO_ASSERT(!(rc & O_NONBLOCK));
	close(fd);

	printf("Checking osmo_sock_init_osa() IPv4 for OSMO_SOCK_F_NONBLOCK\n");
	fd = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP,
			    &any4, NULL, OSMO_SOCK_F_BIND|OSMO_SOCK_F_NONBLOCK);
	OSMO_ASSERT(fd >= 0);
	/* expect it to be blocking */
	rc = fcntl(fd, F_GETFL);
	OSMO_ASSERT(rc & O_NONBLOCK);
	close(fd);

	printf("Checking osmo_sock_init_osa() IPv6 for OSMO_SOCK_F_NONBLOCK\n");
	fd = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP,
			    &any6, NULL, OSMO_SOCK_F_BIND|OSMO_SOCK_F_NONBLOCK);
	OSMO_ASSERT(fd >= 0);
	/* expect it to be blocking */
	rc = fcntl(fd, F_GETFL);
	OSMO_ASSERT(rc & O_NONBLOCK);
	close(fd);

	printf("Checking osmo_sock_init_osa() for invalid flags\n");
	fd = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP, &any4,  NULL, 0);
	OSMO_ASSERT(fd < 0);

	printf("Checking osmo_sock_init_osa() for combined BIND + CONNECT on IPv4\n");
	fd = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP, &localhost4_noport, &localhost4,
			     OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd >= 0);
	name = osmo_sock_get_name(ctx, fd);
#ifndef __FreeBSD__
	/* For some reason, on the jenkins.osmocom.org build slave with
	 * FreeBSD 10 inside a jail, it fails.  Works fine on laforge's
	 * FreeBSD 10 or 11 VM at home */
	OSMO_ASSERT(!strncmp(name, "(r=127.0.0.1:42<->l=127.0.0.1", 29));
#endif
	close(fd);

	printf("Checking osmo_sock_init_osa() for combined BIND + CONNECT on IPv6\n");
	fd = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP, &localhost6_noport, &localhost6,
			     OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd >= 0);
	name = osmo_sock_get_name(ctx, fd);
#ifndef __FreeBSD__
	/* For some reason, on the jenkins.osmocom.org build slave with
	 * FreeBSD 10 inside a jail, it fails.  Works fine on laforge's
	 * FreeBSD 10 or 11 VM at home */
	OSMO_ASSERT(!strncmp(name, "(r=::1:42<->l=::1", 17));
#endif
	close(fd);

	printf("Checking osmo_sock_init_osa() must fail on mixed IPv4 & IPv6\n");
	fd = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP, &localhost4_noport, &localhost6,
			     OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd < 0);

	printf("Checking osmo_sock_init_osa() must fail on mixed IPv6 & IPv4\n");
	fd = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP, &localhost6_noport, &localhost4,
			     OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd < 0);

	printf("Checking osmo_sock_init_osa() must fail on invalid osmo_sockaddr\n");
	fd = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP, &invalid, &localhost4,
			     OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT);
	OSMO_ASSERT(fd < 0);

	talloc_free(name);

	return 0;
}

static void test_osa_str(void)
{
	char buf[256];
	const char *result;
	struct osmo_sockaddr localhost4 = {};
	struct osmo_sockaddr localhost6 = {};

	localhost4.u.sin = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
		.sin_port = htons(42),
	};

	localhost6.u.sin6 = (struct sockaddr_in6){
		.sin6_family = AF_INET6,
		.sin6_port = htons(42),
	};
	inet_pton(AF_INET6, "::1", &localhost6.u.sin6.sin6_addr);

	/* test a too short str */
	memset(&buf[0], 0, sizeof(buf));
	result = osmo_sockaddr_to_str_buf(buf, 1, &localhost4);
	printf("Checking osmo_sockaddr_to_str_buf to small IPv4\n");
	OSMO_ASSERT(result == NULL);

	memset(&buf[0], 0, sizeof(buf));
	result = osmo_sockaddr_to_str_buf(buf, sizeof(buf), &localhost4);
	printf("Checking osmo_sockaddr_to_str_buf IPv4\n");
	OSMO_ASSERT(!strncmp("127.0.0.1:42", result, sizeof(buf)));

	memset(&buf[0], 0, sizeof(buf));
	result = osmo_sockaddr_to_str_buf(buf, 256, &localhost6);
	printf("Checking osmo_sockaddr_to_str_buf IPv6\n");
	OSMO_ASSERT(!strncmp("[::1]:42", result, sizeof(buf)));

	memset(&buf[0], 0, sizeof(buf));
	printf("Checking osmo_sockaddr_to_str_buf too short IPv6\n");
	result = osmo_sockaddr_to_str_buf(buf, 8, &localhost6);
	OSMO_ASSERT(result == NULL);
	osmo_sockaddr_to_str_buf2(buf, 8, &localhost6);
	OSMO_ASSERT(!strncmp("[::1]:4", buf, sizeof(buf)));

	memset(&buf[0], 0, sizeof(buf));
	result = osmo_sockaddr_to_str_buf(buf, 5, &localhost6);
	printf("Checking osmo_sockaddr_to_str_buf too short IPv6\n");
	OSMO_ASSERT(result == NULL);

	localhost6.u.sin6.sin6_port = 0;
	memset(&buf[0], 0, sizeof(buf));
	result = osmo_sockaddr_to_str_buf(buf, 5, &localhost6);
	printf("Checking osmo_sockaddr_to_str_buf only 5 bytes IPv6\n");
	OSMO_ASSERT(result == NULL);

	inet_pton(AF_INET6, "::", &localhost6.u.sin6.sin6_addr);
	memset(&buf[0], 0, sizeof(buf));
	result = osmo_sockaddr_to_str_buf(buf, 5, &localhost6);
	printf("Checking osmo_sockaddr_to_str_buf only 5 bytes IPv6\n");
	OSMO_ASSERT(!strncmp("[::]", result, sizeof(buf)));

	inet_pton(AF_INET6, "2003:1234:5678:90ab:cdef:1234:4321:4321", &localhost6.u.sin6.sin6_addr);
	memset(&buf[0], 0, sizeof(buf));
	result = osmo_sockaddr_to_str_buf(buf, sizeof(buf), &localhost6);
	printf("Checking osmo_sockaddr_to_str_buf long IPv6\n");
	OSMO_ASSERT(!strncmp("[2003:1234:5678:90ab:cdef:1234:4321:4321]", result, sizeof(buf)));

	localhost6.u.sin6.sin6_port = htons(23420);
	memset(&buf[0], 0, sizeof(buf));
	result = osmo_sockaddr_to_str_buf(buf, sizeof(buf), &localhost6);
	printf("Checking osmo_sockaddr_to_str_buf long IPv6 port\n");
	OSMO_ASSERT(!strncmp("[2003:1234:5678:90ab:cdef:1234:4321:4321]:23420", result, sizeof(buf)));

	result = osmo_sockaddr_to_str(&localhost6);
	printf("Checking osmo_sockaddr_to_str_buf long IPv6 port static buffer\n");
	OSMO_ASSERT(!strncmp("[2003:1234:5678:90ab:cdef:1234:4321:4321]:23420", result, sizeof(buf)));
}

static void test_osa_netmask_prefixlen(void)
{
	struct osmo_sockaddr ipv4;
	struct osmo_sockaddr ipv6;
	int rc;

	ipv4.u.sin = (struct sockaddr_in){
		.sin_family = AF_INET,
	};

	ipv4.u.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
	rc = osmo_sockaddr_netmask_to_prefixlen(&ipv4);
	OSMO_ASSERT(rc == 0);

	ipv4.u.sin.sin_addr.s_addr = inet_addr("255.0.0.0");
	rc = osmo_sockaddr_netmask_to_prefixlen(&ipv4);
	OSMO_ASSERT(rc == 8);

	ipv4.u.sin.sin_addr.s_addr = inet_addr("255.255.0.0");
	rc = osmo_sockaddr_netmask_to_prefixlen(&ipv4);
	OSMO_ASSERT(rc == 16);

	ipv4.u.sin.sin_addr.s_addr = inet_addr("255.255.255.0");
	rc = osmo_sockaddr_netmask_to_prefixlen(&ipv4);
	OSMO_ASSERT(rc == 24);

	ipv4.u.sin.sin_addr.s_addr = inet_addr("255.255.255.255");
	rc = osmo_sockaddr_netmask_to_prefixlen(&ipv4);
	OSMO_ASSERT(rc == 32);

	ipv4.u.sin.sin_addr.s_addr = inet_addr("0.255.0.0");
	rc = osmo_sockaddr_netmask_to_prefixlen(&ipv4);
	/* FIXME: This shows the implementation is not that robust checking validity of input netmask: */
	OSMO_ASSERT(rc == 8);

	ipv6.u.sin6 = (struct sockaddr_in6){
		.sin6_family = AF_INET6,
	};

	inet_pton(AF_INET6, "fe::", &ipv6.u.sin6.sin6_addr);
	rc = osmo_sockaddr_netmask_to_prefixlen(&ipv6);
	OSMO_ASSERT(rc == 7);

	inet_pton(AF_INET6, "ff::", &ipv6.u.sin6.sin6_addr);
	rc = osmo_sockaddr_netmask_to_prefixlen(&ipv6);
	OSMO_ASSERT(rc == 8);

	inet_pton(AF_INET6, "ff:ff::", &ipv6.u.sin6.sin6_addr);
	rc = osmo_sockaddr_netmask_to_prefixlen(&ipv6);
	OSMO_ASSERT(rc == 16);

	inet_pton(AF_INET6, "ff:ff::ff", &ipv6.u.sin6.sin6_addr);
	rc = osmo_sockaddr_netmask_to_prefixlen(&ipv6);
	/* FIXME: This shows the implementation is not that robust checking validity of input netmask: */
	OSMO_ASSERT(rc == 24);
}

const struct log_info_cat default_categories[] = {
};

static struct log_info info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char *argv[])
{
	ctx = talloc_named_const(NULL, 0, "socket_test");
	osmo_init_logging2(ctx, &info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);

	test_sockinit();
	test_sockinit2();
	test_get_ip_and_port();
	test_sockinit_osa();
	test_osa_str();
	test_osa_netmask_prefixlen();

	return EXIT_SUCCESS;
}
