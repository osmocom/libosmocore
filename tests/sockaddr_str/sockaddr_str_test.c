/* tests for osmo_sockaddr_str API of libmsomcore */
/*
 * (C) 2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: neels@hofmeyr.de
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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>
#include <netinet/in.h>

struct osmo_sockaddr_str oip_data[] = {
	{ .af = AF_INET, .ip = "1.2.3.4", .port = 5 },
	{ .af = AF_INET, .ip = "0.0.0.0", .port = 0 },
	{ .af = AF_INET, .ip = "255.255.255.255", .port = 65535 },
	{ .af = AF_INET, .ip = "0.0.0.256", .port = 1 },
	{ .af = AF_INET, .ip = "not an ip address", .port = 1 },
	{ .af = AF_INET6, .ip = "1:2:3::4", .port = 5 },
	{ .af = AF_INET6, .ip = "::", .port = 0 },
	{ .af = AF_INET6, .ip = "::1", .port = 0 },
	{ .af = AF_INET6, .ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", .port = 65535 },
	{ .af = AF_INET6, .ip = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", .port = 65535 },
	{ .af = AF_INET6, .ip = "::fffff", .port = 1 },
	{ .af = AF_INET6, .ip = "not an ip address", .port = 1 },

	{ .af = AF_INET6, .ip = "1.2.3.4", .port = 5 },
	{ .af = AF_INET, .ip = "1:2:3::4", .port = 5 },
	{ .af = AF_UNSPEC, .ip = "1.2.3.4", .port = 5 },
	{ .af = AF_INET, .ip = "", .port = 5 },
	{ .af = AF_INET6, .ip = "", .port = 5 },
	{ .af = AF_INET, .ip = "1.2.3.4", .port = 0 },
	{ .af = AF_INET, .ip = "1.2.3:4:5", .port = 0 },
	{ .af = AF_INET6, .ip = "::1:10.9.8.7", .port = 1 },
	{ .af = AF_INET, .ip = "0.0.0.0", .port = 5 },
	{ .af = AF_INET6, .ip = "::", .port = 5 },
	{ .af = AF_INET6, .ip = "0::", .port = 5 },
};

const char *af_name(int af)
{
	switch (af) {
	case AF_INET:
		return "AF_INET";
	case AF_INET6:
		return "AF_INET6";
	case AF_UNSPEC:
		return "AF_UNSPEC";
	default:
		return "?";
	}
}

static const struct value_string err_names[] = {
	{ -EINVAL, "-EINVAL" },
	{}
};

static inline const char *err_name(int err)
{ return get_value_string(err_names, err); }

static inline const char *rc_name(int rc)
{
	if (!rc)
		return "rc == 0";
	if (rc < 0)
		return "rc < 0";
	return "rc > 0";
}

void dump_oip(const struct osmo_sockaddr_str *oip)
{
	printf("{ .af = %s, .ip = %s, .port = %u }\n", af_name(oip->af), osmo_quote_str(oip->ip, -1), oip->port);
}

void sockaddr_str_test_conversions()
{
	int i;
	char buf[1024];

#define hexdump(what) \
	osmo_hexdump_buf(buf, sizeof(buf), (void*)(&what), sizeof(what), "", false)

	for (i = 0; i < ARRAY_SIZE(oip_data); i++) {
		struct osmo_sockaddr_str *x = &oip_data[i];
		int rc;
		printf("\n\n");
		dump_oip(x);

		printf("  OSMO_SOCKADDR_STR_FMT: '" OSMO_SOCKADDR_STR_FMT "'\n",
		       OSMO_SOCKADDR_STR_FMT_ARGS(x));
		printf("  osmo_sockaddr_str_is_set() = %s\n", osmo_sockaddr_str_is_set(x) ? "true" : "false");
		printf("  osmo_sockaddr_str_is_nonzero() = %s\n", osmo_sockaddr_str_is_nonzero(x) ? "true" : "false");

		{
			struct in_addr a = {};

			rc = osmo_sockaddr_str_to_in_addr(x, &a);
			printf("  osmo_sockaddr_str_to_in_addr() %s in_addr=%s\n", rc_name(rc), hexdump(a));

			if (rc == 0) {
				struct osmo_sockaddr_str back;
				rc = osmo_sockaddr_str_from_in_addr(&back, &a, x->port);
				printf("   -> osmo_sockaddr_str_from_in_addr() %s ", rc_name(rc));
				dump_oip(&back);
				if (memcmp(x, &back, sizeof(back)))
					printf("      DIFFERS!\n");
			}
		}

		{
			struct in6_addr a = {};

			rc = osmo_sockaddr_str_to_in6_addr(x, &a);
			printf("  osmo_sockaddr_str_to_in6_addr() %s in6_addr=%s\n", rc_name(rc), hexdump(a));

			if (rc == 0) {
				struct osmo_sockaddr_str back;
				rc = osmo_sockaddr_str_from_in6_addr(&back, &a, x->port);
				printf("   -> osmo_sockaddr_str_from_in6_addr() %s ", rc_name(rc));
				dump_oip(&back);
				if (memcmp(x, &back, sizeof(back)))
					printf("      DIFFERS!\n");
			}
		}

		{
			uint32_t a = 0;

			rc = osmo_sockaddr_str_to_32(x, &a);
			printf("  osmo_sockaddr_str_to_32() %s uint8_t[4]=[ %s]\n", rc_name(rc),
			       osmo_hexdump((void*)&a, sizeof(a)));

			if (rc == 0) {
				struct osmo_sockaddr_str back;
				rc = osmo_sockaddr_str_from_32(&back, a, x->port);
				printf("   -> osmo_sockaddr_str_from_32() %s ", rc_name(rc));
				dump_oip(&back);
				if (memcmp(x, &back, sizeof(back)))
					printf("      DIFFERS!\n");
			}
		}

		{
			uint32_t a = 0;

			rc = osmo_sockaddr_str_to_32h(x, &a);
			printf("  osmo_sockaddr_str_to_32h() %s uint8_t[4]=[ %s]\n", rc_name(rc),
			       osmo_hexdump((void*)&a, sizeof(a)));

			if (rc == 0) {
				struct osmo_sockaddr_str back;
				rc = osmo_sockaddr_str_from_32h(&back, a, x->port);
				printf("   -> osmo_sockaddr_str_from_32h() %s ", rc_name(rc));
				dump_oip(&back);
				if (memcmp(x, &back, sizeof(back)))
					printf("      DIFFERS!\n");
			}
		}

		{
			struct sockaddr_in a = {};

			rc = osmo_sockaddr_str_to_sockaddr_in(x, &a);
			printf("  osmo_sockaddr_str_to_sockaddr_in() %s sockaddr_in=%s\n", rc_name(rc), hexdump(a));

			if (rc == 0) {
				struct osmo_sockaddr_str back;
				rc = osmo_sockaddr_str_from_sockaddr_in(&back, &a);
				printf("   -> osmo_sockaddr_str_from_sockaddr_in() %s ", rc_name(rc));
				dump_oip(&back);
				if (memcmp(x, &back, sizeof(back)))
					printf("      DIFFERS!\n");
			}
		}

		{
			struct sockaddr_in6 a = {};

			rc = osmo_sockaddr_str_to_sockaddr_in6(x, &a);
			printf("  osmo_sockaddr_str_to_sockaddr_in6() %s sockaddr_in6=%s\n", rc_name(rc), hexdump(a));

			if (rc == 0) {
				struct osmo_sockaddr_str back;
				rc = osmo_sockaddr_str_from_sockaddr_in6(&back, &a);
				printf("   -> osmo_sockaddr_str_from_sockaddr_in6() %s ", rc_name(rc));
				dump_oip(&back);
				if (memcmp(x, &back, sizeof(back)))
					printf("      DIFFERS!\n");
			}
		}

		{
			struct sockaddr_storage a = {};

			rc = osmo_sockaddr_str_to_sockaddr(x, &a);
			printf("  osmo_sockaddr_str_to_sockaddr() %s sockaddr_storage=%s\n", rc_name(rc), hexdump(a));

			if (rc == 0) {
				struct osmo_sockaddr_str back;
				rc = osmo_sockaddr_str_from_sockaddr(&back, &a);
				printf("   -> osmo_sockaddr_str_from_sockaddr() %s ", rc_name(rc));
				dump_oip(&back);
				if (memcmp(x, &back, sizeof(back)))
					printf("      DIFFERS!\n");
			}
		}

		{
			struct osmo_sockaddr_str from_str;
			rc = osmo_sockaddr_str_from_str(&from_str, x->ip, x->port);
			printf("  osmo_sockaddr_str_from_str() %s ", rc_name(rc));
			dump_oip(&from_str);
			if (rc == 0 && memcmp(x, &from_str, sizeof(from_str)))
				printf("      DIFFERS!\n");
		}
	}

}

static void test_osmo_sockaddr_str_cmp()
{
	int i;
	printf("\n\n%s\n", __func__);
	for (i = 0; i < ARRAY_SIZE(oip_data); i++) {
		/* use a copy to not hit the pointer comparison in osmo_sockaddr_str_cmp(). */
		struct osmo_sockaddr_str _a = oip_data[i];
		struct osmo_sockaddr_str *a = &_a;
		int j;
		printf("[%2d]\n", i);

		for (j = 0; j < ARRAY_SIZE(oip_data); j++) {
			struct osmo_sockaddr_str *b = &oip_data[j];
			int ip_rc = osmo_sockaddr_str_cmp(a, b);
			printf("  osmo_sockaddr_str_cmp(): " OSMO_SOCKADDR_STR_FMT "%s %s " OSMO_SOCKADDR_STR_FMT "%s\n",
			       OSMO_SOCKADDR_STR_FMT_ARGS(a),
			       osmo_sockaddr_str_is_nonzero(a) ? "" : "(zero)",
			       ip_rc < 0? "<" : (ip_rc == 0 ? "==" : ">" ),
			       OSMO_SOCKADDR_STR_FMT_ARGS(b),
			       osmo_sockaddr_str_is_nonzero(b) ? "" : "(zero)");
		}
	}
}

static int test_sockaddr_strs_dump(void *ctx, struct osmo_sockaddr_str *xdata, size_t count)
{
	char buf[OSMO_SOCK_NAME_MAXLEN * OSMO_SOCK_MAX_ADDRS * 2];
	struct osmo_sockaddr_str *sa_strs[OSMO_SOCK_MAX_ADDRS];
	int i, j, rc;

	for (i = 0, j = 0; j < count && i < OSMO_SOCK_MAX_ADDRS; j++) {//ARRAY_SIZE(oip_data)
		sa_strs[i] = talloc_zero(ctx, struct osmo_sockaddr_str);
		struct sockaddr_storage tmp;
		if (osmo_sockaddr_str_to_sockaddr(&xdata[j], &tmp) == 0) {//&oip_data[j]
			rc = osmo_sockaddr_str_from_sockaddr(sa_strs[i], &tmp);
			if (rc < 0) {
				printf("osmo_sockaddr_str_from_sockaddr(%d) failed on ", i);
				dump_oip(&xdata[j]);//&oip_data[j]
				return rc;
			}
			i++;
		}
	}
	rc = osmo_sockaddr_strs_to_str(buf, sizeof(buf), (const struct osmo_sockaddr_str **)sa_strs, i);
	printf("\nTest data [%d == %ld]: %s\n", rc, strlen(buf), buf);
	return rc;
}

const struct log_info_cat default_categories[] = {
};

static struct log_info info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	int rc;
	void *ctx = talloc_named_const(NULL, 0, "sockaddr_str__test");
	osmo_init_logging2(ctx, &info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);

	sockaddr_str_test_conversions();
	test_osmo_sockaddr_str_cmp();

	rc = test_sockaddr_strs_dump(ctx, oip_data, ARRAY_SIZE(oip_data));
	if (rc < 0)
		return EXIT_FAILURE;

	rc = test_sockaddr_strs_dump(ctx, oip_data, 1);
	if (rc < 0)
		return EXIT_FAILURE;

	rc = test_sockaddr_strs_dump(ctx, oip_data, 0);
	if (rc < 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
