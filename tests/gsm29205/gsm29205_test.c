/*
 * (C) 2018 by sysmocom - s.f.m.c. GmbH
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

#include <osmocom/gsm/gsm29205.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

static void test_gcr(void)
{
	static const uint8_t res[] = {
		0x03, /* .net_len */
		0x51, 0x52, 0x53, /* .net */
		0x02, /* .node length */
		0xde, 0xad, /* .node */
		0x05, /* length of Call. Ref. */
		0x41, 0x42, 0x43, 0x44, 0x45 /* .cr - Call. Ref. */
	};
	uint8_t len;
	struct msgb *msg;
	struct osmo_gcr_parsed p = {
		.net_len = 0,
		.net = { 0 },
		.node = 0x00,
		.cr = { 0 },
	};
	struct osmo_gcr_parsed g = {
		.net_len = 3,
		.net = { 0x51, 0x52, 0x53 },
		.node = 0xDEAD,
		.cr = { 0x41, 0x42, 0x43, 0x44, 0x45 }
	};
	int rc;

	msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "global call reference");
	if (!msg)
		return;

	len = osmo_enc_gcr(msg, &g);
	printf("Testing Global Call Reference encoder...\n\t%d bytes added: %s\n",
	       len, len == ARRAY_SIZE(res) ? "OK" : "FAIL");

	if (!msgb_eq_data_print(msg, res, ARRAY_SIZE(res)))
		abort();

	rc = osmo_dec_gcr(&p, msgb_data(msg), msgb_length(msg));
	if (rc < 0) {
		printf("decoding failed: %s [%s]\n", strerror(-rc), msgb_hexdump(msg));
		abort();
	}

	if (p.net_len != g.net_len) {
		printf("Network ID length parsed wrong: %u != %u\n", p.net_len, g.net_len);
		abort();
	}

	if (p.node != g.node) {
		printf("Node ID parsed wrong: 0x%X != 0x%X\n", p.node, g.node);
		abort();
	}

	if (memcmp(p.net, g.net, g.net_len) != 0) {
		printf("Network ID parsed wrong: %s\n", osmo_hexdump(p.net, p.net_len));
		abort();
	}

	if (memcmp(p.cr, g.cr, 5) != 0) {
		printf("Call ref. ID parsed wrong: %s\n", osmo_hexdump(p.cr, 5));
		abort();
	}

	printf("\tdecoded %d bytes: %s\n", rc, rc == len ? "OK" : "FAIL");
	msgb_free(msg);
}

int main(int argc, char **argv)
{
	osmo_init_logging2(talloc_named_const(NULL, 0, "gsm29205 test"), NULL);

	printf("Testing 3GPP TS 29.205 routines...\n");

	test_gcr();

	printf("Done.\n");

	return EXIT_SUCCESS;
}
