/*
 * (C) 2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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
#include <strings.h>
#include <string.h>

#include <osmocom/gsm/gsm23236.h>
#include <osmocom/core/utils.h>

void *ctx;
bool ok = true;

void bitdump(uint8_t count, uint32_t val)
{
	uint32_t bit;
	if (count < 1)
		return;
	for (bit = ((uint32_t)1) << (count - 1); bit; bit >>= 1)
		printf("%c", (val & bit)? '1' : '0');
}

struct nri_v_get_set_test {
	uint32_t tmsi;
	uint8_t nri_bitlen;
	int16_t expect_get_nri;
	int expect_get_rc;
	int16_t set_nri_v;
	uint32_t expect_tmsi;
	int expect_set_rc;
};

struct nri_v_get_set_test nri_v_get_set_tests[] = {
	{
		.tmsi = 0,
		.nri_bitlen = 10,
		.expect_get_nri = 0,
		.set_nri_v = 0,
		.expect_tmsi = 0,
	},
	{
		.tmsi = 0,
		.nri_bitlen = 10,
		.expect_get_nri = 0,
		.set_nri_v = 0x7fff,
		.expect_tmsi = 0x00ffc000
	},
	{
		.tmsi = 0xffffffff,
		.nri_bitlen = 10,
		.expect_get_nri = 0x3ff,
		.set_nri_v = 0,
		.expect_tmsi = 0xff003fff
	},
	{
		.tmsi = 0xffffffff,
		.nri_bitlen = 10,
		.expect_get_nri = 0x3ff,
		.set_nri_v = 0x7fff,
		.expect_tmsi = 0xffffffff
	},
	{
		.tmsi = 0,
		.nri_bitlen = 5,
		.expect_get_nri = 0,
		.set_nri_v = 0,
		.expect_tmsi = 0,
	},
	{
		.tmsi = 0,
		.nri_bitlen = 5,
		.expect_get_nri = 0,
		.set_nri_v = 0x7fff,
		.expect_tmsi = 0x00f80000
	},
	{
		.tmsi = 0xffffffff,
		.nri_bitlen = 5,
		.expect_get_nri = 0x1f,
		.set_nri_v = 0,
		.expect_tmsi = 0xff07ffff
	},
	{
		.tmsi = 0xffffffff,
		.nri_bitlen = 5,
		.expect_get_nri = 0x1f,
		.set_nri_v = 0x7fff,
		.expect_tmsi = 0xffffffff
	},
	{
		.tmsi = 0x01234567,
		.nri_bitlen = 8,
		.expect_get_nri = 0x23,
		.set_nri_v = 0x42,
		.expect_tmsi = 0x01424567
	},
	{
		.tmsi = 0x01234567,
		.nri_bitlen = 15,
		.expect_get_nri = 0x2345 >> 1,
		.set_nri_v = 0x7fff,
		.expect_tmsi = 0x01ffff67
	},
	{
		.tmsi = 0x01234567,
		.nri_bitlen = 16,
		.expect_get_rc = -1,
		.expect_get_nri = -1,
		.set_nri_v = 0x7fff,
		.expect_set_rc = -1,
		.expect_tmsi = 0x01234567,
	},
	{
		.tmsi = 0x01234567,
		.nri_bitlen = 0,
		.expect_get_rc = -1,
		.expect_get_nri = -1,
		.set_nri_v = 0x7fff,
		.expect_set_rc = -1,
		.expect_tmsi = 0x01234567,
	},
};

void test_nri_v_get_set(void)
{
	struct nri_v_get_set_test *t;

	for (t = nri_v_get_set_tests; t < &nri_v_get_set_tests[ARRAY_SIZE(nri_v_get_set_tests)]; t++) {
		int16_t nri_v = 0;
		uint32_t tmsi2;
		int rc;

		rc = osmo_tmsi_nri_v_get(&nri_v, t->tmsi, t->nri_bitlen);
		printf("\nosmo_tmsi_nri_v_get(0x%08x, %u) -> nri_v=0x%x rc=%d\n", t->tmsi, t->nri_bitlen, nri_v, rc);
		if (!rc) {
			printf("........|NRI->..................\n");
			bitdump(32, t->tmsi);
			printf(" tmsi  nri_bitlen=%u\n", t->nri_bitlen);
			printf("        ");
			bitdump(t->nri_bitlen, nri_v);
			printf(" = 0x%x", nri_v);
		}
		if (nri_v == t->expect_get_nri && rc == t->expect_get_rc) {
			printf(" ok\n");
		} else {
			printf(" ERROR: expected nri_v=0x%x rc=%d\n", t->expect_get_nri, t->expect_get_rc);
			ok = false;
		}

		tmsi2 = t->tmsi;
		rc = osmo_tmsi_nri_v_set(&tmsi2, t->set_nri_v, t->nri_bitlen);
		printf("osmo_tmsi_nri_v_set(0x%08x, 0x%x, %u) -> tmsi=0x%08x rc=%d\n", t->tmsi, t->set_nri_v, t->nri_bitlen,
		       tmsi2, rc);
		if (!rc) {
			printf("        ");
			bitdump(t->nri_bitlen, t->set_nri_v);
			printf("\n");
			bitdump(32, tmsi2);
		}
		if (tmsi2 == t->expect_tmsi && rc == t->expect_set_rc) {
			printf(" ok\n");
		} else {
			printf(" ERROR: expected tmsi=0x%08x rc=%d\n", t->expect_tmsi, t->expect_set_rc);
			ok = false;
		}
	}
}

struct nri_validate_tc {
	int16_t nri;
	uint8_t nri_bitlen;
	int expect_rc;
};

struct nri_validate_tc nri_validate_tests[] = {
	{ .nri = INT16_MIN, .nri_bitlen = 10, .expect_rc = -1 },
	{ .nri = -23, .nri_bitlen = 10, .expect_rc = -1 },
	{ .nri = -1, .nri_bitlen = 10, .expect_rc = -1 },
	{ .nri = 0, .nri_bitlen = 10, .expect_rc = 0 },
	{ .nri = (1 << 10) - 1, .nri_bitlen = 10, .expect_rc = 0 },
	{ .nri = (1 << 10), .nri_bitlen = 10, .expect_rc = 1 },
	{ .nri = INT16_MAX, .nri_bitlen = 10, .expect_rc = 1 },

	{ .nri = INT16_MIN, .nri_bitlen = 5, .expect_rc = -1 },
	{ .nri = -23, .nri_bitlen = 5, .expect_rc = -1 },
	{ .nri = -1, .nri_bitlen = 5, .expect_rc = -1 },
	{ .nri = 0, .nri_bitlen = 5, .expect_rc = 0 },
	{ .nri = (1 << 5) - 1, .nri_bitlen = 5, .expect_rc = 0 },
	{ .nri = (1 << 5), .nri_bitlen = 5, .expect_rc = 1 },
	{ .nri = INT16_MAX, .nri_bitlen = 5, .expect_rc = 1 },

	{ .nri = INT16_MIN, .nri_bitlen = 1, .expect_rc = -1 },
	{ .nri = -23, .nri_bitlen = 1, .expect_rc = -1 },
	{ .nri = -1, .nri_bitlen = 1, .expect_rc = -1 },
	{ .nri = 0, .nri_bitlen = 1, .expect_rc = 0 },
	{ .nri = 1, .nri_bitlen = 1, .expect_rc = 0 },
	{ .nri = 2, .nri_bitlen = 1, .expect_rc = 1 },
	{ .nri = INT16_MAX, .nri_bitlen = 1, .expect_rc = 1 },

	{ .nri = INT16_MIN, .nri_bitlen = 0, .expect_rc = -1 },
	{ .nri = -23, .nri_bitlen = 0, .expect_rc = -1 },
	{ .nri = -1, .nri_bitlen = 0, .expect_rc = -1 },
	{ .nri = 0, .nri_bitlen = 0, .expect_rc = 1 },
	{ .nri = 1, .nri_bitlen = 0, .expect_rc = 1 },
	{ .nri = INT16_MAX, .nri_bitlen = 0, .expect_rc = 1 },
};

void test_nri_validate(void)
{
	struct nri_validate_tc *t;
	printf("\n%s()\n", __func__);
	for (t = nri_validate_tests; (t - nri_validate_tests) < ARRAY_SIZE(nri_validate_tests); t++) {
		int rc = osmo_nri_v_validate(t->nri, t->nri_bitlen);
		printf("osmo_nri_v_validate(%d, %u) = %d ", t->nri, t->nri_bitlen, rc);
		if (rc == t->expect_rc) {
			printf("ok\n");
		} else {
			printf("ERROR, expected rc = %d\n", t->expect_rc);
			ok = false;
		}
	}
}

struct nri_range_validate_tc {
	struct osmo_nri_range range;
	uint8_t nri_bitlen;
	int expect_rc;
};

struct nri_range_validate_tc nri_range_validate_tests[] = {
	{ .range = { .first = INT16_MIN, .last = INT16_MIN }, .nri_bitlen = 10, .expect_rc = -1 },
	{ .range = { .first = -23, .last = -23 }, .nri_bitlen = 10, .expect_rc = -1 },
	{ .range = { .first = -1, .last = -1 }, .nri_bitlen = 10, .expect_rc = -1 },
	{ .range = { .first = 0, .last = 0 }, .nri_bitlen = 10, .expect_rc = 0 },
	{ .range = { .first = (1 << 10) - 1, .last = (1 << 10) - 1 }, .nri_bitlen = 10, .expect_rc = 0 },
	{ .range = { .first = (1 << 10), .last = (1 << 10) }, .nri_bitlen = 10, .expect_rc = 1 },
	{ .range = { .first = INT16_MAX, .last = INT16_MAX }, .nri_bitlen = 10, .expect_rc = 1 },

	{ .range = { .first = INT16_MIN, .last = INT16_MIN }, .nri_bitlen = 5, .expect_rc = -1 },
	{ .range = { .first = -23, .last = -23 }, .nri_bitlen = 5, .expect_rc = -1 },
	{ .range = { .first = -1, .last = -1 }, .nri_bitlen = 5, .expect_rc = -1 },
	{ .range = { .first = 0, .last = 0 }, .nri_bitlen = 5, .expect_rc = 0 },
	{ .range = { .first = (1 << 5) - 1, .last = (1 << 5) - 1 }, .nri_bitlen = 5, .expect_rc = 0 },
	{ .range = { .first = (1 << 5), .last = (1 << 5) }, .nri_bitlen = 5, .expect_rc = 1 },
	{ .range = { .first = INT16_MAX, .last = INT16_MAX }, .nri_bitlen = 5, .expect_rc = 1 },

	{ .range = { .first = INT16_MIN, .last = INT16_MIN }, .nri_bitlen = 1, .expect_rc = -1 },
	{ .range = { .first = -23, .last = -23 }, .nri_bitlen = 1, .expect_rc = -1 },
	{ .range = { .first = -1, .last = -1 }, .nri_bitlen = 1, .expect_rc = -1 },
	{ .range = { .first = 0, .last = 0 }, .nri_bitlen = 1, .expect_rc = 0 },
	{ .range = { .first = 1, .last = 1 }, .nri_bitlen = 1, .expect_rc = 0 },
	{ .range = { .first = 2, .last = 2 }, .nri_bitlen = 1, .expect_rc = 1 },
	{ .range = { .first = INT16_MAX, .last = INT16_MAX }, .nri_bitlen = 1, .expect_rc = 1 },

	{ .range = { .first = INT16_MIN, .last = INT16_MIN }, .nri_bitlen = 0, .expect_rc = -1 },
	{ .range = { .first = -23, .last = -23 }, .nri_bitlen = 0, .expect_rc = -1 },
	{ .range = { .first = -1, .last = -1 }, .nri_bitlen = 0, .expect_rc = -1 },
	{ .range = { .first = 0, .last = 0 }, .nri_bitlen = 0, .expect_rc = 1 },
	{ .range = { .first = 1, .last = 1 }, .nri_bitlen = 0, .expect_rc = 1 },
	{ .range = { .first = INT16_MAX, .last = INT16_MAX }, .nri_bitlen = 0, .expect_rc = 1 },


	{ .range = { .first = 0, .last = INT16_MIN }, .nri_bitlen = 10, .expect_rc = -2 },
	{ .range = { .first = 0, .last = -23 }, .nri_bitlen = 10, .expect_rc = -2 },
	{ .range = { .first = 0, .last = -1 }, .nri_bitlen = 10, .expect_rc = -2 },
	{ .range = { .first = 0, .last = 0 }, .nri_bitlen = 10, .expect_rc = 0 },
	{ .range = { .first = 0, .last = (1 << 10) - 1 }, .nri_bitlen = 10, .expect_rc = 0 },
	{ .range = { .first = 0, .last = (1 << 10) }, .nri_bitlen = 10, .expect_rc = 2 },
	{ .range = { .first = 0, .last = INT16_MAX }, .nri_bitlen = 10, .expect_rc = 2 },

	{ .range = { .first = 0, .last = INT16_MIN }, .nri_bitlen = 5, .expect_rc = -2 },
	{ .range = { .first = 0, .last = -23 }, .nri_bitlen = 5, .expect_rc = -2 },
	{ .range = { .first = 0, .last = -1 }, .nri_bitlen = 5, .expect_rc = -2 },
	{ .range = { .first = 0, .last = 0 }, .nri_bitlen = 5, .expect_rc = 0 },
	{ .range = { .first = 0, .last = (1 << 5) - 1 }, .nri_bitlen = 5, .expect_rc = 0 },
	{ .range = { .first = 0, .last = (1 << 5) }, .nri_bitlen = 5, .expect_rc = 2 },
	{ .range = { .first = 0, .last = INT16_MAX }, .nri_bitlen = 5, .expect_rc = 2 },

	{ .range = { .first = 0, .last = INT16_MIN }, .nri_bitlen = 1, .expect_rc = -2 },
	{ .range = { .first = 0, .last = -23 }, .nri_bitlen = 1, .expect_rc = -2 },
	{ .range = { .first = 0, .last = -1 }, .nri_bitlen = 1, .expect_rc = -2 },
	{ .range = { .first = 0, .last = 0 }, .nri_bitlen = 1, .expect_rc = 0 },
	{ .range = { .first = 0, .last = 1 }, .nri_bitlen = 1, .expect_rc = 0 },
	{ .range = { .first = 0, .last = 2 }, .nri_bitlen = 1, .expect_rc = 2 },
	{ .range = { .first = 0, .last = INT16_MAX }, .nri_bitlen = 1, .expect_rc = 2 },

	{ .range = { .first = 0, .last = INT16_MIN }, .nri_bitlen = 0, .expect_rc = 1 },
	{ .range = { .first = 0, .last = -23 }, .nri_bitlen = 0, .expect_rc = 1 },
	{ .range = { .first = 0, .last = -1 }, .nri_bitlen = 0, .expect_rc = 1 },
	{ .range = { .first = 0, .last = 0 }, .nri_bitlen = 0, .expect_rc = 1 },
	{ .range = { .first = 0, .last = 1 }, .nri_bitlen = 0, .expect_rc = 1 },
	{ .range = { .first = 0, .last = INT16_MAX }, .nri_bitlen = 0, .expect_rc = 1 },


	{ .range = { .first = 0, .last = 0 }, .nri_bitlen = 10, .expect_rc = 0 },
	{ .range = { .first = 1, .last = 0 }, .nri_bitlen = 10, .expect_rc = -3 },
	{ .range = { .first = (1 << 10) - 1, .last = (1 << 10) - 1 }, .nri_bitlen = 10, .expect_rc = 0 },
	{ .range = { .first = (1 << 10) - 1, .last = (1 << 10) - 2 }, .nri_bitlen = 10, .expect_rc = -3 },
	{ .range = { .first = (1 << 10) - 1, .last = 0 }, .nri_bitlen = 10, .expect_rc = -3 },

	{ .range = { .first = 0, .last = 0 }, .nri_bitlen = 5, .expect_rc = 0 },
	{ .range = { .first = 1, .last = 0 }, .nri_bitlen = 5, .expect_rc = -3 },
	{ .range = { .first = (1 << 5) - 1, .last = (1 << 5) - 1 }, .nri_bitlen = 5, .expect_rc = 0 },
	{ .range = { .first = (1 << 5) - 1, .last = (1 << 5) - 2 }, .nri_bitlen = 5, .expect_rc = -3 },
	{ .range = { .first = (1 << 5) - 1, .last = 0 }, .nri_bitlen = 5, .expect_rc = -3 },

	{ .range = { .first = 0, .last = 0 }, .nri_bitlen = 1, .expect_rc = 0 },
	{ .range = { .first = 1, .last = 1 }, .nri_bitlen = 1, .expect_rc = 0 },
	{ .range = { .first = 1, .last = 0 }, .nri_bitlen = 1, .expect_rc = -3 },

};

void test_nri_range_validate(void)
{
	struct nri_range_validate_tc *t;
	printf("\n%s()\n", __func__);
	for (t = nri_range_validate_tests; (t - nri_range_validate_tests) < ARRAY_SIZE(nri_range_validate_tests); t++) {
		int rc = osmo_nri_range_validate(&t->range, t->nri_bitlen);
		printf("osmo_nri_range_validate({%d,%d}, %u) = %d ", t->range.first, t->range.last, t->nri_bitlen, rc);
		if (rc == t->expect_rc) {
			printf("ok\n");
		} else {
			printf("ERROR, expected rc = %d\n", t->expect_rc);
			ok = false;
		}
	}
}

void dump_list(const struct osmo_nri_ranges *nri_ranges)
{
	struct osmo_nri_range *r;
	printf("nri_ranges = {\n");
	llist_for_each_entry(r, &nri_ranges->entries, entry) {
		printf("  { %d, %d },\n", r->first, r->last);
		if (osmo_nri_range_validate(r, 255)) {
			ok = false;
			printf("    ^^^^^ ERROR: invalid range\n");
		}
	}
	printf("};\n");
}

void test_nri_list(void)
{
	struct osmo_nri_ranges *nri_ranges = osmo_nri_ranges_alloc(ctx);
	printf("\n%s()\n", __func__);

#define ADD(FIRST, LAST) do { \
		struct osmo_nri_range r = { .first = FIRST, .last = LAST }; \
		int rc; \
		rc = osmo_nri_ranges_add(nri_ranges, &r); \
		printf("osmo_nri_ranges_add(%d, %d) -> %d\n", r.first, r.last, rc); \
		dump_list(nri_ranges); \
	} while(0)

#define DEL(FIRST, LAST) do { \
		struct osmo_nri_range r = { .first = FIRST, .last = LAST }; \
		int rc; \
		rc = osmo_nri_ranges_del(nri_ranges, &r); \
		printf("osmo_nri_ranges_del(%d, %d) -> %d\n", r.first, r.last, rc); \
		dump_list(nri_ranges); \
	} while(0)

#define MATCHES(NRI, EXPECT_MATCH) do { \
		bool matches = osmo_nri_v_matches_ranges(NRI, nri_ranges); \
		printf("osmo_nri_v_matches_ranges(%d) -> %s\n", NRI, matches ? "true" : "false"); \
		if (matches != EXPECT_MATCH) { \
			ok = false; \
			printf("  ^ ERROR: expected " #EXPECT_MATCH "\n"); \
		} \
	} while(0)

#define OVERLAPS(FIRST, LAST, EXPECT_OVERLAP) do { \
		struct osmo_nri_range r = { .first = FIRST, .last = LAST }; \
		bool overlaps = osmo_nri_range_overlaps_ranges(&r, nri_ranges); \
		printf("osmo_nri_range_overlaps_ranges(%d, %d) -> %s\n", r.first, r.last, overlaps ? "true" : "false"); \
		if (overlaps != EXPECT_OVERLAP) { \
			ok = false; \
			printf("  ^ ERROR: expected " #EXPECT_OVERLAP "\n"); \
		} \
	} while(0)

	dump_list(nri_ranges);
	MATCHES(INT16_MIN, false);
	MATCHES(-1, false);
	MATCHES(0, false);
	MATCHES(INT16_MAX, false);
	MATCHES(100, false);
	OVERLAPS(INT16_MIN, -1, false);
	OVERLAPS(-100, 100, false);
	OVERLAPS(10, 20, false);

	ADD(100, 200);
	MATCHES(INT16_MIN, false);
	MATCHES(-1, false);
	MATCHES(0, false);
	MATCHES(INT16_MAX, false);
	MATCHES(99, false);
	MATCHES(100, true);
	MATCHES(101, true);
	MATCHES(199, true);
	MATCHES(200, true);
	MATCHES(201, false);
	OVERLAPS(INT16_MIN, -1, false);
	OVERLAPS(-100, 100, true);
	OVERLAPS(10, 20, false);
	OVERLAPS(10, 99, false);
	OVERLAPS(10, 100, true);
	OVERLAPS(10, 150, true);
	OVERLAPS(99, 99, false);
	OVERLAPS(100, 100, true);
	OVERLAPS(150, 300, true);
	OVERLAPS(200, 300, true);
	OVERLAPS(201, 300, false);

	printf("\ndel from start:\n");
	DEL(0, 110);
	DEL(111, 111);
	DEL(112, 199);
	MATCHES(INT16_MIN, false);
	MATCHES(-1, false);
	MATCHES(0, false);
	MATCHES(INT16_MAX, false);
	MATCHES(199, false);
	MATCHES(200, true);
	MATCHES(201, false);
	OVERLAPS(INT16_MIN, -1, false);
	OVERLAPS(-1000, 1000, true);
	OVERLAPS(0, 199, false);
	OVERLAPS(0, 200, true);
	OVERLAPS(0, 201, true);
	OVERLAPS(0, 1000, true);
	OVERLAPS(199, 199, false);
	OVERLAPS(200, 200, true);
	OVERLAPS(201, 201, false);

	printf("\ndel from end:\n");
	ADD(100, 200);
	DEL(190, INT16_MAX);
	DEL(189, 189);
	DEL(101, 188);
	MATCHES(INT16_MIN, false);
	MATCHES(-1, false);
	MATCHES(0, false);
	MATCHES(INT16_MAX, false);
	MATCHES(99, false);
	MATCHES(100, true);
	MATCHES(101, false);

	printf("\ndel from middle:\n");
	ADD(100, 200);
	DEL(150, 160);
	DEL(110, 120);
	DEL(130, 130);
	DEL(180, 190);
	MATCHES(INT16_MIN, false);
	MATCHES(-1, false);
	MATCHES(0, false);
	MATCHES(INT16_MAX, false);
	MATCHES(99, false);
	MATCHES(100, true);
	MATCHES(109, true);
	MATCHES(110, false);
	MATCHES(120, false);
	MATCHES(121, true);
	MATCHES(129, true);
	MATCHES(130, false);
	MATCHES(131, true);
	MATCHES(148, true);
	MATCHES(149, true);
	MATCHES(150, false);
	MATCHES(160, false);
	MATCHES(161, true);
	MATCHES(170, true);
	MATCHES(179, true);
	MATCHES(180, false);
	MATCHES(185, false);
	MATCHES(190, false);
	MATCHES(191, true);
	MATCHES(195, true);
	MATCHES(200, true);
	MATCHES(201, false);
	MATCHES(1000, false);
	OVERLAPS(110, 120, false);
	OVERLAPS(110, 130, true);
	OVERLAPS(100, 200, true);

	printf("\ndel across whole chunks:\n");
	DEL(115, 185);
	DEL(105, 195);
	DEL(0, 1000);

	printf("\nadd to join chunks:\n");
	ADD(0, 100);
	DEL(11, 19);
	DEL(23, 23);
	DEL(30, 41);
	ADD(23, 23);
	ADD(11, 41);
	MATCHES(0, true);
	MATCHES(10, true);
	MATCHES(11, true);
	MATCHES(24, true);
	MATCHES(41, true);
	MATCHES(42, true);
	MATCHES(100, true);
	MATCHES(101, false);

	printf("\nborder cases:\n");
	ADD(0, 0);
	ADD(INT16_MAX, INT16_MAX);
	ADD(1, INT16_MAX - 1);
	MATCHES(INT16_MIN, false);
	MATCHES(-1, false);
	MATCHES(0, true);
	MATCHES(INT16_MAX, true);
	DEL(0, 0);
	DEL(INT16_MAX, INT16_MAX);
	DEL(1, INT16_MAX - 1);

	printf("\nrange errors:\n");
	ADD(-1, -1);
	ADD(-20, -10);
	ADD(100, 1);
	ADD(0, INT16_MAX);
	DEL(-1, -1);
	DEL(-20, -10);
	DEL(100, 1);
}

void test_nri_limit_by_ranges(void)
{
	const uint8_t nri_bitlen = 8;
	const int16_t expect_nri_vals[] = { 10, 20, 21, 30, 31, 32 };
	int i;
	struct osmo_nri_ranges *nri_ranges = osmo_nri_ranges_alloc(ctx);
	printf("\n%s()\n", __func__);

	ADD(10, 10);
	ADD(20, 21);
	ADD(30, 32);

	for (i = 0; i < 19; i++) {
		int rc;
		int16_t nri_v;
		int16_t expect_nri_v = expect_nri_vals[i % ARRAY_SIZE(expect_nri_vals)];

		nri_v = i;
		rc = osmo_nri_v_limit_by_ranges(&nri_v, nri_ranges, nri_bitlen);
		printf("osmo_nri_v_limit_by_ranges(%d) -> nri_v=%d rc=%d", i, nri_v, rc);
		if (!rc && nri_v == expect_nri_v) {
			printf(" ok\n");
		} else {
			printf(" ERROR: expected nri_v=%d rc=0\n", expect_nri_v);
			ok = false;
		}
	}
	for (i = 0; i < 19; i++) {
		int rc;
		int16_t nri_v;
		uint32_t tmsi, tmsi2;
		int16_t expect_nri_v = expect_nri_vals[i % ARRAY_SIZE(expect_nri_vals)];

		tmsi = 0;
		osmo_tmsi_nri_v_set(&tmsi, i, nri_bitlen);
		tmsi2 = tmsi;
		rc = osmo_tmsi_nri_v_limit_by_ranges(&tmsi2, nri_ranges, nri_bitlen);
		osmo_tmsi_nri_v_get(&nri_v, tmsi2, nri_bitlen);
		printf("osmo_tmsi_nri_v_limit_by_ranges(0x%08x, %u) -> tmsi=0x%08x nri_v=%d rc=%d",
		       tmsi, nri_bitlen, tmsi2, nri_v, rc);
		if (!rc && nri_v == expect_nri_v) {
			printf(" ok\n");
		} else {
			printf(" ERROR: expected nri_v=%d rc=0\n", expect_nri_v);
			ok = false;
		}
	}
}

int main(int argc, char **argv)
{
	ctx = talloc_named_const(NULL, 0, "nri_test");

	test_nri_v_get_set();
	test_nri_validate();
	test_nri_range_validate();
	test_nri_list();
	test_nri_limit_by_ranges();

	talloc_free(ctx);
	if (!ok) {
		printf("\nFAIL\n");
		return -1;
	}

	printf("\npass\n");
	return 0;
}

