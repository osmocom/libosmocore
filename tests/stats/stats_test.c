/* tests for statistics */
/*
 * (C) 2015 sysmocom - s.m.f.c. GmbH
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

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stats.h>

#include <stdio.h>
#include <inttypes.h>

enum test_ctr {
	TEST_A_CTR,
	TEST_B_CTR,
};

static const struct rate_ctr_desc ctr_description[] = {
	[TEST_A_CTR] = { "ctr:a", "The A counter value"},
	[TEST_B_CTR] = { "ctr:b", "The B counter value"},
};

static const struct rate_ctr_group_desc ctrg_desc = {
	.group_name_prefix = "ctr-test:one",
	.group_description = "Counter test number 1",
	.num_ctr = ARRAY_SIZE(ctr_description),
	.ctr_desc = ctr_description,
	.class_id = OSMO_STATS_CLASS_SUBSCRIBER,
};

static const struct rate_ctr_desc ctr_description_dot[] = {
	[TEST_A_CTR] = { "ctr.a", "The A counter value with ."},
	[TEST_B_CTR] = { "ctr.b", "The B counter value with ."},
};

static const struct rate_ctr_group_desc ctrg_desc_dot = {
	.group_name_prefix = "ctr-test.one_dot",
	.group_description = "Counter test number 1dot",
	.num_ctr = ARRAY_SIZE(ctr_description_dot),
	.ctr_desc = ctr_description_dot,
	.class_id = OSMO_STATS_CLASS_SUBSCRIBER,
};

enum test_items {
	TEST_A_ITEM,
	TEST_B_ITEM,
};

static const struct osmo_stat_item_desc item_description[] = {
	[TEST_A_ITEM] = { "item.a", "The A value", "ma", 4, -1 },
	[TEST_B_ITEM] = { "item.b", "The B value", "kb", 7, -1 },
};

static const struct osmo_stat_item_group_desc statg_desc = {
	.group_name_prefix = "test.one",
	.group_description = "Test number 1",
	.num_items = ARRAY_SIZE(item_description),
	.item_desc = item_description,
	.class_id = OSMO_STATS_CLASS_PEER,
};

static void stat_test(void)
{
	struct osmo_stat_item_group *statg =
		osmo_stat_item_group_alloc(NULL, &statg_desc, 0);

	struct osmo_stat_item_group *sgrp2;
	const struct osmo_stat_item *sitem1, *sitem2;
	int rc;
	int32_t value;
	int32_t next_id_a = 1;
	int32_t next_id_b = 1;
	int i;

	OSMO_ASSERT(statg != NULL);

	sgrp2 = osmo_stat_item_get_group_by_name_idx("test.one", 0);
	OSMO_ASSERT(sgrp2 == statg);

	sgrp2 = osmo_stat_item_get_group_by_name_idx("test.one", 1);
	OSMO_ASSERT(sgrp2 == NULL);

	sgrp2 = osmo_stat_item_get_group_by_name_idx("test.two", 0);
	OSMO_ASSERT(sgrp2 == NULL);

	sitem1 = osmo_stat_item_get_by_name(statg, "item.c");
	OSMO_ASSERT(sitem1 == NULL);

	sitem1 = osmo_stat_item_get_by_name(statg, "item.a");
	OSMO_ASSERT(sitem1 != NULL);
	OSMO_ASSERT(sitem1 == osmo_stat_item_group_get_item(statg, TEST_A_ITEM));

	sitem2 = osmo_stat_item_get_by_name(statg, "item.b");
	OSMO_ASSERT(sitem2 != NULL);
	OSMO_ASSERT(sitem2 != sitem1);
	OSMO_ASSERT(sitem2 == osmo_stat_item_group_get_item(statg, TEST_B_ITEM));

	value = osmo_stat_item_get_last(osmo_stat_item_group_get_item(statg, TEST_A_ITEM));
	OSMO_ASSERT(value == -1);

	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
	OSMO_ASSERT(rc == 0);

	osmo_stat_item_set(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), 1);

	value = osmo_stat_item_get_last(osmo_stat_item_group_get_item(statg, TEST_A_ITEM));
	OSMO_ASSERT(value == 1);

	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
	OSMO_ASSERT(rc == 1);
	OSMO_ASSERT(value == 1);

	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
	OSMO_ASSERT(rc == 0);

	for (i = 2; i <= 32; i++) {
		osmo_stat_item_set(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), i);
		osmo_stat_item_set(osmo_stat_item_group_get_item(statg, TEST_B_ITEM), 1000 + i);

		rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
		OSMO_ASSERT(rc == 1);
		OSMO_ASSERT(value == i);

		rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_B_ITEM), &next_id_b, &value);
		OSMO_ASSERT(rc == 1);
		OSMO_ASSERT(value == 1000 + i);
	}

	/* check if dec & inc is working */
	osmo_stat_item_set(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), 42);
	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
	OSMO_ASSERT(rc == 1);
	OSMO_ASSERT(value == 42);

	osmo_stat_item_dec(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), 21);
	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
	OSMO_ASSERT(rc == 1);
	OSMO_ASSERT(value == 21);

	osmo_stat_item_inc(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), 21);
	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
	OSMO_ASSERT(rc == 1);
	OSMO_ASSERT(value == 42);

	/* Keep 2 in FIFO */
	osmo_stat_item_set(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), 33);
	osmo_stat_item_set(osmo_stat_item_group_get_item(statg, TEST_B_ITEM), 1000 + 33);

	for (i = 34; i <= 64; i++) {
		osmo_stat_item_set(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), i);
		osmo_stat_item_set(osmo_stat_item_group_get_item(statg, TEST_B_ITEM), 1000 + i);

		rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
		OSMO_ASSERT(rc == 1);
		OSMO_ASSERT(value == i-1);

		rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_B_ITEM), &next_id_b, &value);
		OSMO_ASSERT(rc == 1);
		OSMO_ASSERT(value == 1000 + i-1);
	}

	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
	OSMO_ASSERT(rc == 1);
	OSMO_ASSERT(value == 64);

	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_B_ITEM), &next_id_b, &value);
	OSMO_ASSERT(rc == 1);
	OSMO_ASSERT(value == 1000 + 64);

	/* Overrun FIFOs */
	for (i = 65; i <= 96; i++) {
		osmo_stat_item_set(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), i);
		osmo_stat_item_set(osmo_stat_item_group_get_item(statg, TEST_B_ITEM), 1000 + i);
	}

	fprintf(stderr, "Skipping %d values\n", 93 - 65);
	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
	OSMO_ASSERT(rc == 93 - 65 + 1);
	OSMO_ASSERT(value == 93);

	for (i = 94; i <= 96; i++) {
		rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
		OSMO_ASSERT(rc == 1);
		OSMO_ASSERT(value == i);
	}

	fprintf(stderr, "Skipping %d values\n", 90 - 65);
	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_B_ITEM), &next_id_b, &value);
	OSMO_ASSERT(rc == 90 - 65 + 1);
	OSMO_ASSERT(value == 1000 + 90);

	for (i = 91; i <= 96; i++) {
		rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_B_ITEM), &next_id_b, &value);
		OSMO_ASSERT(rc == 1);
		OSMO_ASSERT(value == 1000 + i);
	}

	/* Test Discard (single item) */
	osmo_stat_item_set(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), 97);
	rc = osmo_stat_item_discard(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a);
	OSMO_ASSERT(rc == 1);

	rc = osmo_stat_item_discard(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a);
	OSMO_ASSERT(rc == 0);

	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
	OSMO_ASSERT(rc == 0);

	osmo_stat_item_set(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), 98);
	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
	OSMO_ASSERT(rc == 1);
	OSMO_ASSERT(value == 98);

	rc = osmo_stat_item_get_next(osmo_stat_item_group_get_item(statg, TEST_A_ITEM), &next_id_a, &value);
	OSMO_ASSERT(rc == 0);

	osmo_stat_item_group_free(statg);

	sgrp2 = osmo_stat_item_get_group_by_name_idx("test.one", 0);
	OSMO_ASSERT(sgrp2 == NULL);
}

/*** stats reporter tests ***/

/* define a special stats reporter for testing */

static int sent_counter_vals;
static int sent_stat_item_vals;

enum {
	OSMO_STATS_REPORTER_TEST = OSMO_STATS_REPORTER_LOG + 1,
};

static int stats_reporter_test_send_counter(struct osmo_stats_reporter *srep,
	const struct rate_ctr_group *ctrg,
	const struct rate_ctr_desc *desc,
	int64_t value, int64_t delta)
{
	const char *group_name = ctrg ? ctrg->desc->group_name_prefix : "";

	fprintf(stderr, "  %s: counter p=%s g=%s i=%u n=%s v=%lld d=%lld\n",
		srep->name,
		srep->name_prefix ? srep->name_prefix : "",
		group_name, ctrg ? ctrg->idx : 0,
		desc->name, (long long)value, (long long)delta);

	sent_counter_vals++;
	return 0;
}

static int stats_reporter_test_send_item(struct osmo_stats_reporter *srep,
	const struct osmo_stat_item_group *statg,
	const struct osmo_stat_item_desc *desc, int64_t value)
{
	fprintf(stderr, "  %s: item p=%s g=%s i=%u n=%s v=%"PRId64" u=%s\n",
		srep->name,
		srep->name_prefix ? srep->name_prefix : "",
		statg->desc->group_name_prefix, statg->idx,
		desc->name, value, desc->unit ? desc->unit : "");

	sent_stat_item_vals++;
	return 0;
}

static int stats_reporter_test_open(struct osmo_stats_reporter *srep)
{
	fprintf(stderr, "  %s: open\n", srep->name);
	return 0;
}

static int stats_reporter_test_close(struct osmo_stats_reporter *srep)
{
	fprintf(stderr, "  %s: close\n", srep->name);
	return 0;
}

static struct osmo_stats_reporter *stats_reporter_create_test(const char *name)
{
	struct osmo_stats_reporter *srep;
	srep = osmo_stats_reporter_alloc(OSMO_STATS_REPORTER_TEST, name);

	srep->have_net_config = 0;

	srep->open = stats_reporter_test_open;
	srep->close = stats_reporter_test_close;
	srep->send_counter = stats_reporter_test_send_counter;
	srep->send_item = stats_reporter_test_send_item;

	return srep;
}

static void _do_report(int expect_counter_vals, int expect_stat_item_vals, int line)
{
	sent_counter_vals = 0;
	sent_stat_item_vals = 0;
	osmo_stats_report();
	fprintf(stderr, "reported: %d counter vals, %d stat item vals\n", sent_counter_vals, sent_stat_item_vals);
	OSMO_ASSERT(sent_counter_vals == expect_counter_vals);
	OSMO_ASSERT(sent_stat_item_vals == expect_stat_item_vals);
}

#define do_report(A, B) _do_report(A, B, __LINE__)

static void test_reporting()
{
	struct osmo_stats_reporter *srep1, *srep2, *srep;
	struct osmo_stat_item_group *statg1, *statg2;
	struct rate_ctr_group *ctrg1, *ctrg2, *ctrg3, *ctrg_dup;
	void *stats_ctx = talloc_named_const(NULL, 1, "stats test context");

	int rc;

	fprintf(stderr, "Start test: %s\n", __func__);

	/* Allocate counters and items */
	statg1 = osmo_stat_item_group_alloc(stats_ctx, &statg_desc, 1);
	OSMO_ASSERT(statg1 != NULL);
	statg2 = osmo_stat_item_group_alloc(stats_ctx, &statg_desc, 2);
	OSMO_ASSERT(statg2 != NULL);
	ctrg1 = rate_ctr_group_alloc(stats_ctx, &ctrg_desc, 1);
	OSMO_ASSERT(ctrg1 && ctrg1->idx == 1);
	ctrg2 = rate_ctr_group_alloc(stats_ctx, &ctrg_desc, 2);
	OSMO_ASSERT(ctrg2 && ctrg2->idx == 2);

	ctrg_dup = rate_ctr_group_alloc(stats_ctx, &ctrg_desc, 2);
	OSMO_ASSERT(ctrg_dup && ctrg_dup->idx == 3);
	rate_ctr_group_free(ctrg_dup);

	ctrg3 = rate_ctr_group_alloc(stats_ctx, &ctrg_desc_dot, 3);
	OSMO_ASSERT(ctrg3 && ctrg3->idx == 3);

	srep1 = stats_reporter_create_test("test1");
	OSMO_ASSERT(srep1 != NULL);

	srep2 = stats_reporter_create_test("test2");
	OSMO_ASSERT(srep2 != NULL);

	srep = osmo_stats_reporter_find(OSMO_STATS_REPORTER_TEST, "test1");
	OSMO_ASSERT(srep == srep1);
	srep = osmo_stats_reporter_find(OSMO_STATS_REPORTER_TEST, "test2");
	OSMO_ASSERT(srep == srep2);

	rc = osmo_stats_reporter_enable(srep1);
	OSMO_ASSERT(rc >= 0);
	OSMO_ASSERT(srep1->force_single_flush);
	rc = osmo_stats_reporter_set_max_class(srep1, OSMO_STATS_CLASS_SUBSCRIBER);
	OSMO_ASSERT(rc >= 0);

	rc = osmo_stats_reporter_enable(srep2);
	OSMO_ASSERT(rc >= 0);
	OSMO_ASSERT(srep2->force_single_flush);
	rc = osmo_stats_reporter_set_max_class(srep2, OSMO_STATS_CLASS_SUBSCRIBER);
	OSMO_ASSERT(rc >= 0);

	fprintf(stderr, "report (initial):\n");
	do_report(12, 8);

	fprintf(stderr, "report (srep1 global):\n");
	/* force single flush */
	osmo_stats_reporter_set_max_class(srep1, OSMO_STATS_CLASS_GLOBAL);
	srep1->force_single_flush = 1;
	srep2->force_single_flush = 1;
	do_report(6, 4);

	fprintf(stderr, "report (srep1 peer):\n");
	/* force single flush */
	osmo_stats_reporter_set_max_class(srep1, OSMO_STATS_CLASS_PEER);
	srep1->force_single_flush = 1;
	srep2->force_single_flush = 1;
	do_report(6, 8);

	fprintf(stderr, "report (srep1 subscriber):\n");
	/* force single flush */
	osmo_stats_reporter_set_max_class(srep1, OSMO_STATS_CLASS_SUBSCRIBER);
	srep1->force_single_flush = 1;
	srep2->force_single_flush = 1;
	do_report(12, 8);

	fprintf(stderr, "report (srep2 disabled):\n");
	/* force single flush */
	srep1->force_single_flush = 1;
	srep2->force_single_flush = 1;
	rc = osmo_stats_reporter_disable(srep2);
	OSMO_ASSERT(rc >= 0);
	do_report(6, 4);

	fprintf(stderr, "report (srep2 enabled, no flush forced):\n");
	rc = osmo_stats_reporter_enable(srep2);
	OSMO_ASSERT(rc >= 0);
	do_report(6, 4);

	fprintf(stderr, "report (should be empty):\n");
	do_report(0, 0);

	fprintf(stderr, "report (group 1, counter 1 update):\n");
	rate_ctr_inc(rate_ctr_group_get_ctr(ctrg1, TEST_A_CTR));
	do_report(2, 0);

	fprintf(stderr, "report (group 1, item 1 update):\n");
	osmo_stat_item_set(osmo_stat_item_group_get_item(statg1, TEST_A_ITEM), 10);
	do_report(0, 2);

	fprintf(stderr, "report (group 1, item 1 update twice):\n");
	osmo_stat_item_set(osmo_stat_item_group_get_item(statg1, TEST_A_ITEM), 10);
	osmo_stat_item_set(osmo_stat_item_group_get_item(statg1, TEST_A_ITEM), 10);
	do_report(0, 2);

	fprintf(stderr, "report (group 1, item 1 update twice, check max):\n");
	osmo_stat_item_set(osmo_stat_item_group_get_item(statg1, TEST_A_ITEM), 20);
	osmo_stat_item_set(osmo_stat_item_group_get_item(statg1, TEST_A_ITEM), 10);
	do_report(0, 2);

	fprintf(stderr, "report (group 1, item 1 no update, send last item (!= last max), OS#5215):\n");
	do_report(0, 2);

	fprintf(stderr, "report (group 1, item 1 no update, nothing to send):\n");
	do_report(0, 0);

	fprintf(stderr, "report (remove statg1, ctrg1):\n");
	/* force single flush */
	srep1->force_single_flush = 1;
	srep2->force_single_flush = 1;
	osmo_stat_item_group_free(statg1);
	rate_ctr_group_free(ctrg1);
	do_report(8, 4);

	fprintf(stderr, "report (remove srep1):\n");
	/* force single flush */
	srep1->force_single_flush = 1;
	srep2->force_single_flush = 1;
	osmo_stats_reporter_free(srep1);
	do_report(4, 2);

	fprintf(stderr, "report (remove statg2):\n");
	/* force single flush */
	srep2->force_single_flush = 1;
	osmo_stat_item_group_free(statg2);
	do_report(4, 0);

	fprintf(stderr, "report (remove srep2):\n");
	/* force single flush */
	srep2->force_single_flush = 1;
	osmo_stats_reporter_free(srep2);
	do_report(0, 0);

	fprintf(stderr, "report (remove ctrg2, should be empty):\n");
	rate_ctr_group_free(ctrg2);
	do_report(0, 0);

	rate_ctr_group_free(ctrg3);

	/* Leak check */
	OSMO_ASSERT(talloc_total_blocks(stats_ctx) == 1);
	talloc_free(stats_ctx);

	fprintf(stderr, "End test: %s\n", __func__);
}

int main(int argc, char **argv)
{
	void *ctx = talloc_named_const(NULL, 0, "main");
	osmo_init_logging2(ctx, NULL);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);

	osmo_stat_item_init(NULL);

	stat_test();
	test_reporting();
	talloc_free(ctx);
	return 0;
}
