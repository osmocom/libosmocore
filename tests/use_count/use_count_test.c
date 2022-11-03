/* Test implementation for osmo_use_count API. */
/*
 * (C) 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/fsm.h>

#include <osmocom/core/use_count.h>

static void *ctx = NULL;

#define log(fmt, args...) fprintf(stderr, fmt, ##args)

enum {
	DFOO,
};

#define FOO_USE_BARRING "barring"
#define FOO_USE_FIGHTING "fighting"
#define FOO_USE_KUNG "kungfoo"
#define FOO_USE_RELEASING "releasing"

LLIST_HEAD(all_foo);

struct foo {
	struct llist_head entry;
	struct osmo_fsm_inst *fi;
	struct osmo_use_count use_count;
	struct osmo_use_count_entry use_count_buf[10];
};

enum foo_fsm_events {
	FOO_EV_UNUSED,
};

static char name_buf[1024];
#define use_count_name(UL) osmo_use_count_name_buf(name_buf, sizeof(name_buf), UL)

int foo_use_cb(struct osmo_use_count_entry *use_count_entry, int32_t old_use_count,
	       const char *file, int line)
{
	struct osmo_use_count *use_count = use_count_entry->use_count;
	struct foo *foo = use_count->talloc_object;
	const char *use = use_count_entry->use;
	int32_t new_use_count = use_count_entry->count;

	if (use && (!strcmp(use, FOO_USE_BARRING) || !strcmp(use, FOO_USE_RELEASING))
	    && new_use_count > 1) {
		LOGPFSMLSRC(foo->fi, LOGL_ERROR, file, line,
			    "Attempt to get more than one %s\n", use);
		/* Fix the use count */
		use_count_entry->count = 1;
		return -ERANGE;
	}

	LOGPFSMLSRC(foo->fi, LOGL_NOTICE, file, line, "%s %+d %s: now used by %s\n",
		    foo->fi->id, new_use_count - old_use_count, use ? : "NULL", use_count_name(use_count));

	if (new_use_count < 0) {
		LOGPFSMLSRC(foo->fi, LOGL_ERROR, file, line, "Negative use count on %s: %s\n",
			    use ? : "NULL", use_count_name(use_count));
		/* Let it pass for the sake of this test */
	}

	if (osmo_use_count_total(use_count) == 0)
		osmo_fsm_inst_dispatch(foo->fi, FOO_EV_UNUSED, NULL);
	return 0;
}

#define foo_get_put(FOO, USE, CHANGE) do { \
		int rc = osmo_use_count_get_put(&(FOO)->use_count, USE, CHANGE); \
		if (rc) \
			log("osmo_use_count_get_put(%s, %s, %d) returned error: %d %s\n", \
			    (FOO)->fi->id, USE ? : "NULL", CHANGE, rc, strerror(-rc)); \
	} while(0)

#define foo_get(FOO, USE) foo_get_put(FOO, USE, 1)
#define foo_put(FOO, USE) foo_get_put(FOO, USE, -1)

enum foo_fsm_states {
	FOO_ST_IN_USE,
	FOO_ST_IN_RELEASE,
};

void foo_fsm_in_use(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	OSMO_ASSERT(event == FOO_EV_UNUSED);
	osmo_fsm_inst_state_chg(fi, FOO_ST_IN_RELEASE, 0, 0);
}

void foo_fsm_in_release_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct foo *foo = fi->priv;
	foo_get(foo, FOO_USE_RELEASING);
}

void foo_fsm_in_release(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	OSMO_ASSERT(event == FOO_EV_UNUSED);
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}


#define S(x)	(1 << (x))

static const struct osmo_fsm_state foo_fsm_states[] = {
	[FOO_ST_IN_USE] = {
		.name = "IN_USE",
		.in_event_mask = 0
			| S(FOO_EV_UNUSED)
			,
		.out_state_mask = 0
			| S(FOO_ST_IN_RELEASE)
			,
		.action = foo_fsm_in_use,
	},
	[FOO_ST_IN_RELEASE] = {
		.name = "IN_RELEASE",
		.in_event_mask = 0
			| S(FOO_EV_UNUSED)
			,
		.out_state_mask = 0
			,
		.onenter = foo_fsm_in_release_onenter,
		.action = foo_fsm_in_release,
	},
};

static const struct value_string foo_fsm_event_names[] = {
	OSMO_VALUE_STRING(FOO_EV_UNUSED),
	{}
};

void foo_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct foo *foo = fi->priv;
	llist_del(&foo->entry);
}

static struct osmo_fsm foo_fsm = {
	.name = "foo",
	.states = foo_fsm_states,
	.event_names = foo_fsm_event_names,
	.num_states = ARRAY_SIZE(foo_fsm_states),
	.log_subsys = DFOO,
	.cleanup = foo_cleanup,
};

static struct foo *foo_alloc(const char *name, size_t static_entries)
{
	struct foo *foo;
	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc(&foo_fsm, ctx, NULL, LOGL_DEBUG, name);
	OSMO_ASSERT(fi);
	OSMO_ASSERT(static_entries <= ARRAY_SIZE(foo->use_count_buf));

	foo = talloc_zero(fi, struct foo);
	*foo = (struct foo){
		.fi = fi,
		.use_count = {
			.talloc_object = foo,
			.use_cb = foo_use_cb,
		},
	};
	fi->priv = foo;

	osmo_use_count_make_static_entries(&foo->use_count, foo->use_count_buf, static_entries);

	llist_add_tail(&foo->entry, &all_foo);
	return foo;
}

void print_foos(void)
{
	int count = 0;
	struct foo *foo;
	fprintf(stderr, "\nall use counts:\n");
	llist_for_each_entry(foo, &all_foo, entry) {
		fprintf(stderr, "%s: %s\n", foo->fi->id, use_count_name(&foo->use_count));
		count++;
	}
	fprintf(stderr, "%d foos\n\n", count);
}

static void test_use_count_fsm(void)
{
	struct foo *a, *b, *c;
	log("\n%s()\n", __func__);

	a = foo_alloc("a", 0);
	b = foo_alloc("b", 2);
	c = foo_alloc("c", 10);
	print_foos();

	log("A few gets and puts, logging source file information\n");
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_BASENAME);
	foo_get(a, FOO_USE_BARRING);

	foo_get(b, FOO_USE_BARRING);
	foo_get(b, FOO_USE_FIGHTING);

	print_foos();

	log("Attempt to get more than one on limited 'barring' user:\n");
	foo_get(b, FOO_USE_BARRING);
	print_foos();

	log("Put away one user of b\n");
	foo_put(b, FOO_USE_BARRING);
	print_foos();

	log("(no longer log source file information)\n");
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);

	log("Test null use token\n");
	foo_get(a, NULL);
	print_foos();
	foo_put(a, NULL);
	print_foos();

	log("Put away last user of a, goes to RELEASING state and waits for a hypothetic async release process\n");
	foo_put(a, FOO_USE_BARRING);
	print_foos();

	log("Async releasing of a is done, will dealloc\n");
	foo_put(a, FOO_USE_RELEASING);
	print_foos();

	log("Use b multiple times\n");
	foo_get(b, FOO_USE_KUNG);
	foo_get(b, FOO_USE_KUNG);

	foo_put(b, FOO_USE_KUNG);
	foo_get(b, FOO_USE_KUNG);

	foo_get(b, FOO_USE_KUNG);
	print_foos();

	log("Test range: set kung-fu to INT32_MAX-1, then get three more; total count gets max-clamped to INT32_MAX\n");
	foo_get_put(b, FOO_USE_KUNG, INT32_MAX-1 - osmo_use_count_by(&b->use_count, FOO_USE_KUNG));
	print_foos();
	foo_get(b, FOO_USE_KUNG);
	foo_get(b, FOO_USE_KUNG);
	foo_get(b, FOO_USE_KUNG);
	foo_get_put(b, FOO_USE_FIGHTING, 2);
	foo_get_put(b, FOO_USE_KUNG, -3);
	foo_put(b, FOO_USE_KUNG);
	foo_put(b, FOO_USE_KUNG);
	foo_get(b, FOO_USE_FIGHTING);
	foo_get(b, FOO_USE_FIGHTING);
	foo_get(b, FOO_USE_FIGHTING);
	print_foos();

	log("Release all uses of b\n");
	foo_get_put(b, FOO_USE_KUNG, - osmo_use_count_by(&b->use_count, FOO_USE_KUNG));
	foo_get_put(b, FOO_USE_FIGHTING, - osmo_use_count_by(&b->use_count, FOO_USE_FIGHTING));

	log("Signal async release as done\n");
	foo_put(b, FOO_USE_RELEASING);
	print_foos();

	log("Release something not gotten before: a get/put bug goes into negative count\n");
	foo_put(c, FOO_USE_KUNG);
	print_foos();
	log("More negative\n");
	foo_put(c, FOO_USE_KUNG);
	foo_put(c, FOO_USE_KUNG);
	print_foos();

	log("Also release c\n");
	foo_get_put(c, FOO_USE_KUNG, 4);
	foo_put(c, FOO_USE_KUNG);
	log("Signal async release as done\n");
	foo_put(c, FOO_USE_RELEASING);
	print_foos();
}

static const struct log_info_cat default_categories[] = {
	[DFOO] = {
		.name = "DFOO",
		.description = "FOO",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};


int main(int argc, char **argv)
{
	ctx = talloc_named_const(NULL, 0, "use_count_test.c");

	osmo_fsm_log_addr(false);

	osmo_init_logging2(ctx, &log_info);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_BASENAME);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_filename_pos(osmo_stderr_target, LOG_FILENAME_POS_LINE_END);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	OSMO_ASSERT(osmo_fsm_register(&foo_fsm) == 0);

	test_use_count_fsm();

	return EXIT_SUCCESS;
}
