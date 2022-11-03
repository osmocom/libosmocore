/* Test implementation for osmo_tdef API. */
/*
 * (C) 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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
#include <limits.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/fsm.h>

#include <osmocom/core/tdef.h>

static void *ctx = NULL;

static struct osmo_tdef tdefs[] = {
	{ .T=1, .default_val=100, .desc="100s" },
	{ .T=2, .default_val=100, .unit=OSMO_TDEF_MS, .desc="100ms" },
	{ .T=3, .default_val=50, .unit=OSMO_TDEF_M, .desc="50m" },
	{ .T=4, .default_val=100, .unit=OSMO_TDEF_CUSTOM, .desc="100 potatoes" },

	{ .T=7, .default_val=50, .desc="Water Boiling Timeout", .min_val=20, .max_val=800 },  // default is .unit=OSMO_TDEF_S == 0
	{ .T=8, .default_val=300, .desc="Tea brewing" },
	{ .T=9, .default_val=5, .unit=OSMO_TDEF_M, .desc="Let tea cool down before drinking" },
	{ .T=10, .default_val=20, .unit=OSMO_TDEF_M, .desc="Forgot to drink tea while it's warm" },

	/* test conversions */
	{ .T=1000, .default_val=2*1000, .unit=OSMO_TDEF_MS, .desc="two seconds from ms" },
	{ .T=1001, .default_val=60*1000, .unit=OSMO_TDEF_MS, .desc="one minute from ms" },
	{ .T=1004, .default_val=1, .unit=OSMO_TDEF_MS, .desc="one ms" },
	{ .T=1005, .default_val=0, .unit=OSMO_TDEF_MS, .desc="zero ms" },
	{ .T=1006, .default_val=0, .unit=OSMO_TDEF_S, .desc="zero s" },
	{ .T=1007, .default_val=0, .unit=OSMO_TDEF_M, .desc="zero m" },
	{ .T=1008, .default_val=0, .unit=OSMO_TDEF_CUSTOM, .desc="zero" },
	{ .T=1009, .default_val=0, .unit=OSMO_TDEF_US, .desc="zero us" },

	{ .T=0, .default_val=1, .unit=OSMO_TDEF_CUSTOM, .desc="zero" },

	/* no desc */
	{ .T=123, .default_val=1 },

	{}  //  <-- important! last entry shall be zero
};

static struct osmo_tdef tdefs_range[] = {
	{ .T=1002, .default_val=(ULONG_MAX/60), .unit=OSMO_TDEF_M, .desc="almost too many seconds" },
	{ .T=1003, .default_val=ULONG_MAX, .unit=OSMO_TDEF_M, .desc="too many seconds" },

	{ .T=INT_MAX, .default_val=ULONG_MAX, .unit=OSMO_TDEF_S, .desc="very large" },
	{ .T=INT_MAX-1, .default_val=ULONG_MAX-1, .unit=OSMO_TDEF_S, .desc="very large" },
	{ .T=INT_MAX-2, .default_val=LONG_MAX, .unit=OSMO_TDEF_S, .desc="very large" },
	{ .T=INT_MAX-3, .default_val=ULONG_MAX, .unit=OSMO_TDEF_M, .desc="very large in minutes" },
	{ .T=INT_MIN, .default_val=ULONG_MAX, .unit=OSMO_TDEF_S, .desc="negative" },

	{}
};

#define print_tdef_get(TDEFS, T, AS_UNIT) do { \
		unsigned long val = osmo_tdef_get(TDEFS, T, AS_UNIT, 999); \
		printf("osmo_tdef_get(tdefs, %d, %s, 999)\t= %lu\n", T, osmo_tdef_unit_name(AS_UNIT), val); \
	} while (0)

#define print_tdef_get_short(TDEFS, T, AS_UNIT) do { \
		unsigned long val = osmo_tdef_get(TDEFS, T, AS_UNIT, 999); \
		printf("osmo_tdef_get(%d, %s)\t= %lu\n", T, osmo_tdef_unit_name(AS_UNIT), val); \
	} while (0)

void print_tdef_info(unsigned int T)
{
	const struct osmo_tdef *t = osmo_tdef_get_entry(tdefs, T);
	if (!t) {
		printf("T%d=NULL", T);
		return;
	}
	printf("T%d=%lu%s", T, t->val, osmo_tdef_unit_name(t->unit));
	if (t->val != t->default_val)
		printf("(def=%lu)", t->default_val);
	printf("\n");
}

static void test_tdef_get(bool test_range)
{
	int i;
	enum osmo_tdef_unit as_unit;

	printf("\n%s()\n", __func__);

	osmo_tdefs_reset(tdefs); // make all values the default

	for (i = 0; i < ARRAY_SIZE(tdefs)-1; i++) {
		unsigned int T = tdefs[i].T;
		print_tdef_info(T);
		for (as_unit = OSMO_TDEF_S; as_unit <= OSMO_TDEF_US; as_unit++) {
			print_tdef_get_short(tdefs, T, as_unit);
		}
	}

	if (!test_range)
		return;

	for (i = 0; i < ARRAY_SIZE(tdefs_range)-1; i++) {
		unsigned int T = tdefs_range[i].T;
		print_tdef_info(T);
		for (as_unit = OSMO_TDEF_S; as_unit <= OSMO_TDEF_US; as_unit++) {
			print_tdef_get_short(tdefs_range, T, as_unit);
		}
	}
}

static void test_tdef_get_nonexisting(void)
{
	printf("\n%s()\n", __func__);

	print_tdef_get(tdefs, 5, OSMO_TDEF_S);
	print_tdef_get(tdefs, 5, OSMO_TDEF_MS);
	print_tdef_get(tdefs, 5, OSMO_TDEF_M);
	print_tdef_get(tdefs, 5, OSMO_TDEF_CUSTOM);
	print_tdef_get(tdefs, 5, OSMO_TDEF_US);
}

static void test_tdef_set_and_get(void)
{
	struct osmo_tdef *t;
	printf("\n%s()\n", __func__);

	printf("setting 7 = 42\n");
	t = osmo_tdef_get_entry(tdefs, 7);
	OSMO_ASSERT(t != NULL);
	OSMO_ASSERT(osmo_tdef_val_in_range(t, 42));
	t->val = 42;
	print_tdef_info(7);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_MS);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_S);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_M);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_CUSTOM);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_US);

	printf("setting 7 = 420\n");
	OSMO_ASSERT(osmo_tdef_set(tdefs, 7, 420, OSMO_TDEF_S) == 0);
	print_tdef_info(7);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_MS);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_S);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_M);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_CUSTOM);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_US);

	printf("setting 7 = 10 (ERANGE)\n");
	OSMO_ASSERT(!osmo_tdef_val_in_range(t, 10));
	OSMO_ASSERT(osmo_tdef_set(tdefs, 7, 10, OSMO_TDEF_S) == -ERANGE);
	print_tdef_info(7);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_MS);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_S);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_M);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_CUSTOM);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_US);

	printf("setting 7 = 900 (ERANGE)\n");
	OSMO_ASSERT(!osmo_tdef_val_in_range(t, 900));
	OSMO_ASSERT(osmo_tdef_set(tdefs, 7, 900, OSMO_TDEF_S) == -ERANGE);
	print_tdef_info(7);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_MS);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_S);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_M);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_CUSTOM);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_US);

	printf("setting 23 = 50 (EEXIST)\n");
	OSMO_ASSERT(osmo_tdef_set(tdefs, 23, 50, OSMO_TDEF_S) == -EEXIST);

	printf("resetting\n");
	osmo_tdefs_reset(tdefs);
	print_tdef_info(7);
	print_tdef_get_short(tdefs, 7, OSMO_TDEF_S);
}

enum test_tdef_fsm_states {
	S_A = 0,
	S_B,
	S_C,
	S_D,
	S_G,
	S_H,
	S_I,
	S_J,
	S_K,
	S_L,
	S_M,
	S_N,
	S_O,
	S_X,
	S_Y,
	S_Z,
};

static const struct osmo_tdef_state_timeout test_tdef_state_timeouts[32] = {
	[S_A] = { .T = 1 },
	[S_B] = { .T = 2 },
	[S_C] = { .T = 3 },
	[S_D] = { .T = 4 },

	[S_G] = { .T = 7 },
	[S_H] = { .T = 8 },
	[S_I] = { .T = 9 },
	[S_J] = { .T = 10 },

	/* keep_timer: adopt whichever T was running before and continue the timeout. */
	[S_K] = { .keep_timer = true },
	/* S_F defines an undefined T, but should continue previous state's timeout. */
	[S_L] = { .T = 123, .keep_timer = true },

	/* range */
	[S_M] = { .T = INT_MAX },
	[S_N] = { .T = INT_MIN },

	/* T0 is not addressable from osmo_tdef_state_timeout, since it is indistinguishable from an unset entry. Even
	 * though a timeout value is set for T=0, the transition to state S_O will show "no timer configured". */
	[S_O] = { .T = 0 },

	/* S_X undefined on purpose */
	/* S_Y defines a T that does not exist */
	[S_Y] = { .T = 666 },
	/* S_Z undefined on purpose */
};

#define S(x)	(1 << (x))

static const struct osmo_fsm_state test_tdef_fsm_states[] = {
#define DEF_STATE(NAME) \
	[S_##NAME] = { \
		.name = #NAME, \
		.out_state_mask = 0 \
			| S(S_A) \
			| S(S_B) \
			| S(S_C) \
			| S(S_D) \
			| S(S_G) \
			| S(S_H) \
			| S(S_I) \
			| S(S_J) \
			| S(S_K) \
			| S(S_L) \
			| S(S_M) \
			| S(S_N) \
			| S(S_O) \
			| S(S_X) \
			| S(S_Y) \
			| S(S_Z) \
			, \
	}

	DEF_STATE(A),
	DEF_STATE(B),
	DEF_STATE(C),
	DEF_STATE(D),

	DEF_STATE(G),
	DEF_STATE(H),
	DEF_STATE(I),
	DEF_STATE(J),

	DEF_STATE(K),
	DEF_STATE(L),

	DEF_STATE(M),
	DEF_STATE(N),
	DEF_STATE(O),

	DEF_STATE(X),
	DEF_STATE(Y),
	/* Z: test not being allowed to transition to other states. */
	[S_Z] = {
		.name = "Z",
		.out_state_mask = 0
			| S(S_A)
			,
	},
};

static const struct value_string test_tdef_fsm_event_names[] = { {} };

static struct osmo_fsm test_tdef_fsm = {
	.name = "tdef_test",
	.states = test_tdef_fsm_states,
	.event_names = test_tdef_fsm_event_names,
	.num_states = ARRAY_SIZE(test_tdef_fsm_states),
	.log_subsys = DLGLOBAL,
};

const struct timeval fake_time_start_time = { 123, 456 };

#define fake_time_passes(secs, usecs) do \
{ \
	struct timeval diff; \
	osmo_gettimeofday_override_add(secs, usecs); \
	osmo_clock_override_add(CLOCK_MONOTONIC, secs, usecs * 1000); \
	timersub(&osmo_gettimeofday_override_time, &fake_time_start_time, &diff); \
	printf("Time passes: %ld.%06ld s\n", (long)secs, (long)usecs); \
	osmo_timers_prepare(); \
	osmo_timers_update(); \
} while (0)

void fake_time_start(void)
{
	struct timespec *clock_override;

	osmo_gettimeofday_override_time = fake_time_start_time;
	osmo_gettimeofday_override = true;
	clock_override = osmo_clock_override_gettimespec(CLOCK_MONOTONIC);
	OSMO_ASSERT(clock_override);
	clock_override->tv_sec = fake_time_start_time.tv_sec;
	clock_override->tv_nsec = fake_time_start_time.tv_usec * 1000;
	osmo_clock_override_enable(CLOCK_MONOTONIC, true);
}

static void print_fsm_state(struct osmo_fsm_inst *fi)
{
	struct timeval remaining;
	printf("state=%s T=%d", osmo_fsm_inst_state_name(fi), fi->T);

	if (!osmo_timer_pending(&fi->timer)) {
		printf(", no timeout\n");
		return;
	}

	osmo_timer_remaining(&fi->timer, &osmo_gettimeofday_override_time, &remaining);
	printf(", %lu.%06lu s remaining\n", remaining.tv_sec, remaining.tv_usec);
}


#define test_tdef_fsm_state_chg(tdefs, NEXT_STATE) do { \
		const struct osmo_tdef_state_timeout *st = osmo_tdef_get_state_timeout(NEXT_STATE, \
										       test_tdef_state_timeouts); \
		int rc = osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, test_tdef_state_timeouts, tdefs, 999); \
		if (!st) { \
			printf(" --> %s (no timer configured for this state) rc=%d;\t", \
			       osmo_fsm_state_name(&test_tdef_fsm, NEXT_STATE), rc); \
		} else { \
			struct osmo_tdef *t = osmo_tdef_get_entry(tdefs, st->T); \
			printf(" --> %s (configured as T%d%s %lu %s) rc=%d;\t", \
			       osmo_fsm_state_name(&test_tdef_fsm, NEXT_STATE), \
			       st->T, st->keep_timer ? "(keep_timer)" : "", \
			       t? t->val : 0, t? osmo_tdef_unit_name(t->unit) : "-", \
			       rc); \
		} \
		print_fsm_state(fi); \
	} while(0)



static void test_tdef_state_timeout(bool test_range)
{
	struct osmo_fsm_inst *fi;
	unsigned long m_secs;
	printf("\n%s()\n", __func__);

	osmo_tdefs_reset(tdefs);

	fake_time_start();

	fi = osmo_fsm_inst_alloc(&test_tdef_fsm, ctx, NULL, LOGL_DEBUG, __func__);
	OSMO_ASSERT(fi);
	print_fsm_state(fi);

	test_tdef_fsm_state_chg(tdefs, S_A);
	test_tdef_fsm_state_chg(tdefs, S_B);
	test_tdef_fsm_state_chg(tdefs, S_C);
	test_tdef_fsm_state_chg(tdefs, S_D);

	test_tdef_fsm_state_chg(tdefs, S_G);
	test_tdef_fsm_state_chg(tdefs, S_H);
	test_tdef_fsm_state_chg(tdefs, S_I);
	test_tdef_fsm_state_chg(tdefs, S_J);

	printf("- test keep_timer:\n");
	fake_time_passes(123, 45678);
	print_fsm_state(fi);
	test_tdef_fsm_state_chg(tdefs, S_K);
	test_tdef_fsm_state_chg(tdefs, S_A);
	fake_time_passes(23, 45678);
	print_fsm_state(fi);
	test_tdef_fsm_state_chg(tdefs, S_K);

	test_tdef_fsm_state_chg(tdefs, S_A);
	fake_time_passes(23, 45678);
	print_fsm_state(fi);
	test_tdef_fsm_state_chg(tdefs, S_L);
	test_tdef_fsm_state_chg(tdefs, S_O);
	test_tdef_fsm_state_chg(tdefs, S_L);

	printf("- test T=0:\n");
	test_tdef_fsm_state_chg(tdefs, S_O);

	printf("- test no timer:\n");
	test_tdef_fsm_state_chg(tdefs, S_X);

	printf("- test undefined timer, using default_val arg of osmo_tdef_fsm_inst_state_chg(), here passed as 999:\n");
	test_tdef_fsm_state_chg(tdefs, S_Y);

	/* the range of unsigned long is architecture dependent. This test can be invoked manually to see whether
	 * clamping the timeout values works, but the output will be of varying lengths depending on the system's
	 * unsigned long range, and would cause differences in expected output. */
	if (test_range) {
		struct osmo_tdef *m;

		printf("- test large T:\n");
		test_tdef_fsm_state_chg(tdefs_range, S_M);

		printf("- test T<0:\n");
		test_tdef_fsm_state_chg(tdefs_range, S_N);

		printf("- test range:\n");
		test_tdef_fsm_state_chg(tdefs_range, S_M);

		m = osmo_tdef_get_entry(tdefs_range, INT_MAX);
		OSMO_ASSERT(m);

		/* sweep through all the bits, shifting in 0xfffff.. from the right. */
		m_secs = 0;
		do {
			m_secs = (m_secs << 1) + 1;
			switch (m_secs) {
			case 0x7fff:
				printf("--- int32_t max ---\n");
				break;
			case 0xffff:
				printf("--- uint32_t max ---\n");
				break;
			case 0x7fffffff:
				printf("--- int64_t max ---\n");
				break;
			case 0xffffffff:
				printf("--- uint64_t max ---\n");
				break;
			default:
				break;
			}

			m->val = m_secs - 1;
			test_tdef_fsm_state_chg(tdefs_range, S_M);
			m->val = m_secs;
			test_tdef_fsm_state_chg(tdefs_range, S_M);
			m->val = m_secs + 1;
			test_tdef_fsm_state_chg(tdefs_range, S_M);
		} while (m_secs < ULONG_MAX);
	}

	printf("- test disallowed transition:\n");
	test_tdef_fsm_state_chg(tdefs, S_Z);
	test_tdef_fsm_state_chg(tdefs, S_B);
	test_tdef_fsm_state_chg(tdefs, S_C);
	test_tdef_fsm_state_chg(tdefs, S_D);
}

int main(int argc, char **argv)
{
	ctx = talloc_named_const(NULL, 0, "tdef_test.c");
	osmo_init_logging2(ctx, NULL);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	OSMO_ASSERT(osmo_fsm_register(&test_tdef_fsm) == 0);

	test_tdef_get(argc > 1);
	test_tdef_get_nonexisting();
	test_tdef_set_and_get();
	/* Run range test iff any argument is passed on the cmdline. For the rationale, see the comment in
	 * test_tdef_state_timeout(). */
	test_tdef_state_timeout(argc > 1);

	return EXIT_SUCCESS;
}
