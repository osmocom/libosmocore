/* (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Janosch Hofmeyr <nhofmeyr@sysmocom.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <inttypes.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/time_cc.h>

enum my_ctrs {
	CTR_CEIL,
	CTR_ROUND,
	CTR_FLOOR,
};

const struct rate_ctr_desc my_ctr_desc[] = {
	[CTR_CEIL] =	{"ceil", "testing round_threshold_usec = 1"},
	[CTR_ROUND] =	{"round", "testing round_threshold_usec = 0 = gran_usec/2"},
	[CTR_FLOOR] =	{"floor", "testing round_threshold_usec = gran_usec"},
};

const struct rate_ctr_group_desc my_ctrg_desc = {
	"time_cc_test",
	"Counters for osmo_time_cc test",
	0,
	ARRAY_SIZE(my_ctr_desc),
	my_ctr_desc,
};

struct rate_ctr_group *my_ctrg;


enum my_obj_timers {
	T_GRAN = -23,
	T_ROUND_THRESH = -24,
	T_FORGET_SUM = -25,
};

struct osmo_tdef g_my_obj_tdefs[] = {
	{ .T = T_GRAN, .default_val = 0, .unit = OSMO_TDEF_MS, .desc = "flag_cc granularity, or zero for 1 second" },
	{ .T = T_ROUND_THRESH, .default_val = 0, .unit = OSMO_TDEF_MS,
		.desc = "flag_cc rounding threshold, or zero for half a granularity" },
	{ .T = T_FORGET_SUM, .default_val = 0, .unit = OSMO_TDEF_MS,
		.desc = "flag_cc inactivity forget period, or zero to not forget any timings" },
	{}
};


struct my_obj {
	struct osmo_time_cc flag_cc_ceil;
	struct osmo_time_cc flag_cc_round;
	struct osmo_time_cc flag_cc_floor;
};

void my_obj_init(struct my_obj *my_obj)
{
	osmo_time_cc_init(&my_obj->flag_cc_ceil);
	my_obj->flag_cc_ceil.cfg = (struct osmo_time_cc_cfg){
		.rate_ctr = rate_ctr_group_get_ctr(my_ctrg, CTR_CEIL),
		.round_threshold_usec = 1,
		.T_gran = T_GRAN,
		.T_forget_sum = T_FORGET_SUM,
		.T_defs = g_my_obj_tdefs,
	};

	osmo_time_cc_init(&my_obj->flag_cc_round);
	my_obj->flag_cc_round.cfg = (struct osmo_time_cc_cfg){
		.rate_ctr = rate_ctr_group_get_ctr(my_ctrg, CTR_ROUND),
		.T_gran = T_GRAN,
		.T_round_threshold = T_ROUND_THRESH,
		.T_forget_sum = T_FORGET_SUM,
		.T_defs = g_my_obj_tdefs,
	};

	osmo_time_cc_init(&my_obj->flag_cc_floor);
	my_obj->flag_cc_floor.cfg = (struct osmo_time_cc_cfg){
		.rate_ctr = rate_ctr_group_get_ctr(my_ctrg, CTR_FLOOR),
		.round_threshold_usec = UINT64_MAX, /* always >= gran_usec */
		.T_gran = T_GRAN,
		.T_forget_sum = T_FORGET_SUM,
		.T_defs = g_my_obj_tdefs,
	};
}

void my_obj_event(struct my_obj *my_obj, bool flag)
{
	osmo_time_cc_set_flag(&my_obj->flag_cc_ceil, flag);
	osmo_time_cc_set_flag(&my_obj->flag_cc_round, flag);
	osmo_time_cc_set_flag(&my_obj->flag_cc_floor, flag);
}

void my_obj_destruct(struct my_obj *my_obj)
{
	osmo_time_cc_cleanup(&my_obj->flag_cc_ceil);
	osmo_time_cc_cleanup(&my_obj->flag_cc_round);
	osmo_time_cc_cleanup(&my_obj->flag_cc_floor);
}

static const struct log_info_cat log_categories[] = {
};

static const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main(int argc, char **argv)
{
	void *ctx = talloc_named_const(NULL, 0, "time_cc_test");
	struct timespec *now;
	struct my_obj my_obj = {0};

	osmo_init_logging2(ctx, &log_info);

	/* enable override for CLOCK_MONOTONIC */
	osmo_clock_override_enable(CLOCK_MONOTONIC, true);
	now = osmo_clock_override_gettimespec(CLOCK_MONOTONIC);
	now->tv_sec = 23000;
	now->tv_nsec = 0;

	/* enable override for osmo_gettimeofday(), for osmo_timer_schedule() */
	osmo_gettimeofday_override = true;
	osmo_gettimeofday_override_time = (struct timeval){23000, 0};

	my_ctrg = rate_ctr_group_alloc(ctx, &my_ctrg_desc, 0);

#define CHECK_RATE_CTRS(exp_ceil, exp_round, exp_floor) do { \
		printf("%d CHECK_RATE_CTRS(" #exp_ceil ", " #exp_round ", " #exp_floor ")", \
		       my_obj.flag_cc_round.flag_state); \
		while (osmo_select_main_ctx(1) > 0); \
		if (exp_ceil != my_obj.flag_cc_ceil.cfg.rate_ctr->current \
		    || exp_round != my_obj.flag_cc_round.cfg.rate_ctr->current \
		    || exp_floor != my_obj.flag_cc_floor.cfg.rate_ctr->current) \
			printf("\n     ERROR on line %d: ctr_ceil=%"PRIu64" ctr_round=%"PRIu64" ctr_floor=%"PRIu64"\n", \
			       __LINE__, \
			       my_obj.flag_cc_ceil.cfg.rate_ctr->current, \
			       my_obj.flag_cc_round.cfg.rate_ctr->current, \
			       my_obj.flag_cc_floor.cfg.rate_ctr->current); \
		else \
			printf(" ok\n"); \
	} while (0)

#define ADD_MILLISECS_NO_SELECT(ms) do { \
		osmo_clock_override_add(CLOCK_MONOTONIC, ms / 1000, (uint64_t)(ms % 1000) * 1000000); \
		osmo_gettimeofday_override_add(ms / 1000, (uint64_t)(ms % 1000) * 1000); \
		printf("%d ADD_MILLISECS(" #ms ") --> %ld.%03ld", my_obj.flag_cc_round.flag_state, \
		       now->tv_sec, now->tv_nsec/1000000); \
		printf("\n"); \
	} while (0)

#define ADD_MILLISECS(ms) do { \
		ADD_MILLISECS_NO_SELECT(ms); \
		while (osmo_select_main_ctx(1) > 0); \
	} while (0)

#define FLAG(VAL) do { \
		printf("  flag: %s -> %s\n", my_obj.flag_cc_round.flag_state ? "TRUE" : "FALSE", VAL ? "TRUE" : "FALSE"); \
		my_obj_event(&my_obj, VAL); \
	} while (0)

	/*
	 *                        sum ^
	 *                            |                                          ________
	 *                            |                                         /
	 *                            |                                        /
	 *                            |                                       /
	 *                   3*gran --+--------------------------------------+
	 *                            |                                     /:
	 *                            |                                    / :
	 *                            | - - - - - - - - - - - - - - - - - /  :
	 *                            |                                  /.  :
	 *                            |                                 / .  :
	 *                   2*gran --+--------------------------------+  .  :
	 *                            |                               /:  .  :
	 *                            |                              / :  .  :
	 *                            | - - - - - - - - - -_________/  :  .  :
	 *                            |                   /         .  :  .  :
	 *                            |                  /          .  :  .  :
	 *                   1*gran --+-----------------+           .  :  .  :
	 *                            |                /:           .  :  .  :
	 *                            |               / :           .  :  .  :
	 *                            | - - - - - - -/  :           .  :  .  :
	 *                            |             /.  :           .  :  .  :
	 *                            | ....-------' .  :           .  :  .  :
	 *                         0  +----------------------------------------------------------> elapsed time
	 *                                           .  :           .  :  .  :
	 *                               _   _      _______         ____________
	 *                   flag:    __| |_| |____| .  :  |_______|.  :  .  :  |__________
	 *                            f t f t f    t .  :  f       t.  :  .  :  f
	 *   round_threshold_usec       :            .  :           .  :  .  :
	 *                 = 1 usec:  0  1           .  :2          .  :3 .  :4  = "ceil()"
	 *       = 0 == gran_usec/2:  0              1  :           2  :  3  :   = "round()"
	 *              = gran_usec:  0                 1              2     3   = "floor()"
	 */

	printf("\n----------- cumulating time, without forget_sum\n\n");

	my_obj_init(&my_obj);
	CHECK_RATE_CTRS(0, 0, 0);

	ADD_MILLISECS(100);
	CHECK_RATE_CTRS(0, 0, 0);

	FLAG(true);
	/* flag has just turned true the first time */
	CHECK_RATE_CTRS(0, 0, 0);
	ADD_MILLISECS(1);
	/* flag has been true for 0.001s */
	CHECK_RATE_CTRS(1, 0, 0);
	ADD_MILLISECS(99);
	/* flag has been true for 0.1s */
	CHECK_RATE_CTRS(1, 0, 0);
	FLAG(false);
	CHECK_RATE_CTRS(1, 0, 0);

	ADD_MILLISECS(100);

	CHECK_RATE_CTRS(1, 0, 0);
	FLAG(true);
	CHECK_RATE_CTRS(1, 0, 0);
	ADD_MILLISECS(100);
	/* flag has been true for 0.2s */
	CHECK_RATE_CTRS(1, 0, 0);
	FLAG(false);
	CHECK_RATE_CTRS(1, 0, 0);

	ADD_MILLISECS(300);

	CHECK_RATE_CTRS(1, 0, 0);
	FLAG(true);
	CHECK_RATE_CTRS(1, 0, 0);
	ADD_MILLISECS(299);
	/* flag has been true for 0.499s */
	CHECK_RATE_CTRS(1, 0, 0);
	ADD_MILLISECS(1);
	/* flag has been true for 0.5s */
	CHECK_RATE_CTRS(1, 1, 0);
	ADD_MILLISECS(499);
	/* flag has been true for 0.999s */
	CHECK_RATE_CTRS(1, 1, 0);
	ADD_MILLISECS(1);
	/* flag has been true for 1.0s */
	CHECK_RATE_CTRS(1, 1, 1);
	ADD_MILLISECS(1);
	/* flag has been true for 1.001s */
	CHECK_RATE_CTRS(2, 1, 1);
	ADD_MILLISECS(299);
	/* flag has been true for 1.3s */
	CHECK_RATE_CTRS(2, 1, 1);
	FLAG(false);
	CHECK_RATE_CTRS(2, 1, 1);

	ADD_MILLISECS(400);

	CHECK_RATE_CTRS(2, 1, 1);
	FLAG(true);
	CHECK_RATE_CTRS(2, 1, 1);
	ADD_MILLISECS(199);
	/* flag has been true for 1.499s */
	CHECK_RATE_CTRS(2, 1, 1);
	ADD_MILLISECS(2);
	/* flag has been true for 1.501s */
	CHECK_RATE_CTRS(2, 2, 1);
	ADD_MILLISECS(498);
	/* flag has been true for 1.999s */
	CHECK_RATE_CTRS(2, 2, 1);
	ADD_MILLISECS(2);
	/* flag has been true for 2.001s */
	CHECK_RATE_CTRS(3, 2, 2);
	ADD_MILLISECS(500);
	/* flag has been true for 2.501s */
	CHECK_RATE_CTRS(3, 3, 2);
	ADD_MILLISECS(498);
	/* flag has been true for 2.999s */
	CHECK_RATE_CTRS(3, 3, 2);
	ADD_MILLISECS(3);
	/* flag has been true for 3.003s */
	CHECK_RATE_CTRS(4, 3, 3);
	ADD_MILLISECS(200);
	/* flag has been true for 3.203s */
	CHECK_RATE_CTRS(4, 3, 3);
	FLAG(false);
	CHECK_RATE_CTRS(4, 3, 3);

	ADD_MILLISECS(4321);
	CHECK_RATE_CTRS(4, 3, 3);

	FLAG(true);
	CHECK_RATE_CTRS(4, 3, 3);
	ADD_MILLISECS(5678);
	CHECK_RATE_CTRS(9, 9, 8);
	FLAG(false);
	CHECK_RATE_CTRS(9, 9, 8);

	my_obj_destruct(&my_obj);
	rate_ctr_group_reset(my_ctrg);

	printf("\n----------- test forget_sum_usec\n\n");
	osmo_tdef_set(g_my_obj_tdefs, T_FORGET_SUM, 10, OSMO_TDEF_S);

	now->tv_sec = 23000;
	now->tv_nsec = 0;
	osmo_gettimeofday_override_time = (struct timeval){23000, 0};

	my_obj_init(&my_obj);

	CHECK_RATE_CTRS(0, 0, 0);

	FLAG(true);
	/* flag has just turned true the first time */
	CHECK_RATE_CTRS(0, 0, 0);
	ADD_MILLISECS(100);
	/* flag has been true for 0.1s */
	CHECK_RATE_CTRS(1, 0, 0);
	FLAG(false);
	CHECK_RATE_CTRS(1, 0, 0);

	ADD_MILLISECS(1000);
	/* 1 s of being false, forget_sum_usec has not yet occurred */
	CHECK_RATE_CTRS(1, 0, 0);

	ADD_MILLISECS(8999);
	/* 9.999 s of being false, forget_sum_usec has not yet occurred */
	CHECK_RATE_CTRS(1, 0, 0);

	ADD_MILLISECS(1);
	/* 10 s of being false, forget_sum_usec has occurred */
	CHECK_RATE_CTRS(1, 0, 0);

	FLAG(true);
	CHECK_RATE_CTRS(1, 0, 0);
	ADD_MILLISECS(1);
	/* Since previous sums were forgotton, ceil() triggers again */
	CHECK_RATE_CTRS(2, 0, 0);
	/* If the sum had not been forgotten, adding 400 ms to the initial 100 ms would have triggered round(). Verify
	 * that this does not occur, since now full 500 ms are required */
	ADD_MILLISECS(399);
	CHECK_RATE_CTRS(2, 0, 0);
	/* Adding another 100 ms will trigger round() */
	ADD_MILLISECS(99);
	CHECK_RATE_CTRS(2, 0, 0);
	ADD_MILLISECS(1);
	CHECK_RATE_CTRS(2, 1, 0);
	/* If the sum had not been forgotten, adding 900 ms to the initial 100 ms would have triggered floor(). Verify
	 * that this does not occur, since now full 1000 ms are required. We already added 500 ms above. */
	ADD_MILLISECS(400);
	CHECK_RATE_CTRS(2, 1, 0);
	/* Adding another 100 ms will trigger floor() */
	ADD_MILLISECS(99);
	CHECK_RATE_CTRS(2, 1, 0);
	ADD_MILLISECS(1);
	CHECK_RATE_CTRS(2, 1, 1);

	/* Test that durations of false below forget_sum_usec never trigger a forget */
	ADD_MILLISECS(300);
	CHECK_RATE_CTRS(3, 1, 1);
	/* internal counter is now at 0.3s above the last reported rate counter */
	FLAG(false);
	ADD_MILLISECS(9999);
	FLAG(true);
	ADD_MILLISECS(25);
	FLAG(false);
	ADD_MILLISECS(9999);
	FLAG(true);
	ADD_MILLISECS(25);
	FLAG(false);
	ADD_MILLISECS(9999);
	FLAG(true);
	ADD_MILLISECS(25);
	FLAG(false);
	ADD_MILLISECS(9999);
	FLAG(true);
	ADD_MILLISECS(25);
	/* internal counter is now at 0.4s above the last reported rate counter */
	CHECK_RATE_CTRS(3, 1, 1);
	ADD_MILLISECS(100);
	CHECK_RATE_CTRS(3, 2, 1);
	ADD_MILLISECS(500);
	CHECK_RATE_CTRS(3, 2, 2);

	/* Test that repeated osmo_time_cc_set_flag(false) does not cancel a forget_sum_usec */
	ADD_MILLISECS(300);
	/* internal counter is now at 0.3s above the last reported rate counter */
	CHECK_RATE_CTRS(4, 2, 2);
	FLAG(false);
	ADD_MILLISECS(5000);
	/* Repeat 'false', must not affect forget_sum_usec */
	FLAG(false);
	ADD_MILLISECS(5000);
	CHECK_RATE_CTRS(4, 2, 2);
	/* 10 s have passed, forget_sum_usec has occurred.
	 * Hence ceil() will trigger again right away: */
	FLAG(true);
	ADD_MILLISECS(1);
	CHECK_RATE_CTRS(5, 2, 2);
	/* Adding 200 ms to the initial 300 ms would have triggered round(), but no more after forget_sum_usec */
	ADD_MILLISECS(199);
	CHECK_RATE_CTRS(5, 2, 2);
	/* Adding another 300 ms will trigger round() */
	ADD_MILLISECS(299);
	CHECK_RATE_CTRS(5, 2, 2);
	ADD_MILLISECS(1);
	CHECK_RATE_CTRS(5, 3, 2);
	/* Adding 700 ms to the initial 300 ms would have triggered ceil(), but no more after forget_sum_usec */
	ADD_MILLISECS(200);
	CHECK_RATE_CTRS(5, 3, 2);
	/* Adding another 300 ms will trigger ceil() */
	ADD_MILLISECS(299);
	CHECK_RATE_CTRS(5, 3, 2);
	ADD_MILLISECS(1);
	CHECK_RATE_CTRS(5, 3, 3);

	my_obj_destruct(&my_obj);
	rate_ctr_group_reset(my_ctrg);


	/* Verify correctness when select() lags and runs timer callbacks too late */
	printf("\n----------- cumulating time, without forget_sum, when timer cb are invoked late\n\n");
	osmo_tdef_set(g_my_obj_tdefs, T_FORGET_SUM, 0, OSMO_TDEF_S);
	now->tv_sec = 23000;
	now->tv_nsec = 0;
	osmo_gettimeofday_override_time = (struct timeval){23000, 0};

	my_obj_init(&my_obj);
	CHECK_RATE_CTRS(0, 0, 0);

	ADD_MILLISECS_NO_SELECT(100);
	CHECK_RATE_CTRS(0, 0, 0);

	FLAG(true);
	/* flag has just turned true the first time */
	CHECK_RATE_CTRS(0, 0, 0);
	ADD_MILLISECS_NO_SELECT(100);
	/* flag has been true for 0.1s */
	CHECK_RATE_CTRS(1, 0, 0);
	FLAG(false);
	CHECK_RATE_CTRS(1, 0, 0);

	ADD_MILLISECS_NO_SELECT(100);

	CHECK_RATE_CTRS(1, 0, 0);
	FLAG(true);
	CHECK_RATE_CTRS(1, 0, 0);
	ADD_MILLISECS_NO_SELECT(100);
	/* flag has been true for 0.2s */
	CHECK_RATE_CTRS(1, 0, 0);
	FLAG(false);
	CHECK_RATE_CTRS(1, 0, 0);

	ADD_MILLISECS_NO_SELECT(300);

	CHECK_RATE_CTRS(1, 0, 0);
	FLAG(true);
	CHECK_RATE_CTRS(1, 0, 0);
	ADD_MILLISECS_NO_SELECT(799);
	/* flag has been true for 0.999s */
	CHECK_RATE_CTRS(1, 1, 0);
	ADD_MILLISECS_NO_SELECT(1);
	/* flag has been true for 1.0s */
	CHECK_RATE_CTRS(1, 1, 1);
	ADD_MILLISECS_NO_SELECT(300);
	/* flag has been true for 1.3s */
	CHECK_RATE_CTRS(2, 1, 1);
	FLAG(false);
	CHECK_RATE_CTRS(2, 1, 1);

	ADD_MILLISECS_NO_SELECT(400);

	CHECK_RATE_CTRS(2, 1, 1);
	FLAG(true);
	CHECK_RATE_CTRS(2, 1, 1);
	ADD_MILLISECS_NO_SELECT(699);
	/* flag has been true for 1.999s */
	CHECK_RATE_CTRS(2, 2, 1);
	ADD_MILLISECS_NO_SELECT(1);
	/* flag has been true for 2.0s */
	CHECK_RATE_CTRS(2, 2, 2);
	ADD_MILLISECS_NO_SELECT(1);
	/* flag has been true for 2.001s */
	CHECK_RATE_CTRS(3, 2, 2);
	ADD_MILLISECS_NO_SELECT(499);
	/* flag has been true for 2.5s */
	CHECK_RATE_CTRS(3, 3, 2);
	ADD_MILLISECS_NO_SELECT(499);
	/* flag has been true for 2.999s */
	CHECK_RATE_CTRS(3, 3, 2);
	ADD_MILLISECS_NO_SELECT(1);
	/* flag has been true for 3.0s */
	CHECK_RATE_CTRS(3, 3, 3);
	ADD_MILLISECS_NO_SELECT(200);
	/* flag has been true for 3.2s */
	CHECK_RATE_CTRS(4, 3, 3);
	FLAG(false);
	CHECK_RATE_CTRS(4, 3, 3);

	ADD_MILLISECS_NO_SELECT(4321);
	CHECK_RATE_CTRS(4, 3, 3);

	FLAG(true);
	CHECK_RATE_CTRS(4, 3, 3);
	ADD_MILLISECS_NO_SELECT(5678);
	CHECK_RATE_CTRS(9, 9, 8);
	FLAG(false);
	CHECK_RATE_CTRS(9, 9, 8);

	my_obj_destruct(&my_obj);
	rate_ctr_group_reset(my_ctrg);


	printf("\n----------- test forget_sum, when timer cb are invoked late\n\n");
	osmo_tdef_set(g_my_obj_tdefs, T_FORGET_SUM, 10, OSMO_TDEF_S);

	now->tv_sec = 23000;
	now->tv_nsec = 0;
	osmo_gettimeofday_override_time = (struct timeval){23000, 0};

	my_obj_init(&my_obj);

	CHECK_RATE_CTRS(0, 0, 0);

	FLAG(true);
	/* flag has just turned true the first time */
	CHECK_RATE_CTRS(0, 0, 0);
	ADD_MILLISECS_NO_SELECT(100);
	/* flag has been true for 0.1s */
	CHECK_RATE_CTRS(1, 0, 0);
	FLAG(false);
	CHECK_RATE_CTRS(1, 0, 0);

	ADD_MILLISECS_NO_SELECT(1000);
	/* 1 s of being false, forget_sum_usec has not yet occurred */
	CHECK_RATE_CTRS(1, 0, 0);

	ADD_MILLISECS_NO_SELECT(8999);
	/* 9.999 s of being false, forget_sum_usec has not yet occurred */
	CHECK_RATE_CTRS(1, 0, 0);

	ADD_MILLISECS_NO_SELECT(1);
	/* 10 s of being false, forget_sum_usec has occurred */
	CHECK_RATE_CTRS(1, 0, 0);

	FLAG(true);
	CHECK_RATE_CTRS(1, 0, 0);
	ADD_MILLISECS_NO_SELECT(1);
	/* Since previous sums were forgotton, ceil() triggers again */
	CHECK_RATE_CTRS(2, 0, 0);
	/* If the sum had not been forgotten, adding 400 ms to the initial 100 ms would have triggered round(). Verify
	 * that this does not occur, since now full 500 ms are required */
	ADD_MILLISECS_NO_SELECT(399);
	CHECK_RATE_CTRS(2, 0, 0);
	/* Adding another 100 ms will trigger round() */
	ADD_MILLISECS_NO_SELECT(99);
	CHECK_RATE_CTRS(2, 0, 0);
	ADD_MILLISECS_NO_SELECT(1);
	CHECK_RATE_CTRS(2, 1, 0);
	/* If the sum had not been forgotten, adding 900 ms to the initial 100 ms would have triggered floor(). Verify
	 * that this does not occur, since now full 1000 ms are required. We already added 500 ms above. */
	ADD_MILLISECS_NO_SELECT(400);
	CHECK_RATE_CTRS(2, 1, 0);
	/* Adding another 100 ms will trigger floor() */
	ADD_MILLISECS_NO_SELECT(99);
	CHECK_RATE_CTRS(2, 1, 0);
	ADD_MILLISECS_NO_SELECT(1);
	CHECK_RATE_CTRS(2, 1, 1);

	/* Test that durations of false below forget_sum_usec never trigger a forget */
	ADD_MILLISECS_NO_SELECT(300);
	CHECK_RATE_CTRS(3, 1, 1);
	/* internal counter is now at 0.3s above the last reported rate counter */
	FLAG(false);
	ADD_MILLISECS_NO_SELECT(9999);
	FLAG(true);
	ADD_MILLISECS_NO_SELECT(25);
	FLAG(false);
	ADD_MILLISECS_NO_SELECT(9999);
	FLAG(true);
	ADD_MILLISECS_NO_SELECT(25);
	FLAG(false);
	ADD_MILLISECS_NO_SELECT(9999);
	FLAG(true);
	ADD_MILLISECS_NO_SELECT(25);
	FLAG(false);
	ADD_MILLISECS_NO_SELECT(9999);
	FLAG(true);
	ADD_MILLISECS_NO_SELECT(25);
	/* internal counter is now at 0.4s above the last reported rate counter */
	CHECK_RATE_CTRS(3, 1, 1);
	ADD_MILLISECS_NO_SELECT(100);
	CHECK_RATE_CTRS(3, 2, 1);
	ADD_MILLISECS_NO_SELECT(500);
	CHECK_RATE_CTRS(3, 2, 2);

	my_obj_destruct(&my_obj);
	rate_ctr_group_reset(my_ctrg);


#define SET_TDEFS(gran, round_thresh, forget_sum) do { \
		osmo_tdef_set(g_my_obj_tdefs, T_GRAN, gran, OSMO_TDEF_MS); \
		osmo_tdef_set(g_my_obj_tdefs, T_ROUND_THRESH, round_thresh, OSMO_TDEF_MS); \
		osmo_tdef_set(g_my_obj_tdefs, T_FORGET_SUM, forget_sum, OSMO_TDEF_S); \
		printf("T_defs: T_gran=%luusec T_round_threshold=%luusec T_forget_sum=%luusec\n", \
		       osmo_tdef_get(g_my_obj_tdefs, T_GRAN, OSMO_TDEF_US, -1), \
		       osmo_tdef_get(g_my_obj_tdefs, T_ROUND_THRESH, OSMO_TDEF_US, -1), \
		       osmo_tdef_get(g_my_obj_tdefs, T_FORGET_SUM, OSMO_TDEF_US, -1)); \
	} while (0)

	printf("\n----------- test T_defs\n\n");
	now->tv_sec = 23000;
	now->tv_nsec = 0;
	osmo_gettimeofday_override_time = (struct timeval){23000, 0};

	SET_TDEFS(100, 10, 0);

	my_obj_init(&my_obj);
	CHECK_RATE_CTRS(0, 0, 0);

	ADD_MILLISECS(100);
	CHECK_RATE_CTRS(0, 0, 0);

	FLAG(true);
	/* flag has just turned true the first time */
	CHECK_RATE_CTRS(0, 0, 0);
	ADD_MILLISECS(9);
	/* flag has been true for 0.009s */
	CHECK_RATE_CTRS(1, 0, 0);
	ADD_MILLISECS(1);
	/* flag has been true for 0.010s */
	CHECK_RATE_CTRS(1, 1, 0);
	ADD_MILLISECS(90);
	/* flag has been true for 0.1s */
	CHECK_RATE_CTRS(1, 1, 1);

	SET_TDEFS(200, 190, 1);
	/* gran is changed to 200ms, but still continues until the next scheduled event until the change is picked up.
	 * For ceil(), it is 1 ms ahead.
	 * For round(), it is 10 ms ahead.
	 * For floor(), it is at the next full (previous) gran 100 ms ahead.
	 * When T_defs change, all internal sums are reset to zero without reporting.
	 */
	CHECK_RATE_CTRS(1, 1, 1);
	ADD_MILLISECS(1);
	/* 1ms elapsed: ceil() picks up the T_gran change, starts anew. */
	/* elapsed: ceil 0 ms */
	CHECK_RATE_CTRS(1, 1, 1);
	ADD_MILLISECS(1);
	/* elapsed: ceil 1 ms */
	/* ceil() increments because flag has been true for more than 1 us after reset */
	CHECK_RATE_CTRS(2, 1, 1);
	ADD_MILLISECS(8);
	/* 10 ms elapsed: round() picks up the T_gran change, starts anew */
	/* elapsed: ceil 9 ms, round 0 ms */
	CHECK_RATE_CTRS(2, 1, 1);
	ADD_MILLISECS(90);
	/* 100 ms elapsed: floor() picks up the T_gran change, starts anew */
	/* elapsed: ceil 99 ms, round 90 ms, floor 0 ms */
	CHECK_RATE_CTRS(2, 1, 1);
	ADD_MILLISECS(99);
	/* elapsed: ceil 198 ms, round 189 ms, floor 99 ms */
	CHECK_RATE_CTRS(2, 1, 1);
	ADD_MILLISECS(1);
	/* elapsed: ceil 199 ms, round 190 ms, floor 100 ms */
	CHECK_RATE_CTRS(2, 2, 1);
	ADD_MILLISECS(1);
	/* elapsed: ceil 200 ms, round 191 ms, floor 101 ms */
	CHECK_RATE_CTRS(2, 2, 1);
	ADD_MILLISECS(1);
	/* elapsed: ceil 201 ms, round 192 ms, floor 102 ms */
	CHECK_RATE_CTRS(3, 2, 1);
	ADD_MILLISECS(98);
	/* elapsed: ceil 299 ms, round 290 ms, floor 200 ms */
	CHECK_RATE_CTRS(3, 2, 2);
	ADD_MILLISECS(99);
	/* elapsed: ceil 398 ms, round 389 ms, floor 299 ms */
	CHECK_RATE_CTRS(3, 2, 2);
	ADD_MILLISECS(1);
	/* elapsed: ceil 399 ms, round 390 ms, floor 300 ms */
	CHECK_RATE_CTRS(3, 3, 2);
	ADD_MILLISECS(1);
	/* elapsed: ceil 400 ms, round 391 ms, floor 301 ms */
	CHECK_RATE_CTRS(3, 3, 2);
	ADD_MILLISECS(1);
	/* elapsed: ceil 401 ms, round 392 ms, floor 302 ms */
	CHECK_RATE_CTRS(4, 3, 2);
	ADD_MILLISECS(98);
	/* elapsed: ceil 499 ms, round 490 ms, floor 400 ms */
	CHECK_RATE_CTRS(4, 3, 3);


	SET_TDEFS(100, 0, 0);
	/* T_defs change, but they only get picked up upon the next event:
	 * For ceil(), it is 102 ms ahead.
	 * For round(), it is 100 ms ahead (thresh is still 190, currently at 90).
	 * For floor(), it is 200 ms ahead.
	 * When T_defs change, all internal sums are reset to zero without reporting.
	 */
	CHECK_RATE_CTRS(4, 3, 3);
	ADD_MILLISECS(100);
	CHECK_RATE_CTRS(4, 3, 3);
	/* round() picks up the new T_defs. Internal sum resets, nothing else happens yet.
	 * round() schedules the next event 50 ms ahead. */
	ADD_MILLISECS(2);
	CHECK_RATE_CTRS(4, 3, 3);
	/* ceil() picks up the change, its next event is 1 ms ahead. */
	ADD_MILLISECS(1);
	/* ceil: 0.001
	 * round: 0.003
	 * floor: still 97 ms until it picks up the change */
	CHECK_RATE_CTRS(5, 3, 3);
	ADD_MILLISECS(46);
	CHECK_RATE_CTRS(5, 3, 3);
	ADD_MILLISECS(1);
	/* round() has first counter trigger after T_defs change. */
	CHECK_RATE_CTRS(5, 4, 3);
	/* ceil: 0.048
	 * round: 0.050
	 * floor: still 50 ms until it picks up the change */
	ADD_MILLISECS(50);
	/* floor() picks up the change. nothing happens yet. */
	/* ceil: 0.098
	 * round: 0.100
	 * floor: 0.0 */
	ADD_MILLISECS(2);
	/* ceil: 0.100
	 * round: 0.102
	 * floor: 0.002 */
	CHECK_RATE_CTRS(5, 4, 3);
	ADD_MILLISECS(1);
	/* ceil: 0.101
	 * round: 0.103
	 * floor: 0.003 */
	CHECK_RATE_CTRS(6, 4, 3);
	ADD_MILLISECS(46);
	/* ceil: 0.147
	 * round: 0.149
	 * floor: 0.049 */
	CHECK_RATE_CTRS(6, 4, 3);
	ADD_MILLISECS(1);
	/* ceil: 0.148
	 * round: 0.150
	 * floor: 0.050 */
	CHECK_RATE_CTRS(6, 5, 3);

	my_obj_destruct(&my_obj);
	rate_ctr_group_reset(my_ctrg);

	return 0;
}
