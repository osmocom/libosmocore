#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/select.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
#include <osmocom/ctrl/control_if.h>

enum {
	DMAIN,
};

static void *g_ctx;

static int safe_strcmp(const char *a, const char *b)
{
	if (!a || !b)
		return a == b ? 0 : 1;
	return strcmp(a, b);
}

enum test_fsm_states {
	ST_NULL = 0,
	ST_ONE,
	ST_TWO,
};

enum test_fsm_evt {
	EV_A,
	EV_B,
};

static const struct value_string test_fsm_event_names[] = {
	OSMO_VALUE_STRING(EV_A),
	OSMO_VALUE_STRING(EV_B),
	{ 0, NULL }
};

static void test_fsm_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case EV_A:
		OSMO_ASSERT(data == (void *) 23);
		osmo_fsm_inst_state_chg(fi, ST_ONE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static void test_fsm_one(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case EV_B:
		OSMO_ASSERT(data == (void *) 42);
		osmo_fsm_inst_state_chg(fi,ST_TWO, 1, 2342);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static bool main_loop_run = true;

static int test_fsm_tmr_cb(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi->T == 2342);
	OSMO_ASSERT(fi->state == ST_TWO);
	LOGP(DMAIN, LOGL_INFO, "Timer\n");

	main_loop_run = false;

	return 0;
}

static struct osmo_fsm_state test_fsm_states[] = {
	[ST_NULL] = {
		.in_event_mask = (1 << EV_A),
		.out_state_mask = (1 << ST_ONE),
		.name = "NULL",
		.action = test_fsm_null,
	},
	[ST_ONE]= {
		.in_event_mask = (1 << EV_B),
		.out_state_mask = (1 << ST_TWO),
		.name = "ONE",
		.action= test_fsm_one,
	},
	[ST_TWO]= {
		.in_event_mask = 0,
		.name = "TWO",
		.action = NULL,
	},
};

static struct osmo_fsm fsm = {
	.name = "Test_FSM",
	.states = test_fsm_states,
	.num_states = ARRAY_SIZE(test_fsm_states),
	.log_subsys = DMAIN,
	.event_names = test_fsm_event_names,
};

static struct ctrl_handle *g_ctrl;

static struct ctrl_cmd *exec_ctrl_cmd(const char *cmdstr)
{
	struct ctrl_cmd *cmd;

	cmd = ctrl_cmd_exec_from_string(g_ctrl, cmdstr);
	OSMO_ASSERT(cmd);

	return cmd;
}

static void assert_cmd_reply(const char *cmdstr, const char *expres)
{
	struct ctrl_cmd *cmd;

	cmd = exec_ctrl_cmd(cmdstr);
	if (safe_strcmp(cmd->reply, expres)) {
		fprintf(stderr, "Reply '%s' doesn't match expected '%s'\n", cmd->reply, expres);
		OSMO_ASSERT(0);
	}
	talloc_free(cmd);
}

static struct osmo_fsm_inst *foo(void)
{
	struct osmo_fsm_inst *fi;
	struct ctrl_cmd *cmd;

	LOGP(DMAIN, LOGL_INFO, "Checking FSM allocation\n");
	fi = osmo_fsm_inst_alloc(&fsm, g_ctx, NULL, LOGL_DEBUG, "my_id");
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &fsm);
	OSMO_ASSERT(!strncmp(osmo_fsm_inst_name(fi), fsm.name, strlen(fsm.name)));
	OSMO_ASSERT(fi->state == ST_NULL);
	OSMO_ASSERT(fi->log_level == LOGL_DEBUG);
	assert_cmd_reply("GET 1 fsm.Test_FSM.id.my_id.state", "NULL");
	assert_cmd_reply("GET 1 fsm.Test_FSM.id.my_id.timer", "0,0,0");

	/* Try invalid state transition */
	osmo_fsm_inst_dispatch(fi, EV_B, (void *) 42);
	OSMO_ASSERT(fi->state == ST_NULL);
	assert_cmd_reply("GET 1 fsm.Test_FSM.id.my_id.state", "NULL");


	/* Legitimate state transition */
	osmo_fsm_inst_dispatch(fi, EV_A, (void *) 23);
	OSMO_ASSERT(fi->state == ST_ONE);
	assert_cmd_reply("GET 1 fsm.Test_FSM.id.my_id.state", "ONE");

	/* Legitimate transition with timer */
	fsm.timer_cb = test_fsm_tmr_cb;
	osmo_fsm_inst_dispatch(fi, EV_B, (void *) 42);
	OSMO_ASSERT(fi->state == ST_TWO);
	assert_cmd_reply("GET 1 fsm.Test_FSM.id.my_id.state", "TWO");

	cmd = exec_ctrl_cmd("GET 2 fsm.Test_FSM.id.my_id.dump");
	const char *exp = "'Test_FSM(my_id)','my_id','DEBUG','TWO',2342,timeout_sec=";
	OSMO_ASSERT(!strncmp(cmd->reply, exp, strlen(exp)));
	talloc_free(cmd);

	return fi;
}

static void test_id_api(void)
{
	struct osmo_fsm_inst *fi;

	fprintf(stderr, "\n--- %s()\n", __func__);

/* Assert the instance has this name and can be looked up by it */
#define assert_name(expected_name) \
do { \
	const char *name = osmo_fsm_inst_name(fi); \
	fprintf(stderr, "  osmo_fsm_inst_name() == %s\n", osmo_quote_str(name, -1)); \
	if (safe_strcmp(name, expected_name)) { \
		fprintf(stderr, "    ERROR: expected %s\n", osmo_quote_str(expected_name, -1)); \
		OSMO_ASSERT(false); \
	} \
	OSMO_ASSERT(osmo_fsm_inst_find_by_name(&fsm, expected_name) == fi); \
	fprintf(stderr, "  osmo_fsm_inst_find_by_name(%s) == fi\n", osmo_quote_str(expected_name, -1)); \
} while(0)

/* Assert the instance can be looked up by this id string */
#define assert_id(expected_id) \
do { \
	OSMO_ASSERT(osmo_fsm_inst_find_by_id(&fsm, expected_id) == fi); \
	fprintf(stderr, "  osmo_fsm_inst_find_by_id(%s) == fi\n", osmo_quote_str(expected_id, -1)); \
} while(0)

/* Update the id, assert the proper rc, and expect a resulting fsm inst name + lookup */
#define test_id(new_id, expect_rc, expect_name_suffix) do { \
		int rc; \
		fprintf(stderr, "osmo_fsm_inst_update_id(%s)\n", osmo_quote_str(new_id, -1)); \
		rc = osmo_fsm_inst_update_id(fi, new_id); \
		fprintf(stderr, "    rc == %d", rc); \
		if (rc == (expect_rc)) \
			fprintf(stderr, ", ok\n"); \
		else { \
			fprintf(stderr, ", ERROR: expected rc == %d\n", expect_rc); \
			OSMO_ASSERT(rc == expect_rc); \
		} \
		assert_name("Test_FSM" expect_name_suffix); \
	}while (0)

/* Successfully set a new id, along with name and id lookup assertions */
#define change_id(new_id) \
		test_id(new_id, 0, "(" new_id ")"); \
		assert_id(new_id)

	/* allocate FSM instance without id, there should be a name without id */
	fi = osmo_fsm_inst_alloc(&fsm, g_ctx, NULL, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);
	assert_name("Test_FSM");

	change_id("my_id");
	change_id("another_id");

	test_id(NULL, 0, "");
	/* clear already cleared id */
	test_id(NULL, 0, "");

	change_id("arbitrary_id");

	/* clear id by empty string doesn't work */
	test_id("", -EINVAL, "(arbitrary_id)");

	test_id("invalid.id", -EINVAL, "(arbitrary_id)");

	fprintf(stderr, "--- id format tests...\n");
/* Update the id, assert the proper rc, and expect a resulting fsm inst name + lookup */
#define test_id_f(expect_rc, expect_name_suffix, new_id_fmt, args...) do { \
		int rc; \
		fprintf(stderr, "osmo_fsm_inst_update_id_f(%s, " #args ")\n", \
			osmo_quote_str(new_id_fmt, -1)); \
		rc = osmo_fsm_inst_update_id_f(fi, new_id_fmt, ## args); \
		fprintf(stderr, "    rc == %d", rc); \
		if (rc == (expect_rc)) \
			fprintf(stderr, ", ok\n"); \
		else { \
			fprintf(stderr, ", ERROR: expected rc == %d\n", expect_rc); \
			OSMO_ASSERT(rc == expect_rc); \
		} \
		assert_name("Test_FSM" expect_name_suffix); \
	}while (0)

	test_id_f(-EINVAL, "(arbitrary_id)", "format%cid", '.');
	test_id_f(-EINVAL, "(arbitrary_id)", "%s", "");
	test_id_f(0, "(format23id42)", "format%xid%d", 0x23, 42);
	test_id_f(0, "", NULL);
	test_id_f(0, "", NULL);
	test_id_f(0, "(arbitrary_id)", "%s%c%s", "arbitrary", '_', "id");

	fprintf(stderr, "\n--- %s() done\n\n", __func__);

	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, NULL);
}

const struct timeval fake_time_start_time = { 123, 456 };

#define fake_time_passes(secs, usecs) do \
{ \
	struct timeval diff; \
	osmo_gettimeofday_override_add(secs, usecs); \
	osmo_clock_override_add(CLOCK_MONOTONIC, secs, usecs * 1000); \
	timersub(&osmo_gettimeofday_override_time, &fake_time_start_time, &diff); \
	fprintf(stderr, "Total time passed: %d.%06d s\n", \
		(int)diff.tv_sec, (int)diff.tv_usec); \
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
	fake_time_passes(0, 0);
}

static int timeout_fired = 0;
static int timer_cb(struct osmo_fsm_inst *fi)
{
	timeout_fired = fi->T;
	return 0;
}

static void test_state_chg_keep_timer(void)
{
	struct osmo_fsm_inst *fi;

	fprintf(stderr, "\n--- %s()\n", __func__);

	fsm.timer_cb = timer_cb;

	/* Test that no timer remains no timer */
	fi = osmo_fsm_inst_alloc(&fsm, g_ctx, NULL, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);

	osmo_fsm_inst_state_chg(fi, ST_ONE, 0, 0);
	timeout_fired = -1;

	osmo_fsm_inst_state_chg_keep_timer(fi, ST_TWO);

	OSMO_ASSERT(timeout_fired == -1);
	OSMO_ASSERT(fi->T == 0);

	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, NULL);

	/* Test that a set time continues with exact precision */
	fake_time_start();
	fi = osmo_fsm_inst_alloc(&fsm, g_ctx, NULL, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);

	osmo_fsm_inst_state_chg(fi, ST_ONE, 10, 10);

	timeout_fired = -1;

	fake_time_passes(2, 342);
	osmo_fsm_inst_state_chg_keep_timer(fi, ST_TWO);

	fake_time_passes(0, 0);
	OSMO_ASSERT(timeout_fired == -1);

	fake_time_passes(7, 1000000 - 342 - 1);
	OSMO_ASSERT(timeout_fired == -1);

	fake_time_passes(0, 1);
	OSMO_ASSERT(timeout_fired == 10);

	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, NULL);

	fprintf(stderr, "--- %s() done\n", __func__);
}

static void test_state_chg_T(void)
{
	struct osmo_fsm_inst *fi;

	fprintf(stderr, "\n--- %s()\n", __func__);

	fsm.timer_cb = NULL;

	/* Test setting to timeout_secs = 0, T = 0 */
	fi = osmo_fsm_inst_alloc(&fsm, g_ctx, NULL, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);

	osmo_fsm_inst_state_chg(fi, ST_ONE, 23, 42);
	printf("T = %d\n", fi->T);
	OSMO_ASSERT(fi->T == 42);
	osmo_fsm_inst_state_chg(fi, ST_TWO, 0, 0);
	printf("T = %d\n", fi->T);
	OSMO_ASSERT(fi->T == 0);

	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, NULL);

	/* Test setting to timeout_secs = 0, T != 0 */
	fi = osmo_fsm_inst_alloc(&fsm, g_ctx, NULL, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);

	osmo_fsm_inst_state_chg(fi, ST_ONE, 23, 42);
	printf("T = %d\n", fi->T);
	OSMO_ASSERT(fi->T == 42);
	osmo_fsm_inst_state_chg(fi, ST_TWO, 0, 11);
	printf("T = %d\n", fi->T);
	OSMO_ASSERT(fi->T == 11);

	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, NULL);

	fprintf(stderr, "--- %s() done\n", __func__);
}

/* Test setting a state timeout with second granularity */
static void test_state_chg_Ts(void)
{
	struct osmo_fsm_inst *fi;

	fprintf(stderr, "\n--- %s()\n", __func__);

	fsm.timer_cb = &timer_cb;
	timeout_fired = -1;
	fake_time_start();

	fi = osmo_fsm_inst_alloc(&fsm, g_ctx, NULL, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);

	osmo_fsm_inst_state_chg(fi, ST_ONE, 8, 4242);
	OSMO_ASSERT(timeout_fired == -1);

	fake_time_passes(3, 0); /* +3s */
	OSMO_ASSERT(timeout_fired == -1);

	fake_time_passes(2, 500000); /* +2.5s */
	OSMO_ASSERT(timeout_fired == -1);

	fake_time_passes(2, 500000); /* +2.5s */
	OSMO_ASSERT(timeout_fired == 4242);

	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, NULL);

	fprintf(stderr, "--- %s() done\n", __func__);
}

/* Test setting a state timeout with millisecond granularity */
static void test_state_chg_Tms(void)
{
	struct osmo_fsm_inst *fi;

	fprintf(stderr, "\n--- %s()\n", __func__);

	fsm.timer_cb = &timer_cb;
	timeout_fired = -1;
	fake_time_start();

	fi = osmo_fsm_inst_alloc(&fsm, g_ctx, NULL, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);

	osmo_fsm_inst_state_chg_ms(fi, ST_ONE, 1337, 4242); /* 1s 337ms */
	OSMO_ASSERT(timeout_fired == -1);

	fake_time_passes(0, 500000); /* +500ms, 500ms total */
	OSMO_ASSERT(timeout_fired == -1);

	fake_time_passes(0, 250000); /* +250ms, 750ms total */
	OSMO_ASSERT(timeout_fired == -1);

	fake_time_passes(0, 350000); /* +350ms, 1s 100ms total */
	OSMO_ASSERT(timeout_fired == -1);

	fake_time_passes(0, 200000); /* +200ms, 1s 300ms total */
	OSMO_ASSERT(timeout_fired == -1);

	fake_time_passes(0, 37000); /* +37ms, 1s 337ms total */
	OSMO_ASSERT(timeout_fired == 4242);

	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, NULL);

	fprintf(stderr, "--- %s() done\n", __func__);
}

static const struct log_info_cat default_categories[] = {
	[DMAIN] = {
		.name = "DMAIN",
		.description = "Main",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	struct log_target *stderr_target;
	struct osmo_fsm_inst *finst;

	osmo_fsm_log_addr(false);

	/* Using fake time to get deterministic timeout logging */
	osmo_fsm_log_timeouts(true);

	log_init(&log_info, NULL);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);
	log_set_print_filename2(stderr_target, LOG_FILENAME_NONE);
	log_set_use_color(stderr_target, 0);
	log_set_print_category(stderr_target, 0);
	log_set_print_category_hex(stderr_target, 0);
	g_ctrl = ctrl_handle_alloc(NULL, NULL, NULL);

	g_ctx = NULL;
	OSMO_ASSERT(osmo_fsm_find_by_name(fsm.name) == NULL);
	OSMO_ASSERT(osmo_fsm_register(&fsm) == 0);
	OSMO_ASSERT(osmo_fsm_find_by_name(fsm.name) == &fsm);

	OSMO_ASSERT(osmo_fsm_inst_find_by_name(&fsm, "my_id") == NULL);
	finst = foo();

	while (main_loop_run) {
		osmo_select_main(0);
	}
	osmo_fsm_inst_free(finst);

	test_id_api();
	test_state_chg_keep_timer();
	test_state_chg_T();
	test_state_chg_Ts();
	test_state_chg_Tms();

	osmo_fsm_unregister(&fsm);
	exit(0);
}
