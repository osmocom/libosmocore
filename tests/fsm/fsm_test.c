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

static void test_id_api()
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

	fprintf(stderr, "\n--- %s() done\n\n", __func__);

	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, NULL);
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

	log_init(&log_info, NULL);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);
	log_set_print_filename(stderr_target, 0);
	g_ctrl = ctrl_handle_alloc(NULL, NULL, NULL);

	g_ctx = NULL;
	OSMO_ASSERT(osmo_fsm_find_by_name(fsm.name) == NULL);
	osmo_fsm_register(&fsm);
	OSMO_ASSERT(osmo_fsm_find_by_name(fsm.name) == &fsm);

	OSMO_ASSERT(osmo_fsm_inst_find_by_name(&fsm, "my_id") == NULL);
	finst = foo();

	while (main_loop_run) {
		osmo_select_main(0);
	}
	osmo_fsm_inst_free(finst);

	test_id_api();

	osmo_fsm_unregister(&fsm);
	exit(0);
}
