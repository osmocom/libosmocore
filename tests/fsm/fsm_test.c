#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/select.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
#include <osmocom/ctrl/control_if.h>

enum {
	DMAIN,
};

static void *g_ctx;


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
	if (strcmp(cmd->reply, expres)) {
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
	OSMO_ASSERT(osmo_fsm_inst_find_by_id(&fsm, "my_id") == finst);
	OSMO_ASSERT(osmo_fsm_inst_find_by_name(&fsm, "Test_FSM(my_id)") == finst);
	OSMO_ASSERT(osmo_fsm_inst_update_id(finst, "another_id") == 0);
	OSMO_ASSERT(osmo_fsm_inst_find_by_id(&fsm, "another_id") == finst);
	OSMO_ASSERT(osmo_fsm_inst_find_by_name(&fsm, "Test_FSM(another_id)") == finst);
	OSMO_ASSERT(osmo_fsm_inst_update_id(finst, "my_id") == 0);

	while (main_loop_run) {
		osmo_select_main(0);
	}
	osmo_fsm_inst_free(finst);
	osmo_fsm_unregister(&fsm);
	exit(0);
}
