#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <osmocom/core/utils.h>
#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/ctrl/control_if.h>

static void check_type(enum ctrl_type c)
{
	const char *t = get_value_string(ctrl_type_vals, c);
	int v = get_string_value(ctrl_type_vals, t);

	printf("ctrl type %d is %s ", c, t);
	if (v < 0)
		printf("[PARSE FAILED]\n");
	else
		printf("-> %d %s\n", v, c != v ? "FAIL" : "OK");
}

struct msgb *msgb_from_string(const char *str)
{
	struct ipaccess_head *iph;
	struct ipaccess_head_ext *ipx;
	char *str_msg;
	size_t len = strlen(str) + 1;

	struct msgb *msg = msgb_alloc(1024, str);

	iph = (void*)msgb_put(msg, sizeof(*iph));
	iph->proto = IPAC_PROTO_OSMO;

	ipx = (void*)msgb_put(msg, sizeof(*ipx));
	ipx->proto = IPAC_PROTO_EXT_CTRL;

	str_msg = (char*)msgb_put(msg, len);
	msg->l2h = (void*)str_msg;
	osmo_strlcpy(str_msg, str, len);

	iph->len = msgb_length(msg);
	return msg;
}

static void *ctx = NULL;

struct one_test {
	const char *cmd_str;
	struct ctrl_cmd expect_parsed;
	const char *reply_str;
};

void assert_same_str(const char *label, const char *expect, const char *got)
{
	if ((expect == got) || (expect && got && (strcmp(expect, got) == 0))) {
		printf("%s = '%s'\n", label, osmo_escape_str(got, -1));
		return;
	}

	printf("MISMATCH for '%s':\ngot:      %s\n", label, osmo_escape_str(got, -1));
	printf("expected: %s\n", osmo_escape_str(expect, -1));
	OSMO_ASSERT(expect == got);
}

static void assert_test(struct ctrl_handle *ctrl, struct ctrl_connection *ccon, const struct one_test *t)
{
	struct ctrl_cmd *cmd;
	struct msgb *msg = msgb_from_string(t->cmd_str);
	int ctx_size_was;

	printf("test: '%s'\n", osmo_escape_str(t->cmd_str, -1));
	printf("parsing:\n");

	cmd = ctrl_cmd_parse2(ctx, msg);
	OSMO_ASSERT(cmd);

	if (t->expect_parsed.type != cmd->type) {
		printf("type mismatch: got %s\n", get_value_string(ctrl_type_vals, cmd->type));
		OSMO_ASSERT(t->expect_parsed.type == cmd->type);
	}

#define ASSERT_SAME_STR(field) \
	assert_same_str(#field, t->expect_parsed.field, cmd->field)

	ASSERT_SAME_STR(id);
	if (t->expect_parsed.type != CTRL_TYPE_ERROR) {
		ASSERT_SAME_STR(variable);
		ASSERT_SAME_STR(value);
	}
	ASSERT_SAME_STR(reply);

	talloc_free(cmd);
	msgb_free(msg);

	printf("handling:\n");

	ctx_size_was = talloc_total_size(ctx);

	msg = msgb_from_string(t->cmd_str);
	ctrl_handle_msg(ctrl, ccon, msg);

	if (llist_empty(&ccon->write_queue.msg_queue)) {
		if (t->reply_str) {
			printf("Got no reply, but expected \"%s\"\n", osmo_escape_str(t->reply_str, -1));
			OSMO_ASSERT(!t->reply_str);
		}
	} else {
		struct msgb *sent_msg = msgb_dequeue(&ccon->write_queue.msg_queue);
		OSMO_ASSERT(sent_msg);
		msgb_put_u8(sent_msg, 0);

		printf("replied: '%s'\n", osmo_escape_str((char*)msgb_l2(sent_msg), -1));
		OSMO_ASSERT(t->reply_str);
		OSMO_ASSERT(!strcmp(t->reply_str, (char*)msgb_l2(sent_msg)))
		msgb_free(sent_msg);
	}
	osmo_wqueue_clear(&ccon->write_queue);

	msgb_free(msg);

	if (talloc_total_size(ctx) != ctx_size_was) {
		printf("mem leak!\n");
		talloc_report_full(ctx, stdout);
		OSMO_ASSERT(false);
	}

	printf("ok\n");
}

static const struct one_test test_messages_list[] = {
	{ "GET 1 variable",
		{
			.type = CTRL_TYPE_GET,
			.id = "1",
			.variable = "variable",
		},
		"ERROR 1 Command not found",
	},
	{ "GET 1 variable\n",
		{
			.type = CTRL_TYPE_GET,
			.id = "1",
			.variable = "variable",
		},
		"ERROR 1 Command not found",

	},
	{ "GET 1 var\ni\nable",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET with trailing characters",
		},
		"ERROR 1 GET with trailing characters",
	},
	{ "GET 1 var\ti\table",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET variable contains invalid characters",
		},
		"ERROR 1 GET variable contains invalid characters",
	},
	{ "GET 1 var\ri\rable",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET variable contains invalid characters",
		},
		"ERROR 1 GET variable contains invalid characters",
	},
	{ "GET 1 variable value",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET with trailing characters",
		},
		"ERROR 1 GET with trailing characters",
	},
	{ "GET 1 variable value\n",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET with trailing characters",
		},
		"ERROR 1 GET with trailing characters",
	},
	{ "GET 1 variable multiple value tokens",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET with trailing characters",
		},
		"ERROR 1 GET with trailing characters",
	},
	{ "GET 1 variable multiple value tokens\n",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET with trailing characters",
		},
		"ERROR 1 GET with trailing characters",
	},
	{ "SET 1 variable value",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "value",
		},
		"ERROR 1 Command not found",
	},
	{ "SET 1 variable value\n",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "value",
		},
		"ERROR 1 Command not found",
	},
	{ "SET weird_id variable value",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "err",
			.reply = "Invalid message ID number",
		},
		"ERROR err Invalid message ID number",
	},
	{ "SET weird_id variable value\n",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "err",
			.reply = "Invalid message ID number",
		},
		"ERROR err Invalid message ID number",
	},
	{ "SET 1 variable multiple value tokens",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "multiple value tokens",
		},
		"ERROR 1 Command not found",

	},
	{ "SET 1 variable multiple value tokens\n",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "multiple value tokens",
		},
		"ERROR 1 Command not found",

	},
	{ "SET 1 variable value_with_trailing_spaces  ",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "value_with_trailing_spaces  ",
		},
		"ERROR 1 Command not found",
	},
	{ "SET 1 variable value_with_trailing_spaces  \n",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "value_with_trailing_spaces  ",
		},
		"ERROR 1 Command not found",
	},
	{ "SET \n special_char_id value",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "err",
			.reply = "Invalid message ID number",
		},
		"ERROR err Invalid message ID number",
	},
	{ "SET \t special_char_id value",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "err",
			.reply = "Invalid message ID number",
		},
		"ERROR err Invalid message ID number",
	},
	{ "GET_REPLY 1 variable OK",
		{
			.type = CTRL_TYPE_GET_REPLY,
			.id = "1",
			.variable = "variable",
			.reply = "OK",
		},
	},
	{ "SET_REPLY 1 variable OK",
		{
			.type = CTRL_TYPE_SET_REPLY,
			.id = "1",
			.variable = "variable",
			.reply = "OK",
		},
	},

};

static void test_messages()
{
	struct ctrl_handle *ctrl;
	struct ctrl_connection *ccon;
	int i;

	ctrl = ctrl_handle_alloc2(ctx, NULL, NULL, 0);
	ccon = talloc_zero(ctx, struct ctrl_connection);

	osmo_wqueue_init(&ccon->write_queue, 1);

	for (i = 0; i < ARRAY_SIZE(test_messages_list); i++)
		assert_test(ctrl, ccon, &test_messages_list[i]);

	talloc_free(ccon);
	talloc_free(ctrl);
}

static struct log_info_cat test_categories[] = {
};

static struct log_info info = {
	.cat = test_categories,
	.num_cat = ARRAY_SIZE(test_categories),
};

int main(int argc, char **argv)
{
	ctx = talloc_named_const(NULL, 1, "ctrl_test");
	osmo_init_logging(&info);

	printf("Checking ctrl types...\n");

	check_type(CTRL_TYPE_UNKNOWN);
	check_type(CTRL_TYPE_GET);
	check_type(CTRL_TYPE_SET);
	check_type(CTRL_TYPE_GET_REPLY);
	check_type(CTRL_TYPE_SET_REPLY);
	check_type(CTRL_TYPE_TRAP);
	check_type(CTRL_TYPE_ERROR);
	check_type(64);

	test_messages();

	return 0;
}
