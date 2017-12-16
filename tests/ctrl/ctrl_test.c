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
	char *rc;
	size_t len = strlen(str) + 1;
	/* ctrl_cmd_parse() appends a '\0' to the msgb, allow one more byte. */
	struct msgb *msg = msgb_alloc(len + 1, str);
	msg->l2h = msg->head;
	rc = (char*)msgb_put(msg, len);
	OSMO_ASSERT(rc == (char*)msg->l2h);
	strcpy(rc, str);
	return msg;
}

static void *ctx = NULL;

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

static void assert_parsing(const char *str, const struct ctrl_cmd *expect)
{
	struct ctrl_cmd *cmd;
	struct msgb *msg = msgb_from_string(str);

	printf("test parsing: '%s'\n", osmo_escape_str(str, -1));

	cmd = ctrl_cmd_parse(ctx, msg);
	OSMO_ASSERT(cmd);

	OSMO_ASSERT(expect->type == cmd->type);

#define ASSERT_SAME_STR(field) \
	assert_same_str(#field, expect->field, cmd->field)

	ASSERT_SAME_STR(id);
	ASSERT_SAME_STR(variable);
	ASSERT_SAME_STR(value);
	ASSERT_SAME_STR(reply);

	talloc_free(cmd);
	msgb_free(msg);

	printf("ok\n");
}

struct one_parsing_test {
	const char *cmd_str;
	struct ctrl_cmd expect;
};

static const struct one_parsing_test test_parsing_list[] = {
	{ "GET 1 variable",
		{
			.type = CTRL_TYPE_GET,
			.id = "1",
			.variable = "variable",
		}
	},
	{ "GET 1 variable\n",
		{
			.type = CTRL_TYPE_GET,
			.id = "1",
			.variable = "variable\n", /* current bug */
		}
	},
	{ "GET 1 var\ni\nable",
		{
			.type = CTRL_TYPE_GET,
			.id = "1",
			.variable = "var\ni\nable", /* current bug */
		}
	},
	{ "GET 1 variable value",
		{
			.type = CTRL_TYPE_GET,
			.id = "1",
			.variable = "variable",
			.value = NULL,
		}
	},
	{ "GET 1 variable value\n",
		{
			.type = CTRL_TYPE_GET,
			.id = "1",
			.variable = "variable",
			.value = NULL,
		}
	},
	{ "GET 1 variable multiple value tokens",
		{
			.type = CTRL_TYPE_GET,
			.id = "1",
			.variable = "variable",
			.value = NULL,
		}
	},
	{ "GET 1 variable multiple value tokens\n",
		{
			.type = CTRL_TYPE_GET,
			.id = "1",
			.variable = "variable",
			.value = NULL,
		}
	},
	{ "SET 1 variable value",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "value",
		}
	},
	{ "SET 1 variable value\n",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "value",
		}
	},
	{ "SET weird_id variable value",
		{
			.type = CTRL_TYPE_SET,
			.id = "weird_id",
			.variable = "variable",
			.value = "value",
		}
	},
	{ "SET weird_id variable value\n",
		{
			.type = CTRL_TYPE_SET,
			.id = "weird_id",
			.variable = "variable",
			.value = "value",
		}
	},
	{ "SET 1 variable multiple value tokens",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "multiple value tokens",
		}
	},
	{ "SET 1 variable multiple value tokens\n",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "multiple value tokens",
		}
	},
	{ "SET 1 variable value_with_trailing_spaces  ",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "value_with_trailing_spaces  ",
		}
	},
	{ "SET 1 variable value_with_trailing_spaces  \n",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "value_with_trailing_spaces  ",
		}
	},
	{ "SET \n special_char_id value",
		{
			.type = CTRL_TYPE_SET,
			.id = "\n",
			.variable = "special_char_id",
			.value = "value",
		}
	},
	{ "SET \t special_char_id value",
		{
			.type = CTRL_TYPE_SET,
			.id = "\t",
			.variable = "special_char_id",
			.value = "value",
		}
	},
};

static void test_parsing()
{
	int i;

	for (i = 0; i < ARRAY_SIZE(test_parsing_list); i++)
		assert_parsing(test_parsing_list[i].cmd_str,
			       &test_parsing_list[i].expect);
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

	test_parsing();

	return 0;
}
