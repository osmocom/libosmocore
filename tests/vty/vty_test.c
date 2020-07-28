/* (C) 2013 by sysmocom - s.f.m.c. GmbH, Author: Jacob Erlbeck <jerlbeck@sysmocom.de>
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
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging_internal.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/signal.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>

static enum event last_vty_connection_event = -1;
void *ctx = NULL;

static void test_cmd_string_from_valstr(void)
{
	char *cmd;
	const struct value_string printf_seq_vs[] = {
		{ .value = 42, .str = "[foo%s%s%s%s%s]"},
		{ .value = 43, .str = "[bar%s%s%s%s%s]"},
		{ .value = 0,  .str = NULL}
	};

	printf("Going to test vty_cmd_string_from_valstr()\n");

	/* check against character strings that could break printf */

	cmd = vty_cmd_string_from_valstr (ctx, printf_seq_vs, "[prefix%s%s%s%s%s]", "[sep%s%s%s%s%s]", "[end%s%s%s%s%s]", 1);
	printf ("Tested with %%s-strings, resulting cmd = '%s'\n", cmd);
	talloc_free (cmd);
}

static int do_vty_command(struct vty *vty, const char *cmd)
{
	vector vline;
	int ret;

	printf("Going to execute '%s'\n", cmd);
	vline = cmd_make_strvec(cmd);
	ret = cmd_execute_command(vline, vty, NULL, 0);
	cmd_free_strvec(vline);
	printf("Returned: %d, Current node: %d '%s'\n", ret, vty->node, cmd_prompt(vty->node));
	return ret;
}

/* Handle the events from telnet_interface.c */
static int vty_event_cb(unsigned int subsys, unsigned int signal,
			void *handler_data, void *_signal_data)
{
	struct vty_signal_data *signal_data;

	if (subsys != SS_L_VTY)
		return 0;
	if (signal != S_VTY_EVENT)
		return 0;

	signal_data = _signal_data;
	last_vty_connection_event = signal_data->event;

	fprintf(stderr, "Got VTY event: %d\n", signal_data->event);
	return 0;
}

struct vty_test {
	int sock[2];
};

static struct vty* create_test_vty(struct vty_test *data)
{
	struct vty *vty;
	/* Fake connection. */
	socketpair(AF_UNIX, SOCK_STREAM, 0, data->sock);

	vty = vty_create(data->sock[0], NULL);
	OSMO_ASSERT(vty != NULL);
	OSMO_ASSERT(vty->status != VTY_CLOSE);

	return vty;
}

static void destroy_test_vty(struct vty_test *data, struct vty *vty)
{
	vty_close(vty);
	OSMO_ASSERT(last_vty_connection_event == VTY_CLOSED);
}

static void test_node_tree_structure(void)
{
	struct vty_test test;
	struct vty *vty;

	printf("Going to test VTY node tree structure\n");
	vty = create_test_vty(&test);

	OSMO_ASSERT(do_vty_command(vty, "enable") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == ENABLE_NODE);

	OSMO_ASSERT(do_vty_command(vty, "configure terminal") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CONFIG_NODE);
	OSMO_ASSERT(do_vty_command(vty, "exit") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == ENABLE_NODE);

	OSMO_ASSERT(do_vty_command(vty, "configure terminal") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CONFIG_NODE);
	OSMO_ASSERT(do_vty_command(vty, "end") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == ENABLE_NODE);

	OSMO_ASSERT(do_vty_command(vty, "configure terminal") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CONFIG_NODE);
	OSMO_ASSERT(do_vty_command(vty, "log stderr") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CFG_LOG_NODE);
	OSMO_ASSERT(do_vty_command(vty, "exit") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CONFIG_NODE);
	OSMO_ASSERT(do_vty_command(vty, "log stderr") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CFG_LOG_NODE);
	OSMO_ASSERT(do_vty_command(vty, "end") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == ENABLE_NODE);

	OSMO_ASSERT(do_vty_command(vty, "configure terminal") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CONFIG_NODE);
	OSMO_ASSERT(do_vty_command(vty, "line vty") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == VTY_NODE);
	OSMO_ASSERT(do_vty_command(vty, "exit") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CONFIG_NODE);
	OSMO_ASSERT(do_vty_command(vty, "line vty") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == VTY_NODE);
	OSMO_ASSERT(do_vty_command(vty, "end") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == ENABLE_NODE);


	/* Check for not searching the parent node for matching commands. */
	OSMO_ASSERT(do_vty_command(vty, "configure terminal") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CONFIG_NODE);
	OSMO_ASSERT(do_vty_command(vty, "log stderr") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CFG_LOG_NODE);
	OSMO_ASSERT(do_vty_command(vty, "line vty") == CMD_ERR_NO_MATCH);
	OSMO_ASSERT(vty->node == CFG_LOG_NODE);
	OSMO_ASSERT(do_vty_command(vty, "end") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == ENABLE_NODE);

	/* Check for final 'exit' (connection close). */
	OSMO_ASSERT(do_vty_command(vty, "exit") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == ENABLE_NODE);
	OSMO_ASSERT(vty->status == VTY_CLOSE);

	destroy_test_vty(&test, vty);
}

static void check_srep_vty_config(struct vty* vty,
	struct osmo_stats_reporter *srep)
{
	OSMO_ASSERT(srep->enabled == 0);

	OSMO_ASSERT(do_vty_command(vty, "prefix myprefix") == CMD_SUCCESS);
	OSMO_ASSERT(srep->name_prefix != NULL);
	OSMO_ASSERT(strcmp(srep->name_prefix, "myprefix") == 0);
	OSMO_ASSERT(do_vty_command(vty, "no prefix") == CMD_SUCCESS);
	OSMO_ASSERT(srep->name_prefix == NULL || strlen(srep->name_prefix) == 0);

	OSMO_ASSERT(srep->max_class == OSMO_STATS_CLASS_GLOBAL);
	OSMO_ASSERT(do_vty_command(vty, "level peer") == CMD_SUCCESS);
	OSMO_ASSERT(srep->max_class == OSMO_STATS_CLASS_PEER);
	OSMO_ASSERT(do_vty_command(vty, "level subscriber") == CMD_SUCCESS);
	OSMO_ASSERT(srep->max_class == OSMO_STATS_CLASS_SUBSCRIBER);
	OSMO_ASSERT(do_vty_command(vty, "level global") == CMD_SUCCESS);
	OSMO_ASSERT(srep->max_class == OSMO_STATS_CLASS_GLOBAL);
	OSMO_ASSERT(do_vty_command(vty, "level foobar") == CMD_ERR_NO_MATCH);

	if (srep->have_net_config) {
		OSMO_ASSERT(do_vty_command(vty, "remote-ip 127.0.0.99") ==
			CMD_SUCCESS);
		OSMO_ASSERT(srep->dest_addr_str &&
			strcmp(srep->dest_addr_str, "127.0.0.99") == 0);
		OSMO_ASSERT(do_vty_command(vty, "remote-ip 678.0.0.99") ==
			CMD_WARNING);
		OSMO_ASSERT(srep->dest_addr_str &&
			strcmp(srep->dest_addr_str, "127.0.0.99") == 0);

		OSMO_ASSERT(do_vty_command(vty, "remote-port 12321") ==
			CMD_SUCCESS);
		OSMO_ASSERT(srep->dest_port == 12321);

		OSMO_ASSERT(srep->bind_addr_str == NULL);
		OSMO_ASSERT(do_vty_command(vty, "local-ip 127.0.0.98") ==
			CMD_SUCCESS);
		OSMO_ASSERT(srep->bind_addr_str &&
			strcmp(srep->bind_addr_str, "127.0.0.98") == 0);
		OSMO_ASSERT(do_vty_command(vty, "no local-ip") == CMD_SUCCESS);
		OSMO_ASSERT(srep->bind_addr_str == NULL);

		OSMO_ASSERT(srep->mtu == 0);
		OSMO_ASSERT(do_vty_command(vty, "mtu 987") == CMD_SUCCESS);
		OSMO_ASSERT(srep->mtu == 987);
		OSMO_ASSERT(do_vty_command(vty, "no mtu") == CMD_SUCCESS);
		OSMO_ASSERT(srep->mtu == 0);
	};

	OSMO_ASSERT(do_vty_command(vty, "enable") == CMD_SUCCESS);
	OSMO_ASSERT(srep->enabled != 0);
	OSMO_ASSERT(do_vty_command(vty, "disable") == CMD_SUCCESS);
	OSMO_ASSERT(srep->enabled == 0);
}

static void test_stats_vty(void)
{
	struct osmo_stats_reporter *srep;
	struct vty_test test;
	struct vty *vty;

	printf("Going to test VTY configuration of the stats subsystem\n");
	vty = create_test_vty(&test);

	/* Go to config node */
	OSMO_ASSERT(do_vty_command(vty, "enable") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == ENABLE_NODE);
	OSMO_ASSERT(do_vty_command(vty, "configure terminal") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CONFIG_NODE);

	/* Try to create invalid reporter */
	OSMO_ASSERT(do_vty_command(vty, "stats reporter foobar") ==
		CMD_ERR_NO_MATCH);

	/* Set reporting interval */
	OSMO_ASSERT(do_vty_command(vty, "stats interval 42") == CMD_SUCCESS);
	OSMO_ASSERT(osmo_stats_config->interval == 42);

	/* Create log reporter */
	srep = osmo_stats_reporter_find(OSMO_STATS_REPORTER_LOG, NULL);
	OSMO_ASSERT(srep == NULL);
	OSMO_ASSERT(do_vty_command(vty, "stats reporter log") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CFG_STATS_NODE);
	srep = osmo_stats_reporter_find(OSMO_STATS_REPORTER_LOG, NULL);
	OSMO_ASSERT(srep != NULL);
	OSMO_ASSERT(srep->type == OSMO_STATS_REPORTER_LOG);
	check_srep_vty_config(vty, srep);
	OSMO_ASSERT(do_vty_command(vty, "exit") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CONFIG_NODE);

	/* Create statsd reporter */
	srep = osmo_stats_reporter_find(OSMO_STATS_REPORTER_STATSD, NULL);
	OSMO_ASSERT(srep == NULL);
	OSMO_ASSERT(do_vty_command(vty, "stats reporter statsd") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CFG_STATS_NODE);
	srep = osmo_stats_reporter_find(OSMO_STATS_REPORTER_STATSD, NULL);
	OSMO_ASSERT(srep != NULL);
	OSMO_ASSERT(srep->type == OSMO_STATS_REPORTER_STATSD);
	check_srep_vty_config(vty, srep);
	OSMO_ASSERT(do_vty_command(vty, "exit") == CMD_SUCCESS);
	OSMO_ASSERT(vty->node == CONFIG_NODE);

	/* Destroy log reporter */
	OSMO_ASSERT(osmo_stats_reporter_find(OSMO_STATS_REPORTER_LOG, NULL));
	OSMO_ASSERT(do_vty_command(vty, "no stats reporter log") == CMD_SUCCESS);
	OSMO_ASSERT(!osmo_stats_reporter_find(OSMO_STATS_REPORTER_LOG, NULL));

	/* Destroy statsd reporter */
	OSMO_ASSERT(osmo_stats_reporter_find(OSMO_STATS_REPORTER_STATSD, NULL));
	OSMO_ASSERT(do_vty_command(vty, "no stats reporter statsd") == CMD_SUCCESS);
	OSMO_ASSERT(!osmo_stats_reporter_find(OSMO_STATS_REPORTER_STATSD, NULL));

	destroy_test_vty(&test, vty);
}

void test_exit_by_indent(const char *fname, int expect_rc)
{
	int rc;
	printf("reading file %s, expecting rc=%d\n", fname, expect_rc);
	rc = vty_read_config_file(fname, NULL);
	printf("got rc=%d\n", rc);
	OSMO_ASSERT(rc == expect_rc);
}

enum test_nodes {
	LEVEL1_NODE = _LAST_OSMOVTY_NODE + 1,
	LEVEL2_NODE,
	LEVEL3_NODE,
};

struct cmd_node level1_node = {
	LEVEL1_NODE,
	"%s(config-level1)# ",
	1
};

struct cmd_node level2_node = {
	LEVEL2_NODE,
	"%s(config-level1-level2)# ",
	1
};

struct cmd_node level3_node = {
	LEVEL3_NODE,
	"%s(config-level1-level2-level3)# ",
	1
};

DEFUN(cfg_level1, cfg_level1_cmd,
	"level1 [MARKER]",
	"Level 1 node for VTY testing purposes\n"
	"optional string to mark the line for test debugging\n")
{
	vty->index = NULL;
	vty->node = LEVEL1_NODE;
	printf("called level1 node %s\n", argc? argv[0] : "");
	return CMD_SUCCESS;
}

DEFUN(cfg_level1_child, cfg_level1_child_cmd,
	"child1 [MARKER]",
	"Level 1 child cmd for VTY testing purposes\n"
	"optional string to mark the line for test debugging\n")
{
	printf("called level1 child cmd %s\n", argc? argv[0] : "");
	return CMD_SUCCESS;
}

DEFUN(cfg_level2, cfg_level2_cmd,
	"level2 [MARKER]",
	"Level 2 node for VTY testing purposes\n"
	"optional string to mark the line for test debugging\n")
{
	vty->index = NULL;
	vty->node = LEVEL2_NODE;
	printf("called level2 node %s\n", argc? argv[0] : "");
	return CMD_SUCCESS;
}

DEFUN(cfg_level2_child, cfg_level2_child_cmd,
	"child2 [MARKER]",
	"Level 2 child cmd for VTY testing purposes\n"
	"optional string to mark the line for test debugging\n")
{
	printf("called level2 child cmd %s\n", argc? argv[0] : "");
	return CMD_SUCCESS;
}

DEFUN(cfg_level3, cfg_level3_cmd,
	"level3 [MARKER]",
	"Level 3 node for VTY testing purposes\n"
	"optional string to mark the line for test debugging\n")
{
	vty->index = NULL;
	vty->node = LEVEL3_NODE;
	printf("called level3 node %s\n", argc? argv[0] : "");
	return CMD_SUCCESS;
}

DEFUN(cfg_level3_child, cfg_level3_child_cmd,
	"child3 [MARKER]",
	"Level 3 child cmd for VTY testing purposes\n"
	"optional string to mark the line for test debugging\n")
{
	printf("called level3 child cmd %s\n", argc? argv[0] : "");
	return CMD_SUCCESS;
}

DEFUN(cfg_ambiguous_nr_1, cfg_ambiguous_nr_1_cmd,
	"ambiguous_nr [<0-23>]",
	"testing is_cmd_ambiguous()\n"
	"optional number arg\n")
{
	printf("Called: 'ambiguous_nr [<0-23>]' (argc=%d)\n", argc);
	return CMD_SUCCESS;
}

DEFUN(cfg_ambiguous_nr_2, cfg_ambiguous_nr_2_cmd,
	"ambiguous_nr <0-23> keyword",
	"testing is_cmd_ambiguous()\n"
	"optional number arg\n")
{
	printf("Called: 'ambiguous_nr <0-23> keyword'\n");
	return CMD_SUCCESS;
}

DEFUN(cfg_ambiguous_str_1, cfg_ambiguous_str_1_cmd,
	"ambiguous_str [ARG]",
	"testing is_cmd_ambiguous()\n"
	"optional string arg\n")
{
	printf("Called: 'ambiguous_str [ARG]' (argc=%d)\n", argc);
	return CMD_SUCCESS;
}

DEFUN(cfg_ambiguous_str_2, cfg_ambiguous_str_2_cmd,
	"ambiguous_str ARG keyword",
	"testing is_cmd_ambiguous()\n"
	"optional string arg\n")
{
	printf("Called: 'ambiguous_str ARG keyword'\n");
	return CMD_SUCCESS;
}

DEFUN(cfg_ret_success, cfg_ret_success_cmd,
	"return-success",
	"testing return success\n")
{
	printf("Called: 'return-success'\n");
	return CMD_SUCCESS;
}

DEFUN(cfg_ret_warning, cfg_ret_warning_cmd,
	"return-warning",
	"testing return warning\n")
{
	printf("Called: 'return-warning'\n");
	return CMD_WARNING;
}

DEFUN(cfg_numeric_range, cfg_numeric_range_cmd,
#if ULONG_MAX == 18446744073709551615UL
	"numeric-range <0-18446744073709551615>",
#else
	"numeric-range <0-4294967295>",
#endif
	"testing numeric range\n"
	"the numeric range\n")
{
	printf("Called: 'return-success'\n");
	return CMD_SUCCESS;
}

DEFUN(cfg_range_base10, cfg_range_base10_cmd,
	"range-base10 <0-999999>",
	"testing decimal range\n"
	"the decimal range\n")
{
	printf("Called: 'return-success'\n");
	return CMD_SUCCESS;
}

DEFUN(cfg_range_base16, cfg_range_base16_cmd,
	"range-base16 <0x0-0x8888>",
	"testing hexadecimal range\n"
	"the hexadecimal range\n")
{
	printf("Called: 'return-success'\n");
	return CMD_SUCCESS;
}

DEFUN(cfg_range_baseboth, cfg_range_baseboth_cmd,
	"range-baseboth (<0-999999>|<0x0-0x8888>)",
	"testing both ranges\n"
	"the decimal range\n"
	"the hexadecimal range\n")
{
	printf("Called: 'return-success'\n");
	return CMD_SUCCESS;
}

void test_vty_add_cmds()
{
	install_element(CONFIG_NODE, &cfg_ret_warning_cmd);
	install_element(CONFIG_NODE, &cfg_ret_success_cmd);

	logging_vty_add_deprecated_subsys(tall_log_ctx, "depr");

	install_element(CONFIG_NODE, &cfg_level1_cmd);
	install_node(&level1_node, NULL);
	install_element(LEVEL1_NODE, &cfg_level1_child_cmd);
	install_element(LEVEL1_NODE, &cfg_level2_cmd);

	install_node(&level2_node, NULL);
	install_element(LEVEL2_NODE, &cfg_level2_child_cmd);
	install_element(LEVEL2_NODE, &cfg_level3_cmd);

	install_node(&level3_node, NULL);
	install_element(LEVEL3_NODE, &cfg_level3_child_cmd);

	install_element_ve(&cfg_ambiguous_nr_1_cmd);
	install_element_ve(&cfg_ambiguous_nr_2_cmd);
	install_element_ve(&cfg_ambiguous_str_1_cmd);
	install_element_ve(&cfg_ambiguous_str_2_cmd);

	install_element_ve(&cfg_numeric_range_cmd);

	install_element_ve(&cfg_range_base10_cmd);
	install_element_ve(&cfg_range_base16_cmd);
	install_element_ve(&cfg_range_baseboth_cmd);
}

void test_is_cmd_ambiguous()
{
	struct vty *vty;
	struct vty_test test;

	printf("Going to test is_cmd_ambiguous()\n");
	vty = create_test_vty(&test);

	OSMO_ASSERT(do_vty_command(vty, "ambiguous_nr") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "ambiguous_nr 23") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "ambiguous_nr 23 keyword") == CMD_SUCCESS);

	OSMO_ASSERT(do_vty_command(vty, "ambiguous_str") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "ambiguous_str arg") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "ambiguous_str arg keyword") == CMD_SUCCESS);

	destroy_test_vty(&test, vty);
}

void test_numeric_range()
{
	struct vty *vty;
	struct vty_test test;

	printf("Going to test test_numeric_range()\n");
	vty = create_test_vty(&test);

	OSMO_ASSERT(do_vty_command(vty, "numeric-range 0") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "numeric-range 40000") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "numeric-range -400000") == CMD_ERR_NO_MATCH);

	destroy_test_vty(&test, vty);
}

void test_ranges()
{
	struct vty *vty;
	struct vty_test test;

	printf("Going to test test_ranges()\n");
	vty = create_test_vty(&test);

	printf("test range-base10\n");
	OSMO_ASSERT(do_vty_command(vty, "range-base10 0") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "range-base10 40000") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "range-base10 -400000") == CMD_ERR_NO_MATCH);
	OSMO_ASSERT(do_vty_command(vty, "range-base10 0x0") == CMD_ERR_NO_MATCH);
	OSMO_ASSERT(do_vty_command(vty, "range-base10 0x343") == CMD_ERR_NO_MATCH);
	OSMO_ASSERT(do_vty_command(vty, "range-base10 -0x343") == CMD_ERR_NO_MATCH);

	printf("test range-base16\n");
	OSMO_ASSERT(do_vty_command(vty, "range-base16 0") == CMD_ERR_NO_MATCH);
	OSMO_ASSERT(do_vty_command(vty, "range-base16 40000") == CMD_ERR_NO_MATCH);
	OSMO_ASSERT(do_vty_command(vty, "range-base16 -400000") == CMD_ERR_NO_MATCH);
	OSMO_ASSERT(do_vty_command(vty, "range-base16 0x0") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "range-base16 0x343") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "range-base16 -0x343") == CMD_ERR_NO_MATCH);

	printf("test range-baseboth\n");
	OSMO_ASSERT(do_vty_command(vty, "range-baseboth 0") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "range-baseboth 40000") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "range-baseboth -400000") == CMD_ERR_NO_MATCH);
	OSMO_ASSERT(do_vty_command(vty, "range-baseboth 0x0") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "range-baseboth 0x343") == CMD_SUCCESS);
	OSMO_ASSERT(do_vty_command(vty, "range-baseboth -0x343") == CMD_ERR_NO_MATCH);

	destroy_test_vty(&test, vty);
}
/* Application specific attributes */
enum vty_test_attr {
	VTY_TEST_ATTR_FOO = 0,
	VTY_TEST_ATTR_BAR,
	VTY_TEST_ATTR_ZOO,
	VTY_TEST_ATTR_FOO_DUP,
	VTY_TEST_ATTR_ZOO_DUP,
	VTY_TEST_ATTR_UPPER,
	VTY_TEST_ATTR_RAFC_DOT,
	VTY_TEST_ATTR_RAFC_EXCL,
	VTY_TEST_ATTR_RAFC_AT,
};

int main(int argc, char **argv)
{
	struct vty_app_info vty_info = {
		.name		= "VtyTest",
		.version	= 0,
		.usr_attr_letters = {
			[VTY_TEST_ATTR_FOO]	= 'f',
			[VTY_TEST_ATTR_BAR]	= 'b',
			[VTY_TEST_ATTR_ZOO]	= 'z',

			/* Duplicate detection check */
			[VTY_TEST_ATTR_FOO_DUP]	= 'f',
			[VTY_TEST_ATTR_ZOO_DUP]	= 'z',
			/* Reserved for libraries */
			[VTY_TEST_ATTR_UPPER]	= 'X',
			/* Reserved for global attribues */
			[VTY_TEST_ATTR_RAFC_DOT]	= '.',
			[VTY_TEST_ATTR_RAFC_EXCL]	= '!',
			[VTY_TEST_ATTR_RAFC_AT]		= '@',
		},
	};

	const struct log_info_cat default_categories[] = {};

	const struct log_info log_info = {
		.cat = default_categories,
		.num_cat = ARRAY_SIZE(default_categories),
	};
	void *stats_ctx;

	ctx = talloc_named_const(NULL, 0, "stats test context");
	stats_ctx = talloc_named_const(ctx, 1, "stats test context");

	osmo_signal_register_handler(SS_L_VTY, vty_event_cb, NULL);

	/* Fake logging. */
	osmo_init_logging2(ctx, &log_info);

	/* Init stats */
	osmo_stats_init(stats_ctx);

	vty_init(&vty_info);

	/* Setup VTY commands */
	logging_vty_add_cmds();
	osmo_stats_vty_add_cmds();

	test_vty_add_cmds();

	test_cmd_string_from_valstr();
	test_node_tree_structure();
	test_stats_vty();
	test_exit_by_indent("ok.cfg", 0);
	test_exit_by_indent("ok_more_spaces.cfg", 0);
	test_exit_by_indent("ok_tabs.cfg", 0);
	test_exit_by_indent("ok_tabs_and_spaces.cfg", 0);
	test_exit_by_indent("ok_ignore_comment.cfg", 0);
	test_exit_by_indent("ok_ignore_blank.cfg", 0);
	test_exit_by_indent("fail_not_de-indented.cfg", -EINVAL);
	test_exit_by_indent("fail_too_much_indent.cfg", -EINVAL);
	test_exit_by_indent("fail_tabs_and_spaces.cfg", -EINVAL);
	test_exit_by_indent("ok_indented_root.cfg", 0);
	test_exit_by_indent("ok_empty_parent.cfg", 0);
	test_exit_by_indent("fail_cmd_ret_warning.cfg", -EINVAL);
	test_exit_by_indent("ok_deprecated_logging.cfg", 0);

	test_is_cmd_ambiguous();

	test_numeric_range();
	test_ranges();

	/* Leak check */
	OSMO_ASSERT(talloc_total_blocks(stats_ctx) == 1);

	printf("All tests passed\n");

	return 0;
}
