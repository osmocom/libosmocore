/* Test implementation for osmo_tdef VTY configuration API. */
/*
 * (C) 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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

#define _GNU_SOURCE
#include <getopt.h>
#include <signal.h>
#include <limits.h>
#include <string.h>

#include <osmocom/core/application.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/telnet_interface.h>

#include <osmocom/core/tdef.h>
#include <osmocom/vty/tdef_vty.h>

#include <stdlib.h>

#include "config.h"

void *root_ctx = NULL;

/* ------------------- HERE IS THE INTERESTING TDEF RELEVANT PART ------------------- */

/* This example keeps a separate list of timers for each instance of a dynamically allocated instance of a VTY node,
 * for example of keeping separate timers for each BTS in a BSC.
 */

static const struct osmo_tdef bts_default_tdefs[] = {
	{ .T=1111, .default_val=2, .desc="Dynamic Duo" },
	{ .T=2222, .default_val=1, .desc="BATMAN" },
	{ .T=3333, .default_val=12, .desc="Dadadadadadadadadadadada" },
	{ .T=4444, .default_val=500, .unit=OSMO_TDEF_MS, .desc="POW!" },
	{}
};


/* Boilerplate dynamic VTY node ... */

enum tdef_vty_test_nodes {
	MEMBER_NODE = _LAST_OSMOVTY_NODE + 1,
};

static struct cmd_node member_node = {
	MEMBER_NODE,
	"%s(config-member)# ",
	1,
};

struct member {
	struct llist_head entry;
	char name[23];
	struct osmo_tdef *tdefs;
};

LLIST_HEAD(all_members);

struct member *member_alloc(const char *name)
{
	struct member *m = talloc_zero(root_ctx, struct member);
	osmo_strlcpy(m->name, name, sizeof(m->name));

	/* DYNAMIC TDEF COPIES */
	m->tdefs = (struct osmo_tdef*)talloc_size(m, sizeof(bts_default_tdefs));
	memcpy((char*)m->tdefs, (char*)&bts_default_tdefs, sizeof(bts_default_tdefs));
	osmo_tdefs_reset(m->tdefs);

	llist_add_tail(&m->entry, &all_members);
	return m;
}

struct member *member_find(const char *name)
{
	struct member *m;
	llist_for_each_entry(m, &all_members, entry) {
		if (!strcmp(m->name, name))
			return m;
	}
	return NULL;
}

DEFUN(cfg_member, cfg_member_cmd,
      "member NAME",
      "Enter member node\n" "Existing or new member node name\n")
{
	const char *name = argv[0];
	struct member *m = member_find(name);
	if (!m)
		m = member_alloc(name);
	vty->index = m;
	vty->node = MEMBER_NODE;
	return CMD_SUCCESS;
}


/* TDEF SPECIFIC VTY */

static bool startswith(const char *str, const char *startswith_str)
{
	if (!startswith_str)
		return true;
	if (!str)
		return false;
	return strncmp(str, startswith_str, strlen(startswith_str)) == 0;
}

DEFUN(show_timer, show_member_timer_cmd,
      "show member-timer [NAME] " OSMO_TDEF_VTY_ARG_T_OPTIONAL,
      SHOW_STR "Show timers for a specific member" "member name\n"
      OSMO_TDEF_VTY_DOC_T)
{
	const char *name = argc > 0 ? argv[0] : NULL;
	struct member *m;
	const char *T_arg = argc > 1 ? argv[1] : NULL;
	int shown = 0;

	llist_for_each_entry(m, &all_members, entry) {
		if (!name || startswith(m->name, name)) {
			osmo_tdef_vty_show_cmd(vty, m->tdefs, T_arg, "%11s: ", m->name);
			shown ++;
		}
	}
	if (!shown) {
		vty_out(vty, "%% No such member: %s%s", name ? : "(none)", VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(cfg_member_timer, cfg_member_timer_cmd,
      "timer " OSMO_TDEF_VTY_ARG_SET_OPTIONAL,
      "Configure or show timers for this member\n"
      OSMO_TDEF_VTY_DOC_SET)
{
	struct member *m = vty->index;

	if (!m || !m->tdefs) {
		vty_out(vty, "%% No timers here%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* If any arguments are missing, redirect to 'show' */
	if (argc < 2) {
		const char *T_arg = argc > 0 ? argv[0] : NULL;
		return osmo_tdef_vty_show_cmd(vty, m->tdefs, T_arg, "%11s: ", m->name);
	}

	return osmo_tdef_vty_set_cmd(vty, m->tdefs, argv);
}

static int config_write_member(struct vty *vty)
{
	struct member *m;
	llist_for_each_entry(m, &all_members, entry) {
		vty_out(vty, "member %s%s", m->name, VTY_NEWLINE);
		osmo_tdef_vty_write(vty, m->tdefs, " timer ");
	}

	return CMD_SUCCESS;
}

static void member_init_vty(void)
{
	install_node(&member_node, config_write_member);
	install_element(CONFIG_NODE, &cfg_member_cmd);

	install_element_ve(&show_member_timer_cmd);
	install_element(MEMBER_NODE, &cfg_member_timer_cmd);
}

/* ------------------- THE REST is just boilerplate osmo main() ------------------- */

static void print_help(void)
{
	printf( "options:\n"
		"  -h	--help		this text\n"
		"  -d	--debug MASK	Enable debugging (e.g. -d DRSL:DOML:DLAPDM)\n"
		"  -D	--daemonize	For the process into a background daemon\n"
		"  -c	--config-file	Specify the filename of the config file\n"
		"  -s	--disable-color	Don't use colors in stderr log output\n"
		"  -T	--timestamp	Prefix every log line with a timestamp\n"
		"  -V	--version	Print version information and exit\n"
		"  -e	--log-level	Set a global log-level\n"
		);
}

static struct {
	const char *config_file;
	int daemonize;
} cmdline_config = {};

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_idx = 0, c;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "debug", 1, 0, 'd' },
			{ "daemonize", 0, 0, 'D' },
			{ "config-file", 1, 0, 'c' },
			{ "disable-color", 0, 0, 's' },
			{ "timestamp", 0, 0, 'T' },
			{ "version", 0, 0, 'V' },
			{ "log-level", 1, 0, 'e' },
			{}
		};

		c = getopt_long(argc, argv, "hc:d:Dc:sTVe:",
				long_options, &option_idx);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			cmdline_config.daemonize = 1;
			break;
		case 'c':
			cmdline_config.config_file = optarg;
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
		}
	}
}

static int quit = 0;

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
	case SIGTERM:
		quit++;
		break;
	case SIGABRT:
		osmo_generate_backtrace();
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(root_ctx, stderr);
		break;
	case SIGUSR2:
		talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
}

static struct vty_app_info vty_info = {
	.name		= "tdef_vty_test",
	.version	= PACKAGE_VERSION,
};

static const struct log_info_cat default_categories[] = {};

const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	int rc;

	root_ctx = talloc_named_const(NULL, 0, "tdef_vty_test");

	osmo_init_logging2(root_ctx, &log_info);

	vty_info.tall_ctx = root_ctx;
	vty_init(&vty_info);
	osmo_talloc_vty_add_cmds();

	member_init_vty(); /* <--- relevant init for this example */

	handle_options(argc, argv);

	if (cmdline_config.config_file) {
		rc = vty_read_config_file(cmdline_config.config_file, NULL);
		if (rc < 0) {
			fprintf(stderr, "Failed to parse the config file: '%s'\n", cmdline_config.config_file);
			return 1;
		}
	}

	rc = telnet_init_default(root_ctx, NULL, 42042);
	if (rc < 0)
		return 2;

	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	if (cmdline_config.daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			return 6;
		}
	}

	while (!quit) {
		log_reset_context();
		osmo_select_main(0);
	}

	talloc_free(root_ctx);
	talloc_free(tall_vty_ctx);

	return 0;
}
