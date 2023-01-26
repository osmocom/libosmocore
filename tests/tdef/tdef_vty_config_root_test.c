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

/* ------------------- HERE IS THE INTERESTING TDEF RELEVANT PART ------------------- */

/* This example keeps several separate timer groups and offers 'timer' VTY commands at the root of the config node. See
 * the tdef_vty_config_root_test.vty transcript test.
 */

static struct osmo_tdef tdefs_test[] = {
	{ .T=1, .default_val=100, .desc="Testing a hundred seconds" },  // default is .unit=OSMO_TDEF_S == 0
	{ .T=2, .default_val=100, .unit=OSMO_TDEF_MS, .desc="Testing a hundred milliseconds" },
	{ .T=3, .default_val=100, .unit=OSMO_TDEF_M, .desc="Testing a hundred minutes" },
	{ .T=4, .default_val=100, .unit=OSMO_TDEF_CUSTOM, .desc="Testing a hundred potatoes" },
	{ .T=0x7fffffff, .default_val=0xffffffff, .unit=OSMO_TDEF_M, .desc="Very large" },
	{ .T=-23, .default_val=239471, .desc="Negative T number" },
	{ .T=30, .default_val=50, .desc="Testing range min", .min_val=20 },
	{ .T=31, .default_val=50, .desc="Testing range max", .max_val=52 },
	{ .T=32, .default_val=50, .desc="Testing range both", .min_val=20, .max_val=52 },
	{}  //  <-- important! last entry shall be zero
};

static struct osmo_tdef tdefs_tea[] = {
	{ .T=1, .default_val=50, .desc="Water Boiling Timeout" },
	{ .T=2, .default_val=300, .desc="Tea brewing" },
	{ .T=3, .default_val=5, .unit=OSMO_TDEF_M, .desc="Let tea cool down before drinking" },
	{ .T=4, .default_val=20, .unit=OSMO_TDEF_M, .desc="Forgot to drink tea while it's warm" },
	{}
};

static struct osmo_tdef tdefs_software[] = {
	{ .T=1, .default_val=30, .unit=OSMO_TDEF_M, .desc="Write code" },
	{ .T=2, .default_val=20, .unit=OSMO_TDEF_MS, .desc="Hit segfault" },
	{ .T=3, .default_val=480, .unit=OSMO_TDEF_M, .desc="Fix bugs" },
	{}
};

static struct osmo_tdef_group tdef_groups[] = {
	{
		.name = "tea",
		.desc = "Tea time",
		.tdefs = tdefs_tea,
	},
	{
		.name = "test",
		.desc = "Test timers",
		.tdefs = tdefs_test,
	},
	{
		.name = "software",
		.desc = "Typical software development cycle",
		.tdefs = tdefs_software,
	},
	{}
};

enum tdef_vty_test_nodes {
	TIMER_NODE = _LAST_OSMOVTY_NODE + 1,
};

/* This example puts 'timer' configuration commands directly at the root of the CONFIG_NODE.
 * This TIMER_NODE is merely needed as a hook for the vty_write() command, but becomes an empty node in the VTY docs.
 * It is possible to cheat around needing this if you choose to config_write_timer() in another root nodes' write cb.
 * Another example using a 'network' subnode is \ref tdef_vty_config_subnode_test.c */
static struct cmd_node timer_node = {
	TIMER_NODE,
	"%s(config-timer)# ",
	1,
};

static int config_write_timer(struct vty *vty)
{
	osmo_tdef_vty_groups_write(vty, "");
	return CMD_SUCCESS;
}

static void timer_init_vty(void)
{
	/* Again, this is merely to get a vty write hook, see above. */
	install_node(&timer_node, config_write_timer);

	osmo_tdef_vty_groups_init(CONFIG_NODE, tdef_groups);
}

/* ------------------- THE REST is just boilerplate osmo main() ------------------- */

void *root_ctx = NULL;

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

	timer_init_vty(); /* <---- the only tdef relevant init */

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
