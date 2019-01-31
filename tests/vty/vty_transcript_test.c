/* Test implementation for VTY transcript testing. */
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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

#include <stdlib.h>

#include "config.h"

void *root_ctx = NULL;

static void print_help()
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
	.name		= "vty_transcript_test",
	.version	= PACKAGE_VERSION,
};

static const struct log_info_cat default_categories[] = {};

const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

DEFUN(multi0, multi0_cmd,
      "multi0 (one|two|three)",
      "multi0 test command\n" "1\n2\n3\n")
{
	vty_out(vty, "ok argc=%d%s%s%s", argc, argc ? " " : "", argc ? argv[0] : "", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(multi1, multi1_cmd,
      "multi1 ([one]|[two]|[three])",
      "multi1 test command\n" "1\n2\n3\n")
{
	vty_out(vty, "ok argc=%d%s%s%s", argc, argc ? " " : "", argc ? argv[0] : "", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(multi2, multi2_cmd,
      "multi2 [(one|two|three)]",
      "multi2 test command\n" "1\n2\n3\n")
{
	vty_out(vty, "ok argc=%d%s%s%s", argc, argc ? " " : "", argc ? argv[0] : "", VTY_NEWLINE);
	return CMD_SUCCESS;
}

static void init_vty_cmds()
{
	install_element_ve(&multi0_cmd);
	install_element_ve(&multi1_cmd);
	install_element_ve(&multi2_cmd);
}

int main(int argc, char **argv)
{
	int rc;

	root_ctx = talloc_named_const(NULL, 0, "vty_transcript_test");

	vty_info.tall_ctx = root_ctx;
	vty_init(&vty_info);
	osmo_talloc_vty_add_cmds();
	init_vty_cmds();

	osmo_init_logging2(root_ctx, &log_info);

	handle_options(argc, argv);

	if (cmdline_config.config_file) {
		rc = vty_read_config_file(cmdline_config.config_file, NULL);
		if (rc < 0) {
			fprintf(stderr, "Failed to parse the config file: '%s'\n", cmdline_config.config_file);
			return 1;
		}
	}

	rc = telnet_init_dynif(root_ctx, NULL, vty_get_bind_addr(), 42042);
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
