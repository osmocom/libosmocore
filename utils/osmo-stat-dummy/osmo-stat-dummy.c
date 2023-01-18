/* Rate counter and statsd test application */
/* (C) 2022 by by sysmocom - s.f.m.c. GmbH
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>

#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/core/stats.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/control_vty.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/tdef_vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/misc.h>

#include "config.h"

void *tall_statdummy_ctx  = NULL;
static bool quit = false;
static bool config_given = false;
struct rate_ctr_group *g_ctrg;

enum dummy_rate_ctr_idx {
	DUMMY_VTY = 0,
	DUMMY_AUTO,
};

static void print_help(void)
{
	printf("Some useful options:\n"
		"  -h	--help			This text\n"
		"  -c	--config-file		Specify the filename of the config file\n"
		"  -V	--version		Print version\n"
		"\nVTY reference generation:\n"
		"	--vty-ref-mode MODE	VTY reference generation mode (e.g. 'expert').\n"
		"	--vty-ref-xml		Generate the VTY reference XML output and exit.\n"
		);
}

static void handle_long_options(const char *prog_name, const int long_option)
{
	static int vty_ref_mode = VTY_REF_GEN_MODE_DEFAULT;

	switch (long_option) {
	case 1:
		vty_ref_mode = get_string_value(vty_ref_gen_mode_names, optarg);
		if (vty_ref_mode < 0) {
			fprintf(stderr, "%s: Unknown VTY reference generation mode '%s'\n", prog_name, optarg);
			exit(2);
		}
		break;
	case 2:
		fprintf(stderr, "Generating the VTY reference in mode '%s' (%s)\n",
			get_value_string(vty_ref_gen_mode_names, vty_ref_mode),
			get_value_string(vty_ref_gen_mode_desc, vty_ref_mode));
		vty_dump_xml_ref_mode(stdout, (enum vty_ref_gen_mode) vty_ref_mode);
		exit(0);
	default:
		fprintf(stderr, "%s: error parsing cmdline options\n", prog_name);
		exit(2);
	}
}

static char *handle_options(int argc, char **argv)
{
	char *config_file = NULL;

	while (1) {
		int option_idx = 0, c;
		static int long_option = 0;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "config-file", 1, 0, 'c' },
			{ "version", 0, 0, 'V' },
			{ "vty-ref-mode", 1, &long_option, 1 },
			{ "vty-ref-xml", 0, &long_option, 2 },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hc:V", long_options, &option_idx);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 0:
			handle_long_options(argv[0], long_option);
			break;
		case 'c':
			if (config_file)
				free(config_file);
			config_file = optarg;
			config_given = true;
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			fprintf(stderr, "Unknown option '%c'\n", c);
			exit(0);
			break;
		}
	}

	if (!config_file)
		return "osmo-stat-dummy.cfg";

	return config_file;
}

void sighandler(int sigset)
{
	if (sigset == SIGPIPE)
		return;

	fprintf(stderr, "Signal %d received.\n", sigset);

	switch (sigset) {
	case SIGINT:
	case SIGTERM:
		/* If another signal is received afterwards, the program
		 * is terminated without finishing shutdown process.
		 */
		signal(SIGINT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGPIPE, SIG_DFL);
		signal(SIGABRT, SIG_DFL);
		signal(SIGUSR1, SIG_DFL);
		signal(SIGUSR2, SIG_DFL);

		quit = 1;
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report and
		 * then run default SIGABRT handler, who will generate coredump
		 * and abort the process. abort() should do this for us after we
		 * return, but program wouldn't exit if an external SIGABRT is
		 * received.
		 */
		talloc_report_full(tall_statdummy_ctx, stderr);
		signal(SIGABRT, SIG_DFL);
		raise(SIGABRT);
		break;
	case SIGUSR1:
	case SIGUSR2:
		talloc_report_full(tall_statdummy_ctx, stderr);
		break;
	}
}

static int rate_ctr_timer_cb(struct osmo_fd *ofd, unsigned int what)
{
	uint64_t expire_count;
	int rc;

	/* check that the timer has actually expired */
	if (!(what & OSMO_FD_READ))
		return 0;

	/* read from timerfd: number of expirations of periodic timer */
	rc = read(ofd->fd, (void *) &expire_count, sizeof(expire_count));
	if (rc < 0 && errno == EAGAIN)
		return 0;

	OSMO_ASSERT(rc == sizeof(expire_count));

	if (expire_count > 1)
		LOGP(DLGLOBAL, LOGL_NOTICE, "Stats timer expire_count=%" PRIu64 ": We missed %" PRIu64 " timers\n",
			expire_count, expire_count-1);

	/* Increment the counter value */
	rate_ctr_inc(rate_ctr_group_get_ctr(g_ctrg, DUMMY_AUTO));

	return 0;
}

DEFUN(update_rate_ctr, update_rate_ctr_cmd,
      "update-rate-ctr <0-100000>",
      "Update dummy rate counter\n"
      "Value to add to rate counter\n")
{
	rate_ctr_add(rate_ctr_group_get_ctr(g_ctrg, DUMMY_VTY), atoi(argv[0]));

	return CMD_SUCCESS;
}

static int statdummy_vty_init(void)
{
	install_element_ve(&update_rate_ctr_cmd);

	return 0;
}

int main(int argc, char *argv[])
{
	struct log_info log_info = {};
	char *config_file;
	void *ctx = tall_statdummy_ctx = talloc_named_const(NULL, 0, "osmo-stat-dummy");
	struct ctrl_handle *ctrl;
	struct osmo_fd rate_ctr_timer = { .fd = -1 };
	struct timespec ts_interval = { .tv_sec = 0, .tv_nsec = 500000000 }; /* 0.5 seconds */
	int rc = 0;

	const char vty_copyright[] =
	"Copyright (C) 2022 by by sysmocom - s.f.m.c. GmbH\r\n"
	"Author: Max Suraev <msuraev@sysmocom.de>\r\n"
	"License GNU GPL version 3 or later\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

	struct vty_app_info vty_info = {
		.name		= "OsmoSTATdummy",
		.version	= PACKAGE_VERSION,
		.copyright	= vty_copyright,
		.tall_ctx	= ctx
	};

	const struct rate_ctr_desc dummy_ctr_desc[] = {
		[DUMMY_VTY] =	{ "dummy:vty", "Dummy counter updated via VTY" },
		[DUMMY_AUTO] =	{ "dummy:auto", "Dummy counter autoupdated via timer" },
	};

	const struct rate_ctr_group_desc dummy_ctrg_desc = {
		"dummy",
		"dummy stat tester",
		OSMO_STATS_CLASS_GLOBAL,
		ARRAY_SIZE(dummy_ctr_desc),
		dummy_ctr_desc,
	};

	osmo_init_logging2(ctx, &log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);

	msgb_talloc_ctx_init(ctx, 0);

	vty_init(&vty_info);
	ctrl_vty_init(ctx);
	logging_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	osmo_talloc_vty_add_cmds();

	config_file = handle_options(argc, argv);

	statdummy_vty_init();
	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		if (config_given) {
			fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
			exit(1);
		}
		fprintf(stderr, "No config file: '%s' Using default config.\n", config_file);
	}

	rc = telnet_init_default(ctx, NULL, -1);
	if (rc < 0) {
		fprintf(stderr, "Error initializing telnet\n");
		exit(1);
	}

	ctrl = ctrl_interface_setup(NULL, 1234, NULL);
	if (!ctrl) {
		fprintf(stderr, "Failed to initialize control interface. Exiting.\n");
		exit(1);
	}

	g_ctrg = rate_ctr_group_alloc(ctx, &dummy_ctrg_desc, 0);
	if (!g_ctrg) {
		fprintf(stderr, "Failed to initialize rate counters. Exiting.\n");
		return -1;
	}

	osmo_stats_init(ctx);
	rate_ctr_init(ctx);

	rc = osmo_timerfd_setup(&rate_ctr_timer, rate_ctr_timer_cb, NULL);
	if (rc < 0) {
		LOGP(DLGLOBAL, LOGL_ERROR, "Failed to setup the timer with error code %d (fd=%d)\n",
		     rc, rate_ctr_timer.fd);
		return rc;
	}

	rc = osmo_timerfd_schedule(&rate_ctr_timer, NULL, &ts_interval);
	if (rc < 0) {
		LOGP(DLGLOBAL, LOGL_ERROR, "Failed to schedule the timer with error code %d (fd=%d)\n",
		     rc, rate_ctr_timer.fd);
	}

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGPIPE, sighandler);
	signal(SIGABRT, sighandler);
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);
	osmo_init_ignore_signals();

	while (!quit) {
		osmo_select_main(0);
	}

	telnet_exit();

	talloc_report_full(tall_statdummy_ctx, stderr);
	talloc_free(tall_statdummy_ctx);

	return 0;
}
