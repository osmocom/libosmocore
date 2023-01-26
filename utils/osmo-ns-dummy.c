
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>

#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/core/stats.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/control_vty.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/tdef_vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/misc.h>

#include "config.h"

void *tall_nsdummy_ctx  = NULL;
static struct log_info log_info = {};
static bool quit = false;
static bool config_given = false;
static bool daemonize = false;
static int vty_port = 0;
static int ctrl_port = 0;
static char *config_file = NULL;
struct gprs_ns2_inst *g_nsi;

static const char vty_copyright[] =
	"Copyright (C) 2020 by by sysmocom - s.f.m.c. GmbH\r\n"
	"Author: Alexander Couzens <lynxis@fe80.eu>\r\n"
	"License GNU GPL version 2 or later\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

static struct vty_app_info vty_info = {
	.name		= "OsmoNSdummy",
	.version	= PACKAGE_VERSION,
	.copyright	= vty_copyright,
};

static void print_help(void)
{
	printf( "Some useful options:\n"
		"  -h	--help			This text\n"
		"  -c	--config-file		Specify the filename of the config file\n"
		"  -V	--version		Print version\n"
		"  -D	--daemonize		Fork the process into a background daemon\n"
		"  -p   --vty-port PORT		Set the vty port to listen on.\n"
		"  -r   --ctrl-port PORT	Set the ctrl port to listen on.\n"
		"\nVTY reference generation:\n"
		"    	--vty-ref-mode MODE	VTY reference generation mode (e.g. 'expert').\n"
		"    	--vty-ref-xml		Generate the VTY reference XML output and exit.\n"
		);
}

static void handle_long_options(const char *prog_name, const int long_option)
{
	static int vty_ref_mode = VTY_REF_GEN_MODE_DEFAULT;

	switch (long_option) {
	case 1:
		vty_ref_mode = get_string_value(vty_ref_gen_mode_names, optarg);
		if (vty_ref_mode < 0) {
			fprintf(stderr, "%s: Unknown VTY reference generation "
				"mode '%s'\n", prog_name, optarg);
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

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_idx = 0, c;
		static int long_option = 0;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "config-file", 1, 0, 'c' },
			{ "version", 0, 0, 'V' },
			{ "daemonize", 0, 0, 'D' },
			{ "vty-port", 1, 0, 'p' },
			{ "ctrl-port", 1, 0, 'r' },
			{ "vty-ref-mode", 1, &long_option, 1 },
			{ "vty-ref-xml", 0, &long_option, 2 },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hc:p:r:VD",
				long_options, &option_idx);
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
		case 'p':
			vty_port = atoi(optarg);
			if (vty_port < 0 || vty_port > 65535) {
				fprintf(stderr, "Invalid VTY port %d given!\n", vty_port);
				exit(1);
			}
			break;
		case 'r':
			ctrl_port = atoi(optarg);
			if (ctrl_port < 0 || ctrl_port > 65535) {
				fprintf(stderr, "Invalid CTRL port %d given!\n", ctrl_port);
				exit(1);
			}
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		case 'D':
			daemonize = true;
			break;
		default:
			fprintf(stderr, "Unknown option '%c'\n", c);
			exit(0);
			break;
		}
	}

	if (!config_file)
		config_file = "osmo-ns-dummy.cfg";
	if (!vty_port) {
		fprintf(stderr, "A vty port need to be specified (-p)\n");
		exit(1);
	}
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
		talloc_report_full(tall_nsdummy_ctx, stderr);
		signal(SIGABRT, SIG_DFL);
		raise(SIGABRT);
		break;
	case SIGUSR1:
	case SIGUSR2:
		talloc_report_full(tall_nsdummy_ctx, stderr);
		break;
	}
}

extern int g_mirror_mode;

/* called by the ns layer */
int gprs_ns_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_gprs_ns2_prim *nsp = container_of(oph, struct osmo_gprs_ns2_prim, oph);

	switch (oph->primitive) {
	case GPRS_NS2_PRIM_UNIT_DATA:
		if (g_mirror_mode) {
			/* simply switch indication->request and resubmit */
			oph->operation = PRIM_OP_REQUEST;
			msgb_pull_to_l3(oph->msg);
			nsp->u.unitdata.link_selector = rand(); /* ensure random distribution */
			return gprs_ns2_recv_prim(g_nsi, oph);
		}
		break;
	default:
		break;
	}

	if (oph->msg)
		msgb_free(oph->msg);

	return 0;
}

int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	return 0;
}

extern int nsdummy_vty_init(void);

int main (int argc, char *argv[])
{
	void *ctx = tall_nsdummy_ctx = talloc_named_const(NULL, 0, "osmo-ns-dummy");
	struct ctrl_handle *ctrl;
	int rc = 0;

	osmo_init_logging2(ctx, &log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);
	msgb_talloc_ctx_init(ctx, 0);
	osmo_stats_init(ctx);
	rate_ctr_init(ctx);

	vty_info.tall_ctx = ctx;
	vty_init(&vty_info);
	ctrl_vty_init(ctx);
	logging_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	osmo_talloc_vty_add_cmds();

	handle_options(argc, argv);

	g_nsi = gprs_ns2_instantiate(ctx, gprs_ns_prim_cb, NULL);
	if (!g_nsi) {
		LOGP(DLNS, LOGL_ERROR, "Failed to create NS instance\n");
		exit(1);
	}

	gprs_ns2_vty_init(g_nsi);
	nsdummy_vty_init();
	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0 && config_given) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n",
			config_file);
		exit(1);
	}
	if (rc < 0)
		fprintf(stderr, "No config file: '%s' Using default config.\n",
			config_file);

	rc = telnet_init_default(ctx, NULL, vty_port);
	if (rc < 0) {
		fprintf(stderr, "Error initializing telnet\n");
		exit(1);
	}

	if (ctrl_port > 0) {
		ctrl = ctrl_interface_setup(NULL, ctrl_port, NULL);
		if (!ctrl) {
			fprintf(stderr, "Failed to initialize control interface. Exiting.\n");
			exit(1);
		}
	}

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGPIPE, sighandler);
	signal(SIGABRT, sighandler);
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);
	osmo_init_ignore_signals();

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (!quit) {
		osmo_select_main(0);
	}

	telnet_exit();
	gprs_ns2_free(g_nsi);

	talloc_report_full(tall_nsdummy_ctx, stderr);
	talloc_free(tall_nsdummy_ctx);

	return 0;
}
