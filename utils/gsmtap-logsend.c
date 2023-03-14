/* Small program to read an input file / stdin and send each line via GSMTAP logging */
/* (C) 2023 by Harald Welte <laforge@osmocom.org>
 *
 * All Rights Reserved
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

#include <stdio.h>
#include <errno.h>
#include <sys/uio.h>
#include <getopt.h>

#include <osmocom/core/byteswap.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/core/gsmtap_util.h>

static char *proc_name = "gsmtap-logsend";
static char *subsys_name = "unknown";
static char *dest_host = "localhost";
static int dest_port = GSMTAP_UDP_PORT;

static void help(void)
{
	printf("osmo-gsmtap-logsend Usage:\n"
	       "\t[ -r DESTADDR ] [ -p PORTNR ] [ -n PROC_NAME ] [ -s SUBSYS ] [ INFILE ]\n"
	       "\n"
	       " -a  --remote-address HOSTNAME     Destination IP destination address (default: localhost)\n"
	       " -p  --remote-port PORTNR          Destination UDP Port number (default: 4729)\n"
	       " -n  --process-name PROC_NAME      Process name to include in GSMTAP LOG header\n"
	       " -s  --subsys-name SUBSYS          Subsystem name to include in GSMTAP LOG header\n"
	       " -h  --help                        This help message\n"
	      );
}

int main(int argc, char **argv)
{
	char buf[1024];
	int gsmtap_fd;
	FILE *infile;
	char *line;
	int rc;

	while (1) {
		static const struct option long_options[] = {
			{ "remote-address", 1, 0, 'a' },
			{ "remote-port", 1, 0, 'p' },
			{ "process-name", 1, 0, 'n' },
			{ "subsys-name", 1, 0, 's' },
			{ "help", 0, 0, 'h' },
			{ 0, 0, 0, 0 }
		};
		int c, option_index;

		c = getopt_long(argc, argv, "a:p:n:s:h", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			dest_host = optarg;
			break;
		case 'p':
			dest_port = atoi(optarg);
			break;
		case 'n':
			proc_name = optarg;
			break;
		case 's':
			subsys_name = optarg;
			break;
		case 'h':
			help();
			exit(0);
			break;
		default:
			help();
			exit(1);
		}
	}

	if (argc <= optind) {
		infile = stdin;
	} else {
		infile = fopen(argv[optind], "r");
		if (!infile) {
			fprintf(stderr, "Unable to open %s: %s\n", argv[optind], strerror(errno));
			exit(2);
		}
	}

	gsmtap_fd = gsmtap_source_init_fd(dest_host, dest_port);
	if (gsmtap_fd < 0) {
		fprintf(stderr, "Unable to create GSMTAP soicket: %s\n", strerror(errno));
		exit(2);
	}

	/* prepare all the data structures that don't change for each line */
	struct {
		struct gsmtap_hdr gsmtap;
		struct gsmtap_osmocore_log_hdr log;
	} __attribute__ ((packed)) hdr;
	struct timeval tv;

	memset(&hdr, 0, sizeof(hdr));
	hdr.gsmtap.version = GSMTAP_VERSION;
	hdr.gsmtap.hdr_len = sizeof(hdr.gsmtap)/4;
	hdr.gsmtap.type = GSMTAP_TYPE_OSMOCORE_LOG;

	OSMO_STRLCPY_ARRAY(hdr.log.proc_name, proc_name);
	OSMO_STRLCPY_ARRAY(hdr.log.subsys, subsys_name);
	hdr.log.level = LOGL_INFO;

	while ((line = fgets(buf, sizeof(buf), infile))) {
		struct iovec iov[2] = {
			{ .iov_base = &hdr, .iov_len = sizeof(hdr) },
			{ .iov_base = buf, .iov_len = strlen(line) + 1 },
		};
		osmo_gettimeofday(&tv, NULL);
		hdr.log.ts.sec = osmo_htonl(tv.tv_sec);
		hdr.log.ts.usec = osmo_htonl(tv.tv_usec);

		rc = writev(gsmtap_fd, iov, ARRAY_SIZE(iov));
		if (rc <= 0) {
			fprintf(stderr, "Short write on GSMTAP socket: %d (%s)\n", rc, strerror(errno));
			exit(1);
		}
	}
}
