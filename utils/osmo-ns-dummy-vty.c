/* VTY for osmo-ns-dummy */

/* (C) 2021 Harald Welte <laforge@gnumonks.org>
 *
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>


#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>

#include <osmocom/gsm/prim.h>
#include <osmocom/gprs/gprs_ns2.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/misc.h>

extern struct gprs_ns2_inst *g_nsi;
static struct llist_head g_ns_traf_gens = LLIST_HEAD_INIT(g_ns_traf_gens);
int g_mirror_mode;

/* one NS traffic generator instance.  You can have as many of these as you want,
 * just as long as they have unique names */
struct ns_traf_gen {
	struct llist_head list;
	const char *name;
	struct {
		uint16_t nsei;
		uint16_t bvci;
		/* size of each packet */
		uint16_t pkt_size;
		/* interval between packets in us */
		uint32_t interval_us;
		/* fixed (false) or random (true) LSP */
		bool lsp_randomize;
		/* (fixeD) Link Selector Parameter */
		uint32_t lsp;
	} cfg;
	struct osmo_fd timerfd;
	bool running;
};

#define LOGNTG(ntg, lvl, fmt, args ...) \
	LOGP(DLGLOBAL, lvl, "traf-gen(%s): " fmt, (ntg)->name, ## args)

/* allocate and transmit one NS message */
static int ntg_tx_one(struct ns_traf_gen *ntg)
{
	struct osmo_gprs_ns2_prim nsp = {};
	struct msgb *msg = msgb_alloc_headroom(3072, 20, "NS traffic gen");

	if (!msg)
		return -ENOMEM;
	msgb_put(msg, ntg->cfg.pkt_size);
	nsp.bvci = ntg->cfg.bvci;
	nsp.nsei = ntg->cfg.nsei;
	if (ntg->cfg.lsp_randomize)
		nsp.u.unitdata.link_selector = rand();
	else
		nsp.u.unitdata.link_selector = ntg->cfg.lsp;
	osmo_prim_init(&nsp.oph, SAP_NS, GPRS_NS2_PRIM_UNIT_DATA, PRIM_OP_REQUEST, msg);
	return gprs_ns2_recv_prim(g_nsi, &nsp.oph);
}

/* call-back from transmit timer-fd */
static int ntg_timerfd_cb(struct osmo_fd *ofd, unsigned int what)
{
	uint64_t expire_count;
	struct ns_traf_gen *ntg = ofd->data;
	unsigned int i;
	int rc;

	OSMO_ASSERT(what & OSMO_FD_READ);

	rc = read(ofd->fd, (void *) &expire_count, sizeof(expire_count));
	if (rc < 0 && errno == EAGAIN)
		return 0;
	OSMO_ASSERT(rc == sizeof(expire_count));

	for (i = 0; i < expire_count; i++)
		ntg_tx_one(ntg);

	return 0;
}

static struct ns_traf_gen *ns_traf_gen_find(const char *name)
{
	struct ns_traf_gen *ntg;

	llist_for_each_entry(ntg, &g_ns_traf_gens, list) {
		if (!strcmp(ntg->name, name))
			return ntg;
	}
	return NULL;
}

static struct ns_traf_gen *ns_traf_gen_find_or_alloc(const char *name)
{
	struct ns_traf_gen *ntg;
	int rc;

	ntg = ns_traf_gen_find(name);
	if (ntg)
		return ntg;

	ntg = talloc_zero(g_nsi, struct ns_traf_gen);
	OSMO_ASSERT(ntg);
	ntg->name = talloc_strdup(ntg, name);
	ntg->timerfd.fd = -1;
	rc = osmo_timerfd_setup(&ntg->timerfd, ntg_timerfd_cb, ntg);
	OSMO_ASSERT(rc >= 0);
	llist_add_tail(&ntg->list, &g_ns_traf_gens);

	return ntg;
}

enum nodes {
	NTG_NODE = _LAST_OSMOVTY_NODE + 1,
};

static struct cmd_node ntg_node = {
	NTG_NODE,
	"%s(config-ns-traf-gen)# ",
	1,
};

static int config_write_ntg(struct vty *vty)
{
	struct ns_traf_gen *ntg;

	llist_for_each_entry(ntg, &g_ns_traf_gens, list) {
		vty_out(vty, "ns-traffic-generator %s%s", ntg->name, VTY_NEWLINE);
		vty_out(vty, " nsei %u%s", ntg->cfg.nsei, VTY_NEWLINE);
		vty_out(vty, " bvci %u%s", ntg->cfg.bvci, VTY_NEWLINE);
		vty_out(vty, " packet-size %u%s", ntg->cfg.pkt_size, VTY_NEWLINE);
		vty_out(vty, " interval-us %u%s", ntg->cfg.interval_us, VTY_NEWLINE);
		vty_out(vty, " lsp %u%s", ntg->cfg.lsp, VTY_NEWLINE);
		vty_out(vty, " lsp-mode %s%s", ntg->cfg.lsp_randomize ? "randomized" : "fixed", VTY_NEWLINE);
	}
	vty_out(vty, "mirror-mode %s%s", g_mirror_mode ? "enable" : "disable", VTY_NEWLINE);

	return 0;
}

DEFUN(ntg_start, ntg_start_stop_cmd,
	"ns-traffic-generator (start|stop) NAME",
	"Control named NS traffic generator\n"
	"Start generating traffic in this traffic generator\n"
	"Stop generating traffic in this traffic generator\n"
	"Name of NS traffic generator to start\n")
{
	struct ns_traf_gen *ntg = ns_traf_gen_find(argv[1]);
	if (!ntg) {
		vty_out(vty, "NS Traffic generator '%s' doesn't exist%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "start")) {
		struct timespec interval;
		if (ntg->running) {
			vty_out(vty, "NS Traffic generator was already started%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		interval.tv_sec = ntg->cfg.interval_us / 1000000;
		interval.tv_nsec = (ntg->cfg.interval_us % 1000000) * 1000;
		osmo_timerfd_schedule(&ntg->timerfd, NULL, &interval);
		ntg->running = true;
	} else {
		if (!ntg->running) {
			vty_out(vty, "NS Traffic generator was already stopped%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		osmo_timerfd_disable(&ntg->timerfd);
		ntg->running = false;
	}

	return CMD_SUCCESS;
}

DEFUN(ntg_nsei, ntg_nsei_cmd,
	"nsei <0-65535>",
	"NSEI to use when generating traffic\n"
	"NSEI to use when generating traffic\n")
{
	struct ns_traf_gen *ntg = vty->index;
	ntg->cfg.nsei = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(ntg_bvci, ntg_bvci_cmd,
	"bvci <0-65535>",
	"BVCI to use when generating traffic\n"
	"BVCI to use when generating traffic\n")
{
	struct ns_traf_gen *ntg = vty->index;
	ntg->cfg.bvci = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(ntg_pkt_size, ntg_pkt_size_cmd,
	"packet-size <0-2048>",
	"Packet size for generated NS-UNITDATA payload\n"
	"Packet size for generated NS-UNITDATA payload\n")
{
	struct ns_traf_gen *ntg = vty->index;
	ntg->cfg.pkt_size = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(ntg_pkt_intv_us, ntg_pkt_intv_us_cmd,
	"interval-us <0-1000000>",
	"Interval between packets in microseconds\n"
	"Interval between packets in microseconds\n")
{
	struct ns_traf_gen *ntg = vty->index;
	ntg->cfg.interval_us = atoi(argv[0]);
	if (ntg->running) {
		/* TODO: update timer */
	}
	return CMD_SUCCESS;
}

DEFUN(ntg_lsp, ntg_lsp_cmd,
	"lsp <0-4294967295>",
	"Link Selector Parameter (only used in fixed mode)\n"
	"Link Selector Parameter (only used in fixed mode)\n")
{
	struct ns_traf_gen *ntg = vty->index;
	ntg->cfg.lsp = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

DEFUN(ntg_lsp_mode, ntg_lsp_mode_cmd,
	"lsp-mode (fixed|randomized)",
	"Link Selector Parameter Mode\n"
	"Fixed / Staic LSP\n"
	"Randomized LSP\n")
{
	struct ns_traf_gen *ntg = vty->index;
	if (!strcmp(argv[0], "randomized"))
		ntg->cfg.lsp_randomize = true;
	else
		ntg->cfg.lsp_randomize = false;
	return CMD_SUCCESS;
}

DEFUN(gen_traffic, gen_traffic_cmd,
	"ns-traffic-generator NAME",
	"Configure a given NS traffic generator\n" "Name of NS traffic generator\n")
{
	struct ns_traf_gen *ntg = ns_traf_gen_find_or_alloc(argv[0]);

	if (!ntg)
		return CMD_WARNING;

	vty->index = ntg;
	vty->node = NTG_NODE;

	return CMD_SUCCESS;
}

DEFUN(mirror_mode, mirror_mode_cmd,
	"mirror-mode (enable|disable)",
	"Configure mirroring of incoming NS-UNITDATA\n"
	"Enable mirroring of incoming NS-UNITDATA\n"
	"Disable mirroring of incoming NS-UNITDATA\n")
{
	if (!strcmp(argv[0], "enable"))
		g_mirror_mode = true;
	else
		g_mirror_mode = false;

	return CMD_SUCCESS;
}


int nsdummy_vty_init(void)
{
	/* configuration of traffic generators via CONFIG / NTG node */
	install_element(CONFIG_NODE, &gen_traffic_cmd);
	install_element(CONFIG_NODE, &mirror_mode_cmd);
	install_node(&ntg_node, config_write_ntg);
	install_element(NTG_NODE, &ntg_nsei_cmd);
	install_element(NTG_NODE, &ntg_bvci_cmd);
	install_element(NTG_NODE, &ntg_pkt_size_cmd);
	install_element(NTG_NODE, &ntg_pkt_intv_us_cmd);
	install_element(NTG_NODE, &ntg_lsp_cmd);
	install_element(NTG_NODE, &ntg_lsp_mode_cmd);

	/* starting/stopping the traffic generators is in 'enable' mode, not 'config' */
	install_element(ENABLE_NODE, &ntg_start_stop_cmd);

	return 0;
}
