/*! \file gprs_ns2_vty.c
 * VTY interface for our GPRS Networks Service (NS) implementation. */

/* (C) 2009-2014 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016-2017 by sysmocom - s.f.m.c. GmbH
 * (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Alexander Couzens <lynxis@fe80.eu>
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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include <arpa/inet.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/socket.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>

#include "gprs_ns2_internal.h"

struct ns2_vty_priv {
	/* global listen */
	struct osmo_sockaddr_str udp;
	struct osmo_sockaddr_str frgreaddr;
	int dscp;
	enum gprs_ns2_vc_mode vc_mode;
	/* force vc mode if another configuration forces
	 * the vc mode. E.g. SNS configuration */
	bool force_vc_mode;
	const char *force_vc_mode_reason;
	bool frgre;

	struct llist_head vtyvc;
};

struct ns2_vty_vc {
	struct llist_head list;

	struct osmo_sockaddr_str remote;
	enum gprs_ns_ll ll;

	/* old vty code doesnt support multiple NSVCI per NSEI */
	uint16_t nsei;
	uint16_t nsvci;
	uint16_t frdlci;

	bool remote_end_is_sgsn;
	bool configured;
};

static struct gprs_ns2_inst *vty_nsi = NULL;
static struct ns2_vty_priv priv;

/* FIXME: this should go to some common file as it is copied
 * in vty_interface.c of the BSC */
static const struct value_string gprs_ns_timer_strs[] = {
	{ 0, "tns-block" },
	{ 1, "tns-block-retries" },
	{ 2, "tns-reset" },
	{ 3, "tns-reset-retries" },
	{ 4, "tns-test" },
	{ 5, "tns-alive" },
	{ 6, "tns-alive-retries" },
	{ 7, "tsns-prov" },
	{ 0, NULL }
};

static void log_set_nsvc_filter(struct log_target *target,
				struct gprs_ns2_vc *nsvc)
{
	if (nsvc) {
		target->filter_map |= (1 << LOG_FLT_GB_NSVC);
		target->filter_data[LOG_FLT_GB_NSVC] = nsvc;
	} else if (target->filter_data[LOG_FLT_GB_NSVC]) {
		target->filter_map = ~(1 << LOG_FLT_GB_NSVC);
		target->filter_data[LOG_FLT_GB_NSVC] = NULL;
	}
}

static struct cmd_node ns_node = {
	L_NS_NODE,
	"%s(config-ns)# ",
	1,
};

static struct ns2_vty_vc *vtyvc_alloc(uint16_t nsei) {
	struct ns2_vty_vc *vtyvc = talloc_zero(vty_nsi, struct ns2_vty_vc);
	if (!vtyvc)
		return vtyvc;

	vtyvc->nsei = nsei;

	llist_add(&vtyvc->list, &priv.vtyvc);

	return vtyvc;
}

static void ns2_vc_free(struct ns2_vty_vc *vtyvc) {
	if (!vtyvc)
		return;

	llist_del(&vtyvc->list);
	talloc_free(vtyvc);
}

static struct ns2_vty_vc *vtyvc_by_nsei(uint16_t nsei, bool alloc_missing) {
	struct ns2_vty_vc *vtyvc;

	llist_for_each_entry(vtyvc, &priv.vtyvc, list) {
		if (vtyvc->nsei == nsei)
			return vtyvc;
	}

	if (!alloc_missing)
		return NULL;

	vtyvc = vtyvc_alloc(nsei);
	if (!vtyvc)
		return vtyvc;

	vtyvc->nsei = nsei;
	return vtyvc;
}

static int config_write_ns(struct vty *vty)
{
	struct ns2_vty_vc *vtyvc;
	unsigned int i;
	struct osmo_sockaddr_str sockstr;

	vty_out(vty, "ns%s", VTY_NEWLINE);

	/* global configuration must be written first, as some of it may be
	 * relevant when creating the NSE/NSVC later below */

	vty_out(vty, " encapsulation framerelay-gre enabled %u%s",
		priv.frgre ? 1 : 0, VTY_NEWLINE);

	if (priv.frgre) {
		if (strlen(priv.frgreaddr.ip)) {
			vty_out(vty, " encapsulation framerelay-gre local-ip %s%s",
				sockstr.ip, VTY_NEWLINE);
		}
	} else {
		if (strlen(priv.udp.ip)) {
			vty_out(vty, " encapsulation udp local-ip %s%s",
				priv.udp.ip, VTY_NEWLINE);
		}

		if (priv.udp.port)
			vty_out(vty, " encapsulation udp local-port %u%s",
				priv.udp.port, VTY_NEWLINE);
	}

	if (priv.dscp)
		vty_out(vty, " encapsulation udp dscp %d%s",
			priv.dscp, VTY_NEWLINE);

	vty_out(vty, " encapsulation udp use-reset-block-unblock %s%s",
		priv.vc_mode == NS2_VC_MODE_BLOCKRESET ? "enabled" : "disabled", VTY_NEWLINE);

	llist_for_each_entry(vtyvc, &priv.vtyvc, list) {
		vty_out(vty, " nse %u nsvci %u%s",
			vtyvc->nsei, vtyvc->nsvci, VTY_NEWLINE);

		vty_out(vty, " nse %u remote-role %s%s",
			vtyvc->nsei, vtyvc->remote_end_is_sgsn ? "sgsn" : "bss",
			VTY_NEWLINE);

		switch (vtyvc->ll) {
		case GPRS_NS_LL_UDP:
			vty_out(vty, " nse %u encapsulation udp%s", vtyvc->nsei, VTY_NEWLINE);
			vty_out(vty, " nse %u remote-ip %s%s",
				vtyvc->nsei,
				vtyvc->remote.ip,
				VTY_NEWLINE);
			vty_out(vty, " nse %u remote-port %u%s",
				vtyvc->nsei, vtyvc->remote.port,
				VTY_NEWLINE);
			break;
		case GPRS_NS_LL_FR_GRE:
			vty_out(vty, " nse %u encapsulation framerelay-gre%s",
				vtyvc->nsei, VTY_NEWLINE);
			vty_out(vty, " nse %u remote-ip %s%s",
				vtyvc->nsei,
				vtyvc->remote.ip,
				VTY_NEWLINE);
			vty_out(vty, " nse %u fr-dlci %u%s",
				vtyvc->nsei, vtyvc->frdlci,
				VTY_NEWLINE);
			break;
		default:
			break;
		}
	}

	for (i = 0; i < ARRAY_SIZE(vty_nsi->timeout); i++)
		vty_out(vty, " timer %s %u%s",
			get_value_string(gprs_ns_timer_strs, i),
			vty_nsi->timeout[i], VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_ns, cfg_ns_cmd,
      "ns",
      "Configure the GPRS Network Service")
{
	vty->node = L_NS_NODE;
	return CMD_SUCCESS;
}

static void dump_nsvc(struct vty *vty, struct gprs_ns2_vc *nsvc, bool stats)
{
	struct osmo_sockaddr_str remote;
	struct osmo_sockaddr_str local;
	struct osmo_sockaddr *sockaddr;

	switch (nsvc->ll) {
	case GPRS_NS_LL_UDP: {
		sockaddr = gprs_ns2_ip_vc_sockaddr(nsvc);
		if (!sockaddr) {
			vty_out(vty, "unknown");
			break;
		}

		if (osmo_sockaddr_str_from_sockaddr(
					&remote,
					&sockaddr->u.sas)) {
			vty_out(vty, "unknown");
			break;
		}

		vty_out(vty, "%s:%u <> %s:%u", local.ip, local.port, remote.ip, remote.port);
		break;
	}
	case GPRS_NS_LL_FR_GRE:
		/* TODO: implement dump_nse for FR GRE */
	case GPRS_NS_LL_E1:
		/* TODO: implement dump_nse for E1 */
		break;
	}

	vty_out(vty, "Remote: %s ",
		 gprs_ns2_ll_str(nsvc));

	vty_out(vty, "%s%s", nsvc->ll == GPRS_NS_LL_UDP ? "UDP" : "FR-GRE", VTY_NEWLINE);

	if (stats) {
		vty_out_rate_ctr_group(vty, " ", nsvc->ctrg);
		vty_out_stat_item_group(vty, " ", nsvc->statg);
	}
}

static void dump_nse(struct vty *vty, const struct gprs_ns2_nse *nse, bool stats, bool persistent_only)
{
	struct gprs_ns2_vc *nsvc;

	vty_out(vty, "NSEI %5u%s",
		nse->nsei, VTY_NEWLINE);

	gprs_ns2_sns_dump_vty(vty, nse, stats);
	llist_for_each_entry(nsvc, &nse->nsvc, list) {
		if (persistent_only) {
			if (nsvc->persistent)
				dump_nsvc(vty, nsvc, stats);
		} else {
			dump_nsvc(vty, nsvc, stats);
		}
	}
}

static void dump_ns(struct vty *vty, const struct gprs_ns2_inst *nsi, bool stats, bool persistent_only)
{
	struct gprs_ns2_nse *nse;

	llist_for_each_entry(nse, &nsi->nse, list) {
		dump_nse(vty, nse, stats, persistent_only);
		break;
	}

}

DEFUN(show_ns, show_ns_cmd, "show ns",
	SHOW_STR "Display information about the NS protocol")
{
	dump_ns(vty, vty_nsi, false, false);
	return CMD_SUCCESS;
}

DEFUN(show_ns_stats, show_ns_stats_cmd, "show ns stats",
	SHOW_STR
	"Display information about the NS protocol\n"
	"Include statistics\n")
{
	dump_ns(vty, vty_nsi, true, false);
	return CMD_SUCCESS;
}

DEFUN(show_ns_pers, show_ns_pers_cmd, "show ns persistent",
	SHOW_STR
	"Display information about the NS protocol\n"
	"Show only persistent NS\n")
{
	dump_ns(vty, vty_nsi, true, true);
	return CMD_SUCCESS;
}

DEFUN(show_nse, show_nse_cmd, "show ns (nsei|nsvc) <0-65535> [stats]",
	SHOW_STR "Display information about the NS protocol\n"
	"Select one NSE by its NSE Identifier\n"
	"Select one NSE by its NS-VC Identifier\n"
	"The Identifier of selected type\n"
	"Include Statistics\n")
{
	struct gprs_ns2_inst *nsi = vty_nsi;
	struct gprs_ns2_nse *nse;
	struct gprs_ns2_vc *nsvc;
	uint16_t id = atoi(argv[1]);
	bool show_stats = false;

	if (argc >= 3)
		show_stats = true;

	if (!strcmp(argv[0], "nsei")) {
		nse = gprs_ns2_nse_by_nsei(nsi, id);
		if (!nse) {
			return CMD_WARNING;
		}

		dump_nse(vty, nse, show_stats, false);
	} else {
		nsvc = gprs_ns2_nsvc_by_nsvci(nsi, id);

		if (!nsvc) {
			vty_out(vty, "No such NS Entity%s", VTY_NEWLINE);
			return CMD_WARNING;
		}

		dump_nsvc(vty, nsvc, show_stats);
	}

	return CMD_SUCCESS;
}

#define NSE_CMD_STR "Persistent NS Entity\n" "NS Entity ID (NSEI)\n"

DEFUN(cfg_nse_nsvc, cfg_nse_nsvci_cmd,
	"nse <0-65535> nsvci <0-65535>",
	NSE_CMD_STR
	"NS Virtual Connection\n"
	"NS Virtual Connection ID (NSVCI)\n"
	)
{
	struct ns2_vty_vc *vtyvc;

	uint16_t nsei = atoi(argv[0]);
	uint16_t nsvci = atoi(argv[1]);

	vtyvc = vtyvc_by_nsei(nsei, true);
	if (!vtyvc) {
		vty_out(vty, "Can not allocate space %s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vtyvc->nsvci = nsvci;

	return CMD_SUCCESS;
}

DEFUN(cfg_nse_remoteip, cfg_nse_remoteip_cmd,
	"nse <0-65535> remote-ip " VTY_IPV46_CMD,
	NSE_CMD_STR
	"Remote IP Address\n"
	"Remote IPv4 Address\n"
	"Remote IPv6 Address\n")
{
	uint16_t nsei = atoi(argv[0]);
	struct ns2_vty_vc *vtyvc;

	vtyvc = vtyvc_by_nsei(nsei, true);
	if (!vtyvc) {
		vty_out(vty, "Can not allocate space %s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	osmo_sockaddr_str_from_str2(&vtyvc->remote, argv[1]);

	return CMD_SUCCESS;
}

DEFUN(cfg_nse_remoteport, cfg_nse_remoteport_cmd,
	"nse <0-65535> remote-port <0-65535>",
	NSE_CMD_STR
	"Remote UDP Port\n"
	"Remote UDP Port Number\n")
{
	uint16_t nsei = atoi(argv[0]);
	uint16_t port = atoi(argv[1]);
	struct ns2_vty_vc *vtyvc;

	vtyvc = vtyvc_by_nsei(nsei, true);
	if (!vtyvc) {
		vty_out(vty, "Can not allocate space %s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vtyvc->remote.port = port;

	return CMD_SUCCESS;
}

DEFUN(cfg_nse_fr_dlci, cfg_nse_fr_dlci_cmd,
	"nse <0-65535> fr-dlci <16-1007>",
	NSE_CMD_STR
	"Frame Relay DLCI\n"
	"Frame Relay DLCI Number\n")
{
	uint16_t nsei = atoi(argv[0]);
	uint16_t dlci = atoi(argv[1]);
	struct ns2_vty_vc *vtyvc;

	vtyvc = vtyvc_by_nsei(nsei, true);
	if (!vtyvc) {
		vty_out(vty, "Can not allocate space %s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (vtyvc->ll != GPRS_NS_LL_FR_GRE) {
		vty_out(vty, "Warning: seting FR DLCI on non-FR NSE%s",
			VTY_NEWLINE);
	}

	vtyvc->frdlci = dlci;

	return CMD_SUCCESS;
}

DEFUN(cfg_nse_encaps, cfg_nse_encaps_cmd,
	"nse <0-65535> encapsulation (udp|framerelay-gre)",
	NSE_CMD_STR
	"Encapsulation for NS\n"
	"UDP/IP Encapsulation\n" "Frame-Relay/GRE/IP Encapsulation\n")
{
	uint16_t nsei = atoi(argv[0]);
	struct ns2_vty_vc *vtyvc;

	vtyvc = vtyvc_by_nsei(nsei, true);
	if (!vtyvc) {
		vty_out(vty, "Can not allocate space %s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[1], "udp"))
		vtyvc->ll = GPRS_NS_LL_UDP;
	else
		vtyvc->ll = GPRS_NS_LL_FR_GRE;

	return CMD_SUCCESS;
}

DEFUN(cfg_nse_remoterole, cfg_nse_remoterole_cmd,
	"nse <0-65535> remote-role (sgsn|bss)",
	NSE_CMD_STR
	"Remote NSE Role\n"
	"Remote Peer is SGSN\n"
	"Remote Peer is BSS\n")
{
	uint16_t nsei = atoi(argv[0]);
	struct ns2_vty_vc *vtyvc;

	vtyvc = vtyvc_by_nsei(nsei, true);
	if (!vtyvc) {
		vty_out(vty, "Can not allocate space %s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[1], "sgsn"))
		vtyvc->remote_end_is_sgsn = 1;
	else
		vtyvc->remote_end_is_sgsn = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_nse, cfg_no_nse_cmd,
	"no nse <0-65535>",
	"Delete Persistent NS Entity\n"
	"Delete " NSE_CMD_STR)
{
	uint16_t nsei = atoi(argv[0]);
	struct ns2_vty_vc *vtyvc;

	vtyvc = vtyvc_by_nsei(nsei, false);
	if (!vtyvc) {
		vty_out(vty, "The NSE %d does not exists.%s", nsei, VTY_NEWLINE);
		return CMD_WARNING;
	}

	ns2_vc_free(vtyvc);

	return CMD_SUCCESS;
}

DEFUN(cfg_ns_timer, cfg_ns_timer_cmd,
	"timer " NS_TIMERS " <0-65535>",
	"Network Service Timer\n"
	NS_TIMERS_HELP "Timer Value\n")
{
	int idx = get_string_value(gprs_ns_timer_strs, argv[0]);
	int val = atoi(argv[1]);

	if (idx < 0 || idx >= ARRAY_SIZE(vty_nsi->timeout))
		return CMD_WARNING;

	vty_nsi->timeout[idx] = val;

	return CMD_SUCCESS;
}

#define ENCAPS_STR "NS encapsulation options\n"

DEFUN(cfg_nsip_local_ip, cfg_nsip_local_ip_cmd,
      "encapsulation udp local-ip " VTY_IPV46_CMD,
	ENCAPS_STR "NS over UDP Encapsulation\n"
	"Set the IP address on which we listen for NS/UDP\n"
	"IPv4 Address\n"
	"IPv6 Address\n")
{
	osmo_sockaddr_str_from_str2(&priv.udp, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_nsip_local_port, cfg_nsip_local_port_cmd,
      "encapsulation udp local-port <0-65535>",
	ENCAPS_STR "NS over UDP Encapsulation\n"
	"Set the UDP port on which we listen for NS/UDP\n"
	"UDP port number\n")
{
	unsigned int port = atoi(argv[0]);

	priv.udp.port = port;

	return CMD_SUCCESS;
}

DEFUN(cfg_nsip_dscp, cfg_nsip_dscp_cmd,
      "encapsulation udp dscp <0-255>",
	ENCAPS_STR "NS over UDP Encapsulation\n"
	"Set DSCP/TOS on the UDP socket\n" "DSCP Value\n")
{
	int dscp = atoi(argv[0]);
	struct gprs_ns2_vc_bind *bind;

	priv.dscp = dscp;

	llist_for_each_entry(bind, &vty_nsi->binding, list) {
		if (gprs_ns2_is_ip_bind(bind))
			gprs_ns2_ip_bind_set_dscp(bind, dscp);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_nsip_res_block_unblock, cfg_nsip_res_block_unblock_cmd,
	"encapsulation udp use-reset-block-unblock (enabled|disabled)",
	ENCAPS_STR "NS over UDP Encapsulation\n"
	"Use NS-{RESET,BLOCK,UNBLOCK} procedures in violation of 3GPP TS 48.016\n"
	"Enable NS-{RESET,BLOCK,UNBLOCK}\n"
	"Disable NS-{RESET,BLOCK,UNBLOCK}\n")
{
	enum gprs_ns2_vc_mode vc_mode;
	struct gprs_ns2_vc_bind *bind;

	if (!strcmp(argv[0], "enabled"))
		vc_mode = NS2_VC_MODE_BLOCKRESET;
	else
		vc_mode = NS2_VC_MODE_ALIVE;

	if (priv.force_vc_mode) {
		if (priv.vc_mode != vc_mode)
		{
			vty_out(vty, "Ignoring use-reset-block because it's already set by %s.%s",
				priv.force_vc_mode_reason, VTY_NEWLINE);
			return CMD_WARNING;
		}

		return CMD_SUCCESS;
	}

	priv.vc_mode = vc_mode;

	llist_for_each_entry(bind, &vty_nsi->binding, list) {
		gprs_ns2_bind_set_mode(bind, priv.vc_mode);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_frgre_local_ip, cfg_frgre_local_ip_cmd,
      "encapsulation framerelay-gre local-ip " VTY_IPV46_CMD,
	ENCAPS_STR "NS over Frame Relay over GRE Encapsulation\n"
	"Set the IP address on which we listen for NS/FR/GRE\n"
	"IPv4 Address\n"
	"IPv6 Address\n")
{
	osmo_sockaddr_str_from_str2(&priv.frgreaddr, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_frgre_enable, cfg_frgre_enable_cmd,
      "encapsulation framerelay-gre enabled (1|0)",
	ENCAPS_STR "NS over Frame Relay over GRE Encapsulation\n"
	"Enable or disable Frame Relay over GRE\n"
	"Enable\n" "Disable\n")
{
	int enabled = atoi(argv[0]);

	priv.frgre = enabled;

	return CMD_SUCCESS;
}

/* TODO: allow vty to reset/block/unblock nsvc/nsei */

/* TODO: add filter for NSEI as ns1 code does */
/* TODO: add filter for single connection by description */
DEFUN(logging_fltr_nsvc,
      logging_fltr_nsvc_cmd,
      "logging filter nsvc nsvci <0-65535>",
	LOGGING_STR FILTER_STR
	"Filter based on NS Virtual Connection\n"
	"Identify NS-VC by NSVCI\n"
	"Numeric identifier\n")
{
	struct log_target *tgt;
	struct gprs_ns2_vc *nsvc;
	uint16_t id = atoi(argv[1]);

	log_tgt_mutex_lock();
	tgt = osmo_log_vty2tgt(vty);
	if (!tgt) {
		log_tgt_mutex_unlock();
		return CMD_WARNING;
	}

	nsvc = gprs_ns2_nsvc_by_nsvci(vty_nsi, id);
	if (!nsvc) {
		vty_out(vty, "No NS-VC by that identifier%s", VTY_NEWLINE);
		log_tgt_mutex_unlock();
		return CMD_WARNING;
	}

	log_set_nsvc_filter(tgt, nsvc);
	log_tgt_mutex_unlock();
	return CMD_SUCCESS;
}

int gprs_ns2_vty_init(struct gprs_ns2_inst *nsi)
{
	static bool vty_elements_installed = false;

	vty_nsi = nsi;
	memset(&priv, 0, sizeof(struct ns2_vty_priv));
	INIT_LLIST_HEAD(&priv.vtyvc);
	priv.vc_mode = NS2_VC_MODE_BLOCKRESET;

	/* Regression test code may call this function repeatedly, so make sure
	 * that VTY elements are not duplicated, which would assert. */
	if (vty_elements_installed)
		return 0;
	vty_elements_installed = true;

	install_element_ve(&show_ns_cmd);
	install_element_ve(&show_ns_stats_cmd);
	install_element_ve(&show_ns_pers_cmd);
	install_element_ve(&show_nse_cmd);
	install_element_ve(&logging_fltr_nsvc_cmd);

	install_element(CFG_LOG_NODE, &logging_fltr_nsvc_cmd);

	install_element(CONFIG_NODE, &cfg_ns_cmd);
	install_node(&ns_node, config_write_ns);
	install_element(L_NS_NODE, &cfg_nse_nsvci_cmd);
	install_element(L_NS_NODE, &cfg_nse_remoteip_cmd);
	install_element(L_NS_NODE, &cfg_nse_remoteport_cmd);
	install_element(L_NS_NODE, &cfg_nse_fr_dlci_cmd);
	install_element(L_NS_NODE, &cfg_nse_encaps_cmd);
	install_element(L_NS_NODE, &cfg_nse_remoterole_cmd);
	install_element(L_NS_NODE, &cfg_no_nse_cmd);
	install_element(L_NS_NODE, &cfg_ns_timer_cmd);
	install_element(L_NS_NODE, &cfg_nsip_local_ip_cmd);
	install_element(L_NS_NODE, &cfg_nsip_local_port_cmd);
	install_element(L_NS_NODE, &cfg_nsip_dscp_cmd);
	install_element(L_NS_NODE, &cfg_nsip_res_block_unblock_cmd);
	install_element(L_NS_NODE, &cfg_frgre_enable_cmd);
	install_element(L_NS_NODE, &cfg_frgre_local_ip_cmd);

	/* TODO: nsvc/nsei command to reset states or reset/block/unblock nsei/nsvcs */

	return 0;
}

/*!
 * \brief gprs_ns2_vty_create parse the vty tree into ns nodes
 * It has to be in different steps to ensure the bind is created before creating VCs.
 * \return 0 on success
 */
int gprs_ns2_vty_create() {
	struct ns2_vty_vc *vtyvc;
	struct gprs_ns2_vc_bind *bind;
	struct gprs_ns2_nse *nse;
	struct gprs_ns2_vc *nsvc;
	struct osmo_sockaddr sockaddr;

	if (!vty_nsi)
		return -1;

	/* create binds, only support a single bind. either FR or UDP */
	if (priv.frgre) {
		/* TODO not yet supported !*/
		return -1;
	} else {
		/* UDP */
		osmo_sockaddr_str_to_sockaddr(&priv.udp, &sockaddr.u.sas);
		if (gprs_ns2_ip_bind(vty_nsi, &sockaddr, priv.dscp, &bind)) {
			/* TODO: could not bind on the specific address */
			return -1;
		}
		gprs_ns2_bind_set_mode(bind, priv.vc_mode);
	}

	/* create vcs */
	llist_for_each_entry(vtyvc, &priv.vtyvc, list) {
		if (strlen(vtyvc->remote.ip) == 0) {
			/* Invalid IP for VC */
			continue;
		}

		if (!vtyvc->remote.port) {
			/* Invalid port for VC */
			continue;
		}

		if (osmo_sockaddr_str_to_sockaddr(&vtyvc->remote, &sockaddr.u.sas)) {
			/* Invalid sockaddr for VC */
			continue;
		}

		nse = gprs_ns2_nse_by_nsei(vty_nsi, vtyvc->nsei);
		if (!nse) {
			nse = gprs_ns2_create_nse(vty_nsi, vtyvc->nsei);
			if (!nse) {
				/* Could not create NSE for VTY */
				continue;
			}
		}
		nse->persistent = true;

		if (bind) {
			nsvc = gprs_ns2_ip_connect(bind,
						   &sockaddr,
						   nse,
						   vtyvc->nsvci);
			if (!nsvc) {
				/* Could not create NSVC, connect failed */
				continue;
			}
			nsvc->persistent = true;
		}
	}


	return 0;
}

/*!
 * \brief ns2_vty_bind_apply will be called when a new bind is created to apply vty settings
 * \param bind
 * \return
 */
void ns2_vty_bind_apply(struct gprs_ns2_vc_bind *bind)
{
	gprs_ns2_bind_set_mode(bind, priv.vc_mode);
}

/*!
 * \brief ns2_vty_force_vc_mode force a mode and prevents the vty from overwriting it.
 * \param force if true mode and reason will be set. false to allow modification via vty.
 * \param mode
 * \param reason A description shown to the user when a vty command wants to change the mode.
 */
void gprs_ns2_vty_force_vc_mode(bool force, enum gprs_ns2_vc_mode mode, const char *reason)
{
	priv.force_vc_mode = force;

	if (force) {
		priv.vc_mode = mode;
		priv.force_vc_mode_reason = reason;
	}
}
