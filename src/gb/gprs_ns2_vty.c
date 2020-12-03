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
#include <net/if.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/socket.h>
#include <osmocom/gprs/frame_relay.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>

#include "gprs_ns2_internal.h"

#define SHOW_NS_STR "Display information about the NS protocol\n"

struct ns2_vty_priv {
	/* global listen */
	struct osmo_sockaddr_str udp;
	struct osmo_sockaddr_str frgreaddr;
	int dscp;
	enum gprs_ns2_vc_mode vc_mode;
	bool frgre;

	struct llist_head vtyvc;
};

struct ns2_vty_vc {
	struct llist_head list;

	struct osmo_sockaddr_str remote;
	enum gprs_ns2_ll ll;

	/* old vty code doesnt support multiple NSVCI per NSEI */
	uint16_t nsei;
	uint16_t nsvci;
	uint16_t frdlci;

	struct {
		enum osmo_fr_role role;
	} fr;

	char netif[IF_NAMESIZE];

	bool remote_end_is_sgsn;
	bool configured;
};

static struct gprs_ns2_inst *vty_nsi = NULL;
static struct ns2_vty_priv priv;
static struct osmo_fr_network *vty_fr_network = NULL;

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

static void log_set_nse_filter(struct log_target *target,
				struct gprs_ns2_nse *nse)
{
	if (nse) {
		target->filter_map |= (1 << LOG_FLT_GB_NSE);
		target->filter_data[LOG_FLT_GB_NSE] = nse;
	} else if (target->filter_data[LOG_FLT_GB_NSE]) {
		target->filter_map = ~(1 << LOG_FLT_GB_NSE);
		target->filter_data[LOG_FLT_GB_NSE] = NULL;
	}
}

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
		case GPRS_NS2_LL_UDP:
			vty_out(vty, " nse %u encapsulation udp%s", vtyvc->nsei, VTY_NEWLINE);
			vty_out(vty, " nse %u remote-ip %s%s",
				vtyvc->nsei,
				vtyvc->remote.ip,
				VTY_NEWLINE);
			vty_out(vty, " nse %u remote-port %u%s",
				vtyvc->nsei, vtyvc->remote.port,
				VTY_NEWLINE);
			break;
		case GPRS_NS2_LL_FR_GRE:
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
		case GPRS_NS2_LL_FR:
			vty_out(vty, " nse %u fr %s dlci %u%s",
				vtyvc->nsei, vtyvc->netif, vtyvc->frdlci,
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
	char nsvci_str[32];

	if (nsvc->nsvci_is_valid)
		snprintf(nsvci_str, sizeof(nsvci_str), "%05u", nsvc->nsvci);
	else
		snprintf(nsvci_str, sizeof(nsvci_str), "none");

	vty_out(vty, " NSVCI %s: %s %s data_weight=%u sig_weight=%u %s%s", nsvci_str,
		osmo_fsm_inst_state_name(nsvc->fi),
		nsvc->persistent ? "PERSIST" : "DYNAMIC",
		nsvc->data_weight, nsvc->sig_weight,
		gprs_ns2_ll_str(nsvc), VTY_NEWLINE);

	if (stats) {
		vty_out_rate_ctr_group(vty, "  ", nsvc->ctrg);
		vty_out_stat_item_group(vty, "  ", nsvc->statg);
	}
}

static void dump_nse(struct vty *vty, const struct gprs_ns2_nse *nse, bool stats, bool persistent_only)
{
	struct gprs_ns2_vc *nsvc;

	vty_out(vty, "NSEI %05u: %s, %s%s", nse->nsei, gprs_ns2_lltype_str(nse->ll),
		nse->alive ? "ALIVE" : "DEAD", VTY_NEWLINE);

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

static void dump_bind(struct vty *vty, const struct gprs_ns2_vc_bind *bind, bool stats)
{
	if (bind->dump_vty)
		bind->dump_vty(bind, vty, stats);
}

static void dump_ns_bind(struct vty *vty, const struct gprs_ns2_inst *nsi, bool stats)
{
	struct gprs_ns2_vc_bind *bind;

	llist_for_each_entry(bind, &nsi->binding, list) {
		dump_bind(vty, bind, stats);
	}
}


static void dump_ns_entities(struct vty *vty, const struct gprs_ns2_inst *nsi, bool stats, bool persistent_only)
{
	struct gprs_ns2_nse *nse;

	llist_for_each_entry(nse, &nsi->nse, list) {
		dump_nse(vty, nse, stats, persistent_only);
	}
}

/* Backwards compatibility, among other things for the TestVTYGbproxy which expects
 * 'show ns' to output something about binds */
DEFUN_HIDDEN(show_ns, show_ns_cmd, "show ns",
	SHOW_STR SHOW_NS_STR)
{
	dump_ns_entities(vty, vty_nsi, false, false);
	dump_ns_bind(vty, vty_nsi, false);
	return CMD_SUCCESS;
}


DEFUN(show_ns_binds, show_ns_binds_cmd, "show ns binds [stats]",
	SHOW_STR SHOW_NS_STR
	"Display information about the NS protocol binds\n"
	"Include statistic\n")
{
	bool stats = false;
	if (argc > 0)
		stats = true;

	dump_ns_bind(vty, vty_nsi, stats);
	return CMD_SUCCESS;
}

DEFUN(show_ns_entities, show_ns_entities_cmd, "show ns entities [stats]",
	SHOW_STR SHOW_NS_STR
	"Display information about the NS protocol entities (NSEs)\n"
	"Include statistics\n")
{
	bool stats = false;
	if (argc > 0)
		stats = true;

	dump_ns_entities(vty, vty_nsi, stats, false);
	return CMD_SUCCESS;
}

DEFUN(show_ns_pers, show_ns_pers_cmd, "show ns persistent",
	SHOW_STR SHOW_NS_STR
	"Show only persistent NS\n")
{
	dump_ns_entities(vty, vty_nsi, true, true);
	return CMD_SUCCESS;
}

DEFUN(show_nse, show_nse_cmd, "show ns (nsei|nsvc) <0-65535> [stats]",
	SHOW_STR SHOW_NS_STR
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

static int nsvc_force_unconf_cb(struct gprs_ns2_vc *nsvc, void *ctx)
{
	gprs_ns2_vc_force_unconfigured(nsvc);
	return 0;
}

DEFUN_HIDDEN(nsvc_force_unconf, nsvc_force_unconf_cmd,
	"nsvc nsei <0-65535> force-unconfigured",
	"NS Virtual Connection\n"
	"The NSEI\n"
	"Reset the NSVCs back to initial state\n"
	)
{
	struct gprs_ns2_inst *nsi = vty_nsi;
	struct gprs_ns2_nse *nse;

	uint16_t id = atoi(argv[0]);

	nse = gprs_ns2_nse_by_nsei(nsi, id);
	if (!nse) {
		vty_out(vty, "Could not find NSE for NSEI %u%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Perform the operation for all nsvc */
	gprs_ns2_nse_foreach_nsvc(nse, nsvc_force_unconf_cb, NULL);

	return CMD_SUCCESS;
}

#define NSE_CMD_STR "Persistent NS Entity\n" "NS Entity ID (NSEI)\n"

DEFUN(cfg_nse_fr, cfg_nse_fr_cmd,
	"nse <0-65535> nsvci <0-65535> (fr|frnet) NETIF dlci <0-1023>",
	NSE_CMD_STR
	"NS Virtual Connection\n"
	"NS Virtual Connection ID (NSVCI)\n"
	"Frame Relay User-Side\n"
	"Frame Relay Network-Side\n"
	IFNAME_STR
	"Data Link connection identifier\n"
	"Data Link connection identifier\n"
	)
{
	struct ns2_vty_vc *vtyvc;

	uint16_t nsei = atoi(argv[0]);
	uint16_t nsvci = atoi(argv[1]);
	const char *role = argv[2];
	const char *name = argv[3];
	uint16_t dlci = atoi(argv[4]);

	vtyvc = vtyvc_by_nsei(nsei, true);
	if (!vtyvc) {
		vty_out(vty, "Can not allocate space %s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(role, "fr"))
		vtyvc->fr.role = FR_ROLE_USER_EQUIPMENT;
	else if (!strcmp(role, "frnet"))
		vtyvc->fr.role = FR_ROLE_NETWORK_EQUIPMENT;

	osmo_strlcpy(vtyvc->netif, name, sizeof(vtyvc->netif));
	vtyvc->frdlci = dlci;
	vtyvc->nsvci = nsvci;
	vtyvc->ll = GPRS_NS2_LL_FR;

	return CMD_SUCCESS;
}

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
	"nse <0-65535> nsvci <0-65535> fr-dlci <16-1007>",
	NSE_CMD_STR
	"NS Virtual Connection\n"
	"NS Virtual Connection ID (NSVCI)\n"
	"Frame Relay DLCI\n"
	"Frame Relay DLCI Number\n")
{
	uint16_t nsei = atoi(argv[0]);
	uint16_t nsvci = atoi(argv[1]);
	uint16_t dlci = atoi(argv[2]);
	struct ns2_vty_vc *vtyvc;

	vtyvc = vtyvc_by_nsei(nsei, true);
	if (!vtyvc) {
		vty_out(vty, "Can not allocate space %s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vtyvc->frdlci = dlci;
	vtyvc->nsvci = nsvci;

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
		vtyvc->ll = GPRS_NS2_LL_UDP;
	else
		vtyvc->ll = GPRS_NS2_LL_FR_GRE;

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

	if (!strcmp(argv[0], "enabled"))
		vc_mode = NS2_VC_MODE_BLOCKRESET;
	else
		vc_mode = NS2_VC_MODE_ALIVE;

	priv.vc_mode = vc_mode;

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

DEFUN(logging_fltr_nse,
      logging_fltr_nse_cmd,
      "logging filter nse nsei <0-65535>",
	LOGGING_STR FILTER_STR
	"Filter based on NS Entity\n"
	"Identify NSE by NSEI\n"
	"Numeric identifier\n")
{
	struct log_target *tgt;
	struct gprs_ns2_nse *nse;
	uint16_t id = atoi(argv[0]);

	log_tgt_mutex_lock();
	tgt = osmo_log_vty2tgt(vty);
	if (!tgt) {
		log_tgt_mutex_unlock();
		return CMD_WARNING;
	}

	nse = gprs_ns2_nse_by_nsei(vty_nsi, id);
	if (!nse) {
		vty_out(vty, "No NSE by that identifier%s", VTY_NEWLINE);
		log_tgt_mutex_unlock();
		return CMD_WARNING;
	}

	log_set_nse_filter(tgt, nse);
	log_tgt_mutex_unlock();
	return CMD_SUCCESS;
}

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
	uint16_t id = atoi(argv[0]);

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

/**
 * gprs_ns2_vty_init initialize the vty
 * \param[inout] nsi
 * \param[in] default_bind set the default address to bind to. Can be NULL.
 * \return 0 on success
 */
int gprs_ns2_vty_init(struct gprs_ns2_inst *nsi,
		      const struct osmo_sockaddr_str *default_bind)
{
	static bool vty_elements_installed = false;

	vty_nsi = nsi;
	memset(&priv, 0, sizeof(struct ns2_vty_priv));
	INIT_LLIST_HEAD(&priv.vtyvc);
	priv.vc_mode = NS2_VC_MODE_BLOCKRESET;
	if (default_bind)
		memcpy(&priv.udp, default_bind, sizeof(*default_bind));

	/* Regression test code may call this function repeatedly, so make sure
	 * that VTY elements are not duplicated, which would assert. */
	if (vty_elements_installed)
		return 0;
	vty_elements_installed = true;

	install_lib_element_ve(&show_ns_cmd);
	install_lib_element_ve(&show_ns_binds_cmd);
	install_lib_element_ve(&show_ns_entities_cmd);
	install_lib_element_ve(&show_ns_pers_cmd);
	install_lib_element_ve(&show_nse_cmd);
	install_lib_element_ve(&logging_fltr_nse_cmd);
	install_lib_element_ve(&logging_fltr_nsvc_cmd);

	install_lib_element(ENABLE_NODE, &nsvc_force_unconf_cmd);

	install_lib_element(CFG_LOG_NODE, &logging_fltr_nse_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_fltr_nsvc_cmd);

	install_lib_element(CONFIG_NODE, &cfg_ns_cmd);
	install_node(&ns_node, config_write_ns);
	install_lib_element(L_NS_NODE, &cfg_nse_fr_cmd);
	install_lib_element(L_NS_NODE, &cfg_nse_nsvci_cmd);
	install_lib_element(L_NS_NODE, &cfg_nse_remoteip_cmd);
	install_lib_element(L_NS_NODE, &cfg_nse_remoteport_cmd);
	install_lib_element(L_NS_NODE, &cfg_nse_fr_dlci_cmd);
	install_lib_element(L_NS_NODE, &cfg_nse_encaps_cmd);
	install_lib_element(L_NS_NODE, &cfg_nse_remoterole_cmd);
	install_lib_element(L_NS_NODE, &cfg_no_nse_cmd);
	install_lib_element(L_NS_NODE, &cfg_ns_timer_cmd);
	install_lib_element(L_NS_NODE, &cfg_nsip_local_ip_cmd);
	install_lib_element(L_NS_NODE, &cfg_nsip_local_port_cmd);
	install_lib_element(L_NS_NODE, &cfg_nsip_dscp_cmd);
	install_lib_element(L_NS_NODE, &cfg_nsip_res_block_unblock_cmd);
	install_lib_element(L_NS_NODE, &cfg_frgre_enable_cmd);
	install_lib_element(L_NS_NODE, &cfg_frgre_local_ip_cmd);

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
	struct gprs_ns2_vc_bind *bind, *fr;
	struct gprs_ns2_nse *nse;
	struct gprs_ns2_vc *nsvc;
	struct osmo_sockaddr sockaddr;
	enum gprs_ns2_dialect dialect = NS2_DIALECT_UNDEF;
	int rc = 0;

	if (!vty_nsi)
		return -1;

	/* create binds, only support a single bind. either FR or UDP */
	if (priv.frgre) {
		/* TODO not yet supported !*/
		return -1;
	} else {
		/* UDP */
		osmo_sockaddr_str_to_sockaddr(&priv.udp, &sockaddr.u.sas);
		if (gprs_ns2_ip_bind(vty_nsi, "vtybind", &sockaddr, priv.dscp, &bind)) {
			/* TODO: could not bind on the specific address */
			return -1;
		}
		bind->accept_ipaccess = true;
	}

	/* create vcs */
	llist_for_each_entry(vtyvc, &priv.vtyvc, list) {
		/* validate settings */
		switch (vtyvc->ll) {
		case GPRS_NS2_LL_UDP:
			dialect = NS2_DIALECT_IPACCESS;
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
			break;
		case GPRS_NS2_LL_FR:
			dialect = NS2_DIALECT_STATIC_RESETBLOCK;
			break;
		case GPRS_NS2_LL_FR_GRE:
			dialect = NS2_DIALECT_STATIC_RESETBLOCK;
			continue;
		}

		nse = gprs_ns2_nse_by_nsei(vty_nsi, vtyvc->nsei);
		if (!nse) {
			nse = gprs_ns2_create_nse(vty_nsi, vtyvc->nsei, vtyvc->ll, dialect);
			if (!nse) {
				/* Could not create NSE for VTY */
				continue;
			}
		}
		nse->persistent = true;

		switch (vtyvc->ll) {
		case GPRS_NS2_LL_UDP:
			nsvc = gprs_ns2_ip_connect(bind,
						   &sockaddr,
						   nse,
						   vtyvc->nsvci);
			if (!nsvc) {
				/* Could not create NSVC, connect failed */
				continue;
			}
			nsvc->persistent = true;
			break;
		case GPRS_NS2_LL_FR: {
			if (vty_fr_network == NULL) {
				/* TODO: add a switch for BSS/SGSN/gbproxy */
				vty_fr_network = osmo_fr_network_alloc(vty_nsi);
			}
			fr = gprs_ns2_fr_bind_by_netif(
						vty_nsi,
						vtyvc->netif);
			if (!fr) {
				rc = gprs_ns2_fr_bind(vty_nsi, vtyvc->netif, vtyvc->netif, vty_fr_network, vtyvc->fr.role, &fr);
				if (rc < 0) {
					LOGP(DLNS, LOGL_ERROR, "Can not create fr bind on device %s err: %d\n", vtyvc->netif, rc);
					return rc;
				}
			}

			nsvc = gprs_ns2_fr_connect(fr, vtyvc->nsei, vtyvc->nsvci, vtyvc->frdlci);
			if (!nsvc) {
				/* Could not create NSVC, connect failed */
				continue;
			}
			nsvc->persistent = true;
			break;
		}
		case GPRS_NS2_LL_FR_GRE:
			continue;
		}
	}


	return 0;
}
