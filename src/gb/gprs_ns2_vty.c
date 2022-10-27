/*! \file gprs_ns2_vty.c
 * VTY interface for our GPRS Networks Service (NS) implementation. */

/* (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Alexander Couzens <lynxis@fe80.eu>
 * (C) 2021 by Harald Welte <laforge@osmocom.org>
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

#include <osmocom/core/byteswap.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/socket.h>
#include <osmocom/gprs/frame_relay.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/vty.h>

#include "gprs_ns2_internal.h"

#define SHOW_NS_STR "Display information about the NS protocol\n"
#define NSVCI_STR "NS Virtual Connection ID (NS-VCI)\n"
#define DLCI_STR "Data Link connection identifier\n"

static struct gprs_ns2_inst *vty_nsi = NULL;
static struct osmo_fr_network *vty_fr_network = NULL;
static struct llist_head binds;
static struct llist_head nses;
static struct llist_head ip_sns_default_binds;

struct vty_bind {
	struct llist_head list;
	const char *name;
	enum gprs_ns2_ll ll;
	int dscp;
	uint8_t priority;
	bool accept_ipaccess;
	bool accept_sns;
	uint8_t ip_sns_sig_weight;
	uint8_t ip_sns_data_weight;
};

struct vty_nse {
	struct llist_head list;
	uint16_t nsei;
	/* list of binds which are valid for this nse. Only IP-SNS uses this
	 * to allow `no listen ..` in the bind context. So "half" created binds are valid for
	 * IP-SNS. This allows changing the bind ip without modifying all NSEs afterwards */
	struct llist_head binds;
};

/* used by IP-SNS to connect multiple vty_nse_bind to a vty_nse */
struct vty_nse_bind {
	struct llist_head list;
	struct vty_bind *vbind;
};

/* TODO: this should into osmo timer */
static const struct value_string gprs_ns_timer_strs[] = {
	{ 0, "tns-block" },
	{ 1, "tns-block-retries" },
	{ 2, "tns-reset" },
	{ 3, "tns-reset-retries" },
	{ 4, "tns-test" },
	{ 5, "tns-alive" },
	{ 6, "tns-alive-retries" },
	{ 7, "tsns-prov" },
	{ 8, "tsns-size-retries" },
	{ 9, "tsns-config-retries" },
	{10, "tsns-procedures-retries" },
	{ 0, NULL }
};

const struct value_string vty_fr_role_names[] = {
	{ FR_ROLE_USER_EQUIPMENT,	"fr" },
	{ FR_ROLE_NETWORK_EQUIPMENT,	"frnet" },
	{ 0, NULL }
};

const struct value_string vty_ll_names[] = {
	{ GPRS_NS2_LL_FR,	"fr" },
	{ GPRS_NS2_LL_FR_GRE,	"frgre" },
	{ GPRS_NS2_LL_UDP,	"udp" },
	{ 0, NULL }
};

static struct vty_bind *vty_bind_by_name(const char *name)
{
	struct vty_bind *vbind;
	llist_for_each_entry(vbind, &binds, list) {
		if (!strcmp(vbind->name, name))
			return vbind;
	}
	return NULL;
}

static struct vty_bind *vty_bind_alloc(const char *name)
{
	struct vty_bind *vbind = talloc_zero(vty_nsi, struct vty_bind);
	if (!vbind)
		return NULL;

	vbind->name = talloc_strdup(vty_nsi, name);
	if (!vbind->name) {
		talloc_free(vbind);
		return NULL;
	}

	vbind->ip_sns_sig_weight = 1;
	vbind->ip_sns_data_weight = 1;
	llist_add_tail(&vbind->list, &binds);
	return vbind;
}

static void vty_bind_free(struct vty_bind *vbind)
{
	if (!vbind)
		return;

	llist_del(&vbind->list);
	talloc_free(vbind);
}

static struct vty_nse *vty_nse_by_nsei(uint16_t nsei)
{
	struct vty_nse *vnse;
	llist_for_each_entry(vnse, &nses, list) {
		if (vnse->nsei == nsei)
			return vnse;
	}
	return NULL;
}

static struct vty_nse *vty_nse_alloc(uint16_t nsei)
{
	struct vty_nse *vnse = talloc_zero(vty_nsi, struct vty_nse);
	if (!vnse)
		return NULL;

	vnse->nsei = nsei;
	INIT_LLIST_HEAD(&vnse->binds);
	llist_add_tail(&vnse->list, &nses);
	return vnse;
}

static void vty_nse_free(struct vty_nse *vnse)
{
	if (!vnse)
		return;

	llist_del(&vnse->list);
	/* all vbind of the nse will be freed by talloc */
	talloc_free(vnse);
}

static int vty_nse_add_vbind(struct vty_nse *vnse, struct vty_bind *vbind)
{
	struct vty_nse_bind *vnse_bind;

	if (vbind->ll != GPRS_NS2_LL_UDP)
		return -EINVAL;

	llist_for_each_entry(vnse_bind, &vnse->binds, list) {
		if (vnse_bind->vbind == vbind)
			return -EALREADY;
	}

	vnse_bind = talloc(vnse, struct vty_nse_bind);
	if (!vnse_bind)
		return -ENOMEM;
	vnse_bind->vbind = vbind;

	llist_add_tail(&vnse_bind->list, &vnse->binds);
	return 0;
}

static int vty_nse_remove_vbind(struct vty_nse *vnse, struct vty_bind *vbind)
{
	struct vty_nse_bind *vnse_bind, *tmp;
	if (vbind->ll != GPRS_NS2_LL_UDP)
		return -EINVAL;

	llist_for_each_entry_safe(vnse_bind, tmp, &vnse->binds, list) {
		if (vnse_bind->vbind == vbind) {
			llist_del(&vnse_bind->list);
			talloc_free(vnse_bind);
			return 0;
		}
	}

	return -ENOENT;
}

/* check if the NSE still has SNS configuration */
static bool vty_nse_check_sns(struct gprs_ns2_nse *nse) {
	struct vty_nse *vnse = vty_nse_by_nsei(nse->nsei);

	int count = gprs_ns2_sns_count(nse);
	if (count > 0) {
		 /* there are other sns endpoints */
		return true;
	}

	if (!vnse)
		return false;

	if (llist_empty(&vnse->binds))
		return false;

	return true;
}

static struct cmd_node ns_node = {
	L_NS_NODE,
	"%s(config-ns)# ",
	1,
};

DEFUN(cfg_ns, cfg_ns_cmd,
      "ns",
      "Configure the GPRS Network Service")
{
	vty->node = L_NS_NODE;
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

DEFUN(cfg_ns_nsei, cfg_ns_nsei_cmd,
      "nse <0-65535> [ip-sns-role-sgsn]",
      "Persistent NS Entity\n"
      "NS Entity ID (NSEI)\n"
      "Create NSE in SGSN role (default: BSS)\n"
      )
{
	struct gprs_ns2_nse *nse;
	struct vty_nse *vnse;
	uint16_t nsei = atoi(argv[0]);
	bool sgsn_role = false;
	bool free_vnse = false;
	if (argc > 1 && !strcmp(argv[1], "ip-sns-role-sgsn"))
		sgsn_role = true;

	vnse = vty_nse_by_nsei(nsei);
	if (!vnse) {
		vnse = vty_nse_alloc(nsei);
		if (!vnse) {
			vty_out(vty, "Failed to create vty NSE!%s", VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
		free_vnse = true;
	}

	nse = gprs_ns2_nse_by_nsei(vty_nsi, nsei);
	if (!nse) {
		nse = gprs_ns2_create_nse2(vty_nsi, nsei, GPRS_NS2_LL_UNDEF, GPRS_NS2_DIALECT_UNDEF,
					   sgsn_role);
		if (!nse) {
			vty_out(vty, "Failed to create NSE!%s", VTY_NEWLINE);
			goto err;
		}
		nse->persistent = true;
	}

	if (!nse->persistent) {
		/* TODO: should the dynamic NSE removed? */
		vty_out(vty, "A dynamic NSE with the specified NSEI already exists%s", VTY_NEWLINE);
		goto err;
	}

	vty->node = L_NS_NSE_NODE;
	vty->index = nse;

	return CMD_SUCCESS;

err:
	if (free_vnse)
		talloc_free(vnse);

	return CMD_ERR_INCOMPLETE;
}

DEFUN(cfg_no_ns_nsei, cfg_no_ns_nsei_cmd,
      "no nse <0-65535>",
      NO_STR
      "Delete a Persistent NS Entity\n"
      "NS Entity ID (NSEI)\n"
      )
{
	struct gprs_ns2_nse *nse;
	struct vty_nse *vnse;
	uint16_t nsei = atoi(argv[0]);

	nse = gprs_ns2_nse_by_nsei(vty_nsi, nsei);
	if (!nse) {
		vty_out(vty, "Can not find NS Entity %s%s", argv[0], VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}

	if (!nse->persistent) {
		vty_out(vty, "Ignoring non-persistent NS Entity%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "Deleting NS Entity %u%s", nse->nsei, VTY_NEWLINE);
	gprs_ns2_free_nse(nse);

	vnse = vty_nse_by_nsei(nsei);
	vty_nse_free(vnse);

	return CMD_SUCCESS;
}

/* TODO: add fr/gre */
DEFUN(cfg_ns_bind, cfg_ns_bind_cmd,
      "bind (fr|udp) ID",
      "Configure local Bind\n"
      "Frame Relay\n" "UDP/IP\n"
      "Unique identifier for this bind (to reference from NS-VCs, NSEs, ...)\n"
      )
{
	const char *nstype = argv[0];
	const char *name = argv[1];
	struct vty_bind *vbind;
	enum gprs_ns2_ll ll;
	int rc;

	rc = get_string_value(vty_ll_names, nstype);
	if (rc < 0)
		return CMD_WARNING;
	ll = (enum gprs_ns2_ll) rc;

	if (!osmo_identifier_valid(name)) {
		vty_out(vty, "Invalid ID. The ID should be only alphanumeric.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vbind = vty_bind_by_name(name);
	if (vbind) {
		if (vbind->ll != ll) {
			vty_out(vty, "A bind with the specified ID already exists with a different type (fr|frgre|udp)!%s",
				VTY_NEWLINE);
			return CMD_WARNING;
		}
	} else {
		vbind = vty_bind_alloc(name);
		if (!vbind) {
			vty_out(vty, "Can not create bind - out of memory%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		vbind->ll = ll;
	}

	vty->index = vbind;
	vty->node = L_NS_BIND_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_ns_bind, cfg_no_ns_bind_cmd,
      "no bind ID",
      NO_STR
      "Delete a bind\n"
      "Unique identifier for this bind\n"
      )
{
	struct vty_bind *vbind;
	struct gprs_ns2_vc_bind *bind;
	const char *name = argv[0];

	vbind = vty_bind_by_name(name);
	if (!vbind) {
		vty_out(vty, "bind %s does not exist!%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}
	vty_bind_free(vbind);
	bind = gprs_ns2_bind_by_name(vty_nsi, name);
	if (bind)
		gprs_ns2_free_bind(bind);
	return CMD_SUCCESS;
}


static void config_write_vbind(struct vty *vty, struct vty_bind *vbind)
{
	struct gprs_ns2_vc_bind *bind;
	const struct osmo_sockaddr *addr;
	struct osmo_sockaddr_str addr_str;
	const char *netif, *frrole_str, *llstr;
	enum osmo_fr_role frrole;

	llstr = get_value_string_or_null(vty_ll_names, vbind->ll);
	if (!llstr)
		return;
	vty_out(vty, " bind %s %s%s", llstr, vbind->name, VTY_NEWLINE);

	bind = gprs_ns2_bind_by_name(vty_nsi, vbind->name);
	switch (vbind->ll) {
	case GPRS_NS2_LL_FR:
		if (bind) {
			netif = gprs_ns2_fr_bind_netif(bind);
			if (!netif)
				return;
			frrole = gprs_ns2_fr_bind_role(bind);
			if ((int) frrole == -1)
				return;
			frrole_str = get_value_string_or_null(vty_fr_role_names, frrole);
			if (netif && frrole_str)
				vty_out(vty, "  fr %s %s%s", netif, frrole_str, VTY_NEWLINE);
		}
		break;
	case GPRS_NS2_LL_UDP:
		if (bind) {
			addr = gprs_ns2_ip_bind_sockaddr(bind);
			if (!osmo_sockaddr_str_from_sockaddr(&addr_str, &addr->u.sas)) {
				vty_out(vty, "  listen %s %u%s", addr_str.ip, addr_str.port,
					VTY_NEWLINE);
			}
		}
		if (vbind->accept_ipaccess)
			vty_out(vty, "  accept-ipaccess%s", VTY_NEWLINE);
		if (vbind->accept_sns)
			vty_out(vty, "  accept-dynamic-ip-sns%s", VTY_NEWLINE);
		if (vbind->dscp)
			vty_out(vty, "  dscp %u%s", vbind->dscp, VTY_NEWLINE);
		if (vbind->priority)
			vty_out(vty, "  socket-priority %u%s", vbind->priority, VTY_NEWLINE);
		vty_out(vty, "  ip-sns signalling-weight %u data-weight %u%s",
			vbind->ip_sns_sig_weight, vbind->ip_sns_data_weight, VTY_NEWLINE);
		break;
	default:
		return;
	}
}

static void config_write_nsvc(struct vty *vty, const struct gprs_ns2_vc *nsvc)
{
	const char *netif;
	uint16_t dlci;
	const struct osmo_sockaddr *addr;
	struct osmo_sockaddr_str addr_str;

	switch (nsvc->nse->ll) {
	case GPRS_NS2_LL_UNDEF:
		break;
	case GPRS_NS2_LL_UDP:
		switch (nsvc->nse->dialect) {
		case GPRS_NS2_DIALECT_IPACCESS:
			addr = gprs_ns2_ip_vc_remote(nsvc);
			if (!addr)
				break;
			if (osmo_sockaddr_str_from_sockaddr(&addr_str, &addr->u.sas))
				break;
			vty_out(vty, "  nsvc ipa %s %s %u nsvci %u%s",
				nsvc->bind->name, addr_str.ip, addr_str.port,
				nsvc->nsvci, VTY_NEWLINE);
			break;
		case GPRS_NS2_DIALECT_STATIC_ALIVE:
			addr = gprs_ns2_ip_vc_remote(nsvc);
			if (!addr)
				break;
			if (osmo_sockaddr_str_from_sockaddr(&addr_str, &addr->u.sas))
				break;
			vty_out(vty, "  nsvc udp %s %s %u%s",
				nsvc->bind->name, addr_str.ip, addr_str.port, VTY_NEWLINE);
			break;
		default:
			break;
		}
		break;
	case GPRS_NS2_LL_FR:
		netif = gprs_ns2_fr_bind_netif(nsvc->bind);
		if (!netif)
			break;
		dlci = gprs_ns2_fr_nsvc_dlci(nsvc);
		if (!dlci)
			break;
		OSMO_ASSERT(nsvc->nsvci_is_valid);
		vty_out(vty, "  nsvc fr %s dlci %u nsvci %u%s",
			netif, dlci, nsvc->nsvci, VTY_NEWLINE);
		break;
	case GPRS_NS2_LL_FR_GRE:
		break;
	}
}

static void _config_write_ns_nse(struct vty *vty, struct gprs_ns2_nse *nse)
{
	struct gprs_ns2_vc *nsvc;
	struct vty_nse *vnse = vty_nse_by_nsei(nse->nsei);
	struct vty_nse_bind *vbind;

	OSMO_ASSERT(vnse);

	vty_out(vty, " nse %u%s%s", nse->nsei,
		nse->ip_sns_role_sgsn ? " ip-sns-role-sgsn" : "", VTY_NEWLINE);
	switch (nse->dialect) {
	case GPRS_NS2_DIALECT_SNS:
		ns2_sns_write_vty(vty, nse);
		llist_for_each_entry(vbind, &vnse->binds, list) {
			vty_out(vty, "  ip-sns-bind %s%s", vbind->vbind->name, VTY_NEWLINE);
		}
		break;
	default:
		llist_for_each_entry(nsvc, &nse->nsvc, list) {
			config_write_nsvc(vty, nsvc);
		}
		break;
	}
}

static int config_write_ns_nse(struct vty *vty)
{
	struct gprs_ns2_nse *nse;

	llist_for_each_entry(nse, &vty_nsi->nse, list) {
		if (!nse->persistent)
			continue;

		_config_write_ns_nse(vty, nse);
	}

	return 0;
}

static int config_write_ns_bind(struct vty *vty)
{
	struct vty_bind *vbind;

	llist_for_each_entry(vbind, &binds, list) {
		config_write_vbind(vty, vbind);
	}

	return 0;
}

static int config_write_ns(struct vty *vty)
{
	struct vty_nse_bind *vbind;
	unsigned int i;
	int ret;

	vty_out(vty, "ns%s", VTY_NEWLINE);

	for (i = 0; i < ARRAY_SIZE(vty_nsi->timeout); i++)
		vty_out(vty, " timer %s %u%s",
			get_value_string(gprs_ns_timer_strs, i),
			vty_nsi->timeout[i], VTY_NEWLINE);

	ret = config_write_ns_bind(vty);
	if (ret)
		return ret;

	llist_for_each_entry(vbind, &ip_sns_default_binds, list) {
		vty_out(vty, " ip-sns-default bind %s%s", vbind->vbind->name, VTY_NEWLINE);
	}

	ret = config_write_ns_nse(vty);
	if (ret)
		return ret;

	return 0;
}


static struct cmd_node ns_bind_node = {
	L_NS_BIND_NODE,
	"%s(config-ns-bind)# ",
	1,
};

DEFUN(cfg_ns_bind_listen, cfg_ns_bind_listen_cmd,
      "listen " VTY_IPV46_CMD " <1-65535>",
      "Configure local IP + Port of this bind\n"
      "Local IPv4 Address\n" "Local IPv6 Address\n"
      "Local UDP Port\n"
      )
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;
	int rc;
	const char *addr_str = argv[0];
	unsigned int port = atoi(argv[1]);
	struct osmo_sockaddr_str sockaddr_str;
	struct osmo_sockaddr sockaddr;

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "listen can be only used with UDP bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_sockaddr_str_from_str(&sockaddr_str, addr_str, port)) {
		vty_out(vty, "Can not parse the Address %s %s%s", argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}
	osmo_sockaddr_str_to_sockaddr(&sockaddr_str, &sockaddr.u.sas);
	if (gprs_ns2_ip_bind_by_sockaddr(vty_nsi, &sockaddr)) {
		vty_out(vty, "A bind with the specified address already exists!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	rc = gprs_ns2_ip_bind(vty_nsi, vbind->name, &sockaddr, vbind->dscp, &bind);
	if (rc != 0) {
		vty_out(vty, "Failed to create the bind (rc %d)!%s", rc, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bind->accept_ipaccess = vbind->accept_ipaccess;
	bind->accept_sns = vbind->accept_sns;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_ns_bind_listen, cfg_no_ns_bind_listen_cmd,
      "no listen",
      NO_STR
      "Delete a IP/Port assignment\n"
      )
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "no listen can be only used with UDP bind%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bind = gprs_ns2_bind_by_name(vty_nsi, vbind->name);
	if (!bind)
		return CMD_ERR_NOTHING_TODO;

	OSMO_ASSERT(bind->ll == GPRS_NS2_LL_UDP);
	gprs_ns2_free_bind(bind);
	return CMD_SUCCESS;
}

DEFUN(cfg_ns_bind_dscp, cfg_ns_bind_dscp_cmd,
      "dscp <0-63>",
      "Set DSCP/TOS on the UDP socket\n" "DSCP Value\n")
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;
	uint16_t dscp = atoi(argv[0]);

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "dscp can be only used with UDP bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	vbind->dscp = dscp;
	bind = gprs_ns2_bind_by_name(vty_nsi, vbind->name);
	if (bind)
		gprs_ns2_ip_bind_set_dscp(bind, dscp);

	return CMD_SUCCESS;
}

DEFUN(cfg_no_ns_bind_dscp, cfg_no_ns_bind_dscp_cmd,
      "no dscp",
      "Set DSCP/TOS on the UDP socket\n" "DSCP Value\n")
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;
	uint16_t dscp = 0;

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "dscp can be only used with UDP bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	vbind->dscp = dscp;
	bind = gprs_ns2_bind_by_name(vty_nsi, vbind->name);
	if (bind)
		gprs_ns2_ip_bind_set_dscp(bind, dscp);

	return CMD_SUCCESS;
}

DEFUN(cfg_ns_bind_priority, cfg_ns_bind_priority_cmd,
      "socket-priority <0-255>",
      "Set socket priority on the UDP socket\n" "Priority Value (>6 requires CAP_NET_ADMIN)\n")
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;
	uint8_t prio = atoi(argv[0]);

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "dscp can be only used with UDP bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	vbind->priority = prio;
	bind = gprs_ns2_bind_by_name(vty_nsi, vbind->name);
	if (bind)
		gprs_ns2_ip_bind_set_priority(bind, prio);

	return CMD_SUCCESS;
}

DEFUN(cfg_ns_bind_ipaccess, cfg_ns_bind_ipaccess_cmd,
      "accept-ipaccess",
      "Allow to create dynamic NS Entity by NS Reset PDU on UDP (ip.access style)\n"
      )
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "accept-ipaccess can be only used with UDP bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	vbind->accept_ipaccess = true;
	bind = gprs_ns2_bind_by_name(vty_nsi, vbind->name);
	if (bind)
		bind->accept_ipaccess = true;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_ns_bind_ipaccess, cfg_no_ns_bind_ipaccess_cmd,
      "no accept-ipaccess",
      NO_STR
      "Reject NS Reset PDU on UDP (ip.access style)\n"
      )
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "no accept-ipaccess can be only used with UDP bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	vbind->accept_ipaccess = false;
	bind = gprs_ns2_bind_by_name(vty_nsi, vbind->name);
	if (bind)
		bind->accept_ipaccess = false;

	return CMD_SUCCESS;
}

DEFUN(cfg_ns_bind_accept_sns, cfg_ns_bind_accept_sns_cmd,
      "accept-dynamic-ip-sns",
      "Allow to create dynamic NS Entities by IP-SNS PDUs\n"
      )
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "accept-dynamic-ip-sns can be only used with UDP bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	vbind->accept_sns = true;
	bind = gprs_ns2_bind_by_name(vty_nsi, vbind->name);
	if (bind)
		bind->accept_sns = true;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_ns_bind_accept_sns, cfg_no_ns_bind_accept_sns_cmd,
      "no accept-dynamic-ip-sns",
      NO_STR
      "Disable dynamic creation of NS Entities by IP-SNS PDUs\n"
      )
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "no accept-dynamic-ip-sns can be only used with UDP bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	vbind->accept_sns = false;
	bind = gprs_ns2_bind_by_name(vty_nsi, vbind->name);
	if (bind)
		bind->accept_sns = false;

	return CMD_SUCCESS;
}

DEFUN(cfg_ns_bind_ip_sns_weight, cfg_ns_bind_ip_sns_weight_cmd,
      "ip-sns signalling-weight <0-254> data-weight <0-254>",
      "IP SNS\n"
      "signalling weight used by IP-SNS dynamic configuration\n"
      "signalling weight used by IP-SNS dynamic configuration\n"
      "data weight used by IP-SNS dynamic configuration\n"
      "data weight used by IP-SNS dynamic configuration\n")
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;

	int signalling = atoi(argv[0]);
	int data = atoi(argv[1]);

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "ip-sns signalling-weight <0-254> data-weight <0-254> can be only used with UDP bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	vbind->ip_sns_data_weight = data;
	vbind->ip_sns_sig_weight = signalling;
	bind = gprs_ns2_bind_by_name(vty_nsi, vbind->name);
	if (bind)
		gprs_ns2_ip_bind_set_sns_weight(bind, signalling, data);

	return CMD_SUCCESS;
}

DEFUN(cfg_ns_bind_fr, cfg_ns_bind_fr_cmd,
      "fr NETIF (fr|frnet)",
      "frame relay\n"
      IFNAME_STR
      "fr (user) is used by BSS or SGSN attached to UNI of a FR network\n"
      "frnet (network) is used by SGSN if BSS is directly attached\n"
      )
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;
	const char *netif = argv[0];
	const char *role = argv[1];

	int rc = 0;
	enum osmo_fr_role frrole;

	if (vbind->ll != GPRS_NS2_LL_FR) {
		vty_out(vty, "fr can be only used with frame relay bind%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(role, "fr"))
		frrole = FR_ROLE_USER_EQUIPMENT;
	else if (!strcmp(role, "frnet"))
		frrole = FR_ROLE_NETWORK_EQUIPMENT;
	else
		return CMD_WARNING;

	bind = gprs_ns2_fr_bind_by_netif(vty_nsi, netif);
	if (bind) {
		vty_out(vty, "Interface %s already used.%s", netif, VTY_NEWLINE);
		return CMD_WARNING;
	}

	rc = gprs_ns2_fr_bind(vty_nsi, vbind->name, netif, vty_fr_network, frrole, &bind);
	if (rc < 0) {
		LOGP(DLNS, LOGL_ERROR, "Failed to bind interface %s on fr. Err: %d\n", netif, rc);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_no_ns_bind_fr, cfg_no_ns_bind_fr_cmd,
      "no fr NETIF",
      NO_STR
      "Delete a frame relay link\n"
      "Delete a frame relay link\n"
      IFNAME_STR
      )
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;
	const char *netif = argv[0];

	if (vbind->ll != GPRS_NS2_LL_FR) {
		vty_out(vty, "fr can be only used with frame relay bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bind = gprs_ns2_fr_bind_by_netif(vty_nsi, netif);
	if (!bind) {
		vty_out(vty, "Interface not found.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strcmp(bind->name, vbind->name)) {
		vty_out(vty, "The specified interface is not bound to this bind.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	gprs_ns2_free_bind(bind);
	return CMD_SUCCESS;
}


static struct cmd_node ns_nse_node = {
	L_NS_NSE_NODE,
	"%s(config-ns-nse)# ",
	1,
};

DEFUN(cfg_ns_nse_nsvc_fr, cfg_ns_nse_nsvc_fr_cmd,
      "nsvc fr NETIF dlci <16-1007> nsvci <0-65535>",
      "NS Virtual Connection\n"
      "frame relay\n"
      "frame relay interface. Must be registered via fr vty\n"
      NSVCI_STR
      NSVCI_STR
      DLCI_STR
      DLCI_STR
      )
{
	struct gprs_ns2_vc_bind *bind;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse = vty->index;
	const char *netif = argv[0];
	uint16_t dlci = atoi(argv[1]);
	uint16_t nsvci = atoi(argv[2]);
	bool dialect_modified = false;
	bool ll_modified = false;

	if (nse->ll != GPRS_NS2_LL_FR && nse->ll != GPRS_NS2_LL_UNDEF) {
		vty_out(vty, "Can not mix NS-VC with different link layer%s", VTY_NEWLINE);
		goto err;
	}

	if (nse->dialect != GPRS_NS2_DIALECT_STATIC_RESETBLOCK && nse->dialect != GPRS_NS2_DIALECT_UNDEF) {
		vty_out(vty, "Can not mix NS-VC with different dialects%s", VTY_NEWLINE);
		goto err;
	}

	if (nse->ll == GPRS_NS2_LL_UNDEF) {
		nse->ll = GPRS_NS2_LL_FR;
		ll_modified = true;
	}

	if (nse->dialect == GPRS_NS2_DIALECT_UNDEF) {
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_STATIC_RESETBLOCK);
		dialect_modified = true;
	}


	bind = gprs_ns2_fr_bind_by_netif(vty_nsi, netif);
	if (!bind) {
		vty_out(vty, "Can not find fr interface \"%s\". Please configure it via fr vty.%s",
			netif, VTY_NEWLINE);
		goto err;
	}

	if (gprs_ns2_fr_nsvc_by_dlci(bind, dlci)) {
		vty_out(vty, "A NS-VC with the specified DLCI already exist!%s", VTY_NEWLINE);
		goto err;
	}

	if (gprs_ns2_nsvc_by_nsvci(vty_nsi, nsvci)) {
		vty_out(vty, "A NS-VC with the specified NS-VCI already exist!%s", VTY_NEWLINE);
		goto err;
	}

	nsvc = gprs_ns2_fr_connect(bind, nse, nsvci, dlci);
	if (!nsvc) {
		/* Could not create NS-VC, connect failed */
		vty_out(vty, "Failed to create the NS-VC%s", VTY_NEWLINE);
		goto err;
	}
	nsvc->persistent = true;
	return CMD_SUCCESS;

err:
	if (ll_modified)
		nse->ll = GPRS_NS2_LL_UNDEF;
	if (dialect_modified)
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_UNDEF);

	return CMD_WARNING;
}

DEFUN(cfg_no_ns_nse_nsvc_fr_dlci, cfg_no_ns_nse_nsvc_fr_dlci_cmd,
      "no nsvc fr NETIF dlci <16-1007>",
      NO_STR
      "Delete frame relay NS-VC\n"
      "frame relay\n"
      "frame relay interface. Must be registered via fr vty\n"
      DLCI_STR
      DLCI_STR
      )
{
	struct gprs_ns2_vc_bind *bind;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse = vty->index;
	const char *netif = argv[0];
	uint16_t dlci = atoi(argv[1]);

	if (nse->ll != GPRS_NS2_LL_FR) {
		vty_out(vty, "This NSE doesn't support frame relay.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bind = gprs_ns2_fr_bind_by_netif(vty_nsi, netif);
	if (!bind) {
		vty_out(vty, "Can not find fr interface \"%s\"%s",
			netif, VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}

	nsvc = gprs_ns2_fr_nsvc_by_dlci(bind, dlci);
	if (!nsvc) {
		vty_out(vty, "Can not find a NS-VC on fr interface %s with dlci %u%s",
			netif, dlci, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nse != nsvc->nse) {
		vty_out(vty, "The specified NS-VC is not a part of the NSE %u!%s"
			     "To remove this NS-VC go to the vty node 'nse %u'%s",
			nse->nsei, VTY_NEWLINE,
			nsvc->nse->nsei, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gprs_ns2_free_nsvc(nsvc);
	if (llist_empty(&nse->nsvc)) {
		nse->ll = GPRS_NS2_LL_UNDEF;
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_UNDEF);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_no_ns_nse_nsvci, cfg_no_ns_nse_nsvci_cmd,
      "no nsvc nsvci <0-65535>",
      NO_STR
      "Delete NSVC\n"
      NSVCI_STR
      NSVCI_STR
      )
{
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse = vty->index;
	uint16_t nsvci = atoi(argv[0]);

	switch (nse->dialect) {
	case GPRS_NS2_DIALECT_SNS:
	case GPRS_NS2_DIALECT_STATIC_ALIVE:
		vty_out(vty, "NSE doesn't support NSVCI.%s", VTY_NEWLINE);
		return CMD_WARNING;
	case GPRS_NS2_DIALECT_UNDEF:
		vty_out(vty, "No NSVCs configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	case GPRS_NS2_DIALECT_IPACCESS:
	case GPRS_NS2_DIALECT_STATIC_RESETBLOCK:
		break;
	}

	nsvc = gprs_ns2_nsvc_by_nsvci(vty_nsi, nsvci);
	if (!nsvc) {
		vty_out(vty, "Can not find NS-VC with NS-VCI %u%s", nsvci, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nse != nsvc->nse) {
		vty_out(vty, "NS-VC with NS-VCI %u is not part of this NSE!%s",
			nsvci, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gprs_ns2_free_nsvc(nsvc);
	if (llist_empty(&nse->nsvc)) {
		nse->ll = GPRS_NS2_LL_UNDEF;
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_UNDEF);
	}

	return CMD_SUCCESS;
}

static int ns_nse_nsvc_udp_cmds(struct vty *vty, const char *bind_name, const char *remote_char, uint16_t port,
				uint16_t sig_weight, uint16_t data_weight)
{
	struct gprs_ns2_vc_bind *bind;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse = vty->index;
	bool dialect_modified = false;
	bool ll_modified = false;

	struct osmo_sockaddr_str remote_str;
	struct osmo_sockaddr remote;

	if (nse->ll == GPRS_NS2_LL_UNDEF) {
		nse->ll = GPRS_NS2_LL_UDP;
		ll_modified = true;
	}

	if (nse->dialect == GPRS_NS2_DIALECT_UNDEF) {
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_STATIC_ALIVE);
		dialect_modified = true;
	}

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "Can not mix NS-VC with different link layer%s", VTY_NEWLINE);
		goto err;
	}

	if (nse->dialect != GPRS_NS2_DIALECT_STATIC_ALIVE) {
		vty_out(vty, "Can not mix NS-VC with different dialects%s", VTY_NEWLINE);
		goto err;
	}

	if (osmo_sockaddr_str_from_str(&remote_str, remote_char, port)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		goto err;
	}

	if (osmo_sockaddr_str_to_sockaddr(&remote_str, &remote.u.sas)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		goto err;
	}

	bind = gprs_ns2_bind_by_name(vty_nsi, bind_name);
	if (!bind) {
		vty_out(vty, "Can not find bind with name %s%s",
			bind_name, VTY_NEWLINE);
		goto err;
	}

	if (bind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "Bind %s is not an UDP bind.%s",
			bind_name, VTY_NEWLINE);
		goto err;
	}

	nsvc = gprs_ns2_nsvc_by_sockaddr_bind(bind, &remote);
	if (nsvc) {
		if (nsvc->nse == nse)
			vty_out(vty, "Specified NSVC is already present in this NSE.%s", VTY_NEWLINE);
		else
			vty_out(vty, "Specified NSVC is already present in another NSE%05u.%s", nsvc->nse->nsei, VTY_NEWLINE);
		goto err;
	}

	nsvc = gprs_ns2_ip_connect(bind, &remote, nse, 0);
	if (!nsvc) {
		vty_out(vty, "Can not create NS-VC.%s", VTY_NEWLINE);
		goto err;
	}
	nsvc->sig_weight = sig_weight;
	nsvc->data_weight = data_weight;
	nsvc->persistent = true;

	return CMD_SUCCESS;

err:
	if (ll_modified)
		nse->ll = GPRS_NS2_LL_UNDEF;
	if (dialect_modified)
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_UNDEF);
	return CMD_WARNING;
}

DEFUN(cfg_ns_nse_nsvc_udp, cfg_ns_nse_nsvc_udp_cmd,
      "nsvc udp BIND " VTY_IPV46_CMD " <1-65535>",
      "NS Virtual Connection\n"
      "NS over UDP\n"
      "A unique bind identifier created by ns bind\n"
      "Remote IPv4 Address\n" "Remote IPv6 Address\n"
      "Remote UDP Port\n")
{
	const char *bind_name = argv[0];
	const char *remote = argv[1];
	uint16_t port = atoi(argv[2]);
	uint16_t sig_weight = 1;
	uint16_t data_weight = 1;

	return ns_nse_nsvc_udp_cmds(vty, bind_name, remote, port, sig_weight, data_weight);
}

DEFUN(cfg_ns_nse_nsvc_udp_weights, cfg_ns_nse_nsvc_udp_weights_cmd,
      "nsvc udp BIND " VTY_IPV46_CMD " <1-65535> signalling-weight <0-254> data-weight <0-254>",
      "NS Virtual Connection\n"
      "NS over UDP\n"
      "A unique bind identifier created by ns bind\n"
      "Remote IPv4 Address\n" "Remote IPv6 Address\n"
      "Remote UDP Port\n"
      "Signalling weight of the NSVC (default = 1)\n"
      "Signalling weight of the NSVC (default = 1)\n"
      "Data weight of the NSVC (default = 1)\n"
      "Data weight of the NSVC (default = 1)\n"
      )
{
	const char *bind_name = argv[0];
	const char *remote = argv[1];
	uint16_t port = atoi(argv[2]);
	uint16_t sig_weight = atoi(argv[3]);
	uint16_t data_weight = atoi(argv[4]);

	return ns_nse_nsvc_udp_cmds(vty, bind_name, remote, port, sig_weight, data_weight);
}

DEFUN(cfg_no_ns_nse_nsvc_udp, cfg_no_ns_nse_nsvc_udp_cmd,
      "no nsvc udp BIND " VTY_IPV46_CMD " <1-65535>",
      NO_STR
      "Delete a NS Virtual Connection\n"
      "NS over UDP\n"
      "A unique bind identifier created by ns bind\n"
      "Remote IPv4 Address\n" "Remote IPv6 Address\n"
      "Remote UDP Port\n"
      )
{
	struct gprs_ns2_vc_bind *bind;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse = vty->index;
	const char *bind_name = argv[0];
	struct osmo_sockaddr_str remote_str;
	struct osmo_sockaddr remote;
	uint16_t port = atoi(argv[2]);

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "This NSE doesn't support UDP.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nse->dialect != GPRS_NS2_DIALECT_STATIC_ALIVE) {
		vty_out(vty, "This NSE doesn't support UDP with dialect static alive.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bind = gprs_ns2_bind_by_name(vty_nsi, bind_name);
	if (!bind) {
		vty_out(vty, "Can not find bind with name %s%s",
			bind_name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (bind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "Bind %s is not an UDP bind.%s",
			bind_name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_sockaddr_str_from_str(&remote_str, argv[1], port)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_sockaddr_str_to_sockaddr(&remote_str, &remote.u.sas)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	nsvc = gprs_ns2_nsvc_by_sockaddr_bind(bind, &remote);
	if (!nsvc) {
		vty_out(vty, "Can not find NS-VC with remote %s:%u%s",
			remote_str.ip, remote_str.port, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!nsvc->persistent) {
		vty_out(vty, "NS-VC with remote %s:%u is a dynamic NS-VC. Not configured by vty.%s",
			remote_str.ip, remote_str.port, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nsvc->nse != nse) {
		vty_out(vty, "NS-VC is not part of this NSE!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	gprs_ns2_free_nsvc(nsvc);
	if (llist_empty(&nse->nsvc)) {
		nse->ll = GPRS_NS2_LL_UNDEF;
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_UNDEF);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_ns_nse_nsvc_ipa, cfg_ns_nse_nsvc_ipa_cmd,
      "nsvc ipa BIND " VTY_IPV46_CMD " <1-65535> nsvci <0-65535>" ,
      "NS Virtual Connection\n"
      "NS over UDP ip.access style (uses RESET/BLOCK)\n"
      "A unique bind identifier created by ns bind\n"
      "Remote IPv4 Address\n" "Remote IPv6 Address\n"
      "Remote UDP Port\n"
      NSVCI_STR
      NSVCI_STR
      )
{
	struct gprs_ns2_vc_bind *bind;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse = vty->index;
	bool dialect_modified = false;
	bool ll_modified = false;

	const char *bind_name = argv[0];
	struct osmo_sockaddr_str remote_str;
	struct osmo_sockaddr remote;
	uint16_t port = atoi(argv[2]);
	uint16_t nsvci = atoi(argv[3]);

	if (nse->ll == GPRS_NS2_LL_UNDEF) {
		nse->ll = GPRS_NS2_LL_UDP;
		ll_modified = true;
	}

	if (nse->dialect == GPRS_NS2_DIALECT_UNDEF) {
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_IPACCESS);
		dialect_modified = true;
	}

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "Can not mix NS-VC with different link layer%s", VTY_NEWLINE);
		goto err;
	}

	if (nse->dialect != GPRS_NS2_DIALECT_IPACCESS) {
		vty_out(vty, "Can not mix NS-VC with different dialects%s", VTY_NEWLINE);
		goto err;
	}

	if (osmo_sockaddr_str_from_str(&remote_str, argv[1], port)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		goto err;
	}

	if (osmo_sockaddr_str_to_sockaddr(&remote_str, &remote.u.sas)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		goto err;
	}

	bind = gprs_ns2_bind_by_name(vty_nsi, bind_name);
	if (!bind) {
		vty_out(vty, "Can not find bind with name %s%s",
			bind_name, VTY_NEWLINE);
		goto err;
	}

	if (bind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "Bind %s is not an UDP bind.%s",
			bind_name, VTY_NEWLINE);
		goto err;
	}

	nsvc = gprs_ns2_ip_connect(bind, &remote, nse, nsvci);
	if (!nsvc) {
		vty_out(vty, "Can not create NS-VC.%s", VTY_NEWLINE);
		goto err;
	}
	nsvc->persistent = true;

	return CMD_SUCCESS;

err:
	if (ll_modified)
		nse->ll = GPRS_NS2_LL_UNDEF;
	if (dialect_modified)
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_UNDEF);
	return CMD_WARNING;
}

DEFUN(cfg_no_ns_nse_nsvc_ipa, cfg_no_ns_nse_nsvc_ipa_cmd,
      "no nsvc ipa BIND " VTY_IPV46_CMD " <1-65535> nsvci <0-65535>",
      NO_STR
      "Delete a NS Virtual Connection\n"
      "NS over UDP\n"
      "A unique bind identifier created by ns bind\n"
      "Remote IPv4 Address\n" "Remote IPv6 Address\n"
      "Remote UDP Port\n"
      NSVCI_STR
      NSVCI_STR
      )
{
	struct gprs_ns2_vc_bind *bind;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse = vty->index;
	const char *bind_name = argv[0];
	struct osmo_sockaddr_str remote_str;
	struct osmo_sockaddr remote;
	uint16_t port = atoi(argv[2]);
	uint16_t nsvci = atoi(argv[3]);

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "This NSE doesn't support UDP.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nse->dialect != GPRS_NS2_DIALECT_IPACCESS) {
		vty_out(vty, "This NSE doesn't support UDP with dialect ipaccess.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bind = gprs_ns2_bind_by_name(vty_nsi, bind_name);
	if (!bind) {
		vty_out(vty, "Can not find bind with name %s%s",
			bind_name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (bind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "Bind %s is not an UDP bind.%s",
			bind_name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_sockaddr_str_from_str(&remote_str, argv[1], port)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_sockaddr_str_to_sockaddr(&remote_str, &remote.u.sas)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	nsvc = gprs_ns2_nsvc_by_sockaddr_bind(bind, &remote);
	if (!nsvc) {
		vty_out(vty, "Can not find NS-VC with remote %s:%u%s",
			remote_str.ip, remote_str.port, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!nsvc->persistent) {
		vty_out(vty, "NS-VC with remote %s:%u is a dynamic NS-VC. Not configured by vty.%s",
			remote_str.ip, remote_str.port, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nsvc->nse != nse) {
		vty_out(vty, "NS-VC is not part of this NSE!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!nsvc->nsvci_is_valid) {
		vty_out(vty, "NS-VC doesn't have a nsvci!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nsvc->nsvci != nsvci) {
		vty_out(vty, "NS-VC has a different nsvci (%u)!%s",
			nsvc->nsvci, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gprs_ns2_free_nsvc(nsvc);
	if (llist_empty(&nse->nsvc)) {
		nse->ll = GPRS_NS2_LL_UNDEF;
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_UNDEF);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_ns_nse_ip_sns_remote, cfg_ns_nse_ip_sns_remote_cmd,
      "ip-sns-remote " VTY_IPV46_CMD " <1-65535>",
      "SNS Initial Endpoint\n"
      "SGSN IPv4 Address\n" "SGSN IPv6 Address\n"
      "SGSN UDP Port\n"
      )
{
	struct gprs_ns2_nse *nse = vty->index;
	bool dialect_modified = false;
	bool ll_modified = false;
	int rc;

	/* argv[0] */
	struct osmo_sockaddr_str remote_str;
	struct osmo_sockaddr remote;
	uint16_t port = atoi(argv[1]);

	if (nse->ll == GPRS_NS2_LL_UNDEF) {
		nse->ll = GPRS_NS2_LL_UDP;
		ll_modified = true;
	}

	if (nse->dialect == GPRS_NS2_DIALECT_UNDEF) {
		if (ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_SNS) < 0)
			goto err;
		dialect_modified = true;
	}

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "Can not mix NS-VC with different link layer%s", VTY_NEWLINE);
		goto err;
	}

	if (nse->dialect != GPRS_NS2_DIALECT_SNS) {
		vty_out(vty, "Can not mix NS-VC with different dialects%s", VTY_NEWLINE);
		goto err;
	}

	if (osmo_sockaddr_str_from_str(&remote_str, argv[0], port)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		goto err;
	}

	if (osmo_sockaddr_str_to_sockaddr(&remote_str, &remote.u.sas)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		goto err;
	}

	rc = gprs_ns2_sns_add_endpoint(nse, &remote);
	switch (rc) {
	case 0:
		return CMD_SUCCESS;
	case -EADDRINUSE:
		vty_out(vty, "Specified SNS endpoint already part of the NSE.%s", VTY_NEWLINE);
		return CMD_WARNING;
	default:
		vty_out(vty, "Can not add specified SNS endpoint.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

err:
	if (ll_modified)
		nse->ll = GPRS_NS2_LL_UNDEF;
	if (dialect_modified)
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_UNDEF);
	return CMD_WARNING;
}

DEFUN(cfg_no_ns_nse_ip_sns_remote, cfg_no_ns_nse_ip_sns_remote_cmd,
      "no ip-sns-remote " VTY_IPV46_CMD " <1-65535>",
      NO_STR
      "Delete a SNS Initial Endpoint\n"
      "SGSN IPv4 Address\n" "SGSN IPv6 Address\n"
      "SGSN UDP Port\n"
      )
{
	struct gprs_ns2_nse *nse = vty->index;
	struct osmo_sockaddr_str remote_str; /* argv[0] */
	struct osmo_sockaddr remote;
	uint16_t port = atoi(argv[1]);

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "This NSE doesn't support UDP.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nse->dialect != GPRS_NS2_DIALECT_SNS) {
		vty_out(vty, "This NSE doesn't support UDP with dialect ip-sns.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_sockaddr_str_from_str(&remote_str, argv[0], port)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_sockaddr_str_to_sockaddr(&remote_str, &remote.u.sas)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (gprs_ns2_sns_del_endpoint(nse, &remote)) {
		vty_out(vty, "Can not remove specified SNS endpoint.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (vty_nse_check_sns(nse)) {
		 /* there is still sns configuration valid */
		return CMD_SUCCESS;
	} else {
		/* clean up nse to allow other nsvc commands */
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_UNDEF);
		nse->ll = GPRS_NS2_LL_UNDEF;
	}

	return CMD_SUCCESS;
}

/* add all IP-SNS default binds to the given NSE */
int ns2_sns_add_sns_default_binds(struct gprs_ns2_nse *nse)
{
	struct vty_nse_bind *vnse_bind;
	int count = 0;

	OSMO_ASSERT(nse->ll == GPRS_NS2_LL_UDP);
	OSMO_ASSERT(nse->dialect == GPRS_NS2_DIALECT_SNS);

	llist_for_each_entry(vnse_bind, &ip_sns_default_binds, list) {
		struct gprs_ns2_vc_bind *bind = gprs_ns2_bind_by_name(vty_nsi, vnse_bind->vbind->name);
		/* the bind might not yet created because "listen" is missing. */
		if (!bind)
			continue;
		gprs_ns2_sns_add_bind(nse, bind);
		count++;
	}
	return count;
}

DEFUN(cfg_ns_ip_sns_default_bind, cfg_ns_ip_sns_default_bind_cmd,
      "ip-sns-default bind ID",
      "Defaults for dynamically created NSEs created by IP-SNS in SGSN role\n"
      "IP SNS binds\n"
      "Name of NS udp bind whose IP endpoint will be used as IP-SNS local endpoint. Can be given multiple times.\n")
{
	struct vty_bind *vbind;
	struct vty_nse_bind *vnse_bind;
	const char *name = argv[0];

	vbind = vty_bind_by_name(name);
	if (!vbind) {
		vty_out(vty, "Can not find the given bind '%s'%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "ip-sns-default bind can only be used with UDP bind%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	llist_for_each_entry(vnse_bind, &ip_sns_default_binds, list) {
		if (vnse_bind->vbind == vbind)
			return CMD_SUCCESS;
	}

	vnse_bind = talloc(vty_nsi, struct vty_nse_bind);
	if (!vnse_bind)
		return CMD_WARNING;
	vnse_bind->vbind = vbind;

	llist_add_tail(&vnse_bind->list, &ip_sns_default_binds);

	return CMD_SUCCESS;
}

DEFUN(cfg_no_ns_ip_sns_default_bind, cfg_no_ns_ip_sns_default_bind_cmd,
      "no ip-sns-default bind ID",
      NO_STR "Defaults for dynamically created NSEs created by IP-SNS in SGSN role\n"
      "IP SNS binds\n"
      "Name of NS udp bind whose IP endpoint will be removed as IP-SNS local endpoint.\n")
{
	struct vty_bind *vbind;
	struct vty_nse_bind *vnse_bind;
	const char *name = argv[0];

	vbind = vty_bind_by_name(name);
	if (!vbind) {
		vty_out(vty, "Can not find the given bind '%s'%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "ip-sns-default bind can only be used with UDP bind%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	llist_for_each_entry(vnse_bind, &ip_sns_default_binds, list) {
		if (vnse_bind->vbind == vbind) {
			llist_del(&vnse_bind->list);
			talloc_free(vnse_bind);
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "Bind '%s' was not an ip-sns-default bind%s", name, VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN(cfg_ns_nse_ip_sns_bind, cfg_ns_nse_ip_sns_bind_cmd,
      "ip-sns-bind BINDID",
      "IP SNS binds\n"
      "Name of NS udp bind whose IP endpoint will be used as IP-SNS local endpoint. Can be given multiple times.\n")
{
	struct gprs_ns2_nse *nse = vty->index;
	struct gprs_ns2_vc_bind *bind;
	struct vty_bind *vbind;
	struct vty_nse *vnse;
	const char *name = argv[0];
	bool ll_modified = false;
	bool dialect_modified = false;
	int rc;

	if (nse->ll == GPRS_NS2_LL_UNDEF) {
		nse->ll = GPRS_NS2_LL_UDP;
		ll_modified = true;
	}

	if (nse->dialect == GPRS_NS2_DIALECT_UNDEF) {
		if (ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_SNS) < 0)
			goto err;
		dialect_modified = true;
	}

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "Can not mix NS-VC with different link layer%s", VTY_NEWLINE);
		goto err;
	}

	if (nse->dialect != GPRS_NS2_DIALECT_SNS) {
		vty_out(vty, "Can not mix NS-VC with different dialects%s", VTY_NEWLINE);
		goto err;
	}

	vbind = vty_bind_by_name(name);
	if (!vbind) {
		vty_out(vty, "Can not find the given bind '%s'%s", name, VTY_NEWLINE);
		goto err;
	}

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "ip-sns-bind can only be used with UDP bind%s",
			VTY_NEWLINE);
		goto err;
	}

	/* the vnse has been created together when creating the nse node. The parent node should check this already! */
	vnse = vty_nse_by_nsei(nse->nsei);
	OSMO_ASSERT(vnse);

	rc = vty_nse_add_vbind(vnse, vbind);
	switch (rc) {
	case 0:
		break;
	case -EALREADY:
		vty_out(vty, "Failed to add ip-sns-bind %s already present%s", name, VTY_NEWLINE);
		goto err;
	case -ENOMEM:
		vty_out(vty, "Failed to add ip-sns-bind %s out of memory%s", name, VTY_NEWLINE);
		goto err;
	default:
		vty_out(vty, "Failed to add ip-sns-bind %s! %d%s", name, rc, VTY_NEWLINE);
		goto err;
	}

	/* the bind might not yet created because "listen" is missing. */
	bind = gprs_ns2_bind_by_name(vty_nsi, name);
	if (!bind)
		return CMD_SUCCESS;

	rc = gprs_ns2_sns_add_bind(nse, bind);
	switch (rc) {
	case 0:
		break;
	case -EALREADY:
		vty_out(vty, "Failed to add ip-sns-bind %s already present%s", name, VTY_NEWLINE);
		goto err;
	case -ENOMEM:
		vty_out(vty, "Failed to add ip-sns-bind %s out of memory%s", name, VTY_NEWLINE);
		goto err;
	default:
		vty_out(vty, "Failed to add ip-sns-bind %s! %d%s", name, rc, VTY_NEWLINE);
		goto err;
	}

	return CMD_SUCCESS;
err:
	if (ll_modified)
		nse->ll = GPRS_NS2_LL_UNDEF;
	if (dialect_modified)
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_UNDEF);

	return CMD_WARNING;
}

DEFUN(cfg_no_ns_nse_ip_sns_bind, cfg_no_ns_nse_ip_sns_bind_cmd,
      "no ip-sns-bind BINDID",
      NO_STR
      "IP SNS binds\n"
      "Name of NS udp bind whose IP endpoint will not be used as IP-SNS local endpoint\n")
{
	struct gprs_ns2_nse *nse = vty->index;
	struct gprs_ns2_vc_bind *bind;
	struct vty_bind *vbind;
	struct vty_nse *vnse;
	const char *name = argv[0];
	int rc;

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "This NSE doesn't support UDP.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nse->dialect != GPRS_NS2_DIALECT_SNS) {
		vty_out(vty, "This NSE doesn't support UDP with dialect ip-sns.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vbind = vty_bind_by_name(name);
	if (!vbind) {
		vty_out(vty, "Can not find the given bind '%s'%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (vbind->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "no ip-sns-bind can only be used with UDP bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* the vnse has been created together when creating the nse node. The parent node should check this already! */
	vnse = vty_nse_by_nsei(nse->nsei);
	OSMO_ASSERT(vnse);

	rc = vty_nse_remove_vbind(vnse, vbind);
	switch(rc) {
	case 0:
		break;
	case -ENOENT:
		vty_out(vty, "Bind %s is not part of this NSE%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	case -EINVAL:
		vty_out(vty, "no ip-sns-bind can only be used with UDP bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	default:
		return CMD_WARNING;
	}

	/* the bind might not exists yet */
	bind = gprs_ns2_bind_by_name(vty_nsi, name);
	if (bind)
		gprs_ns2_sns_del_bind(nse, bind);

	if (!vty_nse_check_sns(nse)) {
		/* clean up nse to allow other nsvc commands */
		ns2_nse_set_dialect(nse, GPRS_NS2_DIALECT_UNDEF);
		nse->ll = GPRS_NS2_LL_UNDEF;
	}

	return CMD_SUCCESS;
}

/* non-config commands */
void ns2_vty_dump_nsvc(struct vty *vty, struct gprs_ns2_vc *nsvc, bool stats)
{
	if (nsvc->nsvci_is_valid)
		vty_out(vty, "   NSVCI %05u: %s %s %s %s %ssince ", nsvc->nsvci,
			osmo_fsm_inst_state_name(nsvc->fi),
			nsvc->persistent ? "PERSIST" : "DYNAMIC",
			gprs_ns2_ll_str(nsvc),
			ns2_vc_is_unblocked(nsvc) ? "ALIVE" : "DEAD",
			nsvc->om_blocked ? "(blocked by O&M/vty) " :
				!ns2_vc_is_unblocked(nsvc) ? "(cause: remote) " : "");
	else
		vty_out(vty, "   %s %s sig_weight=%u data_weight=%u %s %s %ssince ",
			osmo_fsm_inst_state_name(nsvc->fi),
			nsvc->persistent ? "PERSIST" : "DYNAMIC",
			nsvc->sig_weight, nsvc->data_weight,
			gprs_ns2_ll_str(nsvc),
			ns2_vc_is_unblocked(nsvc) ? "ALIVE" : "DEAD",
				!ns2_vc_is_unblocked(nsvc) ? "(cause: remote) " : "");

	vty_out_uptime(vty, &nsvc->ts_alive_change);
	vty_out_newline(vty);

	if (stats) {
		vty_out_rate_ctr_group(vty, "    ", nsvc->ctrg);
		vty_out_stat_item_group(vty, "    ", nsvc->statg);
	}
}

static void dump_nse(struct vty *vty, const struct gprs_ns2_nse *nse, bool stats, bool persistent_only)
{
	struct gprs_ns2_vc *nsvc;
	unsigned int nsvcs = 0;

	if (persistent_only && !nse->persistent)
		return;

	vty_out(vty, "NSEI %05u: %s, %s since ", nse->nsei, gprs_ns2_lltype_str(nse->ll),
		nse->alive ? "ALIVE" : "DEAD");
	vty_out_uptime(vty, &nse->ts_alive_change);
	vty_out_newline(vty);

	ns2_sns_dump_vty(vty, " ", nse, stats);
	llist_for_each_entry(nsvc, &nse->nsvc, list) {
		nsvcs++;
	}
	vty_out(vty, "  %u NS-VC:%s", nsvcs, VTY_NEWLINE);
	llist_for_each_entry(nsvc, &nse->nsvc, list)
		ns2_vty_dump_nsvc(vty, nsvc, stats);
}

static void dump_bind(struct vty *vty, const struct gprs_ns2_vc_bind *bind, bool stats)
{
	if (bind->dump_vty)
		bind->dump_vty(bind, vty, stats);

	if (stats) {
		vty_out_stat_item_group(vty, "  ", bind->statg);
	}
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
	if (vty_fr_network && llist_count(&vty_fr_network->links))
		osmo_fr_network_dump_vty(vty, vty_fr_network);
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

		ns2_vty_dump_nsvc(vty, nsvc, show_stats);
	}

	return CMD_SUCCESS;
}

static int nsvc_force_unconf_cb(struct gprs_ns2_vc *nsvc, void *ctx)
{
	ns2_vc_force_unconfigured(nsvc);
	ns2_vc_fsm_start(nsvc);
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

	if (!nse->persistent) {
		gprs_ns2_free_nse(nse);
	} else if (nse->dialect == GPRS_NS2_DIALECT_SNS) {
		gprs_ns2_free_nsvcs(nse);
	} else {
		/* Perform the operation for all nsvc */
		gprs_ns2_nse_foreach_nsvc(nse, nsvc_force_unconf_cb, NULL);
	}

	return CMD_SUCCESS;
}

DEFUN(nse_restart_sns, nse_restart_sns_cmd,
      "nse <0-65535> restart-sns",
      "NSE specific commands\n"
      "NS Entity ID (NSEI)\n"
      "Restart SNS procedure\n")
{
	struct gprs_ns2_inst *nsi = vty_nsi;
	struct gprs_ns2_nse *nse;

	uint16_t id = atoi(argv[0]);
	nse = gprs_ns2_nse_by_nsei(nsi, id);
	if (!nse) {
		vty_out(vty, "Could not find NSE for NSEI %u%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nse->dialect != GPRS_NS2_DIALECT_SNS) {
		vty_out(vty, "Given NSEI %u doesn't use IP-SNS%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gprs_ns2_free_nsvcs(nse);
	return CMD_SUCCESS;
}

DEFUN(nsvc_block, nsvc_block_cmd,
      "nsvc <0-65535> (block|unblock|reset)",
      "NS Virtual Connection\n"
      NSVCI_STR
      "Block a NSVC. As cause code O&M intervention will be used.\n"
      "Unblock a NSVC. As cause code O&M intervention will be used.\n"
      "Reset a NSVC. As cause code O&M intervention will be used.\n")
{
	struct gprs_ns2_inst *nsi = vty_nsi;
	struct gprs_ns2_vc *nsvc;
	int rc;

	uint16_t id = atoi(argv[0]);

	nsvc = gprs_ns2_nsvc_by_nsvci(nsi, id);
	if (!nsvc) {
		vty_out(vty, "Could not find NSVCI %05u%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[1], "block")) {
		rc = ns2_vc_block(nsvc);
		switch (rc) {
		case 0:
			vty_out(vty, "The NS-VC %05u will be blocked.%s", id, VTY_NEWLINE);
			return CMD_SUCCESS;
		case -EALREADY:
			vty_out(vty, "The NS-VC %05u is already blocked.%s", id, VTY_NEWLINE);
			return CMD_ERR_NOTHING_TODO;
		default:
			vty_out(vty, "An unknown error %d happend on NS-VC %05u.%s", rc, id, VTY_NEWLINE);
			return CMD_WARNING;
		}
	} else if (!strcmp(argv[1], "unblock")) {
		rc = ns2_vc_unblock(nsvc);
		switch (rc) {
		case 0:
			vty_out(vty, "The NS-VC %05u will be unblocked.%s", id, VTY_NEWLINE);
			return CMD_SUCCESS;
		case -EALREADY:
			vty_out(vty, "The NS-VC %05u is already unblocked.%s", id, VTY_NEWLINE);
			return CMD_ERR_NOTHING_TODO;
		default:
			vty_out(vty, "An unknown error %d happend on NS-VC %05u.%s", rc, id, VTY_NEWLINE);
			return CMD_WARNING;
		}
	} else {
		ns2_vc_reset(nsvc);
		vty_out(vty, "The NS-VC %05u has been resetted.%s", id, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

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

/*! initialized a reduced vty interface which excludes the configuration nodes besides timeouts.
 *  This can be used by the PCU which can be only configured by the BTS/BSC and not by the vty.
 * \param[in] nsi NS instance on which we operate
 * \return 0 on success.
 */
int gprs_ns2_vty_init_reduced(struct gprs_ns2_inst *nsi)
{
	vty_nsi = nsi;
	INIT_LLIST_HEAD(&binds);
	INIT_LLIST_HEAD(&nses);
	INIT_LLIST_HEAD(&ip_sns_default_binds);

	vty_fr_network = osmo_fr_network_alloc(nsi);
	if (!vty_fr_network)
		return -ENOMEM;

	install_lib_element_ve(&show_ns_cmd);
	install_lib_element_ve(&show_ns_binds_cmd);
	install_lib_element_ve(&show_ns_entities_cmd);
	install_lib_element_ve(&show_ns_pers_cmd);
	install_lib_element_ve(&show_nse_cmd);
	install_lib_element_ve(&logging_fltr_nse_cmd);
	install_lib_element_ve(&logging_fltr_nsvc_cmd);

	install_lib_element(ENABLE_NODE, &nsvc_force_unconf_cmd);
	install_lib_element(ENABLE_NODE, &nsvc_block_cmd);
	install_lib_element(ENABLE_NODE, &nse_restart_sns_cmd);

	install_lib_element(CFG_LOG_NODE, &logging_fltr_nse_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_fltr_nsvc_cmd);

	install_lib_element(CONFIG_NODE, &cfg_ns_cmd);

	install_node(&ns_node, config_write_ns);
	/* TODO: convert into osmo timer */
	install_lib_element(L_NS_NODE, &cfg_ns_timer_cmd);

	return 0;
}

int gprs_ns2_vty_init(struct gprs_ns2_inst *nsi)
{
	int rc = gprs_ns2_vty_init_reduced(nsi);
	if (rc)
		return rc;

	install_lib_element(L_NS_NODE, &cfg_ns_nsei_cmd);
	install_lib_element(L_NS_NODE, &cfg_no_ns_nsei_cmd);
	install_lib_element(L_NS_NODE, &cfg_ns_bind_cmd);
	install_lib_element(L_NS_NODE, &cfg_no_ns_bind_cmd);

	install_lib_element(L_NS_NODE, &cfg_ns_ip_sns_default_bind_cmd);
	install_lib_element(L_NS_NODE, &cfg_no_ns_ip_sns_default_bind_cmd);

	install_node(&ns_bind_node, NULL);
	install_lib_element(L_NS_BIND_NODE, &cfg_ns_bind_listen_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_no_ns_bind_listen_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_ns_bind_dscp_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_no_ns_bind_dscp_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_ns_bind_priority_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_ns_bind_ip_sns_weight_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_ns_bind_ipaccess_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_no_ns_bind_ipaccess_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_ns_bind_fr_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_no_ns_bind_fr_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_ns_bind_accept_sns_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_no_ns_bind_accept_sns_cmd);

	install_node(&ns_nse_node, NULL);
	install_lib_element(L_NS_NSE_NODE, &cfg_ns_nse_nsvc_fr_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_no_ns_nse_nsvci_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_no_ns_nse_nsvc_fr_dlci_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_ns_nse_nsvc_udp_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_ns_nse_nsvc_udp_weights_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_no_ns_nse_nsvc_udp_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_ns_nse_nsvc_ipa_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_no_ns_nse_nsvc_ipa_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_ns_nse_ip_sns_remote_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_no_ns_nse_ip_sns_remote_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_ns_nse_ip_sns_bind_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_no_ns_nse_ip_sns_bind_cmd);

	return 0;
}
