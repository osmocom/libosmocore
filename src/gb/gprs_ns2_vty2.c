/*! \file gprs_ns2_vty.c
 * VTY interface for our GPRS Networks Service (NS) implementation. */

/* (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

static struct gprs_ns2_inst *vty_nsi = NULL;
static struct osmo_fr_network *vty_fr_network = NULL;
static struct llist_head binds;

struct vty_bind {
	struct llist_head list;
	const char *name;
	enum gprs_ns2_ll ll;
	int dscp;
	bool accept_ipaccess;
	bool accept_sns;
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
	{ 0, NULL }
};

static struct vty_bind *vty_bind_by_name(const char *name)
{
	struct vty_bind *vbind;
	llist_for_each_entry(vbind, &binds, list) {
		if (!strncmp(vbind->name, name, strlen(vbind->name)))
			return vbind;
	}
	return NULL;
}

static struct vty_bind *vty_bind_alloc(const char *name)
{
	struct vty_bind *vbind = talloc(vty_nsi, struct vty_bind);
	if (!vbind)
		return NULL;

	vbind->name = talloc_strdup(vty_nsi, name);
	if (!vbind->name) {
		talloc_free(vbind);
		return NULL;
	}

	llist_add(&vbind->list, &binds);
	return vbind;
}

static void vty_bind_free(struct vty_bind *vbind)
{
	if (!vbind)
		return;

	llist_del(&vbind->list);
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
      "nse <0-65535>",
      "Persistent NS Entity\n"
      "NS Entity ID (NSEI)\n"
      )
{
	struct gprs_ns2_nse *nse;
	uint16_t nsei = atoi(argv[0]);

	nse = gprs_ns2_nse_by_nsei(vty_nsi, nsei);
	if (!nse) {
		nse = gprs_ns2_create_nse(vty_nsi, nsei, GPRS_NS2_LL_UNDEF, NS2_DIALECT_UNDEF);
		if (!nse) {
			vty_out(vty, "Failed to create NSE!%s", VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
		nse->persistent = true;
	}

	if (!nse->persistent) {
		/* TODO: should the dynamic NSE removed? */
		vty_out(vty, "A dynamic NSE with the specified NSEI already exists%s", VTY_NEWLINE);
		return CMD_ERR_INCOMPLETE;
	}

	vty->node = L_NS_NSE_NODE;
	vty->index = nse;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_ns_nsei, cfg_no_ns_nsei_cmd,
      "no nse <0-65535>",
      NO_STR
      "Delete a Persistent NS Entity\n"
      "NS Entity ID (NSEI)\n"
      )
{
	struct gprs_ns2_nse *nse;
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

	vty_out(vty, "Deleting NS Entity %d%s", nse->nsei, VTY_NEWLINE);
	gprs_ns2_free_nse(nse);
	return CMD_SUCCESS;
}

/* TODO: add fr/gre */
DEFUN(cfg_ns_bind, cfg_ns_bind_cmd,
      "bind (fr|udp) ID",
      "Binding\n"
      "Frame Relay\n" "UDP/IP\n"
      "a unique identifier for this bind to reference NS-VCs\n"
      )
{
	const char *nstype = argv[0];
	const char *name = argv[1];
	struct vty_bind *vbind;
	enum gprs_ns2_ll ll;
	/* TODO: create a function GPRS_NS2_LL_UDP -> udp function */

	if (!strcmp("udp", nstype))
		ll = GPRS_NS2_LL_UDP;
	else if (!strcmp("fr", nstype))
		ll = GPRS_NS2_LL_FR;
	else if (!strcmp("frgre", nstype))
		ll = GPRS_NS2_LL_FR_GRE;
	else
		return CMD_WARNING;

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
      "Delete a binding\n"
      "a unique identifier for this bind to reference NS-VCs\n"
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
		bind->driver->free_bind(bind);
	return CMD_SUCCESS;
}

static int config_write_ns(struct vty *vty)
{
	/* TODO: */
	return 0;
}

static struct cmd_node ns_bind_node = {
	L_NS_BIND_NODE,
	"%s(config-ns-bind)# ",
	1,
};

DEFUN(cfg_ns_bind_listen, cfg_ns_bind_listen_cmd,
      "listen " VTY_IPV46_CMD " <1-65535>",
      "Binding\n"
      "IPv4 Address\n" "IPv6 Address\n"
      "Port\n"
      )
{
	struct vty_bind *vbind = vty->index;
	struct gprs_ns2_vc_bind *bind;

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
		vty_out(vty, "Can not parse the Address %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}
	osmo_sockaddr_str_to_sockaddr(&sockaddr_str, &sockaddr.u.sas);
	if (gprs_ns2_ip_bind_by_sockaddr(vty_nsi, &sockaddr)) {
		vty_out(vty, "A bind with the specified address already exists!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (gprs_ns2_ip_bind(vty_nsi, vbind->name, &sockaddr, vbind->dscp, &bind) != 0) {
		vty_out(vty, "Failed to create the bind!%s", VTY_NEWLINE);
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
		vty_out(vty, "no listen can be only used with UDP bind%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bind = gprs_ns2_bind_by_name(vty_nsi, vbind->name);
	if (!bind)
		return CMD_ERR_NOTHING_TODO;

	OSMO_ASSERT(bind->ll != GPRS_NS2_LL_UDP);
	bind->driver->free_bind(bind);
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
		vty_out(vty, "fr can be only used with frame relay bind%s",
			VTY_NEWLINE);
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

	bind->driver->free_bind(bind);
	return CMD_SUCCESS;
}

static int config_write_ns_bind(struct vty *vty)
{
	/* TODO: ! */
	return 0;
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
      "NS Virtual Connection ID (NS-VCI)\n"
      "NS Virtual Connection ID (NS-VCI)\n"
      "Data Link connection identifier\n"
      "Data Link connection identifier\n"
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

	if (nse->dialect != NS2_DIALECT_STATIC_RESETBLOCK && nse->dialect != NS2_DIALECT_UNDEF) {
		vty_out(vty, "Can not mix NS-VC with different dialects%s", VTY_NEWLINE);
		goto err;
	}

	if (nse->ll == GPRS_NS2_LL_UNDEF) {
		nse->ll = GPRS_NS2_LL_FR;
		ll_modified = true;
	}

	if (nse->dialect == NS2_DIALECT_UNDEF) {
		nse->dialect = NS2_DIALECT_STATIC_RESETBLOCK;
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
		nse->dialect = NS2_DIALECT_UNDEF;

	return CMD_WARNING;
}

DEFUN(cfg_no_ns_nse_nsvc_fr_dlci, cfg_no_ns_nse_nsvc_fr_dlci_cmd,
      "no nsvc fr NETIF dlci <0-1023>",
      NO_STR
      "Delete frame relay NS-VC\n"
      "frame relay\n"
      "frame relay interface. Must be registered via fr vty\n"
      "Data Link connection identifier\n"
      "Data Link connection identifier\n"
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
		vty_out(vty, "Can not find a NS-VC on fr interface %s with dlci %d%s",
			netif, dlci, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nse != nsvc->nse) {
		vty_out(vty, "The specified NS-VC is not a part of the NSE %d!%s"
			     "To remove this NS-VC go to the vty node 'nse %d'%s",
			nse->nsei, VTY_NEWLINE,
			nsvc->nse->nsei, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gprs_ns2_free_nsvc(nsvc);
	if (llist_empty(&nse->nsvc)) {
		nse->ll = GPRS_NS2_LL_UNDEF;
		nse->dialect = NS2_DIALECT_UNDEF;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_no_ns_nse_nsvc_fr_nsvci, cfg_no_ns_nse_nsvc_fr_nsvci_cmd,
      "no nsvc fr NETIF nsvci <0-65535>",
      NO_STR
      "Delete frame relay NS-VC\n"
      "frame relay\n"
      "frame relay interface. Must be registered via fr vty\n"
      "NS Virtual Connection ID (NS-VCI)\n"
      "NS Virtual Connection ID (NS-VCI)\n"
      )
{
	struct gprs_ns2_vc_bind *bind;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse = vty->index;
	const char *netif = argv[0];
	uint16_t nsvci = atoi(argv[1]);

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

	nsvc = gprs_ns2_nsvc_by_nsvci(vty_nsi, nsvci);
	if (!nsvc) {
		vty_out(vty, "Can not find NS-VC with NS-VCI %d%s", nsvci, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nsvc->bind != bind) {
		vty_out(vty, "NS-VC with NS-VCI %d is not bound to fr interface %s%s",
			nsvci, netif, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nse != nsvc->nse) {
		vty_out(vty, "NS-VC with NS-VCI %d is not part of this NSE!%s",
			nsvci, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gprs_ns2_free_nsvc(nsvc);
	if (llist_empty(&nse->nsvc)) {
		nse->ll = GPRS_NS2_LL_UNDEF;
		nse->dialect = NS2_DIALECT_UNDEF;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_ns_nse_nsvc_udp, cfg_ns_nse_nsvc_udp_cmd,
      "nsvc udp BIND " VTY_IPV46_CMD " <1-65535>",
      "NS Virtual Connection\n"
      "NS over UDP\n"
      "A unique bind identifier created by ns bind\n"
      "Remote IPv4 Address\n" "Remote IPv6 Address\n"
      "Remote UDP Port\n"
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

	if (nse->ll == GPRS_NS2_LL_UNDEF) {
		nse->ll = GPRS_NS2_LL_UDP;
		ll_modified = true;
	}

	if (nse->dialect == NS2_DIALECT_UNDEF) {
		nse->dialect = NS2_DIALECT_STATIC_ALIVE;
		dialect_modified = true;
	}

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "Can not mix NS-VC with different link layer%s", VTY_NEWLINE);
		goto err;
	}

	if (nse->dialect != NS2_DIALECT_STATIC_ALIVE) {
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

	nsvc = gprs_ns2_ip_connect(bind, &remote, nse, 0);
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
		nse->dialect = NS2_DIALECT_UNDEF;
	return CMD_WARNING;
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

	if (nse->dialect != NS2_DIALECT_STATIC_ALIVE) {
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
		vty_out(vty, "Can not find NS-VC with remote %s:%d%s",
			remote_str.ip, remote_str.port, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!nsvc->persistent) {
		vty_out(vty, "NS-VC with remote %s:%d is a dynamic NS-VC. Not configured by vty.%s",
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
		nse->dialect = NS2_DIALECT_UNDEF;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_ns_nse_nsvc_ipa, cfg_ns_nse_nsvc_ipa_cmd,
      "nsvc ipa BIND nsvci <0-65535> " VTY_IPV46_CMD " <1-65535>",
      "NS Virtual Connection\n"
      "NS over UDP ip.access style (uses RESET/BLOCK)\n"
      "A unique bind identifier created by ns bind\n"
      "NS Virtual Connection ID (NS-VCI)\n"
      "NS Virtual Connection ID (NS-VCI)\n"
      "Remote IPv4 Address\n" "Remote IPv6 Address\n"
      "Remote UDP Port\n"
      )
{
	struct gprs_ns2_vc_bind *bind;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse = vty->index;
	bool dialect_modified = false;
	bool ll_modified = false;

	const char *bind_name = argv[0];
	uint16_t nsvci = atoi(argv[1]);
	struct osmo_sockaddr_str remote_str;
	struct osmo_sockaddr remote;
	uint16_t port = atoi(argv[3]);

	if (nse->ll == GPRS_NS2_LL_UNDEF) {
		nse->ll = GPRS_NS2_LL_UDP;
		ll_modified = true;
	}

	if (nse->dialect == NS2_DIALECT_UNDEF) {
		nse->dialect = NS2_DIALECT_IPACCESS;
		dialect_modified = true;
	}

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "Can not mix NS-VC with different link layer%s", VTY_NEWLINE);
		goto err;
	}

	if (nse->dialect != NS2_DIALECT_IPACCESS) {
		vty_out(vty, "Can not mix NS-VC with different dialects%s", VTY_NEWLINE);
		goto err;
	}

	if (osmo_sockaddr_str_from_str(&remote_str, argv[2], port)) {
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
		nse->dialect = NS2_DIALECT_UNDEF;
	return CMD_WARNING;
}

DEFUN(cfg_no_ns_nse_nsvc_ipa, cfg_no_ns_nse_nsvc_ipa_cmd,
      "no nsvc ipa BIND nsvci <0-65535> " VTY_IPV46_CMD " <1-65535>",
      NO_STR
      "Delete a NS Virtual Connection\n"
      "NS over UDP\n"
      "A unique bind identifier created by ns bind\n"
      "NS Virtual Connection ID (NS-VCI)\n"
      "NS Virtual Connection ID (NS-VCI)\n"
      "Remote IPv4 Address\n" "Remote IPv6 Address\n"
      "Remote UDP Port\n"
      )
{
	struct gprs_ns2_vc_bind *bind;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse = vty->index;
	const char *bind_name = argv[0];
	uint16_t nsvci = atoi(argv[1]);
	struct osmo_sockaddr_str remote_str;
	struct osmo_sockaddr remote;
	uint16_t port = atoi(argv[3]);

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "This NSE doesn't support UDP.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nse->dialect != NS2_DIALECT_IPACCESS) {
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

	if (osmo_sockaddr_str_from_str(&remote_str, argv[2], port)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_sockaddr_str_to_sockaddr(&remote_str, &remote.u.sas)) {
		vty_out(vty, "Can not parse IPv4/IPv6 or port.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	nsvc = gprs_ns2_nsvc_by_sockaddr_bind(bind, &remote);
	if (!nsvc) {
		vty_out(vty, "Can not find NS-VC with remote %s:%d%s",
			remote_str.ip, remote_str.port, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!nsvc->persistent) {
		vty_out(vty, "NS-VC with remote %s:%d is a dynamic NS-VC. Not configured by vty.%s",
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
		vty_out(vty, "NS-VC has a different nsvci (%d)!%s",
			nsvc->nsvci, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gprs_ns2_free_nsvc(nsvc);
	if (llist_empty(&nse->nsvc)) {
		nse->ll = GPRS_NS2_LL_UNDEF;
		nse->dialect = NS2_DIALECT_UNDEF;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_ns_nse_ip_sns, cfg_ns_nse_ip_sns_cmd,
      "ip-sns BINDGROUP " VTY_IPV46_CMD " <1-65535>",
      "SNS Initial Endpoint\n"
      "A bind group. Use \"all\" an alias for all UDP binds.\n"
      "SGSN IPv4 Address\n" "SGSN IPv6 Address\n"
      "SGSN UDP Port\n"
      )
{
	struct gprs_ns2_nse *nse = vty->index;
	bool dialect_modified = false;
	bool ll_modified = false;
	int rc;

	/* const char *bind_group = argv[0]; - needs SNS changes */
	struct osmo_sockaddr_str remote_str;
	struct osmo_sockaddr remote;
	uint16_t port = atoi(argv[2]);

	if (nse->ll == GPRS_NS2_LL_UNDEF) {
		nse->ll = GPRS_NS2_LL_UDP;
		ll_modified = true;
	}

	if (nse->dialect == NS2_DIALECT_UNDEF) {
		nse->dialect = NS2_DIALECT_SNS;
		dialect_modified = true;
	}

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "Can not mix NS-VC with different link layer%s", VTY_NEWLINE);
		goto err;
	}

	if (nse->dialect != NS2_DIALECT_SNS) {
		vty_out(vty, "Can not mix NS-VC with different dialects%s", VTY_NEWLINE);
		goto err;
	}

	if (osmo_sockaddr_str_from_str(&remote_str, argv[2], port)) {
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
		nse->dialect = NS2_DIALECT_UNDEF;
	return CMD_WARNING;
}

DEFUN(cfg_no_ns_nse_ip_sns, cfg_no_ns_nse_ip_sns_cmd,
      "no ip-sns BINDGROUP " VTY_IPV46_CMD " <1-65535>",
      NO_STR
      "Delete a SNS Initial Endpoint\n"
      "A bind group. Use \"all\" an alias for all UDP binds.\n"
      "SGSN IPv4 Address\n" "SGSN IPv6 Address\n"
      "SGSN UDP Port\n"
      )
{
	struct gprs_ns2_nse *nse = vty->index;
	/* const char *bind_group = argv[0]; need SNS changes */
	struct osmo_sockaddr_str remote_str; /* argv[2] */
	struct osmo_sockaddr remote;
	uint16_t port = atoi(argv[3]);
	int count;

	if (nse->ll != GPRS_NS2_LL_UDP) {
		vty_out(vty, "This NSE doesn't support UDP.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (nse->dialect != NS2_DIALECT_SNS) {
		vty_out(vty, "This NSE doesn't support UDP with dialect ip-sns.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_sockaddr_str_from_str(&remote_str, argv[2], port)) {
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

	count = gprs_ns2_sns_count(nse);
	if (count > 0) {
		 /* there are other sns endpoints */
		return CMD_SUCCESS;
	} else if (count < 0) {
		OSMO_ASSERT(0);
	} else {
		/* clean up nse to allow other nsvc commands */
		osmo_fsm_inst_term(nse->bss_sns_fi, OSMO_FSM_TERM_REQUEST, NULL);
		nse->ll = GPRS_NS2_LL_UNDEF;
		nse->dialect = NS2_DIALECT_UNDEF;
	}

	return CMD_SUCCESS;
}

static int config_write_ns_nse(struct vty *vty)
{
	/* TODO: ! */
	return 0;
}

/* non-config commands */
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

int gprs_ns2_vty2_init(struct gprs_ns2_inst *nsi)
{
	vty_nsi = nsi;
	INIT_LLIST_HEAD(&binds);

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
	/* TODO: convert into osmo timer */
	install_lib_element(L_NS_NODE, &cfg_ns_timer_cmd);
	install_lib_element(L_NS_NODE, &cfg_ns_nsei_cmd);
	install_lib_element(L_NS_NODE, &cfg_no_ns_nsei_cmd);
	install_lib_element(L_NS_NODE, &cfg_ns_bind_cmd);
	install_lib_element(L_NS_NODE, &cfg_no_ns_bind_cmd);

	install_node(&ns_bind_node, config_write_ns_bind);
	install_lib_element(L_NS_BIND_NODE, &cfg_ns_bind_listen_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_no_ns_bind_listen_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_ns_bind_ipaccess_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_no_ns_bind_ipaccess_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_ns_bind_fr_cmd);
	install_lib_element(L_NS_BIND_NODE, &cfg_no_ns_bind_fr_cmd);
	/* TODO: accept-ip-sns group IDENTIFIER */

	install_node(&ns_nse_node, config_write_ns_nse);
	install_lib_element(L_NS_NSE_NODE, &cfg_ns_nse_nsvc_fr_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_no_ns_nse_nsvc_fr_nsvci_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_no_ns_nse_nsvc_fr_dlci_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_ns_nse_nsvc_udp_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_no_ns_nse_nsvc_udp_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_ns_nse_nsvc_ipa_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_no_ns_nse_nsvc_ipa_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_ns_nse_ip_sns_cmd);
	install_lib_element(L_NS_NSE_NODE, &cfg_no_ns_nse_ip_sns_cmd);


	return 0;
}
