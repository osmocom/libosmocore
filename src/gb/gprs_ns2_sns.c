/*! \file gprs_ns2_sns.c
 * NS Sub-Network Service Protocol implementation
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05)
 * as well as its successor 3GPP TS 48.016 */

/* (C) 2018 by Harald Welte <laforge@gnumonks.org>
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

/* The BSS NSE only has one SGSN IP address configured, and it will use the SNS procedures
 * to communicated its local IPs/ports as well as all the SGSN side IPs/ports and
 * associated weights. The BSS then uses this to establish a full mesh
 * of NSVCs between all BSS-side IPs/ports and SGSN-side IPs/ports.
 *
 * Known limitation/expectation/bugs:
 * - No concurrent dual stack. It supports either IPv4 or IPv6, but not both at the same time.
 * - SNS Add/Change/Delete: Doesn't answer on the same NSVC as received SNS ADD/CHANGE/DELETE PDUs.
 * - SNS Add/Change/Delete: Doesn't communicated the failed IPv4/IPv6 entries on the SNS_ACK.
 */

#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/protocol/gsm_08_16.h>

#include "gprs_ns2_internal.h"

#define S(x)	(1 << (x))

enum ns2_sns_type {
	IPv4,
	IPv6,
};

enum gprs_sns_bss_state {
	GPRS_SNS_ST_UNCONFIGURED,
	GPRS_SNS_ST_SIZE,		/*!< SNS-SIZE procedure ongoing */
	GPRS_SNS_ST_CONFIG_BSS,		/*!< SNS-CONFIG procedure (BSS->SGSN) ongoing */
	GPRS_SNS_ST_CONFIG_SGSN,	/*!< SNS-CONFIG procedure (SGSN->BSS) ongoing */
	GPRS_SNS_ST_CONFIGURED,
};

enum gprs_sns_event {
	GPRS_SNS_EV_SELECT_ENDPOINT,	/*!< Select a SNS endpoint from the list */
	GPRS_SNS_EV_SIZE,
	GPRS_SNS_EV_SIZE_ACK,
	GPRS_SNS_EV_CONFIG,
	GPRS_SNS_EV_CONFIG_END,		/*!< SNS-CONFIG with end flag received */
	GPRS_SNS_EV_CONFIG_ACK,
	GPRS_SNS_EV_ADD,
	GPRS_SNS_EV_DELETE,
	GPRS_SNS_EV_CHANGE_WEIGHT,
	GPRS_SNS_EV_NO_NSVC,
};

static const struct value_string gprs_sns_event_names[] = {
	{ GPRS_SNS_EV_SELECT_ENDPOINT,	"SELECT_ENDPOINT" },
	{ GPRS_SNS_EV_SIZE,		"SIZE" },
	{ GPRS_SNS_EV_SIZE_ACK,		"SIZE_ACK" },
	{ GPRS_SNS_EV_CONFIG,		"CONFIG" },
	{ GPRS_SNS_EV_CONFIG_END,	"CONFIG_END" },
	{ GPRS_SNS_EV_CONFIG_ACK,	"CONFIG_ACK" },
	{ GPRS_SNS_EV_ADD,		"ADD" },
	{ GPRS_SNS_EV_DELETE,		"DELETE" },
	{ GPRS_SNS_EV_CHANGE_WEIGHT,	"CHANGE_WEIGHT" },
	{ GPRS_SNS_EV_NO_NSVC,		"NO_NSVC" },
	{ 0, NULL }
};

struct sns_endpoint {
	struct llist_head list;
	struct osmo_sockaddr saddr;
};

struct ns2_sns_state {
	struct gprs_ns2_nse *nse;

	enum ns2_sns_type ip;

	/* holds the list of initial SNS endpoints */
	struct llist_head sns_endpoints;
	/* prevent recursive reselection */
	bool reselection_running;

	/* The current initial SNS endpoints.
	 * The initial connection will be moved into the NSE
	 * if configured via SNS. Otherwise it will be removed
	 * in configured state. */
	struct sns_endpoint *initial;
	/* all SNS PDU will be sent over this nsvc */
	struct gprs_ns2_vc *sns_nsvc;
	/* iterate over the binds after all remote has been tested */
	int bind_offset;

	/* local configuration to send to the remote end */
	struct gprs_ns_ie_ip4_elem *ip4_local;
	size_t num_ip4_local;

	/* local configuration to send to the remote end */
	struct gprs_ns_ie_ip6_elem *ip6_local;
	size_t num_ip6_local;

	/* local configuration about our capabilities in terms of connections to
	 * remote (SGSN) side */
	size_t num_max_nsvcs;
	size_t num_max_ip4_remote;
	size_t num_max_ip6_remote;

	/* remote configuration as received */
	struct gprs_ns_ie_ip4_elem *ip4_remote;
	unsigned int num_ip4_remote;

	/* remote configuration as received */
	struct gprs_ns_ie_ip6_elem *ip6_remote;
	unsigned int num_ip6_remote;
};

static inline struct gprs_ns2_nse *nse_inst_from_fi(struct osmo_fsm_inst *fi)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	return gss->nse;
}

/* helper function to compute the sum of all (data or signaling) weights */
static int ip4_weight_sum(const struct gprs_ns_ie_ip4_elem *ip4, unsigned int num,
			  bool data_weight)
{
	unsigned int i;
	int weight_sum = 0;

	for (i = 0; i < num; i++) {
		if (data_weight)
			weight_sum += ip4[i].data_weight;
		else
			weight_sum += ip4[i].sig_weight;
	}
	return weight_sum;
}
#define ip4_weight_sum_data(x,y)	ip4_weight_sum(x, y, true)
#define ip4_weight_sum_sig(x,y)		ip4_weight_sum(x, y, false)

/* helper function to compute the sum of all (data or signaling) weights */
static int ip6_weight_sum(const struct gprs_ns_ie_ip6_elem *ip6, unsigned int num,
			  bool data_weight)
{
	unsigned int i;
	int weight_sum = 0;

	for (i = 0; i < num; i++) {
		if (data_weight)
			weight_sum += ip6[i].data_weight;
		else
			weight_sum += ip6[i].sig_weight;
	}
	return weight_sum;
}
#define ip6_weight_sum_data(x,y)	ip6_weight_sum(x, y, true)
#define ip6_weight_sum_sig(x,y)		ip6_weight_sum(x, y, false)

static struct gprs_ns2_vc *nsvc_by_ip4_elem(struct gprs_ns2_nse *nse,
					    const struct gprs_ns_ie_ip4_elem *ip4)
{
	struct osmo_sockaddr sa;
	/* copy over. Both data structures use network byte order */
	sa.u.sin.sin_addr.s_addr = ip4->ip_addr;
	sa.u.sin.sin_port = ip4->udp_port;
	sa.u.sin.sin_family = AF_INET;

	return gprs_ns2_nsvc_by_sockaddr_nse(nse, &sa);
}

static struct gprs_ns2_vc *nsvc_by_ip6_elem(struct gprs_ns2_nse *nse,
					    const struct gprs_ns_ie_ip6_elem *ip6)
{
	struct osmo_sockaddr sa;
	/* copy over. Both data structures use network byte order */
	sa.u.sin6.sin6_addr = ip6->ip_addr;
	sa.u.sin6.sin6_port = ip6->udp_port;
	sa.u.sin6.sin6_family = AF_INET;

	return gprs_ns2_nsvc_by_sockaddr_nse(nse, &sa);
}

/*! Return the initial SNS remote socket address
 * \param nse NS Entity
 * \return address of the initial SNS connection; NULL in case of error
 */
const struct osmo_sockaddr *gprs_ns2_nse_sns_remote(struct gprs_ns2_nse *nse)
{
	struct ns2_sns_state *gss;

	if (!nse->bss_sns_fi)
		return NULL;

	gss = (struct ns2_sns_state *) nse->bss_sns_fi->priv;
	return &gss->initial->saddr;
}

/*! called when a nsvc is beeing freed */
void ns2_sns_free_nsvc(struct gprs_ns2_vc *nsvc)
{
	struct gprs_ns2_nse *nse;
	struct gprs_ns2_vc *tmp;
	struct ns2_sns_state *gss;
	struct osmo_fsm_inst *fi = nsvc->nse->bss_sns_fi;

	if (!fi)
		return;

	gss = (struct ns2_sns_state *) fi->priv;
	if (nsvc != gss->sns_nsvc)
		return;

	nse = nsvc->nse;
	if (nse->alive) {
		/* choose a different sns nsvc */
		llist_for_each_entry(tmp, &nse->nsvc, list) {
			if (gprs_ns2_vc_is_unblocked(tmp))
				gss->sns_nsvc = tmp;
		}
	} else {
		LOGPFSML(fi, LOGL_ERROR, "NSE %d: no remaining NSVC, resetting SNS FSM\n", nse->nsei);
		gss->sns_nsvc = NULL;
		osmo_fsm_inst_dispatch(fi, GPRS_SNS_EV_NO_NSVC, NULL);
	}
}

static void ns2_nsvc_create_ip4(struct osmo_fsm_inst *fi,
				 struct gprs_ns2_nse *nse,
				 const struct gprs_ns_ie_ip4_elem *ip4)
{
	struct gprs_ns2_inst *nsi = nse->nsi;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_vc_bind *bind;
	struct osmo_sockaddr remote = { };
	/* copy over. Both data structures use network byte order */
	remote.u.sin.sin_family = AF_INET;
	remote.u.sin.sin_addr.s_addr = ip4->ip_addr;
	remote.u.sin.sin_port = ip4->udp_port;

	/* for every bind, create a connection if bind type == IP */
	llist_for_each_entry(bind, &nsi->binding, list) {
		/* ignore failed connection */
		nsvc = gprs_ns2_ip_connect_inactive(bind,
					   &remote,
					   nse, 0);
		if (!nsvc) {
			LOGPFSML(fi, LOGL_ERROR, "SNS-CONFIG: Failed to create NSVC\n");
			continue;
		}

		nsvc->sig_weight = ip4->sig_weight;
		nsvc->data_weight = ip4->data_weight;
	}
}

static void ns2_nsvc_create_ip6(struct osmo_fsm_inst *fi,
				 struct gprs_ns2_nse *nse,
				 const struct gprs_ns_ie_ip6_elem *ip6)
{
	struct gprs_ns2_inst *nsi = nse->nsi;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_vc_bind *bind;
	struct osmo_sockaddr remote = {};
	/* copy over. Both data structures use network byte order */
	remote.u.sin6.sin6_family = AF_INET6;
	remote.u.sin6.sin6_addr = ip6->ip_addr;
	remote.u.sin6.sin6_port = ip6->udp_port;

	/* for every bind, create a connection if bind type == IP */
	llist_for_each_entry(bind, &nsi->binding, list) {
		/* ignore failed connection */
		nsvc = gprs_ns2_ip_connect_inactive(bind,
					   &remote,
					   nse, 0);
		if (!nsvc) {
			LOGPFSML(fi, LOGL_ERROR, "SNS-CONFIG: Failed to create NSVC\n");
			continue;
		}

		nsvc->sig_weight = ip6->sig_weight;
		nsvc->data_weight = ip6->data_weight;
	}
}


static int create_missing_nsvcs(struct osmo_fsm_inst *fi)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_vc_bind *bind;
	struct osmo_sockaddr remote = { };
	unsigned int i;

	for (i = 0; i < gss->num_ip4_remote; i++) {
		const struct gprs_ns_ie_ip4_elem *ip4 = &gss->ip4_remote[i];

		remote.u.sin.sin_family = AF_INET;
		remote.u.sin.sin_addr.s_addr = ip4->ip_addr;
		remote.u.sin.sin_port = ip4->udp_port;

		llist_for_each_entry(bind, &nse->nsi->binding, list) {
			bool found = false;

			llist_for_each_entry(nsvc, &nse->nsvc, list) {
				if (nsvc->bind != bind)
					continue;

				if (!osmo_sockaddr_cmp(&remote, gprs_ns2_ip_vc_remote(nsvc))) {
					found = true;
					break;
				}
			}

			if (!found) {
				nsvc = gprs_ns2_ip_connect_inactive(bind, &remote, nse, 0);
				if (!nsvc) {
					/* TODO: add to a list to send back a NS-STATUS */
					continue;
				}
			}

			/* update data / signalling weight */
			nsvc->data_weight = ip4->data_weight;
			nsvc->sig_weight = ip4->sig_weight;
			nsvc->sns_only = false;
		}
	}

	for (i = 0; i < gss->num_ip6_remote; i++) {
		const struct gprs_ns_ie_ip6_elem *ip6 = &gss->ip6_remote[i];

		remote.u.sin6.sin6_family = AF_INET6;
		remote.u.sin6.sin6_addr = ip6->ip_addr;
		remote.u.sin6.sin6_port = ip6->udp_port;

		llist_for_each_entry(bind, &nse->nsi->binding, list) {
			bool found = false;

			llist_for_each_entry(nsvc, &nse->nsvc, list) {
				if (nsvc->bind != bind)
					continue;

				if (!osmo_sockaddr_cmp(&remote, gprs_ns2_ip_vc_remote(nsvc))) {
					found = true;
					break;
				}
			}

			if (!found) {
				nsvc = gprs_ns2_ip_connect_inactive(bind, &remote, nse, 0);
				if (!nsvc) {
					/* TODO: add to a list to send back a NS-STATUS */
					continue;
				}
			}

			/* update data / signalling weight */
			nsvc->data_weight = ip6->data_weight;
			nsvc->sig_weight = ip6->sig_weight;
			nsvc->sns_only = false;
		}
	}


	return 0;
}

/* Add a given remote IPv4 element to gprs_sns_state */
static int add_remote_ip4_elem(struct ns2_sns_state *gss, const struct gprs_ns_ie_ip4_elem *ip4)
{
	unsigned int i;

	if (gss->num_ip4_remote >= gss->num_max_ip4_remote)
		return -NS_CAUSE_INVAL_NR_NS_VC;

	/* check for duplicates */
	for (i = 0; i < gss->num_ip4_remote; i++) {
		if (memcmp(&gss->ip4_remote[i], ip4, sizeof(*ip4)))
			continue;
		/* TODO: log message duplicate */
		/* TODO: check if this is the correct cause code */
		return -NS_CAUSE_PROTO_ERR_UNSPEC;
	}

	gss->ip4_remote = talloc_realloc(gss, gss->ip4_remote, struct gprs_ns_ie_ip4_elem,
					 gss->num_ip4_remote+1);
	gss->ip4_remote[gss->num_ip4_remote] = *ip4;
	gss->num_ip4_remote += 1;
	return 0;
}

/* Remove a given remote IPv4 element from gprs_sns_state */
static int remove_remote_ip4_elem(struct ns2_sns_state *gss, const struct gprs_ns_ie_ip4_elem *ip4)
{
	unsigned int i;

	for (i = 0; i < gss->num_ip4_remote; i++) {
		if (memcmp(&gss->ip4_remote[i], ip4, sizeof(*ip4)))
			continue;
		/* all array elements < i remain as they are; all > i are shifted left by one */
		memmove(&gss->ip4_remote[i], &gss->ip4_remote[i+1], gss->num_ip4_remote-i-1);
		gss->num_ip4_remote -= 1;
		return 0;
	}
	return -1;
}

/* update the weights for specified remote IPv4 */
static int update_remote_ip4_elem(struct ns2_sns_state *gss, const struct gprs_ns_ie_ip4_elem *ip4)
{
	unsigned int i;

	for (i = 0; i < gss->num_ip4_remote; i++) {
		if (gss->ip4_remote[i].ip_addr != ip4->ip_addr ||
		    gss->ip4_remote[i].udp_port != ip4->udp_port)
			continue;

		gss->ip4_remote[i].sig_weight = ip4->sig_weight;
		gss->ip4_remote[i].data_weight = ip4->data_weight;
		return 0;
	}
	return -1;
}

/* Add a given remote IPv6 element to gprs_sns_state */
static int add_remote_ip6_elem(struct ns2_sns_state *gss, const struct gprs_ns_ie_ip6_elem *ip6)
{
	if (gss->num_ip6_remote >= gss->num_max_ip6_remote)
		return -NS_CAUSE_INVAL_NR_NS_VC;

	gss->ip6_remote = talloc_realloc(gss, gss->ip6_remote, struct gprs_ns_ie_ip6_elem,
					 gss->num_ip6_remote+1);
	gss->ip6_remote[gss->num_ip6_remote] = *ip6;
	gss->num_ip6_remote += 1;
	return 0;
}

/* Remove a given remote IPv6 element from gprs_sns_state */
static int remove_remote_ip6_elem(struct ns2_sns_state *gss, const struct gprs_ns_ie_ip6_elem *ip6)
{
	unsigned int i;

	for (i = 0; i < gss->num_ip6_remote; i++) {
		if (memcmp(&gss->ip6_remote[i], ip6, sizeof(*ip6)))
			continue;
		/* all array elements < i remain as they are; all > i are shifted left by one */
		memmove(&gss->ip6_remote[i], &gss->ip6_remote[i+1], gss->num_ip6_remote-i-1);
		gss->num_ip6_remote -= 1;
		return 0;
	}
	return -1;
}

/* update the weights for specified remote IPv6 */
static int update_remote_ip6_elem(struct ns2_sns_state *gss, const struct gprs_ns_ie_ip6_elem *ip6)
{
	unsigned int i;

	for (i = 0; i < gss->num_ip6_remote; i++) {
		if (memcmp(&gss->ip6_remote[i].ip_addr, &ip6->ip_addr, sizeof(ip6->ip_addr)) ||
		    gss->ip6_remote[i].udp_port != ip6->udp_port)
			continue;
		gss->ip6_remote[i].sig_weight = ip6->sig_weight;
		gss->ip6_remote[i].data_weight = ip6->data_weight;
		return 0;
	}
	return -1;
}

static int do_sns_change_weight(struct osmo_fsm_inst *fi, const struct gprs_ns_ie_ip4_elem *ip4, const struct gprs_ns_ie_ip6_elem *ip6)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct gprs_ns2_vc *nsvc;
	struct osmo_sockaddr sa = {};
	const struct osmo_sockaddr *remote;
	uint8_t new_signal;
	uint8_t new_data;

	/* TODO: Upon receiving an SNS-CHANGEWEIGHT PDU, if the resulting sum of the
	 * signalling weights of all the peer IP endpoints configured for this NSE is
	 * equal to zero or if the resulting sum of the data weights of all the peer IP
	 * endpoints configured for this NSE is equal to zero, the BSS/SGSN shall send an
	 * SNS-ACK PDU with a cause code of "Invalid weights". */

	if (ip4) {
		if (update_remote_ip4_elem(gss, ip4))
			return -NS_CAUSE_UNKN_IP_EP;

		/* copy over. Both data structures use network byte order */
		sa.u.sin.sin_addr.s_addr = ip4->ip_addr;
		sa.u.sin.sin_port = ip4->udp_port;
		sa.u.sin.sin_family = AF_INET;
		new_signal = ip4->sig_weight;
		new_data = ip4->data_weight;
	} else if (ip6) {
		if (update_remote_ip6_elem(gss, ip6))
			return -NS_CAUSE_UNKN_IP_EP;

		/* copy over. Both data structures use network byte order */
		sa.u.sin6.sin6_addr = ip6->ip_addr;
		sa.u.sin6.sin6_port = ip6->udp_port;
		sa.u.sin6.sin6_family = AF_INET6;
		new_signal = ip6->sig_weight;
		new_data = ip6->data_weight;
	} else {
		OSMO_ASSERT(false);
	}

	llist_for_each_entry(nsvc, &nse->nsvc, list) {
		remote = gprs_ns2_ip_vc_remote(nsvc);
		/* all nsvc in NSE should be IP/UDP nsvc */
		OSMO_ASSERT(remote);

		if (osmo_sockaddr_cmp(&sa, remote))
			continue;

		LOGPFSML(fi, LOGL_INFO, "CHANGE-WEIGHT NS-VC %s data_weight %u->%u, sig_weight %u->%u\n",
			 gprs_ns2_ll_str(nsvc), nsvc->data_weight, new_data,
			 nsvc->sig_weight, new_signal);

		nsvc->data_weight = new_data;
		nsvc->sig_weight = new_signal;
	}

	return 0;
}

static int do_sns_delete(struct osmo_fsm_inst *fi,
			 const struct gprs_ns_ie_ip4_elem *ip4,
			 const struct gprs_ns_ie_ip6_elem *ip6)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct gprs_ns2_vc *nsvc, *tmp;
	const struct osmo_sockaddr *remote;
	struct osmo_sockaddr sa = {};

	if (ip4) {
		if (remove_remote_ip4_elem(gss, ip4) < 0)
			return -NS_CAUSE_UNKN_IP_EP;
		/* copy over. Both data structures use network byte order */
		sa.u.sin.sin_addr.s_addr = ip4->ip_addr;
		sa.u.sin.sin_port = ip4->udp_port;
		sa.u.sin.sin_family = AF_INET;
	} else if (ip6) {
		if (remove_remote_ip6_elem(gss, ip6))
			return -NS_CAUSE_UNKN_IP_EP;

		/* copy over. Both data structures use network byte order */
		sa.u.sin6.sin6_addr = ip6->ip_addr;
		sa.u.sin6.sin6_port = ip6->udp_port;
		sa.u.sin6.sin6_family = AF_INET6;
	} else {
		OSMO_ASSERT(false);
	}

	llist_for_each_entry_safe(nsvc, tmp, &nse->nsvc, list) {
		remote = gprs_ns2_ip_vc_remote(nsvc);
		/* all nsvc in NSE should be IP/UDP nsvc */
		OSMO_ASSERT(remote);
		if (osmo_sockaddr_cmp(&sa, remote))
			continue;

		LOGPFSML(fi, LOGL_INFO, "DELETE NS-VC %s\n", gprs_ns2_ll_str(nsvc));
		gprs_ns2_free_nsvc(nsvc);
	}

	return 0;
}

static int do_sns_add(struct osmo_fsm_inst *fi,
		      const struct gprs_ns_ie_ip4_elem *ip4,
		      const struct gprs_ns_ie_ip6_elem *ip6)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct gprs_ns2_vc *nsvc;
	int rc = 0;

	/* Upon receiving an SNS-ADD PDU, if the consequent number of IPv4 endpoints
	 * exceeds the number of IPv4 endpoints supported by the NSE, the NSE shall send
	 * an SNS-ACK PDU with a cause code set to "Invalid number of IP4 Endpoints". */
	switch (gss->ip) {
	case IPv4:
		rc = add_remote_ip4_elem(gss, ip4);
		break;
	case IPv6:
		rc = add_remote_ip6_elem(gss, ip6);
		break;
	default:
		/* the gss->ip is initialized with the bss */
		OSMO_ASSERT(false);
	}

	if (rc)
		return rc;

	/* Upon receiving an SNS-ADD PDU containing an already configured IP endpoint the
	 * NSE shall send an SNS-ACK PDU with the cause code "Protocol error -
	 * unspecified" */
	switch (gss->ip) {
	case IPv4:
		nsvc = nsvc_by_ip4_elem(nse, ip4);
		if (nsvc) {
			/* the nsvc should be already in sync with the ip4 / ip6 elements */
			return -NS_CAUSE_PROTO_ERR_UNSPEC;
		}

		/* TODO: failure case */
		ns2_nsvc_create_ip4(fi, nse, ip4);
		break;
	case IPv6:
		nsvc = nsvc_by_ip6_elem(nse, ip6);
		if (nsvc) {
			/* the nsvc should be already in sync with the ip4 / ip6 elements */
			return -NS_CAUSE_PROTO_ERR_UNSPEC;
		}

		/* TODO: failure case */
		ns2_nsvc_create_ip6(fi, nse, ip6);
		break;
	}

	gprs_ns2_start_alive_all_nsvcs(nse);

	return 0;
}


static void ns2_sns_st_unconfigured(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* empty state - SNS Select will start by all action */
}

static void ns2_sns_st_size(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct gprs_ns2_inst *nsi = nse->nsi;
	struct tlv_parsed *tp = NULL;

	switch (event) {
	case GPRS_SNS_EV_SIZE_ACK:
		tp = data;
		if (TLVP_VAL_MINLEN(tp, NS_IE_CAUSE, 1)) {
			LOGPFSML(fi, LOGL_ERROR, "SNS-SIZE-ACK with cause %s\n",
				 gprs_ns2_cause_str(*TLVP_VAL(tp, NS_IE_CAUSE)));
			/* TODO: What to do? */
		} else {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_CONFIG_BSS,
						nsi->timeout[NS_TOUT_TSNS_PROV], 2);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* setup all dynamic SNS settings, create a new nsvc and send the SIZE */
static void ns2_sns_st_size_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns_ie_ip4_elem *ip4_elems;
	struct gprs_ns_ie_ip6_elem *ip6_elems;
	struct gprs_ns2_vc_bind *bind;
	struct gprs_ns2_inst *nsi = gss->nse->nsi;
	struct osmo_sockaddr *remote;
	const struct osmo_sockaddr *sa;
	struct osmo_sockaddr local;
	int count;

	/* on a generic failure, the timer callback will recover */
	if (old_state != GPRS_SNS_ST_UNCONFIGURED)
		ns2_prim_status_ind(gss->nse, NULL, 0, NS_AFF_CAUSE_SNS_FAILURE);

	/* no initial available */
	if (!gss->initial)
		return;

	remote = &gss->initial->saddr;

	/* count how many bindings are available (only UDP binds) */
	count = ns2_ip_count_bind(nsi, remote);
	if (count == 0) {
		/* TODO: logging */
		return;
	}

	bind = ns2_ip_get_bind_by_offset(nsi, remote, gss->bind_offset);
	if (!bind) {
		if (gss->bind_offset) {
			gss->bind_offset = 0;
			bind = ns2_ip_get_bind_by_offset(nsi, remote, gss->bind_offset);
		}

		if (!bind)
			return;
	}

	/* setup the NSVC */
	if (!gss->sns_nsvc) {
		gss->sns_nsvc = gprs_ns2_ip_bind_connect(bind, gss->nse, remote);
		if (!gss->sns_nsvc)
			return;
		gss->sns_nsvc->sns_only = true;
	}

	switch (gss->ip) {
	case IPv4:
		ip4_elems = talloc_zero_size(fi, sizeof(struct gprs_ns_ie_ip4_elem) * count);
		if (!ip4_elems)
			return;

		gss->ip4_local = ip4_elems;

		llist_for_each_entry(bind, &nsi->binding, list) {
			if (!gprs_ns2_is_ip_bind(bind))
				continue;

			sa = gprs_ns2_ip_bind_sockaddr(bind);
			if (!sa)
				continue;

			if (sa->u.sas.ss_family != AF_INET)
				continue;

			/* check if this is an specific bind */
			if (sa->u.sin.sin_addr.s_addr == 0) {
				if (osmo_sockaddr_local_ip(&local, remote))
					continue;

				ip4_elems->ip_addr = local.u.sin.sin_addr.s_addr;
			} else {
				ip4_elems->ip_addr = sa->u.sin.sin_addr.s_addr;
			}

			ip4_elems->udp_port = sa->u.sin.sin_port;
			ip4_elems->sig_weight = 2;
			ip4_elems->data_weight = 1;
			ip4_elems++;
		}

		gss->num_ip4_local = count;
		gss->num_max_ip4_remote = 4;
		gss->num_max_nsvcs = OSMO_MAX(gss->num_max_ip4_remote * gss->num_ip4_local, 8);
		break;
	case IPv6:
		/* IPv6 */
		ip6_elems = talloc_zero_size(fi, sizeof(struct gprs_ns_ie_ip6_elem) * count);
		if (!ip6_elems)
			return;

		gss->ip6_local = ip6_elems;

		llist_for_each_entry(bind, &nsi->binding, list) {
			if (!gprs_ns2_is_ip_bind(bind))
				continue;

			sa = gprs_ns2_ip_bind_sockaddr(bind);
			if (!sa)
				continue;

			if (sa->u.sas.ss_family != AF_INET6)
				continue;

			/* check if this is an specific bind */
			if (IN6_IS_ADDR_UNSPECIFIED(&sa->u.sin6.sin6_addr)) {
				if (osmo_sockaddr_local_ip(&local, remote))
					continue;

				ip6_elems->ip_addr = local.u.sin6.sin6_addr;
			} else {
				ip6_elems->ip_addr = sa->u.sin6.sin6_addr;
			}

			ip6_elems->udp_port = sa->u.sin.sin_port;
			ip6_elems->sig_weight = 2;
			ip6_elems->data_weight = 1;

			ip6_elems++;
		}
		gss->num_ip6_local = count;
		gss->num_max_ip6_remote = 4;
		gss->num_max_nsvcs = OSMO_MAX(gss->num_max_ip6_remote * gss->num_ip6_local, 8);
		break;
	}

	if (gss->num_max_ip4_remote > 0)
		ns2_tx_sns_size(gss->sns_nsvc, true, gss->num_max_nsvcs, gss->num_max_ip4_remote, -1);
	else
		ns2_tx_sns_size(gss->sns_nsvc, true, gss->num_max_nsvcs, -1, gss->num_max_ip6_remote);
}

static void ns2_sns_st_config_bss(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tlv_parsed *tp = NULL;

	switch (event) {
	case GPRS_SNS_EV_CONFIG_ACK:
		tp = (struct tlv_parsed *) data;
		if (TLVP_VAL_MINLEN(tp, NS_IE_CAUSE, 1)) {
			LOGPFSML(fi, LOGL_ERROR, "SNS-CONFIG-ACK with cause %s\n",
							 gprs_ns2_cause_str(*TLVP_VAL(tp, NS_IE_CAUSE)));
			/* TODO: What to do? */
		} else {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_CONFIG_SGSN, 0, 0);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void ns2_sns_st_config_bss_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	/* Transmit SNS-CONFIG */
	switch (gss->ip) {
	case IPv4:
		ns2_tx_sns_config(gss->sns_nsvc, true,
				  gss->ip4_local, gss->num_ip4_local,
				  NULL, 0);
		break;
	case IPv6:
		ns2_tx_sns_config(gss->sns_nsvc, true,
				  NULL, 0,
				  gss->ip6_local, gss->num_ip6_local);
		break;
	}
}


static void ns_sns_st_config_sgsn_ip4(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	const struct gprs_ns_ie_ip4_elem *v4_list;
	unsigned int num_v4;
	struct tlv_parsed *tp = NULL;

	uint8_t cause;

	tp = (struct tlv_parsed *) data;

	if (!TLVP_PRESENT(tp, NS_IE_IPv4_LIST)) {
		cause = NS_CAUSE_INVAL_NR_IPv4_EP;
		ns2_tx_sns_config_ack(gss->sns_nsvc, &cause);
		osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 0);
		return;
	}
	v4_list = (const struct gprs_ns_ie_ip4_elem *) TLVP_VAL(tp, NS_IE_IPv4_LIST);
	num_v4 = TLVP_LEN(tp, NS_IE_IPv4_LIST) / sizeof(*v4_list);
	/* realloc to the new size */
	gss->ip4_remote = talloc_realloc(gss, gss->ip4_remote,
					 struct gprs_ns_ie_ip4_elem,
					 gss->num_ip4_remote+num_v4);
	/* append the new entries to the end of the list */
	memcpy(&gss->ip4_remote[gss->num_ip4_remote], v4_list, num_v4*sizeof(*v4_list));
	gss->num_ip4_remote += num_v4;

	LOGPFSML(fi, LOGL_INFO, "Rx SNS-CONFIG: Remote IPv4 list now %u entries\n",
					 gss->num_ip4_remote);
	if (event == GPRS_SNS_EV_CONFIG_END) {
		/* check if sum of data / sig weights == 0 */
		if (ip4_weight_sum_data(gss->ip4_remote, gss->num_ip4_remote) == 0 ||
				ip4_weight_sum_sig(gss->ip4_remote, gss->num_ip4_remote) == 0) {
			cause = NS_CAUSE_INVAL_WEIGH;
			ns2_tx_sns_config_ack(gss->sns_nsvc, &cause);
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 0);
			return;
		}
		create_missing_nsvcs(fi);
		ns2_tx_sns_config_ack(gss->sns_nsvc, NULL);
		/* start the test procedure on ALL NSVCs! */
		gprs_ns2_start_alive_all_nsvcs(nse);
		osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_CONFIGURED, 0, 0);
	} else {
		/* just send CONFIG-ACK */
		ns2_tx_sns_config_ack(gss->sns_nsvc, NULL);
	}
}

static void ns_sns_st_config_sgsn_ip6(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	const struct gprs_ns_ie_ip6_elem *v6_list;
	unsigned int num_v6;
	struct tlv_parsed *tp = NULL;

	uint8_t cause;

	tp = (struct tlv_parsed *) data;

	if (!TLVP_PRESENT(tp, NS_IE_IPv6_LIST)) {
		cause = NS_CAUSE_INVAL_NR_IPv6_EP;
		ns2_tx_sns_config_ack(gss->sns_nsvc, &cause);
		osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 0);
		return;
	}
	v6_list = (const struct gprs_ns_ie_ip6_elem *) TLVP_VAL(tp, NS_IE_IPv6_LIST);
	num_v6 = TLVP_LEN(tp, NS_IE_IPv6_LIST) / sizeof(*v6_list);
	/* realloc to the new size */
	gss->ip6_remote = talloc_realloc(gss, gss->ip6_remote,
					 struct gprs_ns_ie_ip6_elem,
					 gss->num_ip6_remote+num_v6);
	/* append the new entries to the end of the list */
	memcpy(&gss->ip6_remote[gss->num_ip6_remote], v6_list, num_v6*sizeof(*v6_list));
	gss->num_ip6_remote += num_v6;

	LOGPFSML(fi, LOGL_INFO, "Rx SNS-CONFIG: Remote IPv6 list now %u entries\n",
					 gss->num_ip6_remote);
	if (event == GPRS_SNS_EV_CONFIG_END) {
		/* check if sum of data / sig weights == 0 */
		if (ip6_weight_sum_data(gss->ip6_remote, gss->num_ip6_remote) == 0 ||
				ip6_weight_sum_sig(gss->ip6_remote, gss->num_ip6_remote) == 0) {
			cause = NS_CAUSE_INVAL_WEIGH;
			ns2_tx_sns_config_ack(gss->sns_nsvc, &cause);
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 0);
			return;
		}
		create_missing_nsvcs(fi);
		ns2_tx_sns_config_ack(gss->sns_nsvc, NULL);
		/* start the test procedure on ALL NSVCs! */
		gprs_ns2_start_alive_all_nsvcs(nse);
		osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_CONFIGURED, 0, 0);
	} else {
		/* just send CONFIG-ACK */
		ns2_tx_sns_config_ack(gss->sns_nsvc, NULL);
	}
}

static void ns2_sns_st_config_sgsn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;

	switch (event) {
	case GPRS_SNS_EV_CONFIG_END:
	case GPRS_SNS_EV_CONFIG:

#if 0		/* part of incoming SNS-SIZE (doesn't happen on BSS side */
		if (TLVP_PRESENT(tp, NS_IE_RESET_FLAG)) {
			/* reset all existing config */
			if (gss->ip4_remote)
				talloc_free(gss->ip4_remote);
			gss->num_ip4_remote = 0;
		}
#endif
		/* TODO: reject IPv6 elements on IPv4 mode and vice versa */
		switch (gss->ip) {
		case IPv4:
			ns_sns_st_config_sgsn_ip4(fi, event, data);
			break;
		case IPv6:
			ns_sns_st_config_sgsn_ip6(fi, event, data);
			break;
		default:
			OSMO_ASSERT(0);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* called when receiving GPRS_SNS_EV_ADD in state configure */
static void ns2_sns_st_configured_add(struct osmo_fsm_inst *fi,
				      struct ns2_sns_state *gss,
				      struct tlv_parsed *tp)
{
	const struct gprs_ns_ie_ip4_elem *v4_list = NULL;
	const struct gprs_ns_ie_ip6_elem *v6_list = NULL;
	int num_v4 = 0, num_v6 = 0;
	uint8_t trans_id, cause = 0xff;
	unsigned int i;
	int rc = 0;

	/* TODO: refactor EV_ADD/CHANGE/REMOVE by
	 * check uniqueness within the lists (no doublicate entries)
	 * check not-known-by-us and sent back a list of unknown/known values
	 * (abnormal behaviour according to 48.016)
	 */

	trans_id = *TLVP_VAL(tp, NS_IE_TRANS_ID);
	if (gss->ip == IPv4) {
		if (!TLVP_PRESENT(tp, NS_IE_IPv4_LIST)) {
			cause = NS_CAUSE_INVAL_NR_IPv4_EP;
			ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
			return;
		}

		v4_list = (const struct gprs_ns_ie_ip4_elem *) TLVP_VAL(tp, NS_IE_IPv4_LIST);
		num_v4 = TLVP_LEN(tp, NS_IE_IPv4_LIST) / sizeof(*v4_list);
		for (i = 0; i < num_v4; i++) {
			unsigned int j;
			rc = do_sns_add(fi, &v4_list[i], NULL);
			if (rc < 0) {
				/* rollback/undo to restore previous state */
				for (j = 0; j < i; j++)
					do_sns_delete(fi, &v4_list[j], NULL);
				cause = -rc;
				ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
				break;
			}
		}
	} else { /* IPv6 */
		if (!TLVP_PRESENT(tp, NS_IE_IPv6_LIST)) {
			cause = NS_CAUSE_INVAL_NR_IPv6_EP;
			ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
			return;
		}

		v6_list = (const struct gprs_ns_ie_ip6_elem *) TLVP_VAL(tp, NS_IE_IPv6_LIST);
		num_v6 = TLVP_LEN(tp, NS_IE_IPv6_LIST) / sizeof(*v6_list);
		for (i = 0; i < num_v6; i++) {
			unsigned int j;
			rc = do_sns_add(fi, NULL, &v6_list[i]);
			if (rc < 0) {
				/* rollback/undo to restore previous state */
				for (j = 0; j < i; j++)
					do_sns_delete(fi, NULL, &v6_list[j]);
				cause = -rc;
				ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
				break;
			}
		}
	}

	/* TODO: correct behaviour is to answer to the *same* NSVC from which the SNS_ADD was received */
	ns2_tx_sns_ack(gss->sns_nsvc, trans_id, NULL, v4_list, num_v4, v6_list, num_v6);
}

static void ns2_sns_st_configured_delete(struct osmo_fsm_inst *fi,
					 struct ns2_sns_state *gss,
					 struct tlv_parsed *tp)
{
	const struct gprs_ns_ie_ip4_elem *v4_list = NULL;
	const struct gprs_ns_ie_ip6_elem *v6_list = NULL;
	int num_v4 = 0, num_v6 = 0;
	uint8_t trans_id, cause = 0xff;
	unsigned int i;
	int rc = 0;

	/* TODO: split up delete into v4 + v6
	 * TODO: check if IPv4_LIST or IP_ADDR(v4) is present on IPv6 and vice versa
	 * TODO: check if IPv4_LIST/IPv6_LIST and IP_ADDR is present at the same time
	 */
	trans_id = *TLVP_VAL(tp, NS_IE_TRANS_ID);
	if (gss->ip == IPv4) {
		if (TLVP_PRESENT(tp, NS_IE_IPv4_LIST)) {
			v4_list = (const struct gprs_ns_ie_ip4_elem *) TLVP_VAL(tp, NS_IE_IPv4_LIST);
			num_v4 = TLVP_LEN(tp, NS_IE_IPv4_LIST) / sizeof(*v4_list);
			for ( i = 0; i < num_v4; i++) {
				rc = do_sns_delete(fi, &v4_list[i], NULL);
				if (rc < 0) {
					cause = -rc;
					/* continue to delete others */
				}
			}
			if (cause != 0xff) {
				/* TODO: create list of not-deleted and return it */
				ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
				return;
			}

		} else if (TLVP_PRESENT(tp, NS_IE_IP_ADDR) && TLVP_LEN(tp, NS_IE_IP_ADDR) == 5) {
			/* delete all NS-VCs for given IPv4 address */
			const uint8_t *ie = TLVP_VAL(tp, NS_IE_IP_ADDR);
			struct gprs_ns_ie_ip4_elem *ip4_remote;
			uint32_t ip_addr = *(uint32_t *)(ie+1);
			if (ie[0] != 0x01) { /* Address Type != IPv4 */
				cause = NS_CAUSE_UNKN_IP_ADDR;
				ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
				return;
			}
			/* make a copy as do_sns_delete() will change the array underneath us */
			ip4_remote = talloc_memdup(fi, gss->ip4_remote,
						   gss->num_ip4_remote * sizeof(*v4_list));
			for (i = 0; i < gss->num_ip4_remote; i++) {
				if (ip4_remote[i].ip_addr == ip_addr) {
					rc = do_sns_delete(fi, &ip4_remote[i], NULL);
					if (rc < 0) {
						cause = -rc;
						/* continue to delete others */
					}
				}
			}
			talloc_free(ip4_remote);
			if (cause != 0xff) {
				/* TODO: create list of not-deleted and return it */
				ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
				return;
			}
		} else {
			cause = NS_CAUSE_INVAL_NR_IPv4_EP;
			ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
			return;
		}
	} else { /* IPv6 */
		if (TLVP_PRESENT(tp, NS_IE_IPv6_LIST)) {
			v6_list = (const struct gprs_ns_ie_ip6_elem *) TLVP_VAL(tp, NS_IE_IPv6_LIST);
			num_v6 = TLVP_LEN(tp, NS_IE_IPv6_LIST) / sizeof(*v6_list);
			for (i = 0; i < num_v6; i++) {
				rc = do_sns_delete(fi, NULL, &v6_list[i]);
				if (rc < 0) {
					cause = -rc;
					/* continue to delete others */
				}
			}
			if (cause != 0xff) {
				/* TODO: create list of not-deleted and return it */
				ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
				return;
			}
		} else if (TLVP_PRES_LEN(tp, NS_IE_IP_ADDR, 17)) {
			/* delete all NS-VCs for given IPv4 address */
			const uint8_t *ie = TLVP_VAL(tp, NS_IE_IP_ADDR);
			struct gprs_ns_ie_ip6_elem *ip6_remote;
			struct in6_addr ip6_addr;
			unsigned int i;
			if (ie[0] != 0x02) { /* Address Type != IPv6 */
				cause = NS_CAUSE_UNKN_IP_ADDR;
				ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
				return;
			}
			memcpy(&ip6_addr, (ie+1), sizeof(struct in6_addr));
			/* make a copy as do_sns_delete() will change the array underneath us */
			ip6_remote = talloc_memdup(fi, gss->ip6_remote,
						   gss->num_ip6_remote * sizeof(*v4_list));
			for (i = 0; i < gss->num_ip6_remote; i++) {
				if (!memcmp(&ip6_remote[i].ip_addr, &ip6_addr, sizeof(struct in6_addr))) {
					rc = do_sns_delete(fi, NULL, &ip6_remote[i]);
					if (rc < 0) {
						cause = -rc;
						/* continue to delete others */
					}
				}
			}

			talloc_free(ip6_remote);
			if (cause != 0xff) {
				/* TODO: create list of not-deleted and return it */
				ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
				return;
			}
		} else {
			cause = NS_CAUSE_INVAL_NR_IPv6_EP;
			ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
			return;
		}
	}
	ns2_tx_sns_ack(gss->sns_nsvc, trans_id, NULL, v4_list, num_v4, v6_list, num_v6);
}

static void ns2_sns_st_configured_change(struct osmo_fsm_inst *fi,
					 struct ns2_sns_state *gss,
					 struct tlv_parsed *tp)
{
	const struct gprs_ns_ie_ip4_elem *v4_list = NULL;
	const struct gprs_ns_ie_ip6_elem *v6_list = NULL;
	int num_v4 = 0, num_v6 = 0;
	uint8_t trans_id, cause = 0xff;
	int rc = 0;
	unsigned int i;

	trans_id = *TLVP_VAL(tp, NS_IE_TRANS_ID);
	if (TLVP_PRESENT(tp, NS_IE_IPv4_LIST)) {
		v4_list = (const struct gprs_ns_ie_ip4_elem *) TLVP_VAL(tp, NS_IE_IPv4_LIST);
		num_v4 = TLVP_LEN(tp, NS_IE_IPv4_LIST) / sizeof(*v4_list);
		for (i = 0; i < num_v4; i++) {
			rc = do_sns_change_weight(fi, &v4_list[i], NULL);
			if (rc < 0) {
				cause = -rc;
				/* continue to others */
			}
		}
		if (cause != 0xff) {
			ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
			return;
		}
	} else if (TLVP_PRESENT(tp, NS_IE_IPv6_LIST)) {
		v6_list = (const struct gprs_ns_ie_ip6_elem *) TLVP_VAL(tp, NS_IE_IPv6_LIST);
		num_v6 = TLVP_LEN(tp, NS_IE_IPv6_LIST) / sizeof(*v6_list);
		for (i = 0; i < num_v6; i++) {
			rc = do_sns_change_weight(fi, NULL, &v6_list[i]);
			if (rc < 0) {
				cause = -rc;
				/* continue to others */
			}
		}
		if (cause != 0xff) {
			ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
			return;
		}
	} else {
		cause = NS_CAUSE_INVAL_NR_IPv4_EP;
		ns2_tx_sns_ack(gss->sns_nsvc, trans_id, &cause, NULL, 0, NULL, 0);
		return;
	}
	ns2_tx_sns_ack(gss->sns_nsvc, trans_id, NULL, v4_list, num_v4, v6_list, num_v6);
}

static void ns2_sns_st_configured(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct tlv_parsed *tp = data;

	switch (event) {
	case GPRS_SNS_EV_ADD:
		ns2_sns_st_configured_add(fi, gss, tp);
		break;
	case GPRS_SNS_EV_DELETE:
		ns2_sns_st_configured_delete(fi, gss, tp);
		break;
	case GPRS_SNS_EV_CHANGE_WEIGHT:
		ns2_sns_st_configured_change(fi, gss, tp);
		break;
	}
}

static void ns2_sns_st_configured_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	ns2_prim_status_ind(nse, NULL, 0, NS_AFF_CAUSE_SNS_CONFIGURED);
}

static const struct osmo_fsm_state ns2_sns_bss_states[] = {
	[GPRS_SNS_ST_UNCONFIGURED] = {
		.in_event_mask = 0,
		.out_state_mask = S(GPRS_SNS_ST_SIZE),
		.name = "UNCONFIGURED",
		.action = ns2_sns_st_unconfigured,
	},
	[GPRS_SNS_ST_SIZE] = {
		.in_event_mask = S(GPRS_SNS_EV_SIZE_ACK),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_SIZE) |
				  S(GPRS_SNS_ST_CONFIG_BSS),
		.name = "SIZE",
		.action = ns2_sns_st_size,
		.onenter = ns2_sns_st_size_onenter,
	},
	[GPRS_SNS_ST_CONFIG_BSS] = {
		.in_event_mask = S(GPRS_SNS_EV_CONFIG_ACK),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_CONFIG_BSS) |
				  S(GPRS_SNS_ST_CONFIG_SGSN) |
				  S(GPRS_SNS_ST_SIZE),
		.name = "CONFIG_BSS",
		.action = ns2_sns_st_config_bss,
		.onenter = ns2_sns_st_config_bss_onenter,
	},
	[GPRS_SNS_ST_CONFIG_SGSN] = {
		.in_event_mask = S(GPRS_SNS_EV_CONFIG) |
				 S(GPRS_SNS_EV_CONFIG_END),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_CONFIG_SGSN) |
				  S(GPRS_SNS_ST_CONFIGURED) |
				  S(GPRS_SNS_ST_SIZE),
		.name = "CONFIG_SGSN",
		.action = ns2_sns_st_config_sgsn,
	},
	[GPRS_SNS_ST_CONFIGURED] = {
		.in_event_mask = S(GPRS_SNS_EV_ADD) |
				 S(GPRS_SNS_EV_DELETE) |
				 S(GPRS_SNS_EV_CHANGE_WEIGHT),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_SIZE),
		.name = "CONFIGURED",
		.action = ns2_sns_st_configured,
		.onenter = ns2_sns_st_configured_onenter,
	},
};

static int ns2_sns_fsm_bss_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct gprs_ns2_inst *nsi = nse->nsi;

	switch (fi->T) {
	case 1:
		osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_SIZE, nsi->timeout[NS_TOUT_TSNS_PROV], 1);
		break;
	case 2:
		osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_CONFIG_BSS, nsi->timeout[NS_TOUT_TSNS_PROV], 2);
		break;
	}
	return 0;
}

static void ns2_sns_st_all_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);

	/* reset when receiving GPRS_SNS_EV_NO_NSVC */
	switch (event) {
	case GPRS_SNS_EV_NO_NSVC:
		if (!gss->reselection_running)
			osmo_fsm_inst_dispatch(fi, GPRS_SNS_EV_SELECT_ENDPOINT, NULL);
		break;
	case GPRS_SNS_EV_SELECT_ENDPOINT:
		/* tear down previous state
		 * gprs_ns2_free_nsvcs() will trigger NO_NSVC, prevent this from triggering a reselection */
		gss->reselection_running = true;
		gprs_ns2_free_nsvcs(nse);

		/* Choose the next sns endpoint. */
		if (llist_empty(&gss->sns_endpoints)) {
			gss->initial = NULL;
			ns2_prim_status_ind(gss->nse, NULL, 0, NS_AFF_CAUSE_SNS_NO_ENDPOINTS);
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 3);
			return;
		} else if (!gss->initial) {
			gss->initial = llist_first_entry(&gss->sns_endpoints, struct sns_endpoint, list);
			gss->bind_offset = 0;
		} else if (gss->initial->list.next == &gss->sns_endpoints) {
			/* last entry, continue with first */
			gss->initial = llist_first_entry(&gss->sns_endpoints, struct sns_endpoint, list);
			gss->bind_offset++;
			gss->bind_offset %= ns2_ip_count_bind(nse->nsi, &gss->initial->saddr);
		} else {
			/* next element is an entry */
			gss->initial = llist_entry(gss->initial->list.next, struct sns_endpoint, list);
		}

		gss->reselection_running = false;
		osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_SIZE, nse->nsi->timeout[NS_TOUT_TSNS_PROV], 1);
		break;
	}
}

static struct osmo_fsm gprs_ns2_sns_bss_fsm = {
	.name = "GPRS-NS2-SNS-BSS",
	.states = ns2_sns_bss_states,
	.num_states = ARRAY_SIZE(ns2_sns_bss_states),
	.allstate_event_mask = S(GPRS_SNS_EV_NO_NSVC) |
			       S(GPRS_SNS_EV_SELECT_ENDPOINT),
	.allstate_action = ns2_sns_st_all_action,
	.cleanup = NULL,
	.timer_cb = ns2_sns_fsm_bss_timer_cb,
	/* .log_subsys = DNS, "is not constant" */
	.event_names = gprs_sns_event_names,
	.pre_term = NULL,
	.log_subsys = DLNS,
};

/*! Allocate an IP-SNS FSM for the BSS side.
 *  \param[in] nse NS Entity in which the FSM runs
 *  \param[in] id string identifier
 *  \retruns FSM instance on success; NULL on error */
struct osmo_fsm_inst *ns2_sns_bss_fsm_alloc(struct gprs_ns2_nse *nse,
					    const char *id)
{
	struct osmo_fsm_inst *fi;
	struct ns2_sns_state *gss;

	fi = osmo_fsm_inst_alloc(&gprs_ns2_sns_bss_fsm, nse, NULL, LOGL_DEBUG, id);
	if (!fi)
		return fi;

	gss = talloc_zero(fi, struct ns2_sns_state);
	if (!gss)
		goto err;

	fi->priv = gss;
	gss->nse = nse;
	INIT_LLIST_HEAD(&gss->sns_endpoints);

	return fi;
err:
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
	return NULL;
}

/*! main entry point for receiving SNS messages from the network.
 *  \param[in] nsvc NS-VC on which the message was received
 *  \param[in] msg message buffer of the IP-SNS message
 *  \param[in] tp parsed TLV structure of message
 *  \retruns 0 on success; negative on error */
int gprs_ns2_sns_rx(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp)
{
	struct gprs_ns2_nse *nse = nsvc->nse;
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	uint16_t nsei = nsvc->nse->nsei;
	struct osmo_fsm_inst *fi;

	if (!nse->bss_sns_fi) {
		LOGP(DLNS, LOGL_NOTICE, "NSEI=%u Rx %s for NS Instance that has no SNS!\n",
		     nsvc->nse->nsei, get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));
		return -EINVAL;
	}

	LOGP(DLNS, LOGL_DEBUG, "NSEI=%u Rx SNS PDU type %s\n", nsei,
		get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));

	/* FIXME: how to resolve SNS FSM Instance by NSEI (SGSN)? */
	fi = nse->bss_sns_fi;

	switch (nsh->pdu_type) {
	case SNS_PDUT_SIZE:
		osmo_fsm_inst_dispatch(fi, GPRS_SNS_EV_SIZE, tp);
		break;
	case SNS_PDUT_SIZE_ACK:
		osmo_fsm_inst_dispatch(fi, GPRS_SNS_EV_SIZE_ACK, tp);
		break;
	case SNS_PDUT_CONFIG:
		if (nsh->data[0] & 0x01)
			osmo_fsm_inst_dispatch(fi, GPRS_SNS_EV_CONFIG_END, tp);
		else
			osmo_fsm_inst_dispatch(fi, GPRS_SNS_EV_CONFIG, tp);
		break;
	case SNS_PDUT_CONFIG_ACK:
		osmo_fsm_inst_dispatch(fi, GPRS_SNS_EV_CONFIG_ACK, tp);
		break;
	case SNS_PDUT_ADD:
		osmo_fsm_inst_dispatch(fi, GPRS_SNS_EV_ADD, tp);
		break;
	case SNS_PDUT_DELETE:
		osmo_fsm_inst_dispatch(fi, GPRS_SNS_EV_DELETE, tp);
		break;
	case SNS_PDUT_CHANGE_WEIGHT:
		osmo_fsm_inst_dispatch(fi, GPRS_SNS_EV_CHANGE_WEIGHT, tp);
		break;
	case SNS_PDUT_ACK:
		LOGP(DLNS, LOGL_NOTICE, "NSEI=%u Rx unsupported SNS PDU type %s\n", nsei,
			get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));
		break;
	default:
		LOGP(DLNS, LOGL_ERROR, "NSEI=%u Rx unknown SNS PDU type %s\n", nsei,
			get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));
		return -EINVAL;
	}

	return 0;
}

#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>

static void vty_dump_sns_ip4(struct vty *vty, const struct gprs_ns_ie_ip4_elem *ip4)
{
	struct in_addr in = { .s_addr = ip4->ip_addr };
	vty_out(vty, " %s:%u, Signalling Weight: %u, Data Weight: %u%s",
		inet_ntoa(in), ntohs(ip4->udp_port), ip4->sig_weight, ip4->data_weight, VTY_NEWLINE);
}

static void vty_dump_sns_ip6(struct vty *vty, const struct gprs_ns_ie_ip6_elem *ip6)
{
	char ip_addr[INET6_ADDRSTRLEN] = {};
	if (!inet_ntop(AF_INET6, &ip6->ip_addr, ip_addr, (INET6_ADDRSTRLEN)))
		strcpy(ip_addr, "Invalid IPv6");

	vty_out(vty, " %s:%u, Signalling Weight: %u, Data Weight: %u%s",
		ip_addr, ntohs(ip6->udp_port), ip6->sig_weight, ip6->data_weight, VTY_NEWLINE);
}

/*! Dump the IP-SNS state to a vty.
 *  \param[in] vty VTY to which the state shall be printed
 *  \param[in] nse NS Entity whose IP-SNS state shall be printed
 *  \param[in] stats Whether or not statistics shall also be printed */
void gprs_ns2_sns_dump_vty(struct vty *vty, const struct gprs_ns2_nse *nse, bool stats)
{
	struct ns2_sns_state *gss;
	unsigned int i;

	if (!nse->bss_sns_fi)
		return;

	vty_out_fsm_inst(vty, nse->bss_sns_fi);
	gss = (struct ns2_sns_state *) nse->bss_sns_fi->priv;

	vty_out(vty, "Maximum number of remote  NS-VCs: %zu, IPv4 Endpoints: %zu, IPv6 Endpoints: %zu%s",
		gss->num_max_nsvcs, gss->num_max_ip4_remote, gss->num_max_ip6_remote, VTY_NEWLINE);

	if (gss->num_ip4_local && gss->num_ip4_remote) {
		vty_out(vty, "Local IPv4 Endpoints:%s", VTY_NEWLINE);
		for (i = 0; i < gss->num_ip4_local; i++)
			vty_dump_sns_ip4(vty, &gss->ip4_local[i]);

		vty_out(vty, "Remote IPv4 Endpoints:%s", VTY_NEWLINE);
		for (i = 0; i < gss->num_ip4_remote; i++)
			vty_dump_sns_ip4(vty, &gss->ip4_remote[i]);
	}

	if (gss->num_ip6_local && gss->num_ip6_remote) {
		vty_out(vty, "Local IPv6 Endpoints:%s", VTY_NEWLINE);
		for (i = 0; i < gss->num_ip6_local; i++)
			vty_dump_sns_ip6(vty, &gss->ip6_local[i]);

		vty_out(vty, "Remote IPv6 Endpoints:%s", VTY_NEWLINE);
		for (i = 0; i < gss->num_ip6_remote; i++)
			vty_dump_sns_ip6(vty, &gss->ip6_remote[i]);
	}
}

static struct sns_endpoint *ns2_get_sns_endpoint(struct ns2_sns_state *state,
						 const struct osmo_sockaddr *saddr)
{
	struct sns_endpoint *endpoint;

	llist_for_each_entry(endpoint, &state->sns_endpoints, list) {
		if (!osmo_sockaddr_cmp(saddr, &endpoint->saddr))
			return endpoint;
	}

	return NULL;
}

/*! gprs_ns2_sns_add_endpoint
 *  \param[in] nse
 *  \param[in] sockaddr
 *  \return
 */
int gprs_ns2_sns_add_endpoint(struct gprs_ns2_nse *nse,
			      const struct osmo_sockaddr *saddr)
{
	struct ns2_sns_state *gss;
	struct sns_endpoint *endpoint;
	bool do_selection = false;

	if (nse->ll != GPRS_NS2_LL_UDP) {
		return -EINVAL;
	}

	if (nse->dialect != NS2_DIALECT_SNS) {
		return -EINVAL;
	}

	gss = nse->bss_sns_fi->priv;

	if (ns2_get_sns_endpoint(gss, saddr))
		return -EADDRINUSE;

	endpoint = talloc_zero(nse->bss_sns_fi->priv, struct sns_endpoint);
	if (!endpoint)
		return -ENOMEM;

	endpoint->saddr = *saddr;
	if (llist_empty(&gss->sns_endpoints))
		do_selection = true;

	llist_add_tail(&endpoint->list, &gss->sns_endpoints);
	if (do_selection)
		osmo_fsm_inst_dispatch(nse->bss_sns_fi, GPRS_SNS_EV_SELECT_ENDPOINT, NULL);

	return 0;
}

/*! gprs_ns2_sns_del_endpoint
 *  \param[in] nse
 *  \param[in] sockaddr
 *  \return 0 on success, otherwise < 0
 */
int gprs_ns2_sns_del_endpoint(struct gprs_ns2_nse *nse,
			      const struct osmo_sockaddr *saddr)
{
	struct ns2_sns_state *gss;
	struct sns_endpoint *endpoint;

	if (nse->ll != GPRS_NS2_LL_UDP) {
		return -EINVAL;
	}

	if (nse->dialect != NS2_DIALECT_SNS) {
		return -EINVAL;
	}

	gss = nse->bss_sns_fi->priv;
	endpoint = ns2_get_sns_endpoint(gss, saddr);
	if (!endpoint)
		return -ENOENT;

	/* if this is an unused SNS endpoint it's done */
	if (gss->initial != endpoint) {
		llist_del(&endpoint->list);
		talloc_free(endpoint);
		return 0;
	}

	/* gprs_ns2_free_nsvcs() will trigger GPRS_SNS_EV_NO_NSVC on the last NS-VC
	 * and restart SNS SIZE procedure which selects a new initial */
	LOGP(DLNS, LOGL_INFO, "Current in-use SNS endpoint is being removed."
			      "Closing all NS-VC and restart SNS-SIZE procedure"
			      "with a remaining SNS endpoint.\n");

	/* Continue with the next endpoint in the list.
	 * Special case if the endpoint is at the start or end of the list */
	if (endpoint->list.prev == &gss->sns_endpoints ||
			endpoint->list.next == &gss->sns_endpoints)
		gss->initial = NULL;
	else
		gss->initial = llist_entry(endpoint->list.next->prev,
					    struct sns_endpoint,
					    list);

	llist_del(&endpoint->list);
	gprs_ns2_free_nsvcs(nse);
	talloc_free(endpoint);

	return 0;
}

/*! gprs_ns2_sns_count
 *  \param[in] nse NS Entity whose IP-SNS endpoints shall be printed
 *  \return the count of endpoints or < 0 if NSE doesn't contain sns.
 */
int gprs_ns2_sns_count(struct gprs_ns2_nse *nse)
{
	struct ns2_sns_state *gss;
	struct sns_endpoint *endpoint;
	int count = 0;

	if (nse->ll != GPRS_NS2_LL_UDP) {
		return -EINVAL;
	}

	if (nse->dialect != NS2_DIALECT_SNS) {
		return -EINVAL;
	}

	gss = nse->bss_sns_fi->priv;
	llist_for_each_entry(endpoint, &gss->sns_endpoints, list)
		count++;

	return count;
}

/* initialize osmo_ctx on main tread */
static __attribute__((constructor)) void on_dso_load_ctx(void)
{
	OSMO_ASSERT(osmo_fsm_register(&gprs_ns2_sns_bss_fsm) == 0);
}
