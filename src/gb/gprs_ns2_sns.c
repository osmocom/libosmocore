/*! \file gprs_ns2_sns.c
 * NS Sub-Network Service Protocol implementation
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05)
 * as well as its successor 3GPP TS 48.016 */

/* (C) 2018-2021 by Harald Welte <laforge@gnumonks.org>
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
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/protocol/gsm_08_16.h>

#include "gprs_ns2_internal.h"

#define S(x)	(1 << (x))

enum ns2_sns_role {
	GPRS_SNS_ROLE_BSS,
	GPRS_SNS_ROLE_SGSN,
};

/* BSS-side-only states _ST_BSS_; SGSN-side only states _ST_SGSN_; others shared */
enum gprs_sns_bss_state {
	GPRS_SNS_ST_UNCONFIGURED,
	GPRS_SNS_ST_BSS_SIZE,			/*!< SNS-SIZE procedure ongoing */
	GPRS_SNS_ST_BSS_CONFIG_BSS,		/*!< SNS-CONFIG procedure (BSS->SGSN) ongoing */
	GPRS_SNS_ST_BSS_CONFIG_SGSN,		/*!< SNS-CONFIG procedure (SGSN->BSS) ongoing */
	GPRS_SNS_ST_CONFIGURED,
	GPRS_SNS_ST_SGSN_WAIT_CONFIG,		/* !< SGSN role: Wait for CONFIG from BSS */
	GPRS_SNS_ST_SGSN_WAIT_CONFIG_ACK,	/* !< SGSN role: Wait for CONFIG-ACK from BSS */
	GPRS_SNS_ST_LOCAL_PROCEDURE,		/*!< in process of a ADD/DEL/CHANGE procedure towards SGSN (BSS->SGSN) */
};

static const struct value_string gprs_sns_event_names[] = {
	{ NS2_SNS_EV_REQ_SELECT_ENDPOINT,	"REQ_SELECT_ENDPOINT" },
	{ NS2_SNS_EV_RX_SIZE,			"RX_SIZE" },
	{ NS2_SNS_EV_RX_SIZE_ACK,		"RX_SIZE_ACK" },
	{ NS2_SNS_EV_RX_CONFIG,		"RX_CONFIG" },
	{ NS2_SNS_EV_RX_CONFIG_END,		"RX_CONFIG_END" },
	{ NS2_SNS_EV_RX_CONFIG_ACK,		"RX_CONFIG_ACK" },
	{ NS2_SNS_EV_RX_ADD,	    		"RX_ADD" },
	{ NS2_SNS_EV_RX_DELETE,		"RX_DELETE" },
	{ NS2_SNS_EV_RX_ACK,			"RX_ACK" },
	{ NS2_SNS_EV_RX_CHANGE_WEIGHT,		"RX_CHANGE_WEIGHT" },
	{ NS2_SNS_EV_REQ_NO_NSVC,		"REQ_NO_NSVC" },
	{ NS2_SNS_EV_REQ_FREE_NSVCS,		"REQ_FREE_NSVCS" },
	{ NS2_SNS_EV_REQ_NSVC_ALIVE,		"REQ_NSVC_ALIVE"},
	{ NS2_SNS_EV_REQ_ADD_BIND,		"REQ_ADD_BIND"},
	{ NS2_SNS_EV_REQ_DELETE_BIND,		"REQ_DELETE_BIND"},
	{ NS2_SNS_EV_REQ_CHANGE_WEIGHT,	"REQ_CHANGE_WEIGHT"},
	{ 0, NULL }
};

#define GPRS_SNS_FLAG_KEEP_SELECT_ENDPOINT_ORDER (void *) 1

enum sns_procedure {
	SNS_PROC_NONE,		/*!< used as invalid/idle value */
	SNS_PROC_ADD,
	SNS_PROC_DEL,
	SNS_PROC_CHANGE_WEIGHT,
};

struct sns_endpoint {
	struct llist_head list;
	struct osmo_sockaddr saddr;
};

struct ns2_sns_bind {
	struct llist_head list;
	struct gprs_ns2_vc_bind *bind;
	uint8_t change_weight_state;
};

struct ns2_sns_procedure {
       struct llist_head list;
       struct ns2_sns_bind *sbind;
       uint16_t sig_weight;
       uint16_t data_weight;
       /* copy entry to protect against changes of gss->local */
       struct gprs_ns_ie_ip4_elem ip4;
       struct gprs_ns_ie_ip6_elem ip6;
       enum sns_procedure procedure;
       uint8_t trans_id;
       /* is the procedure in process */
       bool running;
};

struct ns2_sns_elems {
	struct gprs_ns_ie_ip4_elem *ip4;
	unsigned int num_ip4;
	struct gprs_ns_ie_ip6_elem *ip6;
	unsigned int num_ip6;
};

struct ns2_sns_state {
	struct gprs_ns2_nse *nse;

	/* containing the address family AF_* */
	int family;
	enum ns2_sns_role role;		/* local role: BSS or SGSN */

	/* holds the list of initial SNS endpoints */
	struct llist_head sns_endpoints;
	/* list of used struct ns2_sns_bind  */
	struct llist_head binds;
	/* pointer to the bind which was used to initiate the SNS connection */
	struct ns2_sns_bind *initial_bind;
	/* prevent recursive reselection */
	bool reselection_running;

	/* protection against recursive free() */
	bool block_no_nsvc_events;

	/* The current initial SNS endpoints.
	 * The initial connection will be moved into the NSE
	 * if configured via SNS. Otherwise it will be removed
	 * in configured state. */
	struct sns_endpoint *initial;
	/* all SNS PDU will be sent over this nsvc */
	struct gprs_ns2_vc *sns_nsvc;
	/* timer N */
	int N;
	/* true if at least one nsvc is alive */
	bool alive;

	/* local configuration to send to the remote end */
	struct ns2_sns_elems local;

	/* local configuration after all local procedures applied */
	struct ns2_sns_elems local_procedure;

	/* remote configuration as received */
	struct ns2_sns_elems remote;

	/* local configuration about our capabilities in terms of connections to
	 * remote (SGSN) side */
	size_t num_max_nsvcs;
	size_t num_max_ip4_remote;
	size_t num_max_ip6_remote;

	struct llist_head procedures;
	struct ns2_sns_procedure *current_procedure;
	uint8_t trans_id;
};

static inline struct gprs_ns2_nse *nse_inst_from_fi(struct osmo_fsm_inst *fi)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	return gss->nse;
}

/* The SNS has failed. Etither restart the SNS (BSS) or remove the SNS (SGSN) */
#define sns_failed(fi, reason) \
	_sns_failed(fi, reason, __FILE__, __LINE__)
static void _sns_failed(struct osmo_fsm_inst *fi, const char *reason, const char *file, int line)
{
	struct ns2_sns_state *gss = fi->priv;

	if (reason)
		LOGPFSMLSRC(fi, LOGL_ERROR, file, line, "NSE %d: SNS failed: %s\n", gss->nse->nsei, reason);

	gss->alive = false;
	if (gss->role == GPRS_SNS_ROLE_SGSN) {
		if (!gss->nse->persistent)
			gprs_ns2_free_nse(gss->nse);
		else
			_osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 0, file, line);
	} else {
		_osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_REQ_SELECT_ENDPOINT, NULL, file, line);
	}
}

/* helper function to compute the sum of all (data or signaling) weights */
static int ip4_weight_sum(const struct ns2_sns_elems *elems, bool data_weight)
{
	unsigned int i;
	int weight_sum = 0;

	for (i = 0; i < elems->num_ip4; i++) {
		if (data_weight)
			weight_sum += elems->ip4[i].data_weight;
		else
			weight_sum += elems->ip4[i].sig_weight;
	}
	return weight_sum;
}
#define ip4_weight_sum_data(elems)		ip4_weight_sum(elems, true)
#define ip4_weight_sum_sig(elems)		ip4_weight_sum(elems, false)

/* helper function to compute the sum of all (data or signaling) weights */
static int ip6_weight_sum(const struct ns2_sns_elems *elems, bool data_weight)
{
	unsigned int i;
	int weight_sum = 0;

	for (i = 0; i < elems->num_ip6; i++) {
		if (data_weight)
			weight_sum += elems->ip6[i].data_weight;
		else
			weight_sum += elems->ip6[i].sig_weight;
	}
	return weight_sum;
}
#define ip6_weight_sum_data(elems)		ip6_weight_sum(elems, true)
#define ip6_weight_sum_sig(elems)		ip6_weight_sum(elems, false)

static int ip46_weight_sum(const struct ns2_sns_elems *elems, bool data_weight)
{
	return ip4_weight_sum(elems, data_weight) +
	       ip6_weight_sum(elems, data_weight);
}
#define ip46_weight_sum_data(elems)		ip46_weight_sum(elems, true)
#define ip46_weight_sum_sig(elems)		ip46_weight_sum(elems, false)

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

/*! called when a nsvc is beeing freed or the nsvc became dead */
void ns2_sns_replace_nsvc(struct gprs_ns2_vc *nsvc)
{
	struct gprs_ns2_nse *nse = nsvc->nse;
	struct gprs_ns2_vc *tmp;
	struct osmo_fsm_inst *fi = nse->bss_sns_fi;
	struct ns2_sns_state *gss;

	if (!fi)
		return;

	gss = (struct ns2_sns_state *) fi->priv;
	if (nsvc != gss->sns_nsvc)
		return;

	gss->sns_nsvc = NULL;
	if (gss->alive) {
		llist_for_each_entry(tmp, &nse->nsvc, list) {
			if (ns2_vc_is_unblocked(tmp)) {
				gss->sns_nsvc = tmp;
				return;
			}
		}
	} else {
		/* the SNS is waiting for its first NS-VC to come up
		 * choose any other nsvc */
		llist_for_each_entry(tmp, &nse->nsvc, list) {
			if (nsvc != tmp) {
				gss->sns_nsvc = tmp;
				return;
			}
		}
	}

	if (gss->block_no_nsvc_events)
		osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_REQ_NO_NSVC, NULL);
}

static void ns2_clear_elems(struct ns2_sns_elems *elems)
{
	TALLOC_FREE(elems->ip4);
	TALLOC_FREE(elems->ip6);

	elems->num_ip4 = 0;
	elems->num_ip6 = 0;
}

static void ns2_clear_procedures(struct ns2_sns_state *gss)
{
	struct ns2_sns_procedure *procedure, *tmp;
	gss->current_procedure = NULL;
	llist_for_each_entry_safe(procedure, tmp, &gss->procedures, list) {
		llist_del(&procedure->list);
		talloc_free(procedure);
	}
}

static void ns2_vc_create_ip(struct osmo_fsm_inst *fi, struct gprs_ns2_nse *nse, const struct osmo_sockaddr *remote,
			     uint8_t sig_weight, uint8_t data_weight)
{
	struct gprs_ns2_inst *nsi = nse->nsi;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_vc_bind *bind;

	/* for every bind, create a connection if bind type == IP */
	llist_for_each_entry(bind, &nsi->binding, list) {
		if (bind->ll != GPRS_NS2_LL_UDP)
			continue;
		/* ignore failed connection */
		nsvc = gprs_ns2_ip_connect_inactive(bind,
					   remote,
					   nse, 0);
		if (!nsvc) {
			LOGPFSML(fi, LOGL_ERROR, "SNS-CONFIG: Failed to create NSVC\n");
			continue;
		}

		nsvc->sig_weight = sig_weight;
		nsvc->data_weight = data_weight;
	}
}

static void ns2_nsvc_create_ip4(struct osmo_fsm_inst *fi,
				 struct gprs_ns2_nse *nse,
				 const struct gprs_ns_ie_ip4_elem *ip4)
{
	struct osmo_sockaddr remote = { };
	/* copy over. Both data structures use network byte order */
	remote.u.sin.sin_family = AF_INET;
	remote.u.sin.sin_addr.s_addr = ip4->ip_addr;
	remote.u.sin.sin_port = ip4->udp_port;

	ns2_vc_create_ip(fi, nse, &remote, ip4->sig_weight, ip4->data_weight);
}

static void ns2_nsvc_create_ip6(struct osmo_fsm_inst *fi,
				 struct gprs_ns2_nse *nse,
				 const struct gprs_ns_ie_ip6_elem *ip6)
{
	struct osmo_sockaddr remote = {};
	/* copy over. Both data structures use network byte order */
	remote.u.sin6.sin6_family = AF_INET6;
	remote.u.sin6.sin6_addr = ip6->ip_addr;
	remote.u.sin6.sin6_port = ip6->udp_port;

	ns2_vc_create_ip(fi, nse, &remote, ip6->sig_weight, ip6->data_weight);
}

static struct gprs_ns2_vc *nsvc_for_bind_and_remote(struct gprs_ns2_nse *nse,
						    struct gprs_ns2_vc_bind *bind,
						    const struct osmo_sockaddr *remote)
{
	struct gprs_ns2_vc *nsvc;

	llist_for_each_entry(nsvc, &nse->nsvc, list) {
		if (nsvc->bind != bind)
			continue;

		if (!osmo_sockaddr_cmp(remote, gprs_ns2_ip_vc_remote(nsvc)))
			return nsvc;
	}
	return NULL;
}

static int create_missing_nsvcs(struct osmo_fsm_inst *fi)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct gprs_ns2_vc *nsvc;
	struct ns2_sns_bind *sbind;
	struct osmo_sockaddr remote = { };
	unsigned int i;

	/* iterate over all remote IPv4 endpoints */
	for (i = 0; i < gss->remote.num_ip4; i++) {
		const struct gprs_ns_ie_ip4_elem *ip4 = &gss->remote.ip4[i];

		remote.u.sin.sin_family = AF_INET;
		remote.u.sin.sin_addr.s_addr = ip4->ip_addr;
		remote.u.sin.sin_port = ip4->udp_port;

		/* iterate over all local binds within this SNS */
		llist_for_each_entry(sbind, &gss->binds, list) {
			struct gprs_ns2_vc_bind *bind = sbind->bind;

			/* we only care about UDP binds */
			if (bind->ll != GPRS_NS2_LL_UDP)
				continue;

			nsvc = nsvc_for_bind_and_remote(nse, bind, &remote);
			if (!nsvc) {
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

	/* iterate over all remote IPv4 endpoints */
	for (i = 0; i < gss->remote.num_ip6; i++) {
		const struct gprs_ns_ie_ip6_elem *ip6 = &gss->remote.ip6[i];

		remote.u.sin6.sin6_family = AF_INET6;
		remote.u.sin6.sin6_addr = ip6->ip_addr;
		remote.u.sin6.sin6_port = ip6->udp_port;

		/* iterate over all local binds within this SNS */
		llist_for_each_entry(sbind, &gss->binds, list) {
			struct gprs_ns2_vc_bind *bind = sbind->bind;

			if (bind->ll != GPRS_NS2_LL_UDP)
				continue;

			/* we only care about UDP binds */
			nsvc = nsvc_for_bind_and_remote(nse, bind, &remote);
			if (!nsvc) {
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
static int add_ip4_elem(struct ns2_sns_state *gss, struct ns2_sns_elems *elems,
			const struct gprs_ns_ie_ip4_elem *ip4)
{
	/* check for duplicates */
	for (unsigned int i = 0; i < elems->num_ip4; i++) {
		if (memcmp(&elems->ip4[i], ip4, sizeof(*ip4)))
			continue;
		return -1;
	}

	elems->ip4 = talloc_realloc(gss, elems->ip4, struct gprs_ns_ie_ip4_elem,
					 elems->num_ip4+1);
	elems->ip4[elems->num_ip4] = *ip4;
	elems->num_ip4 += 1;
	return 0;
}

/* Remove a given remote IPv4 element from gprs_sns_state */
static int remove_ip4_elem(struct ns2_sns_state *gss, struct ns2_sns_elems *elems,
			   const struct gprs_ns_ie_ip4_elem *ip4)
{
	unsigned int i;

	for (i = 0; i < elems->num_ip4; i++) {
		if (memcmp(&elems->ip4[i], ip4, sizeof(*ip4)))
			continue;
		/* all array elements < i remain as they are; all > i are shifted left by one */
		memmove(&elems->ip4[i], &elems->ip4[i+1], elems->num_ip4-i-1);
		elems->num_ip4 -= 1;
		return 0;
	}
	return -1;
}

/* update the weights for specified remote IPv4 */
static int update_ip4_elem(struct ns2_sns_state *gss, struct ns2_sns_elems *elems,
			   const struct gprs_ns_ie_ip4_elem *ip4)
{
	unsigned int i;

	for (i = 0; i < elems->num_ip4; i++) {
		if (elems->ip4[i].ip_addr != ip4->ip_addr ||
		    elems->ip4[i].udp_port != ip4->udp_port)
			continue;

		elems->ip4[i].sig_weight = ip4->sig_weight;
		elems->ip4[i].data_weight = ip4->data_weight;
		return 0;
	}
	return -1;
}

/* Add a given remote IPv6 element to gprs_sns_state */
static int add_ip6_elem(struct ns2_sns_state *gss, struct ns2_sns_elems *elems,
			const struct gprs_ns_ie_ip6_elem *ip6)
{
	/* check for duplicates */
	for (unsigned int i = 0; i < elems->num_ip6; i++) {
		if (memcmp(&elems->ip6[i].ip_addr, &ip6->ip_addr, sizeof(ip6->ip_addr)) ||
		    elems->ip6[i].udp_port != ip6->udp_port)
			continue;
		return -1;
	}

	elems->ip6 = talloc_realloc(gss, elems->ip6, struct gprs_ns_ie_ip6_elem,
					 elems->num_ip6+1);
	elems->ip6[elems->num_ip6] = *ip6;
	elems->num_ip6 += 1;
	return 0;
}

/* Remove a given remote IPv6 element from gprs_sns_state */
static int remove_ip6_elem(struct ns2_sns_state *gss, struct ns2_sns_elems *elems,
			   const struct gprs_ns_ie_ip6_elem *ip6)
{
	unsigned int i;

	for (i = 0; i < elems->num_ip6; i++) {
		if (memcmp(&elems->ip6[i], ip6, sizeof(*ip6)))
			continue;
		/* all array elements < i remain as they are; all > i are shifted left by one */
		memmove(&elems->ip6[i], &elems->ip6[i+1], elems->num_ip6-i-1);
		elems->num_ip6 -= 1;
		return 0;
	}
	return -1;
}

/* update the weights for specified remote IPv6 */
static int update_ip6_elem(struct ns2_sns_state *gss, struct ns2_sns_elems *elems,
			   const struct gprs_ns_ie_ip6_elem *ip6)
{
	unsigned int i;

	for (i = 0; i < elems->num_ip6; i++) {
		if (memcmp(&elems->ip6[i].ip_addr, &ip6->ip_addr, sizeof(ip6->ip_addr)) ||
		    elems->ip6[i].udp_port != ip6->udp_port)
			continue;
		elems->ip6[i].sig_weight = ip6->sig_weight;
		elems->ip6[i].data_weight = ip6->data_weight;
		return 0;
	}
	return -1;
}

static int remove_bind_elem(struct ns2_sns_state *gss, struct ns2_sns_elems *elems, struct ns2_sns_bind *sbind)
{
	struct gprs_ns_ie_ip4_elem ip4;
	struct gprs_ns_ie_ip6_elem ip6;
	const struct osmo_sockaddr *saddr = gprs_ns2_ip_bind_sockaddr(sbind->bind);

	switch (saddr->u.sa.sa_family) {
	case AF_INET:
		ip4.ip_addr = saddr->u.sin.sin_addr.s_addr;
		ip4.udp_port = saddr->u.sin.sin_port;
		ip4.sig_weight = sbind->bind->sns_sig_weight;
		ip4.data_weight = sbind->bind->sns_data_weight;
		return remove_ip4_elem(gss, elems, &ip4);
	case AF_INET6:
		memcpy(&ip6.ip_addr, &saddr->u.sin6.sin6_addr, sizeof(struct in6_addr));
		ip6.udp_port = saddr->u.sin.sin_port;
		ip6.sig_weight = sbind->bind->sns_sig_weight;
		ip6.data_weight = sbind->bind->sns_data_weight;
		return remove_ip6_elem(gss, elems, &ip6);
	default:
		return -1;
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
		if (update_ip4_elem(gss, &gss->remote, ip4))
			return -NS_CAUSE_UNKN_IP_EP;

		/* copy over. Both data structures use network byte order */
		sa.u.sin.sin_addr.s_addr = ip4->ip_addr;
		sa.u.sin.sin_port = ip4->udp_port;
		sa.u.sin.sin_family = AF_INET;
		new_signal = ip4->sig_weight;
		new_data = ip4->data_weight;
	} else if (ip6) {
		if (update_ip6_elem(gss, &gss->remote, ip6))
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
		if (remove_ip4_elem(gss, &gss->remote, ip4) < 0)
			return -NS_CAUSE_UNKN_IP_EP;
		/* copy over. Both data structures use network byte order */
		sa.u.sin.sin_addr.s_addr = ip4->ip_addr;
		sa.u.sin.sin_port = ip4->udp_port;
		sa.u.sin.sin_family = AF_INET;
	} else if (ip6) {
		if (remove_ip6_elem(gss, &gss->remote, ip6))
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
	switch (gss->family) {
	case AF_INET:
		if (gss->remote.num_ip4 >= gss->num_max_ip4_remote)
			return -NS_CAUSE_INVAL_NR_NS_VC;
		/* TODO: log message duplicate */
		rc = add_ip4_elem(gss, &gss->remote, ip4);
		break;
	case AF_INET6:
		if (gss->remote.num_ip6 >= gss->num_max_ip6_remote)
			return -NS_CAUSE_INVAL_NR_NS_VC;
		/* TODO: log message duplicate */
		rc = add_ip6_elem(gss, &gss->remote, ip6);
		break;
	default:
		/* the gss->ip is initialized with the bss */
		OSMO_ASSERT(false);
	}

	if (rc)
		return -NS_CAUSE_PROTO_ERR_UNSPEC;

	/* Upon receiving an SNS-ADD PDU containing an already configured IP endpoint the
	 * NSE shall send an SNS-ACK PDU with the cause code "Protocol error -
	 * unspecified" */
	switch (gss->family) {
	case AF_INET:
		nsvc = nsvc_by_ip4_elem(nse, ip4);
		if (nsvc) {
			/* the nsvc should be already in sync with the ip4 / ip6 elements */
			return -NS_CAUSE_PROTO_ERR_UNSPEC;
		}

		/* TODO: failure case */
		ns2_nsvc_create_ip4(fi, nse, ip4);
		break;
	case AF_INET6:
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


static void ns2_sns_st_bss_unconfigured(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	OSMO_ASSERT(gss->role == GPRS_SNS_ROLE_BSS);
	/* empty state - SNS Select will start by ns2_sns_st_all_action() */
}

static void ns2_sns_st_bss_size(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct gprs_ns2_inst *nsi = nse->nsi;
	struct tlv_parsed *tp = NULL;

	OSMO_ASSERT(gss->role == GPRS_SNS_ROLE_BSS);

	switch (event) {
	case NS2_SNS_EV_RX_SIZE_ACK:
		tp = data;
		if (TLVP_VAL_MINLEN(tp, NS_IE_CAUSE, 1)) {
			LOGPFSML(fi, LOGL_ERROR, "SNS-SIZE-ACK with cause %s\n",
				 gprs_ns2_cause_str(*TLVP_VAL(tp, NS_IE_CAUSE)));
			/* TODO: What to do? */
		} else {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_BSS_CONFIG_BSS,
						nsi->timeout[NS_TOUT_TSNS_PROV], 2);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int ns2_sns_count_num_local_ep(struct osmo_fsm_inst *fi, int ip_proto)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct ns2_sns_bind *sbind;
	int count = 0;

	llist_for_each_entry(sbind, &gss->binds, list) {
		const struct osmo_sockaddr *sa = gprs_ns2_ip_bind_sockaddr(sbind->bind);
		if (!sa)
			continue;

		switch (ip_proto) {
		case AF_INET:
			if (sa->u.sas.ss_family == AF_INET)
				count++;
			break;
		case AF_INET6:
			if (sa->u.sas.ss_family == AF_INET6)
				count++;
			break;
		}
	}
	return count;
}

static int ns2_sns_copy_local_endpoints(struct ns2_sns_state *gss)
{
	switch (gss->family) {
	case AF_INET:
		gss->local_procedure.ip4 = talloc_realloc(gss, gss->local_procedure.ip4, struct gprs_ns_ie_ip4_elem,
							  gss->local.num_ip4);
		if (!gss->local_procedure.ip4)
			return -ENOMEM;

		gss->local_procedure.num_ip4 = gss->local.num_ip4;
		memcpy(gss->local_procedure.ip4, gss->local.ip4,
		       sizeof(struct gprs_ns_ie_ip4_elem) * gss->local.num_ip4);
		break;
	case AF_INET6:
		gss->local_procedure.ip6 = talloc_realloc(gss, gss->local_procedure.ip6, struct gprs_ns_ie_ip6_elem,
							  gss->local.num_ip6);
		if (!gss->local_procedure.ip6)
			return -ENOMEM;

		gss->local_procedure.num_ip6 = gss->local.num_ip6;
		memcpy(gss->local_procedure.ip6, gss->local.ip6,
		       sizeof(struct gprs_ns_ie_ip6_elem) * gss->local.num_ip6);
		break;
	default:
		OSMO_ASSERT(0);
	}

	return 0;
}

static void ns2_sns_compute_local_ep_from_binds(struct osmo_fsm_inst *fi)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns_ie_ip4_elem *ip4_elems;
	struct gprs_ns_ie_ip6_elem *ip6_elems;
	struct gprs_ns2_vc_bind *bind;
	struct ns2_sns_bind *sbind;
	const struct osmo_sockaddr *remote;
	const struct osmo_sockaddr *sa;
	struct osmo_sockaddr local;
	int count;

	ns2_clear_elems(&gss->local);

	/* no initial available */
	if (gss->role == GPRS_SNS_ROLE_BSS) {
		if (!gss->initial)
			return;
		remote = &gss->initial->saddr;
	} else
		remote = gprs_ns2_ip_vc_remote(gss->sns_nsvc);

	/* count how many bindings are available (only UDP binds) */
	count = llist_count(&gss->binds);
	if (count == 0) {
		LOGPFSML(fi, LOGL_ERROR, "No local binds for this NSE -> cannot determine IP endpoints\n");
		return;
	}

	switch (gss->family) {
	case AF_INET:
		ip4_elems = talloc_realloc(fi, gss->local.ip4, struct gprs_ns_ie_ip4_elem, count);
		if (!ip4_elems)
			return;

		gss->local.ip4 = ip4_elems;
		llist_for_each_entry(sbind, &gss->binds, list) {
			bind = sbind->bind;
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
			ip4_elems->sig_weight = bind->sns_sig_weight;
			ip4_elems->data_weight = bind->sns_data_weight;
			ip4_elems++;
		}

		gss->local.num_ip4 = count;
		gss->num_max_nsvcs = OSMO_MAX(gss->num_max_ip4_remote * gss->local.num_ip4, 8);
		break;
	case AF_INET6:
		/* IPv6 */
		ip6_elems = talloc_realloc(fi, gss->local.ip6, struct gprs_ns_ie_ip6_elem, count);
		if (!ip6_elems)
			return;

		gss->local.ip6 = ip6_elems;

		llist_for_each_entry(sbind, &gss->binds, list) {
			bind = sbind->bind;
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
			ip6_elems->sig_weight = bind->sns_sig_weight;
			ip6_elems->data_weight = bind->sns_data_weight;

			ip6_elems++;
		}
		gss->local.num_ip6 = count;
		gss->num_max_nsvcs = OSMO_MAX(gss->num_max_ip6_remote * gss->local.num_ip6, 8);
		break;
	}

	ns2_sns_copy_local_endpoints(gss);
}

static void ns2_sns_choose_next_bind(struct ns2_sns_state *gss)
{
	/* take the first bind or take the next bind */
	if (!gss->initial_bind || gss->initial_bind->list.next == &gss->binds)
		gss->initial_bind = llist_first_entry_or_null(&gss->binds, struct ns2_sns_bind, list);
	else
		gss->initial_bind = llist_entry(gss->initial_bind->list.next, struct ns2_sns_bind, list);
}

/* setup all dynamic SNS settings, create a new nsvc and send the SIZE */
static void ns2_sns_st_bss_size_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;

	OSMO_ASSERT(gss->role == GPRS_SNS_ROLE_BSS);

	/* on a generic failure, the timer callback will recover */
	if (old_state != GPRS_SNS_ST_UNCONFIGURED)
		ns2_prim_status_ind(gss->nse, NULL, 0, GPRS_NS2_AFF_CAUSE_SNS_FAILURE);
	if (old_state != GPRS_SNS_ST_BSS_SIZE)
		gss->N = 0;

	ns2_clear_procedures(gss);
	gss->alive = false;

	ns2_sns_compute_local_ep_from_binds(fi);
	ns2_sns_choose_next_bind(gss);

	/* setup the NSVC */
	if (!gss->sns_nsvc) {
		struct gprs_ns2_vc_bind *bind = gss->initial_bind->bind;
		struct osmo_sockaddr *remote = &gss->initial->saddr;
		gss->sns_nsvc = ns2_ip_bind_connect(bind, gss->nse, remote);
		if (!gss->sns_nsvc)
			return;
		/* A pre-configured endpoint shall not be used for NSE data or signalling traffic
		 * (with the exception of Size and Configuration procedures) unless it is configured
		 * by the SGSN using the auto-configuration procedures */
		gss->sns_nsvc->sns_only = true;
	}

	if (gss->num_max_ip4_remote > 0)
		ns2_tx_sns_size(gss->sns_nsvc, true, gss->num_max_nsvcs, gss->local.num_ip4, -1);
	else
		ns2_tx_sns_size(gss->sns_nsvc, true, gss->num_max_nsvcs, -1, gss->local.num_ip6);
}

static void ns2_sns_st_bss_config_bss(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct tlv_parsed *tp = NULL;

	OSMO_ASSERT(gss->role == GPRS_SNS_ROLE_BSS);

	switch (event) {
	case NS2_SNS_EV_RX_CONFIG_ACK:
		tp = (struct tlv_parsed *) data;
		if (TLVP_VAL_MINLEN(tp, NS_IE_CAUSE, 1)) {
			LOGPFSML(fi, LOGL_ERROR, "SNS-CONFIG-ACK with cause %s\n",
							 gprs_ns2_cause_str(*TLVP_VAL(tp, NS_IE_CAUSE)));
			/* TODO: What to do? */
		} else {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_BSS_CONFIG_SGSN, nse->nsi->timeout[NS_TOUT_TSNS_PROV], 3);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void ns2_sns_st_bss_config_bss_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;

	OSMO_ASSERT(gss->role == GPRS_SNS_ROLE_BSS);

	if (old_state != GPRS_SNS_ST_BSS_CONFIG_BSS)
		gss->N = 0;

	/* Transmit SNS-CONFIG */
	switch (gss->family) {
	case AF_INET:
		ns2_tx_sns_config(gss->sns_nsvc, true,
				  gss->local.ip4, gss->local.num_ip4,
				  NULL, 0);
		break;
	case AF_INET6:
		ns2_tx_sns_config(gss->sns_nsvc, true,
				  NULL, 0,
				  gss->local.ip6, gss->local.num_ip6);
		break;
	}
}

/* calculate the timeout of the configured state. the configured
 * state will fail if not at least one NS-VC is alive within X second.
 */
static inline int ns_sns_configured_timeout(struct osmo_fsm_inst *fi)
{
	int secs;
	struct gprs_ns2_inst *nsi = nse_inst_from_fi(fi)->nsi;
	secs = nsi->timeout[NS_TOUT_TNS_ALIVE] * nsi->timeout[NS_TOUT_TNS_ALIVE_RETRIES];
	secs += nsi->timeout[NS_TOUT_TNS_TEST];

	return secs;
}

/* append the remote endpoints from the parsed TLV array to the ns2_sns_state */
static int ns_sns_append_remote_eps(struct osmo_fsm_inst *fi, const struct tlv_parsed *tp)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;

	if (TLVP_PRESENT(tp, NS_IE_IPv4_LIST)) {
		const struct gprs_ns_ie_ip4_elem *v4_list;
		unsigned int num_v4;
		v4_list = (const struct gprs_ns_ie_ip4_elem *) TLVP_VAL(tp, NS_IE_IPv4_LIST);
		num_v4 = TLVP_LEN(tp, NS_IE_IPv4_LIST) / sizeof(*v4_list);

		if (num_v4 && gss->remote.ip6)
			return -NS_CAUSE_INVAL_NR_IPv4_EP;

		/* realloc to the new size */
		gss->remote.ip4 = talloc_realloc(gss, gss->remote.ip4,
						 struct gprs_ns_ie_ip4_elem,
						 gss->remote.num_ip4 + num_v4);
		/* append the new entries to the end of the list */
		memcpy(&gss->remote.ip4[gss->remote.num_ip4], v4_list, num_v4*sizeof(*v4_list));
		gss->remote.num_ip4 += num_v4;

		LOGPFSML(fi, LOGL_INFO, "Rx SNS-CONFIG: Remote IPv4 list now %u entries\n",
			 gss->remote.num_ip4);
	}

	if (TLVP_PRESENT(tp, NS_IE_IPv6_LIST)) {
		const struct gprs_ns_ie_ip6_elem *v6_list;
		unsigned int num_v6;
		v6_list = (const struct gprs_ns_ie_ip6_elem *) TLVP_VAL(tp, NS_IE_IPv6_LIST);
		num_v6 = TLVP_LEN(tp, NS_IE_IPv6_LIST) / sizeof(*v6_list);

		if (num_v6 && gss->remote.ip4)
			return -NS_CAUSE_INVAL_NR_IPv6_EP;

		/* realloc to the new size */
		gss->remote.ip6 = talloc_realloc(gss, gss->remote.ip6,
						 struct gprs_ns_ie_ip6_elem,
						 gss->remote.num_ip6 + num_v6);
		/* append the new entries to the end of the list */
		memcpy(&gss->remote.ip6[gss->remote.num_ip6], v6_list, num_v6*sizeof(*v6_list));
		gss->remote.num_ip6 += num_v6;

		LOGPFSML(fi, LOGL_INFO, "Rx SNS-CONFIG: Remote IPv6 list now %d entries\n",
			 gss->remote.num_ip6);
	}

	return 0;
}

static void ns2_sns_st_bss_config_sgsn_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;

	OSMO_ASSERT(gss->role == GPRS_SNS_ROLE_BSS);

	if (old_state != GPRS_SNS_ST_BSS_CONFIG_SGSN)
		gss->N = 0;
}

static void ns2_sns_st_bss_config_sgsn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	uint8_t cause;
	int rc;

	OSMO_ASSERT(gss->role == GPRS_SNS_ROLE_BSS);

	switch (event) {
	case NS2_SNS_EV_RX_CONFIG_END:
	case NS2_SNS_EV_RX_CONFIG:
		rc = ns_sns_append_remote_eps(fi, data);
		if (rc < 0) {
			cause = -rc;
			ns2_tx_sns_config_ack(gss->sns_nsvc, &cause);
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 0);
			return;
		}
		if (event == NS2_SNS_EV_RX_CONFIG_END) {
			/* check if sum of data / sig weights == 0 */
			if (ip46_weight_sum_data(&gss->remote) == 0 || ip46_weight_sum_sig(&gss->remote) == 0) {
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
			osmo_timer_schedule(&fi->timer, nse->nsi->timeout[NS_TOUT_TSNS_PROV], 0);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* called when receiving NS2_SNS_EV_RX_ADD in state configure */
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
	if (gss->family == AF_INET) {
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
	if (gss->family == AF_INET) {
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
			ip4_remote = talloc_memdup(fi, gss->remote.ip4,
						   gss->remote.num_ip4 * sizeof(*v4_list));
			for (i = 0; i < gss->remote.num_ip4; i++) {
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
			ip6_remote = talloc_memdup(fi, gss->remote.ip6,
						   gss->remote.num_ip6 * sizeof(*v4_list));
			for (i = 0; i < gss->remote.num_ip6; i++) {
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
	case NS2_SNS_EV_RX_ADD:
		ns2_sns_st_configured_add(fi, gss, tp);
		break;
	case NS2_SNS_EV_RX_DELETE:
		ns2_sns_st_configured_delete(fi, gss, tp);
		break;
	case NS2_SNS_EV_RX_CHANGE_WEIGHT:
		ns2_sns_st_configured_change(fi, gss, tp);
		break;
	case NS2_SNS_EV_REQ_NSVC_ALIVE:
		osmo_timer_del(&fi->timer);
		break;
	}
}

static void ns2_sns_st_configured_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct gprs_ns2_vc *nsvc;
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	/* NS-VC status updates are only parsed in ST_CONFIGURED.
	 * Do an initial check if there are any nsvc alive atm */
	llist_for_each_entry(nsvc, &nse->nsvc, list) {
		if (ns2_vc_is_unblocked(nsvc)) {
			gss->alive = true;
			osmo_timer_del(&fi->timer);
			break;
		}
	}

	/* remove the initial NSVC if the NSVC isn't part of the configuration */
	if (gss->sns_nsvc->sns_only)
		gprs_ns2_free_nsvc(gss->sns_nsvc);

	if (old_state != GPRS_SNS_ST_LOCAL_PROCEDURE)
		ns2_prim_status_ind(nse, NULL, 0, GPRS_NS2_AFF_CAUSE_SNS_CONFIGURED);

	if (!llist_empty(&gss->procedures)) {
		osmo_fsm_inst_state_chg(gss->nse->bss_sns_fi, GPRS_SNS_ST_LOCAL_PROCEDURE,
					gss->nse->nsi->timeout[NS_TOUT_TSNS_PROV], 5);
	}
}

static void ns2_sns_st_local_procedure_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;

	/* check if resend or not */
	if (!gss->current_procedure) {
		/* take next procedure */
		gss->current_procedure = llist_first_entry_or_null(&gss->procedures,
								   struct ns2_sns_procedure, list);
		if (!gss->current_procedure) {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_CONFIGURED, 0, 0);
			return;
		}
		gss->N = 0;
		gss->current_procedure->running = true;
		gss->current_procedure->trans_id = ++gss->trans_id;
		if (gss->trans_id == 0)
			gss->trans_id = gss->current_procedure->trans_id = 1;

	}

	/* also takes care of retransmitting */
	switch (gss->current_procedure->procedure) {
	case SNS_PROC_ADD:
		if (gss->family == AF_INET)
			ns2_tx_sns_add(gss->sns_nsvc, gss->current_procedure->trans_id, &gss->current_procedure->ip4, 1, NULL, 0);
		else
			ns2_tx_sns_add(gss->sns_nsvc, gss->current_procedure->trans_id, NULL, 0, &gss->current_procedure->ip6, 1);
		break;
	case SNS_PROC_CHANGE_WEIGHT:
		if (gss->family == AF_INET)
			ns2_tx_sns_change_weight(gss->sns_nsvc, gss->current_procedure->trans_id, &gss->current_procedure->ip4, 1, NULL, 0);
		else
			ns2_tx_sns_change_weight(gss->sns_nsvc, gss->current_procedure->trans_id, NULL, 0, &gss->current_procedure->ip6, 1);
		break;
	case SNS_PROC_DEL:
		if (gss->family == AF_INET)
			ns2_tx_sns_del(gss->sns_nsvc, gss->current_procedure->trans_id, &gss->current_procedure->ip4, 1, NULL, 0);
		else
			ns2_tx_sns_del(gss->sns_nsvc, gss->current_procedure->trans_id, NULL, 0, &gss->current_procedure->ip6, 1);
		break;
	default:
		break;
	}
}

static void create_nsvc_for_new_sbind(struct ns2_sns_state *gss, struct ns2_sns_bind *sbind)
{
	struct gprs_ns2_nse *nse = gss->nse;
	struct gprs_ns2_vc_bind *bind = sbind->bind;
	struct gprs_ns2_vc *nsvc;
	struct osmo_sockaddr remote = { };
	unsigned int i;

	/* iterate over all remote IPv4 endpoints */
	for (i = 0; i < gss->remote.num_ip4; i++) {
		const struct gprs_ns_ie_ip4_elem *ip4 = &gss->remote.ip4[i];

		remote.u.sin.sin_family = AF_INET;
		remote.u.sin.sin_addr.s_addr = ip4->ip_addr;
		remote.u.sin.sin_port = ip4->udp_port;
		/* we only care about UDP binds */
		if (bind->ll != GPRS_NS2_LL_UDP)
			continue;

		nsvc = nsvc_for_bind_and_remote(nse, bind, &remote);
		if (!nsvc) {
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

	/* iterate over all remote IPv4 endpoints */
	for (i = 0; i < gss->remote.num_ip6; i++) {
		const struct gprs_ns_ie_ip6_elem *ip6 = &gss->remote.ip6[i];

		remote.u.sin6.sin6_family = AF_INET6;
		remote.u.sin6.sin6_addr = ip6->ip_addr;
		remote.u.sin6.sin6_port = ip6->udp_port;

		/* we only care about UDP binds */
		nsvc = nsvc_for_bind_and_remote(nse, bind, &remote);
		if (!nsvc) {
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

static void ns2_sns_st_local_procedure(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct gprs_ns_ie_ip4_elem *ip4, *proc4;
	struct gprs_ns_ie_ip6_elem *ip6, *proc6;
	struct tlv_parsed *tp = data;
	uint8_t trans_id;
	uint8_t cause;

	switch (event) {
	case NS2_SNS_EV_RX_ADD:
		ns2_sns_st_configured_add(fi, gss, tp);
		break;
	case NS2_SNS_EV_RX_DELETE:
		ns2_sns_st_configured_delete(fi, gss, tp);
		break;
	case NS2_SNS_EV_RX_CHANGE_WEIGHT:
		ns2_sns_st_configured_change(fi, gss, tp);
		break;
	case NS2_SNS_EV_RX_ACK:
		/* presence of trans_id is already checked here */
		trans_id = tlvp_val8(tp, NS_IE_TRANS_ID, 0);
		if (trans_id != gss->current_procedure->trans_id) {
			LOGPFSML(fi, LOGL_INFO, "NSEI=%u Rx SNS ACK with invalid transaction id %d. Valid %d\n",
				 nse->nsei, trans_id, gss->current_procedure->trans_id);
			break;
		}

		if (TLVP_PRESENT(tp, NS_IE_CAUSE)) {
			/* what happend on error cause? return to size? */
			cause = tlvp_val8(tp, NS_IE_CAUSE, 0);
			LOGPFSML(fi, LOGL_ERROR, "NSEI=%u Rx SNS ACK trans %d with cause code %d.\n",
				 nse->nsei, trans_id, cause);
			sns_failed(fi, NULL);
			break;
		}

		switch (gss->current_procedure->procedure) {
		case SNS_PROC_ADD:
			switch (gss->family) {
			case AF_INET:
				add_ip4_elem(gss, &gss->local, &gss->current_procedure->ip4);
				break;
			case AF_INET6:
				add_ip6_elem(gss, &gss->local, &gss->current_procedure->ip6);
				break;
			}
			/* the sbind can be NULL if the bind has been released by del_bind */
			if (gss->current_procedure->sbind) {
				create_nsvc_for_new_sbind(gss, gss->current_procedure->sbind);
				gprs_ns2_start_alive_all_nsvcs(nse);
			}
			break;
		case SNS_PROC_CHANGE_WEIGHT:
			switch (gss->family) {
			case AF_INET:
				proc4 = &gss->current_procedure->ip4;
				for (unsigned int i=0; i<gss->local.num_ip4; i++) {
					ip4 = &gss->local.ip4[i];
					if (ip4->ip_addr != proc4->ip_addr ||
							ip4->udp_port != proc4->udp_port)
						continue;
					ip4->sig_weight = proc4->sig_weight;
					ip4->data_weight = proc4->data_weight;
					break;
				}
				break;
			case AF_INET6:
				proc6 = &gss->current_procedure->ip6;
				for (unsigned int i=0; i<gss->local.num_ip6; i++) {
					ip6 = &gss->local.ip6[i];
					if (memcmp(&ip6->ip_addr, &proc6->ip_addr, sizeof(proc6->ip_addr)) ||
							ip6->udp_port != proc6->udp_port) {
						continue;
					}
					ip6->sig_weight = proc6->sig_weight;
					ip6->data_weight = proc6->data_weight;
					break;
				}
				break;
			default:
				OSMO_ASSERT(0);
			}
			break;
		case SNS_PROC_DEL:
			switch (gss->family) {
			case AF_INET:
				remove_ip4_elem(gss, &gss->local, &gss->current_procedure->ip4);
				break;
			case AF_INET6:
				remove_ip6_elem(gss, &gss->local, &gss->current_procedure->ip6);
				break;
			}
			break;
		default:
			break;
		}

		llist_del(&gss->current_procedure->list);
		talloc_free(gss->current_procedure);
		gss->current_procedure = NULL;

		if (llist_empty(&gss->procedures))
			osmo_fsm_inst_state_chg(gss->nse->bss_sns_fi, GPRS_SNS_ST_CONFIGURED,
						0, 0);
		else
			osmo_fsm_inst_state_chg(gss->nse->bss_sns_fi, GPRS_SNS_ST_LOCAL_PROCEDURE,
						gss->nse->nsi->timeout[NS_TOUT_TSNS_PROV], 5);
		break;
	}
}

static const struct osmo_fsm_state ns2_sns_bss_states[] = {
	[GPRS_SNS_ST_UNCONFIGURED] = {
		.in_event_mask = 0, /* handled by all_state_action */
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_BSS_SIZE),
		.name = "UNCONFIGURED",
		.action = ns2_sns_st_bss_unconfigured,
	},
	[GPRS_SNS_ST_BSS_SIZE] = {
		.in_event_mask = S(NS2_SNS_EV_RX_SIZE_ACK),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_BSS_SIZE) |
				  S(GPRS_SNS_ST_BSS_CONFIG_BSS),
		.name = "BSS_SIZE",
		.action = ns2_sns_st_bss_size,
		.onenter = ns2_sns_st_bss_size_onenter,
	},
	[GPRS_SNS_ST_BSS_CONFIG_BSS] = {
		.in_event_mask = S(NS2_SNS_EV_RX_CONFIG_ACK),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_BSS_CONFIG_BSS) |
				  S(GPRS_SNS_ST_BSS_CONFIG_SGSN) |
				  S(GPRS_SNS_ST_BSS_SIZE),
		.name = "BSS_CONFIG_BSS",
		.action = ns2_sns_st_bss_config_bss,
		.onenter = ns2_sns_st_bss_config_bss_onenter,
	},
	[GPRS_SNS_ST_BSS_CONFIG_SGSN] = {
		.in_event_mask = S(NS2_SNS_EV_RX_CONFIG) |
				 S(NS2_SNS_EV_RX_CONFIG_END),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_BSS_CONFIG_SGSN) |
				  S(GPRS_SNS_ST_CONFIGURED) |
				  S(GPRS_SNS_ST_BSS_SIZE),
		.name = "BSS_CONFIG_SGSN",
		.action = ns2_sns_st_bss_config_sgsn,
		.onenter = ns2_sns_st_bss_config_sgsn_onenter,
	},
	[GPRS_SNS_ST_CONFIGURED] = {
		.in_event_mask = S(NS2_SNS_EV_RX_ADD) |
				 S(NS2_SNS_EV_RX_DELETE) |
				 S(NS2_SNS_EV_RX_CHANGE_WEIGHT) |
				 S(NS2_SNS_EV_REQ_NSVC_ALIVE),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_BSS_SIZE) |
				  S(GPRS_SNS_ST_LOCAL_PROCEDURE),
		.name = "CONFIGURED",
		.action = ns2_sns_st_configured,
		.onenter = ns2_sns_st_configured_onenter,
	},
	[GPRS_SNS_ST_LOCAL_PROCEDURE] = {
		.in_event_mask = S(NS2_SNS_EV_RX_ADD) |
				 S(NS2_SNS_EV_RX_DELETE) |
				 S(NS2_SNS_EV_RX_CHANGE_WEIGHT) |
				 S(NS2_SNS_EV_RX_ACK) |
				 S(NS2_SNS_EV_REQ_NSVC_ALIVE),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_BSS_SIZE) |
				  S(GPRS_SNS_ST_CONFIGURED) |
				  S(GPRS_SNS_ST_LOCAL_PROCEDURE),
		.name = "LOCAL_PROCEDURE",
		.action = ns2_sns_st_local_procedure,
		.onenter = ns2_sns_st_local_procedure_onenter,
	},

};

static int ns2_sns_fsm_bss_timer_cb(struct osmo_fsm_inst *fi)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct gprs_ns2_inst *nsi = nse->nsi;

	gss->N++;
	switch (fi->T) {
	case 1:
		if (gss->N >= nsi->timeout[NS_TOUT_TSNS_SIZE_RETRIES]) {
			sns_failed(fi, "Size retries failed. Selecting next IP-SNS endpoint.");
		} else {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_BSS_SIZE, nsi->timeout[NS_TOUT_TSNS_PROV], 1);
		}
		break;
	case 2:
		if (gss->N >= nsi->timeout[NS_TOUT_TSNS_CONFIG_RETRIES]) {
			sns_failed(fi, "BSS Config retries failed. Selecting next IP-SNS endpoint");
		} else {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_BSS_CONFIG_BSS, nsi->timeout[NS_TOUT_TSNS_PROV], 2);
		}
		break;
	case 3:
		if (gss->N >= nsi->timeout[NS_TOUT_TSNS_CONFIG_RETRIES]) {
			sns_failed(fi, "SGSN Config retries failed. Selecting next IP-SNS endpoint.");
		} else {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_BSS_CONFIG_SGSN, nsi->timeout[NS_TOUT_TSNS_PROV], 3);
		}
		break;
	case 4:
		sns_failed(fi, "Config succeeded but no NS-VC came online. Selecting next IP-SNS endpoint.");
		break;
	case 5:
		if (gss->N >= nsi->timeout[NS_TOUT_TSNS_CONFIG_RETRIES]) {
			sns_failed(fi, "SNS Procedure retries failed.");
		} else {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_LOCAL_PROCEDURE, nsi->timeout[NS_TOUT_TSNS_PROV], 5);
		}
		break;
	}
	return 0;
}

static struct gprs_ns_ie_ip4_elem *ns2_get_sbind_ip4_entry(struct ns2_sns_state *gss,
							   struct ns2_sns_bind *sbind,
							   struct ns2_sns_elems *endpoints)
{
	const struct osmo_sockaddr *addr;
	struct gprs_ns_ie_ip4_elem *ip4;

	if (gss->family != AF_INET)
		return NULL;

	addr = gprs_ns2_ip_bind_sockaddr(sbind->bind);
	if (addr->u.sa.sa_family != AF_INET)
		return NULL;

	for (unsigned int i=0; i<endpoints->num_ip4; i++) {
		ip4 = &endpoints->ip4[i];
		if (ip4->ip_addr == addr->u.sin.sin_addr.s_addr &&
				ip4->udp_port == addr->u.sin.sin_port)
			return ip4;
	}

	return NULL;
}

static struct gprs_ns_ie_ip6_elem *ns2_get_sbind_ip6_entry(struct ns2_sns_state *gss,
							   struct ns2_sns_bind *sbind,
							   struct ns2_sns_elems *endpoints)
{
	const struct osmo_sockaddr *addr;
	struct gprs_ns_ie_ip6_elem *ip6;

	if (gss->family != AF_INET6)
		return NULL;

	addr = gprs_ns2_ip_bind_sockaddr(sbind->bind);
	if (addr->u.sa.sa_family != AF_INET6)
		return NULL;

	for (unsigned int i=0; i<endpoints->num_ip6; i++) {
		ip6 = &endpoints->ip6[i];
		if (memcmp(&ip6->ip_addr, &addr->u.sin6.sin6_addr, sizeof(ip6->ip_addr)) ||
		    ip6->udp_port != addr->u.sin6.sin6_port)
			return ip6;
	}

	return NULL;
}

/* return != 0 if the resulting weight is invalid. return 1 if sbind doesn't have an entry */
static int ns2_update_weight_entry(struct ns2_sns_state *gss, struct ns2_sns_bind *sbind,
				   struct ns2_sns_elems *endpoints)
{
	struct gprs_ns_ie_ip4_elem *ip4;
	struct gprs_ns_ie_ip6_elem *ip6;

	switch (gss->family) {
	case AF_INET:
		ip4 = ns2_get_sbind_ip4_entry(gss, sbind, endpoints);
		if (!ip4)
			return 1;
		ip4->sig_weight = sbind->bind->sns_sig_weight;
		ip4->data_weight = sbind->bind->sns_data_weight;
		return (ip4_weight_sum_sig(endpoints) != 0 && ip4_weight_sum_data(endpoints) != 0);
		break;
	case AF_INET6:
		ip6 = ns2_get_sbind_ip6_entry(gss, sbind, endpoints);
		if (!ip6)
			return 1;
		ip6->sig_weight = sbind->bind->sns_sig_weight;
		ip6->data_weight = sbind->bind->sns_data_weight;
		return (ip6_weight_sum_sig(endpoints) != 0 && ip6_weight_sum_data(endpoints) != 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}
static void ns2_add_procedure(struct ns2_sns_state *gss, struct ns2_sns_bind *sbind,
			      enum sns_procedure procedure_type)
{
	struct ns2_sns_procedure *procedure = NULL;
	const struct osmo_sockaddr *saddr;
	saddr = gprs_ns2_ip_bind_sockaddr(sbind->bind);

	OSMO_ASSERT(saddr->u.sa.sa_family == gss->family);

	switch (procedure_type) {
	case SNS_PROC_ADD:
		break;
	case SNS_PROC_DEL:
		break;
	case SNS_PROC_CHANGE_WEIGHT:
		llist_for_each_entry(procedure, &gss->procedures, list) {
			if (procedure->sbind == sbind && procedure->procedure == procedure_type &&
					!procedure->running) {
				switch(gss->family) {
				case AF_INET:
					/* merge it with a previous procedure */
					procedure->ip4.ip_addr = sbind->bind->sns_sig_weight;
					procedure->ip4.data_weight = sbind->bind->sns_data_weight;
					break;
				case AF_INET6:
					/* merge it with a previous procedure */
					procedure->ip6.sig_weight = sbind->bind->sns_sig_weight;
					procedure->ip6.data_weight = sbind->bind->sns_data_weight;
					break;
				default:
					OSMO_ASSERT(0);
				}
				return;
			}
		}
		break;
	default:
		return;
	}

	procedure = talloc_zero(gss, struct ns2_sns_procedure);
	if (!procedure)
		return;

	switch (procedure_type) {
	case SNS_PROC_ADD:
	case SNS_PROC_CHANGE_WEIGHT:
		procedure->sbind = sbind;
		break;
	default:
		break;
	}

	llist_add_tail(&procedure->list, &gss->procedures);
	procedure->procedure = procedure_type;
	procedure->sig_weight = sbind->bind->sns_sig_weight;
	procedure->data_weight = sbind->bind->sns_data_weight;

	switch(gss->family) {
	case AF_INET:
		procedure->ip4.ip_addr = saddr->u.sin.sin_addr.s_addr;
		procedure->ip4.udp_port = saddr->u.sin.sin_port;
		procedure->ip4.sig_weight = sbind->bind->sns_sig_weight;
		procedure->ip4.data_weight = sbind->bind->sns_data_weight;
		break;
	case AF_INET6:
		memcpy(&procedure->ip6.ip_addr, &saddr->u.sin6.sin6_addr, sizeof(struct in6_addr));
		procedure->ip6.udp_port = saddr->u.sin.sin_port;
		procedure->ip6.sig_weight = sbind->bind->sns_sig_weight;
		procedure->ip6.data_weight = sbind->bind->sns_data_weight;
		break;
	default:
		OSMO_ASSERT(0);
	}

	if (gss->nse->bss_sns_fi->state == GPRS_SNS_ST_CONFIGURED) {
		osmo_fsm_inst_state_chg(gss->nse->bss_sns_fi, GPRS_SNS_ST_LOCAL_PROCEDURE,
					gss->nse->nsi->timeout[NS_TOUT_TSNS_PROV], 5);
	}
}

/* add an entrypoint to sns_endpoints */
static int ns2_sns_add_elements(struct ns2_sns_state *gss, struct ns2_sns_bind *sbind,
				struct ns2_sns_elems *elems)
{
	const struct osmo_sockaddr *saddr;
	struct gprs_ns_ie_ip4_elem ip4;
	struct gprs_ns_ie_ip6_elem ip6;
	int rc = -1;

	saddr = gprs_ns2_ip_bind_sockaddr(sbind->bind);
	OSMO_ASSERT(saddr->u.sa.sa_family == gss->family);

	switch (gss->family) {
	case AF_INET:
		ip4.ip_addr = saddr->u.sin.sin_addr.s_addr;
		ip4.udp_port= saddr->u.sin.sin_port;
		ip4.sig_weight = sbind->bind->sns_sig_weight;
		ip4.data_weight = sbind->bind->sns_data_weight;
		rc = add_ip4_elem(gss, elems, &ip4);
		break;
	case AF_INET6:
		memcpy(&ip6.ip_addr, &saddr->u.sin6.sin6_addr, sizeof(struct in6_addr));
		ip6.udp_port= saddr->u.sin.sin_port;
		ip6.sig_weight = sbind->bind->sns_sig_weight;
		ip6.data_weight = sbind->bind->sns_data_weight;
		rc = add_ip6_elem(gss, elems, &ip6);
		break;
	}

	return rc;
}

/* common allstate-action for both roles */
static void ns2_sns_st_all_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct ns2_sns_bind *sbind;
	struct gprs_ns2_vc *nsvc, *nsvc2;
	struct ns2_sns_procedure *procedure;

	switch (event) {
	case NS2_SNS_EV_REQ_ADD_BIND:
		sbind = data;
		switch (fi->state) {
		case GPRS_SNS_ST_UNCONFIGURED:
			if (gss->role == GPRS_SNS_ROLE_BSS)
				osmo_fsm_inst_dispatch(nse->bss_sns_fi, NS2_SNS_EV_REQ_SELECT_ENDPOINT, NULL);
			break;
		case GPRS_SNS_ST_BSS_SIZE:
			switch (gss->family) {
			case AF_INET:
				if (gss->num_max_ip4_remote <= gss->local.num_ip4 ||
					 gss->num_max_ip4_remote * (gss->local.num_ip4 + 1) > gss->num_max_nsvcs) {
					osmo_fsm_inst_dispatch(nse->bss_sns_fi, NS2_SNS_EV_REQ_SELECT_ENDPOINT, GPRS_SNS_FLAG_KEEP_SELECT_ENDPOINT_ORDER);
					return;
				}
				break;
			case AF_INET6:
				if (gss->num_max_ip6_remote <= gss->local.num_ip6 ||
						gss->num_max_ip6_remote * (gss->local.num_ip6 + 1) > gss->num_max_nsvcs) {
					osmo_fsm_inst_dispatch(nse->bss_sns_fi, NS2_SNS_EV_REQ_SELECT_ENDPOINT, GPRS_SNS_FLAG_KEEP_SELECT_ENDPOINT_ORDER);
					return;
				}
				break;
			}
			ns2_sns_add_elements(gss, sbind, &gss->local);
			break;
		case GPRS_SNS_ST_BSS_CONFIG_BSS:
		case GPRS_SNS_ST_BSS_CONFIG_SGSN:
		case GPRS_SNS_ST_CONFIGURED:
			switch (gss->family) {
			case AF_INET:
				if (gss->num_max_ip4_remote <= gss->local.num_ip4) {
					LOGPFSML(fi, LOGL_ERROR,
						 "NSE %d: ignoring bind %s because there are too many endpoints for the SNS.\n",
						 nse->nsei, sbind->bind->name);
					return;
				}
				if (gss->remote.num_ip4 * (gss->local.num_ip4 + 1) > gss->num_max_nsvcs) {
					LOGPFSML(fi, LOGL_ERROR,
						 "NSE %d: ignoring bind %s because there are too many endpoints for the SNS.\n",
						 nse->nsei, sbind->bind->name);
					return;
				}
				break;
			case AF_INET6:
				if (gss->num_max_ip6_remote <= gss->local.num_ip6) {
					LOGPFSML(fi, LOGL_ERROR,
						 "NSE %d: ignoring bind %s because there are too many endpoints for the SNS.\n",
						 nse->nsei, sbind->bind->name);
					return;
				}
				if (gss->remote.num_ip6 * (gss->local.num_ip6 + 1) > gss->num_max_nsvcs) {
					LOGPFSML(fi, LOGL_ERROR,
						 "NSE %d: ignoring bind %s because there are too many endpoints for the SNS.\n",
						 nse->nsei, sbind->bind->name);
					return;
				}
				break;
			}
			ns2_sns_add_elements(gss, sbind, &gss->local_procedure);
			ns2_add_procedure(gss, sbind, SNS_PROC_ADD);
			break;
		}
		break;
	case NS2_SNS_EV_REQ_DELETE_BIND:
		sbind = data;
		switch (fi->state) {
		case GPRS_SNS_ST_UNCONFIGURED:
			break;
		case GPRS_SNS_ST_BSS_SIZE:
			llist_for_each_entry_safe(nsvc, nsvc2, &nse->nsvc, list) {
				if (nsvc->bind == sbind->bind) {
					gprs_ns2_free_nsvc(nsvc);
				}
			}
			osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_REQ_SELECT_ENDPOINT, NULL);
			break;
		case GPRS_SNS_ST_BSS_CONFIG_BSS:
		case GPRS_SNS_ST_BSS_CONFIG_SGSN:
		case GPRS_SNS_ST_CONFIGURED:
		case GPRS_SNS_ST_LOCAL_PROCEDURE:
			remove_bind_elem(gss, &gss->local_procedure, sbind);
			if (ip46_weight_sum(&gss->local_procedure, true) == 0 ||
					ip46_weight_sum(&gss->local_procedure, false) == 0) {
				LOGPFSML(fi, LOGL_ERROR, "NSE %d: weight has become invalid because of removing bind %s. Resetting the configuration\n",
					 nse->nsei, sbind->bind->name);
				sns_failed(fi, NULL);
				break;
			}
			gss->block_no_nsvc_events = true;
			llist_for_each_entry_safe(nsvc, nsvc2, &nse->nsvc, list) {
				if (nsvc->bind == sbind->bind) {
					gprs_ns2_free_nsvc(nsvc);
				}
			}
			gss->block_no_nsvc_events = false;
			if (nse->sum_sig_weight == 0 || !nse->alive || !gss->alive) {
				sns_failed(fi, "While deleting a bind the current state became invalid (no signalling weight)");
				break;
			}

			/* ensure other procedures doesn't use the sbind */
			llist_for_each_entry(procedure, &gss->procedures, list) {
				if (procedure->sbind == sbind)
					procedure->sbind = NULL;
			}
			ns2_add_procedure(gss, sbind, SNS_PROC_DEL);
			break;
		}

		/* if this is the last bind, the free_nsvc() will trigger a reselection */
		talloc_free(sbind);
		break;
	case NS2_SNS_EV_REQ_CHANGE_WEIGHT:
		sbind = data;
		switch (fi->state) {
		case GPRS_SNS_ST_UNCONFIGURED:
			/* select_endpoint will check if this is a valid configuration */
			if (gss->role == GPRS_SNS_ROLE_BSS)
				osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_REQ_SELECT_ENDPOINT, NULL);
			break;
		case GPRS_SNS_ST_BSS_SIZE:
			/* invalid weight? */
			if (!ns2_update_weight_entry(gss, sbind, &gss->local))
				sns_failed(fi, "updating weights results in an invalid configuration.");
			break;
		default:
			if (!ns2_update_weight_entry(gss, sbind, &gss->local_procedure)) {
				sns_failed(fi, "updating weights results in an invalid configuration.");
				break;
			}
			ns2_add_procedure(gss, sbind, SNS_PROC_CHANGE_WEIGHT);
			break;
		}
	}
}

/* validate the bss configuration (sns endpoint and binds)
 * - no endpoints -> invalid
 * - no binds -> invalid
 * - only v4 sns endpoints, only v6 binds -> invalid
 * - only v4 sns endpoints, but v4 sig weights == 0 -> invalid ...
 */
static int ns2_sns_bss_valid_configuration(struct ns2_sns_state *gss)
{
	struct ns2_sns_bind *sbind;
	struct sns_endpoint *endpoint;
	const struct osmo_sockaddr *addr;
	int v4_sig = 0, v4_data = 0, v6_sig = 0, v6_data = 0;
	bool v4_endpoints = false;
	bool v6_endpoints = false;

	if (llist_empty(&gss->sns_endpoints) || llist_empty(&gss->binds))
		return 0;

	llist_for_each_entry(sbind, &gss->binds, list) {
		addr = gprs_ns2_ip_bind_sockaddr(sbind->bind);
		if (!addr)
			continue;
		switch (addr->u.sa.sa_family) {
		case AF_INET:
			v4_sig += sbind->bind->sns_sig_weight;
			v4_data += sbind->bind->sns_data_weight;
			break;
		case AF_INET6:
			v6_sig += sbind->bind->sns_sig_weight;
			v6_data += sbind->bind->sns_data_weight;
			break;
		}
	}

	llist_for_each_entry(endpoint, &gss->sns_endpoints, list) {
		switch (endpoint->saddr.u.sa.sa_family) {
		case AF_INET:
			v4_endpoints = true;
			break;
		case AF_INET6:
			v6_endpoints = true;
			break;
		}
	}

	return (v4_endpoints && v4_sig && v4_data) || (v6_endpoints && v6_sig && v6_data);
}

/* allstate-action for BSS role */
static void ns2_sns_st_all_action_bss(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);

	/* reset when receiving NS2_SNS_EV_REQ_NO_NSVC */
	switch (event) {
	case NS2_SNS_EV_REQ_NO_NSVC:
		/* ignore reselection running */
		if (gss->reselection_running || gss->block_no_nsvc_events)
			break;

		sns_failed(fi, "no remaining NSVC, resetting SNS FSM");
		break;
	case NS2_SNS_EV_REQ_FREE_NSVCS:
	case NS2_SNS_EV_REQ_SELECT_ENDPOINT:
		/* TODO: keep the order of binds when data == GPRS_SNS_FLAG_KEEP_SELECT_ENDPOINT_ORDER */
		/* tear down previous state
		 * gprs_ns2_free_nsvcs() will trigger NO_NSVC, prevent this from triggering a reselection */
		if (gss->reselection_running || gss->block_no_nsvc_events)
			break;

		gss->reselection_running = true;
		ns2_free_nsvcs(nse);
		ns2_clear_elems(&gss->local);
		ns2_clear_elems(&gss->remote);

		/* Choose the next sns endpoint. */
		if (!ns2_sns_bss_valid_configuration(gss)) {
			gss->initial = NULL;
			ns2_prim_status_ind(gss->nse, NULL, 0, GPRS_NS2_AFF_CAUSE_SNS_NO_ENDPOINTS);
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 3);
			gss->reselection_running = false;
			return;
		} else if (!gss->initial) {
			gss->initial = llist_first_entry(&gss->sns_endpoints, struct sns_endpoint, list);
		} else if (gss->initial->list.next == &gss->sns_endpoints) {
			/* last entry, continue with first */
			gss->initial = llist_first_entry(&gss->sns_endpoints, struct sns_endpoint, list);
		} else {
			/* next element is an entry */
			gss->initial = llist_entry(gss->initial->list.next, struct sns_endpoint, list);
		}

		gss->family = gss->initial->saddr.u.sa.sa_family;
		gss->reselection_running = false;
		osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_BSS_SIZE, nse->nsi->timeout[NS_TOUT_TSNS_PROV], 1);
		break;
	default:
		ns2_sns_st_all_action(fi, event, data);
		break;
	}
}

static struct osmo_fsm gprs_ns2_sns_bss_fsm = {
	.name = "GPRS-NS2-SNS-BSS",
	.states = ns2_sns_bss_states,
	.num_states = ARRAY_SIZE(ns2_sns_bss_states),
	.allstate_event_mask = S(NS2_SNS_EV_REQ_NO_NSVC) |
			       S(NS2_SNS_EV_REQ_FREE_NSVCS) |
			       S(NS2_SNS_EV_REQ_SELECT_ENDPOINT) |
			       S(NS2_SNS_EV_REQ_ADD_BIND) |
			       S(NS2_SNS_EV_REQ_CHANGE_WEIGHT) |
			       S(NS2_SNS_EV_REQ_DELETE_BIND),
	.allstate_action = ns2_sns_st_all_action_bss,
	.cleanup = NULL,
	.timer_cb = ns2_sns_fsm_bss_timer_cb,
	.event_names = gprs_sns_event_names,
	.pre_term = NULL,
	.log_subsys = DLNS,
};

/*! Allocate an IP-SNS FSM for the BSS side.
 *  \param[in] nse NS Entity in which the FSM runs
 *  \param[in] id string identifier
 *  \returns FSM instance on success; NULL on error */
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
	gss->role = GPRS_SNS_ROLE_BSS;
	/* The SGSN doesn't tell the BSS, so we assume there's always sufficient */
	gss->num_max_ip4_remote = 8192;
	gss->num_max_ip6_remote = 8192;
	INIT_LLIST_HEAD(&gss->sns_endpoints);
	INIT_LLIST_HEAD(&gss->binds);
	INIT_LLIST_HEAD(&gss->procedures);

	return fi;
err:
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
	return NULL;
}

/*! main entry point for receiving SNS messages from the network.
 *  \param[in] nsvc NS-VC on which the message was received
 *  \param[in] msg message buffer of the IP-SNS message
 *  \param[in] tp parsed TLV structure of message
 *  \returns 0 on success; negative on error */
int ns2_sns_rx(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp)
{
	struct gprs_ns2_nse *nse = nsvc->nse;
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	uint16_t nsei = nsvc->nse->nsei;
	struct ns2_sns_state *gss;
	struct osmo_fsm_inst *fi;
	int rc = 0;

	if (!nse->bss_sns_fi) {
		LOGNSVC(nsvc, LOGL_NOTICE, "Rx %s for NS Instance that has no SNS!\n",
			get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));
		rc = -EINVAL;
		goto out;
	}

	/* FIXME: how to resolve SNS FSM Instance by NSEI (SGSN)? */
	fi = nse->bss_sns_fi;
	gss = (struct ns2_sns_state *) fi->priv;
	gss->sns_nsvc = nsvc;

	LOGPFSML(fi, LOGL_DEBUG, "NSEI=%u Rx SNS PDU type %s\n", nsei,
		 get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));

	switch (nsh->pdu_type) {
	case SNS_PDUT_SIZE:
		osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_RX_SIZE, tp);
		break;
	case SNS_PDUT_SIZE_ACK:
		osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_RX_SIZE_ACK, tp);
		break;
	case SNS_PDUT_CONFIG:
		if (nsh->data[0] & 0x01)
			osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_RX_CONFIG_END, tp);
		else
			osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_RX_CONFIG, tp);
		break;
	case SNS_PDUT_CONFIG_ACK:
		osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_RX_CONFIG_ACK, tp);
		break;
	case SNS_PDUT_ADD:
		osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_RX_ADD, tp);
		break;
	case SNS_PDUT_DELETE:
		osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_RX_DELETE, tp);
		break;
	case SNS_PDUT_CHANGE_WEIGHT:
		osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_RX_CHANGE_WEIGHT, tp);
		break;
	case SNS_PDUT_ACK:
		osmo_fsm_inst_dispatch(fi, NS2_SNS_EV_RX_ACK, tp);
		break;
	default:
		LOGPFSML(fi, LOGL_ERROR, "NSEI=%u Rx unknown SNS PDU type %s\n", nsei,
			 get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));
		rc = -EINVAL;
	}

out:
	msgb_free(msg);

	return rc;
}

#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>

static void vty_dump_sns_ip4(struct vty *vty, const char *prefix, const struct gprs_ns_ie_ip4_elem *ip4)
{
	struct in_addr in = { .s_addr = ip4->ip_addr };
	vty_out(vty, "%s %s:%u, Signalling Weight: %u, Data Weight: %u%s", prefix,
		inet_ntoa(in), ntohs(ip4->udp_port), ip4->sig_weight, ip4->data_weight, VTY_NEWLINE);
}

static void vty_dump_sns_ip6(struct vty *vty, const char *prefix, const struct gprs_ns_ie_ip6_elem *ip6)
{
	char ip_addr[INET6_ADDRSTRLEN] = {};
	if (!inet_ntop(AF_INET6, &ip6->ip_addr, ip_addr, (INET6_ADDRSTRLEN)))
		strcpy(ip_addr, "Invalid IPv6");

	vty_out(vty, "%s %s:%u, Signalling Weight: %u, Data Weight: %u%s", prefix,
		ip_addr, ntohs(ip6->udp_port), ip6->sig_weight, ip6->data_weight, VTY_NEWLINE);
}

/*! Dump the IP-SNS state to a vty.
 *  \param[in] vty VTY to which the state shall be printed
 *  \param[in] prefix prefix to print at start of each line (typically indenting)
 *  \param[in] nse NS Entity whose IP-SNS state shall be printed
 *  \param[in] stats Whether or not statistics shall also be printed */
void ns2_sns_dump_vty(struct vty *vty, const char *prefix, const struct gprs_ns2_nse *nse, bool stats)
{
	struct ns2_sns_state *gss;
	unsigned int i;

	if (!nse->bss_sns_fi)
		return;

	vty_out_fsm_inst2(vty, prefix, nse->bss_sns_fi);
	gss = (struct ns2_sns_state *) nse->bss_sns_fi->priv;

	vty_out(vty, "%sMaximum number of remote  NS-VCs: %zu, IPv4 Endpoints: %zu, IPv6 Endpoints: %zu%s",
		prefix, gss->num_max_nsvcs, gss->num_max_ip4_remote, gss->num_max_ip6_remote, VTY_NEWLINE);

	if (gss->local.num_ip4 && gss->remote.num_ip4) {
		vty_out(vty, "%sLocal IPv4 Endpoints:%s", prefix, VTY_NEWLINE);
		for (i = 0; i < gss->local.num_ip4; i++)
			vty_dump_sns_ip4(vty, prefix, &gss->local.ip4[i]);

		vty_out(vty, "%sRemote IPv4 Endpoints:%s", prefix, VTY_NEWLINE);
		for (i = 0; i < gss->remote.num_ip4; i++)
			vty_dump_sns_ip4(vty, prefix, &gss->remote.ip4[i]);
	}

	if (gss->local.num_ip6 && gss->remote.num_ip6) {
		vty_out(vty, "%sLocal IPv6 Endpoints:%s", prefix, VTY_NEWLINE);
		for (i = 0; i < gss->local.num_ip6; i++)
			vty_dump_sns_ip6(vty, prefix, &gss->local.ip6[i]);

		vty_out(vty, "%sRemote IPv6 Endpoints:%s", prefix, VTY_NEWLINE);
		for (i = 0; i < gss->remote.num_ip6; i++)
			vty_dump_sns_ip6(vty, prefix, &gss->remote.ip6[i]);
	}
}

/*! write IP-SNS to a vty
 *  \param[in] vty VTY to which the state shall be printed
 *  \param[in] nse NS Entity whose IP-SNS state shall be printed */
void ns2_sns_write_vty(struct vty *vty, const struct gprs_ns2_nse *nse)
{
	struct ns2_sns_state *gss;
	struct osmo_sockaddr_str addr_str;
	struct sns_endpoint *endpoint;

	if (!nse->bss_sns_fi)
		return;

	gss = (struct ns2_sns_state *) nse->bss_sns_fi->priv;
	llist_for_each_entry(endpoint, &gss->sns_endpoints, list) {
		/* It's unlikely that an error happens, but let's better be safe. */
		if (osmo_sockaddr_str_from_sockaddr(&addr_str, &endpoint->saddr.u.sas) != 0)
			addr_str = (struct osmo_sockaddr_str) { .ip = "<INVALID>" };
		vty_out(vty, "  ip-sns-remote %s %u%s", addr_str.ip, addr_str.port, VTY_NEWLINE);
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

	if (nse->dialect != GPRS_NS2_DIALECT_SNS) {
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
		osmo_fsm_inst_dispatch(nse->bss_sns_fi, NS2_SNS_EV_REQ_SELECT_ENDPOINT, NULL);

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

	if (nse->dialect != GPRS_NS2_DIALECT_SNS) {
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

	/* gprs_ns2_free_nsvcs() will trigger NS2_SNS_EV_REQ_NO_NSVC on the last NS-VC
	 * and restart SNS SIZE procedure which selects a new initial */
	LOGNSE(nse, LOGL_INFO, "Current in-use SNS endpoint is being removed."
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

	if (nse->dialect != GPRS_NS2_DIALECT_SNS) {
		return -EINVAL;
	}

	gss = nse->bss_sns_fi->priv;
	llist_for_each_entry(endpoint, &gss->sns_endpoints, list)
		count++;

	return count;
}

void ns2_sns_notify_alive(struct gprs_ns2_nse *nse, struct gprs_ns2_vc *nsvc, bool alive)
{
	struct ns2_sns_state *gss;
	struct gprs_ns2_vc *tmp;

	if (!nse->bss_sns_fi)
		return;

	gss = nse->bss_sns_fi->priv;
	if (nse->bss_sns_fi->state != GPRS_SNS_ST_CONFIGURED && nse->bss_sns_fi->state != GPRS_SNS_ST_LOCAL_PROCEDURE)
		return;

	if (gss->block_no_nsvc_events)
		return;

	if (gss->alive && nse->sum_sig_weight == 0) {
		sns_failed(nse->bss_sns_fi, "No signalling NSVC available");
		return;
	}

	/* check if this is the current SNS NS-VC */
	if (nsvc == gss->sns_nsvc && !alive) {
		/* only replace the SNS NS-VC if there are other alive NS-VC.
		 * There aren't any other alive NS-VC when the SNS fsm just reached CONFIGURED
		 * and couldn't confirm yet if the NS-VC comes up */
		llist_for_each_entry(tmp, &nse->nsvc, list) {
			if (nsvc == tmp)
				continue;
			if (ns2_vc_is_unblocked(nsvc)) {
				ns2_sns_replace_nsvc(nsvc);
				break;
			}
		}
	}

	if (alive == gss->alive)
		return;

	if (alive) {
		/* we need at least a signalling NSVC before become alive */
		if (nse->sum_sig_weight == 0)
			return;
		gss->alive = true;
		osmo_fsm_inst_dispatch(nse->bss_sns_fi, NS2_SNS_EV_REQ_NSVC_ALIVE, NULL);
	} else {
		/* is there at least another alive nsvc? */
		llist_for_each_entry(tmp, &nse->nsvc, list) {
			if (ns2_vc_is_unblocked(tmp))
				return;
		}

		/* all NS-VC have failed */
		gss->alive = false;
		osmo_fsm_inst_dispatch(nse->bss_sns_fi, NS2_SNS_EV_REQ_NO_NSVC, NULL);
	}
}

int gprs_ns2_sns_add_bind(struct gprs_ns2_nse *nse,
			  struct gprs_ns2_vc_bind *bind)
{
	struct ns2_sns_state *gss;
	struct ns2_sns_bind *tmp;

	OSMO_ASSERT(nse->bss_sns_fi);
	gss = nse->bss_sns_fi->priv;

	if (!gprs_ns2_is_ip_bind(bind)) {
		return -EINVAL;
	}

	if (!llist_empty(&gss->binds)) {
		llist_for_each_entry(tmp, &gss->binds, list) {
			if (tmp->bind == bind)
				return -EALREADY;
		}
	}

	tmp = talloc_zero(gss, struct ns2_sns_bind);
	if (!tmp)
		return -ENOMEM;
	tmp->bind = bind;
	llist_add_tail(&tmp->list, &gss->binds);

	osmo_fsm_inst_dispatch(nse->bss_sns_fi, NS2_SNS_EV_REQ_ADD_BIND, tmp);
	return 0;
}

/* Remove a bind from the SNS. All assosiated NSVC must be removed. */
int gprs_ns2_sns_del_bind(struct gprs_ns2_nse *nse,
			     struct gprs_ns2_vc_bind *bind)
{
	struct ns2_sns_state *gss;
	struct ns2_sns_bind *tmp, *tmp2;
	bool found = false;

	if (!nse->bss_sns_fi)
		return -EINVAL;

	gss = nse->bss_sns_fi->priv;
	if (gss->initial_bind && gss->initial_bind->bind == bind) {
		if (gss->initial_bind->list.prev == &gss->binds)
			gss->initial_bind = NULL;
		else
			gss->initial_bind = llist_entry(gss->initial_bind->list.prev, struct ns2_sns_bind, list);
	}

	llist_for_each_entry_safe(tmp, tmp2, &gss->binds, list) {
		if (tmp->bind == bind) {
			llist_del(&tmp->list);
			found = true;
			break;
		}
	}

	if (!found)
		return -ENOENT;

	osmo_fsm_inst_dispatch(nse->bss_sns_fi, NS2_SNS_EV_REQ_DELETE_BIND, tmp);
	return 0;
}

/* Update SNS weights for a bind (local endpoint).
 * \param[in] bind the bind which has been updated
 */
void ns2_sns_update_weights(struct gprs_ns2_vc_bind *bind)
{
	struct ns2_sns_bind *sbind;
	struct gprs_ns2_nse *nse;
	struct ns2_sns_state *gss;
	const struct osmo_sockaddr *addr = gprs_ns2_ip_bind_sockaddr(bind);

	llist_for_each_entry(nse, &bind->nsi->nse, list) {
		if (!nse->bss_sns_fi)
			continue;

		gss = nse->bss_sns_fi->priv;
		if (addr->u.sa.sa_family != gss->family)
			return;

		llist_for_each_entry(sbind, &gss->binds, list) {
			if (sbind->bind == bind) {
				osmo_fsm_inst_dispatch(gss->nse->bss_sns_fi, NS2_SNS_EV_REQ_CHANGE_WEIGHT, sbind);
				break;
			}
		}
	}
}




/***********************************************************************
 * SGSN role
 ***********************************************************************/

/* cleanup all state. If nsvc is given, don't remove this nsvc. (nsvc is given when a SIZE PDU received) */
static void ns2_clear_sgsn(struct ns2_sns_state *gss, struct gprs_ns2_vc *size_nsvc)
{
	struct gprs_ns2_vc *nsvc, *nsvc2;

	ns2_clear_procedures(gss);
	ns2_clear_elems(&gss->local);
	ns2_clear_elems(&gss->remote);
	gss->block_no_nsvc_events = true;
	llist_for_each_entry_safe(nsvc, nsvc2, &gss->nse->nsvc, list) {
		/* Ignore the NSVC over which the SIZE PDU got received */
		if (size_nsvc && size_nsvc == nsvc)
			continue;

		gprs_ns2_free_nsvc(nsvc);
	}
	gss->block_no_nsvc_events = false;
}

static void ns2_sns_st_sgsn_unconfigured_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;

	ns2_clear_sgsn(gss, NULL);
}

static void ns2_sns_st_sgsn_unconfigured(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	OSMO_ASSERT(gss->role == GPRS_SNS_ROLE_SGSN);
	/* do nothing; Rx SNS-SIZE handled in ns2_sns_st_all_action_sgsn() */
}

/* We're waiting for inbound SNS-CONFIG from the BSS */
static void ns2_sns_st_sgsn_wait_config(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct gprs_ns2_inst *nsi = nse->nsi;
	uint8_t cause;
	int rc;

	OSMO_ASSERT(gss->role == GPRS_SNS_ROLE_SGSN);

	switch (event) {
	case NS2_SNS_EV_RX_CONFIG:
	case NS2_SNS_EV_RX_CONFIG_END:
		rc = ns_sns_append_remote_eps(fi, data);
		if (rc < 0) {
			cause = -rc;
			ns2_tx_sns_config_ack(gss->sns_nsvc, &cause);
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 0);
			return;
		}
		/* only change state if last CONFIG was received */
		if (event == NS2_SNS_EV_RX_CONFIG_END) {
			/* ensure sum of data weight / sig weights is > 0 */
			if (ip46_weight_sum_data(&gss->remote) == 0 || ip46_weight_sum_sig(&gss->remote) == 0) {
				cause = NS_CAUSE_INVAL_WEIGH;
				ns2_tx_sns_config_ack(gss->sns_nsvc, &cause);
				osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 0);
				break;
			}
			ns2_tx_sns_config_ack(gss->sns_nsvc, NULL);
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_SGSN_WAIT_CONFIG_ACK, nsi->timeout[NS_TOUT_TSNS_PROV], 3);
		} else {
			/* just send CONFIG-ACK */
			ns2_tx_sns_config_ack(gss->sns_nsvc, NULL);
			osmo_timer_schedule(&fi->timer, nse->nsi->timeout[NS_TOUT_TSNS_PROV], 0);
		}
		break;
	}
}

static void ns2_sns_st_sgsn_wait_config_ack_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	OSMO_ASSERT(gss->role == GPRS_SNS_ROLE_SGSN);

	/* transmit SGSN-oriented SNS-CONFIG */
	ns2_tx_sns_config(gss->sns_nsvc, true, gss->local.ip4, gss->local.num_ip4,
			  gss->local.ip6, gss->local.num_ip6);
}

/* We're waiting for SNS-CONFIG-ACK from the BSS (in response to our outbound SNS-CONFIG) */
static void ns2_sns_st_sgsn_wait_config_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct tlv_parsed *tp = NULL;

	OSMO_ASSERT(gss->role == GPRS_SNS_ROLE_SGSN);

	switch (event) {
	case NS2_SNS_EV_RX_CONFIG_ACK:
		tp = data;
		if (TLVP_VAL_MINLEN(tp, NS_IE_CAUSE, 1)) {
			LOGPFSML(fi, LOGL_ERROR, "Rx SNS-CONFIG-ACK with cause %s\n",
				 gprs_ns2_cause_str(*TLVP_VAL(tp, NS_IE_CAUSE)));
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 0);
			break;
		}
		/* we currently only send one SNS-CONFIG with END FLAG */
		if (true) {
			create_missing_nsvcs(fi);
			/* start the test procedure on ALL NSVCs! */
			gprs_ns2_start_alive_all_nsvcs(nse);
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_CONFIGURED, ns_sns_configured_timeout(fi), 4);
		}
		break;
	}
}

/* SGSN-side SNS state machine */
static const struct osmo_fsm_state ns2_sns_sgsn_states[] = {
	[GPRS_SNS_ST_UNCONFIGURED] = {
		.in_event_mask = 0, /* handled by all_state_action */
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_SGSN_WAIT_CONFIG),
		.name = "UNCONFIGURED",
		.action = ns2_sns_st_sgsn_unconfigured,
		.onenter = ns2_sns_st_sgsn_unconfigured_onenter,
	},
	[GPRS_SNS_ST_SGSN_WAIT_CONFIG] = {
		.in_event_mask = S(NS2_SNS_EV_RX_CONFIG) |
				 S(NS2_SNS_EV_RX_CONFIG_END),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_SGSN_WAIT_CONFIG) |
				  S(GPRS_SNS_ST_SGSN_WAIT_CONFIG_ACK),
		.name = "SGSN_WAIT_CONFIG",
		.action = ns2_sns_st_sgsn_wait_config,
	},
	[GPRS_SNS_ST_SGSN_WAIT_CONFIG_ACK] = {
		.in_event_mask = S(NS2_SNS_EV_RX_CONFIG_ACK),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_SGSN_WAIT_CONFIG) |
				  S(GPRS_SNS_ST_SGSN_WAIT_CONFIG_ACK) |
				  S(GPRS_SNS_ST_CONFIGURED),
		.name = "SGSN_WAIT_CONFIG_ACK",
		.action = ns2_sns_st_sgsn_wait_config_ack,
		.onenter = ns2_sns_st_sgsn_wait_config_ack_onenter,
	},
	[GPRS_SNS_ST_CONFIGURED] = {
		.in_event_mask = S(NS2_SNS_EV_RX_ADD) |
				 S(NS2_SNS_EV_RX_DELETE) |
				 S(NS2_SNS_EV_RX_CHANGE_WEIGHT) |
				 S(NS2_SNS_EV_REQ_NSVC_ALIVE),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_SGSN_WAIT_CONFIG) |
				  S(GPRS_SNS_ST_LOCAL_PROCEDURE),
		.name = "CONFIGURED",
		/* shared with BSS side; once configured there's no difference */
		.action = ns2_sns_st_configured,
		.onenter = ns2_sns_st_configured_onenter,
	},
	[GPRS_SNS_ST_LOCAL_PROCEDURE] = {
		.in_event_mask = S(NS2_SNS_EV_RX_ADD) |
				 S(NS2_SNS_EV_RX_DELETE) |
				 S(NS2_SNS_EV_RX_CHANGE_WEIGHT) |
				 S(NS2_SNS_EV_RX_ACK) |
				 S(NS2_SNS_EV_REQ_CHANGE_WEIGHT) |
				 S(NS2_SNS_EV_REQ_NSVC_ALIVE),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_CONFIGURED) |
				  S(GPRS_SNS_ST_LOCAL_PROCEDURE),
		.name = "LOCAL_PROCEDURE",
		/* shared with BSS side; once configured there's no difference */
		.action = ns2_sns_st_local_procedure,
		.onenter = ns2_sns_st_local_procedure_onenter,
	},
};

static int ns2_sns_fsm_sgsn_timer_cb(struct osmo_fsm_inst *fi)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct gprs_ns2_nse *nse = nse_inst_from_fi(fi);
	struct gprs_ns2_inst *nsi = nse->nsi;

	gss->N++;
	switch (fi->T) {
	case 3:
		if (gss->N >= nsi->timeout[NS_TOUT_TSNS_CONFIG_RETRIES]) {
			LOGPFSML(fi, LOGL_ERROR, "NSE %d: SGSN Config retries failed. Giving up.\n", nse->nsei);
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, nsi->timeout[NS_TOUT_TSNS_PROV], 3);
		} else {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_SGSN_WAIT_CONFIG_ACK, nsi->timeout[NS_TOUT_TSNS_PROV], 3);
		}
		break;
	case 4:
		LOGPFSML(fi, LOGL_ERROR, "NSE %d: Config succeeded but no NS-VC came online.\n", nse->nsei);
		break;
	case 5:
		if (gss->N >= nsi->timeout[NS_TOUT_TSNS_PROCEDURES_RETRIES]) {
			sns_failed(fi, "SNS Procedure retries failed.");
		} else {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_LOCAL_PROCEDURE, nsi->timeout[NS_TOUT_TSNS_PROV],
						fi->T);
		}
		break;
	}

	return 0;
}

/* allstate-action for SGSN role */
static void ns2_sns_st_all_action_sgsn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ns2_sns_state *gss = (struct ns2_sns_state *) fi->priv;
	struct tlv_parsed *tp = NULL;
	size_t num_local_eps, num_remote_eps;
	uint8_t flag;
	uint8_t cause;

	OSMO_ASSERT(gss->role == GPRS_SNS_ROLE_SGSN);

	switch (event) {
	case NS2_SNS_EV_RX_SIZE:
		tp = (struct tlv_parsed *) data;
		/* check for mandatory / conditional IEs */
		if (!TLVP_PRES_LEN(tp, NS_IE_RESET_FLAG, 1) ||
		    !TLVP_PRES_LEN(tp, NS_IE_MAX_NR_NSVC, 2)) {
			cause = NS_CAUSE_MISSING_ESSENT_IE;
			ns2_tx_sns_size_ack(gss->sns_nsvc, &cause);
			if (fi->state == GPRS_SNS_ST_UNCONFIGURED)
				sns_failed(fi, "Rx Size: Missing essential IE");
			break;
		}
		if (!TLVP_PRES_LEN(tp, NS_IE_IPv4_EP_NR, 2) &&
		    !TLVP_PRES_LEN(tp, NS_IE_IPv6_EP_NR, 2)) {
			cause = NS_CAUSE_MISSING_ESSENT_IE;
			ns2_tx_sns_size_ack(gss->sns_nsvc, &cause);
			if (fi->state == GPRS_SNS_ST_UNCONFIGURED)
				sns_failed(fi, "Rx Size: Missing essential IE");
			break;
		}
		if (TLVP_PRES_LEN(tp, NS_IE_IPv4_EP_NR, 2))
			gss->num_max_ip4_remote = tlvp_val16be(tp, NS_IE_IPv4_EP_NR);
		if (TLVP_PRES_LEN(tp, NS_IE_IPv6_EP_NR, 2))
			gss->num_max_ip6_remote = tlvp_val16be(tp, NS_IE_IPv6_EP_NR);
		/* decide if we go for IPv4 or IPv6 */
		if (gss->num_max_ip6_remote && ns2_sns_count_num_local_ep(fi, AF_INET6)) {
			gss->family = AF_INET6;
			ns2_sns_compute_local_ep_from_binds(fi);
			num_local_eps = gss->local.num_ip6;
			num_remote_eps = gss->num_max_ip6_remote;
		} else if (gss->num_max_ip4_remote && ns2_sns_count_num_local_ep(fi, AF_INET)) {
			gss->family = AF_INET;
			ns2_sns_compute_local_ep_from_binds(fi);
			num_local_eps = gss->local.num_ip4;
			num_remote_eps = gss->num_max_ip4_remote;
		} else {
			if (gss->local.num_ip4 && !gss->num_max_ip4_remote)
				cause = NS_CAUSE_INVAL_NR_IPv4_EP;
			else
				cause = NS_CAUSE_INVAL_NR_IPv6_EP;
			ns2_tx_sns_size_ack(gss->sns_nsvc, &cause);
			if (fi->state == GPRS_SNS_ST_UNCONFIGURED)
				sns_failed(fi, "Rx Size: Invalid Nr of IPv4/IPv6 EPs");
			break;
		}
		/* ensure number of NS-VCs is sufficient for full mesh */
		gss->num_max_nsvcs = tlvp_val16be(tp, NS_IE_MAX_NR_NSVC);
		if (gss->num_max_nsvcs < num_remote_eps * num_local_eps) {
			LOGPFSML(fi, LOGL_ERROR, "%zu local and %zu remote EPs, requires %zu NS-VC, "
				 "but BSS supports only %zu maximum NS-VCs\n", num_local_eps,
				 num_remote_eps, num_local_eps * num_remote_eps, gss->num_max_nsvcs);
			cause = NS_CAUSE_INVAL_NR_NS_VC;
			ns2_tx_sns_size_ack(gss->sns_nsvc, &cause);
			if (fi->state == GPRS_SNS_ST_UNCONFIGURED)
				sns_failed(fi, NULL);
			break;
		}
		/* perform state reset, if requested */
		flag = *TLVP_VAL(tp, NS_IE_RESET_FLAG);
		if (flag & 1) {
			/* clear all state */
			/* TODO: ensure gss->sns_nsvc is always the NSVC on which we received the SIZE PDU */
			gss->N = 0;
			ns2_clear_sgsn(gss, gss->sns_nsvc);
			/* keep the NSVC we need for SNS, but unconfigure it */
			gss->sns_nsvc->sig_weight = 0;
			gss->sns_nsvc->data_weight = 0;
			gss->block_no_nsvc_events = true;
			ns2_vc_force_unconfigured(gss->sns_nsvc);
			gss->block_no_nsvc_events = false;
			ns2_sns_compute_local_ep_from_binds(fi);
		}

		if (fi->state == GPRS_SNS_ST_UNCONFIGURED && !(flag & 1)) {
			sns_failed(fi, "Rx Size without Reset flag, but NSE is unknown");
			break;
		}

		/* send SIZE_ACK */
		ns2_tx_sns_size_ack(gss->sns_nsvc, NULL);
		/* only wait for SNS-CONFIG in case of Reset flag */
		if (flag & 1)
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_SGSN_WAIT_CONFIG, 0, 0);
		break;
	case NS2_SNS_EV_REQ_FREE_NSVCS:
		sns_failed(fi, "On user request to free all NSVCs");
		break;
	default:
		ns2_sns_st_all_action(fi, event, data);
		break;
	}
}

static struct osmo_fsm gprs_ns2_sns_sgsn_fsm = {
	.name = "GPRS-NS2-SNS-SGSN",
	.states = ns2_sns_sgsn_states,
	.num_states = ARRAY_SIZE(ns2_sns_sgsn_states),
	.allstate_event_mask = S(NS2_SNS_EV_RX_SIZE) |
			       S(NS2_SNS_EV_REQ_NO_NSVC) |
			       S(NS2_SNS_EV_REQ_FREE_NSVCS) |
			       S(NS2_SNS_EV_REQ_ADD_BIND) |
			       S(NS2_SNS_EV_REQ_CHANGE_WEIGHT) |
			       S(NS2_SNS_EV_REQ_DELETE_BIND),
	.allstate_action = ns2_sns_st_all_action_sgsn,
	.cleanup = NULL,
	.timer_cb = ns2_sns_fsm_sgsn_timer_cb,
	.event_names = gprs_sns_event_names,
	.pre_term = NULL,
	.log_subsys = DLNS,
};

/*! Allocate an IP-SNS FSM for the SGSN side.
 *  \param[in] nse NS Entity in which the FSM runs
 *  \param[in] id string identifier
 *  \returns FSM instance on success; NULL on error */
struct osmo_fsm_inst *ns2_sns_sgsn_fsm_alloc(struct gprs_ns2_nse *nse, const char *id)
{
	struct osmo_fsm_inst *fi;
	struct ns2_sns_state *gss;

	fi = osmo_fsm_inst_alloc(&gprs_ns2_sns_sgsn_fsm, nse, NULL, LOGL_DEBUG, id);
	if (!fi)
		return fi;

	gss = talloc_zero(fi, struct ns2_sns_state);
	if (!gss)
		goto err;

	fi->priv = gss;
	gss->nse = nse;
	gss->role = GPRS_SNS_ROLE_SGSN;
	INIT_LLIST_HEAD(&gss->sns_endpoints);
	INIT_LLIST_HEAD(&gss->binds);
	INIT_LLIST_HEAD(&gss->procedures);

	return fi;
err:
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
	return NULL;
}




/* initialize osmo_ctx on main tread */
static __attribute__((constructor)) void on_dso_load_ctx(void)
{
	OSMO_ASSERT(osmo_fsm_register(&gprs_ns2_sns_bss_fsm) == 0);
	OSMO_ASSERT(osmo_fsm_register(&gprs_ns2_sns_sgsn_fsm) == 0);
}
