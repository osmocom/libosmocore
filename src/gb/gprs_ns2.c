/*! \file gprs_ns2.c
 * GPRS Networks Service (NS) messages on the Gb interface.
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05)
 * as well as its successor 3GPP TS 48.016 */

/* (C) 2009-2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016-2017,2020 sysmocom - s.f.m.c. GmbH
 * Author: Alexander Couzens <lynxis@fe80.eu>
 *
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

/*! \addtogroup libgb
 *  @{
 *
 * GPRS Networks Service (NS) messages on the Gb interface
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05)
 *
 * Some introduction into NS:  NS is used typically on top of frame relay,
 * but in the ip.access world it is encapsulated in UDP packets.  It serves
 * as an intermediate shim betwen BSSGP and the underlying medium.  It doesn't
 * do much, apart from providing congestion notification and status indication.
 *
 * Terms:
 *
 * 	NS		Network Service
 * 	NSVC		NS Virtual Connection
 * 	NSEI		NS Entity Identifier
 * 	NSVL		NS Virtual Link
 * 	NSVLI		NS Virtual Link Identifier
 * 	BVC		BSSGP Virtual Connection
 * 	BVCI		BSSGP Virtual Connection Identifier
 * 	NSVCG		NS Virtual Connection Goup
 * 	Blocked		NS-VC cannot be used for user traffic
 * 	Alive		Ability of a NS-VC to provide communication
 *
 * There can be multiple BSSGP virtual connections over one (group of) NSVC's.  BSSGP will
 * therefore identify the BSSGP virtual connection by a BVCI passed down to NS.
 * NS then has to figure out which NSVC's are responsible for this BVCI.
 * Those mappings are administratively configured.
 *
 * This implementation has the following limitations:
 * - NSVCI 65535 and 65534 are reserved for internal use
 * - There are no BLOCK and UNBLOCK timers (yet?)
 *
 * \file gprs_ns2.c */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gsm/prim.h>
#include <osmocom/gsm/tlv.h>

#include "gprs_ns2_internal.h"

#define ns_set_state(ns_, st_) ns_set_state_with_log(ns_, st_, false, __FILE__, __LINE__)
#define ns_set_remote_state(ns_, st_) ns_set_state_with_log(ns_, st_, true, __FILE__, __LINE__)
#define ns_mark_blocked(ns_) ns_set_state(ns_, (ns_)->state | NSE_S_BLOCKED)
#define ns_mark_unblocked(ns_) ns_set_state(ns_, (ns_)->state & (~NSE_S_BLOCKED));
#define ns_mark_alive(ns_) ns_set_state(ns_, (ns_)->state | NSE_S_ALIVE)
#define ns_mark_dead(ns_) ns_set_state(ns_, (ns_)->state & (~NSE_S_ALIVE));

/* HACK: The NS_IE_IP_ADDR does not follow any known TLV rules.
 * Since it's a hard ABI break to implement 16 bit tag with fixed length entries to workaround it,
 * the parser will be called with ns_att_tlvdef1 and if it's failed with ns_att_tlvdef2.
 * The TLV parser depends on 8bit tag in many places.
 * The NS_IE_IP_ADDR is only valid for SNS_ACK SNS_ADD and SNS_DELETE.
 */
static const struct tlv_definition ns_att_tlvdef1 = {
	.def = {
		[NS_IE_CAUSE]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_VCI]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_PDU]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_BVCI]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_NSEI]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_IPv4_LIST] = { TLV_TYPE_TvLV, 0 },
		[NS_IE_IPv6_LIST] = { TLV_TYPE_TvLV, 0 },
		[NS_IE_MAX_NR_NSVC] = { TLV_TYPE_FIXED, 2 },
		[NS_IE_IPv4_EP_NR] = { TLV_TYPE_FIXED, 2 },
		[NS_IE_IPv6_EP_NR] = { TLV_TYPE_FIXED, 2 },
		[NS_IE_RESET_FLAG] = { TLV_TYPE_TV, 0 },
		/* NS_IE_IP_ADDR in the IPv4 version */
		[NS_IE_IP_ADDR] = { TLV_TYPE_FIXED, 5 },
	},
};

static const struct tlv_definition ns_att_tlvdef2 = {
	.def = {
		[NS_IE_CAUSE]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_VCI]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_PDU]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_BVCI]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_NSEI]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_IPv4_LIST] = { TLV_TYPE_TvLV, 0 },
		[NS_IE_IPv6_LIST] = { TLV_TYPE_TvLV, 0 },
		[NS_IE_MAX_NR_NSVC] = { TLV_TYPE_FIXED, 2 },
		[NS_IE_IPv4_EP_NR] = { TLV_TYPE_FIXED, 2 },
		[NS_IE_IPv6_EP_NR] = { TLV_TYPE_FIXED, 2 },
		[NS_IE_RESET_FLAG] = { TLV_TYPE_TV, 0 },
		/* NS_IE_IP_ADDR in the IPv6 version */
		[NS_IE_IP_ADDR] = { TLV_TYPE_FIXED, 17 },
	},
};


/* Section 10.3.2, Table 13 */
const struct value_string gprs_ns2_cause_strs[] = {
	{ NS_CAUSE_TRANSIT_FAIL,	"Transit network failure" },
	{ NS_CAUSE_OM_INTERVENTION, 	"O&M intervention" },
	{ NS_CAUSE_EQUIP_FAIL,		"Equipment failure" },
	{ NS_CAUSE_NSVC_BLOCKED,	"NS-VC blocked" },
	{ NS_CAUSE_NSVC_UNKNOWN,	"NS-VC unknown" },
	{ NS_CAUSE_BVCI_UNKNOWN,	"BVCI unknown" },
	{ NS_CAUSE_SEM_INCORR_PDU,	"Semantically incorrect PDU" },
	{ NS_CAUSE_PDU_INCOMP_PSTATE,	"PDU not compatible with protocol state" },
	{ NS_CAUSE_PROTO_ERR_UNSPEC,	"Protocol error, unspecified" },
	{ NS_CAUSE_INVAL_ESSENT_IE,	"Invalid essential IE" },
	{ NS_CAUSE_MISSING_ESSENT_IE,	"Missing essential IE" },
	{ NS_CAUSE_INVAL_NR_IPv4_EP,	"Invalid Number of IPv4 Endpoints" },
	{ NS_CAUSE_INVAL_NR_IPv6_EP,	"Invalid Number of IPv6 Endpoints" },
	{ NS_CAUSE_INVAL_NR_NS_VC,	"Invalid Number of NS-VCs" },
	{ NS_CAUSE_INVAL_WEIGH,		"Invalid Weights" },
	{ NS_CAUSE_UNKN_IP_EP,		"Unknown IP Endpoint" },
	{ NS_CAUSE_UNKN_IP_ADDR,	"Unknown IP Address" },
	{ NS_CAUSE_UNKN_IP_TEST_FAILED,	"IP Test Failed" },
	{ 0, NULL }
};

static const struct rate_ctr_desc ns_ctr_description[] = {
	[NS_CTR_PKTS_IN]	= { "packets:in", 	"Packets at NS Level  ( In)" },
	[NS_CTR_PKTS_OUT] 	= { "packets:out",	"Packets at NS Level  (Out)" },
	[NS_CTR_PKTS_OUT_DROP] 	= { "packets:out:drop",	"Dropped Packets      (Out)" },
	[NS_CTR_BYTES_IN]	= { "bytes:in",		"Bytes at NS Level    ( In)" },
	[NS_CTR_BYTES_OUT]	= { "bytes:out",	"Bytes at NS Level    (Out)" },
	[NS_CTR_BYTES_OUT_DROP]	= { "bytes:out:drop",	"Dropped Bytes        (Out)" },
	[NS_CTR_BLOCKED]	= { "blocked",		"NS-VC Block count         " },
	[NS_CTR_UNBLOCKED]	= { "unblocked",	"NS-VC Unblock count       " },
	[NS_CTR_DEAD] 		= { "dead",		"NS-VC gone dead count     " },
	[NS_CTR_REPLACED]	= { "replaced",		"NS-VC replaced other count" },
	[NS_CTR_NSEI_CHG]	= { "nsei-chg",		"NS-VC changed NSEI count  " },
	[NS_CTR_INV_VCI]	= { "inv-nsvci",	"NS-VCI was invalid count  " },
	[NS_CTR_INV_NSEI]	= { "inv-nsei",		"NSEI was invalid count    " },
	[NS_CTR_LOST_ALIVE]	= { "lost:alive",	"ALIVE ACK missing count   " },
	[NS_CTR_LOST_RESET]	= { "lost:reset",	"RESET ACK missing count   " },
};

static const struct rate_ctr_group_desc nse_ctrg_desc = {
	.group_name_prefix = "ns:nse",
	.group_description = "NSE Peer Statistics",
	.num_ctr = ARRAY_SIZE(ns_ctr_description),
	.ctr_desc = ns_ctr_description,
	.class_id = OSMO_STATS_CLASS_PEER,
};

static const struct rate_ctr_group_desc nsvc_ctrg_desc = {
	.group_name_prefix = "ns:nsvc",
	.group_description = "NSVC Peer Statistics",
	.num_ctr = ARRAY_SIZE(ns_ctr_description),
	.ctr_desc = ns_ctr_description,
	.class_id = OSMO_STATS_CLASS_PEER,
};


static const struct osmo_stat_item_desc nsvc_stat_description[] = {
	[NS_STAT_ALIVE_DELAY] = { "alive.delay", "ALIVE response time        ", "ms", 16, 0 },
};

static const struct osmo_stat_item_group_desc nsvc_statg_desc = {
	.group_name_prefix = "ns.nsvc",
	.group_description = "NSVC Peer Statistics",
	.num_items = ARRAY_SIZE(nsvc_stat_description),
	.item_desc = nsvc_stat_description,
	.class_id = OSMO_STATS_CLASS_PEER,
};

const struct osmo_stat_item_desc nsbind_stat_description[] = {
	[NS2_BIND_STAT_BACKLOG_LEN] = { "tx_backlog_length",	"Transmit backlog length", "packets", 16, 0 },
};

static const struct osmo_stat_item_group_desc nsbind_statg_desc = {
	.group_name_prefix = "ns.bind",
	.group_description = "NS Bind Statistics",
	.num_items = ARRAY_SIZE(nsbind_stat_description),
	.item_desc = nsbind_stat_description,
	.class_id = OSMO_STATS_CLASS_PEER,
};

const struct value_string gprs_ns2_aff_cause_prim_strs[] = {
	{ GPRS_NS2_AFF_CAUSE_VC_FAILURE,	"NSVC failure" },
	{ GPRS_NS2_AFF_CAUSE_VC_RECOVERY,	"NSVC recovery" },
	{ GPRS_NS2_AFF_CAUSE_FAILURE,		"NSE failure" },
	{ GPRS_NS2_AFF_CAUSE_RECOVERY,		"NSE recovery" },
	{ GPRS_NS2_AFF_CAUSE_SNS_CONFIGURED,	"NSE SNS configured" },
	{ GPRS_NS2_AFF_CAUSE_SNS_FAILURE,	"NSE SNS failure" },
	{ GPRS_NS2_AFF_CAUSE_SNS_NO_ENDPOINTS,	"NSE SNS no endpoints"},
	{ GPRS_NS2_AFF_CAUSE_MTU_CHANGE,	"NSE MTU changed" },
	{ 0, NULL }
};

const struct value_string gprs_ns2_prim_strs[] = {
	{ GPRS_NS2_PRIM_UNIT_DATA,	"UNIT DATA" },
	{ GPRS_NS2_PRIM_CONGESTION,	"CONGESTION" },
	{ GPRS_NS2_PRIM_STATUS,		"STATUS" },
	{ 0, NULL }
};

const struct value_string gprs_ns2_lltype_strs[] = {
	{ GPRS_NS2_LL_UDP,	"UDP" },
	{ GPRS_NS2_LL_FR_GRE,	"FR_GRE" },
	{ GPRS_NS2_LL_FR,	"FR" },
	{ 0, NULL }
};

/*! string-format a given NS-VC into a user-supplied buffer.
 *  \param[in] buf user-allocated output buffer
 *  \param[in] buf_len size of user-allocated output buffer in bytes
 *  \param[in] nsvc NS-VC to be string-formatted
 *  \return pointer to buf on success; NULL on error */
char *gprs_ns2_ll_str_buf(char *buf, size_t buf_len, struct gprs_ns2_vc *nsvc)
{
	const struct osmo_sockaddr *local;
	const struct osmo_sockaddr *remote;
	struct osmo_sockaddr_str local_str;
	struct osmo_sockaddr_str remote_str;

	if (!buf_len)
		return NULL;

	switch (nsvc->nse->ll) {
	case GPRS_NS2_LL_UDP:
		if (!gprs_ns2_is_ip_bind(nsvc->bind)) {
			buf[0] = '\0';
			return buf;
		}

		local = gprs_ns2_ip_bind_sockaddr(nsvc->bind);
		remote = gprs_ns2_ip_vc_remote(nsvc);
		if (osmo_sockaddr_str_from_sockaddr(&local_str, &local->u.sas))
			strcpy(local_str.ip, "invalid");
		if (osmo_sockaddr_str_from_sockaddr(&remote_str, &remote->u.sas))
			strcpy(remote_str.ip, "invalid");

		if (nsvc->nsvci_is_valid)
			snprintf(buf, buf_len, "udp)[%s]:%u<%u>[%s]:%u",
				 local_str.ip, local_str.port,
				 nsvc->nsvci,
				 remote_str.ip, remote_str.port);
		else
			snprintf(buf, buf_len, "udp)[%s]:%u<>[%s]:%u",
				 local_str.ip, local_str.port,
				 remote_str.ip, remote_str.port);
		break;
	case GPRS_NS2_LL_FR_GRE:
		snprintf(buf, buf_len, "frgre)");
		break;
	case GPRS_NS2_LL_FR:
		snprintf(buf, buf_len, "fr)netif: %s dlci: %u", gprs_ns2_fr_bind_netif(nsvc->bind),
			 gprs_ns2_fr_nsvc_dlci(nsvc));
		break;
	default:
		snprintf(buf, buf_len, "unknown)");
		break;
	}

	buf[buf_len - 1] = '\0';

	return buf;
}

/* udp is the longest: udp)[IP6]:65536<65536>[IP6]:65536 */
#define NS2_LL_MAX_STR 4+2*(INET6_ADDRSTRLEN+9)+8

/*! string-format a given NS-VC to a thread-local static buffer.
 *  \param[in] nsvc NS-VC to be string-formatted
 *  \return pointer to the string on success; NULL on error */
const char *gprs_ns2_ll_str(struct gprs_ns2_vc *nsvc)
{
	static __thread char buf[NS2_LL_MAX_STR];
	return gprs_ns2_ll_str_buf(buf, sizeof(buf), nsvc);
}

/*! string-format a given NS-VC to a dynamically allocated string.
 *  \param[in] ctx talloc context from which to allocate
 *  \param[in] nsvc NS-VC to be string-formatted
 *  \return pointer to the string on success; NULL on error */
char *gprs_ns2_ll_str_c(const void *ctx, struct gprs_ns2_vc *nsvc)
{
	char *buf = talloc_size(ctx, NS2_LL_MAX_STR);
	if (!buf)
		return buf;
	return gprs_ns2_ll_str_buf(buf, NS2_LL_MAX_STR, nsvc);
}

/*! Return the current state name of a given NS-VC to a thread-local static buffer.
 *  \param[in] nsvc NS-VC to return the state of
 *  \return pointer to the string on success; NULL on error */
const char *gprs_ns2_nsvc_state_name(struct gprs_ns2_vc *nsvc)
{
	return osmo_fsm_inst_state_name(nsvc->fi);
}

/* select a signalling NSVC and respect sig_counter
 * param[out] reset_counter - all counter has to be resetted to their signal weight
 * return the chosen nsvc or NULL
 */
static struct gprs_ns2_vc *ns2_load_sharing_signal(struct gprs_ns2_nse *nse)
{
	struct gprs_ns2_vc *nsvc = NULL, *last = NULL, *tmp;

	llist_for_each_entry(tmp, &nse->nsvc, list) {
		if (tmp->sig_weight == 0)
			continue;
		if (!ns2_vc_is_unblocked(tmp))
			continue;
		if (tmp->sig_counter == 0) {
			last = tmp;
			continue;
		}

		tmp->sig_counter--;
		nsvc = tmp;
		break;
	}

	/* all counter were zero, but there are valid nsvc */
	if (!nsvc && last) {
		llist_for_each_entry(tmp, &nse->nsvc, list) {
			tmp->sig_counter = tmp->sig_weight;
		}

		last->sig_counter--;
		return last;
	} else {
		return nsvc;
	}
}

/* 4.4.1 Load Sharing function for the Frame Relay Sub-Network */
static struct gprs_ns2_vc *ns2_load_sharing_modulo(
		struct gprs_ns2_nse *nse,
		uint16_t bvci,
		uint32_t load_selector)
{
	struct gprs_ns2_vc *tmp;
	uint32_t mod;
	uint32_t i = 0;

	if (nse->nsvc_count == 0)
		return NULL;

	mod = (bvci + load_selector) % nse->nsvc_count;
	llist_for_each_entry(tmp, &nse->nsvc, list) {
		if (!ns2_vc_is_unblocked(tmp))
			continue;
		if (i == mod)
			return tmp;
		i++;
	}

	return NULL;
}

/* 4.4.2 Load Sharing function for the IP Sub-Network
 *
 * Implement a simple approach for UDP load sharing of data weight based on the modulo of the lsp.
 *
 * E.g. 3 NSVC: 1st weight 5, 2nd weight 3, 3rd weight 1, lsp = 3.
 * sum all weights = 9
 * target_weight = lsp % sum = 3
 *
 * 1st NSVC will be the target for 0-4
 * 2nd NSVC will be the target for 5-7
 * 3rd NSVC will be the target for 8
 *
 * The 1st NSVC will be used.
 * E.g. lsp = 7. The 2nd NSVC will used.
 */
static struct gprs_ns2_vc *ns2_load_sharing_weight_modulo(
		struct gprs_ns2_nse *nse,
		uint16_t bvci,
		uint32_t load_selector)
{
	struct gprs_ns2_vc *tmp;
	uint32_t mod;
	uint32_t i = 0;

	if (nse->nsvc_count == 0)
		return NULL;

	mod = (bvci + load_selector) % nse->sum_data_weight;
	llist_for_each_entry(tmp, &nse->nsvc, list) {
		if (tmp->data_weight == 0)
			continue;
		if (!ns2_vc_is_unblocked(tmp))
			continue;
		if (i == mod || mod < i + tmp->data_weight)
			return tmp;
		i += tmp->data_weight;
	}

	return NULL;
}

/* pick the first available data NSVC - no load sharing */
struct gprs_ns2_vc *ns2_load_sharing_first(struct gprs_ns2_nse *nse)
{
	struct gprs_ns2_vc *nsvc = NULL, *tmp;

	llist_for_each_entry(tmp, &nse->nsvc, list) {
		if (!ns2_vc_is_unblocked(tmp))
			continue;
		if (tmp->data_weight == 0)
			continue;

		nsvc = tmp;
		break;
	}

	return nsvc;
}


static struct gprs_ns2_vc *ns2_load_sharing(
		struct gprs_ns2_nse *nse,
		uint16_t bvci,
		uint32_t link_selector)
{
	struct gprs_ns2_vc *nsvc = NULL;

	switch (nse->ll) {
	case GPRS_NS2_LL_FR:
		nsvc = ns2_load_sharing_modulo(nse, bvci, link_selector);
		break;
	case GPRS_NS2_LL_UDP:
	default:
		if (bvci == 0) {
			/* signalling */
			nsvc = ns2_load_sharing_signal(nse);
		} else {
			/* data with load sharing parameter */
			nsvc = ns2_load_sharing_weight_modulo(nse, bvci, link_selector);
		}
		break;
	}

	return nsvc;
}

/*! Receive a primitive from the NS User (Gb).
 *  \param[in] nsi NS instance to which the primitive is issued
 *  \param[in] oph The primitive
 *  \return 0 on success; negative on error */
int gprs_ns2_recv_prim(struct gprs_ns2_inst *nsi, struct osmo_prim_hdr *oph)
{
	/* TODO: implement resource distribution */
	/* TODO: check for empty PDUs which can be sent to Request/Confirm
	 *       the IP endpoint */
	struct osmo_gprs_ns2_prim *nsp;
	struct gprs_ns2_nse *nse = NULL;
	struct gprs_ns2_vc *nsvc = NULL;
	uint16_t bvci, nsei;
	uint8_t sducontrol = 0;
	int rc = 0;

	if (oph->sap != SAP_NS) {
		rc = -EINVAL;
		goto out;
	}

	nsp = container_of(oph, struct osmo_gprs_ns2_prim, oph);

	if (oph->operation != PRIM_OP_REQUEST || oph->primitive != GPRS_NS2_PRIM_UNIT_DATA) {
		rc = -EINVAL;
		goto out;
	}

	if (!oph->msg) {
		rc = -EINVAL;
		goto out;
	}

	bvci = nsp->bvci;
	nsei = nsp->nsei;

	nse = gprs_ns2_nse_by_nsei(nsi, nsei);
	if (!nse) {
		rc = -EINVAL;
		goto out;
	}

	if (!nse->alive) {
		goto out;
	}

	nsvc = ns2_load_sharing(nse, bvci, nsp->u.unitdata.link_selector);

	/* TODO: send a status primitive back */
	if (!nsvc)
		goto out;

	if (nsp->u.unitdata.change == GPRS_NS2_ENDPOINT_REQUEST_CHANGE)
		sducontrol = 1;
	else if (nsp->u.unitdata.change == GPRS_NS2_ENDPOINT_CONFIRM_CHANGE)
		sducontrol = 2;

	return ns2_tx_unit_data(nsvc, bvci, sducontrol, oph->msg);

out:
	msgb_free(oph->msg);
	return rc;
}

/*! Send a STATUS.ind primitive to the specified NS instance user.
 *  \param[in] nsi NS instance on which we operate
 *  \param[in] nsei NSEI to which the statue relates
 *  \param[in] bvci BVCI to which the status relates
 *  \param[in] cause The cause of the status */
void ns2_prim_status_ind(struct gprs_ns2_nse *nse,
			 struct gprs_ns2_vc *nsvc,
			 uint16_t bvci,
			 enum gprs_ns2_affecting_cause cause)
{
	char nsvc_str[NS2_LL_MAX_STR];
	struct osmo_gprs_ns2_prim nsp = {};
	nsp.nsei = nse->nsei;
	nsp.bvci = bvci;
	nsp.u.status.cause = cause;
	nsp.u.status.transfer = ns2_count_transfer_cap(nse, bvci);
	nsp.u.status.first = nse->first;
	nsp.u.status.persistent = nse->persistent;
	if (nse->mtu < 4)
		nsp.u.status.mtu = 0;
	else
		nsp.u.status.mtu = nse->mtu - 4; /* 1 Byte NS PDU type, 1 Byte NS SDU control, 2 Byte BVCI */

	if (nsvc) {
		nsp.u.status.nsvc = gprs_ns2_ll_str_buf(nsvc_str, sizeof(nsvc_str), nsvc);
		LOGNSVC(nsvc, LOGL_NOTICE, "NS-STATUS.ind(bvci=%05u): cause=%s, transfer=%d, first=%d, mtu=%d\n",
			nsp.bvci, gprs_ns2_aff_cause_prim_str(nsp.u.status.cause),
			nsp.u.status.transfer, nsp.u.status.first, nsp.u.status.mtu);
	} else {
		LOGNSE(nse, LOGL_NOTICE, "NS-STATUS.ind(bvci=%05u): cause=%s, transfer=%d, first=%d, mtu=%d\n",
			nsp.bvci, gprs_ns2_aff_cause_prim_str(nsp.u.status.cause),
			nsp.u.status.transfer, nsp.u.status.first, nsp.u.status.mtu);
	}

	osmo_prim_init(&nsp.oph, SAP_NS, GPRS_NS2_PRIM_STATUS, PRIM_OP_INDICATION, NULL);
	nse->nsi->cb(&nsp.oph, nse->nsi->cb_data);
}

/*! Allocate a NS-VC within the given bind + NSE.
 * \param[in] bind The 'bind' on which we operate
 * \param[in] nse The NS Entity on which we operate
 * \param[in] initiater - if this is an incoming remote (!initiater) or a local outgoing connection (initater)
 * \param[in] id - human-readable identifier
 * \return newly allocated NS-VC on success; NULL on error */
struct gprs_ns2_vc *ns2_vc_alloc(struct gprs_ns2_vc_bind *bind, struct gprs_ns2_nse *nse, bool initiater,
				 enum gprs_ns2_vc_mode vc_mode, const char *id)
{
	/* Sanity check */
	OSMO_ASSERT(bind->ll == nse->ll);

	struct gprs_ns2_vc *nsvc = talloc_zero(bind, struct gprs_ns2_vc);

	if (!nsvc)
		return NULL;

	nsvc->bind = bind;
	nsvc->nse = nse;
	nsvc->mode = vc_mode;
	nsvc->sig_weight = 1;
	nsvc->data_weight = 1;

	nsvc->ctrg = rate_ctr_group_alloc(nsvc, &nsvc_ctrg_desc, bind->nsi->nsvc_rate_ctr_idx);
	if (!nsvc->ctrg) {
		goto err;
	}
	nsvc->statg = osmo_stat_item_group_alloc(nsvc, &nsvc_statg_desc, bind->nsi->nsvc_rate_ctr_idx);
	if (!nsvc->statg)
		goto err_group;
	if (!ns2_vc_fsm_alloc(nsvc, id, initiater))
		goto err_statg;

	bind->nsi->nsvc_rate_ctr_idx++;

	rate_ctr_group_set_name(nsvc->ctrg, id);
	osmo_stat_item_group_set_name(nsvc->statg, id);

	llist_add_tail(&nsvc->list, &nse->nsvc);
	llist_add_tail(&nsvc->blist, &bind->nsvc);
	osmo_clock_gettime(CLOCK_MONOTONIC, &nsvc->ts_alive_change);
	ns2_nse_update_mtu(nse);

	return nsvc;

err_statg:
	osmo_stat_item_group_free(nsvc->statg);
err_group:
	rate_ctr_group_free(nsvc->ctrg);
err:
	talloc_free(nsvc);

	return NULL;
}

/*! Destroy/release given NS-VC.
 *  \param[in] nsvc NS-VC to destroy */
void gprs_ns2_free_nsvc(struct gprs_ns2_vc *nsvc)
{
	if (!nsvc || nsvc->freed)
		return;
	nsvc->freed = true;
	ns2_prim_status_ind(nsvc->nse, nsvc, 0, GPRS_NS2_AFF_CAUSE_VC_FAILURE);

	llist_del(&nsvc->list);
	llist_del(&nsvc->blist);

	/* notify nse this nsvc is unavailable */
	ns2_nse_notify_unblocked(nsvc, false);

	/* check if sns is using this VC */
	ns2_sns_replace_nsvc(nsvc);
	osmo_fsm_inst_term(nsvc->fi, OSMO_FSM_TERM_REQUEST, NULL);

	/* let the driver/bind clean up it's internal state */
	if (nsvc->priv && nsvc->bind->free_vc)
		nsvc->bind->free_vc(nsvc);

	osmo_stat_item_group_free(nsvc->statg);
	rate_ctr_group_free(nsvc->ctrg);

	talloc_free(nsvc);
}

void ns2_free_nsvcs(struct gprs_ns2_nse *nse)
{
	struct gprs_ns2_vc *nsvc;

	/* prevent recursive free() when the user reacts on a down event and free() a second time */
	while (!llist_empty(&nse->nsvc)) {
		nsvc = llist_first_entry(&nse->nsvc, struct gprs_ns2_vc, list);
		gprs_ns2_free_nsvc(nsvc);
	}
}

/*! Destroy/release all NS-VC of given NSE
 *  \param[in] nse NSE
 */
void gprs_ns2_free_nsvcs(struct gprs_ns2_nse *nse)
{
	if (!nse || nse->freed)
		return;

	if (nse->bss_sns_fi) {
		osmo_fsm_inst_dispatch(nse->bss_sns_fi, NS2_SNS_EV_REQ_FREE_NSVCS, NULL);
	} else {
		ns2_free_nsvcs(nse);
	}
}

/*! Allocate a message buffer for use with the NS2 stack. */
struct msgb *ns2_msgb_alloc(void)
{
	struct msgb *msg = msgb_alloc_headroom(NS_ALLOC_SIZE, NS_ALLOC_HEADROOM,
					       "GPRS/NS");
	if (!msg) {
		LOGP(DLNS, LOGL_ERROR, "Failed to allocate NS message of size %d\n",
			NS_ALLOC_SIZE);
	}
	return msg;
}

/*! Create a status message to be sent over a new connection.
 *  \param[in] orig_msg the original message
 *  \param[in] tp TLVP parsed of the original message
 *  \param[out] reject callee-allocated message buffer of the generated NS-STATUS
 *  \param[in] cause Cause for the rejection
 *  \return 0 on success */
static int reject_status_msg(struct msgb *orig_msg, struct tlv_parsed *tp, struct msgb **reject, enum ns_cause cause)
{
	struct msgb *msg = ns2_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	bool have_vci = false;
	uint8_t _cause = cause;
	uint16_t nsei = 0;

	if (!msg)
		return -ENOMEM;

	if (TLVP_PRES_LEN(tp, NS_IE_NSEI, 2)) {
		nsei = tlvp_val16be(tp, NS_IE_NSEI);

		LOGP(DLNS, LOGL_NOTICE, "NSEI=%u Rejecting message without NSVCI. Tx NS STATUS (cause=%s)\n",
		     nsei, gprs_ns2_cause_str(cause));
	}

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_STATUS;

	msgb_tvlv_put(msg, NS_IE_CAUSE, 1, &_cause);
	have_vci = TLVP_PRES_LEN(tp, NS_IE_VCI, 2);

	/* Section 9.2.7.1: Static conditions for NS-VCI */
	if (cause == NS_CAUSE_NSVC_BLOCKED ||
	    cause == NS_CAUSE_NSVC_UNKNOWN) {
		if (!have_vci) {
			msgb_free(msg);
			return -EINVAL;
		}

		msgb_tvlv_put(msg, NS_IE_VCI, 2, TLVP_VAL(tp, NS_IE_VCI));
	}

	/* Section 9.2.7.2: Static conditions for NS PDU */
	switch (cause) {
	case NS_CAUSE_SEM_INCORR_PDU:
	case NS_CAUSE_PDU_INCOMP_PSTATE:
	case NS_CAUSE_PROTO_ERR_UNSPEC:
	case NS_CAUSE_INVAL_ESSENT_IE:
	case NS_CAUSE_MISSING_ESSENT_IE:
		msgb_tvlv_put(msg, NS_IE_PDU, msgb_l2len(orig_msg),
			      orig_msg->l2h);
		break;
	default:
		break;
	}

	*reject = msg;
	return 0;
}

/*! Resolve a NS Entity based on its NSEI.
 *  \param[in] nsi NS Instance in which we do the look-up
 *  \param[in] nsei NSEI to look up
 *  \return NS Entity in successful case; NULL if none found */
struct gprs_ns2_nse *gprs_ns2_nse_by_nsei(struct gprs_ns2_inst *nsi, uint16_t nsei)
{
	struct gprs_ns2_nse *nse;

	llist_for_each_entry(nse, &nsi->nse, list) {
		if (nse->nsei == nsei)
			return nse;
	}

	return NULL;
}

/*! Resolve a NS-VC Entity based on its NS-VCI.
 *  \param[in] nsi NS Instance in which we do the look-up
 *  \param[in] nsvci NS-VCI to look up
 *  \return NS-VC Entity in successful case; NULL if none found */
struct gprs_ns2_vc *gprs_ns2_nsvc_by_nsvci(struct gprs_ns2_inst *nsi, uint16_t nsvci)
{
	struct gprs_ns2_nse *nse;
	struct gprs_ns2_vc *nsvc;

	llist_for_each_entry(nse, &nsi->nse, list) {
		llist_for_each_entry(nsvc, &nse->nsvc, list) {
			if (nsvc->nsvci_is_valid && nsvc->nsvci == nsvci)
				return nsvc;
		}
	}

	return NULL;
}

/*! Create a NS Entity within given NS instance.
 *  \param[in] nsi NS instance in which to create NS Entity
 *  \param[in] nsei NS Entity Identifier of to-be-created NSE
 *  \param[in] ip_sns_role_sgsn Does local side implement SGSN role?
 *  \returns newly-allocated NS-E in successful case; NULL on error */
struct gprs_ns2_nse *gprs_ns2_create_nse2(struct gprs_ns2_inst *nsi, uint16_t nsei,
					  enum gprs_ns2_ll linklayer, enum gprs_ns2_dialect dialect,
					  bool ip_sns_role_sgsn)
{
	struct gprs_ns2_nse *nse;

	nse = gprs_ns2_nse_by_nsei(nsi, nsei);
	if (nse) {
		LOGNSE(nse, LOGL_ERROR, "Can not create a NSE with already taken NSEI\n");
		return nse;
	}

	nse = talloc_zero(nsi, struct gprs_ns2_nse);
	if (!nse)
		return NULL;
	nse->dialect = GPRS_NS2_DIALECT_UNDEF;
	nse->ip_sns_role_sgsn = ip_sns_role_sgsn;

	if (ns2_nse_set_dialect(nse, dialect) < 0) {
		talloc_free(nse);
		return NULL;
	}

	nse->ctrg = rate_ctr_group_alloc(nse, &nse_ctrg_desc, nsei);
	if (!nse->ctrg) {
		talloc_free(nse);
		return NULL;
	}

	nse->ll = linklayer;
	nse->nsei = nsei;
	nse->nsi = nsi;
	nse->first = true;
	nse->mtu = 0;
	llist_add_tail(&nse->list, &nsi->nse);
	INIT_LLIST_HEAD(&nse->nsvc);
	osmo_clock_gettime(CLOCK_MONOTONIC, &nse->ts_alive_change);

	return nse;
}

int ns2_nse_set_dialect(struct gprs_ns2_nse *nse, enum gprs_ns2_dialect dialect)
{
	char sns[16];

	if (nse->dialect == dialect)
		return 0;

	switch (nse->dialect) {
	case GPRS_NS2_DIALECT_UNDEF:
		if (dialect == GPRS_NS2_DIALECT_SNS) {
			snprintf(sns, sizeof(sns), "NSE%05u-SNS", nse->nsei);
			if (nse->ip_sns_role_sgsn)
				nse->bss_sns_fi = ns2_sns_sgsn_fsm_alloc(nse, sns);
			else
				nse->bss_sns_fi = ns2_sns_bss_fsm_alloc(nse, sns);
			if (!nse->bss_sns_fi)
				return -1;
		}
		nse->dialect = dialect;
		break;
	default:
		if (dialect == GPRS_NS2_DIALECT_UNDEF) {
			if (nse->bss_sns_fi)
				osmo_fsm_inst_term(nse->bss_sns_fi, OSMO_FSM_TERM_REQUEST, NULL);
			nse->bss_sns_fi = NULL;
			nse->dialect = GPRS_NS2_DIALECT_UNDEF;
		} else {
			/* we don't support arbitrary changes without going through UNDEF first */
			return -EPERM;
		}
	}

	return 0;
}

/*! Create a NS Entity within given NS instance.
 *  \param[in] nsi NS instance in which to create NS Entity
 *  \param[in] nsei NS Entity Identifier of to-be-created NSE
 *  \returns newly-allocated NS-E in successful case; NULL on error */
struct gprs_ns2_nse *gprs_ns2_create_nse(struct gprs_ns2_inst *nsi, uint16_t nsei,
					 enum gprs_ns2_ll linklayer, enum gprs_ns2_dialect dialect)
{
	return gprs_ns2_create_nse2(nsi, nsei, linklayer, dialect, false);
}

/*! Return the NSEI
 * \param[in] nse NS Entity
 * \return the nsei.
 */
uint16_t gprs_ns2_nse_nsei(struct gprs_ns2_nse *nse)
{
	return nse->nsei;
}

/*! Destroy given NS Entity.
 *  \param[in] nse NS Entity to destroy */
void gprs_ns2_free_nse(struct gprs_ns2_nse *nse)
{
	if (!nse || nse->freed)
		return;

	nse->freed = true;
	nse->alive = false;
	if (nse->bss_sns_fi) {
		osmo_fsm_inst_term(nse->bss_sns_fi, OSMO_FSM_TERM_REQUEST, NULL);
		nse->bss_sns_fi = NULL;
	}

	gprs_ns2_free_nsvcs(nse);
	ns2_prim_status_ind(nse, NULL, 0, GPRS_NS2_AFF_CAUSE_FAILURE);
	rate_ctr_group_free(nse->ctrg);
	ns2_free_nsvcs(nse);

	llist_del(&nse->list);
	talloc_free(nse);
}

void gprs_ns2_free_nses(struct gprs_ns2_inst *nsi)
{
	struct gprs_ns2_nse *nse;

	/* prevent recursive free() when the user reacts on a down event and free() a second time */
	while (!llist_empty(&nsi->nse)) {
		nse = llist_first_entry(&nsi->nse, struct gprs_ns2_nse, list);
		gprs_ns2_free_nse(nse);
	}
}

static inline int ns2_tlv_parse(struct tlv_parsed *dec,
			 const uint8_t *buf, int buf_len, uint8_t lv_tag,
			 uint8_t lv_tag2)
{
	/* workaround for NS_IE_IP_ADDR not following any known TLV rules.
	 * See comment of ns_att_tlvdef1. */
	int rc = tlv_parse(dec, &ns_att_tlvdef1, buf, buf_len, lv_tag, lv_tag2);
	if (rc < 0)
		return tlv_parse(dec, &ns_att_tlvdef2, buf, buf_len, lv_tag, lv_tag2);
	return rc;
}

static enum ns2_cs ns2_create_vc_sns(struct gprs_ns2_vc_bind *bind,
			  const struct osmo_sockaddr *remote,
			  struct gprs_ns2_vc **success, uint16_t nsei)
{
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse;

	nsvc = gprs_ns2_nsvc_by_sockaddr_bind(bind, remote);
	/* ns2_create_vc() is only called if no NS-VC could be found */
	OSMO_ASSERT(!nsvc);

	nse = gprs_ns2_nse_by_nsei(bind->nsi, nsei);
	if (!nse) {
		if (!bind->accept_sns) {
			struct osmo_sockaddr_str remote_str;
			osmo_sockaddr_str_from_sockaddr(&remote_str, &remote->u.sas);
			/* no dynamic creation of IP-SNS NSE permitted */
			LOGP(DLNS, LOGL_ERROR, "[%s]:%u: Dynamic creation of NSE(%05u) via IP-SNS not "
			     "permitted. Check your config.\n", remote_str.ip, remote_str.port, nsei);
			return NS2_CS_ERROR;
		}
		nse = gprs_ns2_create_nse2(bind->nsi, nsei, bind->ll, GPRS_NS2_DIALECT_SNS, true);
		if (!nse) {
			LOGP(DLNS, LOGL_ERROR, "Failed to create NSE(%05u)\n", nsei);
			return NS2_CS_ERROR;
		}
		/* add configured list of default binds; if that fails, use only current bind */
		if (!ns2_sns_add_sns_default_binds(nse))
			gprs_ns2_sns_add_bind(nse, bind);
	} else {
		/* nsei already known */
		if (nse->ll != bind->ll) {
			LOGNSE(nse, LOGL_ERROR, "Received NS-RESET with wrong linklayer(%s)"
				" for already known NSE(%s)\n", gprs_ns2_lltype_str(bind->ll),
				gprs_ns2_lltype_str(nse->ll));
			return NS2_CS_SKIPPED;
		}
	}

	nsvc = ns2_ip_bind_connect(bind, nse, remote);
	if (!nsvc)
		return NS2_CS_SKIPPED;

	nsvc->nsvci_is_valid = false;

	*success = nsvc;

	return NS2_CS_CREATED;
}

/*! Create a new NS-VC based on a [received] message. Depending on the bind it might create a NSE.
 *  \param[in] bind the bind through which msg was received
 *  \param[in] msg the actual received message
 *  \param[in] remote address of remote peer sending message
 *  \param[in] logname A name to describe the VC. E.g. ip address pair
 *  \param[out] reject A message filled to be sent back. Only used in failure cases.
 *  \param[out] success A pointer which will be set to the new VC on success
 *  \return enum value indicating the status, e.g. GPRS_NS2_CS_CREATED */
enum ns2_cs ns2_create_vc(struct gprs_ns2_vc_bind *bind,
			  struct msgb *msg,
			  const struct osmo_sockaddr *remote,
			  const char *logname,
			  struct msgb **reject,
			  struct gprs_ns2_vc **success)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *)msg->l2h;
	struct tlv_parsed tp;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse;
	enum gprs_ns2_dialect dialect;
	enum gprs_ns2_vc_mode vc_mode;
	uint16_t nsvci;
	uint16_t nsei;
	const struct osmo_sockaddr *local;
	char idbuf[256], tmp[INET6_ADDRSTRLEN + 8];

	int rc, tlv;

	if (msg->len < sizeof(struct gprs_ns_hdr))
		return NS2_CS_ERROR;

	/* parse the tlv early to allow reject status msg to
	 * work with valid tp.
	 * Ignore the return code until the pdu type is parsed because
	 * an unknown pdu type should be ignored */
	tlv = ns2_tlv_parse(&tp, nsh->data,
			   msgb_l2len(msg) - sizeof(*nsh), 0, 0);

	if (bind->ll == GPRS_NS2_LL_UDP && nsh->pdu_type == SNS_PDUT_SIZE && tlv >= 0) {
		uint16_t nsei;

		if (!TLVP_PRES_LEN(&tp, NS_IE_NSEI, 2)) {
			rc = reject_status_msg(msg, &tp, reject, NS_CAUSE_MISSING_ESSENT_IE);
			if (rc < 0)
				LOGP(DLNS, LOGL_ERROR, "Failed to generate reject message (%d)\n", rc);
			return NS2_CS_REJECTED;
		}
		nsei = tlvp_val16be(&tp, NS_IE_NSEI);
		/* Create NS-VC, and if required, even NSE dynamically */
		return ns2_create_vc_sns(bind, remote, success, nsei);
	}

	switch (nsh->pdu_type) {
	case NS_PDUT_STATUS:
		/* Do not respond, see 3GPP TS 08.16, 7.5.1 */
		LOGP(DLNS, LOGL_INFO, "Ignoring NS STATUS from %s "
		     "for non-existing NS-VC\n",
		     logname);
		return NS2_CS_SKIPPED;
	case NS_PDUT_ALIVE_ACK:
		/* Ignore this, see 3GPP TS 08.16, 7.4.1 */
		LOGP(DLNS, LOGL_INFO, "Ignoring NS ALIVE ACK from %s "
		     "for non-existing NS-VC\n",
		     logname);
		return NS2_CS_SKIPPED;
	case NS_PDUT_RESET_ACK:
		/* Ignore this, see 3GPP TS 08.16, 7.3.1 */
		LOGP(DLNS, LOGL_INFO, "Ignoring NS RESET ACK from %s "
		     "for non-existing NS-VC\n",
		     logname);
		return NS2_CS_SKIPPED;
	case NS_PDUT_RESET:
		/* accept PDU RESET when vc_mode matches */
		if (bind->accept_ipaccess) {
			dialect = GPRS_NS2_DIALECT_IPACCESS;
			break;
		}

		rc = reject_status_msg(msg, &tp, reject, NS_CAUSE_PDU_INCOMP_PSTATE);
		if (rc < 0)
			LOGP(DLNS, LOGL_ERROR, "Failed to generate reject message (%d)\n", rc);
		return NS2_CS_REJECTED;
	default:
		rc = reject_status_msg(msg, &tp, reject, NS_CAUSE_PDU_INCOMP_PSTATE);
		if (rc < 0)
			LOGP(DLNS, LOGL_ERROR, "Failed to generate reject message (%d)\n", rc);
		return NS2_CS_REJECTED;
	}

	if (tlv < 0) {
		/* TODO: correct behaviour would checking what's wrong.
		 * If it's an essential TLV for the PDU return NS_CAUSE_INVAL_ESSENT_IE.
		 * Otherwise ignore the non-essential TLV. */
		LOGP(DLNS, LOGL_ERROR, "Rx NS RESET Error %d during "
				       "TLV Parse\n", tlv);
		rc = reject_status_msg(msg, &tp, reject, NS_CAUSE_PROTO_ERR_UNSPEC);
		if (rc < 0)
			LOGP(DLNS, LOGL_ERROR, "Failed to generate reject message (%d)\n", rc);
		return NS2_CS_REJECTED;
	}

	if (!TLVP_PRES_LEN(&tp, NS_IE_CAUSE, 1) ||
	    !TLVP_PRES_LEN(&tp, NS_IE_VCI, 2) || !TLVP_PRES_LEN(&tp, NS_IE_NSEI, 2)) {
		LOGP(DLNS, LOGL_ERROR, "NS RESET Missing mandatory IE\n");
		rc = reject_status_msg(msg, &tp, reject, NS_CAUSE_MISSING_ESSENT_IE);
		if (rc < 0)
			LOGP(DLNS, LOGL_ERROR, "Failed to generate reject message (%d)\n", rc);
		return NS2_CS_REJECTED;
	}

	nsei  = tlvp_val16be(&tp, NS_IE_NSEI);
	nsvci = tlvp_val16be(&tp, NS_IE_VCI);

	/* find or create NSE */
	nse = gprs_ns2_nse_by_nsei(bind->nsi, nsei);
	if (!nse) {
		/* only create nse for udp & ipaccess */
		if (bind->ll != GPRS_NS2_LL_UDP || dialect != GPRS_NS2_DIALECT_IPACCESS)
			return NS2_CS_SKIPPED;

		if (!bind->accept_ipaccess)
			return NS2_CS_SKIPPED;

		nse = gprs_ns2_create_nse(bind->nsi, nsei, bind->ll, dialect);
		if (!nse) {
			LOGP(DLNS, LOGL_ERROR, "Failed to create NSE(%05u)\n", nsei);
			return NS2_CS_ERROR;
		}
	} else {
		/* nsei already known */
		if (nse->ll != bind->ll) {
			LOGNSE(nse, LOGL_ERROR, "Received NS-RESET NS-VCI(%05u) with wrong linklayer(%s)"
				" for already known NSE(%s)\n", nsvci, gprs_ns2_lltype_str(bind->ll),
				gprs_ns2_lltype_str(nse->ll));
			return NS2_CS_SKIPPED;
		}
	}

	nsvc = gprs_ns2_nsvc_by_nsvci(bind->nsi, nsvci);
	if (nsvc) {
		if (nsvc->persistent) {
			LOGNSVC(nsvc, LOGL_ERROR, "Received NS-RESET for a persistent NSE over wrong connection.\n");
			return NS2_CS_SKIPPED;
		}
		/* destroy old dynamic nsvc */
		gprs_ns2_free_nsvc(nsvc);
	}

	/* do nse persistent check late to be more precise on the error message */
	if (nse->persistent) {
		LOGNSE(nse, LOGL_ERROR, "Received NS-RESET for a persistent NSE but the unknown "
		       "NS-VCI(%05u)\n", nsvci);
		return NS2_CS_SKIPPED;
	}

	nsvci = tlvp_val16be(&tp, NS_IE_VCI);
	vc_mode = ns2_dialect_to_vc_mode(dialect);

	local = gprs_ns2_ip_bind_sockaddr(bind);
	osmo_sockaddr_to_str_buf(tmp, sizeof(tmp), local);
	snprintf(idbuf, sizeof(idbuf), "%s-NSE%05u-NSVC%05u-%s-%s", gprs_ns2_lltype_str(nse->ll),
		 nse->nsei, nsvci, tmp, osmo_sockaddr_to_str(remote));
	osmo_identifier_sanitize_buf(idbuf, NULL, '_');
	nsvc = ns2_vc_alloc(bind, nse, false, vc_mode, idbuf);
	if (!nsvc)
		return NS2_CS_SKIPPED;

	nsvc->nsvci = nsvci;
	nsvc->nsvci_is_valid = true;

	*success = nsvc;

	return NS2_CS_CREATED;
}

/*! Create, and connect an inactive, new IP-based NS-VC
 *  \param[in] bind bind in which the new NS-VC is to be created
 *  \param[in] remote remote address to which to connect
 *  \param[in] nse NS Entity in which the NS-VC is to be created
 *  \param[in] nsvci is only required when bind->vc_mode == NS2_VC_MODE_BLOCKRESET
 *  \return pointer to newly-allocated, connected and inactive NS-VC; NULL on error */
struct gprs_ns2_vc *gprs_ns2_ip_connect_inactive(struct gprs_ns2_vc_bind *bind,
					const struct osmo_sockaddr *remote,
					struct gprs_ns2_nse *nse,
					uint16_t nsvci)
{
	struct gprs_ns2_vc *nsvc;

	nsvc = ns2_ip_bind_connect(bind, nse, remote);
	if (!nsvc)
		return NULL;

	if (nsvc->mode == GPRS_NS2_VC_MODE_BLOCKRESET) {
		nsvc->nsvci = nsvci;
		nsvc->nsvci_is_valid = true;
	}

	return nsvc;
}

/*! Create, connect and activate a new IP-based NS-VC
 *  \param[in] bind bind in which the new NS-VC is to be created
 *  \param[in] remote remote address to which to connect
 *  \param[in] nse NS Entity in which the NS-VC is to be created
 *  \param[in] nsvci is only required when bind->vc_mode == NS2_VC_MODE_BLOCKRESET
 *  \return pointer to newly-allocated, connected and activated NS-VC; NULL on error */
struct gprs_ns2_vc *gprs_ns2_ip_connect(struct gprs_ns2_vc_bind *bind,
					const struct osmo_sockaddr *remote,
					struct gprs_ns2_nse *nse,
					uint16_t nsvci)
{
	struct gprs_ns2_vc *nsvc;
	nsvc = gprs_ns2_ip_connect_inactive(bind, remote, nse, nsvci);
	if (!nsvc)
		return NULL;

	ns2_vc_fsm_start(nsvc);

	return nsvc;
}

/*! Create, connect and activate a new IP-based NS-VC
 *  \param[in] bind bind in which the new NS-VC is to be created
 *  \param[in] remote remote address to which to connect
 *  \param[in] nsei NSEI of the NS Entity in which the NS-VC is to be created
 *  \param[in] nsvci is only required when bind->vc_mode == NS2_VC_MODE_BLOCKRESET
 *  \return pointer to newly-allocated, connected and activated NS-VC; NULL on error */
struct gprs_ns2_vc *gprs_ns2_ip_connect2(struct gprs_ns2_vc_bind *bind,
					 const struct osmo_sockaddr *remote,
					 uint16_t nsei,
					 uint16_t nsvci,
					 enum gprs_ns2_dialect dialect)
{
	struct gprs_ns2_nse *nse = gprs_ns2_nse_by_nsei(bind->nsi, nsei);

	if (!nse) {
		nse = gprs_ns2_create_nse(bind->nsi, nsei, GPRS_NS2_LL_UDP, dialect);
		if (!nse)
			return NULL;
	}

	return gprs_ns2_ip_connect(bind, remote, nse, nsvci);
}

/*! Find NS-VC for given socket address.
 *  \param[in] nse NS Entity in which to search
 *  \param[in] sockaddr socket address to search for
 *  \return NS-VC matching sockaddr; NULL if none found */
struct gprs_ns2_vc *gprs_ns2_nsvc_by_sockaddr_nse(struct gprs_ns2_nse *nse,
						  const struct osmo_sockaddr *sockaddr)
{
	struct gprs_ns2_vc *nsvc;
	const struct osmo_sockaddr *remote;

	OSMO_ASSERT(nse);
	OSMO_ASSERT(sockaddr);

	llist_for_each_entry(nsvc, &nse->nsvc, list) {
		remote = gprs_ns2_ip_vc_remote(nsvc);
		if (!osmo_sockaddr_cmp(sockaddr, remote))
			return nsvc;
	}

	return NULL;
}

/*!
 * Iterate over all nsvc of a NS Entity and call the callback.
 * If the callback returns < 0 it aborts the loop and returns the callback return code.
 * \param[in] nse NS Entity to iterate over all nsvcs
 * \param[in] cb the callback to call
 * \param[inout] cb_data the private data of the callback
 * \return 0 if the loop completes. If a callback returns < 0 it will returns this value.
 */
int gprs_ns2_nse_foreach_nsvc(struct gprs_ns2_nse *nse, gprs_ns2_foreach_nsvc_cb cb, void *cb_data)
{
	struct gprs_ns2_vc *nsvc, *tmp;
	int rc = 0;
	llist_for_each_entry_safe(nsvc, tmp, &nse->nsvc, list) {
		rc = cb(nsvc, cb_data);
		if (rc < 0)
			return rc;
	}

	return 0;
}



/*! Bottom-side entry-point for received NS PDU from the driver/bind
 * \param[in] nsvc NS-VC for which the message was received
 * \param msg the received message. Ownership is transferred, caller must not free it!
 * \return 0 on success; negative on error */
int ns2_recv_vc(struct gprs_ns2_vc *nsvc,
		struct msgb *msg)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	struct tlv_parsed tp = { };
	int rc = 0;

	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	RATE_CTR_INC_NS(nsvc, NS_CTR_PKTS_IN);
	RATE_CTR_ADD_NS(nsvc, NS_CTR_BYTES_IN, msg->len);

	if (msg->len < sizeof(struct gprs_ns_hdr)) {
		rc = -EINVAL;
		goto freemsg;
	}

	if (nsh->pdu_type != NS_PDUT_UNITDATA)
		LOG_NS_RX_SIGNAL(nsvc, nsh->pdu_type);
	else
		LOG_NS_DATA(nsvc, "Rx", nsh->pdu_type, LOGL_INFO, "\n");

	switch (nsh->pdu_type) {
	case SNS_PDUT_CONFIG:
		/* one additional byte ('end flag') before the TLV part starts */
		rc = ns2_tlv_parse(&tp, nsh->data+1,
				   msgb_l2len(msg) - sizeof(*nsh)-1, 0, 0);
		if (rc < 0) {
			LOGP(DLNS, LOGL_NOTICE, "Error during TLV Parse in %s\n", msgb_hexdump(msg));
			goto freemsg;
		}
		/* All sub-network service related message types */
		return ns2_sns_rx(nsvc, msg, &tp);
	case SNS_PDUT_ACK:
	case SNS_PDUT_ADD:
	case SNS_PDUT_CHANGE_WEIGHT:
	case SNS_PDUT_DELETE:
		/* weird layout: NSEI TLV, then value-only transaction IE, then TLV again */
		rc = ns2_tlv_parse(&tp, nsh->data+5,
				   msgb_l2len(msg) - sizeof(*nsh)-5, 0, 0);
		if (rc < 0) {
			LOGP(DLNS, LOGL_NOTICE, "Error during TLV Parse in %s\n", msgb_hexdump(msg));
			goto freemsg;
		}
		tp.lv[NS_IE_NSEI].val = nsh->data+2;
		tp.lv[NS_IE_NSEI].len = 2;
		tp.lv[NS_IE_TRANS_ID].val = nsh->data+4;
		tp.lv[NS_IE_TRANS_ID].len = 1;
		return ns2_sns_rx(nsvc, msg, &tp);
	case SNS_PDUT_CONFIG_ACK:
	case SNS_PDUT_SIZE:
	case SNS_PDUT_SIZE_ACK:
		rc = ns2_tlv_parse(&tp, nsh->data,
				   msgb_l2len(msg) - sizeof(*nsh), 0, 0);
		if (rc < 0) {
			LOGP(DLNS, LOGL_NOTICE, "Error during TLV Parse in %s\n", msgb_hexdump(msg));
			goto freemsg;
		}
		/* All sub-network service related message types */
		return ns2_sns_rx(nsvc, msg, &tp);
	case NS_PDUT_UNITDATA:
		return ns2_vc_rx(nsvc, msg, &tp);
	default:
		rc = ns2_tlv_parse(&tp, nsh->data,
				   msgb_l2len(msg) - sizeof(*nsh), 0, 0);
		if (rc < 0) {
			LOGP(DLNS, LOGL_NOTICE, "Error during TLV Parse\n");
			if (nsh->pdu_type != NS_PDUT_STATUS)
				ns2_tx_status(nsvc, NS_CAUSE_PROTO_ERR_UNSPEC, 0, msg, NULL);
			return rc;
		}
		return ns2_vc_rx(nsvc, msg, &tp);
	}
freemsg:
	msgb_free(msg);

	return rc;
}

/* summarize all active data nsvcs */
void ns2_nse_data_sum(struct gprs_ns2_nse *nse)
{
	struct gprs_ns2_vc *nsvc;

	nse->nsvc_count = 0;
	nse->sum_data_weight = 0;
	nse->sum_sig_weight = 0;

	llist_for_each_entry(nsvc, &nse->nsvc, list) {
		if (!ns2_vc_is_unblocked(nsvc))
			continue;

		nse->nsvc_count++;
		nse->sum_data_weight += nsvc->data_weight;
		nse->sum_sig_weight += nsvc->sig_weight;
	}
}

/*! Notify a nse about the change of a NS-VC.
 *  \param[in] nsvc NS-VC which has detected the change (and shall not be notified).
 *  \param[in] unblocked whether the NSE should be marked as unblocked (true) or blocked (false) */
void ns2_nse_notify_unblocked(struct gprs_ns2_vc *nsvc, bool unblocked)
{
	struct gprs_ns2_nse *nse = nsvc->nse;
	struct gprs_ns2_inst *nsi = nse->nsi;
	uint16_t nsei = nse->nsei;

	ns2_nse_data_sum(nse);
	ns2_sns_notify_alive(nse, nsvc, unblocked);

	/* NSE could have been freed, try to get it again */
	nse = gprs_ns2_nse_by_nsei(nsi, nsei);

	if (!nse || unblocked == nse->alive)
		return;

	/* wait until both data_weight and sig_weight are != 0 before declaring NSE as alive */
	if (unblocked && nse->sum_data_weight && nse->sum_sig_weight) {
		nse->alive = true;
		osmo_clock_gettime(CLOCK_MONOTONIC, &nse->ts_alive_change);
		ns2_prim_status_ind(nse, NULL, 0, GPRS_NS2_AFF_CAUSE_RECOVERY);
		nse->first = false;
		return;
	}

	if (nse->alive && (nse->sum_data_weight == 0 || nse->sum_sig_weight == 0)) {
		/* nse became unavailable */
		nse->alive = false;
		osmo_clock_gettime(CLOCK_MONOTONIC, &nse->ts_alive_change);
		ns2_prim_status_ind(nse, NULL, 0, GPRS_NS2_AFF_CAUSE_FAILURE);
	}
}

/*! Create a new GPRS NS instance
 *  \param[in] ctx a talloc context to allocate NS instance from
 *  \param[in] cb Call-back function for dispatching primitives to the user. The Call-back must free all msgb* given in the primitive.
 *  \param[in] cb_data transparent user data passed to Call-back
 *  \returns dynamically allocated gprs_ns_inst; NULL on error */
struct gprs_ns2_inst *gprs_ns2_instantiate(void *ctx, osmo_prim_cb cb, void *cb_data)
{
	struct gprs_ns2_inst *nsi;

	nsi = talloc_zero(ctx, struct gprs_ns2_inst);
	if (!nsi)
		return NULL;

	nsi->cb = cb;
	nsi->cb_data = cb_data;
	INIT_LLIST_HEAD(&nsi->binding);
	INIT_LLIST_HEAD(&nsi->nse);

	nsi->timeout[NS_TOUT_TNS_BLOCK] = 3;
	nsi->timeout[NS_TOUT_TNS_BLOCK_RETRIES] = 3;
	nsi->timeout[NS_TOUT_TNS_RESET] = 3;
	nsi->timeout[NS_TOUT_TNS_RESET_RETRIES] = 3;
	nsi->timeout[NS_TOUT_TNS_TEST] = 30;
	nsi->timeout[NS_TOUT_TNS_ALIVE] = 3;
	nsi->timeout[NS_TOUT_TNS_ALIVE_RETRIES] = 10;
	nsi->timeout[NS_TOUT_TSNS_PROV] = 3; /* 1..10 */
	nsi->timeout[NS_TOUT_TSNS_SIZE_RETRIES] = 3;
	nsi->timeout[NS_TOUT_TSNS_CONFIG_RETRIES] = 3;
	nsi->timeout[NS_TOUT_TSNS_PROCEDURES_RETRIES] = 3;

	return nsi;
}

/*! Destroy a NS Instance (including all its NSEs, binds, ...).
 *  \param[in] nsi NS instance to destroy */
void gprs_ns2_free(struct gprs_ns2_inst *nsi)
{
	if (!nsi)
		return;

	gprs_ns2_free_nses(nsi);
	gprs_ns2_free_binds(nsi);

	talloc_free(nsi);
}

/*! Start the NS-ALIVE FSM in all NS-VCs of given NSE.
 *  \param[in] nse NS Entity in whihc to start NS-ALIVE FSMs */
void gprs_ns2_start_alive_all_nsvcs(struct gprs_ns2_nse *nse)
{
	struct gprs_ns2_vc *nsvc;
	OSMO_ASSERT(nse);

	llist_for_each_entry(nsvc, &nse->nsvc, list) {
		/* A pre-configured endpoint shall not be used for NSE data or signalling traffic
		 * (with the exception of Size and Configuration procedures) unless it is
		 * configured by the SGSN using the auto-configuration procedures */
		if (nsvc->sns_only)
			continue;

		ns2_vc_fsm_start(nsvc);
	}
}

/*! Destroy a given bind.
 *  \param[in] bind the bind we want to destroy */
void gprs_ns2_free_bind(struct gprs_ns2_vc_bind *bind)
{
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_nse *nse;
	if (!bind || bind->freed)
		return;
	bind->freed = true;

	if (gprs_ns2_is_ip_bind(bind)) {
		llist_for_each_entry(nse, &bind->nsi->nse, list) {
			gprs_ns2_sns_del_bind(nse, bind);
		}
	}

	/* prevent recursive free() when the user reacts on a down event and free() a second time */
	while (!llist_empty(&bind->nsvc)) {
		nsvc = llist_first_entry(&bind->nsvc, struct gprs_ns2_vc, blist);
		gprs_ns2_free_nsvc(nsvc);
	}

	if (bind->driver->free_bind)
		bind->driver->free_bind(bind);

	llist_del(&bind->list);
	osmo_stat_item_group_free(bind->statg);
	talloc_free((char *)bind->name);
	talloc_free(bind);
}

void gprs_ns2_free_binds(struct gprs_ns2_inst *nsi)
{
	struct gprs_ns2_vc_bind *bind;

	/* prevent recursive free() when the user reacts on a down event and free() a second time */
	while (!llist_empty(&nsi->binding)) {
		bind = llist_first_entry(&nsi->binding, struct gprs_ns2_vc_bind, list);
		gprs_ns2_free_bind(bind);
	}
}

/*! Search for a bind with a unique name
 *  \param[in] nsi NS instance on which we operate
 *  \param[in] name The unique bind name to search for
 *  \return the bind or NULL if not found
 */
struct gprs_ns2_vc_bind *gprs_ns2_bind_by_name(struct gprs_ns2_inst *nsi, const char *name)
{
	struct gprs_ns2_vc_bind *bind;

	llist_for_each_entry(bind, &nsi->binding, list) {
		if (!strcmp(bind->name, name))
			return bind;
	}

	return NULL;
}

enum gprs_ns2_vc_mode ns2_dialect_to_vc_mode(enum gprs_ns2_dialect dialect)
{
	switch (dialect) {
	case GPRS_NS2_DIALECT_SNS:
	case GPRS_NS2_DIALECT_STATIC_ALIVE:
		return GPRS_NS2_VC_MODE_ALIVE;
	case GPRS_NS2_DIALECT_STATIC_RESETBLOCK:
	case GPRS_NS2_DIALECT_IPACCESS:
		return GPRS_NS2_VC_MODE_BLOCKRESET;
	default:
		return -1;
	}
}

static void add_bind_array(struct gprs_ns2_vc_bind **array,
			   struct gprs_ns2_vc_bind *bind, int size)
{
	int i;
	for (i=0; i < size; i++) {
		if (array[i] == bind)
			return;
		if (!array[i])
			break;
	}

	if (i == size)
		return;

	array[i] = bind;
}

void ns2_nse_update_mtu(struct gprs_ns2_nse *nse)
{
	struct gprs_ns2_vc *nsvc;
	int mtu = 0;

	if (llist_empty(&nse->nsvc)) {
		nse->mtu = 0;
		return;
	}

	llist_for_each_entry(nsvc, &nse->nsvc, list) {
		if (mtu == 0)
			mtu = nsvc->bind->mtu;
		else if (mtu > nsvc->bind->mtu)
			mtu = nsvc->bind->mtu;
	}

	if (nse->mtu == mtu)
		return;

	nse->mtu = mtu;
	if (nse->alive)
		ns2_prim_status_ind(nse, NULL, 0, GPRS_NS2_AFF_CAUSE_MTU_CHANGE);
}

/*! calculate the transfer capabilities for a nse
 *  \param nse the nse to count the transfer capability
 *  \param bvci a bvci - unused
 *  \return the transfer capability in mbit. On error < 0.
 */
int ns2_count_transfer_cap(struct gprs_ns2_nse *nse,
			   uint16_t bvci)
{
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_vc_bind **active_binds;
	int i, active_nsvcs = 0, transfer_cap = 0;

	/* calculate the transfer capabilities based on the binds.
	 * A bind has a transfer capability which is shared across all NSVCs.
	 * Take care the bind cap is not counted twice within a NSE.
	 * This should be accurate for FR and UDP but not for FR/GRE. */

	if (!nse->alive)
		return 0;

	llist_for_each_entry(nsvc, &nse->nsvc, list) {
		if (ns2_vc_is_unblocked(nsvc))
			active_nsvcs++;
	}

	if (!active_nsvcs)
		return 0;

	active_binds = talloc_zero_array(nse, struct gprs_ns2_vc_bind*, active_nsvcs);
	if (!active_binds)
		return -ENOMEM;

	llist_for_each_entry(nsvc, &nse->nsvc, list) {
		if (!ns2_vc_is_unblocked(nsvc))
			continue;
		add_bind_array(active_binds, nsvc->bind, active_nsvcs);
	}

	/* TODO: change calcuation for FR/GRE */
	for (i = 0; i < active_nsvcs; i++) {
		if (active_binds[i])
			transfer_cap += active_binds[i]->transfer_capability;
	}

	talloc_free(active_binds);
	return transfer_cap;
}

/*! common allocation + low-level initialization of a bind. Called by vc-drivers */
int ns2_bind_alloc(struct gprs_ns2_inst *nsi, const char *name,
		   struct gprs_ns2_vc_bind **result)
{
	struct gprs_ns2_vc_bind *bind;

	if (!name)
		return -EINVAL;

	if (gprs_ns2_bind_by_name(nsi, name))
		return -EALREADY;

	bind = talloc_zero(nsi, struct gprs_ns2_vc_bind);
	if (!bind)
		return -ENOMEM;

	bind->name = talloc_strdup(bind, name);
	if (!bind->name) {
		talloc_free(bind);
		return -ENOMEM;
	}

	bind->statg = osmo_stat_item_group_alloc(bind, &nsbind_statg_desc, nsi->bind_rate_ctr_idx);
	if (!bind->statg) {
		talloc_free(bind);
		return -ENOMEM;
	}

	bind->sns_sig_weight = 1;
	bind->sns_data_weight = 1;
	bind->nsi = nsi;
	INIT_LLIST_HEAD(&bind->nsvc);
	llist_add_tail(&bind->list, &nsi->binding);

	nsi->bind_rate_ctr_idx++;

	if (result)
		*result = bind;

	return 0;
}

/*! @} */
