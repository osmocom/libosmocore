/*! \file gprs_ns.c
 * GPRS Networks Service (NS) messages on the Gb interface.
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05)
 * as well as its successor 3GPP TS 48.016 */
/*
 * (C) 2009-2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016-2017 sysmocom - s.f.m.c. GmbH
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
 * - Only one NS-VC for each NSE: No load-sharing function
 * - NSVCI 65535 and 65534 are reserved for internal use
 * - Only UDP is supported as of now, no frame relay support
 * - There are no BLOCK and UNBLOCK timers (yet?)
 *
 * \file gprs_ns.c */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/signal.h>
#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_ns_frgre.h>

#include "common_vty.h"
#include "gb_internal.h"

#define ns_set_state(ns_, st_) ns_set_state_with_log(ns_, st_, false, __FILE__, __LINE__)
#define ns_set_remote_state(ns_, st_) ns_set_state_with_log(ns_, st_, true, __FILE__, __LINE__)
#define ns_mark_blocked(ns_) ns_set_state(ns_, (ns_)->state | NSE_S_BLOCKED)
#define ns_mark_unblocked(ns_) ns_set_state(ns_, (ns_)->state & (~NSE_S_BLOCKED));
#define ns_mark_alive(ns_) ns_set_state(ns_, (ns_)->state | NSE_S_ALIVE)
#define ns_mark_dead(ns_) ns_set_state(ns_, (ns_)->state & (~NSE_S_ALIVE));

#define ERR_IF_NSVC_USES_SNS(nsvc, reason) 							\
	do {											\
		if ((nsvc)->nsi->bss_sns_fi) {							\
			LOGP(DNS, LOGL_ERROR, "NSEI=%u Asked to %s. Rejected on IP-SNS\n",	\
				nsvc->nsei, reason);						\
			osmo_log_backtrace(DNS, LOGL_ERROR);					\
			return -EIO;								\
		}										\
	} while (0)

static const struct tlv_definition ns_att_tlvdef = {
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
		/* TODO: IP_ADDR can be 5 or 17 bytes long, depending on first byte. This
		 * cannot be expressed in our TLV parser.  However, we don't do IPv6 anyway */
		[NS_IE_IP_ADDR] = { TLV_TYPE_FIXED, 5 },
	},
};

enum ns_ctr {
	NS_CTR_PKTS_IN,
	NS_CTR_PKTS_OUT,
	NS_CTR_BYTES_IN,
	NS_CTR_BYTES_OUT,
	NS_CTR_BLOCKED,
	NS_CTR_DEAD,
	NS_CTR_REPLACED,
	NS_CTR_NSEI_CHG,
	NS_CTR_INV_VCI,
	NS_CTR_INV_NSEI,
	NS_CTR_LOST_ALIVE,
	NS_CTR_LOST_RESET,
};

static const struct rate_ctr_desc nsvc_ctr_description[] = {
	{ "packets:in", "Packets at NS Level  ( In)" },
	{ "packets:out","Packets at NS Level  (Out)" },
	{ "bytes:in",	"Bytes at NS Level    ( In)" },
	{ "bytes:out",	"Bytes at NS Level    (Out)" },
	{ "blocked",	"NS-VC Block count         " },
	{ "dead",	"NS-VC gone dead count     " },
	{ "replaced",	"NS-VC replaced other count" },
	{ "nsei-chg",	"NS-VC changed NSEI count  " },
	{ "inv-nsvci",	"NS-VCI was invalid count  " },
	{ "inv-nsei",	"NSEI was invalid count    " },
	{ "lost:alive",	"ALIVE ACK missing count   " },
	{ "lost:reset",	"RESET ACK missing count   " },
};

static const struct rate_ctr_group_desc nsvc_ctrg_desc = {
	.group_name_prefix = "ns:nsvc",
	.group_description = "NSVC Peer Statistics",
	.num_ctr = ARRAY_SIZE(nsvc_ctr_description),
	.ctr_desc = nsvc_ctr_description,
	.class_id = OSMO_STATS_CLASS_PEER,
};

enum ns_stat {
	NS_STAT_ALIVE_DELAY,
};

static const struct osmo_stat_item_desc nsvc_stat_description[] = {
	{ "alive.delay", "ALIVE response time        ", "ms", 16, 0 },
};

static const struct osmo_stat_item_group_desc nsvc_statg_desc = {
	.group_name_prefix = "ns.nsvc",
	.group_description = "NSVC Peer Statistics",
	.num_items = ARRAY_SIZE(nsvc_stat_description),
	.item_desc = nsvc_stat_description,
	.class_id = OSMO_STATS_CLASS_PEER,
};

const struct value_string gprs_ns_signal_ns_names[] = {
	{ S_NS_RESET,		"NS-RESET" },
	{ S_NS_BLOCK,		"NS-BLOCK" },
	{ S_NS_UNBLOCK,		"NS-UNBLOCK" },
	{ S_NS_ALIVE_EXP,	"NS-ALIVE expired" },
	{ S_NS_REPLACED,	"NSVC replaced" },
	{ S_NS_MISMATCH,	"Unexpected IE" },
	{ S_SNS_CONFIGURED,	"SNS Configured" },
	{ 0, NULL }
};

#define CHECK_TX_RC(rc, nsvc) \
		if (rc < 0)							\
			LOGP(DNS, LOGL_ERROR, "TX failed (%d) to peer %s\n",	\
				rc, gprs_ns_ll_str(nsvc));

static bool nsvc_is_not_used(const struct gprs_nsvc *nsvc)
{
	if (nsvc->data_weight == 0 && nsvc->sig_weight == 0)
		return true;
	else
		return false;
}

struct msgb *gprs_ns_msgb_alloc(void)
{
	struct msgb *msg = msgb_alloc_headroom(NS_ALLOC_SIZE, NS_ALLOC_HEADROOM,
		"GPRS/NS");
	if (!msg) {
		LOGP(DNS, LOGL_ERROR, "Failed to allocate NS message of size %d\n",
			NS_ALLOC_SIZE);
	}
	return msg;
}

/* FIXME: convert to osmo_fsm */
static inline void ns_set_state_with_log(struct gprs_nsvc *nsvc, uint32_t state, bool is_remote,
					 const char *file, unsigned line)
{
	uint32_t old_state = is_remote ? nsvc->remote_state : nsvc->state;

	LOGPSRC(DNS, LOGL_DEBUG, file, line, "NSEI %d (NS-VCI=%u) setting %sstate [%s,%s,%s] -> [%s,%s,%s]\n",
		nsvc->nsei, nsvc->nsvci, is_remote ? "remote " : "",
		NS_DESC_A(old_state), NS_DESC_B(old_state), NS_DESC_R(old_state),
		NS_DESC_A(state), NS_DESC_B(state), NS_DESC_R(state));

	if (is_remote)
		nsvc->remote_state = state;
	else
		nsvc->state = state;
}

/*! Lookup struct gprs_nsvc based on NSVCI
 *  \param[in] nsi NS instance in which to search
 *  \param[in] nsvci NSVCI to be searched
 *  \returns gprs_nsvc of respective NSVCI
 */
struct gprs_nsvc *gprs_nsvc_by_nsvci(struct gprs_ns_inst *nsi, uint16_t nsvci)
{
	struct gprs_nsvc *nsvc;
	llist_for_each_entry(nsvc, &nsi->gprs_nsvcs, list) {
		if (nsvc->nsvci == nsvci)
			return nsvc;
	}
	return NULL;
}

/*! Lookup struct gprs_nsvc based on NSEI
 *  \param[in] nsi NS instance in which to search
 *  \param[in] nsei NSEI to be searched
 *  \returns first gprs_nsvc of respective NSEI
 */
struct gprs_nsvc *gprs_nsvc_by_nsei(struct gprs_ns_inst *nsi, uint16_t nsei)
{
	struct gprs_nsvc *nsvc;
	llist_for_each_entry(nsvc, &nsi->gprs_nsvcs, list) {
		if (nsvc->nsei == nsei)
			return nsvc;
	}
	return NULL;
}

/*! Determine active NS-VC for given NSEI + BVCI.
 *  Use this function to determine which of the NS-VCs inside the NS Instance
 *  shall be used to transmit data for given NSEI + BVCI */
static struct gprs_nsvc *gprs_active_nsvc_by_nsei(struct gprs_ns_inst *nsi,
						  uint16_t nsei, uint16_t bvci)
{
	struct gprs_nsvc *nsvc;
	llist_for_each_entry(nsvc, &nsi->gprs_nsvcs, list) {
		/* if signalling BVCI, skip any NSVC with signalling weight == 0 */
		if (bvci == 0 && nsvc->sig_weight == 0)
			continue;
		/* if point-to-point BVCI, skip any NSVC with data weight == 0 */
		if (bvci != 0 && nsvc->data_weight == 0)
			continue;
		if (nsvc->nsei == nsei) {
			if (!(nsvc->state & NSE_S_BLOCKED) &&
			    nsvc->state & NSE_S_ALIVE)
				return nsvc;
		}
	}
	return NULL;
}

/*! Lookup NS-VC based on specified remote peer socket addr.
 *  \param[in] nsi NS Instance within which we shall look up the NS-VC
 *  \param[in] sin Remote peer Socket Address (IP + UDP Port)
 *  \returns NS-VC matching the given peer; NULL in case of none */
struct gprs_nsvc *gprs_nsvc_by_rem_addr(struct gprs_ns_inst *nsi, const struct sockaddr_in *sin)
{
	struct gprs_nsvc *nsvc;
	llist_for_each_entry(nsvc, &nsi->gprs_nsvcs, list) {
		if (nsvc->ip.bts_addr.sin_addr.s_addr ==
					sin->sin_addr.s_addr &&
		    nsvc->ip.bts_addr.sin_port == sin->sin_port)
			return nsvc;
	}
	return NULL;
}

static void gprs_ns_timer_cb(void *data);

/*! Create a new NS-VC (Virtual Circuit) within given instance
 *  \param[in] nsi NS Instance in which to create the NSVC
 *  \param[in] nsvci] NS Virtual Connection Identifier for this NSVC
 *  \param[in] sig_weight Signalling Weight of this NS-VC. Use "0" for no signalling
 *  \param[in] data_weight Data WEight of this NS-VC. Use "0" for no data
 *  \returns newly-created gprs_nsvc within nsi. NULL on error. */
struct gprs_nsvc *gprs_nsvc_create2(struct gprs_ns_inst *nsi, uint16_t nsvci,
				    uint8_t sig_weight, uint8_t data_weight)
{
	struct gprs_nsvc *nsvc;

	if (gprs_nsvc_by_nsvci(nsi, nsvci)) {
		LOGP(DNS, LOGL_ERROR, "Cannot create NS-VC for already-existing NSVCI=%u\n", nsvci);
		return NULL;
	}

	LOGP(DNS, LOGL_INFO, "NSVCI=%u Creating NS-VC with Signal weight %u, Data weight %u\n",
	     nsvci, sig_weight, data_weight);

	nsvc = talloc_zero(nsi, struct gprs_nsvc);
	if (!nsvc)
		return NULL;
	nsvc->nsvci = nsvci;
	nsvc->nsvci_is_valid = 1;
	/* before RESET procedure: BLOCKED and DEAD */
	if (nsi->bss_sns_fi || !nsi->nsip.use_reset_block_unblock)
		ns_set_state(nsvc, 0);
	else
		ns_set_state(nsvc, NSE_S_BLOCKED);
	nsvc->nsi = nsi;
	osmo_timer_setup(&nsvc->timer, gprs_ns_timer_cb, nsvc);
	nsvc->ctrg = rate_ctr_group_alloc(nsvc, &nsvc_ctrg_desc, nsvci);
	if (!nsvc->ctrg) {
		talloc_free(nsvc);
		return NULL;
	}
	nsvc->statg = osmo_stat_item_group_alloc(nsvc, &nsvc_statg_desc, nsvci);
	nsvc->sig_weight = sig_weight;
	nsvc->data_weight = data_weight;

	llist_add(&nsvc->list, &nsi->gprs_nsvcs);

	return nsvc;
}

/*! Delete given NS-VC
 *  \param[in] nsvc gprs_nsvc to be deleted
 */
void gprs_nsvc_delete(struct gprs_nsvc *nsvc)
{
	osmo_timer_del(&nsvc->timer);
	llist_del(&nsvc->list);
	rate_ctr_group_free(nsvc->ctrg);
	osmo_stat_item_group_free(nsvc->statg);
	talloc_free(nsvc);
}

static void ns_osmo_signal_dispatch(struct gprs_nsvc *nsvc, unsigned int signal,
			       uint8_t cause)
{
	struct ns_signal_data nssd = {0};

	nssd.nsvc = nsvc;
	nssd.cause = cause;

	osmo_signal_dispatch(SS_L_NS, signal, &nssd);
}

static void ns_osmo_signal_dispatch_mismatch(struct gprs_nsvc *nsvc,
					     struct msgb *msg,
					     uint8_t pdu_type, uint8_t ie_type)
{
	struct ns_signal_data nssd = {0};

	nssd.nsvc     = nsvc;
	nssd.pdu_type = pdu_type;
	nssd.ie_type  = ie_type;
	nssd.msg      = msg;

	osmo_signal_dispatch(SS_L_NS, S_NS_MISMATCH, &nssd);
}

static void ns_osmo_signal_dispatch_replaced(struct gprs_nsvc *nsvc, struct gprs_nsvc *old_nsvc)
{
	struct ns_signal_data nssd = {0};

	nssd.nsvc = nsvc;
	nssd.old_nsvc = old_nsvc;

	osmo_signal_dispatch(SS_L_NS, S_NS_REPLACED, &nssd);
}

const struct value_string gprs_ns_pdu_strings[] = {
	/* 3GPP TS 48.016 §9.2 Network Service Control PDUs */
	{ NS_PDUT_UNITDATA,	"NS-UNITDATA" },	/* §9.2.1 */
	{ NS_PDUT_RESET,	"NS-RESET" },		/* §9.2.5 */
	{ NS_PDUT_RESET_ACK,	"NS-RESET-ACK" },	/* §9.2.6 */
	{ NS_PDUT_BLOCK,	"NS-BLOCK" },		/* §9.2.3 */
	{ NS_PDUT_BLOCK_ACK,	"NS-BLOCK-ACK" },	/* §9.2.4 */
	{ NS_PDUT_UNBLOCK,	"NS-UNBLOCK" },		/* §9.2.8 */
	{ NS_PDUT_UNBLOCK_ACK,	"NS-UNBLOCK-ACK" },	/* §9.2.9 */
	{ NS_PDUT_STATUS,	"NS-STATUS" },		/* §9.2.7 */
	{ NS_PDUT_ALIVE,	"NS-ALIVE" },		/* §9.2.1 */
	{ NS_PDUT_ALIVE_ACK,	"NS-ALIVE-ACK" },	/* §9.2.2 */
	/* 3GPP TS 48.016 §9.3 Sub-Network Service Control PDUs */
	{ SNS_PDUT_ACK,			"SNS-ACK" },		/* §9.3.1 */
	{ SNS_PDUT_ADD,			"SNS-ADD" },		/* §9.3.2 */
	{ SNS_PDUT_CHANGE_WEIGHT,	"SNS-CHANGEWEIGHT" },	/* §9.3.3 */
	{ SNS_PDUT_CONFIG,		"SNS-CONFIG" },		/* §9.3.4 */
	{ SNS_PDUT_CONFIG_ACK,		"SNS-CONFIG-ACK" },	/* §9.3.5 */
	{ SNS_PDUT_DELETE,		"SNS-DELETE" },		/* §9.3.6 */
	{ SNS_PDUT_SIZE,		"SNS-SIZE" },		/* §9.3.7 */
	{ SNS_PDUT_SIZE_ACK,		"SNS-SIZE-ACK" },	/* §9.3.8 */
	{ 0, NULL }
};

/* Section 10.3.2, Table 13 */
static const struct value_string ns_cause_str[] = {
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

/*! Obtain a human-readable string for NS cause value */
const char *gprs_ns_cause_str(enum ns_cause cause)
{
	return get_value_string(ns_cause_str, cause);
}

static int nsip_sendmsg(struct gprs_nsvc *nsvc, struct msgb *msg);
extern int grps_ns_frgre_sendmsg(struct gprs_nsvc *nsvc, struct msgb *msg);

static bool ns_is_sns(uint8_t pdu_type)
{
	switch (pdu_type) {
	case SNS_PDUT_CONFIG:
	case SNS_PDUT_ACK:
	case SNS_PDUT_ADD:
	case SNS_PDUT_CHANGE_WEIGHT:
	case SNS_PDUT_DELETE:
	case SNS_PDUT_CONFIG_ACK:
	case SNS_PDUT_SIZE:
	case SNS_PDUT_SIZE_ACK:
		return true;
	default:
		return false;
	}
}

static int gprs_ns_tx(struct gprs_nsvc *nsvc, struct msgb *msg)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	int ret;

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	/* A pre-configured endpoint shall not be used for NSE data or signalling
	 * traffic (with the exception of Size and Configuration procedures) unless it
	 * is configured by the SGSN using the auto-configuration procedures. */
	if (nsvc_is_not_used(nsvc) && !ns_is_sns(nsh->pdu_type) && nsh->pdu_type != NS_PDUT_STATUS) {
		LOGP(DNS, LOGL_NOTICE, "Not transmitting %s on unused/pre-configured endpoint\n",
			get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));
		msgb_free(msg);
		return -EINVAL;
	}

	/* Increment number of Uplink bytes */
	rate_ctr_inc(rate_ctr_group_get_ctr(nsvc->ctrg, NS_CTR_PKTS_OUT));
	rate_ctr_add(rate_ctr_group_get_ctr(nsvc->ctrg, NS_CTR_BYTES_OUT), msgb_l2len(msg));

	switch (nsvc->ll) {
	case GPRS_NS_LL_UDP:
		ret = nsip_sendmsg(nsvc, msg);
		if (ret < 0)
			LOGP(DNS, LOGL_INFO,
				"failed to send NS message via UDP: %s\n",
				strerror(-ret));
		break;
	case GPRS_NS_LL_FR_GRE:
		ret = gprs_ns_frgre_sendmsg(nsvc, msg);
		if (ret < 0)
			LOGP(DNS, LOGL_INFO,
				"failed to send NS message via FR/GRE: %s\n",
				strerror(-ret));
		break;
	default:
		LOGP(DNS, LOGL_ERROR, "unsupported NS linklayer %u\n", nsvc->ll);
		msgb_free(msg);
		ret = -EIO;
		break;
	}
	return ret;
}

static int gprs_ns_tx_simple(struct gprs_nsvc *nsvc, uint8_t pdu_type)
{
	struct msgb *msg = gprs_ns_msgb_alloc();
	struct gprs_ns_hdr *nsh;

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	if (!msg)
		return -ENOMEM;

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = pdu_type;

	return gprs_ns_tx(nsvc, msg);
}

/*! Transmit a NS-RESET on a given NSVC
 *  \param[in] nsvc NS-VC used for transmission
 *  \paam[in] cause Numeric NS cause value
 */
int gprs_ns_tx_reset(struct gprs_nsvc *nsvc, uint8_t cause)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsvci = osmo_htons(nsvc->nsvci);
	uint16_t nsei = osmo_htons(nsvc->nsei);

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS RESET");

	msg = gprs_ns_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	LOGP(DNS, LOGL_INFO, "NSEI=%u Tx NS RESET (NSVCI=%u, cause=%s)\n",
		nsvc->nsei, nsvc->nsvci, gprs_ns_cause_str(cause));

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_RESET;

	msgb_tvlv_put(msg, NS_IE_CAUSE, 1, &cause);
	msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *) &nsvci);
	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *) &nsei);

	return gprs_ns_tx(nsvc, msg);

}

/*! Transmit a NS-STATUS on a given NSVC
 *  \param[in] nsvc NS-VC to be used for transmission
 *  \param[in] cause Numeric NS cause value
 *  \param[in] bvci BVCI to be reset within NSVC
 *  \param[in] orig_msg message causing the STATUS */
int gprs_ns_tx_status(struct gprs_nsvc *nsvc, uint8_t cause,
		      uint16_t bvci, struct msgb *orig_msg)
{
	struct msgb *msg = gprs_ns_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	uint16_t nsvci = osmo_htons(nsvc->nsvci);

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	bvci = osmo_htons(bvci);

	if (!msg)
		return -ENOMEM;

	LOGP(DNS, LOGL_NOTICE, "NSEI=%u Tx NS STATUS (NSVCI=%u, cause=%s)\n",
		nsvc->nsei, nsvc->nsvci, gprs_ns_cause_str(cause));

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_STATUS;

	msgb_tvlv_put(msg, NS_IE_CAUSE, 1, &cause);

	/* Section 9.2.7.1: Static conditions for NS-VCI */
	if (cause == NS_CAUSE_NSVC_BLOCKED ||
	    cause == NS_CAUSE_NSVC_UNKNOWN)
		msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *)&nsvci);

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

	/* Section 9.2.7.3: Static conditions for BVCI */
	if (cause == NS_CAUSE_BVCI_UNKNOWN)
		msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *)&bvci);

	return gprs_ns_tx(nsvc, msg);
}

/*! Transmit a NS-BLOCK on a given NS-VC
 *  \param[in] nsvc NS-VC on which the NS-BLOCK is to be transmitted
 *  \param[in] cause Numeric NS Cause value
 *  \returns 0 in case of success
 */
int gprs_ns_tx_block(struct gprs_nsvc *nsvc, uint8_t cause)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsvci = osmo_htons(nsvc->nsvci);

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS BLOCK");

	msg = gprs_ns_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	LOGP(DNS, LOGL_INFO, "NSEI=%u Tx NS BLOCK (NSVCI=%u, cause=%s)\n",
		nsvc->nsei, nsvc->nsvci, gprs_ns_cause_str(cause));

	/* be conservative and mark it as blocked even now! */
	ns_mark_blocked(nsvc);
	rate_ctr_inc(rate_ctr_group_get_ctr(nsvc->ctrg, NS_CTR_BLOCKED));

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_BLOCK;

	msgb_tvlv_put(msg, NS_IE_CAUSE, 1, &cause);
	msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *) &nsvci);

	return gprs_ns_tx(nsvc, msg);
}

/*! Transmit a NS-BLOCK-ACK on a given NS-VC
 *  \param[in] nsvc NS-VC on which the NS-BLOCK is to be transmitted
 *  \returns 0 in case of success
 */
static int gprs_ns_tx_block_ack(struct gprs_nsvc *nsvc)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsvci = osmo_htons(nsvc->nsvci);

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS BLOCK ACK");

	msg = gprs_ns_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	LOGP(DNS, LOGL_INFO, "NSEI=%u Tx NS BLOCK ACK (NSVCI=%u)\n", nsvc->nsei, nsvc->nsvci);

	/* be conservative and mark it as blocked even now! */
	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_BLOCK_ACK;

	msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *) &nsvci);

	return gprs_ns_tx(nsvc, msg);
}

/*! Transmit a NS-UNBLOCK on a given NS-VC
 *  \param[in] nsvc NS-VC on which the NS-UNBLOCK is to be transmitted
 *  \returns 0 in case of success
 */
int gprs_ns_tx_unblock(struct gprs_nsvc *nsvc)
{
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS UNBLOCK");

	LOGP(DNS, LOGL_INFO, "NSEI=%u Tx NS UNBLOCK (NSVCI=%u)\n",
		nsvc->nsei, nsvc->nsvci);

	return gprs_ns_tx_simple(nsvc, NS_PDUT_UNBLOCK);
}

/*! Transmit a NS-ALIVE on a given NS-VC
 *  \param[in] nsvc NS-VC on which the NS-ALIVE is to be transmitted
 *  \returns 0 in case of success
 */
int gprs_ns_tx_alive(struct gprs_nsvc *nsvc)
{
	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	LOGP(DNS, LOGL_DEBUG, "NSEI=%u Tx NS ALIVE (NSVCI=%u)\n",
		nsvc->nsei, nsvc->nsvci);

	return gprs_ns_tx_simple(nsvc, NS_PDUT_ALIVE);
}

/*! Transmit a NS-ALIVE-ACK on a given NS-VC
 *  \param[in] nsvc NS-VC on which the NS-ALIVE-ACK is to be transmitted
 *  \returns 0 in case of success
 */
int gprs_ns_tx_alive_ack(struct gprs_nsvc *nsvc)
{
	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	LOGP(DNS, LOGL_DEBUG, "NSEI=%u Tx NS ALIVE_ACK (NSVCI=%u)\n",
		nsvc->nsei, nsvc->nsvci);

	return gprs_ns_tx_simple(nsvc, NS_PDUT_ALIVE_ACK);
}

static const enum ns_timeout timer_mode_tout[_NSVC_TIMER_NR] = {
	[NSVC_TIMER_TNS_RESET]	= NS_TOUT_TNS_RESET,
	[NSVC_TIMER_TNS_ALIVE]	= NS_TOUT_TNS_ALIVE,
	[NSVC_TIMER_TNS_TEST]	= NS_TOUT_TNS_TEST,
};

static const struct value_string timer_mode_strs[] = {
	{ NSVC_TIMER_TNS_RESET, "tns-reset" },
	{ NSVC_TIMER_TNS_ALIVE, "tns-alive" },
	{ NSVC_TIMER_TNS_TEST, "tns-test" },
	{ 0, NULL }
};

static void nsvc_start_timer(struct gprs_nsvc *nsvc, enum nsvc_timer_mode mode)
{
	enum ns_timeout tout = timer_mode_tout[mode];
	unsigned int seconds = nsvc->nsi->timeout[tout];

	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	DEBUGP(DNS, "NSEI=%u Starting timer in mode %s (%u seconds)\n",
		nsvc->nsei, get_value_string(timer_mode_strs, mode),
		seconds);

	osmo_timer_del(&nsvc->timer);

	osmo_gettimeofday(&nsvc->timer_started, NULL);
	nsvc->timer_mode = mode;
	osmo_timer_schedule(&nsvc->timer, seconds, 0);
}

static int nsvc_timer_elapsed_ms(struct gprs_nsvc *nsvc)
{
	struct timeval now, elapsed;
	osmo_gettimeofday(&now, NULL);
	timersub(&now, &nsvc->timer_started, &elapsed);

	return 1000 * elapsed.tv_sec + elapsed.tv_usec / 1000;
}

static void gprs_ns_timer_cb(void *data)
{
	struct gprs_nsvc *nsvc = data;
	enum ns_timeout tout = timer_mode_tout[nsvc->timer_mode];
	unsigned int seconds = nsvc->nsi->timeout[tout];

	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	DEBUGP(DNS, "NSEI=%u Timer expired in mode %s (%u seconds)\n",
		nsvc->nsei, get_value_string(timer_mode_strs, nsvc->timer_mode),
		seconds);

	switch (nsvc->timer_mode) {
	case NSVC_TIMER_TNS_ALIVE:
		/* Tns-alive case: we expired without response ! */
		rate_ctr_inc(rate_ctr_group_get_ctr(nsvc->ctrg, NS_CTR_LOST_ALIVE));
		nsvc->alive_retries++;
		if (nsvc->alive_retries >
			nsvc->nsi->timeout[NS_TOUT_TNS_ALIVE_RETRIES]) {
			/* mark as dead (and blocked unless IP-SNS) */
			rate_ctr_inc(rate_ctr_group_get_ctr(nsvc->ctrg, NS_CTR_DEAD));
			if (!nsvc->nsi->bss_sns_fi && nsvc->nsi->nsip.use_reset_block_unblock) {
				ns_set_state(nsvc, NSE_S_BLOCKED);
				rate_ctr_inc(rate_ctr_group_get_ctr(nsvc->ctrg, NS_CTR_BLOCKED));
			} else
				ns_set_state(nsvc, 0);
			LOGP(DNS, LOGL_NOTICE,
				"NSEI=%u Tns-alive expired more then "
				"%u times, blocking NS-VC\n", nsvc->nsei,
				nsvc->nsi->timeout[NS_TOUT_TNS_ALIVE_RETRIES]);
			ns_osmo_signal_dispatch(nsvc, S_NS_ALIVE_EXP, 0);
			/* FIXME: should we send this signal in case of SNS? */
			if (!nsvc->nsi->bss_sns_fi && nsvc->nsi->nsip.use_reset_block_unblock)
				ns_osmo_signal_dispatch(nsvc, S_NS_BLOCK, NS_CAUSE_NSVC_BLOCKED);
			return;
		}
		/* Tns-test case: send NS-ALIVE PDU */
		gprs_ns_tx_alive(nsvc);
		/* start Tns-alive timer */
		nsvc_start_timer(nsvc, NSVC_TIMER_TNS_ALIVE);
		break;
	case NSVC_TIMER_TNS_TEST:
		/* Tns-test case: send NS-ALIVE PDU */
		gprs_ns_tx_alive(nsvc);
		/* start Tns-alive timer (transition into faster
		 * alive retransmissions) */
		nsvc->alive_retries = 0;
		nsvc_start_timer(nsvc, NSVC_TIMER_TNS_ALIVE);
		break;
	case NSVC_TIMER_TNS_RESET:
		rate_ctr_inc(rate_ctr_group_get_ctr(nsvc->ctrg, NS_CTR_LOST_RESET));
		if (!(nsvc->state & NSE_S_RESET))
			LOGP(DNS, LOGL_NOTICE,
				"NSEI=%u Reset timed out but RESET flag is not set\n",
				nsvc->nsei);
		/* Mark NS-VC locally as blocked and dead */
		ns_set_state(nsvc, NSE_S_BLOCKED | NSE_S_RESET);
		/* Chapter 7.3: Re-send the RESET */
		gprs_ns_tx_reset(nsvc, NS_CAUSE_OM_INTERVENTION);
		/* Re-start Tns-reset timer */
		nsvc_start_timer(nsvc, NSVC_TIMER_TNS_RESET);
		break;
	case _NSVC_TIMER_NR:
		break;
	}
}

/* Section 9.2.6 */
static int gprs_ns_tx_reset_ack(struct gprs_nsvc *nsvc)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsvci, nsei;

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS RESET ACK");

	msg = gprs_ns_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	nsvci = osmo_htons(nsvc->nsvci);
	nsei = osmo_htons(nsvc->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = NS_PDUT_RESET_ACK;

	LOGP(DNS, LOGL_INFO, "NSEI=%u Tx NS RESET ACK (NSVCI=%u)\n",
		nsvc->nsei, nsvc->nsvci);

	msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *)&nsvci);
	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);

	return gprs_ns_tx(nsvc, msg);
}

/*! Encode + Transmit a SNS-ACK as per Section 9.3.1.
 *  \param[in] nsvc NS-VC through which to transmit the ACK
 *  \param[in] trans_id Transaction ID which to acknowledge
 *  \param[in] cause Pointer to cause value (NULL if no cause to be sent)
 *  \param[in] ip4_elems Array of IPv4 Elements
 *  \param[in] num_ip4_elems number of ip4_elems
 *  \returns 0 on success; negative in case of error */
int gprs_ns_tx_sns_ack(struct gprs_nsvc *nsvc, uint8_t trans_id, uint8_t *cause,
			const struct gprs_ns_ie_ip4_elem *ip4_elems,
			unsigned int num_ip4_elems)
{
	struct msgb *msg = gprs_ns_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nsi->bss_sns_fi) {
		LOGP(DNS, LOGL_ERROR, "NSEI=%u Cannot transmit SNS on NSVC without SNS active\n",
		     nsvc->nsei);
		msgb_free(msg);
		return -EIO;
	}

	nsei = osmo_htons(nsvc->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = SNS_PDUT_ACK;
	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);
	msgb_v_put(msg, trans_id);
	if (cause)
		msgb_tvlv_put(msg, NS_IE_CAUSE, 1, cause);
	if (ip4_elems) {
		/* List of IP4 Elements 10.3.2c */
		msgb_tvlv_put(msg, NS_IE_IPv4_LIST,
			      num_ip4_elems*sizeof(struct gprs_ns_ie_ip4_elem),
			      (const uint8_t *)ip4_elems);
	}
	/* FIXME: List of IP6 elements 10.3.2d */
	return gprs_ns_tx(nsvc, msg);
}

/*! Encode + Transmit a SNS-CONFIG as per Section 9.3.4.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-CONFIG
 *  \param[in] end_flag Whether or not this is the last SNS-CONFIG
 *  \param[in] ip4_elems Array of IPv4 Elements
 *  \param[in] num_ip4_elems number of ip4_elems
 *  \returns 0 on success; negative in case of error */
int gprs_ns_tx_sns_config(struct gprs_nsvc *nsvc, bool end_flag,
			  const struct gprs_ns_ie_ip4_elem *ip4_elems,
			  unsigned int num_ip4_elems)
{
	struct msgb *msg = gprs_ns_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nsi->bss_sns_fi) {
		LOGP(DNS, LOGL_ERROR, "NSEI=%u Cannot transmit SNS on NSVC without SNS active\n",
		     nsvc->nsei);
		msgb_free(msg);
		return -EIO;
	}

	nsei = osmo_htons(nsvc->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = SNS_PDUT_CONFIG;

	msgb_v_put(msg, end_flag ? 0x01 : 0x00);
	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);

	/* List of IP4 Elements 10.3.2c */
	msgb_tvlv_put(msg, NS_IE_IPv4_LIST, num_ip4_elems*sizeof(struct gprs_ns_ie_ip4_elem),
			(const uint8_t *)ip4_elems);
	/* FIXME: List of IP6 elements 10.3.2d */

	return gprs_ns_tx(nsvc, msg);
}

/*! Encode + Transmit a SNS-CONFIG-ACK as per Section 9.3.5.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-CONFIG-ACK
 *  \param[in] cause Pointer to cause value (NULL if no cause to be sent)
 *  \returns 0 on success; negative in case of error */
int gprs_ns_tx_sns_config_ack(struct gprs_nsvc *nsvc, uint8_t *cause)
{
	struct msgb *msg = gprs_ns_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nsi->bss_sns_fi) {
		LOGP(DNS, LOGL_ERROR, "NSEI=%u Cannot transmit SNS on NSVC without SNS active\n",
		     nsvc->nsei);
		msgb_free(msg);
		return -EIO;
	}

	nsei = osmo_htons(nsvc->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = SNS_PDUT_CONFIG_ACK;

	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);
	if (cause)
		msgb_tvlv_put(msg, NS_IE_CAUSE, 1, cause);

	return gprs_ns_tx(nsvc, msg);
}


/*! Encode + transmit a SNS-SIZE as per Section 9.3.7.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-SIZE
 *  \param[in] reset_flag Whether or not to add a RESET flag
 *  \param[in] max_nr_nsvc Maximum number of NS-VCs
 *  \param[in] ip4_ep_nr Number of IPv4 endpoints (NULL if none)
 *  \param[in] ip6_ep_nr Number of IPv6 endpoints (NULL if none)
 *  \returns 0 on success; negative in case of error */
int gprs_ns_tx_sns_size(struct gprs_nsvc *nsvc, bool reset_flag, uint16_t max_nr_nsvc,
			uint16_t *ip4_ep_nr, uint16_t *ip6_ep_nr)
{
	struct msgb *msg = gprs_ns_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nsi->bss_sns_fi) {
		LOGP(DNS, LOGL_ERROR, "NSEI=%u Cannot transmit SNS on NSVC without SNS active\n",
		     nsvc->nsei);
		msgb_free(msg);
		return -EIO;
	}

	nsei = osmo_htons(nsvc->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = SNS_PDUT_SIZE;

	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);
	msgb_tv_put(msg, NS_IE_RESET_FLAG, reset_flag ? 0x01 : 0x00);
	msgb_tv16_put(msg, NS_IE_MAX_NR_NSVC, max_nr_nsvc);
	if (ip4_ep_nr)
		msgb_tv16_put(msg, NS_IE_IPv4_EP_NR, *ip4_ep_nr);
	if (ip6_ep_nr)
		msgb_tv16_put(msg, NS_IE_IPv6_EP_NR, *ip6_ep_nr);

	return gprs_ns_tx(nsvc, msg);
}

/*! Encode + Transmit a SNS-SIZE-ACK as per Section 9.3.8.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-SIZE-ACK
 *  \param[in] cause Pointer to cause value (NULL if no cause to be sent)
 *  \returns 0 on success; negative in case of error */
int gprs_ns_tx_sns_size_ack(struct gprs_nsvc *nsvc, uint8_t *cause)
{
	struct msgb *msg = gprs_ns_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nsi->bss_sns_fi) {
		LOGP(DNS, LOGL_ERROR, "NSEI=%u Cannot transmit SNS on NSVC without SNS active\n",
		     nsvc->nsei);
		msgb_free(msg);
		return -EIO;
	}

	nsei = osmo_htons(nsvc->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = SNS_PDUT_SIZE_ACK;

	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);
	if (cause)
		msgb_tvlv_put(msg, NS_IE_CAUSE, 1, cause);

	return gprs_ns_tx(nsvc, msg);
}

/*! High-level function for transmitting a NS-UNITDATA messsage
 *  \param[in] nsi NS-instance on which we shall transmit
 *  \param[in] msg struct msgb to be trasnmitted
 *
 * This function obtains the NS-VC by the msgb_nsei(msg) and then checks
 * if the NS-VC is ALIVE and not BLOCKED.  After that, it adds a NS
 * header for the NS-UNITDATA message type and sends it off.
 *
 * Section 9.2.10: transmit side / NS-UNITDATA-REQUEST primitive
 */
int gprs_ns_sendmsg(struct gprs_ns_inst *nsi, struct msgb *msg)
{
	struct gprs_nsvc *nsvc;
	struct gprs_ns_hdr *nsh;
	uint16_t bvci = msgb_bvci(msg);

	nsvc = gprs_active_nsvc_by_nsei(nsi, msgb_nsei(msg), msgb_bvci(msg));
	if (!nsvc) {
		int rc;
		if (gprs_nsvc_by_nsei(nsi, msgb_nsei(msg))) {
		    LOGP(DNS, LOGL_ERROR,
			 "All NS-VCs for NSEI %u are either dead or blocked!\n",
			 msgb_nsei(msg));
		    rc = -EBUSY;
		} else {
		    LOGP(DNS, LOGL_ERROR, "Unable to resolve NSEI %u "
			 "to NS-VC!\n", msgb_nsei(msg));
		    rc = -EINVAL;
		}

		msgb_free(msg);
		return rc;
	}
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	msg->l2h = msgb_push(msg, sizeof(*nsh) + 3);
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	if (!nsh) {
		LOGP(DNS, LOGL_ERROR, "Not enough headroom for NS header\n");
		msgb_free(msg);
		return -EIO;
	}

	nsh->pdu_type = NS_PDUT_UNITDATA;
	/* spare octet in data[0] */
	nsh->data[1] = bvci >> 8;
	nsh->data[2] = bvci & 0xff;

	return gprs_ns_tx(nsvc, msg);
}

/* Section 9.2.10: receive side */
static int gprs_ns_rx_unitdata(struct gprs_nsvc *nsvc, struct msgb *msg)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *)msg->l2h;
	uint16_t bvci;

	if (nsvc->state & NSE_S_BLOCKED)
		return gprs_ns_tx_status(nsvc, NS_CAUSE_NSVC_BLOCKED,
					 0, msg);

	/* spare octet in data[0] */
	bvci = nsh->data[1] << 8 | nsh->data[2];
	msgb_bssgph(msg) = &nsh->data[3];
	msgb_bvci(msg) = bvci;

	/* call upper layer (BSSGP) */
	return nsvc->nsi->cb(GPRS_NS_EVT_UNIT_DATA, nsvc, msg, bvci);
}

/* Section 9.2.7 */
static int gprs_ns_rx_status(struct gprs_nsvc *nsvc, struct msgb *msg)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	struct tlv_parsed tp;
	uint8_t cause;
	int rc;

	LOGP(DNS, LOGL_NOTICE, "NSEI=%u Rx NS STATUS ", nsvc->nsei);

	rc = tlv_parse(&tp, &ns_att_tlvdef, nsh->data,
			msgb_l2len(msg) - sizeof(*nsh), 0, 0);
	if (rc < 0) {
		LOGPC(DNS, LOGL_NOTICE, "Error during TLV Parse\n");
		LOGP(DNS, LOGL_ERROR, "NSEI=%u Rx NS STATUS: "
			"Error during TLV Parse\n", nsvc->nsei);
		return rc;
	}

	if (!TLVP_PRESENT(&tp, NS_IE_CAUSE)) {
		LOGPC(DNS, LOGL_INFO, "missing cause IE\n");
		return -EINVAL;
	}

	cause = *TLVP_VAL(&tp, NS_IE_CAUSE);
	LOGPC(DNS, LOGL_NOTICE, "cause=%s\n", gprs_ns_cause_str(cause));

	return 0;
}

/* Replace a nsvc object with another based on NSVCI.
 * This function replaces looks for a NSVC with the given NSVCI and replaces it
 * if possible and necessary. If replaced, the former value of *nsvc is
 * returned in *old_nsvc.
 * \return != 0 if *nsvc points to a matching NSVC.
 */
static int gprs_nsvc_replace_if_found(uint16_t nsvci,
				      struct gprs_nsvc **nsvc,
				      struct gprs_nsvc **old_nsvc)
{
	struct gprs_nsvc *matching_nsvc;

	if ((*nsvc)->nsvci == nsvci) {
		*old_nsvc = NULL;
		return 1;
	}

	matching_nsvc = gprs_nsvc_by_nsvci((*nsvc)->nsi, nsvci);

	if (!matching_nsvc)
		return 0;

	/* The NS-VCI is already used by this NS-VC */

	char *old_peer;

	/* Exchange the NS-VC objects */
	*old_nsvc = *nsvc;
	*nsvc     = matching_nsvc;

	/* Do logging */
	old_peer = talloc_strdup(*old_nsvc, gprs_ns_ll_str(*old_nsvc));
	LOGP(DNS, LOGL_INFO, "NS-VC changed link (NSVCI=%u) from %s to %s\n",
	     nsvci, old_peer, gprs_ns_ll_str(*nsvc));

	talloc_free(old_peer);

	return 1;
}

/* Section 7.3 */
static int gprs_ns_rx_reset(struct gprs_nsvc **nsvc, struct msgb *msg)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	struct tlv_parsed tp;
	uint8_t cause;
	uint16_t nsvci, nsei;
	struct gprs_nsvc *orig_nsvc = NULL;
	int rc;

	rc = tlv_parse(&tp, &ns_att_tlvdef, nsh->data,
			msgb_l2len(msg) - sizeof(*nsh), 0, 0);
	if (rc < 0) {
		LOGP(DNS, LOGL_ERROR, "NSEI=%u Rx NS RESET "
			"Error during TLV Parse\n", (*nsvc)->nsei);
		return rc;
	}

	if (!TLVP_PRESENT(&tp, NS_IE_CAUSE) ||
	    !TLVP_PRESENT(&tp, NS_IE_VCI) ||
	    !TLVP_PRESENT(&tp, NS_IE_NSEI)) {
		LOGP(DNS, LOGL_ERROR, "NS RESET Missing mandatory IE\n");
		gprs_ns_tx_status(*nsvc, NS_CAUSE_MISSING_ESSENT_IE, 0, msg);
		return -EINVAL;
	}

	cause = *(uint8_t  *) TLVP_VAL(&tp, NS_IE_CAUSE);
	nsvci = tlvp_val16be(&tp, NS_IE_VCI);
	nsei  = tlvp_val16be(&tp, NS_IE_NSEI);

	LOGP(DNS, LOGL_INFO, "NSVCI=%u%s Rx NS RESET (NSEI=%u, NSVCI=%u, cause=%s)\n",
	     (*nsvc)->nsvci, (*nsvc)->nsvci_is_valid ? "" : "(invalid)",
	     nsei, nsvci, gprs_ns_cause_str(cause));

	if ((*nsvc)->nsvci_is_valid && (*nsvc)->nsvci != nsvci) {
		if ((*nsvc)->persistent || (*nsvc)->remote_end_is_sgsn) {
			/* The incoming RESET doesn't match the NSVCI. Send an
			 * appropriate RESET_ACK and ignore the RESET.
			 * See 3GPP TS 08.16, 7.3.1, 2nd paragraph.
			 */
			ns_osmo_signal_dispatch_mismatch(*nsvc, msg,
							 NS_PDUT_RESET,
							 NS_IE_VCI);
			rate_ctr_inc(rate_ctr_group_get_ctr((*nsvc)->ctrg, NS_CTR_INV_VCI));
			gprs_ns_tx_reset_ack(*nsvc);
			return 0;
		}

		/* NS-VCI has changed */
		if (!gprs_nsvc_replace_if_found(nsvci, nsvc, &orig_nsvc)) {
			LOGP(DNS, LOGL_INFO, "Creating NS-VC %d replacing %d "
			     "at %s\n",
			     nsvci, (*nsvc)->nsvci,
			     gprs_ns_ll_str(*nsvc));
			orig_nsvc = *nsvc;
			*nsvc = gprs_nsvc_create2((*nsvc)->nsi, nsvci, 1, 1);
			(*nsvc)->nsei  = nsei;
		}
	}

	if ((*nsvc)->nsvci_is_valid && (*nsvc)->nsei != nsei) {
		if ((*nsvc)->persistent || (*nsvc)->remote_end_is_sgsn) {
			/* The incoming RESET doesn't match the NSEI. Send an
			 * appropriate RESET_ACK and ignore the RESET.
			 * See 3GPP TS 08.16, 7.3.1, 3rd paragraph.
			 */
			ns_osmo_signal_dispatch_mismatch(*nsvc, msg,
							 NS_PDUT_RESET,
							 NS_IE_NSEI);
			rate_ctr_inc(rate_ctr_group_get_ctr((*nsvc)->ctrg, NS_CTR_INV_NSEI));
			rc = gprs_ns_tx_reset_ack(*nsvc);
			CHECK_TX_RC(rc, *nsvc);
			return 0;
		}

		/* NSEI has changed */
		rate_ctr_inc(rate_ctr_group_get_ctr((*nsvc)->ctrg, NS_CTR_NSEI_CHG));
		(*nsvc)->nsei = nsei;
	}

	/* Mark NS-VC as blocked and alive */
	ns_set_state(*nsvc, NSE_S_BLOCKED | NSE_S_ALIVE);

	if (orig_nsvc) {
		rate_ctr_inc(rate_ctr_group_get_ctr((*nsvc)->ctrg, NS_CTR_REPLACED));
		ns_osmo_signal_dispatch_replaced(*nsvc, orig_nsvc);

		/* Update the ll info fields */
		gprs_ns_ll_copy(*nsvc, orig_nsvc);
		gprs_ns_ll_clear(orig_nsvc);
	} else {
		(*nsvc)->nsei  = nsei;
		(*nsvc)->nsvci = nsvci;
		(*nsvc)->nsvci_is_valid = 1;
		rate_ctr_group_upd_idx((*nsvc)->ctrg, nsvci);
		osmo_stat_item_group_udp_idx((*nsvc)->statg, nsvci);
	}

	/* inform interested parties about the fact that this NSVC
	 * has received RESET */
	ns_osmo_signal_dispatch(*nsvc, S_NS_RESET, cause);

	rc = gprs_ns_tx_reset_ack(*nsvc);

	/* start the test procedure */
	gprs_nsvc_start_test(*nsvc);

	return rc;
}

static int gprs_ns_rx_reset_ack(struct gprs_nsvc **nsvc, struct msgb *msg)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	struct tlv_parsed tp;
	uint16_t nsvci, nsei;
	struct gprs_nsvc *orig_nsvc = NULL;
	int rc;

	rc = tlv_parse(&tp, &ns_att_tlvdef, nsh->data,
			msgb_l2len(msg) - sizeof(*nsh), 0, 0);
	if (rc < 0) {
		LOGP(DNS, LOGL_ERROR, "NSEI=%u Rx NS RESET ACK "
			"Error during TLV Parse\n", (*nsvc)->nsei);
		return rc;
	}

	if (!TLVP_PRESENT(&tp, NS_IE_VCI) ||
	    !TLVP_PRESENT(&tp, NS_IE_NSEI)) {
		LOGP(DNS, LOGL_ERROR, "NS RESET ACK Missing mandatory IE\n");
		rc = gprs_ns_tx_status(*nsvc, NS_CAUSE_MISSING_ESSENT_IE, 0, msg);
		CHECK_TX_RC(rc, *nsvc);
		return -EINVAL;
	}

	nsvci = tlvp_val16be(&tp, NS_IE_VCI);
	nsei  = tlvp_val16be(&tp, NS_IE_NSEI);

	LOGP(DNS, LOGL_INFO, "NSVCI=%u%s Rx NS RESET ACK (NSEI=%u, NSVCI=%u)\n",
	     (*nsvc)->nsvci, (*nsvc)->nsvci_is_valid ? "" : "(invalid)",
	     nsei, nsvci);

	if (!((*nsvc)->state & NSE_S_RESET)) {
		/* Not waiting for a RESET_ACK on this NS-VC, ignore it.
		 * See 3GPP TS 08.16, 7.3.1, 5th paragraph.
		 */
		LOGP(DNS, LOGL_ERROR,
		     "NS RESET ACK Discarding unexpected message for "
		     "NS-VCI %d from SGSN NSEI=%d\n",
		     nsvci, nsei);
		return 0;
	}

	if (!(*nsvc)->nsvci_is_valid) {
		LOGP(DNS, LOGL_NOTICE,
		     "NS RESET ACK Uninitialised NS-VC (%u) for "
		     "NS-VCI %d, NSEI=%d from %s\n",
		     (*nsvc)->nsvci, nsvci, nsei, gprs_ns_ll_str(*nsvc));
		return -EINVAL;
	}

	if ((*nsvc)->nsvci != nsvci) {
		/* NS-VCI has changed */

		/* if !0, use another NSVC object that matches the NSVCI */
		int use_other_nsvc;

		/* Only do this with BSS peers */
		use_other_nsvc = !(*nsvc)->remote_end_is_sgsn &&
			!(*nsvc)->persistent;

		if (use_other_nsvc)
			/* Update *nsvc to point to the right NSVC object */
			use_other_nsvc = gprs_nsvc_replace_if_found(nsvci, nsvc,
								    &orig_nsvc);

		if (!use_other_nsvc) {
			/* The incoming RESET_ACK doesn't match the NSVCI.
			 * See 3GPP TS 08.16, 7.3.1, 4th paragraph.
			 */
			ns_osmo_signal_dispatch_mismatch(*nsvc, msg,
							 NS_PDUT_RESET_ACK,
							 NS_IE_VCI);
			rate_ctr_inc(rate_ctr_group_get_ctr((*nsvc)->ctrg, NS_CTR_INV_VCI));
			LOGP(DNS, LOGL_ERROR,
			     "NS RESET ACK Unknown NS-VCI %d (%s NSEI=%d) "
			     "from %s\n",
			     nsvci,
			     (*nsvc)->remote_end_is_sgsn ? "SGSN" : "BSS",
			     nsei, gprs_ns_ll_str(*nsvc));
			return -EINVAL;
		}

		/* Notify others */
		rate_ctr_inc(rate_ctr_group_get_ctr((*nsvc)->ctrg, NS_CTR_REPLACED));
		ns_osmo_signal_dispatch_replaced(*nsvc, orig_nsvc);

		/* Update the ll info fields */
		gprs_ns_ll_copy(*nsvc, orig_nsvc);
		gprs_ns_ll_clear(orig_nsvc);
	} else if ((*nsvc)->nsei != nsei) {
		if ((*nsvc)->persistent || (*nsvc)->remote_end_is_sgsn) {
			/* The incoming RESET_ACK doesn't match the NSEI.
			 * See 3GPP TS 08.16, 7.3.1, 4th paragraph.
			 */
			ns_osmo_signal_dispatch_mismatch(*nsvc, msg,
							 NS_PDUT_RESET_ACK,
							 NS_IE_NSEI);
			rate_ctr_inc(rate_ctr_group_get_ctr((*nsvc)->ctrg, NS_CTR_INV_NSEI));
			LOGP(DNS, LOGL_ERROR,
			     "NS RESET ACK Unknown NSEI %d (NS-VCI=%u) from %s\n",
			     nsei, nsvci, gprs_ns_ll_str(*nsvc));
			return -EINVAL;
		}

		/* NSEI has changed */
		rate_ctr_inc(rate_ctr_group_get_ctr((*nsvc)->ctrg, NS_CTR_NSEI_CHG));
		(*nsvc)->nsei = nsei;
	}

	/* Mark NS-VC as blocked and alive */
	ns_set_state(*nsvc, NSE_S_BLOCKED | NSE_S_ALIVE);
	ns_set_remote_state(*nsvc, NSE_S_BLOCKED | NSE_S_ALIVE);
	rate_ctr_inc(rate_ctr_group_get_ctr((*nsvc)->ctrg, NS_CTR_BLOCKED));
	if ((*nsvc)->persistent || (*nsvc)->remote_end_is_sgsn) {
		/* stop RESET timer */
		osmo_timer_del(&(*nsvc)->timer);
	}
	/* Initiate TEST proc.: Send ALIVE and start timer */
	gprs_nsvc_start_test(*nsvc);

	return 0;
}

static int gprs_ns_rx_block(struct gprs_nsvc *nsvc, struct msgb *msg)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	struct tlv_parsed tp;
	uint8_t *cause;
	int rc;

	LOGP(DNS, LOGL_INFO, "NSEI=%u Rx NS BLOCK\n", nsvc->nsei);

	ns_mark_blocked(nsvc);

	rc = tlv_parse(&tp, &ns_att_tlvdef, nsh->data,
			msgb_l2len(msg) - sizeof(*nsh), 0, 0);
	if (rc < 0) {
		LOGP(DNS, LOGL_ERROR, "NSEI=%u Rx NS BLOCK "
			"Error during TLV Parse\n", nsvc->nsei);
		return rc;
	}

	if (!TLVP_PRESENT(&tp, NS_IE_CAUSE) ||
	    !TLVP_PRESENT(&tp, NS_IE_VCI)) {
		LOGP(DNS, LOGL_ERROR, "NS RESET Missing mandatory IE\n");
		gprs_ns_tx_status(nsvc, NS_CAUSE_MISSING_ESSENT_IE, 0, msg);
		return -EINVAL;
	}

	cause = (uint8_t *) TLVP_VAL(&tp, NS_IE_CAUSE);
	//nsvci = (uint16_t *) TLVP_VAL(&tp, NS_IE_VCI);

	ns_osmo_signal_dispatch(nsvc, S_NS_BLOCK, *cause);
	rate_ctr_inc(rate_ctr_group_get_ctr(nsvc->ctrg, NS_CTR_BLOCKED));

	return gprs_ns_tx_block_ack(nsvc);
}

int gprs_ns_vc_create(struct gprs_ns_inst *nsi, struct msgb *msg,
		      struct gprs_nsvc *fallback_nsvc,
		      struct gprs_nsvc **new_nsvc);

int gprs_ns_process_msg(struct gprs_ns_inst *nsi, struct msgb *msg,
		      struct gprs_nsvc **nsvc);

/*! Receive incoming NS message from underlying transport layer
 *  \param nsi NS instance to which the data belongs
 *  \param[in] msg message buffer containing newly-received data
 *  \param[in] saddr socketaddr from which data was received
 *  \param[in] ll link-layer type in which data was received
 *  \returns 0 in case of success, < 0 in case of error
 *
 * This is the main entry point int othe NS imlementation where frames
 * from the underlying transport (normally UDP) enter.
 */
int gprs_ns_rcvmsg(struct gprs_ns_inst *nsi, struct msgb *msg,
		   struct sockaddr_in *saddr, enum gprs_ns_ll ll)
{
	struct gprs_nsvc *nsvc;
	int rc = 0;

	/* look up the NSVC based on source address */
	nsvc = gprs_nsvc_by_rem_addr(nsi, saddr);

	if (!nsvc) {
		struct gprs_nsvc *fallback_nsvc;

		fallback_nsvc = nsi->unknown_nsvc;
		log_set_context(LOG_CTX_GB_NSVC, fallback_nsvc);
		fallback_nsvc->ip.bts_addr = *saddr;
		fallback_nsvc->ll = ll;

		rc = gprs_ns_vc_create(nsi, msg, fallback_nsvc, &nsvc);

		if (rc < 0)
			return rc;

		rc = 0;
	}

	if (nsvc)
		rc = gprs_ns_process_msg(nsi, msg, &nsvc);

	return rc;
}

char *gprs_ns_ll_str_buf(char *buf, size_t buf_len, const struct gprs_nsvc *nsvc)
{
	switch(nsvc->ll) {
	case GPRS_NS_LL_UDP:
		snprintf(buf, buf_len, "%s:%u",
			 inet_ntoa(nsvc->ip.bts_addr.sin_addr), osmo_ntohs(nsvc->ip.bts_addr.sin_port));
		break;
	case GPRS_NS_LL_FR_GRE:
		snprintf(buf, buf_len, "%s:%u",
			 inet_ntoa(nsvc->frgre.bts_addr.sin_addr), osmo_ntohs(nsvc->frgre.bts_addr.sin_port));
		break;
	default:
		buf[0] = '\0';
		break;
	}

	buf[buf_len - 1] = '\0';

	return buf;
}

const char *gprs_ns_ll_str(const struct gprs_nsvc *nsvc)
{
	static __thread char buf[80];
	return gprs_ns_ll_str_buf(buf, sizeof(buf), nsvc);
}

char *gprs_ns_ll_str_c(const void *ctx, const struct gprs_nsvc *nsvc)
{
	char *buf = talloc_size(ctx, INET6_ADDRSTRLEN+10);
	if (!buf)
		return buf;
	return gprs_ns_ll_str_buf(buf, INET6_ADDRSTRLEN+10, nsvc);
}

void gprs_ns_ll_copy(struct gprs_nsvc *nsvc, struct gprs_nsvc *other)
{
	nsvc->ll = other->ll;

	switch (nsvc->ll) {
	case GPRS_NS_LL_UDP:
		nsvc->ip = other->ip;
		break;
	case GPRS_NS_LL_FR_GRE:
		nsvc->frgre = other->frgre;
		break;
	default:
		break;
	}
}

void gprs_ns_ll_clear(struct gprs_nsvc *nsvc)
{
	switch (nsvc->ll) {
	case GPRS_NS_LL_UDP:
		nsvc->ip.bts_addr.sin_addr.s_addr = INADDR_ANY;
		nsvc->ip.bts_addr.sin_port        = 0;
		break;
	case GPRS_NS_LL_FR_GRE:
		nsvc->frgre.bts_addr.sin_addr.s_addr = INADDR_ANY;
		nsvc->frgre.bts_addr.sin_port        = 0;
		break;
	default:
		break;
	}
}

/*! Create/get NS-VC independently from underlying transport layer
 *  \param nsi NS instance to which the data belongs
 *  \param[in] msg message buffer containing newly-received data
 *  \param[in] fallback_nsvc is used to send error messages back to the peer
 *             and to initialise the ll info of a created NS-VC object
 *  \param[out] new_nsvc contains a pointer to a NS-VC object if one has
 *              been created or found
 *  \returns < 0 in case of error, GPRS_NS_CS_SKIPPED if a message has been
 *           skipped, GPRS_NS_CS_REJECTED if a message has been rejected and
 *           answered accordingly, GPRS_NS_CS_CREATED if a new NS-VC object
 *           has been created and registered, and GPRS_NS_CS_FOUND if an
 *           existing NS-VC object has been found with the same NSEI.
 *
 * This contains the initial NS automaton state (NS-VC not yet attached).
 */
int gprs_ns_vc_create(struct gprs_ns_inst *nsi, struct msgb *msg,
		      struct gprs_nsvc *fallback_nsvc,
		      struct gprs_nsvc **new_nsvc)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *)msg->l2h;
	struct gprs_nsvc *existing_nsvc;

	struct tlv_parsed tp;
	uint16_t nsvci;
	uint16_t nsei;

	int rc;

	if (nsh->pdu_type == NS_PDUT_STATUS) {
		/* Do not respond, see 3GPP TS 08.16, 7.5.1 */
		LOGP(DNS, LOGL_INFO, "Ignoring NS STATUS from %s "
		     "for non-existing NS-VC\n",
		     gprs_ns_ll_str(fallback_nsvc));
		return GPRS_NS_CS_SKIPPED;
	}

	if (nsh->pdu_type == NS_PDUT_ALIVE_ACK) {
		/* Ignore this, see 3GPP TS 08.16, 7.4.1 */
		LOGP(DNS, LOGL_INFO, "Ignoring NS ALIVE ACK from %s "
		     "for non-existing NS-VC\n",
		     gprs_ns_ll_str(fallback_nsvc));
		return GPRS_NS_CS_SKIPPED;
	}

	if (nsh->pdu_type == NS_PDUT_RESET_ACK) {
		/* Ignore this, see 3GPP TS 08.16, 7.3.1 */
		LOGP(DNS, LOGL_INFO, "Ignoring NS RESET ACK from %s "
		     "for non-existing NS-VC\n",
		     gprs_ns_ll_str(fallback_nsvc));
		return GPRS_NS_CS_SKIPPED;
	}

	/* Only the RESET procedure creates a new NSVC */
	if (nsh->pdu_type != NS_PDUT_RESET) {
		/* Since we have no NSVC, we have to use a fake */
		log_set_context(LOG_CTX_GB_NSVC, fallback_nsvc);
		LOGP(DNS, LOGL_INFO, "Rejecting NS PDU type %s "
		     "from %s for non-existing NS-VC\n",
		     get_value_string(gprs_ns_pdu_strings, nsh->pdu_type), gprs_ns_ll_str(fallback_nsvc));
		fallback_nsvc->nsvci = fallback_nsvc->nsei = 0xfffe;
		fallback_nsvc->nsvci_is_valid = 0;
		ns_set_state(fallback_nsvc, NSE_S_ALIVE);

		rc = gprs_ns_tx_status(fallback_nsvc,
				       NS_CAUSE_PDU_INCOMP_PSTATE, 0, msg);
		if (rc < 0) {
			LOGP(DNS, LOGL_ERROR, "TX failed (%d) to peer %s\n",
				rc, gprs_ns_ll_str(fallback_nsvc));
			return rc;
		}
		return GPRS_NS_CS_REJECTED;
	}

	rc = tlv_parse(&tp, &ns_att_tlvdef, nsh->data,
		       msgb_l2len(msg) - sizeof(*nsh), 0, 0);
	if (rc < 0) {
		LOGP(DNS, LOGL_ERROR, "Rx NS RESET Error %d during "
		     "TLV Parse\n", rc);
		return rc;
	}
	if (!TLVP_PRESENT(&tp, NS_IE_CAUSE) ||
	    !TLVP_PRESENT(&tp, NS_IE_VCI) || !TLVP_PRESENT(&tp, NS_IE_NSEI)) {
		LOGP(DNS, LOGL_ERROR, "NS RESET Missing mandatory IE\n");
		rc = gprs_ns_tx_status(fallback_nsvc, NS_CAUSE_MISSING_ESSENT_IE, 0,
				  msg);
		CHECK_TX_RC(rc, fallback_nsvc);
		return -EINVAL;
	}
	nsvci = tlvp_val16be(&tp, NS_IE_VCI);
	nsei  = tlvp_val16be(&tp, NS_IE_NSEI);
	/* Check if we already know this NSVCI, the remote end might
	 * simply have changed addresses, or it is a SGSN */
	existing_nsvc = gprs_nsvc_by_nsvci(nsi, nsvci);
	if (!existing_nsvc) {
		*new_nsvc = gprs_nsvc_create2(nsi, 0xffff, 1, 1);
		(*new_nsvc)->nsvci_is_valid = 0;
		log_set_context(LOG_CTX_GB_NSVC, *new_nsvc);
		gprs_ns_ll_copy(*new_nsvc, fallback_nsvc);
		LOGP(DNS, LOGL_INFO, "Creating NS-VC for BSS at %s\n",
		     gprs_ns_ll_str(fallback_nsvc));

		return GPRS_NS_CS_CREATED;
	}

	/* Check NSEI */
	if (existing_nsvc->nsei != nsei) {
		LOGP(DNS, LOGL_NOTICE,
			"NS-VC changed NSEI (NSVCI=%u) from %u to %u\n",
			nsvci, existing_nsvc->nsei, nsei);

		/* Override old NSEI */
		existing_nsvc->nsei  = nsei;

		/* Do statistics */
		rate_ctr_inc(rate_ctr_group_get_ctr(existing_nsvc->ctrg, NS_CTR_NSEI_CHG));
	}

	*new_nsvc = existing_nsvc;
	gprs_ns_ll_copy(*new_nsvc, fallback_nsvc);
	return GPRS_NS_CS_FOUND;
}

/*! Process NS message independently from underlying transport layer
 *  \param nsi NS instance to which the data belongs
 *  \param[in] msg message buffer containing newly-received data
 *  \param[inout] nsvc refers to the virtual connection, may be modified when
 *                     processing a NS_RESET
 *  \returns 0 in case of success, < 0 in case of error
 *
 * This contains the main NS automaton.
 */
int gprs_ns_process_msg(struct gprs_ns_inst *nsi, struct msgb *msg,
			struct gprs_nsvc **nsvc)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	struct tlv_parsed tp;
	int rc = 0;

	msgb_nsei(msg) = (*nsvc)->nsei;

	log_set_context(LOG_CTX_GB_NSVC, *nsvc);

	/* Increment number of Incoming bytes */
	rate_ctr_inc(rate_ctr_group_get_ctr((*nsvc)->ctrg, NS_CTR_PKTS_IN));
	rate_ctr_add(rate_ctr_group_get_ctr((*nsvc)->ctrg, NS_CTR_BYTES_IN), msgb_l2len(msg));

	if (nsvc_is_not_used(*nsvc) && !ns_is_sns(nsh->pdu_type) && nsh->pdu_type != NS_PDUT_STATUS) {
		LOGP(DNS, LOGL_NOTICE, "NSEI=%u Rx %s on unused/pre-configured endpoint, discarding\n",
			(*nsvc)->nsei, get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));
		gprs_ns_tx_status(*nsvc, NS_CAUSE_PROTO_ERR_UNSPEC, 0, msg);
		return 0;
	}

	switch (nsh->pdu_type) {
	case NS_PDUT_ALIVE:
		/* If we're dead and blocked and suddenly receive a
		 * NS-ALIVE out of the blue, we might have been re-started
		 * and should send a NS-RESET to make sure everything recovers
		 * fine. */
		if ((*nsvc)->state == NSE_S_BLOCKED)
			rc = gprs_nsvc_reset((*nsvc), NS_CAUSE_PDU_INCOMP_PSTATE);
		else if (!((*nsvc)->state & NSE_S_RESET)) {
			/* if we're not alive, we cannot transmit the ACK; set ALIVE */
			if (!((*nsvc)->state & NSE_S_ALIVE))
				ns_mark_alive(*nsvc);
			rc = gprs_ns_tx_alive_ack(*nsvc);
		}
		break;
	case NS_PDUT_ALIVE_ACK:
		ns_mark_alive(*nsvc);
		if ((*nsvc)->timer_mode == NSVC_TIMER_TNS_ALIVE)
			osmo_stat_item_set(osmo_stat_item_group_get_item((*nsvc)->statg, NS_STAT_ALIVE_DELAY),
				nsvc_timer_elapsed_ms(*nsvc));
		/* stop Tns-alive and start Tns-test */
		nsvc_start_timer(*nsvc, NSVC_TIMER_TNS_TEST);
		if ((*nsvc)->remote_end_is_sgsn) {
			/* FIXME: this should be one level higher */
			if ((*nsvc)->state & NSE_S_BLOCKED)
				rc = gprs_ns_tx_unblock(*nsvc);
		}
		break;
	case NS_PDUT_UNITDATA:
		/* actual user data */
		rc = gprs_ns_rx_unitdata(*nsvc, msg);
		break;
	case NS_PDUT_STATUS:
		rc = gprs_ns_rx_status(*nsvc, msg);
		break;
	case NS_PDUT_RESET:
		rc = gprs_ns_rx_reset(nsvc, msg);
		break;
	case NS_PDUT_RESET_ACK:
		rc = gprs_ns_rx_reset_ack(nsvc, msg);
		break;
	case NS_PDUT_UNBLOCK:
		/* Section 7.2: unblocking procedure */
		LOGP(DNS, LOGL_INFO, "NSEI=%u Rx NS UNBLOCK\n", (*nsvc)->nsei);
		ns_mark_unblocked(*nsvc);
		/* This UNBLOCK_ACK message will cause our peer to move us into NS_UNBLOCKED state. */
		rc = gprs_ns_tx_simple(*nsvc, NS_PDUT_UNBLOCK_ACK);
		if (rc < 0)
			break;
		/*
		 * UNBLOCK_ACK has been transmitted.
		 * Signal handlers may send additional messages following UNBLOCK_ACK under
		 * the assumption that NS is now in UNBLOCKED state at our peer's end.
		 */
		ns_osmo_signal_dispatch(*nsvc, S_NS_UNBLOCK, 0);
		break;
	case NS_PDUT_UNBLOCK_ACK:
		LOGP(DNS, LOGL_INFO, "NSEI=%u Rx NS UNBLOCK ACK\n", (*nsvc)->nsei);
		/* mark NS-VC as unblocked + active */
		ns_set_state(*nsvc, NSE_S_ALIVE);
		ns_set_remote_state(*nsvc, NSE_S_ALIVE);
		ns_osmo_signal_dispatch(*nsvc, S_NS_UNBLOCK, 0);
		break;
	case NS_PDUT_BLOCK:
		rc = gprs_ns_rx_block(*nsvc, msg);
		break;
	case NS_PDUT_BLOCK_ACK:
		LOGP(DNS, LOGL_INFO, "NSEI=%u Rx NS BLOCK ACK\n", (*nsvc)->nsei);
		/* mark remote NS-VC as blocked + active */
		ns_set_remote_state(*nsvc, NSE_S_BLOCKED | NSE_S_ALIVE);
		break;
	case SNS_PDUT_CONFIG:
		if (!nsi->bss_sns_fi)
			goto unexpected_sns;
		/* one additional byte ('end flag') before the TLV part starts */
		rc = tlv_parse(&tp, &ns_att_tlvdef, nsh->data+1,
				msgb_l2len(msg) - sizeof(*nsh)-1, 0, 0);
		if (rc < 0) {
			LOGPC(DNS, LOGL_NOTICE, "Error during TLV Parse in %s\n", msgb_hexdump(msg));
			return rc;
		}
		/* All sub-network service related message types */
		rc = gprs_ns_rx_sns(nsi, msg, &tp);
		break;
	case SNS_PDUT_ACK:
	case SNS_PDUT_ADD:
	case SNS_PDUT_CHANGE_WEIGHT:
	case SNS_PDUT_DELETE:
		if (!nsi->bss_sns_fi)
			goto unexpected_sns;
		/* weird layout: NSEI TLV, then value-only transaction IE, then TLV again */
		rc = tlv_parse(&tp, &ns_att_tlvdef, nsh->data+5,
				msgb_l2len(msg) - sizeof(*nsh)-5, 0, 0);
		if (rc < 0) {
			LOGPC(DNS, LOGL_NOTICE, "Error during TLV Parse in %s\n", msgb_hexdump(msg));
			return rc;
		}
		tp.lv[NS_IE_NSEI].val = nsh->data+2;
		tp.lv[NS_IE_NSEI].len = 2;
		tp.lv[NS_IE_TRANS_ID].val = nsh->data+4;
		tp.lv[NS_IE_TRANS_ID].len = 1;
		rc = gprs_ns_rx_sns(nsi, msg, &tp);
		break;
	case SNS_PDUT_CONFIG_ACK:
	case SNS_PDUT_SIZE:
	case SNS_PDUT_SIZE_ACK:
		if (!nsi->bss_sns_fi)
			goto unexpected_sns;
		rc = tlv_parse(&tp, &ns_att_tlvdef, nsh->data,
				msgb_l2len(msg) - sizeof(*nsh), 0, 0);
		if (rc < 0) {
			LOGPC(DNS, LOGL_NOTICE, "Error during TLV Parse in %s\n", msgb_hexdump(msg));
			return rc;
		}
		/* All sub-network service related message types */
		rc = gprs_ns_rx_sns(nsi, msg, &tp);
		break;
	default:
		LOGP(DNS, LOGL_NOTICE, "NSEI=%u Rx Unknown NS PDU type 0x%02x\n",
			(*nsvc)->nsei, nsh->pdu_type);
		rc = -EINVAL;
		break;
unexpected_sns:
		LOGP(DNS, LOGL_NOTICE, "NSEI=%u Rx %s for NS Instance that has no SNS!\n",
			(*nsvc)->nsei, get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));
		rc = -EINVAL;
		break;
	}
	return rc;
}

static bool gprs_sns_fsm_registered = false;

/*! Create a new GPRS NS instance
 *  \param[in] cb Call-back function for incoming BSSGP data
 *  \returns dynamically allocated gprs_ns_inst
 */
struct gprs_ns_inst *gprs_ns_instantiate(gprs_ns_cb_t *cb, void *ctx)
{
	struct gprs_ns_inst *nsi;

	if (!gprs_sns_fsm_registered) {
		int rc = gprs_sns_init();
		if (rc < 0)
			return NULL;
		gprs_sns_fsm_registered = true;
	}

	nsi = talloc_zero(ctx, struct gprs_ns_inst);
	if (!nsi)
		return NULL;
	nsi->cb = cb;
	INIT_LLIST_HEAD(&nsi->gprs_nsvcs);
	nsi->timeout[NS_TOUT_TNS_BLOCK] = 3;
	nsi->timeout[NS_TOUT_TNS_BLOCK_RETRIES] = 3;
	nsi->timeout[NS_TOUT_TNS_RESET] = 3;
	nsi->timeout[NS_TOUT_TNS_RESET_RETRIES] = 3;
	nsi->timeout[NS_TOUT_TNS_TEST] = 30;
	nsi->timeout[NS_TOUT_TNS_ALIVE] = 3;
	nsi->timeout[NS_TOUT_TNS_ALIVE_RETRIES] = 10;
	nsi->timeout[NS_TOUT_TSNS_PROV] = 3; /* 1..10 */

	/* Create the dummy NSVC that we use for sending
	 * messages to non-existant/unknown NS-VC's */
	nsi->unknown_nsvc = gprs_nsvc_create2(nsi, 0xfffe, 1, 1);
	nsi->unknown_nsvc->nsvci_is_valid = 0;
	llist_del(&nsi->unknown_nsvc->list);
	INIT_LLIST_HEAD(&nsi->unknown_nsvc->list);

	/* By default we are in IPA compatible mode, that is we use NS-RESET, NS-BLOCK
	 * and NS-UNBLOCK procedures even for an IP/UDP based Gb interface, in violation
	 * of 3GPP TS 48.016. */
	nsi->nsip.use_reset_block_unblock = true;

	return nsi;
}

void gprs_ns_close(struct gprs_ns_inst *nsi)
{
	struct gprs_nsvc *nsvc, *nsvc2;

	gprs_nsvc_delete(nsi->unknown_nsvc);

	/* delete all NSVCs and clear their timers */
	llist_for_each_entry_safe(nsvc, nsvc2, &nsi->gprs_nsvcs, list)
		gprs_nsvc_delete(nsvc);

	/* close socket and unregister */
	if (nsi->nsip.fd.data) {
		close(nsi->nsip.fd.fd);
		osmo_fd_unregister(&nsi->nsip.fd);
		nsi->nsip.fd.data = NULL;
	}
}

/*! Destroy an entire NS instance
 *  \param nsi gprs_ns_inst that is to be destroyed
 *
 *  This function releases all resources associated with the
 *  NS-instance.
 */
void gprs_ns_destroy(struct gprs_ns_inst *nsi)
{
	gprs_ns_close(nsi);
	/* free the NSI */
	talloc_free(nsi);
}


/* NS-over-IP code, according to 3GPP TS 48.016 Chapter 6.2
 * We don't support Size Procedure, Configuration Procedure, ChangeWeight Procedure */

/* Read a single NS-over-IP message */
static struct msgb *read_nsip_msg(struct osmo_fd *bfd, int *error,
				  struct sockaddr_in *saddr)
{
	struct msgb *msg = gprs_ns_msgb_alloc();
	int ret = 0;
	socklen_t saddr_len = sizeof(*saddr);

	if (!msg) {
		*error = -ENOMEM;
		return NULL;
	}

	ret = recvfrom(bfd->fd, msg->data, NS_ALLOC_SIZE - NS_ALLOC_HEADROOM, 0,
			(struct sockaddr *)saddr, &saddr_len);
	if (ret < 0) {
		LOGP(DNS, LOGL_ERROR, "recv error %s during NSIP recvfrom %s\n",
		     strerror(errno), osmo_sock_get_name2(bfd->fd));
		msgb_free(msg);
		*error = ret;
		return NULL;
	} else if (ret == 0) {
		msgb_free(msg);
		*error = ret;
		return NULL;
	}

	msg->l2h = msg->data;
	msgb_put(msg, ret);

	return msg;
}

static int handle_nsip_read(struct osmo_fd *bfd)
{
	int error;
	struct sockaddr_in saddr;
	struct gprs_ns_inst *nsi = bfd->data;
	struct msgb *msg = read_nsip_msg(bfd, &error, &saddr);

	if (!msg)
		return error;

	error = gprs_ns_rcvmsg(nsi, msg, &saddr, GPRS_NS_LL_UDP);

	msgb_free(msg);

	return error;
}

static int handle_nsip_write(struct osmo_fd *bfd)
{
	/* FIXME: actually send the data here instead of nsip_sendmsg() */
	return -EIO;
}

static int nsip_sendmsg(struct gprs_nsvc *nsvc, struct msgb *msg)
{
	int rc;
	struct gprs_ns_inst *nsi = nsvc->nsi;
	struct sockaddr_in *daddr = &nsvc->ip.bts_addr;

	rc = sendto(nsi->nsip.fd.fd, msg->data, msg->len, 0,
		  (struct sockaddr *)daddr, sizeof(*daddr));

	msgb_free(msg);

	return rc;
}

/* UDP Port 23000 carries the LLC-in-BSSGP-in-NS protocol stack */
static int nsip_fd_cb(struct osmo_fd *bfd, unsigned int what)
{
	int rc = 0;

	if (what & OSMO_FD_READ)
		rc = handle_nsip_read(bfd);
	if (what & OSMO_FD_WRITE)
		rc = handle_nsip_write(bfd);

	return rc;
}

/*! Create a listening socket for GPRS NS/UDP/IP
 *  \param[in] nsi NS protocol instance to listen
 *  \returns >=0 (fd) in case of success, negative in case of error
 *
 *  A call to this function will create a UDP socket bound to the port
 *  number and IP address specified in the NS protocol instance. The
 *  file descriptor of the socket will be stored in nsi->nsip.fd.
 */
int gprs_ns_nsip_listen(struct gprs_ns_inst *nsi)
{
	struct in_addr in;
	struct in_addr remote;
	char remote_str[INET_ADDRSTRLEN];
	int ret;

	in.s_addr = osmo_htonl(nsi->nsip.local_ip);
	remote.s_addr = osmo_htonl(nsi->nsip.remote_ip);

	nsi->nsip.fd.cb = nsip_fd_cb;
	nsi->nsip.fd.data = nsi;

	if (nsi->nsip.remote_ip && nsi->nsip.remote_port) {
		/* connect to ensure only we only accept packets from the
		 * configured remote end/peer */
		snprintf(remote_str, sizeof(remote_str), "%s", inet_ntoa(remote));
		ret =
		    osmo_sock_init2_ofd(&nsi->nsip.fd, AF_INET, SOCK_DGRAM,
					IPPROTO_UDP, inet_ntoa(in),
					nsi->nsip.local_port, remote_str,
					nsi->nsip.remote_port, OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT |
					OSMO_SOCK_F_BIND | OSMO_SOCK_F_DSCP(nsi->nsip.dscp));

		LOGP(DNS, LOGL_NOTICE,
		     "Listening for nsip packets from %s:%u on %s:%u\n",
		     remote_str, nsi->nsip.remote_port, inet_ntoa(in), nsi->nsip.local_port);
	} else {
		/* Accept UDP packets from any source IP/Port */
		ret = osmo_sock_init_ofd(&nsi->nsip.fd, AF_INET, SOCK_DGRAM,
					 IPPROTO_UDP, inet_ntoa(in), nsi->nsip.local_port,
					 OSMO_SOCK_F_BIND | OSMO_SOCK_F_DSCP(nsi->nsip.dscp));

		LOGP(DNS, LOGL_NOTICE, "Listening for nsip packets on %s:%u\n", inet_ntoa(in), nsi->nsip.local_port);
	}

	if (ret < 0) {
		nsi->nsip.fd.cb = NULL;
		nsi->nsip.fd.data = NULL;
		return ret;
	}

	LOGP(DNS, LOGL_NOTICE, "NS UDP socket at %s:%d\n", inet_ntoa(in), nsi->nsip.local_port);

	return ret;
}

/*! Initiate a RESET procedure
 *  \param[in] nsvc NS-VC in which to start the procedure
 *  \param[in] cause Numeric NS cause value
 *
 * This is a high-level function initiating a NS-RESET procedure. It
 * will not only send a NS-RESET, but also set the state to BLOCKED and
 * start the Tns-reset timer.
 */
int gprs_nsvc_reset(struct gprs_nsvc *nsvc, uint8_t cause)
{
	int rc;

	ERR_IF_NSVC_USES_SNS(nsvc, "RESET procedure based on API request");

	LOGP(DNS, LOGL_INFO, "NSEI=%u RESET procedure based on API request\n",
		nsvc->nsei);

	/* Mark NS-VC locally as blocked and dead */
	ns_set_state(nsvc, NSE_S_BLOCKED | NSE_S_RESET);

	/* Send NS-RESET PDU */
	rc = gprs_ns_tx_reset(nsvc, cause);
	if (rc < 0) {
		LOGP(DNS, LOGL_ERROR, "NSEI=%u, error resetting NS-VC\n",
			nsvc->nsei);
	}
	/* Start Tns-reset */
	nsvc_start_timer(nsvc, NSVC_TIMER_TNS_RESET);

	return rc;
}

/*! Establish a NS connection (from the BSS) to the SGSN
 *  \param nsi NS-instance
 *  \param[in] dest Destination IP/Port
 *  \param[in] nsei NSEI of the to-be-established NS-VC
 *  \param[in] nsvci NSVCI of the to-be-established NS-VC
 *  \returns struct gprs_nsvc representing the new NS-VC
 *
 * This function will establish a single NS/UDP/IP connection in uplink
 * (BSS to SGSN) direction.
 */
struct gprs_nsvc *gprs_ns_nsip_connect(struct gprs_ns_inst *nsi,
				struct sockaddr_in *dest, uint16_t nsei,
				uint16_t nsvci)
{
	struct gprs_nsvc *nsvc;

	nsvc = gprs_nsvc_by_rem_addr(nsi, dest);
	if (!nsvc)
		nsvc = gprs_nsvc_create2(nsi, nsvci, 1, 1);
	nsvc->ip.bts_addr = *dest;
	nsvc->nsei = nsei;
	nsvc->remote_end_is_sgsn = 1;

	gprs_nsvc_reset(nsvc, NS_CAUSE_OM_INTERVENTION);
	return nsvc;
}

/*! Establish a NS connection (from the BSS) to the SGSN using SNS auto-configuration
 *  \param nsi NS-instance
 *  \param[in] dest Destination IP/Port
 *  \param[in] nsei NSEI of the to-be-established NS-VC
 *  \param[in] nsvci NSVCI of the to-be-established NS-VC
 *  \returns struct gprs_nsvc representing the new NS-VC
 *
 * This function will establish a single NS/UDP/IP connection in uplink
 * (BSS to SGSN) direction.  It will start with the SNS-SIZE procedure,
 * followed by BSS-originated SNS-CONFIG, then SGSN-originated SNS-CONFIG.
 *
 * Once configuration completes, the user will be notified by the S_SNS_CONFIGURED signal,
 * at which point he typically would want to initiate NS-RESET by means of gprs_nsvc_reset().
 */
struct gprs_nsvc *gprs_ns_nsip_connect_sns(struct gprs_ns_inst *nsi,
				struct sockaddr_in *dest, uint16_t nsei,
				uint16_t nsvci)
{
	struct gprs_nsvc *nsvc;

	/* FIXME: We are getting the order wrong here.  Normally, one would want
	 * to start the SNS FSM *before* creating any NS-VC and then create the NS-VC
	 * after the SNS layer has established the IP/port/etc.  However, this would
	 * require some massive code and API changes compared to existing libosmogb,
	 * so let's keep the old logic. */
	nsvc = gprs_nsvc_by_rem_addr(nsi, dest);
	if (!nsvc) {
		/* create NSVC with 0 data + signalling weight. This is illegal in SNS
		 * and can hence only be created locally and serves as indication that
		 * this NS-VC shall not be used for anything except SNS _unless_ it is
		 * modified via SNS-{CONFIG,CHANGEWEIGHT,ADD} to become part of the
		 * active NS-VCs */
		nsvc = gprs_nsvc_create2(nsi, nsvci, 0, 0);
	}
	nsvc->ip.bts_addr = *dest;
	nsvc->nsei = nsei;
	nsvc->remote_end_is_sgsn = 1;
	/* NSVCs are always UNBLOCKED in IP-SNS */
	ns_set_state(nsvc, 0);

	if (nsi->bss_sns_fi)
		osmo_fsm_inst_term(nsi->bss_sns_fi, OSMO_FSM_TERM_REQUEST, NULL);
	nsi->bss_sns_fi = gprs_sns_bss_fsm_alloc(nsi, nsvc, "NSIP");
	gprs_sns_bss_fsm_start(nsi);
	return nsvc;
}

void gprs_ns_set_log_ss(int ss)
{
	DNS = ss;
}

/*! Append the nsvc state to a talloc string
 * \param s The string to append to (allocated with talloc)
 * \param[in] nsvc The NS-VC to print the state of
 * \returns The new string with state information appended to it
 *
 * This function will append a comma-separated state of the NS-VC to the
 * string. The string needs to be allocated with talloc (e.g. talloc_strdup)
 */
char *gprs_nsvc_state_append(char *s, struct gprs_nsvc *nsvc)
{
	s = talloc_asprintf_append(s,
		"%u,%u,%s,%s,%s,%s,%s\n",
		nsvc->nsei, nsvc->nsvci,
		NS_DESC_A(nsvc->state),
		NS_DESC_B(nsvc->state),
		nsvc->remote_end_is_sgsn ? "SGSN" : "BSS",
		NS_DESC_A(nsvc->remote_state),
		NS_DESC_B(nsvc->remote_state));

	return s;
}

/*! Start the ALIVE timer procedure in all NS-VCs part of this NS Instance */
void gprs_nsvc_start_test(struct gprs_nsvc *nsvc)
{
	/* skip the initial NS-VC unless it has explicitly been configured
	 * via SNS-CONFIG from the SGSN */
	if (nsvc_is_not_used(nsvc))
		return;
	gprs_ns_tx_alive(nsvc);
	nsvc_start_timer(nsvc, NSVC_TIMER_TNS_TEST);
}

void gprs_start_alive_all_nsvcs(struct gprs_ns_inst *nsi)
{
	struct gprs_nsvc *nsvc;
	llist_for_each_entry(nsvc, &nsi->gprs_nsvcs, list) {
		/* start the test procedure */
		gprs_nsvc_start_test(nsvc);
	}
}

/*! @} */
