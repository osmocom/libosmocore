/*! \file gprs_ns2_message.c
 * NS-over-FR-over-GRE implementation.
 * GPRS Networks Service (NS) messages on the Gb interface.
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05)
 * as well as its successor 3GPP TS 48.016 */

/* (C) 2020 sysmocom - s.f.m.c. GmbH
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

#include <errno.h>

#include <osmocom/core/byteswap.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/stats.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/protocol/gsm_08_16.h>

#include "gprs_ns2_internal.h"

#define ERR_IF_NSVC_USES_SNS(nsvc, reason)						\
	do {										\
		if (!nsvc->nse->bss_sns_fi)						\
			break;								\
		LOGNSVC(nsvc, LOGL_DEBUG, "invalid packet %s with SNS\n", reason);	\
	} while (0)

static int ns2_validate_reset(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp, uint8_t *cause)
{
	if (!TLVP_PRES_LEN(tp, NS_IE_CAUSE, 1) ||
	    !TLVP_PRES_LEN(tp, NS_IE_VCI, 2) || !TLVP_PRES_LEN(tp, NS_IE_NSEI, 2)) {
		*cause = NS_CAUSE_MISSING_ESSENT_IE;
		return -1;
	}

	return 0;
}

static int ns2_validate_reset_ack(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp, uint8_t *cause)
{
	if (!TLVP_PRES_LEN(tp, NS_IE_VCI, 2) || !TLVP_PRES_LEN(tp, NS_IE_NSEI, 2)) {
		*cause = NS_CAUSE_MISSING_ESSENT_IE;
		return -1;
	}

	return 0;
}

static int ns2_validate_block(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp, uint8_t *cause)
{
	if (!TLVP_PRES_LEN(tp, NS_IE_VCI, 2) || !TLVP_PRES_LEN(tp, NS_IE_CAUSE, 1)) {
		*cause = NS_CAUSE_MISSING_ESSENT_IE;
		return -1;
	}

	return 0;
}

static int ns2_validate_block_ack(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp, uint8_t *cause)
{
	if (!TLVP_PRES_LEN(tp, NS_IE_VCI, 2)) {
		*cause = NS_CAUSE_MISSING_ESSENT_IE;
		return -1;
	}

	return 0;
}

static int ns2_validate_status(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp, uint8_t *cause)
{

	if (!TLVP_PRES_LEN(tp, NS_IE_CAUSE, 1)) {
		*cause = NS_CAUSE_MISSING_ESSENT_IE;
		return -1;
	}

	uint8_t _cause = tlvp_val8(tp, NS_IE_CAUSE, 0);
	switch (_cause) {
	case NS_CAUSE_NSVC_BLOCKED:
	case NS_CAUSE_NSVC_UNKNOWN:
		if (!TLVP_PRES_LEN(tp, NS_IE_VCI, 1)) {
			*cause = NS_CAUSE_MISSING_ESSENT_IE;
			return -1;
		}

		if (nsvc->mode != GPRS_NS2_VC_MODE_BLOCKRESET) {
			*cause = NS_CAUSE_PDU_INCOMP_PSTATE;
			return -1;
		}
		break;
	case NS_CAUSE_SEM_INCORR_PDU:
	case NS_CAUSE_PDU_INCOMP_PSTATE:
	case NS_CAUSE_PROTO_ERR_UNSPEC:
	case NS_CAUSE_INVAL_ESSENT_IE:
	case NS_CAUSE_MISSING_ESSENT_IE:
		if (!TLVP_PRES_LEN(tp, NS_IE_PDU, 1)) {
			*cause = NS_CAUSE_MISSING_ESSENT_IE;
			return -1;
		}
		break;
	case NS_CAUSE_BVCI_UNKNOWN:
		if (!TLVP_PRES_LEN(tp, NS_IE_BVCI, 2)) {
			*cause = NS_CAUSE_MISSING_ESSENT_IE;
			return -1;
		}
		break;
	case NS_CAUSE_UNKN_IP_TEST_FAILED:
		if (!TLVP_PRESENT(tp, NS_IE_IPv4_LIST) && !TLVP_PRESENT(tp, NS_IE_IPv6_LIST)) {
			*cause = NS_CAUSE_MISSING_ESSENT_IE;
			return -1;
		}
		break;
	}

	return 0;
}

int ns2_validate(struct gprs_ns2_vc *nsvc,
		 uint8_t pdu_type,
		 struct msgb *msg,
		 struct tlv_parsed *tp,
		 uint8_t *cause)
{
	switch (pdu_type) {
	case NS_PDUT_RESET:
		return ns2_validate_reset(nsvc, msg, tp, cause);
	case NS_PDUT_RESET_ACK:
		return ns2_validate_reset_ack(nsvc, msg, tp, cause);
	case NS_PDUT_BLOCK:
		return ns2_validate_block(nsvc, msg, tp, cause);
	case NS_PDUT_BLOCK_ACK:
		return ns2_validate_block_ack(nsvc, msg, tp, cause);
	case NS_PDUT_STATUS:
		return ns2_validate_status(nsvc, msg, tp, cause);

	/* following PDUs doesn't have any payloads */
	case NS_PDUT_ALIVE:
	case NS_PDUT_ALIVE_ACK:
	case NS_PDUT_UNBLOCK:
	case NS_PDUT_UNBLOCK_ACK:
		if (msgb_l2len(msg) != sizeof(struct gprs_ns_hdr)) {
			*cause = NS_CAUSE_PROTO_ERR_UNSPEC;
			return -1;
		}
		break;
	}

	return 0;
}


static int ns_vc_tx(struct gprs_ns2_vc *nsvc, struct msgb *msg)
{
	unsigned int bytes = msgb_length(msg);
	int rc;


	rc = nsvc->bind->send_vc(nsvc, msg);
	if (rc < 0) {
		RATE_CTR_INC_NS(nsvc, NS_CTR_PKTS_OUT_DROP);
		RATE_CTR_ADD_NS(nsvc, NS_CTR_BYTES_OUT_DROP, bytes);
	} else {
		RATE_CTR_INC_NS(nsvc, NS_CTR_PKTS_OUT);
		RATE_CTR_ADD_NS(nsvc, NS_CTR_BYTES_OUT, bytes);
	}

	return rc;
}

/* transmit functions */
static int ns2_tx_simple(struct gprs_ns2_vc *nsvc, uint8_t pdu_type)
{
	struct msgb *msg = ns2_msgb_alloc();
	struct gprs_ns_hdr *nsh;

	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	if (!msg)
		return -ENOMEM;

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = pdu_type;

	LOG_NS_TX_SIGNAL(nsvc, nsh->pdu_type);
	return ns_vc_tx(nsvc, msg);
}

/*! Transmit a NS-BLOCK on a given NS-VC.
 *  \param[in] vc NS-VC on which the NS-BLOCK is to be transmitted
 *  \param[in] cause Numeric NS Cause value
 *  \param[in] nsvci if given this NSVCI will be encoded. If NULL the nsvc->nsvci will be used.
 *  \returns 0 in case of success */
int ns2_tx_block(struct gprs_ns2_vc *nsvc, uint8_t cause, uint16_t *nsvci)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t encoded_nsvci;

	if (nsvci)
		encoded_nsvci = osmo_htons(*nsvci);
	else
		encoded_nsvci = osmo_htons(nsvc->nsvci);

	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS BLOCK");

	msg = ns2_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	rate_ctr_inc(rate_ctr_group_get_ctr(nsvc->ctrg, NS_CTR_BLOCKED));

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_BLOCK;

	msgb_tvlv_put(msg, NS_IE_CAUSE, 1, &cause);
	msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *) &encoded_nsvci);

	LOG_NS_SIGNAL(nsvc, "Tx", nsh->pdu_type, LOGL_INFO, " cause=%s\n", gprs_ns2_cause_str(cause));
	return ns_vc_tx(nsvc, msg);
}

/*! Transmit a NS-BLOCK-ACK on a given NS-VC.
 *  \param[in] nsvc NS-VC on which the NS-BLOCK is to be transmitted
 *  \param[in] nsvci if given this NSVCI will be encoded. If NULL the nsvc->nsvci will be used.
 *  \returns 0 in case of success */
int ns2_tx_block_ack(struct gprs_ns2_vc *nsvc, uint16_t *nsvci)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t encoded_nsvci;

	if (nsvci)
		encoded_nsvci = osmo_htons(*nsvci);
	else
		encoded_nsvci = osmo_htons(nsvc->nsvci);

	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS BLOCK ACK");

	msg = ns2_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_BLOCK_ACK;

	msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *) &encoded_nsvci);

	LOG_NS_TX_SIGNAL(nsvc, nsh->pdu_type);
	return ns_vc_tx(nsvc, msg);
}

/*! Transmit a NS-RESET on a given NS-VC.
 *  \param[in] nsvc NS-VC used for transmission
 *  \paam[in] cause Numeric NS cause value
 *  \returns 0 in case of success */
int ns2_tx_reset(struct gprs_ns2_vc *nsvc, uint8_t cause)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsvci = osmo_htons(nsvc->nsvci);
	uint16_t nsei = osmo_htons(nsvc->nse->nsei);

	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS RESET");

	msg = ns2_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_RESET;

	msgb_tvlv_put(msg, NS_IE_CAUSE, 1, &cause);
	msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *) &nsvci);
	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *) &nsei);

	LOG_NS_SIGNAL(nsvc, "Tx", nsh->pdu_type, LOGL_INFO, " cause=%s\n", gprs_ns2_cause_str(cause));
	return ns_vc_tx(nsvc, msg);
}

/*! Transmit a NS-RESET-ACK on a given NS-VC.
 *  \param[in] nsvc NS-VC used for transmission
 *  \returns 0 in case of success */
int ns2_tx_reset_ack(struct gprs_ns2_vc *nsvc)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsvci, nsei;

	/* Section 9.2.6 */
	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS RESET ACK");

	msg = ns2_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	nsvci = osmo_htons(nsvc->nsvci);
	nsei = osmo_htons(nsvc->nse->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = NS_PDUT_RESET_ACK;

	msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *)&nsvci);
	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);

	LOG_NS_TX_SIGNAL(nsvc, nsh->pdu_type);
	return ns_vc_tx(nsvc, msg);
}

/*! Transmit a NS-UNBLOCK on a given NS-VC.
 *  \param[in] nsvc NS-VC on which the NS-UNBLOCK is to be transmitted
 *  \returns 0 in case of success */
int ns2_tx_unblock(struct gprs_ns2_vc *nsvc)
{
	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS UNBLOCK");

	return ns2_tx_simple(nsvc, NS_PDUT_UNBLOCK);
}


/*! Transmit a NS-UNBLOCK-ACK on a given NS-VC.
 *  \param[in] nsvc NS-VC on which the NS-UNBLOCK-ACK is to be transmitted
 *  \returns 0 in case of success */
int ns2_tx_unblock_ack(struct gprs_ns2_vc *nsvc)
{
	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS UNBLOCK ACK");

	return ns2_tx_simple(nsvc, NS_PDUT_UNBLOCK_ACK);
}

/*! Transmit a NS-ALIVE on a given NS-VC.
 *  \param[in] nsvc NS-VC on which the NS-ALIVE is to be transmitted
 *  \returns 0 in case of success */
int ns2_tx_alive(struct gprs_ns2_vc *nsvc)
{
	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	return ns2_tx_simple(nsvc, NS_PDUT_ALIVE);
}

/*! Transmit a NS-ALIVE-ACK on a given NS-VC.
 *  \param[in] nsvc NS-VC on which the NS-ALIVE-ACK is to be transmitted
 *  \returns 0 in case of success */
int ns2_tx_alive_ack(struct gprs_ns2_vc *nsvc)
{
	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	return ns2_tx_simple(nsvc, NS_PDUT_ALIVE_ACK);
}

/*! Transmit NS-UNITDATA on a given NS-VC.
 *  \param[in] nsvc NS-VC on which the NS-UNITDATA is to be transmitted
 *  \param[in] bvci BVCI to encode in NS-UNITDATA header
 *  \param[in] sducontrol SDU control octet of NS header
 *  \param[in] msg message buffer containing payload
 *  \returns 0 in case of success */
int ns2_tx_unit_data(struct gprs_ns2_vc *nsvc,
		     uint16_t bvci, uint8_t sducontrol,
		     struct msgb *msg)
{
	struct gprs_ns_hdr *nsh;

	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	msg->l2h = msgb_push(msg, sizeof(*nsh) + 3);
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	if (!nsh) {
		LOGNSVC(nsvc, LOGL_ERROR, "Not enough headroom for NS header\n");
		msgb_free(msg);
		return -EIO;
	}

	nsh->pdu_type = NS_PDUT_UNITDATA;
	nsh->data[0] = sducontrol;
	nsh->data[1] = bvci >> 8;
	nsh->data[2] = bvci & 0xff;

	LOG_NS_DATA(nsvc, "Tx", nsh->pdu_type, LOGL_INFO, "\n");
	return ns_vc_tx(nsvc, msg);
}

/*! Transmit a NS-STATUS on a given NS-VC.
 *  \param[in] nsvc NS-VC to be used for transmission
 *  \param[in] cause Numeric NS cause value
 *  \param[in] bvci BVCI to be reset within NSVC
 *  \param[in] orig_msg message causing the STATUS
 *  \param[in] nsvci if given this NSVCI will be encoded. If NULL the nsvc->nsvci will be used.
 *  \returns 0 in case of success */
int ns2_tx_status(struct gprs_ns2_vc *nsvc, uint8_t cause,
		  uint16_t bvci, struct msgb *orig_msg, uint16_t *nsvci)
{
	struct msgb *msg = ns2_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	uint16_t encoded_nsvci;
	unsigned int orig_len, max_orig_len;

	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	bvci = osmo_htons(bvci);

	if (!msg)
		return -ENOMEM;

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_STATUS;

	msgb_tvlv_put(msg, NS_IE_CAUSE, 1, &cause);

	switch (cause) {
	case NS_CAUSE_NSVC_BLOCKED:
	case NS_CAUSE_NSVC_UNKNOWN:
		/* Section 9.2.7.1: Static conditions for NS-VCI */
		if (nsvci)
			encoded_nsvci = osmo_htons(*nsvci);
		else
			encoded_nsvci = osmo_htons(nsvc->nsvci);
		msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *)&encoded_nsvci);
		break;
	case NS_CAUSE_SEM_INCORR_PDU:
	case NS_CAUSE_PDU_INCOMP_PSTATE:
	case NS_CAUSE_PROTO_ERR_UNSPEC:
	case NS_CAUSE_INVAL_ESSENT_IE:
	case NS_CAUSE_MISSING_ESSENT_IE:
		/* Section 9.2.7.2: Static conditions for NS PDU */
		/* ensure the PDU doesn't exceed the MTU */
		orig_len = msgb_l2len(orig_msg);
		max_orig_len = msgb_length(msg) + TVLV_GROSS_LEN(orig_len);
		if (max_orig_len > nsvc->bind->mtu)
			orig_len -= max_orig_len - nsvc->bind->mtu;
		msgb_tvlv_put(msg, NS_IE_PDU, orig_len, orig_msg->l2h);
		break;
	case NS_CAUSE_BVCI_UNKNOWN:
		/* Section 9.2.7.3: Static conditions for BVCI */
		msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *)&bvci);
		break;

	default:
		break;
	}

	LOG_NS_SIGNAL(nsvc, "Tx", nsh->pdu_type, LOGL_INFO, " cause=%s\n", gprs_ns2_cause_str(cause));
	return ns_vc_tx(nsvc, msg);
}

/*! Encode + Transmit a SNS-ADD/SNS-CHANGE-WEIGHT as per Section 9.3.2/9.3.3.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-CONFIG
 *  \param[in] pdu The PDU type to send out
 *  \param[in] trans_id The transaction id
 *  \param[in] ip4_elems Array of IPv4 Elements
 *  \param[in] num_ip4_elems number of ip4_elems
 *  \param[in] ip6_elems Array of IPv6 Elements
 *  \param[in] num_ip6_elems number of ip6_elems
 *  \returns 0 on success; negative in case of error */
static int ns2_tx_sns_procedure(struct gprs_ns2_vc *nsvc,
				enum ns_pdu_type pdu,
				uint8_t trans_id,
				const struct gprs_ns_ie_ip4_elem *ip4_elems,
				unsigned int num_ip4_elems,
				const struct gprs_ns_ie_ip6_elem *ip6_elems,
				unsigned int num_ip6_elems)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	if (!nsvc)
		return -EINVAL;

	if (!ip4_elems && !ip6_elems)
		return -EINVAL;

	msg = ns2_msgb_alloc();

	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nse->bss_sns_fi) {
		LOGNSVC(nsvc, LOGL_ERROR, "Cannot transmit SNS on NSVC without SNS active\n");
		msgb_free(msg);
		return -EIO;
	}

	nsei = osmo_htons(nsvc->nse->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = pdu;
	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);
	msgb_v_put(msg, trans_id);

	/* List of IP4 Elements 10.3.2c */
	if (ip4_elems) {
		msgb_tvlv_put(msg, NS_IE_IPv4_LIST, num_ip4_elems*sizeof(struct gprs_ns_ie_ip4_elem),
			      (const uint8_t *)ip4_elems);
	} else if (ip6_elems) {
		/* List of IP6 elements 10.3.2d */
		msgb_tvlv_put(msg, NS_IE_IPv6_LIST, num_ip6_elems*sizeof(struct gprs_ns_ie_ip6_elem),
			      (const uint8_t *)ip6_elems);
	}

	return ns_vc_tx(nsvc, msg);
}

/*! Encode + Transmit a SNS-ADD as per Section 9.3.2.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-CONFIG
 *  \param[in] trans_id The transaction id
 *  \param[in] ip4_elems Array of IPv4 Elements
 *  \param[in] num_ip4_elems number of ip4_elems
 *  \param[in] ip6_elems Array of IPv6 Elements
 *  \param[in] num_ip6_elems number of ip6_elems
 *  \returns 0 on success; negative in case of error */
int ns2_tx_sns_add(struct gprs_ns2_vc *nsvc,
		   uint8_t trans_id,
		   const struct gprs_ns_ie_ip4_elem *ip4_elems,
		   unsigned int num_ip4_elems,
		   const struct gprs_ns_ie_ip6_elem *ip6_elems,
		   unsigned int num_ip6_elems)
{
	return ns2_tx_sns_procedure(nsvc, SNS_PDUT_ADD, trans_id, ip4_elems, num_ip4_elems, ip6_elems, num_ip6_elems);
}

/*! Encode + Transmit a SNS-CHANGE-WEIGHT as per Section 9.3.3.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-CONFIG
 *  \param[in] trans_id The transaction id
 *  \param[in] ip4_elems Array of IPv4 Elements
 *  \param[in] num_ip4_elems number of ip4_elems
 *  \param[in] ip6_elems Array of IPv6 Elements
 *  \param[in] num_ip6_elems number of ip6_elems
 *  \returns 0 on success; negative in case of error */
int ns2_tx_sns_change_weight(struct gprs_ns2_vc *nsvc,
			     uint8_t trans_id,
			     const struct gprs_ns_ie_ip4_elem *ip4_elems,
			     unsigned int num_ip4_elems,
			     const struct gprs_ns_ie_ip6_elem *ip6_elems,
			     unsigned int num_ip6_elems)
{
	return ns2_tx_sns_procedure(nsvc, SNS_PDUT_CHANGE_WEIGHT, trans_id, ip4_elems, num_ip4_elems, ip6_elems, num_ip6_elems);
}

/*! Encode + Transmit a SNS-DEL as per Section 9.3.6.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-CONFIG
 *  \param[in] trans_id The transaction id
 *  \param[in] ip4_elems Array of IPv4 Elements
 *  \param[in] num_ip4_elems number of ip4_elems
 *  \param[in] ip6_elems Array of IPv6 Elements
 *  \param[in] num_ip6_elems number of ip6_elems
 *  \returns 0 on success; negative in case of error */
int ns2_tx_sns_del(struct gprs_ns2_vc *nsvc,
		   uint8_t trans_id,
		   const struct gprs_ns_ie_ip4_elem *ip4_elems,
		   unsigned int num_ip4_elems,
		   const struct gprs_ns_ie_ip6_elem *ip6_elems,
		   unsigned int num_ip6_elems)
{
	/* TODO: IP Address field */
	return ns2_tx_sns_procedure(nsvc, SNS_PDUT_DELETE, trans_id, ip4_elems, num_ip4_elems, ip6_elems, num_ip6_elems);
}


/*! Encode + Transmit a SNS-ACK as per Section 9.3.1.
 *  \param[in] nsvc NS-VC through which to transmit the ACK
 *  \param[in] trans_id Transaction ID which to acknowledge
 *  \param[in] cause Pointer to cause value (NULL if no cause to be sent)
 *  \param[in] ip4_elems Array of IPv4 Elements
 *  \param[in] num_ip4_elems number of ip4_elems
 *  \returns 0 on success; negative in case of error */
int ns2_tx_sns_ack(struct gprs_ns2_vc *nsvc, uint8_t trans_id, uint8_t *cause,
			const struct gprs_ns_ie_ip4_elem *ip4_elems,
			unsigned int num_ip4_elems,
			const struct gprs_ns_ie_ip6_elem *ip6_elems,
			unsigned int num_ip6_elems)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	if (!nsvc)
		return -1;

	msg = ns2_msgb_alloc();

	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nse->bss_sns_fi) {
		LOGNSVC(nsvc, LOGL_ERROR, "Cannot transmit SNS on NSVC without SNS active\n");
		msgb_free(msg);
		return -EIO;
	}


	nsei = osmo_htons(nsvc->nse->nsei);

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
	if (ip6_elems) {
		/* List of IP6 elements 10.3.2d */
		msgb_tvlv_put(msg, NS_IE_IPv6_LIST,
			      num_ip6_elems*sizeof(struct gprs_ns_ie_ip6_elem),
			      (const uint8_t *)ip6_elems);
	}

	LOG_NS_SIGNAL(nsvc, "Tx", nsh->pdu_type, LOGL_INFO,
		      " (trans_id=%u, cause=%s, num_ip4=%u, num_ip6=%u)\n",
		      trans_id, cause ? gprs_ns2_cause_str(*cause) : "NULL", num_ip4_elems, num_ip6_elems);
	return ns_vc_tx(nsvc, msg);
}

/*! Encode + Transmit a SNS-CONFIG as per Section 9.3.4.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-CONFIG
 *  \param[in] end_flag Whether or not this is the last SNS-CONFIG
 *  \param[in] ip4_elems Array of IPv4 Elements
 *  \param[in] num_ip4_elems number of ip4_elems
 *  \returns 0 on success; negative in case of error */
int ns2_tx_sns_config(struct gprs_ns2_vc *nsvc, bool end_flag,
			   const struct gprs_ns_ie_ip4_elem *ip4_elems,
			   unsigned int num_ip4_elems,
			   const struct gprs_ns_ie_ip6_elem *ip6_elems,
			   unsigned int num_ip6_elems)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	if (!nsvc)
		return -1;

	msg = ns2_msgb_alloc();

	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nse->bss_sns_fi) {
		LOGNSVC(nsvc, LOGL_ERROR, "Cannot transmit SNS on NSVC without SNS active\n");
		msgb_free(msg);
		return -EIO;
	}

	nsei = osmo_htons(nsvc->nse->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = SNS_PDUT_CONFIG;

	msgb_v_put(msg, end_flag ? 0x01 : 0x00);
	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);

	/* List of IP4 Elements 10.3.2c */
	if (ip4_elems) {
		msgb_tvlv_put(msg, NS_IE_IPv4_LIST, num_ip4_elems*sizeof(struct gprs_ns_ie_ip4_elem),
			      (const uint8_t *)ip4_elems);
	} else if (ip6_elems) {
		/* List of IP6 elements 10.3.2d */
		msgb_tvlv_put(msg, NS_IE_IPv6_LIST, num_ip6_elems*sizeof(struct gprs_ns_ie_ip6_elem),
			      (const uint8_t *)ip6_elems);
	}

	LOG_NS_SIGNAL(nsvc, "Tx", nsh->pdu_type, LOGL_INFO,
		      " (end_flag=%u, num_ip4=%u, num_ip6=%u)\n",
		      end_flag, num_ip4_elems, num_ip6_elems);
	return ns_vc_tx(nsvc, msg);
}

/*! Encode + Transmit a SNS-CONFIG-ACK as per Section 9.3.5.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-CONFIG-ACK
 *  \param[in] cause Pointer to cause value (NULL if no cause to be sent)
 *  \returns 0 on success; negative in case of error */
int ns2_tx_sns_config_ack(struct gprs_ns2_vc *nsvc, uint8_t *cause)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	if (!nsvc)
		return -1;

	msg = ns2_msgb_alloc();
	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nse->bss_sns_fi) {
		LOGNSVC(nsvc, LOGL_ERROR, "Cannot transmit SNS on NSVC without SNS active\n");
		msgb_free(msg);
		return -EIO;
	}

	nsei = osmo_htons(nsvc->nse->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = SNS_PDUT_CONFIG_ACK;

	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);
	if (cause)
		msgb_tvlv_put(msg, NS_IE_CAUSE, 1, cause);

	LOGNSVC(nsvc, LOGL_INFO, "Tx SNS-CONFIG-ACK (cause=%s)\n",
		cause ? gprs_ns2_cause_str(*cause) : "NULL");
	LOG_NS_TX_SIGNAL(nsvc, nsh->pdu_type);
	return ns_vc_tx(nsvc, msg);
}


/*! Encode + transmit a SNS-SIZE as per Section 9.3.7.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-SIZE
 *  \param[in] reset_flag Whether or not to add a RESET flag
 *  \param[in] max_nr_nsvc Maximum number of NS-VCs
 *  \param[in] ip4_ep_nr Number of IPv4 endpoints (< 0 will omit the TLV)
 *  \param[in] ip6_ep_nr Number of IPv6 endpoints (< 0 will omit the TLV)
 *  \returns 0 on success; negative in case of error */
int ns2_tx_sns_size(struct gprs_ns2_vc *nsvc, bool reset_flag, uint16_t max_nr_nsvc,
			 int ip4_ep_nr, int ip6_ep_nr)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	if (!nsvc)
		return -1;

	msg = ns2_msgb_alloc();

	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nse->bss_sns_fi) {
		LOGNSVC(nsvc, LOGL_ERROR, "Cannot transmit SNS on NSVC without SNS active\n");
		msgb_free(msg);
		return -EIO;
	}

	nsei = osmo_htons(nsvc->nse->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = SNS_PDUT_SIZE;

	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);
	msgb_tv_put(msg, NS_IE_RESET_FLAG, reset_flag ? 0x01 : 0x00);
	msgb_tv16_put(msg, NS_IE_MAX_NR_NSVC, max_nr_nsvc);
	if (ip4_ep_nr >= 0)
		msgb_tv16_put(msg, NS_IE_IPv4_EP_NR, ip4_ep_nr);
	if (ip6_ep_nr >= 0)
		msgb_tv16_put(msg, NS_IE_IPv6_EP_NR, ip6_ep_nr);

	LOG_NS_SIGNAL(nsvc, "Tx", nsh->pdu_type, LOGL_INFO,
		      " (reset=%u, max_nr_nsvc=%u, num_ip4=%d, num_ip6=%d)\n",
		      reset_flag, max_nr_nsvc, ip4_ep_nr, ip6_ep_nr);
	return ns_vc_tx(nsvc, msg);
}

/*! Encode + Transmit a SNS-SIZE-ACK as per Section 9.3.8.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-SIZE-ACK
 *  \param[in] cause Pointer to cause value (NULL if no cause to be sent)
 *  \returns 0 on success; negative in case of error */
int ns2_tx_sns_size_ack(struct gprs_ns2_vc *nsvc, uint8_t *cause)
{
	struct msgb *msg = ns2_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	log_set_context(LOG_CTX_GB_NSE, nsvc->nse);
	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nse->bss_sns_fi) {
		LOGNSVC(nsvc, LOGL_ERROR, "Cannot transmit SNS on NSVC without SNS active\n");
		msgb_free(msg);
		return -EIO;
	}

	nsei = osmo_htons(nsvc->nse->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = SNS_PDUT_SIZE_ACK;

	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);
	if (cause)
		msgb_tvlv_put(msg, NS_IE_CAUSE, 1, cause);

	LOG_NS_SIGNAL(nsvc, "Tx", nsh->pdu_type, LOGL_INFO, " cause=%s\n",
		      cause ? gprs_ns2_cause_str(*cause) : "NULL");
	return ns_vc_tx(nsvc, msg);
}
