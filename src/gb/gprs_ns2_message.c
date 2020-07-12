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
		LOGP(DLNS, LOGL_DEBUG, "NSEI=%u Rx invalid packet %s with SNS\n",	\
				       nsvc->nse->nsei, reason);			\
	} while (0)

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



int gprs_ns2_validate_reset(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp, uint8_t *cause)
{
	if (!TLVP_PRESENT(tp, NS_IE_CAUSE) || !TLVP_PRESENT(tp, NS_IE_VCI) || !TLVP_PRESENT(tp, NS_IE_NSEI)) {
		*cause = NS_CAUSE_MISSING_ESSENT_IE;
		return -1;
	}

	return 0;
}

int gprs_ns2_validate_reset_ack(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp, uint8_t *cause)
{
	if (!TLVP_PRESENT(tp, NS_IE_VCI) || !TLVP_PRESENT(tp, NS_IE_NSEI)) {
		*cause = NS_CAUSE_MISSING_ESSENT_IE;
		return -1;
	}

	return 0;
}

int gprs_ns2_validate_block(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp, uint8_t *cause)
{
	if (!TLVP_PRESENT(tp, NS_IE_VCI) || !TLVP_PRESENT(tp, NS_IE_CAUSE)) {
		*cause = NS_CAUSE_MISSING_ESSENT_IE;
		return -1;
	}

	return 0;
}

int gprs_ns2_validate_block_ack(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp, uint8_t *cause)
{
	if (!TLVP_PRESENT(tp, NS_IE_VCI)) {
		*cause = NS_CAUSE_MISSING_ESSENT_IE;
		return -1;
	}

	return 0;
}

int gprs_ns2_validate_status(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp, uint8_t *cause)
{

	if (!TLVP_PRESENT(tp, NS_IE_CAUSE)) {
		*cause = NS_CAUSE_MISSING_ESSENT_IE;
		return -1;
	}

	uint8_t _cause = tlvp_val8(tp, NS_IE_VCI, 0);

	switch (_cause) {
	case NS_CAUSE_NSVC_BLOCKED:
	case NS_CAUSE_NSVC_UNKNOWN:
		if (!TLVP_PRESENT(tp, NS_IE_CAUSE)) {
			*cause = NS_CAUSE_MISSING_ESSENT_IE;
			return -1;
		}
		break;
	case NS_CAUSE_SEM_INCORR_PDU:
	case NS_CAUSE_PDU_INCOMP_PSTATE:
	case NS_CAUSE_PROTO_ERR_UNSPEC:
	case NS_CAUSE_INVAL_ESSENT_IE:
	case NS_CAUSE_MISSING_ESSENT_IE:
		if (!TLVP_PRESENT(tp, NS_IE_CAUSE)) {
			*cause = NS_CAUSE_MISSING_ESSENT_IE;
			return -1;
		}
		break;
	case NS_CAUSE_BVCI_UNKNOWN:
		if (!TLVP_PRESENT(tp, NS_IE_BVCI)) {
			*cause = NS_CAUSE_MISSING_ESSENT_IE;
			return -1;
		}
		break;
	case NS_CAUSE_UNKN_IP_TEST_FAILED:
		if (!TLVP_PRESENT (tp, NS_IE_IPv4_LIST) && !TLVP_PRESENT(tp, NS_IE_IPv6_LIST)) {
			*cause = NS_CAUSE_MISSING_ESSENT_IE;
			return -1;
		}
		break;
	}

	return 0;
}

int gprs_ns2_validate(struct gprs_ns2_vc *nsvc,
		      uint8_t pdu_type,
		      struct msgb *msg,
		      struct tlv_parsed *tp,
		      uint8_t *cause)
{
	switch (pdu_type) {
	case NS_PDUT_RESET:
		return gprs_ns2_validate_reset(nsvc, msg, tp, cause);
	case NS_PDUT_RESET_ACK:
		return gprs_ns2_validate_reset_ack(nsvc, msg, tp, cause);
	case NS_PDUT_BLOCK:
		return gprs_ns2_validate_block(nsvc, msg, tp, cause);
	case NS_PDUT_BLOCK_ACK:
		return gprs_ns2_validate_block_ack(nsvc, msg, tp, cause);
	case NS_PDUT_STATUS:
		return gprs_ns2_validate_status(nsvc, msg, tp, cause);

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


/* transmit functions */
static int ns2_tx_simple(struct gprs_ns2_vc *nsvc, uint8_t pdu_type)
{
	struct msgb *msg = gprs_ns2_msgb_alloc();
	struct gprs_ns_hdr *nsh;

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	if (!msg)
		return -ENOMEM;

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = pdu_type;

	return nsvc->bind->send_vc(nsvc, msg);
}

/*! Transmit a NS-BLOCK on a given NS-VC
 *  \param[in] vc NS-VC on which the NS-BLOCK is to be transmitted
 *  \param[in] cause Numeric NS Cause value
 *  \returns 0 in case of success
 */
int ns2_tx_block(struct gprs_ns2_vc *nsvc, uint8_t cause)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsvci = osmo_htons(nsvc->nsvci);

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS BLOCK");

	msg = gprs_ns2_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	LOGP(DLNS, LOGL_INFO, "NSEI=%u Tx NS BLOCK (NSVCI=%u, cause=%s)\n",
		nsvc->nse->nsei, nsvc->nsvci, gprs_ns2_cause_str(cause));

	rate_ctr_inc(&nsvc->ctrg->ctr[NS_CTR_BLOCKED]);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_BLOCK;

	msgb_tvlv_put(msg, NS_IE_CAUSE, 1, &cause);
	msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *) &nsvci);

	return nsvc->bind->send_vc(nsvc, msg);
}

/*! Transmit a NS-BLOCK-ACK on a given NS-VC
 *  \param[in] nsvc NS-VC on which the NS-BLOCK is to be transmitted
 *  \returns 0 in case of success
 */
int ns2_tx_block_ack(struct gprs_ns2_vc *nsvc)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsvci = osmo_htons(nsvc->nsvci);

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS BLOCK ACK");

	msg = gprs_ns2_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	LOGP(DLNS, LOGL_INFO, "NSEI=%u Tx NS BLOCK ACK (NSVCI=%u)\n", nsvc->nse->nsei, nsvc->nsvci);

	/* be conservative and mark it as blocked even now! */
	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_BLOCK_ACK;

	msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *) &nsvci);

	return nsvc->bind->send_vc(nsvc, msg);
}

/*! Transmit a NS-RESET on a given NSVC
 *  \param[in] nsvc NS-VC used for transmission
 *  \paam[in] cause Numeric NS cause value
 */
int ns2_tx_reset(struct gprs_ns2_vc *nsvc, uint8_t cause)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsvci = osmo_htons(nsvc->nsvci);
	uint16_t nsei = osmo_htons(nsvc->nse->nsei);

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS RESET");

	msg = gprs_ns2_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	LOGP(DLNS, LOGL_INFO, "NSEI=%u Tx NS RESET (NSVCI=%u, cause=%s)\n",
		nsvc->nse->nsei, nsvc->nsvci, gprs_ns2_cause_str(cause));

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_RESET;

	msgb_tvlv_put(msg, NS_IE_CAUSE, 1, &cause);
	msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *) &nsvci);
	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *) &nsei);

	return nsvc->bind->send_vc(nsvc, msg);
}

/* Section 9.2.6 */
int ns2_tx_reset_ack(struct gprs_ns2_vc *nsvc)
{
	struct msgb *msg;
	struct gprs_ns_hdr *nsh;
	uint16_t nsvci, nsei;

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS RESET ACK");

	msg = gprs_ns2_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	nsvci = osmo_htons(nsvc->nsvci);
	nsei = osmo_htons(nsvc->nse->nsei);

	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;

	nsh->pdu_type = NS_PDUT_RESET_ACK;

	LOGP(DLNS, LOGL_INFO, "NSEI=%u Tx NS RESET ACK (NSVCI=%u)\n",
		nsvc->nse->nsei, nsvc->nsvci);

	msgb_tvlv_put(msg, NS_IE_VCI, 2, (uint8_t *)&nsvci);
	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (uint8_t *)&nsei);

	return nsvc->bind->send_vc(nsvc, msg);
}

/*! Transmit a NS-UNBLOCK on a given NS-VC
 *  \param[in] nsvc NS-VC on which the NS-UNBLOCK is to be transmitted
 *  \returns 0 in case of success
 */
int ns2_tx_unblock(struct gprs_ns2_vc *nsvc)
{
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS UNBLOCK");

	LOGP(DLNS, LOGL_INFO, "NSEI=%u Tx NS UNBLOCK (NSVCI=%u)\n",
		nsvc->nse->nsei, nsvc->nsvci);

	return ns2_tx_simple(nsvc, NS_PDUT_UNBLOCK);
}


/*! Transmit a NS-UNBLOCK-ACK on a given NS-VC
 *  \param[in] nsvc NS-VC on which the NS-UNBLOCK-ACK is to be transmitted
 *  \returns 0 in case of success
 */
int ns2_tx_unblock_ack(struct gprs_ns2_vc *nsvc)
{
	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	ERR_IF_NSVC_USES_SNS(nsvc, "transmit NS UNBLOCK ACK");

	LOGP(DLNS, LOGL_INFO, "NSEI=%u Tx NS UNBLOCK (NSVCI=%u)\n",
		nsvc->nse->nsei, nsvc->nsvci);

	return ns2_tx_simple(nsvc, NS_PDUT_UNBLOCK_ACK);
}

/*! Transmit a NS-ALIVE on a given NS-VC
 *  \param[in] nsvc NS-VC on which the NS-ALIVE is to be transmitted
 *  \returns 0 in case of success
 */
int ns2_tx_alive(struct gprs_ns2_vc *nsvc)
{
	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	LOGP(DLNS, LOGL_DEBUG, "NSEI=%u Tx NS ALIVE (NSVCI=%u)\n",
		nsvc->nse->nsei, nsvc->nsvci);

	return ns2_tx_simple(nsvc, NS_PDUT_ALIVE);
}

/*! Transmit a NS-ALIVE-ACK on a given NS-VC
 *  \param[in] nsvc NS-VC on which the NS-ALIVE-ACK is to be transmitted
 *  \returns 0 in case of success
 */
int ns2_tx_alive_ack(struct gprs_ns2_vc *nsvc)
{
	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	LOGP(DLNS, LOGL_DEBUG, "NSEI=%u Tx NS ALIVE_ACK (NSVCI=%u)\n",
		nsvc->nse->nsei, nsvc->nsvci);

	return ns2_tx_simple(nsvc, NS_PDUT_ALIVE_ACK);
}

int ns2_tx_unit_data(struct gprs_ns2_vc *nsvc,
		     uint16_t bvci, uint8_t sducontrol,
		     struct msgb *msg)
{
	struct gprs_ns_hdr *nsh;

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	msg->l2h = msgb_push(msg, sizeof(*nsh) + 3);
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	if (!nsh) {
		LOGP(DLNS, LOGL_ERROR, "Not enough headroom for NS header\n");
		msgb_free(msg);
		return -EIO;
	}

	nsh->pdu_type = NS_PDUT_UNITDATA;
	nsh->data[0] = sducontrol;
	nsh->data[1] = bvci >> 8;
	nsh->data[2] = bvci & 0xff;

	return nsvc->bind->send_vc(nsvc, msg);
}

/*! Transmit a NS-STATUS on a given NSVC
 *  \param[in] nsvc NS-VC to be used for transmission
 *  \param[in] cause Numeric NS cause value
 *  \param[in] bvci BVCI to be reset within NSVC
 *  \param[in] orig_msg message causing the STATUS */
int ns2_tx_status(struct gprs_ns2_vc *nsvc, uint8_t cause,
		       uint16_t bvci, struct msgb *orig_msg)
{
	struct msgb *msg = gprs_ns2_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	uint16_t nsvci = osmo_htons(nsvc->nsvci);

	log_set_context(LOG_CTX_GB_NSVC, nsvc);

	bvci = osmo_htons(bvci);

	if (!msg)
		return -ENOMEM;

	LOGP(DLNS, LOGL_NOTICE, "NSEI=%u Tx NS STATUS (NSVCI=%u, cause=%s)\n",
		nsvc->nse->nsei, nsvc->nsvci, gprs_ns2_cause_str(cause));

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

	return nsvc->bind->send_vc(nsvc, msg);
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
	struct msgb *msg = gprs_ns2_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	if (!nsvc)
		return -1;

	msg = gprs_ns2_msgb_alloc();

	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nse->bss_sns_fi) {
		LOGP(DLNS, LOGL_ERROR, "NSEI=%u Cannot transmit SNS on NSVC without SNS active\n",
		     nsvc->nse->nsei);
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

	return nsvc->bind->send_vc(nsvc, msg);
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

	msg = gprs_ns2_msgb_alloc();

	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nse->bss_sns_fi) {
		LOGP(DLNS, LOGL_ERROR, "NSEI=%u Cannot transmit SNS on NSVC without SNS active\n",
		     nsvc->nse->nsei);
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

	return nsvc->bind->send_vc(nsvc, msg);
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

	msg = gprs_ns2_msgb_alloc();
	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nse->bss_sns_fi) {
		LOGP(DLNS, LOGL_ERROR, "NSEI=%u Cannot transmit SNS on NSVC without SNS active\n",
		     nsvc->nse->nsei);
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

	return nsvc->bind->send_vc(nsvc, msg);
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
	struct msgb *msg = gprs_ns2_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	if (!nsvc)
		return -1;

	msg = gprs_ns2_msgb_alloc();

	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nse->bss_sns_fi) {
		LOGP(DLNS, LOGL_ERROR, "NSEI=%u Cannot transmit SNS on NSVC without SNS active\n",
		     nsvc->nse->nsei);
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

	return nsvc->bind->send_vc(nsvc, msg);
}

/*! Encode + Transmit a SNS-SIZE-ACK as per Section 9.3.8.
 *  \param[in] nsvc NS-VC through which to transmit the SNS-SIZE-ACK
 *  \param[in] cause Pointer to cause value (NULL if no cause to be sent)
 *  \returns 0 on success; negative in case of error */
int ns2_tx_sns_size_ack(struct gprs_ns2_vc *nsvc, uint8_t *cause)
{
	struct msgb *msg = gprs_ns2_msgb_alloc();
	struct gprs_ns_hdr *nsh;
	uint16_t nsei;

	log_set_context(LOG_CTX_GB_NSVC, nsvc);
	if (!msg)
		return -ENOMEM;

	if (!nsvc->nse->bss_sns_fi) {
		LOGP(DLNS, LOGL_ERROR, "NSEI=%u Cannot transmit SNS on NSVC without SNS active\n",
		     nsvc->nse->nsei);
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

	return nsvc->bind->send_vc(nsvc, msg);
}


