/* Implementation of 3GPP TS 48.016 NS IP Sub-Network Service */
/* (C) 2018 by Harald Welte <laforge@gnumonks.org> */

/* The BSS NSE only has one SGSN IP address configured, and it will use the SNS procedures
 * to communicated its local IPs/ports as well as all the SGSN side IPs/ports and
 * associated weights.  In theory, the BSS then uses this to establish a full mesh
 * of NSVCs between all BSS-side IPs/ports and SGSN-side IPs/ports */

#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/signal.h>
#include <osmocom/core/socket.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gprs/gprs_ns.h>

#include "common_vty.h"
#include "gb_internal.h"

#define S(x)	(1 << (x))

struct gprs_sns_state {
	struct gprs_ns_inst *nsi;
	struct gprs_nsvc *nsvc_hack;

	/* local configuration to send to the remote end */
	struct gprs_ns_ie_ip4_elem *ip4_local;
	size_t num_ip4_local;

	/* local configuration about our capabilities in terms of connections to
	 * remote (SGSN) side */
	size_t num_max_nsvcs;
	size_t num_max_ip4_remote;

	/* remote configuration as received */
	struct gprs_ns_ie_ip4_elem *ip4_remote;
	unsigned int num_ip4_remote;

	/* IP-SNS based Gb doesn't have a NSVCI.  However, our existing Gb stack
	 * requires a unique NSVCI per NS-VC.  Let's simply allocate them dynamically from
	 * the maximum (65533), counting downwards */
	uint16_t next_nsvci;
};

static inline struct gprs_ns_inst *ns_inst_from_fi(struct osmo_fsm_inst *fi)
{
	struct gprs_sns_state *gss = (struct gprs_sns_state *) fi->priv;
	return gss->nsi;
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

static struct gprs_nsvc *nsvc_by_ip4_elem(struct gprs_ns_inst *nsi,
					  const struct gprs_ns_ie_ip4_elem *ip4)
{
	struct sockaddr_in sin;
	/* copy over. Both data structures use network byte order */
	sin.sin_addr.s_addr = ip4->ip_addr;
	sin.sin_port = ip4->udp_port;
	return gprs_nsvc_by_rem_addr(nsi, &sin);
}

static struct gprs_nsvc *gprs_nsvc_create_ip4(struct gprs_ns_inst *nsi,
					      const struct gprs_ns_ie_ip4_elem *ip4)
{
	struct gprs_sns_state *gss = (struct gprs_sns_state *) nsi->bss_sns_fi->priv;
	struct gprs_nsvc *nsvc;
	struct sockaddr_in sin;
	/* copy over. Both data structures use network byte order */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip4->ip_addr;
	sin.sin_port = ip4->udp_port;

	nsvc = gprs_nsvc_create2(nsi, gss->next_nsvci--, ip4->sig_weight, ip4->data_weight);
	if (!nsvc)
		return NULL;

	/* NSEI is the same across all NS-VCs */
	nsvc->nsei = gss->nsvc_hack->nsei;
	nsvc->nsvci_is_valid = 0;
	nsvc->ip.bts_addr = sin;

	return nsvc;
}

static int create_missing_nsvcs(struct osmo_fsm_inst *fi)
{
	struct gprs_sns_state *gss = (struct gprs_sns_state *) fi->priv;
	struct gprs_ns_inst *nsi = ns_inst_from_fi(fi);
	unsigned int i;

	for (i = 0; i < gss->num_ip4_remote; i++) {
		const struct gprs_ns_ie_ip4_elem *ip4 = &gss->ip4_remote[i];
		struct gprs_nsvc *nsvc = nsvc_by_ip4_elem(nsi, ip4);
		if (!nsvc) {
			/* create, if it doesn't exist */
			nsvc = gprs_nsvc_create_ip4(nsi, ip4);
			if (!nsvc) {
				LOGPFSML(fi, LOGL_ERROR, "SNS-CONFIG: Failed to create NSVC\n");
				continue;
			}
		} else {
			/* update data / signalling weight */
			nsvc->data_weight = ip4->data_weight;
			nsvc->sig_weight = ip4->sig_weight;
		}
		LOGPFSML(fi, LOGL_INFO, "NS-VC %s data_weight=%u, sig_weight=%u\n",
			 gprs_ns_ll_str(nsvc), nsvc->data_weight, nsvc->sig_weight);
	}

	return 0;
}

/* Add a given remote IPv4 element to gprs_sns_state */
static int add_remote_ip4_elem(struct gprs_sns_state *gss, const struct gprs_ns_ie_ip4_elem *ip4)
{
	if (gss->num_ip4_remote >= gss->num_max_ip4_remote)
		return -E2BIG;

	gss->ip4_remote = talloc_realloc(gss, gss->ip4_remote, struct gprs_ns_ie_ip4_elem,
					 gss->num_ip4_remote+1);
	gss->ip4_remote[gss->num_ip4_remote] = *ip4;
	gss->num_ip4_remote += 1;
	return 0;
}

/* Remove a given remote IPv4 element from gprs_sns_state */
static int remove_remote_ip4_elem(struct gprs_sns_state *gss, const struct gprs_ns_ie_ip4_elem *ip4)
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
static int update_remote_ip4_elem(struct gprs_sns_state *gss, const struct gprs_ns_ie_ip4_elem *ip4)
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


static int do_sns_change_weight(struct osmo_fsm_inst *fi, const struct gprs_ns_ie_ip4_elem *ip4)
{
	struct gprs_sns_state *gss = (struct gprs_sns_state *) fi->priv;
	struct gprs_ns_inst *nsi = ns_inst_from_fi(fi);
	struct gprs_nsvc *nsvc = nsvc_by_ip4_elem(nsi, ip4);

	/* TODO: Upon receiving an SNS-CHANGEWEIGHT PDU, if the resulting sum of the
	 * signalling weights of all the peer IP endpoints configured for this NSE is
	 * equal to zero or if the resulting sum of the data weights of all the peer IP
	 * endpoints configured for this NSE is equal to zero, the BSS/SGSN shall send an
	 * SNS-ACK PDU with a cause code of "Invalid weights". */

	update_remote_ip4_elem(gss, ip4);

	if (!nsvc) {
		LOGPFSML(fi, LOGL_NOTICE, "Couldn't find NS-VC for SNS-CHANGE_WEIGHT\n");
		return -NS_CAUSE_NSVC_UNKNOWN;
	}

	LOGPFSML(fi, LOGL_INFO, "CHANGE-WEIGHT NS-VC %s data_weight %u->%u, sig_weight %u->%u\n",
		 gprs_ns_ll_str(nsvc), nsvc->data_weight, ip4->data_weight,
		 nsvc->sig_weight, ip4->sig_weight);

	nsvc->data_weight = ip4->data_weight;
	nsvc->sig_weight = ip4->sig_weight;

	return 0;
}

static int do_sns_delete(struct osmo_fsm_inst *fi, const struct gprs_ns_ie_ip4_elem *ip4)
{
	struct gprs_sns_state *gss = (struct gprs_sns_state *) fi->priv;
	struct gprs_ns_inst *nsi = ns_inst_from_fi(fi);
	struct gprs_nsvc *nsvc = nsvc_by_ip4_elem(nsi, ip4);

	if (remove_remote_ip4_elem(gss, ip4) < 0)
		return -NS_CAUSE_UNKN_IP_EP;

	if (!nsvc) {
		LOGPFSML(fi, LOGL_NOTICE, "Couldn't find NS-VC for SNS-DELETE\n");
		return -NS_CAUSE_NSVC_UNKNOWN;
	}
	LOGPFSML(fi, LOGL_INFO, "DELETE NS-VC %s\n", gprs_ns_ll_str(nsvc));
	gprs_nsvc_delete(nsvc);

	return 0;
}

static int do_sns_add(struct osmo_fsm_inst *fi, const struct gprs_ns_ie_ip4_elem *ip4)
{
	struct gprs_sns_state *gss = (struct gprs_sns_state *) fi->priv;
	struct gprs_ns_inst *nsi = ns_inst_from_fi(fi);
	struct gprs_nsvc *nsvc;

	/* Upon receiving an SNS-ADD PDU, if the consequent number of IPv4 endpoints
	 * exceeds the number of IPv4 endpoints supported by the NSE, the NSE shall send
	 * an SNS-ACK PDU with a cause code set to "Invalid number of IP4 Endpoints". */
	if (add_remote_ip4_elem(gss, ip4) < 0)
		return -NS_CAUSE_INVAL_NR_NS_VC;

	/* Upon receiving an SNS-ADD PDU containing an already configured IP endpoint the
	 * NSE shall send an SNS-ACK PDU with the cause code "Protocol error -
	 * unspecified" */
	nsvc = nsvc_by_ip4_elem(nsi, ip4);
	if (nsvc)
		return -NS_CAUSE_PROTO_ERR_UNSPEC;

	nsvc = gprs_nsvc_create_ip4(nsi, ip4);
	if (!nsvc) {
		LOGPFSML(fi, LOGL_ERROR, "SNS-ADD: Failed to create NSVC\n");
		remove_remote_ip4_elem(gss, ip4);
		return -NS_CAUSE_EQUIP_FAIL;
	}
	LOGPFSML(fi, LOGL_INFO, "ADD NS-VC %s data_weight=%u, sig_weight=%u\n",
		 gprs_ns_ll_str(nsvc), nsvc->data_weight, nsvc->sig_weight);
	/* Start the test procedure for this new NS-VC */
	gprs_nsvc_start_test(nsvc);
	return 0;
}



/***********************************************************************
 * BSS-side FSM for IP Sub-Network Service
 ***********************************************************************/

enum gprs_sns_bss_state {
	GPRS_SNS_ST_UNCONFIGURED,
	GPRS_SNS_ST_SIZE,		/*!< SNS-SIZE procedure ongoing */
	GPRS_SNS_ST_CONFIG_BSS,		/*!< SNS-CONFIG procedure (BSS->SGSN) ongoing */
	GPRS_SNS_ST_CONFIG_SGSN,	/*!< SNS-CONFIG procedure (SGSN->BSS) ongoing */
	GPRS_SNS_ST_CONFIGURED,
};

enum gprs_sns_event {
	GPRS_SNS_EV_START,
	GPRS_SNS_EV_SIZE,
	GPRS_SNS_EV_SIZE_ACK,
	GPRS_SNS_EV_CONFIG,
	GPRS_SNS_EV_CONFIG_END,		/*!< SNS-CONFIG with end flag received */
	GPRS_SNS_EV_CONFIG_ACK,
	GPRS_SNS_EV_ADD,
	GPRS_SNS_EV_DELETE,
	GPRS_SNS_EV_CHANGE_WEIGHT,
};

static const struct value_string gprs_sns_event_names[] = {
	{ GPRS_SNS_EV_START, 		"START" },
	{ GPRS_SNS_EV_SIZE,		"SIZE" },
	{ GPRS_SNS_EV_SIZE_ACK,		"SIZE_ACK" },
	{ GPRS_SNS_EV_CONFIG,		"CONFIG" },
	{ GPRS_SNS_EV_CONFIG_END,	"CONFIG_END" },
	{ GPRS_SNS_EV_CONFIG_ACK,	"CONFIG_ACK" },
	{ GPRS_SNS_EV_ADD,		"ADD" },
	{ GPRS_SNS_EV_DELETE,		"DELETE" },
	{ GPRS_SNS_EV_CHANGE_WEIGHT,	"CHANGE_WEIGHT" },
	{ 0, NULL }
};

static void gprs_sns_st_unconfigured(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_ns_inst *nsi = ns_inst_from_fi(fi);
	switch (event) {
	case GPRS_SNS_EV_START:
		osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_SIZE, nsi->timeout[NS_TOUT_TSNS_PROV], 1);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void gprs_sns_st_size(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_ns_inst *nsi = ns_inst_from_fi(fi);
	struct tlv_parsed *tp = NULL;

	switch (event) {
	case GPRS_SNS_EV_SIZE_ACK:
		tp = data;
		if (TLVP_VAL_MINLEN(tp, NS_IE_CAUSE, 1)) {
			LOGPFSML(fi, LOGL_ERROR, "SNS-SIZE-ACK with cause %s\n",
				 gprs_ns_cause_str(*TLVP_VAL(tp, NS_IE_CAUSE)));
			/* FIXME: What to do? */
		} else {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_CONFIG_BSS,
						nsi->timeout[NS_TOUT_TSNS_PROV], 2);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}
static void gprs_sns_st_size_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct gprs_sns_state *gss = (struct gprs_sns_state *) fi->priv;
	uint16_t num_max_ip4_remote = gss->num_max_ip4_remote;

	gprs_ns_tx_sns_size(gss->nsvc_hack, true, gss->num_max_nsvcs, &num_max_ip4_remote, NULL);
}


static void gprs_sns_st_config_bss(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct gprs_sns_state *gss = (struct gprs_sns_state *) fi->priv;
	//struct gprs_ns_inst *nsi = ns_inst_from_fi(fi);
	struct tlv_parsed *tp = NULL;

	switch (event) {
	case GPRS_SNS_EV_CONFIG_ACK:
		tp = data;
		if (TLVP_VAL_MINLEN(tp, NS_IE_CAUSE, 1)) {
			LOGPFSML(fi, LOGL_ERROR, "SNS-CONFIG-ACK with cause %s\n",
				 gprs_ns_cause_str(*TLVP_VAL(tp, NS_IE_CAUSE)));
			/* FIXME: What to do? */
		} else {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_CONFIG_SGSN, 0, 0);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}
static void gprs_sns_st_config_bss_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct gprs_sns_state *gss = (struct gprs_sns_state *) fi->priv;
	/* Transmit SNS-CONFIG */
	gprs_ns_tx_sns_config(gss->nsvc_hack, true, gss->ip4_local, gss->num_ip4_local);
}

static void gprs_sns_st_config_sgsn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_sns_state *gss = (struct gprs_sns_state *) fi->priv;
	struct tlv_parsed *tp = NULL;
	struct gprs_ns_inst *nsi = ns_inst_from_fi(fi);
	const struct gprs_ns_ie_ip4_elem *v4_list;
	unsigned int num_v4;
	uint8_t cause;

	switch (event) {
	case GPRS_SNS_EV_CONFIG_END:
	case GPRS_SNS_EV_CONFIG:
		tp = data;
#if 0		/* part of incoming SNS-SIZE (doesn't happen on BSS side */
		if (TLVP_PRESENT(tp, NS_IE_RESET_FLAG)) {
			/* reset all existing config */
			if (gss->ip4_remote)
				talloc_free(gss->ip4_remote);
			gss->num_ip4_remote = 0;
		}
#endif
		if (!TLVP_PRESENT(tp, NS_IE_IPv4_LIST)) {
			cause = NS_CAUSE_INVAL_NR_IPv4_EP;
			gprs_ns_tx_sns_config_ack(gss->nsvc_hack, &cause);
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 0);
			break;
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
				gprs_ns_tx_sns_config_ack(gss->nsvc_hack, &cause);
				osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_UNCONFIGURED, 0, 0);
				break;
			}
			create_missing_nsvcs(fi);
			gprs_ns_tx_sns_config_ack(gss->nsvc_hack, NULL);
			/* start the test procedure on ALL NSVCs! */
			gprs_start_alive_all_nsvcs(nsi);
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_CONFIGURED, 0, 0);
		} else {
			/* just send CONFIG-ACK */
			gprs_ns_tx_sns_config_ack(gss->nsvc_hack, NULL);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void gprs_sns_st_configured(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_sns_state *gss = (struct gprs_sns_state *) fi->priv;
	struct tlv_parsed *tp = NULL;
	const struct gprs_ns_ie_ip4_elem *v4_list = NULL;
	unsigned int num_v4 = 0;
	uint8_t trans_id;
	uint8_t cause = 0xff;
	unsigned int i;
	int rc;

	switch (event) {
	case GPRS_SNS_EV_ADD:
		tp = data;
		trans_id = *TLVP_VAL(tp, NS_IE_TRANS_ID);
		if (TLVP_PRESENT(tp, NS_IE_IPv4_LIST)) {
			v4_list = (const struct gprs_ns_ie_ip4_elem *) TLVP_VAL(tp, NS_IE_IPv4_LIST);
			num_v4 = TLVP_LEN(tp, NS_IE_IPv4_LIST) / sizeof(*v4_list);
			for (i = 0; i < num_v4; i++) {
				rc = do_sns_add(fi, &v4_list[i]);
				if (rc < 0) {
					unsigned int j;
					/* rollback/undo to restore previous state */
					for (j = 0; j < i; j++)
						do_sns_delete(fi, &v4_list[j]);
					cause = -rc;
					gprs_ns_tx_sns_ack(gss->nsvc_hack, trans_id, &cause, NULL, 0);
					break;
				}
			}
		} else {
			cause = NS_CAUSE_INVAL_NR_IPv4_EP;
			gprs_ns_tx_sns_ack(gss->nsvc_hack, trans_id, &cause, NULL, 0);
			break;
		}
		gprs_ns_tx_sns_ack(gss->nsvc_hack, trans_id, NULL, v4_list, num_v4);
		break;
	case GPRS_SNS_EV_DELETE:
		tp = data;
		trans_id = *TLVP_VAL(tp, NS_IE_TRANS_ID);
		if (TLVP_PRESENT(tp, NS_IE_IPv4_LIST)) {
			v4_list = (const struct gprs_ns_ie_ip4_elem *) TLVP_VAL(tp, NS_IE_IPv4_LIST);
			num_v4 = TLVP_LEN(tp, NS_IE_IPv4_LIST) / sizeof(*v4_list);
			for (i = 0; i < num_v4; i++) {
				rc = do_sns_delete(fi, &v4_list[i]);
				if (rc < 0) {
					cause = -rc;
					/* continue to delete others */
				}
			}
			if (cause != 0xff) {
				/* TODO: create list of not-deleted and return it */
				gprs_ns_tx_sns_ack(gss->nsvc_hack, trans_id, &cause, NULL, 0);
				break;
			}
		} else if (TLVP_PRES_LEN(tp, NS_IE_IP_ADDR, 5)) {
			/* delete all NS-VCs for given IP address */
			const uint8_t *ie = TLVP_VAL(tp, NS_IE_IP_ADDR);
			struct gprs_ns_ie_ip4_elem *ip4_remote;
			uint32_t ip_addr = *(uint32_t *)(ie+1);
			if (ie[0] != 0x01) { /* Address Type != IPv4 */
				cause = NS_CAUSE_UNKN_IP_ADDR;
				gprs_ns_tx_sns_ack(gss->nsvc_hack, trans_id, &cause, NULL, 0);
				break;
			}
			/* make a copy as do_sns_delete() will change the array underneath us */
			ip4_remote = talloc_memdup(fi, gss->ip4_remote,
						   gss->num_ip4_remote*sizeof(*v4_list));
			for (i = 0; i < gss->num_ip4_remote; i++) {
				if (ip4_remote[i].ip_addr == ip_addr) {
					rc = do_sns_delete(fi, &ip4_remote[i]);
					if (rc < 0) {
						cause = -rc;
						/* continue to delete others */
					}
				}
			}
			talloc_free(ip4_remote);
			if (cause != 0xff) {
				/* TODO: create list of not-deleted and return it */
				gprs_ns_tx_sns_ack(gss->nsvc_hack, trans_id, &cause, NULL, 0);
				break;
			}
		} else {
			cause = NS_CAUSE_INVAL_NR_IPv4_EP;
			gprs_ns_tx_sns_ack(gss->nsvc_hack, trans_id, &cause, NULL, 0);
			break;
		}
		gprs_ns_tx_sns_ack(gss->nsvc_hack, trans_id, NULL, v4_list, num_v4);
		break;
	case GPRS_SNS_EV_CHANGE_WEIGHT:
		tp = data;
		trans_id = *TLVP_VAL(tp, NS_IE_TRANS_ID);
		if (TLVP_PRESENT(tp, NS_IE_IPv4_LIST)) {
			v4_list = (const struct gprs_ns_ie_ip4_elem *) TLVP_VAL(tp, NS_IE_IPv4_LIST);
			num_v4 = TLVP_LEN(tp, NS_IE_IPv4_LIST) / sizeof(*v4_list);
			for (i = 0; i < num_v4; i++) {
				rc = do_sns_change_weight(fi, &v4_list[i]);
				if (rc < 0) {
					cause = -rc;
					/* continue to others */
				}
			}
			if (cause != 0xff) {
				gprs_ns_tx_sns_ack(gss->nsvc_hack, trans_id, &cause, NULL, 0);
				break;
			}
		} else {
			cause = NS_CAUSE_INVAL_NR_IPv4_EP;
			gprs_ns_tx_sns_ack(gss->nsvc_hack, trans_id, &cause, NULL, 0);
			break;
		}
		gprs_ns_tx_sns_ack(gss->nsvc_hack, trans_id, NULL, v4_list, num_v4);
		break;
	}
}

static void gprs_sns_st_configured_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct ns_signal_data nssd = {0};
	osmo_signal_dispatch(SS_L_NS, S_SNS_CONFIGURED, &nssd);
}

static const struct osmo_fsm_state gprs_sns_bss_states[] = {
	[GPRS_SNS_ST_UNCONFIGURED] = {
		.in_event_mask = S(GPRS_SNS_EV_START),
		.out_state_mask = S(GPRS_SNS_ST_SIZE),
		.name = "UNCONFIGURED",
		.action = gprs_sns_st_unconfigured,
	},
	[GPRS_SNS_ST_SIZE] = {
		.in_event_mask = S(GPRS_SNS_EV_SIZE_ACK),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_SIZE) |
				  S(GPRS_SNS_ST_CONFIG_BSS),
		.name = "SIZE",
		.action = gprs_sns_st_size,
		.onenter = gprs_sns_st_size_onenter,
	},
	[GPRS_SNS_ST_CONFIG_BSS] = {
		.in_event_mask = S(GPRS_SNS_EV_CONFIG_ACK),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_CONFIG_BSS) |
				  S(GPRS_SNS_ST_CONFIG_SGSN),
		.name = "CONFIG_BSS",
		.action = gprs_sns_st_config_bss,
		.onenter = gprs_sns_st_config_bss_onenter,
	},
	[GPRS_SNS_ST_CONFIG_SGSN] = {
		.in_event_mask = S(GPRS_SNS_EV_CONFIG) |
				 S(GPRS_SNS_EV_CONFIG_END),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED) |
				  S(GPRS_SNS_ST_CONFIG_SGSN) |
				  S(GPRS_SNS_ST_CONFIGURED),
		.name = "CONFIG_SGSN",
		.action = gprs_sns_st_config_sgsn,
	},
	[GPRS_SNS_ST_CONFIGURED] = {
		.in_event_mask = S(GPRS_SNS_EV_ADD) |
				 S(GPRS_SNS_EV_DELETE) |
				 S(GPRS_SNS_EV_CHANGE_WEIGHT),
		.out_state_mask = S(GPRS_SNS_ST_UNCONFIGURED),
		.name = "CONFIGURED",
		.action = gprs_sns_st_configured,
		.onenter = gprs_sns_st_configured_onenter,
	},
};

static int gprs_sns_fsm_bss_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gprs_ns_inst *nsi = ns_inst_from_fi(fi);

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

static struct osmo_fsm gprs_sns_bss_fsm = {
	.name = "GPRS-SNS-BSS",
	.states = gprs_sns_bss_states,
	.num_states = ARRAY_SIZE(gprs_sns_bss_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.cleanup = NULL,
	.timer_cb = gprs_sns_fsm_bss_timer_cb,
	/* .log_subsys = DNS, "is not constant" */
	.event_names = gprs_sns_event_names,
	.pre_term = NULL,
};

struct osmo_fsm_inst *gprs_sns_bss_fsm_alloc(void *ctx, struct gprs_nsvc *nsvc,
					     const char *id)
{
	struct osmo_fsm_inst *fi;
	struct gprs_sns_state *gss;
	struct gprs_ns_ie_ip4_elem *ip4;
	struct gprs_ns_inst *nsi = nsvc->nsi;

	fi = osmo_fsm_inst_alloc(&gprs_sns_bss_fsm, ctx, NULL, LOGL_DEBUG, id);
	if (!fi)
		return fi;

	gss = talloc_zero(fi, struct gprs_sns_state);
	if (!gss)
		goto err;

	fi->priv = gss;
	gss->nsi = nsi;
	/* FIXME: we shouldn't use 'nsvc' here but only gprs_ns_inst */
	gss->nsvc_hack = nsvc;
	gss->next_nsvci = 65533; /* 65534 + 65535 are already used internally */

	/* create IPv4 list from the one IP/port the NS instance has */
	ip4 = talloc_zero(gss, struct gprs_ns_ie_ip4_elem);
	if (!ip4)
		goto err;
	if (nsi->nsip.local_ip)
		ip4->ip_addr = htonl(nsi->nsip.local_ip);
	else {
		/* unspecified local address. Figure out which address the kernel would use if we
		 * wanted to send a packet to the remote_ip */
		char local_ip[32];
		struct sockaddr_in *daddr = &nsvc->ip.bts_addr;
		osmo_sock_local_ip(local_ip, inet_ntoa(daddr->sin_addr));
		ip4->ip_addr = inet_addr(local_ip);
	}
	ip4->udp_port = htons(gss->nsi->nsip.local_port);
	ip4->sig_weight = 2;
	ip4->data_weight = 1;
	gss->ip4_local = ip4;
	gss->num_ip4_local = 1;
	gss->num_max_nsvcs = 8;
	gss->num_max_ip4_remote = 4;

	return fi;
err:
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
	return NULL;
}

int gprs_sns_bss_fsm_start(struct gprs_ns_inst *nsi)
{
	return osmo_fsm_inst_dispatch(nsi->bss_sns_fi, GPRS_SNS_EV_START, NULL);
}

/* main entry point for receiving SNS messages from the network */
int gprs_ns_rx_sns(struct gprs_ns_inst *nsi, struct msgb *msg, struct tlv_parsed *tp)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	uint16_t nsei = msgb_nsei(msg);
	struct osmo_fsm_inst *fi;

	LOGP(DNS, LOGL_DEBUG, "NSEI=%u Rx SNS PDU type %s\n", nsei,
		get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));

	/* FIXME: how to resolve SNS FSM Instance by NSEI (SGSN)? */
	fi = nsi->bss_sns_fi;

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
		LOGP(DNS, LOGL_NOTICE, "NSEI=%u Rx unsupported SNS PDU type %s\n", nsei,
			get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));
		break;
	default:
		LOGP(DNS, LOGL_ERROR, "NSEI=%u Rx unknown SNS PDU type %s\n", nsei,
			get_value_string(gprs_ns_pdu_strings, nsh->pdu_type));
		return -EINVAL;
	}

	return 0;
}

int gprs_sns_init(void)
{
	/* "DNS" is not a constant/#define, but an integer variable set by the client app */
	gprs_sns_bss_fsm.log_subsys = DNS;
	return osmo_fsm_register(&gprs_sns_bss_fsm);
}

#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>

static void vty_dump_sns_ip4(struct vty *vty, const struct gprs_ns_ie_ip4_elem *ip4)
{
	struct in_addr in = { .s_addr = ip4->ip_addr };
	vty_out(vty, " %s:%u, Signalling Weight: %u, Data Weight: %u%s",
		inet_ntoa(in), ntohs(ip4->udp_port), ip4->sig_weight, ip4->data_weight, VTY_NEWLINE);
}

void gprs_sns_dump_vty(struct vty *vty, const struct gprs_ns_inst *nsi, bool stats)
{
	struct gprs_sns_state *gss;
	unsigned int i;

	if (!nsi->bss_sns_fi)
		return;

	vty_out_fsm_inst(vty, nsi->bss_sns_fi);
	gss = (struct gprs_sns_state *) nsi->bss_sns_fi->priv;

	vty_out(vty, "Maximum number of remote  NS-VCs: %zu, IPv4 Endpoints: %zu%s",
		gss->num_max_nsvcs, gss->num_max_ip4_remote, VTY_NEWLINE);

	vty_out(vty, "Local IPv4 Endpoints:%s", VTY_NEWLINE);
	for (i = 0; i < gss->num_ip4_local; i++)
		vty_dump_sns_ip4(vty, &gss->ip4_local[i]);

	vty_out(vty, "Remote IPv4 Endpoints:%s", VTY_NEWLINE);
	for (i = 0; i < gss->num_ip4_remote; i++)
		vty_dump_sns_ip4(vty, &gss->ip4_remote[i]);
}
