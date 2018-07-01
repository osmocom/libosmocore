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

	/* remote configuration as received */
	struct gprs_ns_ie_ip4_elem *ip4_remote;
	unsigned int num_ip4_remote;
};

static inline struct gprs_ns_inst *ns_inst_from_fi(struct osmo_fsm_inst *fi)
{
	struct gprs_sns_state *gss = (struct gprs_sns_state *) fi->priv;
	return gss->nsi;
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
};

static const struct value_string gprs_sns_event_names[] = {
	{ GPRS_SNS_EV_START, 		"START" },
	{ GPRS_SNS_EV_SIZE,		"SIZE" },
	{ GPRS_SNS_EV_SIZE_ACK,		"SIZE_ACK" },
	{ GPRS_SNS_EV_CONFIG,		"CONFIG" },
	{ GPRS_SNS_EV_CONFIG_END,	"CONFIG_END" },
	{ GPRS_SNS_EV_CONFIG_ACK,	"CONFIG_ACK" },
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
	uint16_t num = gss->num_ip4_local;

	gprs_ns_tx_sns_size(gss->nsvc_hack, true, num, &num, NULL);
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
		if (TLVP_PRESENT(tp, NS_IE_IPv4_LIST)) {
			const struct gprs_ns_ie_ip4_elem *v4_list;
			unsigned int num_v4;
			v4_list = (const struct gprs_ns_ie_ip4_elem *) TLVP_VAL(tp, NS_IE_IPv4_LIST);
			num_v4 = TLVP_LEN(tp, NS_IE_IPv4_LIST) / sizeof(*v4_list);
			/* realloc to the new size */
			gss->ip4_remote = talloc_realloc(gss, gss->ip4_remote,
							 struct gprs_ns_ie_ip4_elem,
							 gss->num_ip4_remote+num_v4);
			/* append the new entries to the end of the list */
			memcpy(&gss->ip4_remote[gss->num_ip4_remote], v4_list, num_v4);
			gss->num_ip4_remote += num_v4;
		} else {
			uint8_t cause = NS_CAUSE_INVAL_NR_IPv4_EP;
			gprs_ns_tx_sns_config_ack(gss->nsvc_hack, &cause);
			/* state change? */
		}
		LOGPFSML(fi, LOGL_INFO, "Rx SNS-CONFIG: Remote IPv4 list now %u entries\n",
			 gss->num_ip4_remote);
		if (event == GPRS_SNS_EV_CONFIG_END) {
			osmo_fsm_inst_state_chg(fi, GPRS_SNS_ST_CONFIGURED, 0, 0);
		}
		/* send CONFIG-ACK */
		gprs_ns_tx_sns_config_ack(gss->nsvc_hack, NULL);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void gprs_sns_st_configured(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* FIXME: ADD/DELETE procedures */
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
		//.in_event_mask = S(),
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

struct osmo_fsm_inst *gprs_sns_bss_fsm_start(void *ctx, struct gprs_nsvc *nsvc,
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
		struct in_addr in = { .s_addr = htonl(nsi->nsip.remote_ip) };
		osmo_sock_local_ip(local_ip, inet_ntoa(in));
		ip4->ip_addr = inet_addr(local_ip);
	}
	ip4->udp_port = htons(gss->nsi->nsip.local_port);
	ip4->sig_weight = 2;
	ip4->data_weight = 1;
	gss->ip4_local = ip4;
	gss->num_ip4_local = 1;

	/* start the FSM */
	osmo_fsm_inst_dispatch(fi, GPRS_SNS_EV_START, NULL);

	return fi;
err:
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
	return NULL;
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
	case SNS_PDUT_ACK:
	case SNS_PDUT_ADD:
	case SNS_PDUT_DELETE:
	case SNS_PDUT_CHANGE_WEIGHT:
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
