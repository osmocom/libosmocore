/*! \file gprs_ns2_internal.h */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/logging.h>
#include <osmocom/gprs/protocol/gsm_08_16.h>
#include <osmocom/gprs/gprs_ns2.h>

#define LOGNSE(nse, lvl, fmt, args ...) \
	LOGP(DLNS, lvl, "NSE(%05u) " fmt, (nse)->nsei, ## args)

#define LOGBIND(bind, lvl, fmt, args ...) \
	LOGP(DLNS, lvl, "BIND(%s) " fmt, (bind)->name, ## args)

#define LOGNSVC_SS(ss, nsvc, lvl, fmt, args ...)				\
	do {									\
		if ((nsvc)->nsvci_is_valid) {					\
			LOGP(ss, lvl, "NSE(%05u)-NSVC(%05u) " fmt,		\
			     (nsvc)->nse->nsei, (nsvc)->nsvci, ## args);	\
		} else { 							\
			LOGP(ss, lvl, "NSE(%05u)-NSVC(none) " fmt, 		\
			     (nsvc)->nse->nsei, ## args);			\
		}								\
	} while (0)

#define LOGNSVC(nsvc, lvl, fmt, args ...)					\
	LOGNSVC_SS(DLNS, nsvc, lvl, fmt, ## args)

#define LOG_NS_SIGNAL(nsvc, direction, pdu_type, lvl, fmt, args ...)	\
	LOGNSVC_SS(DLNSSIGNAL, nsvc, lvl, "%s %s" fmt, direction, get_value_string(gprs_ns_pdu_strings, pdu_type), ## args)

#define LOG_NS_DATA(nsvc, direction, pdu_type, lvl, fmt, args ...)	\
	LOGNSVC_SS(DLNSDATA, nsvc, lvl, "%s %s" fmt, direction, get_value_string(gprs_ns_pdu_strings, pdu_type), ## args)

#define LOG_NS_RX_SIGNAL(nsvc, pdu_type) LOG_NS_SIGNAL(nsvc, "Rx", pdu_type, LOGL_INFO, "\n")
#define LOG_NS_TX_SIGNAL(nsvc, pdu_type) LOG_NS_SIGNAL(nsvc, "Tx", pdu_type, LOGL_INFO, "\n")

#define RATE_CTR_INC_NS(nsvc, ctr) \
	do { \
		struct gprs_ns2_vc *_nsvc = (nsvc); \
		rate_ctr_inc(rate_ctr_group_get_ctr(_nsvc->ctrg, ctr)); \
		rate_ctr_inc(rate_ctr_group_get_ctr(_nsvc->nse->ctrg, ctr)); \
	} while (0)

#define RATE_CTR_ADD_NS(nsvc, ctr, val) \
	do { \
		struct gprs_ns2_vc *_nsvc = (nsvc); \
		rate_ctr_add(rate_ctr_group_get_ctr(_nsvc->ctrg, ctr), val); \
		rate_ctr_add(rate_ctr_group_get_ctr(_nsvc->nse->ctrg, ctr), val); \
	} while (0)


struct osmo_fsm_inst;
struct tlv_parsed;
struct vty;

struct gprs_ns2_vc_driver;
struct gprs_ns2_vc_bind;

#define NS_TIMERS_COUNT 11
#define NS_TIMERS "(tns-block|tns-block-retries|tns-reset|tns-reset-retries|tns-test|tns-alive|tns-alive-retries|tsns-prov|tsns-size-retries|tsns-config-retries|tsns-procedures-retries)"
#define NS_TIMERS_HELP	\
	"(un)blocking Timer (Tns-block) timeout\n"		\
	"(un)blocking Timer (Tns-block) number of retries\n"	\
	"Reset Timer (Tns-reset) timeout\n"			\
	"Reset Timer (Tns-reset) number of retries\n"		\
	"Test Timer (Tns-test) timeout\n"			\
	"Alive Timer (Tns-alive) timeout\n"			\
	"Alive Timer (Tns-alive) number of retries\n"		\
	"SNS Provision Timer (Tsns-prov) timeout\n"		\
	"SNS Size number of retries\n"				\
	"SNS Config number of retries\n"			\
	"SNS Procedures number of retries\n"			\

/* Educated guess - LLC user payload is 1500 bytes plus possible headers */
#define NS_ALLOC_SIZE	3072
#define NS_ALLOC_HEADROOM 20

enum ns2_timeout {
	NS_TOUT_TNS_BLOCK,
	NS_TOUT_TNS_BLOCK_RETRIES,
	NS_TOUT_TNS_RESET,
	NS_TOUT_TNS_RESET_RETRIES,
	NS_TOUT_TNS_TEST,
	NS_TOUT_TNS_ALIVE,
	NS_TOUT_TNS_ALIVE_RETRIES,
	NS_TOUT_TSNS_PROV,
	NS_TOUT_TSNS_SIZE_RETRIES,
	NS_TOUT_TSNS_CONFIG_RETRIES,
	NS_TOUT_TSNS_PROCEDURES_RETRIES,
};

enum nsvc_timer_mode {
	/* standard timers */
	NSVC_TIMER_TNS_TEST,
	NSVC_TIMER_TNS_ALIVE,
	NSVC_TIMER_TNS_RESET,
	_NSVC_TIMER_NR,
};

enum ns2_vc_stat {
	NS_STAT_ALIVE_DELAY,
};

enum ns2_bind_stat {
	NS2_BIND_STAT_BACKLOG_LEN,
};

/*! Osmocom NS2 VC create status */
enum ns2_cs {
	NS2_CS_CREATED,     /*!< A NSVC object has been created */
	NS2_CS_FOUND,       /*!< A NSVC object has been found */
	NS2_CS_REJECTED,    /*!< Rejected and answered message */
	NS2_CS_SKIPPED,     /*!< Skipped message */
	NS2_CS_ERROR,       /*!< Failed to process message */
};

enum ns_ctr {
	NS_CTR_PKTS_IN,
	NS_CTR_PKTS_OUT,
	NS_CTR_PKTS_OUT_DROP,
	NS_CTR_BYTES_IN,
	NS_CTR_BYTES_OUT,
	NS_CTR_BYTES_OUT_DROP,
	NS_CTR_BLOCKED,
	NS_CTR_UNBLOCKED,
	NS_CTR_DEAD,
	NS_CTR_REPLACED,
	NS_CTR_NSEI_CHG,
	NS_CTR_INV_VCI,
	NS_CTR_INV_NSEI,
	NS_CTR_LOST_ALIVE,
	NS_CTR_LOST_RESET,
};

#define NSE_S_BLOCKED	0x0001
#define NSE_S_ALIVE	0x0002
#define NSE_S_RESET	0x0004

#define NS_DESC_B(st) ((st) & NSE_S_BLOCKED ? "BLOCKED" : "UNBLOCKED")
#define NS_DESC_A(st) ((st) & NSE_S_ALIVE ? "ALIVE" : "DEAD")
#define NS_DESC_R(st) ((st) & NSE_S_RESET ? "RESET" : "UNRESET")

/*! An instance of the NS protocol stack */
struct gprs_ns2_inst {
	/*! callback to the user for incoming UNIT DATA IND */
	osmo_prim_cb cb;

	/*! callback data */
	void *cb_data;

	/*! linked lists of all NSVC binds (e.g. IPv4 bind, but could be also E1 */
	struct llist_head binding;

	/*! linked lists of all NSVC in this instance */
	struct llist_head nse;

	uint16_t timeout[NS_TIMERS_COUNT];

	/*! workaround for rate counter until rate counter accepts char str as index */
	uint32_t nsvc_rate_ctr_idx;
	uint32_t bind_rate_ctr_idx;
};


/*! Structure repesenting a NSE. The BSS/PCU will only have a single NSE, while SGSN has one for each BSS/PCU */
struct gprs_ns2_nse {
	uint16_t nsei;

	/*! entry back to ns2_inst */
	struct gprs_ns2_inst *nsi;

	/*! llist entry for gprs_ns2_inst */
	struct llist_head list;

	/*! llist head to hold all nsvc */
	struct llist_head nsvc;

	/*! count all active NSVCs */
	int nsvc_count;

	/*! true if this NSE was created by VTY or pcu socket) */
	bool persistent;

	/*! true if this NSE wasn't yet alive at all.
	 * Will be true after the first status ind with NS_AFF_CAUSE_RECOVERY */
	bool first;

	/*! true if this NSE has at least one alive VC */
	bool alive;

	/*! which link-layer are we based on? */
	enum gprs_ns2_ll ll;

	/*! which dialect does this NSE speaks? */
	enum gprs_ns2_dialect dialect;

	struct osmo_fsm_inst *bss_sns_fi;

	/*! sum of all the data weight of _alive_ NS-VCs */
	uint32_t sum_data_weight;

	/*! sum of all the signalling weight of _alive_ NS-VCs */
	uint32_t sum_sig_weight;

	/*! MTU of a NS PDU. This is the lowest MTU of all NSVCs */
	uint16_t mtu;

	/*! are we implementing the SGSN role? */
	bool ip_sns_role_sgsn;

	/*! NSE-wide statistics */
	struct rate_ctr_group *ctrg;

	/*! recursive anchor */
	bool freed;

	/*! when the NSE became alive or dead */
	struct timespec ts_alive_change;
};

/*! Structure representing a single NS-VC */
struct gprs_ns2_vc {
	/*! list of NS-VCs within NSE */
	struct llist_head list;

	/*! list of NS-VCs within bind, bind is the owner! */
	struct llist_head blist;

	/*! pointer to NS Instance */
	struct gprs_ns2_nse *nse;

	/*! pointer to NS VL bind. bind own the memory of this instance */
	struct gprs_ns2_vc_bind *bind;

	/*! true if this NS was created by VTY or pcu socket) */
	bool persistent;

	/*! uniquely identifies NS-VC if VC contains nsvci */
	uint16_t nsvci;

	/*! signalling weight. 0 = don't use for signalling (BVCI == 0)*/
	uint8_t sig_weight;

	/*! signalling packet counter for the load sharing function */
	uint8_t sig_counter;

	/*! data weight. 0 = don't use for user data (BVCI != 0) */
	uint8_t data_weight;

	/*! can be used by the bind/driver of the virtual circuit. e.g. ipv4/ipv6/frgre/e1 */
	void *priv;

	bool nsvci_is_valid;
	/*! should this NS-VC only be used for SNS-SIZE and SNS-CONFIG? */
	bool sns_only;

	struct rate_ctr_group *ctrg;
	struct osmo_stat_item_group *statg;

	enum gprs_ns2_vc_mode mode;

	struct osmo_fsm_inst *fi;

	/*! recursive anchor */
	bool freed;

	/*! if blocked by O&M/vty */
	bool om_blocked;

	/*! when the NSVC became alive or dead */
	struct timespec ts_alive_change;
};

/*! Structure repesenting a bind instance. E.g. IPv4 listen port. */
struct gprs_ns2_vc_bind {
	/*! unique name */
	const char *name;
	/*! list entry in nsi */
	struct llist_head list;
	/*! list of all VC */
	struct llist_head nsvc;
	/*! driver private structure */
	void *priv;
	/*! a pointer back to the nsi */
	struct gprs_ns2_inst *nsi;
	struct gprs_ns2_vc_driver *driver;

	bool accept_ipaccess;
	bool accept_sns;

	/*! transfer capability in mbit */
	int transfer_capability;

	/*! MTU of a NS PDU on this bind. */
	uint16_t mtu;

	/*! which link-layer are we based on? */
	enum gprs_ns2_ll ll;

	/*! send a msg over a VC */
	int (*send_vc)(struct gprs_ns2_vc *nsvc, struct msgb *msg);

	/*! free the vc priv data */
	void (*free_vc)(struct gprs_ns2_vc *nsvc);

	/*! allow to show information for the vty */
	void (*dump_vty)(const struct gprs_ns2_vc_bind *bind,
			 struct vty *vty, bool stats);

	/*! the IP-SNS signalling weight when doing dynamic configuration */
	uint8_t sns_sig_weight;
	/*! the IP-SNS data weight when doing dynamic configuration */
	uint8_t sns_data_weight;

	struct osmo_stat_item_group *statg;

	/*! recursive anchor */
	bool freed;
};

struct gprs_ns2_vc_driver {
	const char *name;
	void *priv;
	void (*free_bind)(struct gprs_ns2_vc_bind *driver);
};

enum ns2_sns_event {
	NS2_SNS_EV_REQ_SELECT_ENDPOINT,	/*!< Select a SNS endpoint from the list */
	NS2_SNS_EV_RX_SIZE,
	NS2_SNS_EV_RX_SIZE_ACK,
	NS2_SNS_EV_RX_CONFIG,
	NS2_SNS_EV_RX_CONFIG_END,		/*!< SNS-CONFIG with end flag received */
	NS2_SNS_EV_RX_CONFIG_ACK,
	NS2_SNS_EV_RX_ADD,
	NS2_SNS_EV_RX_DELETE,
	NS2_SNS_EV_RX_CHANGE_WEIGHT,
	NS2_SNS_EV_RX_ACK,			/*!< Rx of SNS-ACK (response to ADD/DELETE/CHG_WEIGHT */
	NS2_SNS_EV_REQ_NO_NSVC,		/*!< no more NS-VC remaining (all dead) */
	NS2_SNS_EV_REQ_FREE_NSVCS,		/*!< free all NS-VCs */
	NS2_SNS_EV_REQ_NSVC_ALIVE,		/*!< a NS-VC became alive */
	NS2_SNS_EV_REQ_ADD_BIND,		/*!< add a new local bind to this NSE */
	NS2_SNS_EV_REQ_DELETE_BIND,		/*!< remove a local bind from this NSE */
	NS2_SNS_EV_REQ_CHANGE_WEIGHT,		/*!< a bind changed its weight */
};

enum ns2_cs ns2_create_vc(struct gprs_ns2_vc_bind *bind,
			       struct msgb *msg,
			       const struct osmo_sockaddr *remote,
			       const char *logname,
			       struct msgb **reject,
			       struct gprs_ns2_vc **success);

int ns2_recv_vc(struct gprs_ns2_vc *nsvc,
		struct msgb *msg);

struct gprs_ns2_vc *ns2_vc_alloc(struct gprs_ns2_vc_bind *bind,
				 struct gprs_ns2_nse *nse,
				 bool initiater,
				 enum gprs_ns2_vc_mode vc_mode,
				 const char *id);

void ns2_free_nsvcs(struct gprs_ns2_nse *nse);
int ns2_bind_alloc(struct gprs_ns2_inst *nsi, const char *name,
		   struct gprs_ns2_vc_bind **result);

struct msgb *ns2_msgb_alloc(void);

void ns2_sns_write_vty(struct vty *vty, const struct gprs_ns2_nse *nse);
void ns2_sns_dump_vty(struct vty *vty, const char *prefix, const struct gprs_ns2_nse *nse, bool stats);
void ns2_prim_status_ind(struct gprs_ns2_nse *nse,
			 struct gprs_ns2_vc *nsvc,
			 uint16_t bvci,
			 enum gprs_ns2_affecting_cause cause);
void ns2_nse_notify_alive(struct gprs_ns2_vc *nsvc, bool alive);
void ns2_nse_update_mtu(struct gprs_ns2_nse *nse);
int ns2_nse_set_dialect(struct gprs_ns2_nse *nse, enum gprs_ns2_dialect dialect);

/* message */
int ns2_validate(struct gprs_ns2_vc *nsvc,
		 uint8_t pdu_type,
		 struct msgb *msg,
		 struct tlv_parsed *tp,
		 uint8_t *cause);

/* SNS messages */
int ns2_tx_sns_ack(struct gprs_ns2_vc *nsvc, uint8_t trans_id, uint8_t *cause,
			const struct gprs_ns_ie_ip4_elem *ip4_elems,
			unsigned int num_ip4_elems,
			const struct gprs_ns_ie_ip6_elem *ip6_elems,
			unsigned int num_ip6_elems);
int ns2_tx_sns_config(struct gprs_ns2_vc *nsvc, bool end_flag,
			   const struct gprs_ns_ie_ip4_elem *ip4_elems,
			   unsigned int num_ip4_elems,
			   const struct gprs_ns_ie_ip6_elem *ip6_elems,
			   unsigned int num_ip6_elems);
int ns2_tx_sns_config_ack(struct gprs_ns2_vc *nsvc, uint8_t *cause);
int ns2_tx_sns_size(struct gprs_ns2_vc *nsvc, bool reset_flag, uint16_t max_nr_nsvc,
			 int ip4_ep_nr, int ip6_ep_nr);
int ns2_tx_sns_size_ack(struct gprs_ns2_vc *nsvc, uint8_t *cause);

int ns2_tx_sns_add(struct gprs_ns2_vc *nsvc,
		   uint8_t trans_id,
		   const struct gprs_ns_ie_ip4_elem *ip4_elems,
		   unsigned int num_ip4_elems,
		   const struct gprs_ns_ie_ip6_elem *ip6_elems,
		   unsigned int num_ip6_elems);
int ns2_tx_sns_change_weight(struct gprs_ns2_vc *nsvc,
			     uint8_t trans_id,
			     const struct gprs_ns_ie_ip4_elem *ip4_elems,
			     unsigned int num_ip4_elems,
			     const struct gprs_ns_ie_ip6_elem *ip6_elems,
			     unsigned int num_ip6_elems);
int ns2_tx_sns_del(struct gprs_ns2_vc *nsvc,
		   uint8_t trans_id,
		   const struct gprs_ns_ie_ip4_elem *ip4_elems,
		   unsigned int num_ip4_elems,
		   const struct gprs_ns_ie_ip6_elem *ip6_elems,
		   unsigned int num_ip6_elems);

/* transmit message over a VC */
int ns2_tx_block(struct gprs_ns2_vc *nsvc, uint8_t cause, uint16_t *nsvci);
int ns2_tx_block_ack(struct gprs_ns2_vc *nsvc, uint16_t *nsvci);

int ns2_tx_reset(struct gprs_ns2_vc *nsvc, uint8_t cause);
int ns2_tx_reset_ack(struct gprs_ns2_vc *nsvc);

int ns2_tx_unblock(struct gprs_ns2_vc *nsvc);
int ns2_tx_unblock_ack(struct gprs_ns2_vc *nsvc);

int ns2_tx_alive(struct gprs_ns2_vc *nsvc);
int ns2_tx_alive_ack(struct gprs_ns2_vc *nsvc);

int ns2_tx_unit_data(struct gprs_ns2_vc *nsvc,
		     uint16_t bvci, uint8_t sducontrol,
		     struct msgb *msg);

int ns2_tx_status(struct gprs_ns2_vc *nsvc, uint8_t cause,
		  uint16_t bvci, struct msgb *orig_msg, uint16_t *nsvci);

/* driver */
struct gprs_ns2_vc *ns2_ip_bind_connect(struct gprs_ns2_vc_bind *bind,
					struct gprs_ns2_nse *nse,
					const struct osmo_sockaddr *remote);
int ns2_ip_count_bind(struct gprs_ns2_inst *nsi, struct osmo_sockaddr *remote);
struct gprs_ns2_vc_bind *ns2_ip_get_bind_by_index(struct gprs_ns2_inst *nsi,
						  struct osmo_sockaddr *remote,
						  int index);

/* sns */
int ns2_sns_rx(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp);
struct osmo_fsm_inst *ns2_sns_bss_fsm_alloc(struct gprs_ns2_nse *nse,
					     const char *id);
struct osmo_fsm_inst *ns2_sns_sgsn_fsm_alloc(struct gprs_ns2_nse *nse, const char *id);
void ns2_sns_replace_nsvc(struct gprs_ns2_vc *nsvc);
void ns2_sns_notify_alive(struct gprs_ns2_nse *nse, struct gprs_ns2_vc *nsvc, bool alive);
void ns2_sns_update_weights(struct gprs_ns2_vc_bind *bind);

/* vc */
struct osmo_fsm_inst *ns2_vc_fsm_alloc(struct gprs_ns2_vc *nsvc,
					    const char *id, bool initiate);
int ns2_vc_fsm_start(struct gprs_ns2_vc *nsvc);
int ns2_vc_force_unconfigured(struct gprs_ns2_vc *nsvc);
int ns2_vc_rx(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp);
int ns2_vc_is_alive(struct gprs_ns2_vc *nsvc);
int ns2_vc_is_unblocked(struct gprs_ns2_vc *nsvc);
int ns2_vc_block(struct gprs_ns2_vc *nsvc);
int ns2_vc_reset(struct gprs_ns2_vc *nsvc);
int ns2_vc_unblock(struct gprs_ns2_vc *nsvc);
void ns2_vty_dump_nsvc(struct vty *vty, struct gprs_ns2_vc *nsvc, bool stats);

/* nse */
void ns2_nse_notify_unblocked(struct gprs_ns2_vc *nsvc, bool unblocked);
enum gprs_ns2_vc_mode ns2_dialect_to_vc_mode(enum gprs_ns2_dialect dialect);
int ns2_count_transfer_cap(struct gprs_ns2_nse *nse,
			   uint16_t bvci);

/* vty */
int ns2_sns_add_sns_default_binds(struct gprs_ns2_nse *nse);
