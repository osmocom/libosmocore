/*! \file gprs_ns2_internal.h */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/gprs/protocol/gsm_08_16.h>
#include <osmocom/gprs/gprs_ns2.h>

struct osmo_fsm_inst;
struct tlv_parsed;
struct vty;

struct gprs_ns2_vc_driver;
struct gprs_ns2_vc_bind;



#define NS_TIMERS_COUNT 8
#define NS_TIMERS "(tns-block|tns-block-retries|tns-reset|tns-reset-retries|tns-test|tns-alive|tns-alive-retries|tsns-prov)"
#define NS_TIMERS_HELP	\
	"(un)blocking Timer (Tns-block) timeout\n"		\
	"(un)blocking Timer (Tns-block) number of retries\n"	\
	"Reset Timer (Tns-reset) timeout\n"			\
	"Reset Timer (Tns-reset) number of retries\n"		\
	"Test Timer (Tns-test) timeout\n"			\
	"Alive Timer (Tns-alive) timeout\n"			\
	"Alive Timer (Tns-alive) number of retries\n"		\
	"SNS Provision Timer (Tsns-prov) timeout\n"

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
};

enum nsvc_timer_mode {
	/* standard timers */
	NSVC_TIMER_TNS_TEST,
	NSVC_TIMER_TNS_ALIVE,
	NSVC_TIMER_TNS_RESET,
	_NSVC_TIMER_NR,
};

enum ns_stat {
	NS_STAT_ALIVE_DELAY,
};

/*! Osmocom NS link layer types */
enum gprs_ns_ll {
	GPRS_NS_LL_UDP,		/*!< NS/UDP/IP */
	GPRS_NS_LL_E1,		/*!< NS/E1 */
	GPRS_NS_LL_FR_GRE,	/*!< NS/FR/GRE/IP */
};

/*! Osmocom NS2 VC create status */
enum gprs_ns2_cs {
	GPRS_NS2_CS_CREATED,     /*!< A NSVC object has been created */
	GPRS_NS2_CS_FOUND,       /*!< A NSVC object has been found */
	GPRS_NS2_CS_REJECTED,    /*!< Rejected and answered message */
	GPRS_NS2_CS_SKIPPED,     /*!< Skipped message */
	GPRS_NS2_CS_ERROR,       /*!< Failed to process message */
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

	/*! create dynamic NSE on receiving packages */
	bool create_nse;

	uint16_t timeout[NS_TIMERS_COUNT];

	/*! workaround for rate counter until rate counter accepts char str as index */
	uint32_t rate_ctr_idx;
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

	/*! true if this NSE was created by VTY or pcu socket) */
	bool persistent;

	/*! true if this NSE wasn't yet alive at all.
	 * Will be true after the first status ind with NS_AFF_CAUSE_RECOVERY */
	bool first;

	/*! true if this NSE has at least one alive VC */
	bool alive;

	struct osmo_fsm_inst *bss_sns_fi;
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

	/*! signaling weight. 0 = don't use for user data (BVCI != 0) */
	uint8_t data_weight;

	/*! can be used by the bind/driver of the virtual circuit. e.g. ipv4/ipv6/frgre/e1 */
	void *priv;

	bool nsvci_is_valid;
	bool sns_only;

	struct rate_ctr_group *ctrg;
	struct osmo_stat_item_group *statg;

	/*! which link-layer are we based on? */
	enum gprs_ns_ll ll;
	enum gprs_ns2_vc_mode mode;

	struct osmo_fsm_inst *fi;
};

/*! Structure repesenting a bind instance. E.g. IPv4 listen port. */
struct gprs_ns2_vc_bind {
	/*! list entry in nsi */
	struct llist_head list;
	/*! list of all VC */
	struct llist_head nsvc;
	/*! driver private structure */
	void *priv;
	/*! a pointer back to the nsi */
	struct gprs_ns2_inst *nsi;
	struct gprs_ns2_vc_driver *driver;

	/*! if VCs use reset/block/unblock method. IP shall not use this */
	enum gprs_ns2_vc_mode vc_mode;

	/*! send a msg over a VC */
	int (*send_vc)(struct gprs_ns2_vc *nsvc, struct msgb *msg);

	/*! free the vc priv data */
	void (*free_vc)(struct gprs_ns2_vc *nsvc);

	/*! allow to show information for the vty */
	void (*dump_vty)(const struct gprs_ns2_vc_bind *bind,
			 struct vty *vty, bool stats);
};

struct gprs_ns2_vc_driver {
	const char *name;
	void *priv;
	void (*free_bind)(struct gprs_ns2_vc_bind *driver);
};

enum gprs_ns2_cs ns2_create_vc(struct gprs_ns2_vc_bind *bind,
			       struct msgb *msg,
			       const char *logname,
			       struct msgb **reject,
			       struct gprs_ns2_vc **success);

int ns2_recv_vc(struct gprs_ns2_vc *nsvc,
		struct msgb *msg);

struct gprs_ns2_vc *ns2_vc_alloc(struct gprs_ns2_vc_bind *bind,
				 struct gprs_ns2_nse *nse,
				 bool initiater);

struct msgb *gprs_ns2_msgb_alloc(void);

void gprs_ns2_sns_dump_vty(struct vty *vty, const struct gprs_ns2_nse *nse, bool stats);
void ns2_prim_status_ind(struct gprs_ns2_nse *nse,
			 struct gprs_ns2_vc *nsvc,
			 uint16_t bvci,
			 enum gprs_ns2_affecting_cause cause);
void ns2_nse_notify_alive(struct gprs_ns2_vc *nsvc, bool alive);

/* message */
int gprs_ns2_validate(struct gprs_ns2_vc *nsvc,
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

/* transmit message over a VC */
int ns2_tx_block(struct gprs_ns2_vc *nsvc, uint8_t cause);
int ns2_tx_block_ack(struct gprs_ns2_vc *nsvc);

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
		       uint16_t bvci, struct msgb *orig_msg);

/* driver */
struct gprs_ns2_vc *gprs_ns2_ip_bind_connect(struct gprs_ns2_vc_bind *bind,
					     struct gprs_ns2_nse *nse,
					     const struct osmo_sockaddr *remote);

/* sns */
int gprs_ns2_sns_rx(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp);
struct osmo_fsm_inst *ns2_sns_bss_fsm_alloc(struct gprs_ns2_nse *nse,
					     const char *id);
int ns2_sns_bss_fsm_start(struct gprs_ns2_nse *nse, struct gprs_ns2_vc *nsvc,
			  const struct osmo_sockaddr *remote);
void ns2_sns_free_nsvc(struct gprs_ns2_vc *nsvc);

/* vc */
struct osmo_fsm_inst *gprs_ns2_vc_fsm_alloc(struct gprs_ns2_vc *nsvc,
					    const char *id, bool initiate);
int gprs_ns2_vc_fsm_start(struct gprs_ns2_vc *nsvc);
int gprs_ns2_vc_rx(struct gprs_ns2_vc *nsvc, struct msgb *msg, struct tlv_parsed *tp);
int gprs_ns2_vc_is_alive(struct gprs_ns2_vc *nsvc);
int gprs_ns2_vc_is_unblocked(struct gprs_ns2_vc *nsvc);

/* vty.c */
void ns2_vty_bind_apply(struct gprs_ns2_vc_bind *bind);

/* nse */
void ns2_nse_notify_unblocked(struct gprs_ns2_vc *nsvc, bool unblocked);
