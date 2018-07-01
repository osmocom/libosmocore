#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gprs/gprs_ns.h>

/* gprs_ns_sns.c */
int gprs_ns_rx_sns(struct gprs_ns_inst *nsi, struct msgb *msg, struct tlv_parsed *tp);

struct osmo_fsm_inst *gprs_sns_bss_fsm_alloc(void *ctx, struct gprs_nsvc *nsvc, const char *id);
int gprs_sns_bss_fsm_start(struct gprs_ns_inst *nsi);

int gprs_sns_init(void);

/* gprs_ns.c */
void gprs_nsvc_start_test(struct gprs_nsvc *nsvc);
void gprs_start_alive_all_nsvcs(struct gprs_ns_inst *nsi);
int gprs_ns_tx_sns_ack(struct gprs_nsvc *nsvc, uint8_t trans_id, uint8_t *cause,
		       const struct gprs_ns_ie_ip4_elem *ip4_elems,unsigned int num_ip4_elems);

int gprs_ns_tx_sns_config(struct gprs_nsvc *nsvc, bool end_flag,
			  const struct gprs_ns_ie_ip4_elem *ip4_elems,
			  unsigned int num_ip4_elems);

int gprs_ns_tx_sns_config_ack(struct gprs_nsvc *nsvc, uint8_t *cause);

int gprs_ns_tx_sns_size(struct gprs_nsvc *nsvc, bool reset_flag, uint16_t max_nr_nsvc,
			uint16_t *ip4_ep_nr, uint16_t *ip6_ep_nr);

int gprs_ns_tx_sns_size_ack(struct gprs_nsvc *nsvc, uint8_t *cause);

struct vty;
void gprs_sns_dump_vty(struct vty *vty, const struct gprs_ns_inst *nsi, bool stats);
