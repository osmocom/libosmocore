#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gprs/gprs_ns.h>

void gprs_nsvc_start_test(struct gprs_nsvc *nsvc);
int gprs_ns_tx_sns_ack(struct gprs_nsvc *nsvc, uint8_t trans_id, uint8_t *cause,
		       const struct gprs_ns_ie_ip4_elem *ip4_elems,unsigned int num_ip4_elems);

int gprs_ns_tx_sns_config(struct gprs_nsvc *nsvc, bool end_flag,
			  const struct gprs_ns_ie_ip4_elem *ip4_elems,
			  unsigned int num_ip4_elems);

int gprs_ns_tx_sns_config_ack(struct gprs_nsvc *nsvc, uint8_t *cause);

int gprs_ns_tx_sns_size(struct gprs_nsvc *nsvc, bool reset_flag, uint16_t max_nr_nsvc,
			uint16_t *ip4_ep_nr, uint16_t *ip6_ep_nr);

int gprs_ns_tx_sns_size_ack(struct gprs_nsvc *nsvc, uint8_t *cause);
