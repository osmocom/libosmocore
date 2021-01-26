
#pragma once

#include <osmocom/gprs/gprs_bssgp.h>

extern bssgp_bvc_send bssgp_ns_send;
extern void *bssgp_ns_send_data;

int bssgp_rx_rim(struct msgb *msg, struct tlv_parsed *tp, uint16_t bvci);
