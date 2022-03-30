#pragma once
#include <stdint.h>

struct gprs_ns2_inst;
struct osmo_fsm_inst;
struct gprs_ra_id;
struct bssgp2_flow_ctrl;

enum bssp_ptp_bvc_fsm_state {
	BSSGP_BVCFSM_S_NULL,
	BSSGP_BVCFSM_S_BLOCKED,
	BSSGP_BVCFSM_S_WAIT_RESET_ACK,
	BSSGP_BVCFSM_S_UNBLOCKED,
};

enum bssgp_ptp_bvc_fsm_event {
	/* Rx of BSSGP PDUs from the remote side; 'data' is 'struct tlv_parsed', and
	 * the assumption is that the caller has already validated all mandatory IEs
	 * are present and of sufficient length */
	BSSGP_BVCFSM_E_RX_BLOCK,
	BSSGP_BVCFSM_E_RX_BLOCK_ACK,
	BSSGP_BVCFSM_E_RX_UNBLOCK,
	BSSGP_BVCFSM_E_RX_UNBLOCK_ACK,
	BSSGP_BVCFSM_E_RX_RESET,
	BSSGP_BVCFSM_E_RX_RESET_ACK,
	BSSGP_BVCFSM_E_RX_FC_BVC,
	BSSGP_BVCFSM_E_RX_FC_BVC_ACK,
	/* Requests of the local user */
	BSSGP_BVCFSM_E_REQ_BLOCK,	/* data: uint8_t *cause */
	BSSGP_BVCFSM_E_REQ_UNBLOCK,
	BSSGP_BVCFSM_E_REQ_RESET,	/* data: uint8_t *cause */
	BSSGP_BVCFSM_E_REQ_FC_BVC,	/* data: struct bssgp2_flow_ctrl */
};

struct bssgp_bvc_fsm_ops {
	/* call-back notifying the user of a state change */
	void (*state_chg_notification)(uint16_t nsei, uint16_t bvci, int old_state, int new_state,
					void *priv);
	/* call-back notifying the user of a BVC-RESET event */
	void (*reset_notification)(uint16_t nsei, uint16_t bvci, const struct gprs_ra_id *ra_id,
				   uint16_t cell_id, uint8_t cause, void *priv);
	void (*rx_fc_bvc)(uint16_t nsei, uint16_t bvci, const struct bssgp2_flow_ctrl *fc, void *priv);
	void (*reset_ack_notification)(uint16_t nsei, uint16_t bvci, const struct gprs_ra_id *ra_id,
				   uint16_t cell_id, uint8_t cause, void *priv);
};

struct osmo_fsm_inst *
bssgp_bvc_fsm_alloc_sig_bss(void *ctx, struct gprs_ns2_inst *nsi, uint16_t nsei, uint32_t features);

struct osmo_fsm_inst *
bssgp_bvc_fsm_alloc_ptp_bss(void *ctx, struct gprs_ns2_inst *nsi, uint16_t nsei, uint16_t bvci,
			    const struct gprs_ra_id *ra_id, uint16_t cell_id);

struct osmo_fsm_inst *
bssgp_bvc_fsm_alloc_sig_sgsn(void *ctx, struct gprs_ns2_inst *nsi, uint16_t nsei, uint32_t features);

struct osmo_fsm_inst *
bssgp_bvc_fsm_alloc_ptp_sgsn(void *ctx, struct gprs_ns2_inst *nsi, uint16_t nsei, uint16_t bvci);

void bssgp_bvc_fsm_set_ops(struct osmo_fsm_inst *fi, const struct bssgp_bvc_fsm_ops *ops, void *ops_priv);

bool bssgp_bvc_fsm_is_unblocked(struct osmo_fsm_inst *fi);

uint8_t bssgp_bvc_fsm_get_block_cause(struct osmo_fsm_inst *fi);

uint32_t bssgp_bvc_fsm_get_features_advertised(struct osmo_fsm_inst *fi);
uint32_t bssgp_bvc_fsm_get_features_received(struct osmo_fsm_inst *fi);
uint32_t bssgp_bvc_fsm_get_features_negotiated(struct osmo_fsm_inst *fi);

void bssgp_bvc_fsm_set_max_pdu_len(struct osmo_fsm_inst *fi, uint16_t max_pdu_len);
uint16_t bssgp_bvc_fsm_get_max_pdu_len(const struct osmo_fsm_inst *fi);