#pragma once
#include <stdint.h>

#include <osmocom/gprs/protocol/gsm_08_18.h>
#include <osmocom/gprs/gprs_ns2.h>

struct gprs_ns2_inst;
struct gprs_ra_id;
struct msgb;

int bssgp2_nsi_tx_ptp(struct gprs_ns2_inst *nsi, uint16_t nsei, uint16_t bvci,
		      struct msgb *msg, uint32_t lsp);

int bssgp2_nsi_tx_sig(struct gprs_ns2_inst *nsi, uint16_t nsei, struct msgb *msg, uint32_t lsp);

struct msgb *bssgp2_enc_bvc_block(uint16_t bvci, enum gprs_bssgp_cause cause);

struct msgb *bssgp2_enc_bvc_block_ack(uint16_t bvci);

struct msgb *bssgp2_enc_bvc_unblock(uint16_t bvci);

struct msgb *bssgp2_enc_bvc_unblock_ack(uint16_t bvci);

struct msgb *bssgp2_enc_bvc_reset(uint16_t bvci, enum gprs_bssgp_cause cause,
				  const struct gprs_ra_id *ra_id, uint16_t cell_id,
				  const uint8_t *feat_bm, const uint8_t *ext_feat_bm);

struct msgb *bssgp2_enc_bvc_reset_ack(uint16_t bvci, const struct gprs_ra_id *ra_id, uint16_t cell_id,
				      const uint8_t *feat_bm, const uint8_t *ext_feat_bm);

struct msgb *bssgp2_enc_status(uint8_t cause, const uint16_t *bvci, const struct msgb *orig_msg);
