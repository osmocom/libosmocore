#pragma once
#include <stdint.h>

#include <osmocom/gprs/protocol/gsm_08_18.h>
#include <osmocom/gprs/gprs_ns2.h>

struct bssgp2_flow_ctrl;
struct gprs_ns2_inst;
struct gprs_ra_id;
struct msgb;

struct bssgp2_flow_ctrl {
	uint8_t tag;
	/* maximum bucket size (Bmax) in bytes */
	uint64_t bucket_size_max;
	/*! bucket leak rate in _bytes_ per second */
	uint64_t bucket_leak_rate;
	/* percentage how full the given bucket is */
	uint8_t bucket_full_ratio;
	bool bucket_full_ratio_present;
	union {
		/*! FC-BVC specifi members */
		struct {
			/*! default maximum bucket size per MS in bytes */
			uint64_t bmax_default_ms;
			/*! default bucket leak rate (R) for MS flow control bucket */
			uint64_t r_default_ms;

			/*! average milliseconds of queueing delay for a BVC */
			uint32_t measurement;
			bool measurement_present;
		} bvc;
		/*! FC-MS specifi members */
		struct {
			/*! TLLI of the MS */
			uint32_t tlli;
		} ms;
	} u;
};


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

struct msgb *bssgp2_enc_flush_ll(uint32_t tlli, uint16_t old_bvci,
				 const uint16_t *new_bvci, const uint16_t *nsei);
struct msgb *bssgp2_enc_status(uint8_t cause, const uint16_t *bvci, const struct msgb *orig_msg, uint16_t max_pdu_len);


int bssgp2_dec_fc_bvc(struct bssgp2_flow_ctrl *fc, const struct tlv_parsed *tp);
struct msgb *bssgp2_enc_fc_bvc(const struct bssgp2_flow_ctrl *fc, enum bssgp_fc_granularity *gran);
struct msgb *bssgp2_enc_fc_bvc_ack(uint8_t tag);
int bssgp2_dec_fc_ms(struct bssgp2_flow_ctrl *fc, struct tlv_parsed *tp);
struct msgb *bssgp2_enc_fc_ms(const struct bssgp2_flow_ctrl *fc, enum bssgp_fc_granularity *gran);
struct msgb *bssgp2_enc_fc_ms_ack(uint32_t tlli, uint8_t tag);
