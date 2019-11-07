#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/defs.h>
#include <osmocom/codec/codec.h>

/* ECU state for GSM-FR */
struct osmo_ecu_fr_state {
	bool subsequent_lost_frame;
	uint8_t frame_backup[GSM_FR_BYTES];
};

void osmo_ecu_fr_reset(struct osmo_ecu_fr_state *state, const uint8_t *frame)
	OSMO_DEPRECATED_OUTSIDE("Use generic ECU abstraction layer instead");
int osmo_ecu_fr_conceal(struct osmo_ecu_fr_state *state, uint8_t *frame)
	OSMO_DEPRECATED_OUTSIDE("Use generic ECU abstraction layer instead");

enum osmo_ecu_codec {
	OSMO_ECU_CODEC_HR,
	OSMO_ECU_CODEC_FR,
	OSMO_ECU_CODEC_EFR,
	OSMO_ECU_CODEC_AMR,
	_NUM_OSMO_ECU_CODECS
};

/***********************************************************************
 * Generic ECU abstraction layer below
 ***********************************************************************/

/* As the developer and copyright holder of the related code, I hereby
 * state that any ECU implementation using 'struct osmo_ecu_ops' and
 * registering with the 'osmo_ecu_register()' function shall not be
 * considered as a derivative work under any applicable copyright law;
 * the copyleft terms of GPLv2 shall hence not apply to any such ECU
 * implementation.
 *
 * The intent of the above exception is to allow anyone to combine third
 * party Error Concealment Unit implementations with libosmocodec.
 * including but not limited to such published by ETSI.
 *
 *   -- Harald Welte <laforge@gnumonks.org> on August 1, 2019.
 */

/* Codec independent ECU state */
struct osmo_ecu_state {
	enum osmo_ecu_codec codec;
	uint8_t data[0];
};

/* initialize an ECU instance */
struct osmo_ecu_state *osmo_ecu_init(void *ctx, enum osmo_ecu_codec codec);

/* destroy an ECU instance */
void osmo_ecu_destroy(struct osmo_ecu_state *st);

/* process a received frame a substitute/erroneous frame */
int osmo_ecu_frame_in(struct osmo_ecu_state *st, bool bfi,
		      const uint8_t *frame, unsigned int frame_bytes);

/* generate output data for a substitute/erroneous frame */
int osmo_ecu_frame_out(struct osmo_ecu_state *st, uint8_t *frame_out);

struct osmo_ecu_ops {
	struct osmo_ecu_state * (*init)(void *ctx, enum osmo_ecu_codec codec);
	void (*destroy)(struct osmo_ecu_state *);
	int (*frame_in)(struct osmo_ecu_state *st, bool bfi,
			const uint8_t *frame, unsigned int frame_bytes);
	int (*frame_out)(struct osmo_ecu_state *st, uint8_t *frame_out);
};

int osmo_ecu_register(const struct osmo_ecu_ops *ops, enum osmo_ecu_codec codec);
