#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/codec/codec.h>

/* Codec independent ECU state */
struct osmo_ecu_fr_state {
	bool subsequent_lost_frame;
	uint8_t frame_backup[GSM_FR_BYTES];
};

void osmo_ecu_fr_reset(struct osmo_ecu_fr_state *state, uint8_t *frame);
int osmo_ecu_fr_conceal(struct osmo_ecu_fr_state *state, uint8_t *frame);
