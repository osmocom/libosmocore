#pragma once

#include <osmocom/core/bits.h>

/* See Section 5.1.2.1 of ITU-T V.110 */
#define MAX_D_BITS	48
#define MAX_E_BITS	7
#define MAX_S_BITS	9
#define MAX_X_BITS	2

/*! a 'decoded' representation of a single V.110 frame. contains unpacket D, E, S and X bits */
struct osmo_v110_decoded_frame {
	ubit_t d_bits[MAX_D_BITS];
	ubit_t e_bits[MAX_E_BITS];
	ubit_t s_bits[MAX_S_BITS];
	ubit_t x_bits[MAX_X_BITS];
};

int osmo_v110_decode_frame(struct osmo_v110_decoded_frame *fr, const ubit_t *ra_bits, size_t n_bits);
int osmo_v110_encode_frame(ubit_t *ra_bits, size_t n_bits, const struct osmo_v110_decoded_frame *fr);

void osmo_v110_ubit_dump(FILE *outf, const ubit_t *fr, size_t in_len);


/*! enum for each supported V.110 synchronous RA1 function (one for each user bitrate) */
enum osmo_v100_sync_ra1_rate {
	OSMO_V110_SYNC_RA1_600,
	OSMO_V110_SYNC_RA1_1200,
	OSMO_V110_SYNC_RA1_2400,
	OSMO_V110_SYNC_RA1_4800,
	OSMO_V110_SYNC_RA1_7200,
	OSMO_V110_SYNC_RA1_9600,
	OSMO_V110_SYNC_RA1_12000,
	OSMO_V110_SYNC_RA1_14400,
	OSMO_V110_SYNC_RA1_19200,
	OSMO_V110_SYNC_RA1_24000,
	OSMO_V110_SYNC_RA1_28800,
	OSMO_V110_SYNC_RA1_38400,
	_NUM_OSMO_V110_SYNC_RA1
};

int osmo_v110_sync_ra1_get_user_data_chunk_bitlen(enum osmo_v100_sync_ra1_rate rate);
int osmo_v110_sync_ra1_get_user_data_rate(enum osmo_v100_sync_ra1_rate rate);
int osmo_v110_sync_ra1_get_intermediate_rate(enum osmo_v100_sync_ra1_rate rate);

int osmo_v110_sync_ra1_user_to_ir(enum osmo_v100_sync_ra1_rate rate, struct osmo_v110_decoded_frame *fr,
				  const ubit_t *d_in, size_t in_len);

int osmo_v110_sync_ra1_ir_to_user(enum osmo_v100_sync_ra1_rate rate, ubit_t *d_out, size_t out_len,
				  const struct osmo_v110_decoded_frame *fr);
