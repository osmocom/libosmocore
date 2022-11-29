#pragma once
#include <osmocom/isdn/v110.h>

int osmo_csd_12k_6k_decode_frame(struct osmo_v110_decoded_frame *fr, const ubit_t *ra_bits, size_t n_bits);
int osmo_csd_12k_6k_encode_frame(ubit_t *ra_bits, size_t ra_bits_size, const struct osmo_v110_decoded_frame *fr);
int osmo_csd_3k6_decode_frame(struct osmo_v110_decoded_frame *fr, const ubit_t *ra_bits, size_t n_bits);
int osmo_csd_3k6_encode_frame(ubit_t *ra_bits, size_t ra_bits_size, const struct osmo_v110_decoded_frame *fr);
void osmo_csd_ubit_dump(FILE *outf, const ubit_t *fr, size_t in_len);
