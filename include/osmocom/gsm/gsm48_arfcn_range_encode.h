/*! \file gsm48_arfcn_range_encode.h */

#pragma once

#include <stdint.h>

enum osmo_gsm48_range {
	OSMO_GSM48_ARFCN_RANGE_INVALID	= -1,
	OSMO_GSM48_ARFCN_RANGE_128		= 127,
	OSMO_GSM48_ARFCN_RANGE_256		= 255,
	OSMO_GSM48_ARFCN_RANGE_512		= 511,
	OSMO_GSM48_ARFCN_RANGE_1024		= 1023,
};

#define OSMO_GSM48_RANGE_ENC_MAX_ARFCNS	29

int osmo_gsm48_range_enc_determine_range(const int *arfcns, int size, int *f0_out);
int osmo_gsm48_range_enc_arfcns(enum osmo_gsm48_range rng, const int *arfcns, int sze, int *out, int idx);
int osmo_gsm48_range_enc_find_index(enum osmo_gsm48_range rng, const int *arfcns, int size);
int osmo_gsm48_range_enc_filter_arfcns(int *arfcns, const int sze, const int f0, int *f0_included);

int osmo_gsm48_range_enc_128(uint8_t *chan_list, int f0, int *w);
int osmo_gsm48_range_enc_256(uint8_t *chan_list, int f0, int *w);
int osmo_gsm48_range_enc_512(uint8_t *chan_list, int f0, int *w);
int osmo_gsm48_range_enc_1024(uint8_t *chan_list, int f0, int f0_incl, int *w);
