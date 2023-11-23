/*
 * GSM RLP (Radio Link Protocol) as used in CSD (3GPP TS 44.022)
 *
 * Copyright (C) 2022-2023 Harald Welte <laforge@osmocom.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */



#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <osmocom/core/utils.h>

/*! \defgroup rlp GSM RLP (Radio Link Protocol) as used in CSD (3GPP TS 24.022)
 *  @{
 * \file rlp.h */

/*! RLP frame type as per 3GPP TS 24.022 Section 5.2.1 */
enum osmo_rlp_ftype {
	OSMO_RLP_FT_U,
	OSMO_RLP_FT_S,
	OSMO_RLP_FT_IS,
};
extern const struct value_string osmo_rlp_ftype_vals[];

/*! RLP U-Frame Type as per 3GPP TS 24.022 Section 5.2.1 */
enum osmo_rlp_u_ftype {
	OSMO_RLP_U_FT_SABM	= 0x07,
	OSMO_RLP_U_FT_UA	= 0x0c,
	OSMO_RLP_U_FT_DISC	= 0x08,
	OSMO_RLP_U_FT_DM	= 0x03,
	OSMO_RLP_U_FT_NULL	= 0x0f,
	OSMO_RLP_U_FT_UI	= 0x00,
	OSMO_RLP_U_FT_XID	= 0x17,
	OSMO_RLP_U_FT_TEST	= 0x1c,
	OSMO_RLP_U_FT_REMAP	= 0x11,
};
extern const struct value_string osmo_rlp_ftype_u_vals[];

/*! RLP S-Frame type as per 3GPP TS 24.022 Section 5.2.1 */
enum osmo_rlp_s_ftype {
	OSMO_RLP_S_FT_RR	= 0,
	OSMO_RLP_S_FT_REJ	= 2,
	OSMO_RLP_S_FT_RNR	= 1,
	OSMO_RLP_S_FT_SREJ	= 3,
};
extern const struct value_string osmo_rlp_ftype_s_vals[];

/*! Data structure representing one decoded RLP frame */
struct osmo_rlp_frame_decoded {
	uint8_t version;
	enum osmo_rlp_ftype ftype;
	enum osmo_rlp_u_ftype u_ftype;
	enum osmo_rlp_s_ftype s_ftype;
	bool c_r;
	bool p_f;
	uint8_t s_bits;
	uint16_t n_s;
	uint16_t n_r;
	uint32_t fcs;
	uint8_t info[536/8];
	uint16_t info_len;
};

int osmo_rlp_decode(struct osmo_rlp_frame_decoded *out, uint8_t version, const uint8_t *data, size_t data_len);
int osmo_rlp_encode(uint8_t *out, size_t out_size, const struct osmo_rlp_frame_decoded *in);
uint32_t osmo_rlp_fcs_compute(const uint8_t *in, size_t in_len);

/*! @} */
