/*! \addtogroup gsm0808
 *  @{
 *  \file gsm0808_utils.h */
/*
 * (C) 2016 by sysmocom - s.f.m.c. GmbH, Author: Philipp Maier
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#pragma once

struct sockaddr_storage;

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/gsm_utils.h>

 /*! (225-1)/2 is the maximum number of elements in a cell identifier list. */
#define GSM0808_CELL_ID_LIST2_MAXLEN		127

/*! Instead of this, use either struct gsm0808_cell_id or gsm0808_cell_id_list2.
 * All elements contain parsed representations of the data in the corresponding IE, in host-byte order.
 */
union gsm0808_cell_id_u {
	struct osmo_cell_global_id		global;
	struct osmo_lac_and_ci_id		lac_and_ci;
	uint16_t				ci;
	struct osmo_location_area_id		lai_and_lac;
	uint16_t				lac;
};

/*! Parsed representation of Cell Identifier IE (3GPP TS 48.008 3.2.2.17) */
struct gsm0808_cell_id {
	enum CELL_IDENT id_discr;
	union gsm0808_cell_id_u id;
};

/*! Parsed representation of a Cell Identifier List IE (3GPP TS 48.008 3.2.2.27). */
struct gsm0808_cell_id_list2 {
	enum CELL_IDENT id_discr;
	union gsm0808_cell_id_u id_list[GSM0808_CELL_ID_LIST2_MAXLEN];
	unsigned int id_list_len;
};

extern const struct value_string gsm0808_cell_id_discr_names[];
static inline const char *gsm0808_cell_id_discr_name(enum CELL_IDENT id_discr)
{ return get_value_string(gsm0808_cell_id_discr_names, id_discr); }

const char *gsm0808_cell_id_name(const struct gsm0808_cell_id *cid);
const char *gsm0808_cell_id_name2(const struct gsm0808_cell_id *cid);
const char *gsm0808_cell_id_list_name(const struct gsm0808_cell_id_list2 *cil);
int gsm0808_cell_id_list_name_buf(char *buf, size_t buflen, const struct gsm0808_cell_id_list2 *cil);
int gsm0808_cell_id_u_name(char *buf, size_t buflen,
			   enum CELL_IDENT id_discr, const union gsm0808_cell_id_u *u);

uint8_t gsm0808_enc_aoip_trasp_addr(struct msgb *msg,
				    const struct sockaddr_storage *ss);
int gsm0808_dec_aoip_trasp_addr(struct sockaddr_storage *ss,
				const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_speech_codec(struct msgb *msg,
				 const struct gsm0808_speech_codec *sc);
int gsm0808_dec_speech_codec(struct gsm0808_speech_codec *sc,
			     const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_speech_codec_list(struct msgb *msg,
				      const struct gsm0808_speech_codec_list
				      *scl);
int gsm0808_dec_speech_codec_list(struct gsm0808_speech_codec_list *scl,
				  const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_channel_type(struct msgb *msg,
				 const struct gsm0808_channel_type *ct);
int gsm0808_dec_channel_type(struct gsm0808_channel_type *ct,
			     const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_encrypt_info(struct msgb *msg,
				 const struct gsm0808_encrypt_info *ei);
int gsm0808_dec_encrypt_info(struct gsm0808_encrypt_info *ei,
			     const uint8_t *elem, uint8_t len);
uint8_t gsm0808_enc_cell_id_list2(struct msgb *msg, const struct gsm0808_cell_id_list2 *cil);
uint8_t gsm0808_enc_cell_id_list(struct msgb *msg,
				 const struct gsm0808_cell_id_list *cil)
				 OSMO_DEPRECATED("use gsm0808_enc_cell_id_list2 instead");
int gsm0808_dec_cell_id_list2(struct gsm0808_cell_id_list2 *cil, const uint8_t *elem, uint8_t len);
int gsm0808_dec_cell_id_list(struct gsm0808_cell_id_list *cil,
			     const uint8_t *elem, uint8_t len)
			     OSMO_DEPRECATED("use gsm0808_dec_cell_id_list2 instead");
int gsm0808_cell_id_list_add(struct gsm0808_cell_id_list2 *dst, const struct gsm0808_cell_id_list2 *src);
void gsm0808_cell_id_to_list(struct gsm0808_cell_id_list2 *dst, const struct gsm0808_cell_id *src);
uint8_t gsm0808_enc_cell_id(struct msgb *msg, const struct gsm0808_cell_id *ci);
int gsm0808_dec_cell_id(struct gsm0808_cell_id *ci, const uint8_t *elem, uint8_t len);
int gsm0808_chan_type_to_speech_codec(uint8_t perm_spch);
int gsm0808_speech_codec_from_chan_type(struct gsm0808_speech_codec *sc,
					uint8_t perm_spch);

/*! Return 3GPP TS 48.008 3.2.2.49 Current Channel Type 1 from enum gsm_chan_t. */
static inline uint8_t gsm0808_current_channel_type_1(enum gsm_chan_t type)
{
	switch (type) {
	default:
		return 0;
	case GSM_LCHAN_SDCCH:
		return 0x01;
	case GSM_LCHAN_TCH_F:
		return 0x18;
	case GSM_LCHAN_TCH_H:
		return 0x19;
	}
}

/*! Return 3GPP TS 48.008 3.2.2.51 Speech Version aka permitted speech version indication in 3.2.2.11
 * Channel Type. */
static inline enum gsm0808_permitted_speech gsm0808_permitted_speech(enum gsm_chan_t type,
								     enum gsm48_chan_mode mode)
{
	switch (mode) {
	case GSM48_CMODE_SPEECH_V1:
		switch (type) {
		case GSM_LCHAN_TCH_F:
			return GSM0808_PERM_FR1;
		case GSM_LCHAN_TCH_H:
			return GSM0808_PERM_HR1;
		default:
			return 0;
		}
	case GSM48_CMODE_SPEECH_EFR:
		switch (type) {
		case GSM_LCHAN_TCH_F:
			return GSM0808_PERM_FR2;
		case GSM_LCHAN_TCH_H:
			return GSM0808_PERM_HR2;
		default:
			return 0;
		}
	case GSM48_CMODE_SPEECH_AMR:
		switch (type) {
		case GSM_LCHAN_TCH_F:
			return GSM0808_PERM_HR3;
		case GSM_LCHAN_TCH_H:
			return GSM0808_PERM_HR3;
		default:
			return 0;
		}
	default:
		return 0;
	}
}

/*! Return 3GPP TS 48.008 3.2.2.33 Chosen Channel. */
static inline uint8_t gsm0808_chosen_channel(enum gsm_chan_t type, enum gsm48_chan_mode mode)
{
	uint8_t channel_mode = 0, channel = 0;

	switch (mode) {
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_EFR:
	case GSM48_CMODE_SPEECH_AMR:
		channel_mode = 0x9;
		break;
	case GSM48_CMODE_SIGN:
		channel_mode = 0x8;
		break;
	case GSM48_CMODE_DATA_14k5:
		channel_mode = 0xe;
		break;
	case GSM48_CMODE_DATA_12k0:
		channel_mode = 0xb;
		break;
	case GSM48_CMODE_DATA_6k0:
		channel_mode = 0xc;
		break;
	case GSM48_CMODE_DATA_3k6:
		channel_mode = 0xd;
		break;
	default:
		return 0;
	}

	switch (type) {
	case GSM_LCHAN_NONE:
		channel = 0x0;
		break;
	case GSM_LCHAN_SDCCH:
		channel = 0x1;
		break;
	case GSM_LCHAN_TCH_F:
		channel = 0x8;
		break;
	case GSM_LCHAN_TCH_H:
		channel = 0x9;
		break;
	default:
		return 0;
	}

	return channel_mode << 4 | channel;
}

const char *gsm0808_channel_type_name(const struct gsm0808_channel_type *ct);

/*! @} */
