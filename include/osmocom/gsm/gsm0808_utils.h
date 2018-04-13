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
#include <osmocom/gsm/gsm23003.h>

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
uint8_t gsm0808_enc_cell_id(struct msgb *msg, const struct gsm0808_cell_id *ci);
int gsm0808_dec_cell_id(struct gsm0808_cell_id *ci, const uint8_t *elem, uint8_t len);
int gsm0808_chan_type_to_speech_codec(uint8_t perm_spch);
int gsm0808_speech_codec_from_chan_type(struct gsm0808_speech_codec *sc,
					uint8_t perm_spch);

/*! @} */
