/* (C) 2009,2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009,2010 by On-Waves
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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#pragma once

#include "tlv.h"
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <sys/socket.h>

struct msgb;

struct msgb *gsm0808_create_layer3(struct msgb *msg_l3, uint16_t nc,
				   uint16_t cc, int lac, uint16_t _ci);
struct msgb *gsm0808_create_layer3_aoip(const struct msgb *msg_l3, uint16_t nc,
					uint16_t cc, int lac, uint16_t _ci,
					const struct gsm0808_speech_codec_list
					*scl);
struct msgb *gsm0808_create_reset(void);
struct msgb *gsm0808_create_reset_ack(void);
struct msgb *gsm0808_create_clear_command(uint8_t reason);
struct msgb *gsm0808_create_clear_complete(void);
struct msgb *gsm0808_create_cipher(const struct gsm0808_encrypt_info *ei,
				   const uint8_t *cipher_response_mode);
struct msgb *gsm0808_create_cipher_complete(struct msgb *layer3, uint8_t alg_id);
struct msgb *gsm0808_create_cipher_reject(uint8_t cause);
struct msgb *gsm0808_create_classmark_update(const uint8_t *cm2, uint8_t cm2_len,
					     const uint8_t *cm3, uint8_t cm3_len);
struct msgb *gsm0808_create_sapi_reject(uint8_t link_id);
struct msgb *gsm0808_create_ass_compl(uint8_t rr_cause, uint8_t chosen_channel,
				      uint8_t encr_alg_id, uint8_t speech_mode,
				      const struct sockaddr_storage *ss,
				      const struct gsm0808_speech_codec *sc,
				      const struct gsm0808_speech_codec_list
				      *scl);
struct msgb *gsm0808_create_assignment_completed(uint8_t rr_cause,
						 uint8_t chosen_channel,
						 uint8_t encr_alg_id,
						 uint8_t speech_mode);
struct msgb *gsm0808_create_ass_fail(uint8_t cause, const uint8_t *rr_cause,
				     const struct gsm0808_speech_codec_list
				     *scl);
struct msgb *gsm0808_create_assignment_failure(uint8_t cause, uint8_t *rr_cause);
struct msgb *gsm0808_create_clear_rqst(uint8_t cause);

struct msgb *gsm0808_create_dtap(struct msgb *msg, uint8_t link_id);
void gsm0808_prepend_dtap_header(struct msgb *msg, uint8_t link_id);

const struct tlv_definition *gsm0808_att_tlvdef(void);

const char *gsm0808_bssmap_name(uint8_t msg_type);
const char *gsm0808_bssap_name(uint8_t msg_type);
