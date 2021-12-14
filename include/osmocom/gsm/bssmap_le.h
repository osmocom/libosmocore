/*! \addtogroup bssmap_le
 *  @{
 *  \file bssmap_le.h
 * Message encoding and decoding for 3GPP TS 49.031 BSSMAP-LE.
 */
/*
 * (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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
 */
#pragma once

#include <osmocom/gsm/protocol/gsm_49_031.h>

struct osmo_bsslap_err;
struct osmo_gad_err;

struct osmo_bssmap_le_err {
	int rc;
	enum bssmap_le_msgt msg_type;
	enum bssmap_le_iei iei;
	enum lcs_cause cause;
	struct osmo_bsslap_err *bsslap_err;
	struct osmo_gad_err *gad_err;
	char *logmsg;
};

struct osmo_bssap_le_err {
	int rc;
	struct osmo_bssmap_le_err *bssmap_le_err;
	void *dtap_err;
	char *logmsg;
};

enum bssmap_le_msgt osmo_bssmap_le_msgt(const uint8_t *data, uint8_t len);

extern const struct value_string osmo_bssmap_le_msgt_names[];
static inline const char *osmo_bssmap_le_msgt_name(enum bssmap_le_msgt val)
{ return get_value_string(osmo_bssmap_le_msgt_names, val); }

extern const struct value_string osmo_bssmap_le_iei_names[];
static inline const char *osmo_bssmap_le_iei_name(enum bssmap_le_iei val)
{ return get_value_string(osmo_bssmap_le_iei_names, val); }

int osmo_lcs_cause_enc(struct msgb *msg, const struct lcs_cause_ie *lcs_cause);
int osmo_lcs_cause_dec(struct lcs_cause_ie *lcs_cause,
		       enum bssmap_le_msgt msgt, enum bssmap_le_iei iei,
		       struct osmo_bssmap_le_err **err, void *err_ctx,
		       const uint8_t *data, uint8_t len);

int osmo_bssap_le_pdu_to_str_buf(char *buf, size_t buflen, const struct bssap_le_pdu *bssap_le);
char *osmo_bssap_le_pdu_to_str_c(void *ctx, const struct bssap_le_pdu *bssap_le);

struct msgb *osmo_bssap_le_enc(const struct bssap_le_pdu *pdu);
int osmo_bssap_le_dec(struct bssap_le_pdu *pdu, struct osmo_bssap_le_err **err, void *err_ctx, struct msgb *msg);

uint8_t osmo_bssmap_le_ie_enc_location_type(struct msgb *msg, const struct bssmap_le_location_type *location_type);
int osmo_bssmap_le_ie_dec_location_type(struct bssmap_le_location_type *lt,
					enum bssmap_le_msgt msgt, enum bssmap_le_iei iei,
					struct osmo_bssmap_le_err **err, void *err_ctx,
					const uint8_t *elem, uint8_t len);

/*! @} */
