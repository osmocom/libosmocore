/*! \addtogroup bsslap
 *  @{
 *  \file bsslap.h
 * Message encoding and decoding for 3GPP TS 48.071 BSS LCS Assistance Protocol (BSSLAP).
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

#include <osmocom/gsm/protocol/gsm_48_071.h>
#include <osmocom/gsm/protocol/gsm_49_031.h>

struct msgb;

struct osmo_bsslap_err {
	int rc;
	enum bsslap_msgt msg_type;
	enum bsslap_iei iei;
	enum lcs_cause cause;
	char *logmsg;
};

extern const struct value_string osmo_bsslap_msgt_names[];
static inline const char *osmo_bsslap_msgt_name(enum bsslap_msgt val)
{ return get_value_string(osmo_bsslap_msgt_names, val); }

extern const struct value_string osmo_bsslap_iei_names[];
static inline const char *osmo_bsslap_iei_name(enum bsslap_iei val)
{ return get_value_string(osmo_bsslap_iei_names, val); }

int osmo_bsslap_enc(struct msgb *msg, const struct bsslap_pdu *pdu);
int osmo_bsslap_dec(struct bsslap_pdu *pdu,
		    struct osmo_bsslap_err **err, void *err_ctx,
		    const uint8_t *data, size_t len);

/*! @} */
