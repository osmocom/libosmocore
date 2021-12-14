/*
 * (C) 2018 by sysmocom - s.f.m.c. GmbH
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
 */

#include "config.h"

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm29205.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>

#include <errno.h>

/*! \addtogroup gsm29205
 *  @{
 *  \file gsm29205.c
 *  Functions related to 3GPP TS 29.205, primarily message generation/encoding.
 */

/*! Create Global Call Reference.
 *  \param[out] msg Message Buffer for appending IE
 *  \param[in] g Global Call Reference, 3GPP TS 29.205 Table B 2.1.9.1
 *  \returns number of bytes added to \a msg */
uint8_t osmo_enc_gcr(struct msgb *msg, const struct osmo_gcr_parsed *g)
{
	uint8_t buf[2];

	if (!g)
		return 0;

	if (g->net_len < 3 || g->net_len > 5)
		return 0;

	msgb_lv_put(msg, g->net_len, g->net);

	osmo_store16be(g->node, &buf);
	msgb_lv_put(msg, 2, buf);

	msgb_lv_put(msg, 5, g->cr);

	/* Length: LV(Net) + LV(Node) + LV(CRef) - see 3GPP TS §3.2.2.115 */
	return (g->net_len + 1) + (2 + 1) + (5 + 1);
}

/*! Decode Global Call Reference, 3GPP TS 29.205 Table B 2.1.9.1.
 *  \param[out] gcr Caller-provided memory to store Global Call Reference
 *  \param[in] elem IE value to be decoded
 *  \param[in] len Length of \a elem in bytes
 *  \returns number of bytes parsed; negative on error */
int osmo_dec_gcr(struct osmo_gcr_parsed *gcr, const uint8_t *elem, uint8_t len)
{
	uint16_t parsed = 1; /* account for length byte right away */

	if (len < 13)
		return -EBADMSG;

	gcr->net_len = elem[0];
	if (gcr->net_len < 3 || gcr->net_len > 5)
		return -EINVAL;

	memcpy(gcr->net, elem + parsed, gcr->net_len);
	/* +1 for ignored Node ID length field */
	parsed += (gcr->net_len + 1);

	gcr->node = osmo_load16be(elem + parsed);
	parsed += 2;

	if (elem[parsed] != 5) /* see Table B 2.1.9.2 */
		return -ENOENT;

	parsed++;

	memcpy(gcr->cr, elem + parsed, 5);

	return parsed + 5;
}

/*! Compare two GCR structs.
 *  \param[in] gcr1 pointer to the GCR struct
 *  \param[in] gcr2 pointer to the GCR struct
 *  \returns true if GCRs are equal, false otherwise */
bool osmo_gcr_eq(const struct osmo_gcr_parsed *gcr1, const struct osmo_gcr_parsed *gcr2)
{
	if (gcr1->net_len != gcr2->net_len)
		return false;

	if (gcr1->node != gcr2->node)
		return false;

	if (memcmp(gcr1->cr, gcr2->cr, 5) != 0)
		return false;

	if (memcmp(gcr1->net, gcr2->net, gcr2->net_len) != 0)
		return false;

	return true;
}
