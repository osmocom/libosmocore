/*
 * (C) 2017 by sysmocom - s.f.m.c. GmbH
 * (C) 2017 by Philipp Maier <pmaier@sysmocom.de>
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
 *
 */

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <osmocom/codec/codec.h>
#include <osmocom/codec/ecu.h>

/***********************************************************************
 * Integration with ECU core
 ***********************************************************************/

static struct osmo_ecu_state *ecu_fr_init(void *ctx, enum osmo_ecu_codec codec)
{
	struct osmo_ecu_state *st;
	size_t size = sizeof(*st) + sizeof(struct osmo_ecu_fr_state);

	st = talloc_named_const(ctx, size, "ecu_state_FR");
	if (!st)
		return NULL;

	memset(st, 0, size);
	st->codec = codec;

	return st;
}

static int ecu_fr_frame_in(struct osmo_ecu_state *st, bool bfi, const uint8_t *frame,
			   unsigned int frame_bytes)
{
	struct osmo_ecu_fr_state *fr = (struct osmo_ecu_fr_state *) &st->data;
	if (bfi)
		return 0;

	osmo_ecu_fr_reset(fr, frame);
	return 0;
}

static int ecu_fr_frame_out(struct osmo_ecu_state *st, uint8_t *frame_out)
{
	struct osmo_ecu_fr_state *fr = (struct osmo_ecu_fr_state *) &st->data;

	if (osmo_ecu_fr_conceal(fr, frame_out) == 0)
		return GSM_FR_BYTES;
	else
		return -1;
}

static const struct osmo_ecu_ops osmo_ecu_ops_fr = {
	.init = ecu_fr_init,
	.frame_in = ecu_fr_frame_in,
	.frame_out = ecu_fr_frame_out,
};

static __attribute__((constructor)) void on_dso_load_ecu_fr(void)
{
	osmo_ecu_register(&osmo_ecu_ops_fr, OSMO_ECU_CODEC_FR);
}
