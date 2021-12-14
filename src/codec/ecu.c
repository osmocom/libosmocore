/* Core infrastructure for ECU implementations */

/* (C) 2019 by Harald Welte <laforge@gnumonks.org>
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

/* As the developer and copyright holder of the related code, I hereby
 * state that any ECU implementation using 'struct osmo_ecu_ops' and
 * registering with the 'osmo_ecu_register()' function shall not be
 * considered as a derivative work under any applicable copyright law;
 * the copyleft terms of GPLv2 shall hence not apply to any such ECU
 * implementation.
 *
 * The intent of the above exception is to allow anyone to combine third
 * party Error Concealment Unit implementations with libosmocodec.
 * including but not limited to such published by ETSI.
 *
 *   -- Harald Welte <laforge@gnumonks.org> on August 1, 2019.
 */

#include <string.h>
#include <errno.h>

#include <osmocom/codec/ecu.h>
#include <osmocom/core/talloc.h>

static const struct osmo_ecu_ops *g_ecu_ops[_NUM_OSMO_ECU_CODECS];

/***********************************************************************
 * high-level API for users
 ***********************************************************************/

/*! initialize an ECU instance for given codec.
 *  \param[in] ctx talloc context from which to allocate
 *  \parma[in] codec codec for which to initialize/create ECU */
struct osmo_ecu_state *osmo_ecu_init(void *ctx, enum osmo_ecu_codec codec)
{
	if (codec >= ARRAY_SIZE(g_ecu_ops))
		return NULL;
	if (!g_ecu_ops[codec] || !g_ecu_ops[codec]->init)
		return NULL;
	return g_ecu_ops[codec]->init(ctx, codec);
}

/*! destroy an ECU instance */
void osmo_ecu_destroy(struct osmo_ecu_state *st)
{
	if (st->codec >= ARRAY_SIZE(g_ecu_ops))
		return;
	if (!g_ecu_ops[st->codec])
		return;

	if (!g_ecu_ops[st->codec]->destroy)
		talloc_free(st);
	else
		g_ecu_ops[st->codec]->destroy(st);
}

/*! process a received frame a substitute/erroneous frame.
 *  \param[in] st  ECU state/instance on which to operate
 *  \param[in] bfi Bad Frame Indication
 *  \param[in] frame received codec frame to be processed
 *  \param[in] frame_bytes number of bytes available in frame */
int osmo_ecu_frame_in(struct osmo_ecu_state *st, bool bfi,
                      const uint8_t *frame, unsigned int frame_bytes)
{
	if (st->codec >= ARRAY_SIZE(g_ecu_ops))
		return -EINVAL;
	if (!g_ecu_ops[st->codec])
		return -EBUSY;
	return g_ecu_ops[st->codec]->frame_in(st, bfi, frame, frame_bytes);
}

/*! generate output data for a substitute/erroneous frame.
 *  \param[in] st ECU state/instance on which to operate
 *  \param[out] frame_out buffer for generated output frame
 *  \return number of bytes written to frame_out; negative on error */
int osmo_ecu_frame_out(struct osmo_ecu_state *st, uint8_t *frame_out)
{
	if (st->codec >= ARRAY_SIZE(g_ecu_ops))
		return -EINVAL;
	if (!g_ecu_ops[st->codec])
		return -EBUSY;
	return g_ecu_ops[st->codec]->frame_out(st, frame_out);
}

/***********************************************************************
 * low-level API for ECU implementations
 ***********************************************************************/

/*! register an ECU implementation for a given codec */
int osmo_ecu_register(const struct osmo_ecu_ops *ops, enum osmo_ecu_codec codec)
{
	if (codec >= ARRAY_SIZE(g_ecu_ops))
		return -EINVAL;
	if (g_ecu_ops[codec])
		return -EBUSY;

	g_ecu_ops[codec] = ops;

	return 0;
}
