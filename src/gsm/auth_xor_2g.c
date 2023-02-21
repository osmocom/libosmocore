/*! \file auth_xor.c
 * GSM XOR-2G algorithm as specified in Annex 4 (A.4.1.2) of 3GPP TS 51.010-1.
 * This is implemented by typical GSM MS tester */

/*
 * (C) 2023 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * Author: Daniel Willmann <dwillmann@sysmocom.de>
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

#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <osmocom/crypt/auth.h>

/*! \addtogroup auth
 *  @{
 */

static void xor(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		out[i] = a[i] ^ b[i];
}

/* GSM XOR-2G algorithm as specified in Annex 4 (A.4.1.2) of 3GPP TS 51.010-1. */
static int xor2g_gen_vec(struct osmo_auth_vector *vec,
		       struct osmo_sub_auth_data *aud,
		       const uint8_t *_rand)
{
	uint8_t res1[16];

	if (aud->type != OSMO_AUTH_TYPE_GSM)
		return -ENOTSUP;

	/* Step 1: XOR to the challenge RAND, a predefined number Ki, having the same bit length (128 bits) as
	 * RAND. */
	xor(res1, aud->u.gsm.ki, _rand, sizeof(res1));

	/* Step 2: The most significant 32 bits of RES1 form SRES. */
	memcpy(vec->sres, res1, 4);
	/* The next 64 bits of RES1 form Kc */
	memcpy(vec->kc, res1+4, 8);

	vec->auth_types = OSMO_AUTH_TYPE_GSM;
	return 0;
}

static struct osmo_auth_impl xor2g_alg = {
	.algo = OSMO_AUTH_ALG_XOR_2G,
	.name = "XOR-2G (libosmogsm built-in)",
	.priority = 1000,
	.gen_vec = &xor2g_gen_vec,
};

static __attribute__((constructor)) void on_dso_load_xor(void)
{
	osmo_auth_register(&xor2g_alg);
}

/*! @} */
