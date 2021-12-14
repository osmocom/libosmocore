/*! \file auth_xor.c
 * GSM/GPRS/3G authentication core infrastructure */
/*
 * (C) 2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2017 by sysmocom s.f.m.c. GmbH
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

#include <osmocom/core/bit64gen.h>
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

/* 3GPP TS 34.108, section 8.1.2.1 */
static int xor_gen_vec(struct osmo_auth_vector *vec,
		       struct osmo_sub_auth_data *aud,
		       const uint8_t *_rand)
{
	uint8_t xdout[16], cdout[8];
	uint8_t ak[6], xmac[8];
	int i;

	/* Step 1: xdout = (ki or k) ^ rand */
	if (aud->type == OSMO_AUTH_TYPE_GSM)
		xor(xdout, aud->u.gsm.ki, _rand, sizeof(xdout));
	else if (aud->type == OSMO_AUTH_TYPE_UMTS)
		xor(xdout, aud->u.umts.k, _rand, sizeof(xdout));
	else
		return -ENOTSUP;

	/**
	 * Step 2: res = xdout
	 *
	 * Suggested length for res is 128 bits, i.e. 16 bytes,
	 * but also can be in range: 30 < n < 128 bits.
	 */
	memcpy(vec->res, xdout, sizeof(xdout));
	vec->res_len = sizeof(xdout);

	/* ck = xdout[1-15,0] */
	memcpy(vec->ck, xdout + 1, sizeof(xdout) - 1);
	vec->ck[15] = xdout[0];

	/* ik = xdout[2-15,0-1] */
	memcpy(vec->ik, xdout + 2, sizeof(xdout) - 2);
	memcpy(vec->ik + sizeof(xdout) - 2, xdout, 2);

	/* ak = xdout[3-8] */
	memcpy(ak, xdout + 3, sizeof(ak));

	/**
	 * 3GPP TS 33.102, clause 6.8.1.2, b
	 * sres = c2(res) = res[0-3] ^ res[4-7] ^ res[8-11] ^ res[12-15]
	 */
	for (i = 0; i < 4; i++) {
		vec->sres[i]  = vec->res[i] ^ vec->res[i + 4];
		vec->sres[i] ^= vec->res[i + 8] ^ vec->res[i + 12];
	}

	/**
	 * 3GPP TS 33.102, clause 6.8.1.2, c
	 * kc = c3(ck, ik) = ck[0-7] ^ ck[8-15] ^ ik[0-7] ^ ik[8-15]
	 * FIXME: do we really have CK/IK for GSM?
	 */
	osmo_auth_c3(vec->kc, vec->ck, vec->ik);

	/* The further part is UMTS specific */
	if (aud->type != OSMO_AUTH_TYPE_UMTS) {
		vec->auth_types = OSMO_AUTH_TYPE_GSM;
		return 0;
	}

	/**
	 * Step 3: cdout = sqn[0-5] || amf[0-1]
	 * NOTE (for USIM): sqn[0-5] = autn[0-5] ^ ak[0-5]
	 */
	osmo_store64be_ext(aud->u.umts.sqn, cdout, 6);
	memcpy(cdout + 6, aud->u.umts.amf, 2);

	/* Step 4: xmac = xdout[0-8] ^ cdout[0-8] */
	xor(xmac, xdout, cdout, sizeof(xmac));

	/**
	 * Step 5: autn = sqn ^ ak || amf || mac
	 * NOTE: cdout still contains SQN from step 3
	 */
	xor(vec->autn, cdout, ak, sizeof(ak));
	memcpy(vec->autn + 6, aud->u.umts.amf, 2);
	memcpy(vec->autn + 8, xmac, sizeof(xmac));

	vec->auth_types = OSMO_AUTH_TYPE_UMTS | OSMO_AUTH_TYPE_GSM;

	return 0;
}

/* 3GPP TS 34.108, section 8.1.2.2 */
static int xor_gen_vec_auts(struct osmo_auth_vector *vec,
			    struct osmo_sub_auth_data *aud,
			    const uint8_t *auts,
			    const uint8_t *rand_auts,
			    const uint8_t *_rand)
{
	uint8_t xdout[16], cdout[8];
	uint8_t ak[6], xmac[8];
	uint8_t sqnms[6];

	/* Step 1: xdout = (ki or k) ^ rand */
	if (aud->type == OSMO_AUTH_TYPE_GSM)
		xor(xdout, aud->u.gsm.ki, _rand, sizeof(xdout));
	else if (aud->type == OSMO_AUTH_TYPE_UMTS)
		xor(xdout, aud->u.umts.k, _rand, sizeof(xdout));
	else
		return -ENOTSUP;

	/* Step 2: ak = xdout[2-8] */
	memcpy(ak, xdout + 3, 6);

	/* sqnms = auts[0-5] ^ ak[0-5] */
	xor(sqnms, auts, ak, sizeof(ak));

	/* cdout = sqnms || amf* (dummy) */
	memcpy(cdout, sqnms, 6);
	memset(cdout + 6, 0x00, 2);

	/* xmac = xdout[0-7] ^ cdout[0-7] */
	xor(xmac, xdout, cdout, 8);

	/* Compare the last 64 bits of received AUTS with the locally-generated MAC-S */
	if (memcmp(auts + 6, xmac, 8))
		return -1;

	/* Update the "largest used SQN" from the USIM,
	 * milenage_gen_vec() will increment it. */
	aud->u.umts.sqn_ms = osmo_load64be_ext(sqnms, 6) >> 16;
	aud->u.umts.sqn = aud->u.umts.sqn_ms;

	return xor_gen_vec(vec, aud, _rand);
}

static struct osmo_auth_impl xor_alg = {
	.algo = OSMO_AUTH_ALG_XOR,
	.name = "XOR (libosmogsm built-in)",
	.priority = 1000,
	.gen_vec = &xor_gen_vec,
	.gen_vec_auts = &xor_gen_vec_auts,
};

static __attribute__((constructor)) void on_dso_load_xor(void)
{
	osmo_auth_register(&xor_alg);
}

/*! @} */
