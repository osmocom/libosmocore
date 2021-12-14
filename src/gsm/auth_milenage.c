/*! \file auth_milenage.c
 * GSM/GPRS/3G authentication core infrastructure */
/*
 * (C) 2011 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <osmocom/crypt/auth.h>
#include <osmocom/core/bits.h>
#include "milenage/common.h"
#include "milenage/milenage.h"

/*! \addtogroup auth
 *  @{
 */

static const uint8_t *gen_opc_if_needed(const struct osmo_sub_auth_data *aud, uint8_t *gen_opc)
{
	int rc;

	/* Check if we only know OP and compute OPC if required */
	if (aud->type == OSMO_AUTH_TYPE_UMTS && aud->u.umts.opc_is_op) {
		rc = milenage_opc_gen(gen_opc, aud->u.umts.k, aud->u.umts.opc);
		if (rc < 0)
			return NULL;
		return gen_opc;
	} else
		return aud->u.umts.opc;
}

static int milenage_gen_vec(struct osmo_auth_vector *vec,
			    struct osmo_sub_auth_data *aud,
			    const uint8_t *_rand)
{
	size_t res_len = sizeof(vec->res);
	uint64_t next_sqn;
	uint8_t gen_opc[16];
	const uint8_t *opc;
	uint8_t sqn[6];
	uint64_t ind_mask;
	uint64_t seq_1;
	int rc;

	opc = gen_opc_if_needed(aud, gen_opc);
	if (!opc)
		return -1;

	/* Determine next SQN, according to 3GPP TS 33.102:
	 * SQN consists of SEQ and a lower significant part of IND bits:
	 *
	 * |----------SEQ------------|
	 * |------------------------SQN-----------|
	 *                           |-----IND----|
	 *
	 * The IND part is used as "slots": e.g. a given HLR client will always
	 * get the same IND part, called ind here, with incrementing SEQ. In
	 * the USIM, each IND slot enforces that its SEQ are used in ascending
	 * order -- as long as that constraint is satisfied, the SQN may jump
	 * forwards and backwards. For example, for ind_bitlen == 5, asking the
	 * USIM for SQN = 32, 64, 33 is allowed, because 32 and 64 are
	 * SEQ || (ind == 0), and though 33 is below 64, it is ind == 1 and
	 * allowed.  Not allowed would be 32, 96, 64, because 64 would go
	 * backwards after 96, both being ind == 0.
	 *
	 * From the last used SQN, we want to increment SEQ + 1, and then pick
	 * the matching IND part.
	 *
	 * IND size is suggested in TS 33.102 as 5 bits. SQN is 48 bits long.
	 * If ind_bitlen is passed too large here, the algorithms will break
	 * down. But at which point should we return an error? A sane limit
	 * seems to be ind_bitlen == 10, but to protect against failure,
	 * limiting ind_bitlen to 28 is enough, 28 being the number of bits
	 * suggested for the delta in 33.102, which is discussed to still
	 * require 2^15 > 32000 authentications to wrap the SQN back to the
	 * start.
	 *
	 * Note that if a caller with ind == 1 generates N vectors, the SQN
	 * stored after this will reflect SEQ + N. If then another caller with
	 * ind == 2 generates another N vectors, this will then use SEQ + N
	 * onwards and end up with SEQ + N + N. In other words, most of each
	 * SEQ's IND slots will remain unused. When looking at SQN being 48
	 * bits wide, after dropping ind_bitlen (say 5) from it, we will still
	 * have a sequence range of 2^43 = 8.8e12, eight trillion sequences,
	 * which is large enough to not bother further. With the maximum
	 * ind_bitlen of 28 enforced below, we still get more than 1 million
	 * sequences, which is also sufficiently large.
	 *
	 * An ind_bitlen of zero may be passed from legacy callers that are not
	 * aware of the IND extension. For these, below algorithm works out as
	 * before, simply incrementing SQN by 1.
	 *
	 * This is also a mechanism for tools like the osmo-auc-gen to directly
	 * request a given SQN to be used. With ind_bitlen == 0 the caller can
	 * be sure that this code will increment SQN by exactly one before
	 * generating a tuple, thus a caller would simply pass
	 * { .ind_bitlen = 0, .ind = 0, .sqn = (desired_sqn - 1) }
	 */

	if (aud->u.umts.ind_bitlen > OSMO_MILENAGE_IND_BITLEN_MAX)
		return -2;

	seq_1 = 1LL << aud->u.umts.ind_bitlen;
	ind_mask = ~(seq_1 - 1);

	/* the ind index must not affect the SEQ part */
	if (aud->u.umts.ind >= seq_1)
		return -3;

	/* keep the incremented SQN local until gsm_milenage() succeeded. */
	next_sqn = ((aud->u.umts.sqn + seq_1) & ind_mask) + aud->u.umts.ind;

	osmo_store64be_ext(next_sqn, sqn, 6);
	milenage_generate(opc, aud->u.umts.amf, aud->u.umts.k,
			  sqn, _rand,
			  vec->autn, vec->ik, vec->ck, vec->res, &res_len);
	vec->res_len = res_len;
	rc = gsm_milenage(opc, aud->u.umts.k, _rand, vec->sres, vec->kc);
	if (rc < 0)
		return rc;

	vec->auth_types = OSMO_AUTH_TYPE_UMTS | OSMO_AUTH_TYPE_GSM;

	/* for storage in the caller's AUC database */
	aud->u.umts.sqn = next_sqn;

	return 0;
}

static int milenage_gen_vec_auts(struct osmo_auth_vector *vec,
				 struct osmo_sub_auth_data *aud,
				 const uint8_t *auts, const uint8_t *rand_auts,
				 const uint8_t *_rand)
{
	uint8_t sqn_out[6];
	uint8_t gen_opc[16];
	const uint8_t *opc;
	int rc;

	opc = gen_opc_if_needed(aud, gen_opc);

	rc = milenage_auts(opc, aud->u.umts.k, rand_auts, auts, sqn_out);
	if (rc < 0)
		return rc;

	aud->u.umts.sqn_ms = osmo_load64be_ext(sqn_out, 6) >> 16;
	/* Update our "largest used SQN" from the USIM -- milenage_gen_vec()
	 * below will increment SQN. */
	aud->u.umts.sqn = aud->u.umts.sqn_ms;

	return milenage_gen_vec(vec, aud, _rand);
}

static struct osmo_auth_impl milenage_alg = {
	.algo = OSMO_AUTH_ALG_MILENAGE,
	.name = "MILENAGE (libosmogsm built-in)",
	.priority = 1000,
	.gen_vec = &milenage_gen_vec,
	.gen_vec_auts = &milenage_gen_vec_auts,
};

static __attribute__((constructor)) void on_dso_load_milenage(void)
{
	osmo_auth_register(&milenage_alg);
}

/*! @} */
