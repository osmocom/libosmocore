/* (C) 2023 by Harald Welte <laforge@osmocom.org>
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
 */

#include <stdint.h>
#include <string.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/utils.h>

#include "KeccakP-1600-3gpp.h"

/* TUAK authentication algorithm
 * as proposed by 3GPP as an alternative to Milenage
 * algorithm based on SHA-3 (more exactly its KeccakP-1600 permutation)
 * see 3GPP TS 35.231, 232 and 233 */

static unsigned int g_keccak_iterations = 1;
static const char algoname[] = "TUAK1.0";
const uint8_t zero16[16] = { 0, };

void tuak_set_keccak_iterations(unsigned int i)
{
	g_keccak_iterations = i;
}

/* append data from 'input' to 'buf' at 'idx', reversing byte order */
#define PUSH_DATA(buf, idx, input, nbytes)	\
	for (int i = nbytes-1; i >= 0; i--) {	\
		buf[idx++] = input[i];		\
	}

/* like memcpy(), but reversing they order of bytes */
void memcpy_reverse(uint8_t *dst, const uint8_t *src, size_t len)
{
	for (size_t i = 0; i < len; i++)
		dst[i] = src[len-i-1];
}

static void tuak_core(uint8_t buf[200], const uint8_t *opc, uint8_t instance, const uint8_t *_rand,
		      const uint8_t *amf, const uint8_t *sqn, const uint8_t *k, uint8_t k_len_bytes,
		      unsigned int keccac_iterations)
{
	unsigned int idx = 0;

	PUSH_DATA(buf, idx, opc, 32);
	buf[idx++] = instance;
	PUSH_DATA(buf, idx, algoname, strlen(algoname)); /* without trailing NUL */
	PUSH_DATA(buf, idx, _rand, 16);
	PUSH_DATA(buf, idx, amf, 2);
	PUSH_DATA(buf, idx, sqn, 6);
	PUSH_DATA(buf, idx, k, k_len_bytes);
	memset(buf+idx, 0, 32-k_len_bytes); idx += 32-k_len_bytes;
	buf[idx++] = 0x1f;
	memset(buf+idx, 0, 38); idx += 38;
	buf[idx++] = 0x80;
	memset(buf+idx, 0, 64); idx += 64;
	OSMO_ASSERT(idx == 200);

	for (unsigned int i = 0; i < keccac_iterations; i++)
		Keccak_f_64((uint64_t *) buf);
}

/**
 * tuak_f1 - TUAK f1 algorithm
 * @opc: OPc = 256-bit value derived from OP and K
 * @k: K = 128-bit or 256-bit subscriber key
 * @_rand: RAND = 128-bit random challenge
 * @sqn: SQN = 48-bit sequence number
 * @amf: AMF = 16-bit authentication management field
 * @mac_a: Buffer for MAC-A = 64/128/256-bit network authentication code
 * Returns: 0 on success, -1 on failure
 */
int tuak_f1(const uint8_t *opc, const uint8_t *k, uint8_t k_len_bytes, const uint8_t *_rand,
	    const uint8_t *sqn, const uint8_t *amf, uint8_t *mac_a, uint8_t mac_a_len_bytes,
	    unsigned int keccac_iterations)
{
	uint8_t buf[200];
	uint8_t instance = 0x00;

	switch (mac_a_len_bytes) {
	case 8:
		instance |= 0x08;
		break;
	case 16:
		instance |= 0x10;
		break;
	case 32:
		instance |= 0x20;
		break;
	default:
		return -EINVAL;
	}

	switch (k_len_bytes) {
	case 16:
		break;
	case 32:
		instance |= 0x01;
		break;
	default:
		return -EINVAL;
	}

	tuak_core(buf, opc, instance, _rand, amf, sqn, k, k_len_bytes, keccac_iterations);

	memcpy_reverse(mac_a, buf, mac_a_len_bytes);

	return 0;
}

/**
 * tuak_f1star - TUAK f1* algorithm
 * @opc: OPc = 256-bit value derived from OP and K
 * @k: K = 128-bit or 256-bit subscriber key
 * @_rand: RAND = 128-bit random challenge
 * @sqn: SQN = 48-bit sequence number
 * @amf: AMF = 16-bit authentication management field
 * @mac_s: Buffer for MAC-S = 64/128/256-bit resync authentication code
 * Returns: 0 on success, -1 on failure
 */
int tuak_f1star(const uint8_t *opc, const uint8_t *k, uint8_t k_len_bytes, const uint8_t *_rand,
		const uint8_t *sqn, const uint8_t *amf, uint8_t *mac_s, uint8_t mac_s_len_bytes,
		unsigned int keccac_iterations)
{
	uint8_t buf[200];
	uint8_t instance = 0x80;

	switch (mac_s_len_bytes) {
	case 8:
		instance |= 0x08;
		break;
	case 16:
		instance |= 0x10;
		break;
	case 32:
		instance |= 0x20;
		break;
	default:
		return -EINVAL;
	}

	switch (k_len_bytes) {
	case 16:
		break;
	case 32:
		instance |= 0x01;
		break;
	default:
		return -EINVAL;
	}

	tuak_core(buf, opc, instance, _rand, amf, sqn, k, k_len_bytes, keccac_iterations);

	memcpy_reverse(mac_s, buf, mac_s_len_bytes);

	return 0;
}

/**
 * tuak_f2345 - TUAK f2, f3, f4, f5, algorithms
 * @opc: OPc = 256-bit value derived from OP and K
 * @k: K = 128/256-bit subscriber key
 * @_rand: RAND = 128-bit random challenge
 * @res: Buffer for RES = 32/64/128/256-bit signed response (f2), or %NULL
 * @ck: Buffer for CK = 128/256-bit confidentiality key (f3), or %NULL
 * @ik: Buffer for IK = 128/256-bit integrity key (f4), or %NULL
 * @ak: Buffer for AK = 48-bit anonymity key (f5), or %NULL
 * Returns: 0 on success, -1 on failure
 */
int tuak_f2345(const uint8_t *opc, const uint8_t *k, uint8_t k_len_bytes,
	       const uint8_t *_rand, uint8_t *res, uint8_t res_len_bytes,
	       uint8_t *ck, uint8_t ck_len_bytes,
	       uint8_t *ik, uint8_t ik_len_bytes, uint8_t *ak, unsigned int keccac_iterations)
{
	uint8_t buf[200];
	uint8_t instance = 0x40;

	switch (res_len_bytes) {
	case 4:
		break;
	case 8:
		instance |= 0x08;
		break;
	case 16:
		instance |= 0x10;
		break;
	case 32:
		instance |= 0x20;
		break;
	default:
		return -EINVAL;
	}

	switch (ck_len_bytes) {
	case 16:
		break;
	case 32:
		instance |= 0x04;
		break;
	default:
		return -EINVAL;
	}

	switch (ik_len_bytes) {
	case 16:
		break;
	case 32:
		instance |= 0x02;
		break;
	default:
		return -EINVAL;
	}

	switch (k_len_bytes) {
	case 16:
		break;
	case 32:
		instance |= 0x01;
		break;
	default:
		return -EINVAL;
	}

	tuak_core(buf, opc, instance, _rand, zero16, zero16, k, k_len_bytes, keccac_iterations);

	if (res)
		memcpy_reverse(res, buf, res_len_bytes);

	if (ck)
		memcpy_reverse(ck, buf + 32, ck_len_bytes);

	if (ik)
		memcpy_reverse(ik, buf + 64, ik_len_bytes);

	if (ak)
		memcpy_reverse(ak, buf + 96, 6);

	return 0;
}

/**
 * tuak_f5star - TUAK f5* algorithm
 * @opc: OPc = 256-bit value derived from OP and K
 * @k: K = 128/256-bit subscriber key
 * @_rand: RAND = 128-bit random challenge
 * @ak: Buffer for AK = 48-bit anonymity key (f5)
 * Returns: 0 on success, -1 on failure
 */
int tuak_f5star(const uint8_t *opc, const uint8_t *k, uint8_t k_len_bytes,
		const uint8_t *_rand, uint8_t *ak, unsigned int keccac_iterations)
{
	uint8_t buf[200];
	uint8_t instance = 0xc0;

	switch (k_len_bytes) {
	case 16:
		break;
	case 32:
		instance += 1;
		break;
	default:
		return -EINVAL;
	}

	tuak_core(buf, opc, instance, _rand, zero16, zero16, k, k_len_bytes, keccac_iterations);

	memcpy_reverse(ak, buf + 96, 6);

	return 0;
}

/**
 * tuak_generate - Generate AKA AUTN,IK,CK,RES
 * @opc: OPc = 256-bit operator variant algorithm configuration field (encr.)
 * @amf: AMF = 16-bit authentication management field
 * @k: K = 128/256-bit subscriber key
 * @sqn: SQN = 48-bit sequence number
 * @_rand: RAND = 128-bit random challenge
 * @autn: Buffer for AUTN = 128-bit authentication token
 * @ik: Buffer for IK = 128/256-bit integrity key (f4), or %NULL
 * @ck: Buffer for CK = 128/256-bit confidentiality key (f3), or %NULL
 * @res: Buffer for RES = 32/64/128-bit signed response (f2), or %NULL
 * @res_len: Max length for res; set to used length or 0 on failure
 */
void tuak_generate(const uint8_t *opc, const uint8_t *amf, const uint8_t *k, uint8_t k_len_bytes,
		   const uint8_t *sqn, const uint8_t *_rand, uint8_t *autn, uint8_t *ik,
		   uint8_t *ck, uint8_t *res, size_t *res_len)
{
	int i;
	uint8_t mac_a[8], ak[6];

	if (*res_len < 4) {
		*res_len = 0;
		return;
	}
	if (tuak_f1(opc, k, k_len_bytes, _rand, sqn, amf, mac_a, sizeof(mac_a), g_keccak_iterations) ||
	    tuak_f2345(opc, k, k_len_bytes, _rand, res, *res_len, ck, 16, ik, 16, ak, g_keccak_iterations)) {
		*res_len = 0;
		return;
	}

	/* AUTN = (SQN ^ AK) || AMF || MAC */
	for (i = 0; i < 6; i++)
		autn[i] = sqn[i] ^ ak[i];
	memcpy(autn + 6, amf, 2);
	memcpy(autn + 8, mac_a, 8);
}


/**
 * tuak_auts - Milenage AUTS validation
 * @opc: OPc = 256-bit operator variant algorithm configuration field (encr.)
 * @k: K = 128/256-bit subscriber key
 * @_rand: RAND = 128-bit random challenge
 * @auts: AUTS = 112-bit authentication token from client
 * @sqn: Buffer for SQN = 48-bit sequence number
 * Returns: 0 = success (sqn filled), -1 on failure
 */
int tuak_auts(const uint8_t *opc, const uint8_t *k, uint8_t k_len_bytes,
	      const uint8_t *_rand, const uint8_t *auts, uint8_t *sqn)
{
	uint8_t amf[2] = { 0x00, 0x00 }; /* TS 33.102 v7.0.0, 6.3.3 */
	uint8_t ak[6], mac_s[8];
	int i;

	if (tuak_f5star(opc, k, k_len_bytes, _rand, ak, g_keccak_iterations))
		return -1;
	for (i = 0; i < 6; i++)
		sqn[i] = auts[i] ^ ak[i];
	if (tuak_f1star(opc, k, k_len_bytes, _rand, sqn, amf, mac_s, 8, g_keccak_iterations) ||
	    memcmp(mac_s, auts + 6, 8) != 0)
		return -1;
	return 0;
}

int tuak_opc_gen(uint8_t *opc, const uint8_t *k, uint8_t k_len_bytes, const uint8_t *op)
{
	uint8_t buf[200];
	uint8_t instance;

	switch (k_len_bytes) {
	case 16:
		instance = 0x00;
		break;
	case 32:
		instance = 0x01;
		break;
	default:
		return -EINVAL;
	}

	tuak_core(buf, op, instance, zero16, zero16, zero16, k, k_len_bytes, g_keccak_iterations);

	memcpy_reverse(opc, buf, 32);

	return 0;
}
