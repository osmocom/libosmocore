/*
 * (C) 2021 by sysmocom s.f.m.c. GmbH
 *
 * Author: Eric Wild <ewild@sysmocom.de>
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

#include <stdint.h>
#include <string.h>

#include "config.h"
#if (USE_GNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#define HMAC_FUNC(k,lk,s,sl,out) gnutls_hmac_fast(GNUTLS_MAC_SHA256,k,lk,s,sl,out)
#else
#include <osmocom/crypt/kdf.h>
#define HMAC_FUNC(k,lk,s,sl,out) hmac_sha256(k,lk,s,sl,out)
#endif

#include <osmocom/core/bit32gen.h>
#include <osmocom/crypt/kdf.h>

#include "kdf/common.h"
#include "kdf/sha256.h"


#if (USE_GNUTLS)
/* gnutls < 3.3.0 requires global init.
 * gnutls >= 3.3.0 does it automatic.
 * It doesn't hurt calling it twice,
 * as long it's not done at the same time (threads).
 */
__attribute__((constructor))
static void on_dso_load_gnutls(void)
{
	if (!gnutls_check_version("3.3.0"))
		gnutls_global_init();
}

__attribute__((destructor))
static void on_dso_unload_gnutls(void)
{
	if (!gnutls_check_version("3.3.0"))
		gnutls_global_deinit();
}
#endif

/*
 * This file uses the generic key derivation function defined in 3GPP TS 33.220 Annex B
 *
 * The S parameter always consists of concatenated values FC | P0 | L0 | Pi | Li | ...
 * with Pi = Parameter number i and Li = Length of Pi (two octets)
 *
 * FC is either a single octet or two octets 0xff | FC
 * FC values ranges depend on the specification parts that use the KDF,
 * they are defined in 3GPP TS 33.220 Annex B.2.2
 *
 */

/*! \addtogroup kdf
 *  @{
 *  key derivation functions
 *
 * \file kdf.c */

/* 3GPP TS 33.102 B.5 */
void osmo_kdf_kc128(const uint8_t* ck, const uint8_t* ik, uint8_t* kc128) {
	uint8_t k[16*2];
	uint8_t s[1];
	uint8_t out_tmp256[32];
	memcpy (&k[0], ck, 16);
	memcpy (&k[16], ik, 16);

	s[0] = 0x32; // yeah, really just one FC byte..

	HMAC_FUNC(k, 32, s, 1, out_tmp256);
	memcpy(kc128, out_tmp256, 16);
}

/* 3GPP TS 33.401 A.2 */
void osmo_kdf_kasme(const uint8_t *ck, const uint8_t *ik, const uint8_t* plmn_id,
					const uint8_t *sqn,  const uint8_t *ak, uint8_t *kasme)
{
	uint8_t s[14];
	uint8_t k[16*2];
	int i;

	memcpy(&k[0], ck, 16);
	memcpy(&k[16], ik, 16);

	s[0] = 0x10;
	memcpy(&s[1], plmn_id, 3);
	s[4] = 0x00;
	s[5] = 0x03;

	for (i = 0; i < 6; i++)
		s[6+i] = sqn[i] ^ ak[i];
	s[12] = 0x00;
	s[13] = 0x06;

	HMAC_FUNC(k, 32, s, 14, kasme);
}

/* 3GPP TS 33.401 A.3 */
void osmo_kdf_enb(const uint8_t *kasme, uint32_t ul_count, uint8_t *kenb)
{
	uint8_t s[7];

	s[0] = 0x11;
	osmo_store32be(ul_count, &s[1]);
	s[5] = 0x00;
	s[6] = 0x04;

	HMAC_FUNC(kasme, 32, s, 7, kenb);
}

/* 3GPP TS 33.401 A.4 */
void osmo_kdf_nh(const uint8_t *kasme, const uint8_t *sync_input, uint8_t *nh)
{
	uint8_t s[35];

	s[0] = 0x12;
	memcpy(s+1, sync_input, 32);
	s[33] = 0x00;
	s[34] = 0x20;

	HMAC_FUNC(kasme, 32, s, 35, nh);
}

/* 3GPP TS 33.401 A.7 */
void osmo_kdf_nas(uint8_t algo_type, uint8_t algo_id, const uint8_t *kasme, uint8_t *knas)
{
	uint8_t s[7];
	uint8_t out[32];

	s[0] = 0x15;
	s[1] = algo_type;
	s[2] = 0x00;
	s[3] = 0x01;
	s[4] = algo_id;
	s[5] = 0x00;
	s[6] = 0x01;

	HMAC_FUNC(kasme, 32, s, 7, out);
	memcpy(knas, out+16, 16);
}

/*! @} */
