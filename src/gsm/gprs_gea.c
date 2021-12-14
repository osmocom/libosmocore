/*! \file gprs_gea.c
 * GEA 3 & 4 plugin */
/*
 * Copyright (C) 2016 by sysmocom - s.f.m.c. GmbH
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

#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/gsm/gea.h>

#include <stdint.h>

/*! \addtogroup crypto
 *  @{
 */

static struct gprs_cipher_impl gea3_impl = {
	.algo = GPRS_ALGO_GEA3,
	.name = "GEA3 (libosmogsm built-in)",
	.priority = 100,
	.run = &gea3,
};

static struct gprs_cipher_impl gea4_impl = {
	.algo = GPRS_ALGO_GEA4,
	.name = "GEA4 (libosmogsm built-in)",
	.priority = 100,
	.run = &gea4,
};

static __attribute__((constructor)) void on_dso_load_gea(void)
{
	gprs_cipher_register(&gea3_impl);
	gprs_cipher_register(&gea4_impl);
}

/*! @} */
