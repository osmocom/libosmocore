/*! \defgroup gsm29205 3GPP TS 29.205
 *  @{
 *  \file gsm29205.h */
/*
 * (C) 2018 by sysmocom - s.f.m.c. GmbH
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

#pragma once

#include <osmocom/core/msgb.h>

#include <stdint.h>

#define OSMO_GCR_MIN_LEN 13

/*! Parsed representation of Global Call Reference, 3GPP TS 29.205 Table B 2.1.9.1. */
struct osmo_gcr_parsed {
	uint8_t net[5];  /** Network ID, ITU-T Q.1902.3 */
	uint8_t net_len; /** length (3-5 octets) of gsm29205_gcr#net */
	uint16_t node;   /** Node ID */
	uint8_t cr[5];   /** Call Reference ID */
};

uint8_t osmo_enc_gcr(struct msgb *msg, const struct osmo_gcr_parsed *g);
int osmo_dec_gcr(struct osmo_gcr_parsed *gcr, const uint8_t *elem, uint8_t len);
bool osmo_gcr_eq(const struct osmo_gcr_parsed *gcr1, const struct osmo_gcr_parsed *gcr2);
