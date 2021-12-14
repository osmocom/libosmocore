/*! \addtogroup gsm0808
 *  @{
 *  \file gsm0808_lcs.h
 *
 * Declarations that depend on both gsm0808.h and bssmap_le.h: LCS related message coding.
 * (This file prevents circular dependency between struct definitions for BSSMAP messages, since BSSMAP references
 * struct lcs_cause and struct bssmap_le_location_type, and BSSMAP-LE references gsm0808_cause.
 */
/*
 * (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/bssmap_le.h>

struct gsm0808_perform_location_request {
	struct bssmap_le_location_type location_type;
	struct osmo_mobile_identity imsi;

	bool more_items; /*!< always set this to false */
};
struct msgb *gsm0808_create_perform_location_request(const struct gsm0808_perform_location_request *params);

struct gsm0808_perform_location_response {
	bool location_estimate_present;
	union gad_raw location_estimate;

	struct lcs_cause_ie lcs_cause;
};
struct msgb *gsm0808_create_perform_location_response(const struct gsm0808_perform_location_response *params);

int gsm0808_enc_lcs_cause(struct msgb *msg, const struct lcs_cause_ie *lcs_cause);
struct msgb *gsm0808_create_perform_location_abort(const struct lcs_cause_ie *lcs_cause);

/*! @} */
