/*! \file gsm23003.h */

/* (C) 2018 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Harald Welte, Philipp Maier
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

#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/protocol/gsm_29_118.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

/*! 3GPP TS 3GPP TS 29.018 8.14 SGsAP-PAGING-REQUEST. */
struct gsm29118_paging_req {
	char imsi[GSM48_MI_SIZE];
	char vlr_name[SGS_VLR_NAME_MAXLEN + 1];
	uint8_t serv_ind;

	bool lai_present;
	struct osmo_location_area_id lai;
};

/*! 3GPP TS 3GPP TS 29.018 8.15 SGsAP-RESET-ACK and 8.16 SGsAP-RESET-INDICATION. */
struct gsm29118_reset_msg {
	bool vlr_name_present;
	char vlr_name[SGS_VLR_NAME_MAXLEN + 1];
	bool mme_name_present;
	char mme_name[SGS_MME_NAME_LEN + 1];
};

struct msgb *gsm29118_msgb_alloc(void);
struct msgb *gsm29118_create_alert_req(const char *imsi);
struct msgb *gsm29118_create_dl_ud(const char *imsi, struct msgb *nas_msg);
struct msgb *gsm29118_create_eps_det_ack(const char *imsi);
struct msgb *gsm29118_create_imsi_det_ack(const char *imsi);
struct msgb *gsm29118_create_lu_ack(const char *imsi, const struct osmo_location_area_id *lai, const uint8_t *new_id,
				    unsigned int new_id_len);
struct msgb *gsm29118_create_lu_rej(const char *imsi, uint8_t rej_cause, const struct osmo_location_area_id *lai);
struct msgb *gsm29118_create_mm_info_req(const char *imsi, const uint8_t *mm_info, uint8_t mm_info_len);
struct msgb *gsm29118_create_paging_req(struct gsm29118_paging_req *params);
struct msgb *gsm29118_create_reset_ack(struct gsm29118_reset_msg *params);
struct msgb *gsm29118_create_reset_ind(struct gsm29118_reset_msg *params);
struct msgb *gsm29118_create_status(const char *imsi, enum sgsap_sgs_cause cause, const struct msgb *err_msg);
struct msgb *gsm29118_create_release_req(const char *imsi, const uint8_t sgs_cause);
struct msgb *gsm29118_create_service_abort_req(const char *imsi);
