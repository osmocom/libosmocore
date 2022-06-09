#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/protocol/gsm_48_049.h>
#include <osmocom/gsm/gsm0808_utils.h>

/* Definitions for parsed / abstract representation of messages in the
 * CBSP (Cell Broadcast Service Protocol, 3GPP TS 48.049).  Data here is *not* formatted
 * like the on-the-wire format.  Any similarities are coincidential ;) */

/* Copyright (C) 2019  Harald Welte <laforge@gnumonks.org>
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

/* Decoded 8.2.3 Message Content */
struct osmo_cbsp_content {
	struct llist_head list;
	uint8_t user_len;
	uint8_t data[82];
};

/* Decoded Entry in a 8.2.6 Cell List */
struct osmo_cbsp_cell_ent {
	struct llist_head list;		/* entry in osmo_cbsp_cell_list.list */
	union gsm0808_cell_id_u cell_id;
};
struct osmo_cbsp_cell_list {
	enum CELL_IDENT id_discr;
	struct llist_head list;		/* list of osmo_cbsp_cell_ent */
};

/* Decoded Entry in a 8.2.10 Completed List */
struct osmo_cbsp_num_compl_ent {
	struct llist_head list;		/* entry in osmo_cbsp_num_compl_list.list */
	union gsm0808_cell_id_u cell_id;
	uint16_t num_compl;
	uint8_t num_bcast_info;
};
struct osmo_cbsp_num_compl_list {
	enum CELL_IDENT id_discr;
	struct llist_head list;		/* list of osmo_cbsp_num_compl_ent */
};

/* Decoded Entry in a 8.2.12 Radio Resource Loading List */
struct osmo_cbsp_loading_ent {
	struct llist_head list;		/* entry in osmo_cbsp_loading_list */
	union gsm0808_cell_id_u cell_id;
	uint8_t load[2];
};
struct osmo_cbsp_loading_list {
	enum CELL_IDENT id_discr;
	struct llist_head list;		/* list of osmo_cbsp_loading_ent */
};

/* Decoded Entry in a 8.2.11 Failure List */
struct osmo_cbsp_fail_ent {
	struct llist_head list;		/* entry in a fail_list below */
	enum CELL_IDENT id_discr;
	union gsm0808_cell_id_u cell_id;
	uint8_t cause;			/* enum osmo_cbsp_cause */
};


/* 8.1.3.1 */
struct osmo_cbsp_write_replace {
	uint16_t msg_id;		/* 8.2.16 M */
	uint16_t new_serial_nr;		/* 8.2.5 M */
	uint16_t *old_serial_nr;	/* 8.2.4 */
	struct osmo_cbsp_cell_list cell_list;

	bool is_cbs;
	union {
		struct {
			enum cbsp_channel_ind channel_ind;
			enum cbsp_category category;
			uint16_t rep_period;
			uint16_t num_bcast_req;
			/* num_of_pages implicit as llist_count(msg_content) */
			uint8_t dcs;
			struct llist_head msg_content;
		} cbs;
		struct {
			uint8_t indicator;
			uint16_t warning_type;
			uint8_t warning_sec_info[50];
			uint32_t warning_period;	/* in seconds; 0xffffffff = unlimited */
		} emergency;
	} u;
};

/* 8.1.3.2 */
struct osmo_cbsp_write_replace_complete {
	uint16_t msg_id;
	uint16_t new_serial_nr;
	uint16_t *old_serial_nr;
	struct osmo_cbsp_num_compl_list num_compl_list;
	struct osmo_cbsp_cell_list cell_list;
	enum cbsp_channel_ind *channel_ind;
};

/* 8.1.3.3 */
struct osmo_cbsp_write_replace_failure {
	uint16_t msg_id;
	uint16_t new_serial_nr;
	uint16_t *old_serial_nr;
	struct llist_head fail_list;		/* list of osmo_cbsp_fail_ent */
	struct osmo_cbsp_num_compl_list num_compl_list;
	struct osmo_cbsp_cell_list cell_list;
	enum cbsp_channel_ind *channel_ind;
};

/* 8.1.3.4 */
struct osmo_cbsp_kill {
	uint16_t msg_id;
	uint16_t old_serial_nr;
	struct osmo_cbsp_cell_list cell_list;
	enum cbsp_channel_ind *channel_ind;
};

/* 8.1.3.5 */
struct osmo_cbsp_kill_complete {
	uint16_t msg_id;
	uint16_t old_serial_nr;
	struct osmo_cbsp_num_compl_list num_compl_list;
	struct osmo_cbsp_cell_list cell_list;
	enum cbsp_channel_ind *channel_ind;
};

/* 8.1.3.6 */
struct osmo_cbsp_kill_failure {
	uint16_t msg_id;
	uint16_t old_serial_nr;
	struct llist_head fail_list;		/* list of osmo_cbsp_fail_ent */
	struct osmo_cbsp_num_compl_list num_compl_list;
	struct osmo_cbsp_cell_list cell_list;
	enum cbsp_channel_ind *channel_ind;
};

/* 8.1.3.7 */
struct osmo_cbsp_load_query {
	struct osmo_cbsp_cell_list cell_list;
	enum cbsp_channel_ind channel_ind;
};

/* 8.1.3.8 */
struct osmo_cbsp_load_query_complete {
	struct osmo_cbsp_loading_list loading_list;
	enum cbsp_channel_ind channel_ind;
};

/* 8.1.3.9 */
struct osmo_cbsp_load_query_failure {
	struct llist_head fail_list;		/* list of osmo_cbsp_fail_ent */
	enum cbsp_channel_ind channel_ind;
	struct osmo_cbsp_loading_list loading_list;
};

/* 8.1.3.10 */
struct osmo_cbsp_msg_status_query {
	uint16_t msg_id;
	uint16_t old_serial_nr;
	struct osmo_cbsp_cell_list cell_list;
	enum cbsp_channel_ind channel_ind;
};

/* 8.1.3.11 */
struct osmo_cbsp_msg_status_query_complete {
	uint16_t msg_id;
	uint16_t old_serial_nr;
	struct osmo_cbsp_num_compl_list num_compl_list;
	enum cbsp_channel_ind channel_ind;
};

/* 8.1.3.12 */
struct osmo_cbsp_msg_status_query_failure {
	uint16_t msg_id;
	uint16_t old_serial_nr;
	struct llist_head fail_list;		/* list of osmo_cbsp_fail_ent */
	enum cbsp_channel_ind channel_ind;
	struct osmo_cbsp_num_compl_list num_compl_list;
};

/* 8.1.3.16 */
struct osmo_cbsp_reset {
	struct osmo_cbsp_cell_list cell_list;
};

/* 8.1.3.17 */
struct osmo_cbsp_reset_complete {
	struct osmo_cbsp_cell_list cell_list;
};

/* 8.1.3.18 */
struct osmo_cbsp_reset_failure {
	struct llist_head fail_list;		/* list of osmo_cbsp_fail_ent */
	struct osmo_cbsp_cell_list cell_list;
};

/* 8.1.3.18a */
struct osmo_cbsp_keep_alive {
	uint8_t repetition_period;
};

/* 8.1.3.18b */
struct osmo_cbsp_keep_alive_complete {
};

/* 8.1.3.19 */
struct osmo_cbsp_restart {
	struct osmo_cbsp_cell_list cell_list;
	uint8_t bcast_msg_type;
	uint8_t recovery_ind;
};

/* 8.1.3.20 */
struct osmo_cbsp_failure {
	struct llist_head fail_list;		/* list of osmo_cbsp_fail_ent */
	uint8_t bcast_msg_type;
};

/* 8.1.3.21 */
struct osmo_cbsp_error_ind {
	enum cbsp_cell_id_cause cause;
	uint16_t *msg_id;
	uint16_t *new_serial_nr;
	uint16_t *old_serial_nr;
	enum cbsp_channel_ind *channel_ind;
};

/* 8.2.13 Cause */
enum osmo_cbsp_cause {
	OSMO_CBSP_CAUSE_PARAM_NOT_RECOGNISED = 0,
	OSMO_CBSP_CAUSE_PARAM_VALUE_INVALID,
	OSMO_CBSP_CAUSE_MSG_REF_NOT_IDENTIFIED,
	OSMO_CBSP_CAUSE_CELL_ID_NOT_VALID,
	OSMO_CBSP_CAUSE_UNRECOGNISED_MESSAGE,
	OSMO_CBSP_CAUSE_MISSING_MANDATORY_ELEMENT,
	OSMO_CBSP_CAUSE_BSC_CAPACITY_EXCEEDED,
	OSMO_CBSP_CAUSE_CELL_MEMORY_EXCEEDED,
	OSMO_CBSP_CAUSE_BSC_MEMORY_EXCEEDED,
	OSMO_CBSP_CAUSE_CELL_BROADCAST_NOT_SUPPORTED,
	OSMO_CBSP_CAUSE_CELL_BROADCAST_NOT_OPERATIONAL,
	OSMO_CBSP_CAUSE_INCOMPATIBLE_DRX_PARAM,
	OSMO_CBSP_CAUSE_EXT_CHAN_NOT_SUPPORTED,
	OSMO_CBSP_CAUSE_MSG_REF_ALREADY_USED,
	OSMO_CBSP_CAUSE_UNSPECIFIED_ERROR,
	OSMO_CBSP_CAUSE_LAI_OR_LAC_NOT_VALID,
};
extern const struct value_string osmo_cbsp_cause_names[];
static inline const char *osmo_cbsp_cause_name(enum osmo_cbsp_cause cause)
{
	return get_value_string(osmo_cbsp_cause_names, cause);
}

/* decoded CBSP message */
struct osmo_cbsp_decoded {
	enum cbsp_msg_type msg_type;
	union {
		struct osmo_cbsp_write_replace write_replace;
		struct osmo_cbsp_write_replace_complete write_replace_compl;
		struct osmo_cbsp_write_replace_failure write_replace_fail;

		struct osmo_cbsp_kill kill;
		struct osmo_cbsp_kill_complete kill_compl;
		struct osmo_cbsp_kill_failure kill_fail;

		struct osmo_cbsp_load_query load_query;
		struct osmo_cbsp_load_query_complete load_query_compl;
		struct osmo_cbsp_load_query_failure load_query_fail;

		struct osmo_cbsp_msg_status_query msg_status_query;
		struct osmo_cbsp_msg_status_query_complete msg_status_query_compl;
		struct osmo_cbsp_msg_status_query_failure msg_status_query_fail;

		/* TODO: set DRX */

		struct osmo_cbsp_reset reset;
		struct osmo_cbsp_reset_complete reset_compl;
		struct osmo_cbsp_reset_failure reset_fail;

		struct osmo_cbsp_restart restart;

		struct osmo_cbsp_failure failure;

		struct osmo_cbsp_error_ind error_ind;

		struct osmo_cbsp_keep_alive keep_alive;
		struct osmo_cbsp_keep_alive_complete keep_alive_compl;
	} u;
};

extern const __thread char *osmo_cbsp_errstr;

struct msgb *osmo_cbsp_msgb_alloc(void *ctx, const char *name);
struct msgb *osmo_cbsp_encode(void *ctx, const struct osmo_cbsp_decoded *in);
struct osmo_cbsp_decoded *osmo_cbsp_decode(void *ctx, struct msgb *in);
void osmo_cbsp_init_struct(struct osmo_cbsp_decoded *cbsp, enum cbsp_msg_type msg_type);
struct osmo_cbsp_decoded *osmo_cbsp_decoded_alloc(void *ctx,  enum cbsp_msg_type msg_type);

int osmo_cbsp_recv_buffered(void *ctx, int fd, struct msgb **rmsg, struct msgb **tmp_msg);
