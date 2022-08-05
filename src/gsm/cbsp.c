/* Cell Broadcast Service Protocol (CBSP, 3GPP TS 48.049): Message encoding, decoding and reception */
/*
 * Copyright (C) 2019  Harald Welte <laforge@gnumonks.org>
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

#include "config.h"

#include <errno.h>

#include <sys/types.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/cbsp.h>
#include <osmocom/gsm/gsm0808_utils.h>

const __thread char *osmo_cbsp_errstr;

struct msgb *osmo_cbsp_msgb_alloc(void *ctx, const char *name)
{
	/* make the messages rather large as the cell lists can be long! */
	return msgb_alloc_headroom_c(ctx, 65535, 16, name);
}

/***********************************************************************
 * IE Encoding
 ***********************************************************************/

/* 8.2.6 Cell List */
static void msgb_put_cbsp_cell_list(struct msgb *msg, const struct osmo_cbsp_cell_list *cl)
{
	const struct osmo_cbsp_cell_ent *ent;
	uint8_t *lenptr;

	/* put tag; reserve space for length; put discriminator */
	msgb_put_u8(msg, CBSP_IEI_CELL_LIST);
	lenptr = msgb_put(msg, sizeof(uint16_t));
	msgb_put_u8(msg, cl->id_discr);
	/* put list elements */
	llist_for_each_entry(ent, &cl->list, list) {
		gsm0808_msgb_put_cell_id_u(msg, cl->id_discr, &ent->cell_id);
	}
	/* update IE length */
	osmo_store16be(msg->tail - (lenptr+2), lenptr);
}

/* 8.2.11 Failure List (discriminator per entry) */
static void msgb_put_cbsp_fail_list(struct msgb *msg, const struct llist_head *fl)
{
	const struct osmo_cbsp_fail_ent *ent;
	uint8_t *lenptr;

	/* put tag; reserve space for length; put discriminator */
	msgb_put_u8(msg, CBSP_IEI_FAILURE_LIST);
	lenptr = msgb_put(msg, sizeof(uint16_t));
	/* put list elements */
	llist_for_each_entry(ent, fl, list) {
		msgb_put_u8(msg, ent->id_discr);
		gsm0808_msgb_put_cell_id_u(msg, ent->id_discr, &ent->cell_id);
		msgb_put_u8(msg, ent->cause);
	}
	/* update IE length */
	osmo_store16be(msg->tail - (lenptr+2), lenptr);
}

/* 8.2.12 Radio Resource Loading List */
static void msgb_put_cbsp_loading_list(struct msgb *msg, const struct osmo_cbsp_loading_list *ll)
{
	const struct osmo_cbsp_loading_ent *ent;
	uint8_t *lenptr;

	/* put tag; reserve space for length; put discriminator */
	msgb_put_u8(msg, CBSP_IEI_RR_LOADING_LIST);
	lenptr = msgb_put(msg, sizeof(uint16_t));
	msgb_put_u8(msg, ll->id_discr);
	/* put list elements */
	llist_for_each_entry(ent, &ll->list, list) {
		gsm0808_msgb_put_cell_id_u(msg, ll->id_discr, &ent->cell_id);
		msgb_put_u8(msg, ent->load[0]);
		msgb_put_u8(msg, ent->load[1]);
	}
	/* update IE length */
	osmo_store16be(msg->tail - (lenptr+2), lenptr);
}

/* 8.2.10 Completed List */
static void msgb_put_cbsp_num_compl_list(struct msgb *msg, const struct osmo_cbsp_num_compl_list *cl)
{
	const struct osmo_cbsp_num_compl_ent *ent;
	uint8_t *lenptr;

	/* put tag; reserve space for length; put discriminator */
	msgb_put_u8(msg, CBSP_IEI_NUM_BCAST_COMPL_LIST);
	lenptr = msgb_put(msg, sizeof(uint16_t));
	msgb_put_u8(msg, cl->id_discr);
	/* put list elements */
	llist_for_each_entry(ent, &cl->list, list) {
		gsm0808_msgb_put_cell_id_u(msg, cl->id_discr, &ent->cell_id);
		msgb_put_u16(msg, ent->num_compl);
		msgb_put_u8(msg, ent->num_bcast_info);
	}
	/* update IE length */
	osmo_store16be(msg->tail - (lenptr+2), lenptr);
}

static int encode_wperiod(uint32_t secs)
{
	if (secs == 0xffffffff)
		return 0; /* infinite */
	if (secs <= 10)
		return secs;
	if (secs <= 30)
		return 10 + (secs-10)/2;
	if (secs <= 120)
		return 30 + (secs-30)/5;
	if (secs <= 600)
		return 120 + (secs-120)/10;
	if (secs <= 60*60)
		return 600 + (secs-600)/30;
	osmo_cbsp_errstr = "warning period out of range";
	return -1;
}

/***********************************************************************
 * Message Encoding
 ***********************************************************************/

/* 8.1.3.1 WRITE REPLACE */
static int cbsp_enc_write_repl(struct msgb *msg, const struct osmo_cbsp_write_replace *in)
{
	msgb_tv16_put(msg, CBSP_IEI_MSG_ID, in->msg_id);
	msgb_tv16_put(msg, CBSP_IEI_NEW_SERIAL_NR, in->new_serial_nr);
	if (in->old_serial_nr)
		msgb_tv16_put(msg, CBSP_IEI_OLD_SERIAL_NR, *in->old_serial_nr);
	msgb_put_cbsp_cell_list(msg, &in->cell_list);
	if (in->is_cbs) {
		int num_of_pages = llist_count(&in->u.cbs.msg_content);
		struct osmo_cbsp_content *ce;
		if (num_of_pages == 0 || num_of_pages > 15) {
			osmo_cbsp_errstr = "invalid number of pages";
			return -EINVAL;
		}
		msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, in->u.cbs.channel_ind);
		msgb_tv_put(msg, CBSP_IEI_CATEGORY, in->u.cbs.category);
		msgb_tv16_put(msg, CBSP_IEI_REP_PERIOD, in->u.cbs.rep_period);
		msgb_tv16_put(msg, CBSP_IEI_NUM_BCAST_REQ, in->u.cbs.num_bcast_req);
		msgb_tv_put(msg, CBSP_IEI_NUM_OF_PAGES, num_of_pages);
		msgb_tv_put(msg, CBSP_IEI_DCS, in->u.cbs.dcs);
		llist_for_each_entry(ce, &in->u.cbs.msg_content, list) {
			uint8_t *out;
			/* cannot use msgb_tlv_put() as 'len' isn't actually the length of
			 * the data field */
			msgb_put_u8(msg, CBSP_IEI_MSG_CONTENT);
			msgb_put_u8(msg, ce->user_len);
			out = msgb_put(msg, sizeof(ce->data));
			memcpy(out, ce->data, sizeof(ce->data));
		}
	} else {
		int wperiod = encode_wperiod(in->u.emergency.warning_period);
		uint8_t *cur;
		if (wperiod < 0)
			return -EINVAL;
		msgb_tv_put(msg, CBSP_IEI_EMERG_IND, in->u.emergency.indicator);
		msgb_tv16_put(msg, CBSP_IEI_WARN_TYPE, in->u.emergency.warning_type);
		/* Tag + fixed length value! */
		msgb_put_u8(msg, CBSP_IEI_WARN_SEC_INFO);
		cur = msgb_put(msg, sizeof(in->u.emergency.warning_sec_info));
		memcpy(cur, in->u.emergency.warning_sec_info, sizeof(in->u.emergency.warning_sec_info));
		msgb_tv_put(msg, CBSP_IEI_WARNING_PERIOD, wperiod);
	}
	return 0;
}

/* 8.1.3.2 WRITE REPLACE COMPLETE*/
static int cbsp_enc_write_repl_compl(struct msgb *msg, const struct osmo_cbsp_write_replace_complete *in)
{
	msgb_tv16_put(msg, CBSP_IEI_MSG_ID, in->msg_id);
	msgb_tv16_put(msg, CBSP_IEI_NEW_SERIAL_NR, in->new_serial_nr);
	if (in->old_serial_nr)
		msgb_tv16_put(msg, CBSP_IEI_OLD_SERIAL_NR, *in->old_serial_nr);

	if (!llist_empty(&in->num_compl_list.list))
		msgb_put_cbsp_num_compl_list(msg, &in->num_compl_list);
	if (!llist_empty(&in->cell_list.list))
		msgb_put_cbsp_cell_list(msg, &in->cell_list);
	if (in->channel_ind)
		msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, *in->channel_ind);
	return 0;
}

/* 8.1.3.3 WRITE REPLACE FAILURE */
static int cbsp_enc_write_repl_fail(struct msgb *msg, const struct osmo_cbsp_write_replace_failure *in)
{
	msgb_tv16_put(msg, CBSP_IEI_MSG_ID, in->msg_id);
	msgb_tv16_put(msg, CBSP_IEI_NEW_SERIAL_NR, in->new_serial_nr);
	if (in->old_serial_nr)
		msgb_tv16_put(msg, CBSP_IEI_OLD_SERIAL_NR, *in->old_serial_nr);

	msgb_put_cbsp_fail_list(msg, &in->fail_list);
	if (!llist_empty(&in->num_compl_list.list))
		msgb_put_cbsp_num_compl_list(msg, &in->num_compl_list);
	if (!llist_empty(&in->cell_list.list))
		msgb_put_cbsp_cell_list(msg, &in->cell_list);
	if (in->channel_ind)
		msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, *in->channel_ind);
	return 0;
}

/* 8.1.3.4 KILL */
static int cbsp_enc_kill(struct msgb *msg, const struct osmo_cbsp_kill *in)
{
	msgb_tv16_put(msg, CBSP_IEI_MSG_ID, in->msg_id);
	msgb_tv16_put(msg, CBSP_IEI_OLD_SERIAL_NR, in->old_serial_nr);
	msgb_put_cbsp_cell_list(msg, &in->cell_list);
	if (in->channel_ind)
		msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, *in->channel_ind);
	return 0;
}

/* 8.1.3.5 KILL COMPLETE */
static int cbsp_enc_kill_compl(struct msgb *msg, const struct osmo_cbsp_kill_complete *in)
{
	msgb_tv16_put(msg, CBSP_IEI_MSG_ID, in->msg_id);
	msgb_tv16_put(msg, CBSP_IEI_OLD_SERIAL_NR, in->old_serial_nr);
	if (!llist_empty(&in->num_compl_list.list))
		msgb_put_cbsp_num_compl_list(msg, &in->num_compl_list);
	if (!llist_empty(&in->cell_list.list))
		msgb_put_cbsp_cell_list(msg, &in->cell_list);
	if (in->channel_ind)
		msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, *in->channel_ind);
	return 0;
}

/* 8.1.3.6 KILL FAILURE */
static int cbsp_enc_kill_fail(struct msgb *msg, const struct osmo_cbsp_kill_failure *in)
{
	msgb_tv16_put(msg, CBSP_IEI_MSG_ID, in->msg_id);
	msgb_tv16_put(msg, CBSP_IEI_OLD_SERIAL_NR, in->old_serial_nr);
	msgb_put_cbsp_fail_list(msg, &in->fail_list);
	if (!llist_empty(&in->num_compl_list.list))
		msgb_put_cbsp_num_compl_list(msg, &in->num_compl_list);
	if (!llist_empty(&in->cell_list.list))
		msgb_put_cbsp_cell_list(msg, &in->cell_list);
	if (in->channel_ind)
		msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, *in->channel_ind);
	return 0;
}

/* 8.1.3.7 LOAD QUERY */
static int cbsp_enc_load_query(struct msgb *msg, const struct osmo_cbsp_load_query *in)
{
	msgb_put_cbsp_cell_list(msg, &in->cell_list);
	msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, in->channel_ind);
	return 0;
}

/* 8.1.3.8 LOAD QUERY COMPLETE */
static int cbsp_enc_load_query_compl(struct msgb *msg, const struct osmo_cbsp_load_query_complete *in)
{
	msgb_put_cbsp_loading_list(msg, &in->loading_list);
	msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, in->channel_ind);
	return 0;
}

/* 8.1.3.9 LOAD QUERY FAILURE */
static int cbsp_enc_load_query_fail(struct msgb *msg, const struct osmo_cbsp_load_query_failure *in)
{
	msgb_put_cbsp_fail_list(msg, &in->fail_list);
	msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, in->channel_ind);
	if (!llist_empty(&in->loading_list.list))
		msgb_put_cbsp_loading_list(msg, &in->loading_list);
	return 0;
}

/* 8.1.3.10 STATUS QUERY */
static int cbsp_enc_msg_status_query(struct msgb *msg, const struct osmo_cbsp_msg_status_query *in)
{
	msgb_tv16_put(msg, CBSP_IEI_MSG_ID, in->msg_id);
	msgb_tv16_put(msg, CBSP_IEI_OLD_SERIAL_NR, in->old_serial_nr);
	msgb_put_cbsp_cell_list(msg, &in->cell_list);
	msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, in->channel_ind);
	return 0;
}

/* 8.1.3.11 STATUS QUERY COMPLETE */
static int cbsp_enc_msg_status_query_compl(struct msgb *msg,
					   const struct osmo_cbsp_msg_status_query_complete *in)
{
	msgb_tv16_put(msg, CBSP_IEI_MSG_ID, in->msg_id);
	msgb_tv16_put(msg, CBSP_IEI_OLD_SERIAL_NR, in->old_serial_nr);
	msgb_put_cbsp_num_compl_list(msg, &in->num_compl_list);
	msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, in->channel_ind);
	return 0;
}

/* 8.1.3.12 STATUS QUERY FAILURE */
static int cbsp_enc_msg_status_query_fail(struct msgb *msg,
					  const struct osmo_cbsp_msg_status_query_failure *in)
{
	msgb_tv16_put(msg, CBSP_IEI_MSG_ID, in->msg_id);
	msgb_tv16_put(msg, CBSP_IEI_OLD_SERIAL_NR, in->old_serial_nr);
	msgb_put_cbsp_fail_list(msg, &in->fail_list);
	msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, in->channel_ind);
	if (!llist_empty(&in->num_compl_list.list))
		msgb_put_cbsp_num_compl_list(msg, &in->num_compl_list);
	return 0;
}

/* 8.1.3.16 RESET */
static int cbsp_enc_reset(struct msgb *msg, const struct osmo_cbsp_reset *in)
{
	msgb_put_cbsp_cell_list(msg, &in->cell_list);
	return 0;
}

/* 8.1.3.17 RESET COMPLETE */
static int cbsp_enc_reset_compl(struct msgb *msg, const struct osmo_cbsp_reset_complete *in)
{
	msgb_put_cbsp_cell_list(msg, &in->cell_list);
	return 0;
}

/* 8.1.3.18 RESET FAILURE */
static int cbsp_enc_reset_fail(struct msgb *msg, const struct osmo_cbsp_reset_failure *in)
{
	msgb_put_cbsp_fail_list(msg, &in->fail_list);
	if (!llist_empty(&in->cell_list.list))
		msgb_put_cbsp_cell_list(msg, &in->cell_list);
	return 0;
}

/* 8.1.3.18a KEEP ALIVE */
static int cbsp_enc_keep_alive(struct msgb *msg, const struct osmo_cbsp_keep_alive *in)
{
	int rperiod = encode_wperiod(in->repetition_period);
	if (in->repetition_period > 120)
		return -EINVAL;
	if (rperiod < 0)
		return -EINVAL;
	msgb_tv_put(msg, CBSP_IEI_KEEP_ALIVE_REP_PERIOD, rperiod);
	return 0;
}

/* 8.1.3.18b KEEP ALIVE COMPLETE */
static int cbsp_enc_keep_alive_compl(struct msgb *msg, const struct osmo_cbsp_keep_alive_complete *in)
{
	return 0;
}

/* 8.1.3.19 RESTART */
static int cbsp_enc_restart(struct msgb *msg, const struct osmo_cbsp_restart *in)
{
	msgb_put_cbsp_cell_list(msg, &in->cell_list);
	msgb_tv_put(msg, CBSP_IEI_BCAST_MSG_TYPE, in->bcast_msg_type);
	msgb_tv_put(msg, CBSP_IEI_RECOVERY_IND, in->recovery_ind);
	return 0;
}

/* 8.1.3.20 FAILURE */
static int cbsp_enc_failure(struct msgb *msg, const struct osmo_cbsp_failure *in)
{
	msgb_put_cbsp_fail_list(msg, &in->fail_list);
	msgb_tv_put(msg, CBSP_IEI_BCAST_MSG_TYPE, in->bcast_msg_type);
	return 0;
}

/* 8.1.3.21 ERROR INDICATION */
static int cbsp_enc_error_ind(struct msgb *msg, const struct osmo_cbsp_error_ind *in)
{
	msgb_tv_put(msg, CBSP_IEI_CAUSE, in->cause);
	if (in->msg_id)
		msgb_tv16_put(msg, CBSP_IEI_MSG_ID, *in->msg_id);
	if (in->new_serial_nr)
		msgb_tv16_put(msg, CBSP_IEI_NEW_SERIAL_NR, *in->new_serial_nr);
	if (in->old_serial_nr)
		msgb_tv16_put(msg, CBSP_IEI_OLD_SERIAL_NR, *in->old_serial_nr);
	if (in->channel_ind)
		msgb_tv_put(msg, CBSP_IEI_CHANNEL_IND, *in->channel_ind);
	return 0;
}

/*! Encode a CBSP message from the decoded/parsed structure representation to binary PDU.
 *  \param[in] ctx talloc context from which to allocate returned msgb.
 *  \param[in] in decoded CBSP message which is to be encoded.  Ownership not transferred.
 *  \return callee-allocated message buffer containing binary CBSP PDU; NULL on error */
struct msgb *osmo_cbsp_encode(void *ctx, const struct osmo_cbsp_decoded *in)
{
	struct msgb *msg = osmo_cbsp_msgb_alloc(ctx, __func__);
	unsigned int len;
	int rc;

	osmo_cbsp_errstr = NULL;

	if (!msg)
		return NULL;

	switch (in->msg_type) {
	case CBSP_MSGT_WRITE_REPLACE:
		rc = cbsp_enc_write_repl(msg, &in->u.write_replace);
		break;
	case CBSP_MSGT_WRITE_REPLACE_COMPL:
		rc = cbsp_enc_write_repl_compl(msg, &in->u.write_replace_compl);
		break;
	case CBSP_MSGT_WRITE_REPLACE_FAIL:
		rc = cbsp_enc_write_repl_fail(msg, &in->u.write_replace_fail);
		break;
	case CBSP_MSGT_KILL:
		rc = cbsp_enc_kill(msg, &in->u.kill);
		break;
	case CBSP_MSGT_KILL_COMPL:
		rc = cbsp_enc_kill_compl(msg, &in->u.kill_compl);
		break;
	case CBSP_MSGT_KILL_FAIL:
		rc = cbsp_enc_kill_fail(msg, &in->u.kill_fail);
		break;
	case CBSP_MSGT_LOAD_QUERY:
		rc = cbsp_enc_load_query(msg, &in->u.load_query);
		break;
	case CBSP_MSGT_LOAD_QUERY_COMPL:
		rc = cbsp_enc_load_query_compl(msg, &in->u.load_query_compl);
		break;
	case CBSP_MSGT_LOAD_QUERY_FAIL:
		rc = cbsp_enc_load_query_fail(msg, &in->u.load_query_fail);
		break;
	case CBSP_MSGT_MSG_STATUS_QUERY:
		rc = cbsp_enc_msg_status_query(msg, &in->u.msg_status_query);
		break;
	case CBSP_MSGT_MSG_STATUS_QUERY_COMPL:
		rc = cbsp_enc_msg_status_query_compl(msg, &in->u.msg_status_query_compl);
		break;
	case CBSP_MSGT_MSG_STATUS_QUERY_FAIL:
		rc = cbsp_enc_msg_status_query_fail(msg, &in->u.msg_status_query_fail);
		break;
	case CBSP_MSGT_RESET:
		rc = cbsp_enc_reset(msg, &in->u.reset);
		break;
	case CBSP_MSGT_RESET_COMPL:
		rc = cbsp_enc_reset_compl(msg, &in->u.reset_compl);
		break;
	case CBSP_MSGT_RESET_FAIL:
		rc = cbsp_enc_reset_fail(msg, &in->u.reset_fail);
		break;
	case CBSP_MSGT_RESTART:
		rc = cbsp_enc_restart(msg, &in->u.restart);
		break;
	case CBSP_MSGT_FAILURE:
		rc = cbsp_enc_failure(msg, &in->u.failure);
		break;
	case CBSP_MSGT_ERROR_IND:
		rc = cbsp_enc_error_ind(msg, &in->u.error_ind);
		break;
	case CBSP_MSGT_KEEP_ALIVE:
		rc = cbsp_enc_keep_alive(msg, &in->u.keep_alive);
		break;
	case CBSP_MSGT_KEEP_ALIVE_COMPL:
		rc = cbsp_enc_keep_alive_compl(msg, &in->u.keep_alive_compl);
		break;
	case CBSP_MSGT_SET_DRX:
	case CBSP_MSGT_SET_DRX_COMPL:
	case CBSP_MSGT_SET_DRX_FAIL:
		osmo_cbsp_errstr = "message type not implemented";
		rc = -1;
		break;
	default:
		osmo_cbsp_errstr = "message type not known in spec";
		rc = -1;
		break;
	}

	if (rc < 0) {
		msgb_free(msg);
		return NULL;
	}

	/* push header in front */
	len = msgb_length(msg);
	msgb_push_u8(msg, len & 0xff);
	msgb_push_u8(msg, (len >> 8) & 0xff);
	msgb_push_u8(msg, (len >> 16) & 0xff);
	msgb_push_u8(msg, in->msg_type);

	return msg;
}

/***********************************************************************
 * IE Decoding
 ***********************************************************************/

/* 8.2.6 Cell List */
static int cbsp_decode_cell_list(struct osmo_cbsp_cell_list *cl, void *ctx,
				 const uint8_t *buf, unsigned int len)
{
	const uint8_t *cur = buf;
	int rc;

	cl->id_discr = *cur++;

	while (cur < buf + len) {
		struct osmo_cbsp_cell_ent *ent = talloc_zero(ctx, struct osmo_cbsp_cell_ent);
		unsigned int len_remain = len - (cur - buf);
		OSMO_ASSERT(ent);
		rc = gsm0808_decode_cell_id_u(&ent->cell_id, cl->id_discr, cur, len_remain);
		if (rc < 0) {
			osmo_cbsp_errstr = "cell list: error decoding cell_id_union";
			return rc;
		}
		cur += gsm0808_cell_id_size(cl->id_discr);
		llist_add_tail(&ent->list, &cl->list);
	}
	return 0;
}

/* 8.2.11 Failure List (discriminator per entry) */
static int cbsp_decode_fail_list(struct llist_head *fl, void *ctx,
				 const uint8_t *buf, unsigned int len)
{
	const uint8_t *cur = buf;
	int rc;

	while (cur < buf + len) {
		struct osmo_cbsp_fail_ent *ent = talloc_zero(ctx, struct osmo_cbsp_fail_ent);
		unsigned int len_remain = len - (cur - buf);
		OSMO_ASSERT(ent);
		ent->id_discr = *cur++;
		rc = gsm0808_decode_cell_id_u(&ent->cell_id, ent->id_discr, cur, len_remain-1);
		if (rc < 0) {
			osmo_cbsp_errstr = "fail list: error decoding cell_id_union";
			return rc;
		}
		cur += gsm0808_cell_id_size(ent->id_discr);
		ent->cause = *cur++;
		llist_add_tail(&ent->list, fl);
	}
	return 0;
}

/* 8.2.12 Radio Resource Loading List */
static int cbsp_decode_loading_list(struct osmo_cbsp_loading_list *ll, void *ctx,
				    const uint8_t *buf, unsigned int len)
{
	const uint8_t *cur = buf;
	int rc;

	ll->id_discr = *cur++;
	while (cur < buf + len) {
		struct osmo_cbsp_loading_ent *ent = talloc_zero(ctx, struct osmo_cbsp_loading_ent);
		unsigned int len_remain = len - (cur - buf);
		OSMO_ASSERT(ent);
		rc = gsm0808_decode_cell_id_u(&ent->cell_id, ll->id_discr, cur, len_remain);
		if (rc < 0) {
			osmo_cbsp_errstr = "load list: error decoding cell_id_union";
			return rc;
		}
		cur += gsm0808_cell_id_size(ll->id_discr);
		if (cur + 2 > buf + len) {
			talloc_free(ent);
			osmo_cbsp_errstr = "load list: truncated IE";
			return -EINVAL;
		}
		ent->load[0] = *cur++;
		ent->load[1] = *cur++;
		llist_add_tail(&ent->list, &ll->list);
	}
	return 0;
}

/* 8.2.10 Completed List */
static int cbsp_decode_num_compl_list(struct osmo_cbsp_num_compl_list *cl, void *ctx,
					const uint8_t *buf, unsigned int len)
{
	const uint8_t *cur = buf;
	int rc;

	cl->id_discr = *cur++;
	while (cur < buf + len) {
		struct osmo_cbsp_num_compl_ent *ent = talloc_zero(ctx, struct osmo_cbsp_num_compl_ent);
		unsigned int len_remain = len - (cur - buf);
		OSMO_ASSERT(ent);
		rc = gsm0808_decode_cell_id_u(&ent->cell_id, cl->id_discr, cur, len_remain);
		if (rc < 0) {
			osmo_cbsp_errstr = "completed list: error decoding cell_id_union";
			return rc;
		}
		cur += gsm0808_cell_id_size(cl->id_discr);
		if (cur + 3 > buf + len) {
			talloc_free(ent);
			osmo_cbsp_errstr = "completed list: truncated IE";
			return -EINVAL;
		}
		ent->num_compl = osmo_load16be(cur); cur += 2;
		ent->num_bcast_info = *cur++;
		llist_add_tail(&ent->list, &cl->list);
	}
	return 0;
}

/* 8.2.25 */
static uint32_t decode_wperiod(uint8_t in)
{
	if (in == 0x00)
		return 0xffffffff; /* infinite */
	if (in <= 10)
		return in;
	if (in <= 20)
		return 10 + (in - 10)*2;
	if (in <= 38)
		return 30 + (in - 20)*5;
	if (in <= 86)
		return 120 + (in - 38)*10;
	if (in <= 186)
		return 600 + (in - 86)*30;
	else
		return 0;
}


/***********************************************************************
 * Message Decoding
 ***********************************************************************/

/* 8.1.3.1 WRITE REPLACE */
static int cbsp_dec_write_repl(struct osmo_cbsp_write_replace *out, const struct tlv_parsed *tp,
				struct msgb *in, void *ctx)
{
	unsigned int i;
	int rc;

	/* check for mandatory IEs */
	if (!TLVP_PRESENT(tp, CBSP_IEI_MSG_ID) ||
	    !TLVP_PRESENT(tp, CBSP_IEI_NEW_SERIAL_NR) ||
	    !TLVP_PRESENT(tp, CBSP_IEI_CELL_LIST)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	out->msg_id = tlvp_val16be(tp, CBSP_IEI_MSG_ID);
	out->new_serial_nr = tlvp_val16be(tp, CBSP_IEI_NEW_SERIAL_NR);
	if (TLVP_PRESENT(tp, CBSP_IEI_OLD_SERIAL_NR)) {
		out->old_serial_nr = talloc(ctx, uint16_t);
		*out->old_serial_nr = tlvp_val16be(tp, CBSP_IEI_OLD_SERIAL_NR);
	}

	INIT_LLIST_HEAD(&out->cell_list.list);
	rc = cbsp_decode_cell_list(&out->cell_list, ctx, TLVP_VAL(tp, CBSP_IEI_CELL_LIST),
				   TLVP_LEN(tp, CBSP_IEI_CELL_LIST));
	if (rc < 0)
		return rc;

	if (TLVP_PRESENT(tp, CBSP_IEI_CHANNEL_IND)) {
		uint8_t num_of_pages;
		INIT_LLIST_HEAD(&out->u.cbs.msg_content);
		if (TLVP_PRESENT(tp, CBSP_IEI_EMERG_IND)) {
			osmo_cbsp_errstr = "missing/short mandatory IE";
			return -EINVAL;
		}
		if (!TLVP_PRESENT(tp, CBSP_IEI_CATEGORY) ||
		    !TLVP_PRESENT(tp, CBSP_IEI_REP_PERIOD) ||
		    !TLVP_PRESENT(tp, CBSP_IEI_NUM_BCAST_REQ) ||
		    !TLVP_PRESENT(tp, CBSP_IEI_NUM_OF_PAGES) ||
		    !TLVP_PRESENT(tp, CBSP_IEI_DCS)) {
			osmo_cbsp_errstr = "missing/short mandatory IE";
			return -EINVAL;
		}
		out->is_cbs = true;
		out->u.cbs.channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);
		out->u.cbs.category = *TLVP_VAL(tp, CBSP_IEI_CATEGORY);
		out->u.cbs.rep_period = tlvp_val16be(tp, CBSP_IEI_REP_PERIOD);
		out->u.cbs.num_bcast_req = tlvp_val16be(tp, CBSP_IEI_NUM_BCAST_REQ);
		out->u.cbs.dcs = *TLVP_VAL(tp, CBSP_IEI_DCS);
		num_of_pages = *TLVP_VAL(tp, CBSP_IEI_NUM_OF_PAGES);
		if (num_of_pages < 1)
			return -EINVAL;
		/* parse pages */
		for (i = 0; i < num_of_pages; i++) {
			const uint8_t *ie = TLVP_VAL(&tp[i], CBSP_IEI_MSG_CONTENT);
			struct osmo_cbsp_content *page;
			if (!ie) {
				osmo_cbsp_errstr = "insufficient message content IEs";
				return -EINVAL;
			}
			page = talloc_zero(ctx, struct osmo_cbsp_content);
			OSMO_ASSERT(page);
			page->user_len = ie[0]; /* length byte before payload */
			memcpy(page->data, ie+1, sizeof(page->data));
			llist_add_tail(&page->list, &out->u.cbs.msg_content);
		}
	} else {
		if (!TLVP_PRES_LEN(tp, CBSP_IEI_EMERG_IND, 1) ||
		    !TLVP_PRES_LEN(tp, CBSP_IEI_WARN_TYPE, 2) ||
		    !TLVP_PRES_LEN(tp, CBSP_IEI_WARN_SEC_INFO, 50) ||
		    !TLVP_PRES_LEN(tp, CBSP_IEI_WARNING_PERIOD, 1)) {
			osmo_cbsp_errstr = "missing/short mandatory IE";
			return -EINVAL;
		}
		out->u.emergency.indicator = *TLVP_VAL(tp, CBSP_IEI_EMERG_IND);
		out->u.emergency.warning_type = tlvp_val16be(tp, CBSP_IEI_WARN_TYPE);
		memcpy(&out->u.emergency.warning_sec_info, TLVP_VAL(tp, CBSP_IEI_WARN_SEC_INFO),
			sizeof(out->u.emergency.warning_sec_info));
		out->u.emergency.warning_period = decode_wperiod(*TLVP_VAL(tp, CBSP_IEI_WARNING_PERIOD));
	}
	return 0;
}

/* 8.1.3.2 WRITE REPLACE COMPLETE*/
static int cbsp_dec_write_repl_compl(struct osmo_cbsp_write_replace_complete *out,
				     const struct tlv_parsed *tp, struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_MSG_ID, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_NEW_SERIAL_NR, 2)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	out->msg_id = tlvp_val16be(tp, CBSP_IEI_MSG_ID);
	out->new_serial_nr = tlvp_val16be(tp, CBSP_IEI_NEW_SERIAL_NR);
	if (TLVP_PRES_LEN(tp, CBSP_IEI_OLD_SERIAL_NR, 2)) {
		out->old_serial_nr = talloc(ctx, uint16_t);
		*out->old_serial_nr = tlvp_val16be(tp, CBSP_IEI_OLD_SERIAL_NR);
	}

	INIT_LLIST_HEAD(&out->num_compl_list.list);
	if (TLVP_PRES_LEN(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST, 7)) {
		rc = cbsp_decode_num_compl_list(&out->num_compl_list, ctx,
						TLVP_VAL(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST),
						TLVP_LEN(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST));
		if (rc < 0)
			return rc;
	}

	INIT_LLIST_HEAD(&out->cell_list.list);
	rc = cbsp_decode_cell_list(&out->cell_list, ctx, TLVP_VAL(tp, CBSP_IEI_CELL_LIST),
				   TLVP_LEN(tp, CBSP_IEI_CELL_LIST));
	if (rc < 0)
		return rc;

	if (TLVP_PRES_LEN(tp, CBSP_IEI_CHANNEL_IND, 1)) {
		out->channel_ind = talloc(ctx, enum cbsp_channel_ind);
		*out->channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);
	}
	return 0;
}

/* 8.1.3.3 WRITE REPLACE FAILURE */
static int cbsp_dec_write_repl_fail(struct osmo_cbsp_write_replace_failure *out,
				    const struct tlv_parsed *tp, struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_MSG_ID, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_NEW_SERIAL_NR, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_FAILURE_LIST, 5)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	out->msg_id = tlvp_val16be(tp, CBSP_IEI_MSG_ID);
	out->new_serial_nr = tlvp_val16be(tp, CBSP_IEI_NEW_SERIAL_NR);
	if (TLVP_PRES_LEN(tp, CBSP_IEI_OLD_SERIAL_NR, 2)) {
		out->old_serial_nr = talloc(ctx, uint16_t);
		*out->old_serial_nr = tlvp_val16be(tp, CBSP_IEI_OLD_SERIAL_NR);
	}

	INIT_LLIST_HEAD(&out->fail_list);
	rc = cbsp_decode_fail_list(&out->fail_list, ctx,
				   TLVP_VAL(tp, CBSP_IEI_FAILURE_LIST),
				   TLVP_LEN(tp, CBSP_IEI_FAILURE_LIST));
	if (rc < 0)
		return rc;

	INIT_LLIST_HEAD(&out->num_compl_list.list);
	if (TLVP_PRES_LEN(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST, 7)) {
		rc = cbsp_decode_num_compl_list(&out->num_compl_list, ctx,
						TLVP_VAL(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST),
						TLVP_LEN(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST));
		if (rc < 0)
			return rc;
	}

	INIT_LLIST_HEAD(&out->cell_list.list);
	if (TLVP_PRES_LEN(tp, CBSP_IEI_CELL_LIST, 1)) {
		rc = cbsp_decode_cell_list(&out->cell_list, ctx, TLVP_VAL(tp, CBSP_IEI_CELL_LIST),
					   TLVP_LEN(tp, CBSP_IEI_CELL_LIST));
		if (rc < 0)
			return rc;
	}

	if (TLVP_PRES_LEN(tp, CBSP_IEI_CHANNEL_IND, 1)) {
		out->channel_ind = talloc(ctx, enum cbsp_channel_ind);
		*out->channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);
	}
	return 0;
}

/* 8.1.3.4 KILL */
static int cbsp_dec_kill(struct osmo_cbsp_kill *out, const struct tlv_parsed *tp,
			 struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_MSG_ID, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_OLD_SERIAL_NR, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_CELL_LIST, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	out->msg_id = tlvp_val16be(tp, CBSP_IEI_MSG_ID);
	out->old_serial_nr = tlvp_val16be(tp, CBSP_IEI_OLD_SERIAL_NR);

	INIT_LLIST_HEAD(&out->cell_list.list);
	rc = cbsp_decode_cell_list(&out->cell_list, ctx, TLVP_VAL(tp, CBSP_IEI_CELL_LIST),
				   TLVP_LEN(tp, CBSP_IEI_CELL_LIST));
	if (rc < 0)
		return rc;

	if (TLVP_PRES_LEN(tp, CBSP_IEI_CHANNEL_IND, 1)) {
		out->channel_ind = talloc(ctx, enum cbsp_channel_ind);
		*out->channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);
	}
	return 0;
}

/* 8.1.3.5 KILL COMPLETE */
static int cbsp_dec_kill_compl(struct osmo_cbsp_kill_complete *out, const struct tlv_parsed *tp,
				struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_MSG_ID, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_OLD_SERIAL_NR, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_CELL_LIST, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	out->msg_id = tlvp_val16be(tp, CBSP_IEI_MSG_ID);
	out->old_serial_nr = tlvp_val16be(tp, CBSP_IEI_OLD_SERIAL_NR);

	INIT_LLIST_HEAD(&out->num_compl_list.list);
	if (TLVP_PRES_LEN(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST, 7)) {
		rc = cbsp_decode_num_compl_list(&out->num_compl_list, ctx,
						TLVP_VAL(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST),
						TLVP_LEN(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST));
		if (rc < 0)
			return rc;
	}

	INIT_LLIST_HEAD(&out->cell_list.list);
	rc = cbsp_decode_cell_list(&out->cell_list, ctx, TLVP_VAL(tp, CBSP_IEI_CELL_LIST),
				   TLVP_LEN(tp, CBSP_IEI_CELL_LIST));
	if (rc < 0)
		return rc;

	if (TLVP_PRES_LEN(tp, CBSP_IEI_CHANNEL_IND, 1)) {
		out->channel_ind = talloc(ctx, enum cbsp_channel_ind);
		*out->channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);
	}
	return 0;
}

/* 8.1.3.6 KILL FAILURE */
static int cbsp_dec_kill_fail(struct osmo_cbsp_kill_failure *out, const struct tlv_parsed *tp,
			      struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_MSG_ID, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_OLD_SERIAL_NR, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_FAILURE_LIST, 5)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	out->msg_id = tlvp_val16be(tp, CBSP_IEI_MSG_ID);
	out->old_serial_nr = tlvp_val16be(tp, CBSP_IEI_OLD_SERIAL_NR);

	INIT_LLIST_HEAD(&out->fail_list);
	rc = cbsp_decode_fail_list(&out->fail_list, ctx,
				   TLVP_VAL(tp, CBSP_IEI_FAILURE_LIST),
				   TLVP_LEN(tp, CBSP_IEI_FAILURE_LIST));
	if (rc < 0)
		return rc;

	INIT_LLIST_HEAD(&out->num_compl_list.list);
	if (TLVP_PRES_LEN(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST, 7)) {
		rc = cbsp_decode_num_compl_list(&out->num_compl_list, ctx,
						TLVP_VAL(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST),
						TLVP_LEN(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST));
		if (rc < 0)
			return rc;
	}

	INIT_LLIST_HEAD(&out->cell_list.list);
	if (TLVP_PRES_LEN(tp, CBSP_IEI_CELL_LIST, 1)) {
		rc = cbsp_decode_cell_list(&out->cell_list, ctx, TLVP_VAL(tp, CBSP_IEI_CELL_LIST),
					   TLVP_LEN(tp, CBSP_IEI_CELL_LIST));
		if (rc < 0)
			return rc;
	}

	if (TLVP_PRES_LEN(tp, CBSP_IEI_CHANNEL_IND, 1)) {
		out->channel_ind = talloc(ctx, enum cbsp_channel_ind);
		*out->channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);
	}
	return 0;
}

/* 8.1.3.7 LOAD QUERY */
static int cbsp_dec_load_query(struct osmo_cbsp_load_query *out, const struct tlv_parsed *tp,
				struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_CELL_LIST, 1) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_CHANNEL_IND, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	INIT_LLIST_HEAD(&out->cell_list.list);
	rc = cbsp_decode_cell_list(&out->cell_list, ctx, TLVP_VAL(tp, CBSP_IEI_CELL_LIST),
				   TLVP_LEN(tp, CBSP_IEI_CELL_LIST));
	if (rc < 0)
		return rc;

	out->channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);
	return 0;
}

/* 8.1.3.8 LOAD QUERY COMPLETE */
static int cbsp_dec_load_query_compl(struct osmo_cbsp_load_query_complete *out,
				     const struct tlv_parsed *tp, struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_RR_LOADING_LIST, 6) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_CHANNEL_IND, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	INIT_LLIST_HEAD(&out->loading_list.list);
	rc = cbsp_decode_loading_list(&out->loading_list, ctx,
				      TLVP_VAL(tp, CBSP_IEI_RR_LOADING_LIST),
				      TLVP_LEN(tp, CBSP_IEI_RR_LOADING_LIST));
	if (rc < 0)
		return rc;

	out->channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);
	return 0;
}

/* 8.1.3.9 LOAD QUERY FAILURE */
static int cbsp_dec_load_query_fail(struct osmo_cbsp_load_query_failure *out,
				    const struct tlv_parsed *tp, struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_FAILURE_LIST, 5) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_CHANNEL_IND, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	INIT_LLIST_HEAD(&out->fail_list);
	rc = cbsp_decode_fail_list(&out->fail_list, ctx,
				   TLVP_VAL(tp, CBSP_IEI_FAILURE_LIST),
				   TLVP_LEN(tp, CBSP_IEI_FAILURE_LIST));
	if (rc < 0)
		return rc;

	out->channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);

	INIT_LLIST_HEAD(&out->loading_list.list);
	if (TLVP_PRES_LEN(tp, CBSP_IEI_RR_LOADING_LIST, 6)) {
		rc = cbsp_decode_loading_list(&out->loading_list, ctx,
					      TLVP_VAL(tp, CBSP_IEI_RR_LOADING_LIST),
					      TLVP_LEN(tp, CBSP_IEI_RR_LOADING_LIST));
	}
	return rc;
}

/* 8.1.3.10 STATUS QUERY */
static int cbsp_dec_msg_status_query(struct osmo_cbsp_msg_status_query *out,
				     const struct tlv_parsed *tp, struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_MSG_ID, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_OLD_SERIAL_NR, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_CELL_LIST, 1) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_CHANNEL_IND, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	out->msg_id = tlvp_val16be(tp, CBSP_IEI_MSG_ID);
	out->old_serial_nr = tlvp_val16be(tp, CBSP_IEI_OLD_SERIAL_NR);

	INIT_LLIST_HEAD(&out->cell_list.list);
	rc = cbsp_decode_cell_list(&out->cell_list, ctx, TLVP_VAL(tp, CBSP_IEI_CELL_LIST),
				   TLVP_LEN(tp, CBSP_IEI_CELL_LIST));
	if (rc < 0)
		return rc;

	out->channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);
	return 0;
}

/* 8.1.3.11 STATUS QUERY COMPLETE */
static int cbsp_dec_msg_status_query_compl(struct osmo_cbsp_msg_status_query_complete *out,
					   const struct tlv_parsed *tp, struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_MSG_ID, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_OLD_SERIAL_NR, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST, 7) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_CHANNEL_IND, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	out->msg_id = tlvp_val16be(tp, CBSP_IEI_MSG_ID);
	out->old_serial_nr = tlvp_val16be(tp, CBSP_IEI_OLD_SERIAL_NR);

	INIT_LLIST_HEAD(&out->num_compl_list.list);
	rc = cbsp_decode_num_compl_list(&out->num_compl_list, ctx,
					TLVP_VAL(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST),
					TLVP_LEN(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST));
	if (rc < 0)
		return rc;
	out->channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);
	return 0;
}

/* 8.1.3.12 STATUS QUERY FAILURE */
static int cbsp_dec_msg_status_query_fail(struct osmo_cbsp_msg_status_query_failure *out,
					  const struct tlv_parsed *tp, struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_MSG_ID, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_OLD_SERIAL_NR, 2) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_FAILURE_LIST, 5) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_CHANNEL_IND, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	out->msg_id = tlvp_val16be(tp, CBSP_IEI_MSG_ID);
	out->old_serial_nr = tlvp_val16be(tp, CBSP_IEI_OLD_SERIAL_NR);

	INIT_LLIST_HEAD(&out->fail_list);
	rc = cbsp_decode_fail_list(&out->fail_list, ctx,
				   TLVP_VAL(tp, CBSP_IEI_FAILURE_LIST),
				   TLVP_LEN(tp, CBSP_IEI_FAILURE_LIST));
	if (rc < 0)
		return rc;

	out->channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);

	INIT_LLIST_HEAD(&out->num_compl_list.list);
	if (TLVP_PRES_LEN(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST, 7)) {
		rc = cbsp_decode_num_compl_list(&out->num_compl_list, ctx,
						TLVP_VAL(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST),
						TLVP_LEN(tp, CBSP_IEI_NUM_BCAST_COMPL_LIST));
		if (rc < 0)
			return rc;
	}
	return 0;
}

/* 8.1.3.16 RESET */
static int cbsp_dec_reset(struct osmo_cbsp_reset *out, const struct tlv_parsed *tp,
			  struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_CELL_LIST, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	INIT_LLIST_HEAD(&out->cell_list.list);
	rc = cbsp_decode_cell_list(&out->cell_list, ctx, TLVP_VAL(tp, CBSP_IEI_CELL_LIST),
				   TLVP_LEN(tp, CBSP_IEI_CELL_LIST));
	if (rc < 0)
		return rc;

	return 0;
}

/* 8.1.3.17 RESET COMPLETE */
static int cbsp_dec_reset_compl(struct osmo_cbsp_reset_complete *out, const struct tlv_parsed *tp,
				struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_CELL_LIST, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	INIT_LLIST_HEAD(&out->cell_list.list);
	rc = cbsp_decode_cell_list(&out->cell_list, ctx, TLVP_VAL(tp, CBSP_IEI_CELL_LIST),
				   TLVP_LEN(tp, CBSP_IEI_CELL_LIST));
	if (rc < 0)
		return rc;

	return 0;
}

/* 8.1.3.18 RESET FAILURE */
static int cbsp_dec_reset_fail(struct osmo_cbsp_reset_failure *out, const struct tlv_parsed *tp,
				struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_FAILURE_LIST, 5)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	INIT_LLIST_HEAD(&out->fail_list);
	rc = cbsp_decode_fail_list(&out->fail_list, ctx,
				   TLVP_VAL(tp, CBSP_IEI_FAILURE_LIST),
				   TLVP_LEN(tp, CBSP_IEI_FAILURE_LIST));
	if (rc < 0)
		return rc;

	INIT_LLIST_HEAD(&out->cell_list.list);
	if (TLVP_PRES_LEN(tp, CBSP_IEI_CELL_LIST, 1)) {
		rc = cbsp_decode_cell_list(&out->cell_list, ctx, TLVP_VAL(tp, CBSP_IEI_CELL_LIST),
					   TLVP_LEN(tp, CBSP_IEI_CELL_LIST));
		if (rc < 0)
			return rc;
	}
	return 0;
}

/* 8.1.3.18a KEEP ALIVE */
static int cbsp_dec_keep_alive(struct osmo_cbsp_keep_alive *out, const struct tlv_parsed *tp,
				struct msgb *in, void *ctx)
{
	uint8_t rperiod;
	if (!TLVP_PRES_LEN(tp, CBSP_IEI_KEEP_ALIVE_REP_PERIOD, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	rperiod = *TLVP_VAL(tp, CBSP_IEI_KEEP_ALIVE_REP_PERIOD);
	out->repetition_period = decode_wperiod(rperiod);
	return 0;
}

/* 8.1.3.18b KEEP ALIVE COMPLETE */
static int cbsp_dec_keep_alive_compl(struct osmo_cbsp_keep_alive_complete *out,
				     const struct tlv_parsed *tp, struct msgb *in, void *ctx)
{
	return 0;
}

/* 8.1.3.19 RESTART */
static int cbsp_dec_restart(struct osmo_cbsp_restart *out, const struct tlv_parsed *tp,
			    struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_CELL_LIST, 1) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_BCAST_MSG_TYPE, 1) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_RECOVERY_IND, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	INIT_LLIST_HEAD(&out->cell_list.list);
	rc = cbsp_decode_cell_list(&out->cell_list, ctx, TLVP_VAL(tp, CBSP_IEI_CELL_LIST),
				   TLVP_LEN(tp, CBSP_IEI_CELL_LIST));
	if (rc < 0)
		return rc;

	out->bcast_msg_type = *TLVP_VAL(tp, CBSP_IEI_BCAST_MSG_TYPE);
	out->recovery_ind = *TLVP_VAL(tp, CBSP_IEI_RECOVERY_IND);
	return 0;
}

/* 8.1.3.20 FAILURE */
static int cbsp_dec_failure(struct osmo_cbsp_failure *out, const struct tlv_parsed *tp,
			    struct msgb *in, void *ctx)
{
	int rc;

	if (!TLVP_PRES_LEN(tp, CBSP_IEI_FAILURE_LIST, 5) ||
	    !TLVP_PRES_LEN(tp, CBSP_IEI_BCAST_MSG_TYPE, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	INIT_LLIST_HEAD(&out->fail_list);
	rc = cbsp_decode_fail_list(&out->fail_list, ctx,
				   TLVP_VAL(tp, CBSP_IEI_FAILURE_LIST),
				   TLVP_LEN(tp, CBSP_IEI_FAILURE_LIST));
	if (rc < 0)
		return rc;

	out->bcast_msg_type = *TLVP_VAL(tp, CBSP_IEI_BCAST_MSG_TYPE);
	return 0;
}

/* 8.1.3.21 ERROR INDICATION */
static int cbsp_dec_error_ind(struct osmo_cbsp_error_ind *out, const struct tlv_parsed *tp,
			      struct msgb *in, void *ctx)
{
	if (!TLVP_PRES_LEN(tp, CBSP_IEI_CAUSE, 1)) {
		osmo_cbsp_errstr = "missing/short mandatory IE";
		return -EINVAL;
	}

	out->cause = *TLVP_VAL(tp, CBSP_IEI_CAUSE);
	if (TLVP_PRES_LEN(tp, CBSP_IEI_MSG_ID, 2)) {
		out->msg_id = talloc(ctx, uint16_t);
		*out->msg_id = tlvp_val16be(tp, CBSP_IEI_MSG_ID);
	}
	if (TLVP_PRES_LEN(tp, CBSP_IEI_NEW_SERIAL_NR, 2)) {
		out->new_serial_nr = talloc(ctx, uint16_t);
		*out->new_serial_nr = tlvp_val16be(tp, CBSP_IEI_NEW_SERIAL_NR);
	}
	if (TLVP_PRES_LEN(tp, CBSP_IEI_OLD_SERIAL_NR, 2)) {
		out->old_serial_nr = talloc(ctx, uint16_t);
		*out->old_serial_nr = tlvp_val16be(tp, CBSP_IEI_OLD_SERIAL_NR);
	}
	if (TLVP_PRES_LEN(tp, CBSP_IEI_CHANNEL_IND, 1)) {
		out->channel_ind = talloc(ctx, enum cbsp_channel_ind);
		*out->channel_ind = *TLVP_VAL(tp, CBSP_IEI_CHANNEL_IND);
	}
	return 0;
}

/*! Decode a CBSP message from wire formwat to pased structure.
 *  \param[in] ctx talloc context from which to allocate decoded output.
 *  \param[in] in message buffer contiaining binary CBSP message.
 *  \returns callee-allocated decoded representation of CBSP message; NULL on error */
struct osmo_cbsp_decoded *osmo_cbsp_decode(void *ctx, struct msgb *in)
{
	OSMO_ASSERT(in->l1h != NULL && in->l2h != NULL);
	struct osmo_cbsp_decoded *out = talloc_zero(ctx, struct osmo_cbsp_decoded);
	const struct cbsp_header *h = msgb_l1(in);
	struct tlv_parsed tp[16]; /* max. number of pages in a given CBS message */
	unsigned int len;
	int rc;

	osmo_cbsp_errstr = NULL;

	if (!out)
		return NULL;

	if (msgb_l1len(in) < sizeof(*h)) {
		goto out_err;
	}
	len = h->len[0] << 16 | h->len[1] << 8 | h->len[2];

	/* discard messages where indicated length is more than we have */
	if (len > msgb_l2len(in)) {
		goto out_err;
	}

	/* trim any messages with extra payload at the end */
	if (len < msgb_l2len(in))
		msgb_trim(in, (in->l2h - in->data) + msgb_l2len(in));
	out->msg_type = h->msg_type;

	rc = tlv_parse2(tp, ARRAY_SIZE(tp), &cbsp_att_tlvdef, msgb_l2(in), msgb_l2len(in), 0, 0);
	if (rc < 0) {
		goto out_err;
	}

	switch (h->msg_type) {
	case CBSP_MSGT_WRITE_REPLACE:
		rc = cbsp_dec_write_repl(&out->u.write_replace, tp, in, out);
		break;
	case CBSP_MSGT_WRITE_REPLACE_COMPL:
		rc = cbsp_dec_write_repl_compl(&out->u.write_replace_compl, tp, in, out);
		break;
	case CBSP_MSGT_WRITE_REPLACE_FAIL:
		rc = cbsp_dec_write_repl_fail(&out->u.write_replace_fail, tp, in, out);
		break;
	case CBSP_MSGT_KILL:
		rc = cbsp_dec_kill(&out->u.kill, tp, in, out);
		break;
	case CBSP_MSGT_KILL_COMPL:
		rc = cbsp_dec_kill_compl(&out->u.kill_compl, tp, in, out);
		break;
	case CBSP_MSGT_KILL_FAIL:
		rc = cbsp_dec_kill_fail(&out->u.kill_fail, tp, in, out);
		break;
	case CBSP_MSGT_LOAD_QUERY:
		rc = cbsp_dec_load_query(&out->u.load_query, tp, in, out);
		break;
	case CBSP_MSGT_LOAD_QUERY_COMPL:
		rc = cbsp_dec_load_query_compl(&out->u.load_query_compl, tp, in, out);
		break;
	case CBSP_MSGT_LOAD_QUERY_FAIL:
		rc = cbsp_dec_load_query_fail(&out->u.load_query_fail, tp, in, out);
		break;
	case CBSP_MSGT_MSG_STATUS_QUERY:
		rc = cbsp_dec_msg_status_query(&out->u.msg_status_query, tp, in, out);
		break;
	case CBSP_MSGT_MSG_STATUS_QUERY_COMPL:
		rc = cbsp_dec_msg_status_query_compl(&out->u.msg_status_query_compl, tp, in, out);
		break;
	case CBSP_MSGT_MSG_STATUS_QUERY_FAIL:
		rc = cbsp_dec_msg_status_query_fail(&out->u.msg_status_query_fail, tp, in, out);
		break;
	case CBSP_MSGT_RESET:
		rc = cbsp_dec_reset(&out->u.reset, tp, in, out);
		break;
	case CBSP_MSGT_RESET_COMPL:
		rc = cbsp_dec_reset_compl(&out->u.reset_compl, tp, in, out);
		break;
	case CBSP_MSGT_RESET_FAIL:
		rc = cbsp_dec_reset_fail(&out->u.reset_fail, tp, in, out);
		break;
	case CBSP_MSGT_RESTART:
		rc = cbsp_dec_restart(&out->u.restart, tp, in, out);
		break;
	case CBSP_MSGT_FAILURE:
		rc = cbsp_dec_failure(&out->u.failure, tp, in, out);
		break;
	case CBSP_MSGT_ERROR_IND:
		rc = cbsp_dec_error_ind(&out->u.error_ind, tp, in, out);
		break;
	case CBSP_MSGT_KEEP_ALIVE:
		rc = cbsp_dec_keep_alive(&out->u.keep_alive, tp, in, out);
		break;
	case CBSP_MSGT_KEEP_ALIVE_COMPL:
		rc = cbsp_dec_keep_alive_compl(&out->u.keep_alive_compl, tp, in, out);
		break;
	case CBSP_MSGT_SET_DRX:
	case CBSP_MSGT_SET_DRX_COMPL:
	case CBSP_MSGT_SET_DRX_FAIL:
		osmo_cbsp_errstr = "message type not implemented";
		rc = -1;
		break;
	default:
		osmo_cbsp_errstr = "message type not known in spec";
		rc = -1;
		break;
	}

	if (rc < 0) {
		goto out_err;
	}

	return out;

out_err:
	talloc_free(out);
	return NULL;
}

/* initialization of 'decoded' structure of given message type */
void osmo_cbsp_init_struct(struct osmo_cbsp_decoded *cbsp, enum cbsp_msg_type msg_type)
{
	memset(cbsp, 0, sizeof(*cbsp));
	cbsp->msg_type = msg_type;

	switch (msg_type) {
	case CBSP_MSGT_WRITE_REPLACE:
		INIT_LLIST_HEAD(&cbsp->u.write_replace.cell_list.list);
		break;
	case CBSP_MSGT_WRITE_REPLACE_COMPL:
		INIT_LLIST_HEAD(&cbsp->u.write_replace_compl.num_compl_list.list);
		INIT_LLIST_HEAD(&cbsp->u.write_replace_compl.cell_list.list);
		break;
	case CBSP_MSGT_WRITE_REPLACE_FAIL:
		INIT_LLIST_HEAD(&cbsp->u.write_replace_fail.fail_list);
		INIT_LLIST_HEAD(&cbsp->u.write_replace_fail.num_compl_list.list);
		INIT_LLIST_HEAD(&cbsp->u.write_replace_fail.cell_list.list);
		break;
	case CBSP_MSGT_KILL:
		INIT_LLIST_HEAD(&cbsp->u.kill.cell_list.list);
		break;
	case CBSP_MSGT_KILL_COMPL:
		INIT_LLIST_HEAD(&cbsp->u.kill_compl.num_compl_list.list);
		INIT_LLIST_HEAD(&cbsp->u.kill_compl.cell_list.list);
		break;
	case CBSP_MSGT_KILL_FAIL:
		INIT_LLIST_HEAD(&cbsp->u.kill_fail.fail_list);
		INIT_LLIST_HEAD(&cbsp->u.kill_fail.num_compl_list.list);
		INIT_LLIST_HEAD(&cbsp->u.kill_fail.cell_list.list);
		break;
	case CBSP_MSGT_LOAD_QUERY:
		INIT_LLIST_HEAD(&cbsp->u.load_query.cell_list.list);
		break;
	case CBSP_MSGT_LOAD_QUERY_COMPL:
		INIT_LLIST_HEAD(&cbsp->u.load_query_compl.loading_list.list);
		break;
	case CBSP_MSGT_LOAD_QUERY_FAIL:
		INIT_LLIST_HEAD(&cbsp->u.load_query_fail.fail_list);
		break;
	case CBSP_MSGT_MSG_STATUS_QUERY:
		INIT_LLIST_HEAD(&cbsp->u.msg_status_query.cell_list.list);
		break;
	case CBSP_MSGT_MSG_STATUS_QUERY_COMPL:
		INIT_LLIST_HEAD(&cbsp->u.msg_status_query_compl.num_compl_list.list);
		break;
	case CBSP_MSGT_MSG_STATUS_QUERY_FAIL:
		INIT_LLIST_HEAD(&cbsp->u.msg_status_query_fail.fail_list);
		INIT_LLIST_HEAD(&cbsp->u.msg_status_query_fail.num_compl_list.list);
		break;
	case CBSP_MSGT_RESET:
		INIT_LLIST_HEAD(&cbsp->u.reset.cell_list.list);
		break;
	case CBSP_MSGT_RESET_COMPL:
		INIT_LLIST_HEAD(&cbsp->u.reset_compl.cell_list.list);
		break;
	case CBSP_MSGT_RESET_FAIL:
		INIT_LLIST_HEAD(&cbsp->u.reset_fail.fail_list);
		INIT_LLIST_HEAD(&cbsp->u.reset_fail.cell_list.list);
		break;
	case CBSP_MSGT_RESTART:
		INIT_LLIST_HEAD(&cbsp->u.restart.cell_list.list);
		break;
	case CBSP_MSGT_FAILURE:
		INIT_LLIST_HEAD(&cbsp->u.failure.fail_list);
		break;
	default:
		break;
	}
}

/*! Dynamically allocate and initialize decoded CBSP structure.
 *  \param[in] ctx talloc context from which to allocate
 *  \param[in] msg_type CBSP message type for which to initialize result
 *  \returns allocated + initialized decoded CBSP structure; NULL on talloc failure */
struct osmo_cbsp_decoded *osmo_cbsp_decoded_alloc(void *ctx,  enum cbsp_msg_type msg_type)
{
	struct osmo_cbsp_decoded *cbsp = talloc_zero(ctx, struct osmo_cbsp_decoded);
	if (!cbsp)
		return NULL;
	osmo_cbsp_init_struct(cbsp, msg_type);
	return cbsp;
}

/***********************************************************************
 * Message Reception
 ***********************************************************************/

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>

/*! Read one CBSP message from socket fd or store part if still not fully received.
 *  \param[in] ctx talloc context from which to allocate new msgb.
 *  \param[in] fd The fd for the socket to read from.
 *  \param[out] rmsg internally allocated msgb containing a fully received CBSP message.
 *  \param[inout] tmp_msg internally allocated msgb caching data for not yet fully received message.
 *
 *  Function is designed just like ipa_msg_recv_buffered()
 */
int osmo_cbsp_recv_buffered(void *ctx, int fd, struct msgb **rmsg, struct msgb **tmp_msg)
{
	struct msgb *msg = tmp_msg ? *tmp_msg : NULL;
	struct cbsp_header *h;
	int len, rc;
	int needed;

	if (!msg) {
		msg = osmo_cbsp_msgb_alloc(ctx, __func__);
		if (!msg)
			return -ENOMEM;
		msg->l1h = msg->tail;
	}

	if (msg->l2h == NULL) {
		/* first read the [missing part of the] header */
		needed = sizeof(*h) - msg->len;
		rc = recv(fd, msg->tail, needed, 0);
		if (rc == 0)
			goto discard_msg;
		else if (rc < 0) {
			if (errno == EAGAIN || errno == EINTR)
				rc = 0;
			else {
				rc = -errno;
				goto discard_msg;
			}
		}
		msgb_put(msg, rc);
		if (rc < needed) {
			if (msg->len == 0) {
				rc = -EAGAIN;
				goto discard_msg;
			}

			if (!tmp_msg) {
				rc = -EIO;
				goto discard_msg;
			}
			*tmp_msg = msg;
			return -EAGAIN;
		}
		msg->l2h = msg->tail;
	}

	h = (struct cbsp_header *) msg->data;
	/* then read the length as specified in the header */
	len = h->len[0] << 16 | h->len[1] << 8 | h->len[2];

	needed = len - msgb_l2len(msg);
	if (needed > 0) {
		if (needed > msgb_tailroom(msg)) {
			rc = -ENOMEM;
			goto discard_msg;
		}
		rc = recv(fd, msg->tail, needed, 0);
		if (rc == 0)
			goto discard_msg;
		else if (rc < 0) {
			if (errno == EAGAIN || errno == EINTR)
				rc = 0;
			else {
				rc = -errno;
				goto discard_msg;
			}
		}
		msgb_put(msg, rc);
		/* still not all of payload received? */
		if (rc < needed) {
			if (!tmp_msg) {
				rc = -EIO;
				goto discard_msg;
			}
			*tmp_msg = msg;
			return -EAGAIN;
		}
	}
	/* else: complete message received */
	rc = msgb_length(msg);
	if (tmp_msg)
		*tmp_msg = NULL;
	*rmsg = msg;
	return rc;

discard_msg:
	if (tmp_msg)
		*tmp_msg = NULL;
	msgb_free(msg);
	return rc;
}

/*! value_string[] for enum osmo_cbsp_cause. */
const struct value_string osmo_cbsp_cause_names[] = {
	{ OSMO_CBSP_CAUSE_PARAM_NOT_RECOGNISED, "Parameter-not-recognised" },
	{ OSMO_CBSP_CAUSE_PARAM_VALUE_INVALID, "Parameter-value-invalid" },
	{ OSMO_CBSP_CAUSE_MSG_REF_NOT_IDENTIFIED, "Message-reference-not-identified" },
	{ OSMO_CBSP_CAUSE_CELL_ID_NOT_VALID, "Cell-identity-not-valid" },
	{ OSMO_CBSP_CAUSE_UNRECOGNISED_MESSAGE, "Unrecognised-message" },
	{ OSMO_CBSP_CAUSE_MISSING_MANDATORY_ELEMENT, "Missing-mandatory-element" },
	{ OSMO_CBSP_CAUSE_BSC_CAPACITY_EXCEEDED, "BSC-capacity-exceeded" },
	{ OSMO_CBSP_CAUSE_CELL_MEMORY_EXCEEDED, "Cell-memory-exceeded" },
	{ OSMO_CBSP_CAUSE_BSC_MEMORY_EXCEEDED, "BSC-memory-exceeded" },
	{ OSMO_CBSP_CAUSE_CELL_BROADCAST_NOT_SUPPORTED, "Cell-broadcast-not-supported" },
	{ OSMO_CBSP_CAUSE_CELL_BROADCAST_NOT_OPERATIONAL, "Cell-broadcast-not-operational" },
	{ OSMO_CBSP_CAUSE_INCOMPATIBLE_DRX_PARAM, "Incompatible-DRX-parameter:"},
	{ OSMO_CBSP_CAUSE_EXT_CHAN_NOT_SUPPORTED, "Extended-channel-not-supported"},
	{ OSMO_CBSP_CAUSE_MSG_REF_ALREADY_USED, "Message-reference-already-used"},
	{ OSMO_CBSP_CAUSE_UNSPECIFIED_ERROR, "Unspecified-error"},
	{ OSMO_CBSP_CAUSE_LAI_OR_LAC_NOT_VALID, "LAI-or-LAC-not-valid"},
	{ 0, NULL }
};

#endif /* HAVE_SYS_SOCKET_H */
