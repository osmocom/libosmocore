/*! \file core.c
 * Core routines for SIM/UICC/USIM access. */
/*
 * (C) 2012-2020 by Harald Welte <laforge@gnumonks.org>
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


#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/sim/sim.h>

#include "sim_int.h"

struct osim_decoded_data *osim_file_decode(struct osim_file *file,
					   int len, uint8_t *data)
{
	struct osim_decoded_data *dd;

	if (!file->desc->ops.parse)
		return NULL;

	dd = talloc_zero(file, struct osim_decoded_data);
	if (!dd)
		return NULL;
	dd->file = file;

	if (file->desc->ops.parse(dd, file->desc, len, data) < 0) {
		talloc_free(dd);
		return NULL;
	} else
		return dd;
}

struct msgb *osim_file_encode(const struct osim_file_desc *desc,
				const struct osim_decoded_data *data)
{
	if (!desc->ops.encode)
		return NULL;

	return desc->ops.encode(desc, data);
}

static struct osim_decoded_element *
__element_alloc(void *ctx, const char *name, enum osim_element_type type,
		enum osim_element_repr repr)
{
	struct osim_decoded_element *elem;

	elem = talloc_zero(ctx, struct osim_decoded_element);
	if (!elem)
		return NULL;
	elem->name = name;
	elem->type = type;
	elem->representation = repr;

	if (elem->type == ELEM_T_GROUP)
		INIT_LLIST_HEAD(&elem->u.siblings);

	return elem;
}


struct osim_decoded_element *
element_alloc(struct osim_decoded_data *dd, const char *name,
	      enum osim_element_type type, enum osim_element_repr repr)
{
	struct osim_decoded_element *elem;

	elem = __element_alloc(dd, name, type, repr);
	if (!elem)
		return NULL;

	llist_add_tail(&elem->list, &dd->decoded_elements);

	return elem;
}

struct osim_decoded_element *
element_alloc_sub(struct osim_decoded_element *ee, const char *name,
	      enum osim_element_type type, enum osim_element_repr repr)
{
	struct osim_decoded_element *elem;

	elem = __element_alloc(ee, name, type, repr);
	if (!elem)
		return NULL;

	llist_add(&elem->list, &ee->u.siblings);

	return elem;
}


void add_filedesc(struct osim_file_desc *root, const struct osim_file_desc *in, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		struct osim_file_desc *ofd = talloc_memdup(root, &in[i], sizeof(*in));
		llist_add_tail(&ofd->list, &root->child_list);
	}
}

struct osim_file_desc *alloc_df(void *ctx, uint16_t fid, const char *name)
{
	struct osim_file_desc *mf;

	mf = talloc_zero(ctx, struct osim_file_desc);
	if (!mf)
		return NULL;
	mf->type = TYPE_DF;
	mf->fid = fid;
	mf->short_name = name;
	INIT_LLIST_HEAD(&mf->child_list);

	return mf;
}

struct osim_file_desc *
add_df_with_ef(struct osim_file_desc *parent,
		uint16_t fid, const char *name,
		const struct osim_file_desc *in, int num)
{
	struct osim_file_desc *df;

	df = alloc_df(parent, fid, name);
	if (!df)
		return NULL;
	df->parent = parent;
	llist_add_tail(&df->list, &parent->child_list);
	add_filedesc(df, in, num);

	return df;
}

struct osim_file_desc *
alloc_adf_with_ef(void *ctx,
		const uint8_t *adf_name, uint8_t adf_name_len,
		const char *name, const struct osim_file_desc *in,
		int num)
{
	struct osim_file_desc *df;

	df = alloc_df(ctx, 0xffff, name);
	if (!df)
		return NULL;
	df->type = TYPE_ADF;
	df->df_name = adf_name;
	df->df_name_len = adf_name_len;
	add_filedesc(df, in, num);

	return df;
}

struct osim_file_desc *
osim_file_desc_find_name(struct osim_file_desc *parent, const char *name)
{
	struct osim_file_desc *ofd;
	llist_for_each_entry(ofd, &parent->child_list, list) {
		if (!strcmp(ofd->short_name, name)) {
			return ofd;
		}
	}
	return NULL;
}

struct osim_file_desc *
osim_file_desc_find_aid(struct osim_file_desc *parent, const uint8_t *aid, uint8_t aid_len)
{
	struct osim_file_desc *ofd;
	llist_for_each_entry(ofd, &parent->child_list, list) {
		if (ofd->type != TYPE_ADF)
			continue;
		if (aid_len > ofd->df_name_len)
			continue;
		if (!memcmp(ofd->df_name, aid, aid_len)) {
			return ofd;
		}
	}
	return NULL;
}

struct osim_file_desc *
osim_file_desc_find_fid(struct osim_file_desc *parent, uint16_t fid)
{
	struct osim_file_desc *ofd;
	llist_for_each_entry(ofd, &parent->child_list, list) {
		if (ofd->fid == fid) {
			return ofd;
		}
	}
	return NULL;
}

struct osim_file_desc *
osim_file_desc_find_sfid(struct osim_file_desc *parent, uint8_t sfid)
{
	struct osim_file_desc *ofd;
	llist_for_each_entry(ofd, &parent->child_list, list) {
		if (ofd->sfid == SFI_NONE)
			continue;
		if (ofd->sfid == sfid) {
			return ofd;
		}
	}
	return NULL;
}


/***********************************************************************
 * Application Profiles + Applications
 ***********************************************************************/

static LLIST_HEAD(g_app_profiles);

/*! Register an application profile. Typically called at early start-up. */
void osim_app_profile_register(struct osim_card_app_profile *aprof)
{
	OSMO_ASSERT(!osim_app_profile_find_by_name(aprof->name));
	OSMO_ASSERT(!osim_app_profile_find_by_aid(aprof->aid, aprof->aid_len));
	llist_add_tail(&aprof->list, &g_app_profiles);
}

/*! Find any registered application profile based on its name (e.g. "ADF.USIM") */
const struct osim_card_app_profile *
osim_app_profile_find_by_name(const char *name)
{
	struct osim_card_app_profile *ap;

	llist_for_each_entry(ap, &g_app_profiles, list) {
		if (!strcmp(name, ap->name))
			return ap;
	}
	return NULL;
}

/*! Find any registered application profile based on its AID */
const struct osim_card_app_profile *
osim_app_profile_find_by_aid(const uint8_t *aid, uint8_t aid_len)
{
	struct osim_card_app_profile *ap;

	llist_for_each_entry(ap, &g_app_profiles, list) {
		if (ap->aid_len > aid_len)
			continue;
		if (!memcmp(ap->aid, aid, ap->aid_len))
			return ap;
	}
	return NULL;
}

struct osim_card_app_hdl *
osim_card_hdl_find_app(struct osim_card_hdl *ch, const uint8_t *aid, uint8_t aid_len)
{
	struct osim_card_app_hdl *ah;

	if (aid_len > MAX_AID_LEN)
		return NULL;

	llist_for_each_entry(ah, &ch->apps, list) {
		if (!memcmp(ah->aid, aid, aid_len))
			return ah;
	}
	return NULL;
}

/*! Add an application to a given card */
int osim_card_hdl_add_app(struct osim_card_hdl *ch, const uint8_t *aid, uint8_t aid_len,
			  const char *label)
{
	struct osim_card_app_hdl *ah;

	if (aid_len > MAX_AID_LEN)
		return -EINVAL;

	if (osim_card_hdl_find_app(ch, aid, aid_len))
		return -EEXIST;

	ah = talloc_zero(ch, struct osim_card_app_hdl);
	if (!ah)
		return -ENOMEM;

	memcpy(ah->aid, aid, aid_len);
	ah->aid_len = aid_len;
	ah->prof = osim_app_profile_find_by_aid(ah->aid, ah->aid_len);
	if (label)
		ah->label = talloc_strdup(ah, label);
	llist_add_tail(&ah->list, &ch->apps);
	return 0;
}

/*! Generate an APDU message and initialize APDU command header
 *  \param[in] cla CLASS byte
 *  \param[in] ins INSTRUCTION byte
 *  \param[in] p1 Parameter 1 byte
 *  \param[in] p2 Parameter 2 byte
 *  \param[in] lc number of bytes in the command data field Nc, which will encoded in 0, 1 or 3 bytes into Lc
 *  \param[in] le maximum number of bytes expected in the response data field,  which will encoded in 0, 1, 2 or 3 bytes into Le
 *  \returns an APDU message generated using provided APDU parameters
 * 
 * This function generates an APDU message, as defined in ISO/IEC 7816-4:2005(E) §5.1.
 * The APDU command header, command and response fields lengths are initialized using the parameters.
 * The APDU case is determined by the command and response fields lengths.
 */
struct msgb *osim_new_apdumsg(uint8_t cla, uint8_t ins, uint8_t p1,
			      uint8_t p2, uint16_t lc, uint16_t le)
{
	struct osim_apdu_cmd_hdr *ch;
	struct msgb *msg = msgb_alloc(lc+le+sizeof(*ch)+2, "APDU");
	if (!msg)
		return NULL;

	ch = (struct osim_apdu_cmd_hdr *) msgb_put(msg, sizeof(*ch));
	msg->l2h = (uint8_t *) ch;

	ch->cla = cla;
	ch->ins = ins;
	ch->p1 = p1;
	ch->p2 = p2;

	msgb_apdu_lc(msg) = lc;
	msgb_apdu_le(msg) = le;

	if (lc == 0 && le == 0)
		msgb_apdu_case(msg) = APDU_CASE_1;
	else if (lc == 0 && le >= 1) {
		if (le <= 256)
			msgb_apdu_case(msg) = APDU_CASE_2S;
		else
			msgb_apdu_case(msg) = APDU_CASE_2E;
	} else if (le == 0 && lc >= 1) {
		if (lc <= 255)
			msgb_apdu_case(msg) = APDU_CASE_3S;
		else
			msgb_apdu_case(msg) = APDU_CASE_3E;
	} else if (lc >= 1 && le >= 1) {
		if (lc <= 255 && le <= 256)
			msgb_apdu_case(msg) = APDU_CASE_4S;
		else
			msgb_apdu_case(msg) = APDU_CASE_4E;
	}

	return msg;
}


char *osim_print_sw_buf(char *buf, size_t buf_len, const struct osim_chan_hdl *ch, uint16_t sw_in)
{
	const struct osim_card_sw *csw = NULL;

	if (!ch)
		goto ret_def;

	if (ch->cur_app && ch->cur_app->prof)
		csw = osim_app_profile_find_sw(ch->cur_app->prof, sw_in);

	if (!csw && ch->card->prof)
		csw = osim_cprof_find_sw(ch->card->prof, sw_in);

	if (!csw)
		goto ret_def;

	switch (csw->type) {
	case SW_TYPE_STR:
		snprintf(buf, buf_len, "%04x (%s)", sw_in, csw->u.str);
		break;
	default:
		goto ret_def;
	}

	buf[buf_len-1] = '\0';

	return buf;

ret_def:
	snprintf(buf, buf_len, "%04x (Unknown)", sw_in);
	buf[buf_len-1] = '\0';

	return buf;
}

char *osim_print_sw(const struct osim_chan_hdl *ch, uint16_t sw_in)
{
	static __thread char sw_print_buf[256];
	return osim_print_sw_buf(sw_print_buf, sizeof(sw_print_buf), ch, sw_in);
}

char *osim_print_sw_c(const void *ctx, const struct osim_chan_hdl *ch, uint16_t sw_in)
{
	char *buf = talloc_size(ctx, 256);
	if (!buf)
		return NULL;
	return osim_print_sw_buf(buf, 256, ch, sw_in);
}

/*! Find status word within given card profile */
const struct osim_card_sw *osim_cprof_find_sw(const struct osim_card_profile *cp, uint16_t sw_in)
{
	const struct osim_card_sw **sw_lists = cp->sws;
	const struct osim_card_sw *sw_list, *sw;

	for (sw_list = *sw_lists++; sw_list != NULL; sw_list = *sw_lists++) {
		for (sw = sw_list; sw->code != 0 && sw->mask != 0; sw++) {
			if ((sw_in & sw->mask) == sw->code)
				return sw;
		}
	}
	return NULL;
}

/*! Find application-specific status word within given card application profile */
const struct osim_card_sw *osim_app_profile_find_sw(const struct osim_card_app_profile *ap, uint16_t sw_in)
{
	const struct osim_card_sw *sw_list = ap->sw, *sw;

	for (sw = sw_list; sw->code != 0 && sw->mask != 0; sw++) {
		if ((sw_in & sw->mask) == sw->code)
			return sw;
	}
	return NULL;
}

enum osim_card_sw_class osim_sw_class(const struct osim_chan_hdl *ch, uint16_t sw_in)
{
	const struct osim_card_sw *csw = NULL;

	OSMO_ASSERT(ch);
	OSMO_ASSERT(ch->card);

	if (ch->cur_app && ch->cur_app->prof)
		csw = osim_app_profile_find_sw(ch->cur_app->prof, sw_in);

	if (!csw && ch->card->prof)
		csw = osim_cprof_find_sw(ch->card->prof, sw_in);

	if (!csw)
		return SW_CLS_NONE;

	return csw->class;
}

int default_decode(struct osim_decoded_data *dd,
		   const struct osim_file_desc *desc,
		   int len, uint8_t *data)
{
	struct osim_decoded_element *elem;

	elem = element_alloc(dd, "Unknown Payload", ELEM_T_BYTES, ELEM_REPR_HEX);
	elem->u.buf = talloc_memdup(elem, data, len);

	return 0;
}

int osim_init(void *ctx)
{
	osim_app_profile_register(osim_aprof_usim(ctx));
	osim_app_profile_register(osim_aprof_isim(ctx));
	osim_app_profile_register(osim_aprof_hpsim(ctx));

	return 0;
}
