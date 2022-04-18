/*! \file utils.c
 * Utility routines for printing common objects in the Osmocom world. */
/*
 * (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2013,2015 by sysmocom - s.f.m.c. GmbH
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
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/counter.h>

#include <osmocom/vty/vty.h>

/*! \addtogroup rate_ctr
 *  @{
 */

struct vty_out_context {
	struct vty *vty;
	const char *prefix;
	int max_level;
	bool skip_zero;
};

static int rate_ctr_handler(
	struct rate_ctr_group *ctrg, struct rate_ctr *ctr,
	const struct rate_ctr_desc *desc, void *vctx_)
{
	struct vty_out_context *vctx = vctx_;
	struct vty *vty = vctx->vty;

	if (vctx->skip_zero && ctr->current == 0)
		return 0;

	vty_out(vty, " %s%s: %8" PRIu64 " "
		"(%" PRIu64 "/s %" PRIu64 "/m %" PRIu64 "/h %" PRIu64 "/d)%s",
		vctx->prefix, desc->description, ctr->current,
		ctr->intv[RATE_CTR_INTV_SEC].rate,
		ctr->intv[RATE_CTR_INTV_MIN].rate,
		ctr->intv[RATE_CTR_INTV_HOUR].rate,
		ctr->intv[RATE_CTR_INTV_DAY].rate,
		VTY_NEWLINE);

	return 0;
}

/*! print a rate counter group to given VTY
 *  \param[in] vty The VTY to which it should be printed
 *  \param[in] prefix Any additional log prefix ahead of each line
 *  \param[in] ctrg Rate counter group to be printed
 *  \param[in] skip_zero Skip all zero-valued counters
 */
void vty_out_rate_ctr_group2(struct vty *vty, const char *prefix,
			     struct rate_ctr_group *ctrg, bool skip_zero)
{
	struct vty_out_context vctx = {vty, prefix, 0, skip_zero};

	vty_out(vty, "%s%s:%s", prefix, ctrg->desc->group_description, VTY_NEWLINE);

	rate_ctr_for_each_counter(ctrg, rate_ctr_handler, &vctx);
}

void vty_out_rate_ctr_group(struct vty *vty, const char *prefix,
			   struct rate_ctr_group *ctrg)
{
	vty_out_rate_ctr_group2(vty, prefix, ctrg, false);
}

static char *
pad_append_str(char *s, const char *a, int minwidth)
{
	s = talloc_asprintf_append(s, "%*s", minwidth, a);
	OSMO_ASSERT(s);
	return s;
}

static char *
pad_append_ctr(char *s, uint64_t ctr, int minwidth)
{
	s = talloc_asprintf_append(s, "%*" PRIu64, minwidth, ctr);
	OSMO_ASSERT(s);
	return s;
}

static int rate_ctr_handler_fmt(
	struct rate_ctr_group *ctrg, struct rate_ctr *ctr,
	const struct rate_ctr_desc *desc, void *vctx_)
{
	struct vty_out_context *vctx = vctx_;
	struct vty *vty = vctx->vty;
	const char *fmt = vctx->prefix;
	char *s;

	if (vctx->skip_zero && ctr->current == 0)
		return 0;

	s = talloc_strdup(vty, "");
	OSMO_ASSERT(s);

	while (*fmt) {
		int ch, minwidth = 0, sign = 1;
		char *p = strchr(fmt, '%');

		if (p == NULL) {
			/* No further % directives in format string. Copy rest verbatim and exit. */
			s = talloc_strdup_append_buffer(s, fmt);
			OSMO_ASSERT(s);
			break;
		} else {
			ptrdiff_t len;

			OSMO_ASSERT(p >= fmt);
			len = p - fmt;
			if (len) {
				/* Copy bytes verbatim until next '%' byte. */
				s = talloc_strndup_append_buffer(s, fmt, len);
				OSMO_ASSERT(s);
			}
			fmt = (const char *)(p + 1); /* skip past '%' */
			if (*fmt == '\0')
				break;
		}

		ch = *fmt++;
		if (ch == '-' && isdigit(*fmt)) {
			sign = -1;
			ch = *fmt++;
		}
		while (isdigit(ch) && *fmt != '\0') {
			minwidth *= 10;
			minwidth += (ch - '0');
			ch = *fmt++;
		}
		minwidth *= sign;

		switch (ch) {
		case '%':
			s = talloc_asprintf_append(s, "%c", ch);
			OSMO_ASSERT(s);
			break;
		case 'd':
			s = pad_append_str(s, desc->description, minwidth);
			break;
		case 'n':
			s = pad_append_str(s, desc->name, minwidth);
			break;
		case 'c':
			s = pad_append_ctr(s, ctr->current, minwidth);
			break;
		case 'p':
			s = pad_append_ctr(s, ctr->previous, minwidth);
			break;
		case 'S':
			s = pad_append_ctr(s, ctr->intv[RATE_CTR_INTV_SEC].rate, minwidth);
			break;
		case 'M':
			s = pad_append_ctr(s, ctr->intv[RATE_CTR_INTV_MIN].rate, minwidth);
			break;
		case 'H':
			s = pad_append_ctr(s, ctr->intv[RATE_CTR_INTV_HOUR].rate, minwidth);
			break;
		case 'D':
			s = pad_append_ctr(s, ctr->intv[RATE_CTR_INTV_DAY].rate, minwidth);
			break;
		default:
			break;
		}
	}

	vty_out(vty, "%s%s", s, VTY_NEWLINE);
	talloc_free(s);

	return 0;
}

/*! print a rate counter group to given VTY, formatting the line for each counter according to a format string.
 *
 * The following format string directives are supported:
 * - %d: The description of the counter
 * - %n: The name of the counter
 * - %c: The current value of the counter
 * - %p: The previous value of the counter
 * - %S: The interval of the counter in seconds
 * - %M: The interval of the counter in minutes
 * - %H: The interval of the counter in hours
 * - %D: The interval of the counter in days
 * - %%: Print a literal %.
 *
 * An optional number between % and the letter in a format directive may be used to set a minimum field width.
 * If the expanded format directive is smaller than this width (according to strlen()) the string will be
 * left-padded (if the number is positive) or right-padded (if the number is negative) with spaces.
 * For example, "%25n" prints the counter name left-padded up to a minimum width of 25 columns.
 *
 * VTY_NEWLINE will be appended to the format string when it is printed.
 *
 *  \param[in] vty The VTY to which it should be printed
 *  \param[in] ctrg Rate counter group to be printed
 *  \param[in] fmt A format which may contain the above directives.
 *  \param[in] skip_zero Skip all zero-valued counters
 */
void vty_out_rate_ctr_group_fmt2(struct vty *vty, const char *fmt,
				 struct rate_ctr_group *ctrg, bool skip_zero)
{
	struct vty_out_context vctx = {vty, fmt, 0, skip_zero};
	rate_ctr_for_each_counter(ctrg, rate_ctr_handler_fmt, &vctx);
}

void vty_out_rate_ctr_group_fmt(struct vty *vty, const char *fmt,
				struct rate_ctr_group *ctrg)
{
	vty_out_rate_ctr_group_fmt2(vty, fmt, ctrg, false);
}
static int rate_ctr_group_handler(struct rate_ctr_group *ctrg, void *vctx_)
{
	struct vty_out_context *vctx = vctx_;
	struct vty *vty = vctx->vty;

	if (ctrg->desc->class_id > vctx->max_level)
		return 0;

	vty_out(vty, "%s%s (%d)", vctx->prefix, ctrg->desc->group_description, ctrg->idx);
	if (ctrg->name)
		vty_out(vty, "('%s')", ctrg->name);
	vty_out(vty, ":%s", VTY_NEWLINE);

	rate_ctr_for_each_counter(ctrg, rate_ctr_handler, vctx);

	return 0;
}

/*! @} */


/*! \addtogroup stats
 *  @{
 */

static int osmo_stat_item_handler(
	struct osmo_stat_item_group *statg, struct osmo_stat_item *item, void *vctx_)
{
	struct vty_out_context *vctx = vctx_;
	struct vty *vty = vctx->vty;
	const struct osmo_stat_item_desc *desc = osmo_stat_item_get_desc(item);
	int32_t value = osmo_stat_item_get_last(item);
	const char *unit = (desc->unit != OSMO_STAT_ITEM_NO_UNIT) ? desc->unit : "";

	if (vctx->skip_zero && value == 0)
		return 0;

	vty_out(vty, " %s%s: %8" PRIi32 " %s%s",
		vctx->prefix, desc->description, value, unit, VTY_NEWLINE);

	return 0;
}

/*! print a stat item group to given VTY
 *  \param[in] vty The VTY to which it should be printed
 *  \param[in] prefix Any additional log prefix ahead of each line
 *  \param[in] statg Stat item group to be printed
 *  \param[in] skip_zero Skip all zero-valued counters
 */
void vty_out_stat_item_group2(struct vty *vty, const char *prefix,
			      struct osmo_stat_item_group *statg, bool skip_zero)
{
	struct vty_out_context vctx = {vty, prefix, 0, skip_zero};

	vty_out(vty, "%s%s:%s", prefix, statg->desc->group_description,
		VTY_NEWLINE);
	osmo_stat_item_for_each_item(statg, osmo_stat_item_handler, &vctx);
}

void vty_out_stat_item_group(struct vty *vty, const char *prefix,
			     struct osmo_stat_item_group *statg)
{
	return vty_out_stat_item_group2(vty, prefix, statg, false);
}

static int osmo_stat_item_group_handler(struct osmo_stat_item_group *statg, void *vctx_)
{
	struct vty_out_context *vctx = vctx_;
	struct vty *vty = vctx->vty;

	if (statg->desc->class_id > vctx->max_level)
		return 0;

	vty_out(vty, "%s%s (%d)", vctx->prefix, statg->desc->group_description, statg->idx);
	if (statg->name)
		vty_out(vty, "('%s')", statg->name);
	vty_out(vty, ":%s", VTY_NEWLINE);

	osmo_stat_item_for_each_item(statg, osmo_stat_item_handler, vctx);

	return 0;
}

/*! @} */

/*! \addtogroup vty
 *  @{
 */

static int handle_counter(struct osmo_counter *counter, void *vctx_)
{
	struct vty_out_context *vctx = vctx_;
	struct vty *vty = vctx->vty;
	const char *description = counter->description;
	unsigned long value = osmo_counter_get(counter);

	if (vctx->skip_zero && value == 0)
		return 0;

	if (!counter->description)
		description = counter->name;

	vty_out(vty, " %s%s: %8lu%s", vctx->prefix, description, value, VTY_NEWLINE);

	return 0;
}

void vty_out_statistics_partial2(struct vty *vty, const char *prefix, int max_level, bool skip_zero)
{
	struct vty_out_context vctx = {vty, prefix, max_level, skip_zero};

	vty_out(vty, "%sUngrouped counters:%s", prefix, VTY_NEWLINE);
	osmo_counters_for_each(handle_counter, &vctx);
	rate_ctr_for_each_group(rate_ctr_group_handler, &vctx);
	osmo_stat_item_for_each_group(osmo_stat_item_group_handler, &vctx);
}

void vty_out_statistics_partial(struct vty *vty, const char *prefix, int max_level)
{
	return vty_out_statistics_partial2(vty, prefix, max_level, false);
}

void vty_out_statistics_full2(struct vty *vty, const char *prefix, bool skip_zero)
{
	vty_out_statistics_partial2(vty, prefix, INT_MAX, skip_zero);
}

void vty_out_statistics_full(struct vty *vty, const char *prefix)
{
	vty_out_statistics_full2(vty, prefix, false);
}

/*! Generate a VTY command string from value_string */
char *vty_cmd_string_from_valstr(void *ctx, const struct value_string *vals,
				 const char *prefix, const char *sep,
				 const char *end, int do_lower)
{
	int len = 0, offset = 0, ret, rem;
	int size = strlen(prefix) + strlen(end);
	int sep_len = strlen(sep);
	const struct value_string *vs;
	char *str;

	for (vs = vals; vs->value || vs->str; vs++)
		size += strlen(vs->str) + sep_len;

	rem = size;
	str = talloc_zero_size(ctx, size);
	if (!str)
		return NULL;

	ret = snprintf(str + offset, rem, "%s", prefix);
	if (ret < 0)
		goto err;
	OSMO_SNPRINTF_RET(ret, rem, offset, len);

	for (vs = vals; vs->value || vs->str; vs++) {
		if (vs->str) {
			int j, name_len = strlen(vs->str)+1;
			char name[name_len];

			for (j = 0; j < name_len; j++)
				name[j] = do_lower ?
					tolower(vs->str[j]) : vs->str[j];

			name[name_len-1] = '\0';
			ret = snprintf(str + offset, rem, "%s%s", name, sep);
			if (ret < 0)
				goto err;
			OSMO_SNPRINTF_RET(ret, rem, offset, len);
		}
	}
	offset -= sep_len;	/* to remove the trailing sep */
	rem += sep_len;

	ret = snprintf(str + offset, rem, "%s", end);
	if (ret < 0)
		goto err;
	OSMO_SNPRINTF_RET(ret, rem, offset, len);
err:
	str[size-1] = '\0';
	return str;
}

/*! @} */
