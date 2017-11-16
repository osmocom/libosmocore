/* (C) 2009-2017 by Harald Welte <laforge@gnumonks.org>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

/*! \addtogroup rate_ctr
 *  @{
 *  Counters about events and their event rates.
 *
 *  As \ref osmo_counter and \ref osmo_stat_item are concerned only with
 *  a single given value that may be increased/decreased, or the difference
 *  to one given previous value, this module adds some support for keeping
 *  long term information about a given event rate.
 *
 *  A \ref rate_ctr keeps information on the amount of events per second,
 *  per minute, per hour and per day.
 *
 *  \ref rate_ctr come in groups: An application describes a group of counters
 *  with their names and identities once in a (typically const) \ref
 *  rate_ctr_group_desc.
 *
 *  As objects (such as e.g. a subscriber or a PDP context) are
 *  allocated dynamically at runtime, the application calls \ref
 *  rate_ctr_group_alloc with a refernce to the \ref
 *  rate_ctr_group_desc, which causes the library to allocate one set of
 *  \ref rate_ctr: One for each in the group.
 *
 *  The application then uses functions like \ref rate_ctr_add or \ref
 *  rate_ctr_inc to increment the value as certain events (e.g. location
 *  update) happens.
 *
 *  The library internally keeps a timer once per second which iterates
 *  over all registered counters and which updates the per-second,
 *  per-minute, per-hour and per-day averages based on the current
 *  value.
 *
 *  The counters can be reported using \ref stats or by VTY
 *  introspection, as well as by any application-specific code accessing
 *  the \ref rate_ctr.intv array directly.
 *
 * \file rate_ctr.c */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/logging.h>

static LLIST_HEAD(rate_ctr_groups);

static void *tall_rate_ctr_ctx;


static bool rate_ctrl_group_desc_validate(const struct rate_ctr_group_desc *desc, bool quiet)
{
	unsigned int i;
	const struct rate_ctr_desc *ctr_desc;

	if (!desc) {
		LOGP(DLGLOBAL, LOGL_ERROR, "NULL is not a valid counter group descriptor\n");
		return false;
	}
	ctr_desc = desc->ctr_desc;

	DEBUGP(DLGLOBAL, "validating counter group %p(%s) with %u counters\n", desc,
		desc->group_name_prefix, desc->num_ctr);

	if (!osmo_identifier_valid(desc->group_name_prefix)) {
		if (!quiet)
			LOGP(DLGLOBAL, LOGL_ERROR, "'%s' is not a valid counter group identifier\n",
				desc->group_name_prefix);
		return false;
	}

	for (i = 0; i < desc->num_ctr; i++) {
		if (!osmo_identifier_valid(ctr_desc[i].name)) {
			if (!quiet)
				LOGP(DLGLOBAL, LOGL_ERROR, "'%s' is not a valid counter identifier\n",
					ctr_desc[i].name);
			return false;
		}
	}

	return true;
}

/* return 'in' if it doesn't contaon any '.'; otherwise allocate a copy and
 * replace all '.' with ':' */
static char *mangle_identifier_ifneeded(const void *ctx, const char *in)
{
	char *out;
	unsigned int i;

	if (!in)
		return NULL;

	if (!strchr(in, '.'))
		return (char *)in;

	out = talloc_strdup(ctx, in);
	OSMO_ASSERT(out);

	for (i = 0; i < strlen(out); i++) {
		if (out[i] == '.')
			out[i] = ':';
	}

	return out;
}

/* "mangle" a rate counter group descriptor, i.e. replace any '.' with ':' */
static struct rate_ctr_group_desc *
rate_ctr_group_desc_mangle(void *ctx, const struct rate_ctr_group_desc *desc)
{
	struct rate_ctr_group_desc *desc_new = talloc_zero(ctx, struct rate_ctr_group_desc);
	int i;

	OSMO_ASSERT(desc_new);

	/* mangle the name_prefix but copy/keep the rest */
	desc_new->group_name_prefix = mangle_identifier_ifneeded(desc_new, desc->group_name_prefix);
	desc_new->group_description = desc->group_description;
	desc_new->class_id = desc->class_id;
	desc_new->num_ctr = desc->num_ctr;
	desc_new->ctr_desc = talloc_array(desc_new, struct rate_ctr_desc, desc_new->num_ctr);
	OSMO_ASSERT(desc_new->ctr_desc);

	for (i = 0; i < desc->num_ctr; i++) {
		struct rate_ctr_desc *ctrd_new = (struct rate_ctr_desc *) desc_new->ctr_desc;
		const struct rate_ctr_desc *ctrd = desc->ctr_desc;

		if (!ctrd[i].name) {
			LOGP(DLGLOBAL, LOGL_ERROR, "counter group '%s'[%d] == NULL, aborting\n",
				desc->group_name_prefix, i);
			goto err_free;
		}

		ctrd_new[i].name = mangle_identifier_ifneeded(desc_new->ctr_desc, ctrd[i].name);
		ctrd_new[i].description = ctrd[i].description;
	}

	if (!rate_ctrl_group_desc_validate(desc_new, false)) {
		/* simple mangling of identifiers ('.' -> ':') was not sufficient to render a valid
		 * descriptor, we have to bail out */
		LOGP(DLGLOBAL, LOGL_ERROR, "counter group '%s' still invalid after mangling\n",
			desc->group_name_prefix);
		goto err_free;
	}

	LOGP(DLGLOBAL, LOGL_INFO, "Needed to mangle ounter group '%s' names still using '.' as "
		"separator, please consider updating the application\n", desc->group_name_prefix);

	return desc_new;
err_free:
	talloc_free(desc_new);
	return NULL;
}

/*! Allocate a new group of counters according to description
 *  \param[in] ctx \ref talloc context
 *  \param[in] desc Rate counter group description
 *  \param[in] idx Index of new counter group
 */
struct rate_ctr_group *rate_ctr_group_alloc(void *ctx,
					    const struct rate_ctr_group_desc *desc,
					    unsigned int idx)
{
	unsigned int size;
	struct rate_ctr_group *group;

	size = sizeof(struct rate_ctr_group) +
			desc->num_ctr * sizeof(struct rate_ctr);

	if (!ctx)
		ctx = tall_rate_ctr_ctx;

	group = talloc_zero_size(ctx, size);
	if (!group)
		return NULL;

	/* attempt to mangle all '.' in identifiers to ':' for backwards compat */
	if (!rate_ctrl_group_desc_validate(desc, true)) {
		desc = rate_ctr_group_desc_mangle(group, desc);
		if (!desc) {
			talloc_free(group);
			return NULL;
		}
	}

	group->desc = desc;
	group->idx = idx;

	llist_add(&group->list, &rate_ctr_groups);

	return group;
}

/*! Free the memory for the specified group of counters */
void rate_ctr_group_free(struct rate_ctr_group *grp)
{
	llist_del(&grp->list);
	talloc_free(grp);
}

/*! Add a number to the counter */
void rate_ctr_add(struct rate_ctr *ctr, int inc)
{
	ctr->current += inc;
}

/*! Return the counter difference since the last call to this function */
int64_t rate_ctr_difference(struct rate_ctr *ctr)
{
	int64_t result = ctr->current - ctr->previous;
	ctr->previous = ctr->current;

	return result;
}

/* TODO: support update intervals > 1s */
/* TODO: implement this as a special stats reporter */

static void interval_expired(struct rate_ctr *ctr, enum rate_ctr_intv intv)
{
	/* calculate rate over last interval */
	ctr->intv[intv].rate = ctr->current - ctr->intv[intv].last;
	/* save current counter for next interval */
	ctr->intv[intv].last = ctr->current;

	/* update the rate of the next bigger interval.  This will
	 * be overwritten when that next larger interval expires */
	if (intv + 1 < ARRAY_SIZE(ctr->intv))
		ctr->intv[intv+1].rate += ctr->intv[intv].rate;
}

static struct osmo_timer_list rate_ctr_timer;
static uint64_t timer_ticks;

/* The one-second interval has expired */
static void rate_ctr_group_intv(struct rate_ctr_group *grp)
{
	unsigned int i;

	for (i = 0; i < grp->desc->num_ctr; i++) {
		struct rate_ctr *ctr = &grp->ctr[i];

		interval_expired(ctr, RATE_CTR_INTV_SEC);
		if ((timer_ticks % 60) == 0)
			interval_expired(ctr, RATE_CTR_INTV_MIN);
		if ((timer_ticks % (60*60)) == 0)
			interval_expired(ctr, RATE_CTR_INTV_HOUR);
		if ((timer_ticks % (24*60*60)) == 0)
			interval_expired(ctr, RATE_CTR_INTV_DAY);
	}
}

static void rate_ctr_timer_cb(void *data)
{
	struct rate_ctr_group *ctrg;

	/* Increment number of ticks before we calculate intervals,
	 * as a counter value of 0 would already wrap all counters */
	timer_ticks++;

	llist_for_each_entry(ctrg, &rate_ctr_groups, list)
		rate_ctr_group_intv(ctrg);

	osmo_timer_schedule(&rate_ctr_timer, 1, 0);
}

/*! Initialize the counter module. Call this once from your application.
 *  \param[in] tall_ctx Talloc context from which rate_ctr_group will be allocated
 *  \returns 0 on success; negative on error */
int rate_ctr_init(void *tall_ctx)
{
	tall_rate_ctr_ctx = tall_ctx;
	osmo_timer_setup(&rate_ctr_timer, rate_ctr_timer_cb, NULL);
	osmo_timer_schedule(&rate_ctr_timer, 1, 0);

	return 0;
}

/*! Search for counter group based on group name and index
 *  \param[in] name Name of the counter group you're looking for
 *  \param[in] idx Index inside the counter group
 *  \returns \ref rate_ctr_group or NULL in case of error */
struct rate_ctr_group *rate_ctr_get_group_by_name_idx(const char *name, const unsigned int idx)
{
	struct rate_ctr_group *ctrg;

	llist_for_each_entry(ctrg, &rate_ctr_groups, list) {
		if (!ctrg->desc)
			continue;

		if (!strcmp(ctrg->desc->group_name_prefix, name) &&
				ctrg->idx == idx) {
			return ctrg;
		}
	}
	return NULL;
}

/*! Search for counter based on group + name
 *  \param[in] ctrg pointer to \ref rate_ctr_group
 *  \param[in] name name of counter inside group
 *  \returns \ref rate_ctr or NULL in case of error
 */
const struct rate_ctr *rate_ctr_get_by_name(const struct rate_ctr_group *ctrg, const char *name)
{
	int i;
	const struct rate_ctr_desc *ctr_desc;

	if (!ctrg->desc)
		return NULL;

	for (i = 0; i < ctrg->desc->num_ctr; i++) {
		ctr_desc = &ctrg->desc->ctr_desc[i];

		if (!strcmp(ctr_desc->name, name)) {
			return &ctrg->ctr[i];
		}
	}
	return NULL;
}

/*! Iterate over each counter in group and call function
 *  \param[in] counter group over whose counter to iterate
 *  \param[in] handle_counter function pointer
 *  \param[in] data Data to hand transparently to \ref handle_counter
 *  \returns 0 on success; negative otherwise
 */
int rate_ctr_for_each_counter(struct rate_ctr_group *ctrg,
	rate_ctr_handler_t handle_counter, void *data)
{
	int rc = 0;
	int i;

	for (i = 0; i < ctrg->desc->num_ctr; i++) {
		struct rate_ctr *ctr = &ctrg->ctr[i];
		rc = handle_counter(ctrg,
			ctr, &ctrg->desc->ctr_desc[i], data);
		if (rc < 0)
			return rc;
	}

	return rc;
}

/*! Iterate over all counter groups
 *  \param[in] handle_group function pointer of callback function
 *  \param[in] data Data to hand transparently to \ref handle_group
 *  \returns 0 on success; negative otherwise
 */
int rate_ctr_for_each_group(rate_ctr_group_handler_t handle_group, void *data)
{
	struct rate_ctr_group *statg;
	int rc = 0;

	llist_for_each_entry(statg, &rate_ctr_groups, list) {
		rc = handle_group(statg, data);
		if (rc < 0)
			return rc;
	}

	return rc;
}

/*! @} */
