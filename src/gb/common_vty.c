/*! \file common_vty.c
 * OpenBSC VTY common helpers. */
/*
 * (C) 2009-2012 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2010 by Holger Hans Peter Freyther
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdlib.h>
#include <string.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>

#include <osmocom/gprs/gprs_msgb.h>

#include "common_vty.h"

int gprs_log_filter_fn(const struct log_context *ctx,
			struct log_target *tar)
{
	const void *nse = log_get_context(ctx, LOG_CTX_GB_NSE);
	const void *nsvc = log_get_context(ctx, LOG_CTX_GB_NSVC);
	const void *bvc = log_get_context(ctx, LOG_CTX_GB_BVC);

	/* Filter on the NS Entity */
	if (log_get_filter(tar, LOG_FLT_GB_NSE) &&
	    nse && (nse == log_get_filter_data(tar, LOG_FLT_GB_NSE)))
		return 1;

	/* Filter on the NS Virtual Connection */
	if (log_get_filter(tar, LOG_FLT_GB_NSVC) &&
	    nsvc && (nsvc == log_get_filter_data(tar, LOG_FLT_GB_NSVC)))
		return 1;

	/* Filter on the BSSGP Virtual Connection */
	if (log_get_filter(tar, LOG_FLT_GB_BVC) &&
	    bvc && (bvc == log_get_filter_data(tar, LOG_FLT_GB_BVC)))
		return 1;

	return 0;
}


int DNS;
