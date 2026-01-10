/*! \file logging_emscripten.c
 *  Logging support code using a JS callback. This module sends log
 *  messages to a JavaScript callback named `on_log`
 *  with interface on_log(const char *subsys, int level, const char *msg).
 *  */
/*
 * (C) 2026 by Timur Davydov <dtv.comp@gmail.com>
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

/*! \addtogroup logging
 *  @{
 * \file logging_emscripten.c */

#include <stdarg.h>
#include <stdio.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/logging_internal.h>

#include <emscripten.h>

EM_JS(void, on_log_wrapper, (const char *subsys, int level, const char *msg), {
	return on_log(subsys, level, msg);
});

static void _emscripten_raw_output(struct log_target *target, int subsys,
			       unsigned int level, const char *file,
			       int line, int cont, const char *format,
			       va_list ap)
{
	char msg[MAX_LOG_SIZE];
	const char *subsys_name = log_category_name(subsys);
	int rc;

	rc = vsnprintf(msg, sizeof(msg), format, ap);
	if (rc <= 0)
		return;
	if (rc >= sizeof(msg))
		rc = sizeof(msg) - 1;

	/* Drop newline at the end if exists: */
	if (msg[rc - 1] == '\n')
		msg[rc - 1] = '\0';

	on_log_wrapper(subsys_name ? subsys_name : "", level, msg);
}

/*! Create a new logging target for JS callback logging (uses `on_log`)
 *  \returns Log target in case of success, NULL in case of error
 */
struct log_target *log_target_create_emscripten(void)
{
	struct log_target *target;

	target = log_target_create();
	if (!target)
		return NULL;

	target->type = LOG_TGT_TYPE_EMSCRIPTEN;
	target->raw_output = _emscripten_raw_output;

	return target;
}

/* @} */
