/*! \file pseudotalloc.c
 * overly simplistic talloc replacement for deeply embedded
 * microcontrollers.  Obviously this has none of the properties of real
 * talloc, it is particualrly not hierarchical at all.
 *
 * (C) 2017 by Harald Welte <laforge@gnumonks.org>
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
 */

#include "talloc.h"
#include <string.h>
#include <stdio.h>

void *_talloc_zero(const void *ctx, size_t size, const char *name)
{
	void *p = pseudotalloc_malloc(size);
	if (!p)
		return NULL;
	memset(p, 0, size);
	return p;
}

int _talloc_free(void *ptr, const char *location)
{
	pseudotalloc_free(ptr);
	return 0;
}

void *talloc_named_const(const void *context, size_t size, const char *name)
{
	return pseudotalloc_malloc(size);
}

void *talloc_named(const void *context, size_t size, const char *fmt, ...)
{
	return pseudotalloc_malloc(size);
}

void talloc_set_name_const(const void *ptr, const char *name)
{
}

char *talloc_strdup(const void *context, const char *p)
{
	char *ptr;
	size_t len;

	if (!p)
		return NULL;
	len = strlen(p);

	ptr = talloc_size(context, len+1);
	if (!ptr)
		return NULL;
	memcpy(ptr, p, len+1);

	return ptr;
}

void *talloc_pool(const void *context, size_t size)
{
	return (void *) context;
}

void *_talloc_array(const void *ctx, size_t el_size, unsigned count, const char *name)
{
	return talloc_size(ctx, el_size * count);
}

void *_talloc_zero_array(const void *ctx, size_t el_size, unsigned count, const char *name)
{
	return talloc_zero_size(ctx, el_size * count);
}

char *talloc_asprintf(const void *ctx, const char *fmt, ...)
{
	char *buf;
	size_t len = 128;
	va_list args;
	va_start(args, fmt);

	buf = talloc_size(ctx, len);
	if (len < vsnprintf(buf, len, fmt, args))
		strcpy(&buf[len-6], "[...]");

	va_end(args);
	return buf;
}

void *_talloc_steal_loc(const void *new_ctx, const void *obj, const char *location)
{
	/* as we don't do hierarchical allocations, this is simply a NOP */
	return (void *)obj;
}

char *talloc_vasprintf(const void *t, const char *fmt, va_list ap)
{
	/* we have a hard-coded maximum string length of 128 bytes in this pseudo implementation */
	char *buf = pseudotalloc_malloc(128);
	if (!buf)
		return NULL;
	vsnprintf(buf, 128, fmt, ap);
	return buf;
}
