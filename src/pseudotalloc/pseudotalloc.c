/* overly simplistic talloc replacement for deeply embedded
 * microcontrollers.  Obviously this has none of the properties of real
 * talloc, it is particualrly not hierarchical at all */


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
