#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <osmocom/core/backtrace.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/panic.h>
#include <osmocom/core/defs.h>

/*! \defgroup utils General-purpose utility functions
 *  @{
 * \file utils.h */

/*! Determine number of elements in an array of static size */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
/*! Return the maximum of two specified values */
#define OSMO_MAX(a, b) ((a) >= (b) ? (a) : (b))
/*! Return the minimum of two specified values */
#define OSMO_MIN(a, b) ((a) >= (b) ? (b) : (a))
/*! Stringify the name of a macro x, e.g. an FSM event name.
 * Note: if nested within another preprocessor macro, this will
 * stringify the value of x instead of its name. */
#define OSMO_STRINGIFY(x) #x
/*! Stringify the value of a macro x, e.g. a port number. */
#define OSMO_STRINGIFY_VAL(x) OSMO_STRINGIFY(x)
/*! Make a value_string entry from an enum value name */
#define OSMO_VALUE_STRING(x) { x, #x }
/*! Number of bytes necessary to store given BITS */
#define OSMO_BYTES_FOR_BITS(BITS) ((BITS + 8 - 1) / 8)

/*! Copy a C-string into a sized buffer using sizeof to detect buffer's size */
#define OSMO_STRLCPY_ARRAY(array, src) osmo_strlcpy(array, src, sizeof(array))

/*! A mapping between human-readable string and numeric value */
struct value_string {
	unsigned int value;	/*!< numeric value */
	const char *str;	/*!< human-readable string */
};

const char *get_value_string(const struct value_string *vs, uint32_t val);
const char *get_value_string_or_null(const struct value_string *vs,
				     uint32_t val);

int get_string_value(const struct value_string *vs, const char *str);

char osmo_bcd2char(uint8_t bcd);
/* only works for numbers in ascci */
uint8_t osmo_char2bcd(char c);

int osmo_bcd2str(char *dst, size_t dst_size, const uint8_t *bcd, int start_nibble, int end_nibble, bool allow_hex);

int osmo_hexparse(const char *str, uint8_t *b, int max_len);

char *osmo_ubit_dump_buf(char *buf, size_t buf_len, const uint8_t *bits, unsigned int len);
char *osmo_ubit_dump(const uint8_t *bits, unsigned int len);
char *osmo_hexdump(const unsigned char *buf, int len);
char *osmo_hexdump_c(const void *ctx, const unsigned char *buf, int len);
char *osmo_hexdump_nospc(const unsigned char *buf, int len);
char *osmo_hexdump_nospc_c(const void *ctx, const unsigned char *buf, int len);
const char *osmo_hexdump_buf(char *out_buf, size_t out_buf_size, const unsigned char *buf, int len, const char *delim,
			     bool delim_after_last);

char *osmo_osmo_hexdump_nospc(const unsigned char *buf, int len) __attribute__((__deprecated__));

#define osmo_static_assert(exp, name) typedef int dummy##name [(exp) ? 1 : -1] __attribute__((__unused__));

void osmo_str2lower(char *out, const char *in)
	OSMO_DEPRECATED("Use osmo_str_tolower() or osmo_str_tolower_buf() instead,"
			" to properly check target memory bounds");
void osmo_str2upper(char *out, const char *in)
	OSMO_DEPRECATED("Use osmo_str_toupper() or osmo_str_toupper_buf() instead,"
			" to properly check target memory bounds");

size_t osmo_str_tolower_buf(char *dest, size_t dest_len, const char *src);
const char *osmo_str_tolower(const char *src);
char *osmo_str_tolower_c(const void *ctx, const char *src);

size_t osmo_str_toupper_buf(char *dest, size_t dest_len, const char *src);
const char *osmo_str_toupper(const char *src);
char *osmo_str_toupper_c(const void *ctx, const char *src);

#define OSMO_SNPRINTF_RET(ret, rem, offset, len)		\
do {								\
	len += ret;						\
	if (ret > rem)						\
		ret = rem;					\
	offset += ret;						\
	rem -= ret;						\
} while (0)

/*! Helper macro to terminate when an assertion failes
 *  \param[in] exp Predicate to verify
 *  This function will generate a backtrace and terminate the program if
 *  the predicate evaluates to false (0).
 */
#define OSMO_ASSERT(exp)    \
	if (!(exp)) { \
		osmo_panic("Assert failed %s %s:%d\n", #exp, __FILE__, __LINE__); \
	}

/*! duplicate a string using talloc and release its prior content (if any)
 * \param[in] ctx Talloc context to use for allocation
 * \param[out] dst pointer to string, will be updated with ptr to new string
 * \param[in] newstr String that will be copieed to newly allocated string */
static inline void osmo_talloc_replace_string(void *ctx, char **dst, const char *newstr)
{
	if (*dst)
		talloc_free(*dst);
	*dst = talloc_strdup(ctx, newstr);
}

/*! Append to a string and re-/allocate if necessary.
 * \param[in] ctx  Talloc context to use for initial allocation.
 * \param[in,out] dest  char* to re-/allocate and append to.
 * \param[in] fmt  printf-like string format.
 * \param[in] args  Arguments for fmt.
 *
 * \a dest may be passed in NULL, or a string previously allocated by talloc.
 * If an existing string is passed in, it will remain associated with whichever
 * ctx it was allocated before, regardless whether it matches \a ctx or not.
 */
#define osmo_talloc_asprintf(ctx, dest, fmt, args ...) \
	do { \
		if (!dest) \
			dest = talloc_asprintf(ctx, fmt, ## args); \
		else \
			dest = talloc_asprintf_append((char*)dest, fmt, ## args); \
	} while (0)

int osmo_constant_time_cmp(const uint8_t *exp, const uint8_t *rel, const int count);
uint64_t osmo_decode_big_endian(const uint8_t *data, size_t data_len);
uint8_t *osmo_encode_big_endian(uint64_t value, size_t data_len);

size_t osmo_strlcpy(char *dst, const char *src, size_t siz);

bool osmo_is_hexstr(const char *str, int min_digits, int max_digits,
		    bool require_even);

bool osmo_identifier_valid(const char *str);
bool osmo_separated_identifiers_valid(const char *str, const char *sep_chars);

const char *osmo_escape_str(const char *str, int len);
char *osmo_escape_str_buf(const char *str, int in_len, char *buf, size_t bufsize);
char *osmo_escape_str_c(const void *ctx, const char *str, int in_len);
const char *osmo_quote_str(const char *str, int in_len);
char *osmo_quote_str_buf(const char *str, int in_len, char *buf, size_t bufsize);
char *osmo_quote_str_c(const void *ctx, const char *str, int in_len);

uint32_t osmo_isqrt32(uint32_t x);

const char osmo_luhn(const char* in, int in_len);

/*! State for OSMO_STRBUF_APPEND() and OSMO_STRBUF_PRINTF(). See there for examples. */
struct osmo_strbuf {
	/*! Point to the start of a string buffer. */
	char *buf;
	/*! Total sizeof() the buffer buf points at. */
	size_t len;
	/*! Current writing position in buf (end of the string written so far). */
	char *pos;
	/*! After all OSMO_STRBUF_APPEND operations, reflects the total number of characters that would be written had
	 * buf been large enough. Like snprintf()'s return value, this does not include the terminating nul character.
	 * Hence, to allocate an adequately sized buffer, add 1 to this number. */
	size_t chars_needed;
};

/*! Append a string to a buffer, as printed by an snprintf()-like function and with similar bounds checking.
 * Make sure to never write past the end of the buffer, and collect the total size that would be needed.
 *
 *     // an example function implementation to append: write N spaces.
 *     int print_spaces(char *dst, size_t dst_len, int n)
 *     {
 *             int i;
 *             if (n < 0)
 *                     return -EINVAL;
 *             for (i = 0; i < n && i < dst_len; i++)
 *                     dst[i] = ' ';
 *             if (dst_len)
 *                     dst[OSMO_MIN(dst_len - 1, n)] = '\0';
 *             // return the n that we would have liked to write if space were available:
 *             return n;
 *     }
 *
 *     // append above spaces as well as an snprintf()
 *     void strbuf_example()
 *     {
 *             char buf[23];
 *             struct osmo_strbuf sb = { .buf = buf, .len = sizeof(buf) };
 *
 *             OSMO_STRBUF_APPEND(sb, print_spaces, 5);
 *             OSMO_STRBUF_APPEND(sb, snprintf, "The answer is %d but what is the question?", 42);
 *             OSMO_STRBUF_APPEND(sb, print_spaces, 423423);
 *
 *             printf("%s\n", buf);
 *             printf("would have needed %zu bytes\n", sb.chars_needed);
 *     }
 *
 * \param[inout] STRBUF  A struct osmo_strbuf instance.
 * \param[in] func  A function with a signature of int func(char *dst, size_t dst_len [, args]) with semantics like
 *                  snprintf().
 * \param[in] args  Arguments passed to func, if any.
 */
#define OSMO_STRBUF_APPEND(STRBUF, func, args...) do { \
		if (!(STRBUF).pos) \
			(STRBUF).pos = (STRBUF).buf; \
		size_t _sb_remain = (STRBUF).buf ? (STRBUF).len - ((STRBUF).pos - (STRBUF).buf) : 0; \
		int _sb_l = func((STRBUF).pos, _sb_remain, ##args); \
		if (_sb_l < 0 || _sb_l > _sb_remain) \
			(STRBUF).pos = (STRBUF).buf + (STRBUF).len; \
		else if ((STRBUF).pos) \
			(STRBUF).pos += _sb_l; \
		if (_sb_l > 0) \
			(STRBUF).chars_needed += _sb_l; \
	} while(0)

/*! Shortcut for OSMO_STRBUF_APPEND() invocation using snprintf().
 *
 *     int strbuf_example2(char *buf, size_t buflen)
 *     {
 *             int i;
 *             struct osmo_strbuf sb = { .buf = buf, .len = buflen };
 *
 *             OSMO_STRBUF_PRINTF(sb, "T minus");
 *             for (i = 10; i; i--)
 *                     OSMO_STRBUF_PRINTF(sb, " %d", i);
 *             OSMO_STRBUF_PRINTF(sb, " ... Lift off!");
 *
 *             return sb.chars_needed;
 *     }
 *
 * \param[inout] STRBUF  A struct osmo_strbuf instance.
 * \param[in] fmt  Format string passed to snprintf.
 * \param[in] args  Additional arguments passed to snprintf, if any.
 */
#define OSMO_STRBUF_PRINTF(STRBUF, fmt, args...) \
	OSMO_STRBUF_APPEND(STRBUF, snprintf, fmt, ##args)

/*! Like OSMO_STRBUF_APPEND(), but for function signatures that return the char* buffer instead of a length.
 * When using this function, the final STRBUF.chars_needed may not reflect the actual number of characters needed, since
 * that number cannot be obtained from this kind of function signature.
 * \param[inout] STRBUF  A struct osmo_strbuf instance.
 * \param[in] func  A function with a signature of char *func(char *dst, size_t dst_len [, args]) where
 *                  the returned string is always written to dst.
 * \param[in] args  Arguments passed to func, if any.
 */
#define OSMO_STRBUF_APPEND_NOLEN(STRBUF, func, args...) do { \
		if (!(STRBUF).pos) \
			(STRBUF).pos = (STRBUF).buf; \
		size_t _sb_remain = (STRBUF).buf ? (STRBUF).len - ((STRBUF).pos - (STRBUF).buf) : 0; \
		if (_sb_remain) { \
			func((STRBUF).pos, _sb_remain, ##args); \
		} \
		size_t _sb_l = (STRBUF).pos ? strnlen((STRBUF).pos, _sb_remain) : 0; \
		if (_sb_l > _sb_remain) \
			(STRBUF).pos = (STRBUF).buf + (STRBUF).len; \
		else if ((STRBUF).pos) \
			(STRBUF).pos += _sb_l; \
		(STRBUF).chars_needed += _sb_l; \
	} while(0)

bool osmo_str_startswith(const char *str, const char *startswith_str);

/*! @} */
