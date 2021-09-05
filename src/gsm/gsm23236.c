/*! \file gsm23236.c
 * Utility function implementations related to 3GPP TS 23.236 */
/*
 * (C) 2020 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <errno.h>
#include <stdlib.h>

#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm23236.h>

/*! Validate that the given NRI is valid for a given nri_bitlen range.
 * \param[in] nri_v  NRI value to validate.
 * \param[in] nri_bitlen  Valid NRI range in nr of bits used; if nri_bitlen > OSMO_NRI_BITLEN_MAX, nri_v is only
 *                        checked to not be marked invalid.
 * \returns 0 if valid, <0 if the NRI is <0, >0 if the NRI surpasses the range.
 */
int osmo_nri_v_validate(int16_t nri_v, uint8_t nri_bitlen)
{
	if (nri_v < 0)
		return -1;
	if (nri_bitlen < OSMO_NRI_BITLEN_MIN)
		return 1;
	if (nri_bitlen < OSMO_NRI_BITLEN_MAX && (nri_v >> nri_bitlen))
		return 1;
	return 0;
}

/*! Match NRI value against a list NRI ranges. */
static bool nri_v_matches_range(const struct osmo_nri_range *range, int16_t nri_v)
{
	return range && nri_v >= range->first && nri_v <= range->last;
}

/*! Return true if the ranges overlap, i.e. one or more NRI values appear in both ranges. */
static bool nri_range_overlaps_range(const struct osmo_nri_range *a, const struct osmo_nri_range *b)
{
	return nri_v_matches_range(b, a->first) || nri_v_matches_range(b, a->last)
		|| nri_v_matches_range(a, b->first) || nri_v_matches_range(a, b->last);
}

/*! Return true if the ranges overlap or are directly adjacent to each other. */
static bool nri_range_touches(const struct osmo_nri_range *a, const struct osmo_nri_range *b)
{
	/* The first > last check may seem redundant, but ensures integer overflow safety. */
	return nri_range_overlaps_range(a, b)
		|| (a->first > b->last && a->first == b->last + 1)
		|| (b->first > a->last && b->first == a->last + 1);
}

/*! Grow target range to also span range 'add'. Only useful for touching ranges, since all values between the two ranges
 * are also included. */
static void nri_range_extend(struct osmo_nri_range *target, const struct osmo_nri_range *add)
{
	target->first = OSMO_MIN(target->first, add->first);
	target->last = OSMO_MAX(target->last, add->last);
}

/*! Return true when the given NRI value appears in the list of NRI ranges.
 * \param[in] nri_v  NRI value to look for.
 * \param[in] nri_ranges  List NRI ranges.
 * \returns true iff nri_v appears anywhere in nri_ranges.
 */
bool osmo_nri_v_matches_ranges(int16_t nri_v, const struct osmo_nri_ranges *nri_ranges)
{
	struct osmo_nri_range *range;
	if (!nri_ranges)
		return false;
	llist_for_each_entry(range, &nri_ranges->entries, entry) {
		if (nri_v_matches_range(range, nri_v))
			return true;
	}
	return false;
}

/*! Modulo and shift the given NRI value so that it becomes a value present in a list of NRI ranges.
 * Only range values within nri_bitlen are used.
 * \param[inout] nri_v  The NRI value to limit, e.g. random bits or an increment counter value.
 * \param[in] nri_ranges  List of NRI ranges indicating valid NRI values, where no entries may overlap in range values,
 *                        and all entries must be valid (first <= last).
 * \returns 0 on success, negative on error.
 */
int osmo_nri_v_limit_by_ranges(int16_t *nri_v, const struct osmo_nri_ranges *nri_ranges, uint32_t nri_bitlen)
{
	struct osmo_nri_range *range;
	uint32_t total_values = 0;
	int16_t v = *nri_v;
	int16_t range_max = (((int16_t)1) << nri_bitlen) - 1;

	if (v < 0 || !nri_ranges)
		return -1;

	/* Sum up total amount of range values */
	llist_for_each_entry(range, &nri_ranges->entries, entry) {
		if (osmo_nri_range_validate(range, 255))
			return -1;
		if (range->first > range_max)
			continue;
		total_values += OSMO_MIN(range_max, range->last) - range->first + 1;
	}

	/* Modulo the given NRI value by that, and pick that nth value from the given ranges.
	 * (nri_ranges is pretty much guaranteed to be sorted and range_max checks thus would no longer be needed, but
	 * just check them anyway.) */
	v %= total_values;
	llist_for_each_entry(range, &nri_ranges->entries, entry) {
		uint32_t len;
		if (range->first > range_max)
			continue;
		len = OSMO_MIN(range_max, range->last) - range->first + 1;
		if (v < len) {
			*nri_v = range->first + v;
			return 0;
		}
		v -= len;
	}

	/* Nothing found -- there are no entires or my math is off. */
	return -1;
}

/*! Retrieve the Network Resource Indicator bits from a TMSI or p-TMSI.
 * Useful for MSC pooling as described by 3GPP TS 23.236.
 * \param[out] nri_v  Write the extracted NRI value to this location (if non-NULL). If 0 is returned, it is guaranteed
 *                    that nri_v >= 0. On non-zero return code, nri_v == -1.
 * \param[in] tmsi  TMSI value containing NRI bits.
 * \param[in] nri_bitlen  Length of the NRI value in number of bits,
 *                        OSMO_NRI_BITLEN_MIN <= nri_bitlen <= * OSMO_NRI_BITLEN_MAX.
 * \return 0 on success, negative on error (i.e. if nri_bitlen is not in the valid range).
 */
int osmo_tmsi_nri_v_get(int16_t *nri_v, uint32_t tmsi, uint8_t nri_bitlen)
{
	uint8_t lowest_bit;
	if (nri_v)
		*nri_v = -1;
	if (nri_bitlen < OSMO_NRI_BITLEN_MIN || nri_bitlen > OSMO_NRI_BITLEN_MAX)
		return -1;
	/* If not interested in the NRI value, exit here. */
	if (!nri_v)
		return 0;
	/* According to 3GPP TS 23.236, the most significant bit of the NRI is always bit 23.
	 * (So this is not a temporary placeholder 23 we sometimes like to use, it is an actually specified 23!) */
	lowest_bit = 23 - (nri_bitlen - 1);
	/* ????xxxxxx??????? -> 0000000????xxxxxx  tmsi >> lowest_bit
	 *                   ->            xxxxxx  & (bitmask that is nri_bitlen bits wide)
	 */
	*nri_v = (tmsi >> lowest_bit) & ((((uint32_t)1) << nri_bitlen) - 1);
	return 0;
}

/*! Write Network Resource Indicator bits into a TMSI or p-TMSI.
 * Overwrite the NRI bits with a given NRI value in a TMSI or p-TMSI.
 * Useful for MSC pooling as described by 3GPP TS 23.236.
 * \param[inout] tmsi  A base TMSI or p-TMSI to replace the NRI value in, result is written back to this location.
 * \param[in] nri_v  The NRI value to place in the tmsi.
 * \param[in] nri_bitlen  Length of the NRI value in number of bits,
 *                        OSMO_NRI_BITLEN_MIN <= nri_bitlen <= * OSMO_NRI_BITLEN_MAX.
 * \return 0 on success, negative on error (i.e. if nri_bitlen is not in the valid range or if tmsi is NULL).
 */
int osmo_tmsi_nri_v_set(uint32_t *tmsi, int16_t nri_v, uint8_t nri_bitlen)
{
	uint8_t lowest_bit;
	uint32_t v_mask;
	if (nri_bitlen < OSMO_NRI_BITLEN_MIN || nri_bitlen > OSMO_NRI_BITLEN_MAX)
		return -1;
	if (nri_v < 0)
		return -1;
	if (!tmsi)
		return -1;
	lowest_bit = 23 - (nri_bitlen - 1);
	v_mask = ((((uint32_t)1) << nri_bitlen) - 1) << lowest_bit;
	*tmsi = ((*tmsi) & ~v_mask) | ((((uint32_t)nri_v) << lowest_bit) & v_mask);
	return 0;
}

/*! Apply osmo_nri_v_limit_by_ranges() in-place on the NRI value included in a TMSI.
 * Extract the NRI value from the TMSI, limit that to be part of the ranges given in 'nri_ranges', and place the
 * resulting NRI value back in the TMSI.
 * \param[inout] tmsi  TMSI value of which to modify the NRI bits, e.g. fresh randomized bits.
 * \param[in] nri_ranges  List of NRI ranges indicating valid NRI values, where no entries may overlap in range values,
 *                        and all entries must be valid (first <= last).
 * \param[in] nri_bitlen  Valid NRI range in nr of bits used.
 * \returns 0 on success, negative on error.
 */
int osmo_tmsi_nri_v_limit_by_ranges(uint32_t *tmsi, const struct osmo_nri_ranges *nri_ranges, uint8_t nri_bitlen)
{
	int rc;
	int16_t nri_v;
	rc = osmo_tmsi_nri_v_get(&nri_v, *tmsi, nri_bitlen);
	if (rc)
		return rc;
	rc = osmo_nri_v_limit_by_ranges(&nri_v, nri_ranges, nri_bitlen);
	if (rc)
		return rc;
	return osmo_tmsi_nri_v_set(tmsi, nri_v, nri_bitlen);
}

/*! Validate that the given NRI range is valid for a given nri_bitlen range.
 * \param[in] nri_range  NRI value range to validate.
 * \param[in] nri_bitlen  Valid NRI range in nr of bits used. If nri_bitlen > OSMO_NRI_BITLEN_MAX, the NRI range is only
 *                        validated to be first <= last and non-negative, not checked to fit a bit length range,
 * \returns 0 if valid, -1 or 1 if range->first is invalid, -2 or 2 if range->last is invalid, -3 if first > last.
 */
int osmo_nri_range_validate(const struct osmo_nri_range *range, uint8_t nri_bitlen)
{
	int rc;
	rc = osmo_nri_v_validate(range->first, nri_bitlen);
	if (rc)
		return rc;
	rc = osmo_nri_v_validate(range->last, nri_bitlen);
	if (rc)
		return 2 * rc;
	if (range->first > range->last)
		return -3;
	return 0;
}

/*! Return true when the given NRI range has at least one NRI value that appears in a list of other NRI ranges.
 * \param[in] range  NRI range to look for.
 * \param[in] nri_ranges  List NRI ranges.
 * \returns true iff any NRI value from 'range' appears anywhere in nri_ranges.
 */
bool osmo_nri_range_overlaps_ranges(const struct osmo_nri_range *range, const struct osmo_nri_ranges *nri_ranges)
{
	struct osmo_nri_range *i;
	if (!nri_ranges)
		return false;
	llist_for_each_entry(i, &nri_ranges->entries, entry) {
		if (nri_range_overlaps_range(i, range))
			return true;
	}
	return false;
}

/*! Allocate an empty struct osmo_nri_ranges (list of struct osmo_nri_range).
 * \param ctx  Talloc context to allocate from.
 * \return allocated empty list.
 */
struct osmo_nri_ranges *osmo_nri_ranges_alloc(void *ctx)
{
	struct osmo_nri_ranges *nri_ranges;
	nri_ranges = talloc_zero(ctx, struct osmo_nri_ranges);
	OSMO_ASSERT(nri_ranges);
	INIT_LLIST_HEAD(&nri_ranges->entries);
	return nri_ranges;
}

/*! Free a struct osmo_nri_ranges.
 * \param nri_ranges The list to discard.
 */
void osmo_nri_ranges_free(struct osmo_nri_ranges *nri_ranges)
{
	if (nri_ranges)
		talloc_free(nri_ranges);
}

/*! Insert a new struct osmo_nri_range in an osmo_nri_ranges list, so that it remains sorted by 'first' values. */
static void nri_ranges_add_entry_sorted(struct osmo_nri_ranges *nri_ranges, struct osmo_nri_range *add)
{
	struct osmo_nri_range *r;
	struct llist_head *at_pos;
	OSMO_ASSERT(nri_ranges);
	at_pos = nri_ranges->entries.prev;
	llist_for_each_entry(r, &nri_ranges->entries, entry) {
		if (r->first <= add->first)
			continue;
		at_pos = r->entry.prev;
		break;
	}
	llist_add(&add->entry, at_pos);
}

/*! Add a range of NRI values to a list of nri_range structs.
 * Intelligently add and/or combine the entries in a list of NRI ranges to also include the NRI range given in 'add'.
 * The list remains sorted by 'first' values.
 * \param[inout] nri_ranges  List of talloc allocated struct osmo_nri_range entries to add the new range to.
 * \param[in] add  NRI range to add to 'nri_ranges'.
 * \returns 0 on success, negative on error (if the range in 'add' is invalid).
 */
int osmo_nri_ranges_add(struct osmo_nri_ranges *nri_ranges, const struct osmo_nri_range *add)
{
	struct osmo_nri_range *range;
	struct osmo_nri_range *range_next;
	struct osmo_nri_range *target = NULL;

	if (osmo_nri_range_validate(add, 255))
		return -1;
	if (!nri_ranges)
		return -1;

	/* Is there an entry overlapping this range? */
	llist_for_each_entry(range, &nri_ranges->entries, entry) {
		if (!nri_range_touches(range, add))
			continue;
		target = range;
	}

	if (!target) {
		/* No overlaps with existing ranges, create a new one. */
		target = talloc_zero(nri_ranges, struct osmo_nri_range);
		OSMO_ASSERT(target);
		*target = *add;
		nri_ranges_add_entry_sorted(nri_ranges, target);
		return 0;
	}

	/* Overlap found, join into existing entry */
	nri_range_extend(target, add);

	/* Remove redundant entries */
	llist_for_each_entry_safe(range, range_next, &nri_ranges->entries, entry) {
		if (range == target)
			continue;
		if (!nri_range_touches(target, range))
			continue;
		nri_range_extend(target, range);
		llist_del(&range->entry);
		talloc_free(range);
	}
	return 0;
}

/*! Remove a range of NRI values from a list of nri_range structs.
 * Intelligently drop and/or cut or split the entries in a list of NRI ranges to no longer include the NRI range given
 * in 'del'. Note that after this, the list may have more entries than before, if a range was split into two smaller
 * ranges.
 * \param[inout] nri_ranges  List of talloc allocated struct osmo_nri_range entries to remove values from.
 * \param[in] del  NRI range to remove from 'nri_ranges'.
 * \returns 0 on success, negative on error (if the range in 'del' is invalid).
 */
int osmo_nri_ranges_del(struct osmo_nri_ranges *nri_ranges, const struct osmo_nri_range *del)
{
	struct osmo_nri_range *range;
	struct osmo_nri_range *range_next;

	if (osmo_nri_range_validate(del, 255))
		return -1;
	if (!nri_ranges)
		return -1;

	llist_for_each_entry_safe(range, range_next, &nri_ranges->entries, entry) {
		bool head;
		bool tail;
		if (!nri_range_overlaps_range(range, del))
			continue;

		head = nri_v_matches_range(range, del->first) && (del->first > range->first);
		tail = nri_v_matches_range(range, del->last) && (del->last < range->last);

		if (head && tail) {
			/* Range cut in two */
			struct osmo_nri_range *new_tail;

			/* Add a new entry for the tail section */
			new_tail = talloc_zero(nri_ranges, struct osmo_nri_range);
			OSMO_ASSERT(new_tail);
			*new_tail = (struct osmo_nri_range){
				.first = del->last + 1,
				.last = range->last,
			};
			llist_add(&new_tail->entry, &range->entry);

			/* Existing entry becomes the head section */
			range->last = del->first - 1;
		} else if (head) {
			/* Range reduced, a head remains */
			range->last = del->first - 1;
		} else if (tail) {
			/* Range reduced, a tail remains */
			range->first = del->last + 1;
		} else {
			/* nothing remains */
			llist_del(&range->entry);
			talloc_free(range);
		}
	}
	return 0;
}

/*! Compose a human readable representation of a list of NRI ranges in a buffer, like "23..42,123..142".
 * \param[out] buf  Target buffer.
 * \param[in] buflen  sizeof(buf).
 * \param[in] nri_ranges  List NRI ranges.
 * \returns strlen() of string that would be written if the buffer is large enough, like snprintf().
 */
int osmo_nri_ranges_to_str_buf(char *buf, size_t buflen, const struct osmo_nri_ranges *nri_ranges)
{
	struct osmo_nri_range *range;
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	bool first = true;
	if (!nri_ranges || llist_empty(&nri_ranges->entries)) {
		OSMO_STRBUF_PRINTF(sb, "empty");
		return sb.chars_needed;
	}
	llist_for_each_entry(range, &nri_ranges->entries, entry) {
		OSMO_STRBUF_PRINTF(sb, "%s%d..%d", first ? "" : ",", range->first, range->last);
	}
	return sb.chars_needed;
}

/*! Compose a human readable representation of a list of NRI ranges in a talloc buffer, like "23..42,123..142".
 * \param[in] ctx  Talloc context.
 * \param[in] nri_ranges  List of NRI ranges.
 * \returns a talloc allocated string.
 */
char *osmo_nri_ranges_to_str_c(void *ctx, const struct osmo_nri_ranges *nri_ranges)
{
	OSMO_NAME_C_IMPL(ctx, 16, "ERROR", osmo_nri_ranges_to_str_buf, nri_ranges);
}

/*! Parse a string to an NRI value, allowing both decimal and hexadecimal formats; useful for VTY config
 * implementations.
 * \param[out] dst  Write the resulting NRI value to this location.
 * \param[in] str  Decimal "511" or hex "0x1ff" string to parse.
 * \returns 0 on success, negative on error.
 */
static int osmo_nri_parse(int16_t *dst, const char *str)
{
	int val;
	int base = 10;
	if (osmo_str_startswith(str, "0x"))
		base = 16;
	if (osmo_str_to_int(&val, str, base, 0, INT16_MAX))
		return -1;
	*dst = (int16_t)val;
	return 0;
}

/*! Parse string arguments to a struct osmo_nri_range; useful for VTY config implementations.
 * Validate and parse 'first' and optional 'last' string arguments into struct osmo_nri_range values.
 * The strings may be in decimal format ("511") or hexadecimal with leading "0x" ("0x1ff").
 * If only one of 'first'/'last' is provided, the resulting range will have only that value (first == last).
 * \param[out] nri_range  Target for parsed values.
 * \param[in] first_str  Decimal or hex string, representing the first value in the range, or NULL if omitted.
 * \param[in] last_str  Decimal or hex string, representing the last value in the range, or NULL if omitted.
 * \returns 0 on success, negative on error.
 */
static int osmo_nri_parse_range(struct osmo_nri_range *nri_range, const char *first_str, const char *last_str)
{
	if (!nri_range)
		return -1;
	if (!first_str) {
		first_str = last_str;
		last_str = NULL;
		if (!first_str)
			return -1;
	}
	if (osmo_nri_parse(&nri_range->first, first_str))
		return -1;
	nri_range->last = nri_range->first;
	if (last_str) {
		if (osmo_nri_parse(&nri_range->last, last_str))
			return -1;
	}
	return 0;
}

/*! VTY implementation for adding an NRI range to a list of ranges.
 * Parse one or, if present, two argv arguments, which must be numbers representing the first and last value to add to
 * the list of NRI ranges, in decimal format ("511") or hexadecimal with leading "0x" ("0x1ff"). If the range values
 * surpass the nri_bitlen, return a warning in 'message', but still add the values to the list.
 * \param[out] message  Returned string constant to alert the user with, or NULL if all is well.
 * \param[out] added_range  If not NULL, write the range parsing result to this location.
 * \param[in] nri_ranges  List NRI ranges to add to.
 * \param[in] argc  Argument count.
 * \param[in] argv  Argument list.
 * \param[in] nri_bitlen  Valid NRI range in nr of bits used.
 * \returns 0 on success, -1 on error, 1 for a warning (if adding was successful but the added range surpasses
 *          nri_bitlen).
 */
int osmo_nri_ranges_vty_add(const char **message, struct osmo_nri_range *added_range,
			    struct osmo_nri_ranges *nri_ranges, int argc, const char **argv, uint8_t nri_bitlen)
{
	struct osmo_nri_range add_range;
	if (osmo_nri_parse_range(&add_range, argv[0], argc > 1 ? argv[1] : NULL)) {
		*message = "Error: cannot parse NRI range";
		return -1;
	}

	if (added_range)
		*added_range = add_range;

	if (osmo_nri_ranges_add(nri_ranges, &add_range)) {
		*message = "Error: failed to add NRI range";
		return -1;
	}

	if (nri_bitlen <= OSMO_NRI_BITLEN_MAX && osmo_nri_range_validate(&add_range, nri_bitlen)) {
		*message = "Warning: NRI range surpasses current NRI bitlen";
		return 1;
	}

	*message = NULL;
	return 0;
}

/*! VTY implementation for removing an NRI range from a list of ranges.
 * Parse one or, if present, two argv arguments, which must be numbers representing the first and last value to remove
 * from the list of NRI ranges, in decimal format ("511") or hexadecimal with leading "0x" ("0x1ff").
 * \param[out] message  Returned string constant to alert the user with, or NULL if all is well.
 * \param[out] removed_range  If not NULL, write the range parsing result to this location.
 * \param[in] nri_ranges  List of NRI ranges to remove from.
 * \param[in] argc  Argument count.
 * \param[in] argv  Argument list.
 * \returns 0 on success, -1 on error, 1 for a warning.
 */
int osmo_nri_ranges_vty_del(const char **message, struct osmo_nri_range *removed_range,
			    struct osmo_nri_ranges *nri_ranges, int argc, const char **argv)
{
	struct osmo_nri_range del_range;
	if (osmo_nri_parse_range(&del_range, argv[0], argc > 1 ? argv[1] : NULL)) {
		*message = "Error: cannot parse NRI range";
		return -1;
	}

	if (removed_range)
		*removed_range = del_range;

	if (osmo_nri_ranges_del(nri_ranges, &del_range)) {
		*message = "Error: failed to remove NRI range";
		return -1;
	}

	*message = NULL;
	return 0;
}
