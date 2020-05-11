/*! \file gsm23236.h
 * API to handle Network Resource Indicator (NRI) values and ranges for MSC pooling, as in 3GPP TS 23.236.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>

#define OSMO_NRI_BITLEN_MIN 1
#define OSMO_NRI_BITLEN_MAX 15
#define OSMO_NRI_BITLEN_DEFAULT 10

/*! One range of NRI values. An NRI is a Network Resource Indicator, a number of a configured bit length (typically 10
 * bit). In an MSC pool for load balancing, it is used to indicate which MSC has issued a TMSI: the NRI is located with
 * its most significant bit located on the TMSI's second octet's most significant bit. See 3GPP TS 23.236. */
struct osmo_nri_range {
	struct llist_head entry;

	/*! First value of the NRI range, i.e. inclusive. */
	int16_t first;
	/*! Last value of the NRI range, i.e. inclusive. */
	int16_t last;
};

/*! A list of struct osmo_nri_range. Use osmo_nri_ranges_alloc() to create, and osmo_nri_ranges_free() (or talloc_free()
 * on the parent context) to destroy. Always use osmo_nri_ranges_add() to insert entries, to ensure that the list
 * remains sorted by 'first' values, which some of the osmo_nri_ranges API assumes to always be true.
 *
 * This struct serves as talloc context for the osmo_nri_range entries in the list, simplifying function signatures. It
 * also makes the API future proof, to easily accomodate possible future additions.
 */
struct osmo_nri_ranges {
	/* List of struct osmo_nri_range entries, talloc allocated from the parent struct osmo_nri_ranges. */
	struct llist_head entries;
};

int osmo_nri_v_validate(int16_t nri_v, uint8_t nri_bitlen);
bool osmo_nri_v_matches_ranges(int16_t nri_v, const struct osmo_nri_ranges *nri_ranges);
int osmo_nri_v_limit_by_ranges(int16_t *nri_v, const struct osmo_nri_ranges *nri_ranges, uint32_t nri_bitlen);

int osmo_tmsi_nri_v_get(int16_t *nri_v, uint32_t tmsi, uint8_t nri_bitlen);
int osmo_tmsi_nri_v_set(uint32_t *tmsi, int16_t nri_v, uint8_t nri_bitlen);
int osmo_tmsi_nri_v_limit_by_ranges(uint32_t *tmsi, const struct osmo_nri_ranges *nri_ranges, uint8_t nri_bitlen);

int osmo_nri_range_validate(const struct osmo_nri_range *range, uint8_t nri_bitlen);
bool osmo_nri_range_overlaps_ranges(const struct osmo_nri_range *range, const struct osmo_nri_ranges *nri_ranges);

struct osmo_nri_ranges *osmo_nri_ranges_alloc(void *ctx);
void osmo_nri_ranges_free(struct osmo_nri_ranges *nri_ranges);
int osmo_nri_ranges_add(struct osmo_nri_ranges *nri_ranges, const struct osmo_nri_range *add);
int osmo_nri_ranges_del(struct osmo_nri_ranges *nri_ranges, const struct osmo_nri_range *del);
int osmo_nri_ranges_vty_add(const char **message, struct osmo_nri_range *added_range,
			    struct osmo_nri_ranges *nri_ranges, int argc, const char **argv, uint8_t nri_bitlen);
int osmo_nri_ranges_vty_del(const char **message, struct osmo_nri_range *removed_range,
			    struct osmo_nri_ranges *nri_ranges, int argc, const char **argv);
int osmo_nri_ranges_to_str_buf(char *buf, size_t buflen, const struct osmo_nri_ranges *nri_ranges);
char *osmo_nri_ranges_to_str_c(void *ctx, const struct osmo_nri_ranges *nri_ranges);
