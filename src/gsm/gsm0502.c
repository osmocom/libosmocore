/*! \file gsm0502.c
 * Paging helper code */
/*
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by Sylvain Munaut <tnt@246tNt.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm0502.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/logging.h>
#include <inttypes.h>

unsigned int
gsm0502_calc_paging_group(const struct gsm48_control_channel_descr *chan_desc, uint64_t imsi)
{
	int ccch_conf;
	int bs_cc_chans;
	int blocks;
	unsigned int group;

	ccch_conf = chan_desc->ccch_conf;
	bs_cc_chans = rsl_ccch_conf_to_bs_cc_chans(ccch_conf);
	/* code word + 2, as 2 channels equals 0x0 */
	blocks = gsm48_number_of_paging_subchannels(chan_desc);
	group = gsm0502_get_paging_group(imsi, bs_cc_chans, blocks);

	return group;
}

/* Clause 7 Table 1 of 5 Mapping of logical channels onto physical channels */
#define TCH_REPEAT_LENGTH 13
#define FACCH_F_REPEAT_LENGTH 13
#define FACCH_H_REPEAT_LENGTH 26

static const uint8_t gsm0502_tch_f_traffic_block_map[3][8] = {
	{0, 1, 2, 3, 4, 5, 6, 7},
	{4, 5, 6, 7, 8, 9, 10, 11},
	{8, 9, 10, 11, 0, 1, 2, 3}
};

static const uint8_t gsm0502_tch_h0_traffic_block_map[3][4] = {
	{0, 2, 4, 6},
	{4, 6, 8, 10},
	{8, 10, 0, 2}
};

static const uint8_t gsm0502_tch_h1_traffic_block_map[3][4] = {
	{1, 3, 5, 7},
	{5, 7, 9, 11},
	{9, 11, 1, 3}
};

static const uint8_t gsm0502_tch_f_facch_block_map[3][8] = {
	{0, 1, 2, 3, 4, 5, 6, 7},
	{4, 5, 6, 7, 8, 9, 10, 11},
	{8, 9, 10, 11, 0, 1, 2, 3}
};

static const uint8_t gsm0502_tch_h0_facch_block_map[3][6] = {
	{0, 2, 4, 6, 8, 10},
	{8, 10, 13, 15, 17, 19},
	{17, 19, 21, 23, 0, 2}
};

static const uint8_t gsm0502_tch_h1_facch_block_map[3][6] = {
	{1, 3, 5, 7, 9, 11},
	{9, 11, 14, 16, 18, 20},
	{18, 20, 22, 24, 1, 3}
};

/* Struct to describe a remapping function for block frame nbumbers. The member
 * blockend describes the ending of a block for which we want to determine the
 * beginning frame number. The member distance describes the value we need to
 * subtract from the blockend frame number in order to get the beginning of the
 * the block. The member cycle describes the Repeat length in TDMA frames we
 * are dealing with. For traffic channels this is always 13, for control
 * channels it is different. The member len simply defines amount of
 * blockendings and distances we store in the remap table */
struct fn_remap_table {
	unsigned int cycle;
	unsigned int len;
	uint8_t blockend[8];
	uint8_t distance[8];
};

/* Memory to hold the remap tables we will automatically generate on startup */
static struct fn_remap_table tch_f_remap_table;
static struct fn_remap_table tch_h0_remap_table;
static struct fn_remap_table tch_h1_remap_table;
static struct fn_remap_table facch_f_remap_table;
static struct fn_remap_table facch_h0_remap_table;
static struct fn_remap_table facch_h1_remap_table;
static struct fn_remap_table *fn_remap_table_ptr[FN_REMAP_MAX];

/* Generate a remap table from a given block map. A block map lists the block
 * layout as defined in GSM 05.02, Clause 7 Table 1 of 5, one block per row.
 * Parameters:
 *   table: name of the remap table to output
 *   map: traffic block map input
 *   rows: length of the traffic block map
 *   cols: witdh of the traffic block map
 *   repeat: repeat length in TDMA frames (cycle) */
#define fn_remap_table_from_traffic_block_map(table, map, rows, cols, repeat) \
	for(i=0;i<rows;i++) { \
		table.blockend[i] = map[i][cols-1]; \
		if(map[i][0] <= map[i][cols-1]) \
			table.distance[i] = map[i][cols-1] - map[i][0]; \
		else \
			table.distance[i] = repeat - map[i][0] + map[i][cols-1]; \
	} \
	table.cycle = repeat; \
	table.len = rows;

/* Automatically generate fn remap tables on startupmake */
static __attribute__ ((constructor))
void fn_remap_tables_build(void)
{
	/* Required by macro */
	unsigned int i;

	/* Generate tables */
	fn_remap_table_from_traffic_block_map(tch_f_remap_table,
					      gsm0502_tch_f_traffic_block_map, 3, 8,
					      TCH_REPEAT_LENGTH);
	fn_remap_table_from_traffic_block_map(tch_h0_remap_table,
					      gsm0502_tch_h0_traffic_block_map, 3, 4,
					      TCH_REPEAT_LENGTH);
	fn_remap_table_from_traffic_block_map(tch_h1_remap_table,
					      gsm0502_tch_h1_traffic_block_map, 3, 4,
					      TCH_REPEAT_LENGTH);
	fn_remap_table_from_traffic_block_map(facch_f_remap_table,
					      gsm0502_tch_f_facch_block_map, 3, 8,
					      FACCH_F_REPEAT_LENGTH);
	fn_remap_table_from_traffic_block_map(facch_h0_remap_table,
					      gsm0502_tch_h0_facch_block_map, 3, 6,
					      FACCH_H_REPEAT_LENGTH);
	fn_remap_table_from_traffic_block_map(facch_h1_remap_table,
					      gsm0502_tch_h1_facch_block_map, 3, 6,
					      FACCH_H_REPEAT_LENGTH);

	fn_remap_table_ptr[FN_REMAP_TCH_F] = &tch_f_remap_table;
	fn_remap_table_ptr[FN_REMAP_TCH_H0] = &tch_h0_remap_table;
	fn_remap_table_ptr[FN_REMAP_TCH_H1] = &tch_h1_remap_table;
	fn_remap_table_ptr[FN_REMAP_FACCH_F] = &facch_f_remap_table;
	fn_remap_table_ptr[FN_REMAP_FACCH_H0] = &facch_h0_remap_table;
	fn_remap_table_ptr[FN_REMAP_FACCH_H1] = &facch_h1_remap_table;
}

/*! Calculate the frame number of the beginning of a block.
 *  \param[in] fn frame number of the block ending.
 *  \param[in] channel channel type (see also enum fn_remap_channel).
 *  \returns frame number of the beginning of the block or input frame number if
 *           remapping was not possible. */
uint32_t gsm0502_fn_remap(uint32_t fn, enum gsm0502_fn_remap_channel channel)
{
	uint8_t fn_cycle;
	uint8_t i;
	int sub = -1;
	struct fn_remap_table *table;

	OSMO_ASSERT(channel < ARRAY_SIZE(fn_remap_table_ptr));
        table = fn_remap_table_ptr[(uint8_t)channel];

	fn_cycle = fn % table->cycle;

	for (i = 0; i < table->len; i++) {
		if (table->blockend[i] == fn_cycle) {
			sub = table->distance[i];
			break;
		}
	}

	if (sub == -1) {
		LOGP(DLGLOBAL, LOGL_ERROR, "could not remap frame number!, fn=%" PRIu32 "\n", fn);
		return fn;
	}

	return GSM_TDMA_FN_SUB(fn, sub);
}

/* Magic numbers (RNTABLE) for pseudo-random hopping sequence generation. */
static const uint8_t rn_table[114] = {
	 48,  98,  63,   1,  36,  95,  78, 102,  94,  73,
	  0,  64,  25,  81,  76,  59, 124,  23, 104, 100,
	101,  47, 118,  85,  18,  56,  96,  86,  54,   2,
	 80,  34, 127,  13,   6,  89,  57, 103,  12,  74,
	 55, 111,  75,  38, 109,  71, 112,  29,  11,  88,
	 87,  19,   3,  68, 110,  26,  33,  31,   8,  45,
	 82,  58,  40, 107,  32,   5, 106,  92,  62,  67,
	 77, 108, 122,  37,  60,  66, 121,  42,  51, 126,
	117, 114,   4,  90,  43,  52,  53, 113, 120,  72,
	 16,  49,   7,  79, 119,  61,  22,  84,   9,  97,
	 91,  15,  21,  24,  46,  39,  93, 105,  65,  70,
	125,  99,  17, 123,
};

/*! Hopping sequence generation as per 3GPP TS 45.002, section 6.2.3.
 *  \param[in] t GSM time (TDMA frame number, T1/T2/T3).
 *  \param[in] hsn Hopping Sequence Number.
 *  \param[in] maio Mobile Allocation Index Offset.
 *  \param[in] n number of entries in mobile allocation (arfcn table).
 *  \param[in] ma array of ARFCNs (sorted in ascending order)
 *		  representing the Mobile Allocation.
 *  \returns ARFCN to use for given input parameters at time 't'
 *	     or Mobile Allocation Index if ma == NULL.
 */
uint16_t gsm0502_hop_seq_gen(const struct gsm_time *t,
			     uint8_t hsn, uint8_t maio,
			     size_t n, const uint16_t *ma)
{
	unsigned int mai;

	if (hsn == 0) {
		/* cyclic hopping */
		mai = (t->fn + maio) % n;
	} else {
		/* pseudo random hopping */
		int m, mp, tp, s, pnm;

		pnm = (n >> 0) | (n >> 1)
		    | (n >> 2) | (n >> 3)
		    | (n >> 4) | (n >> 5)
		    | (n >> 6);

		m = t->t2 + rn_table[(hsn ^ (t->t1 & 63)) + t->t3];
		mp = m & pnm;

		if (mp < n)
			s = mp;
		else {
			tp = t->t3 & pnm;
			s = (mp + tp) % n;
		}

		mai = (s + maio) % n;
	}

	return ma ? ma[mai] : mai;
}
