/*! \file gsm0502.h */

#pragma once

#include <stdint.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>

/* Table 5 Clause 7 TS 05.02 */
static inline unsigned int
gsm0502_get_n_pag_blocks(struct gsm48_control_channel_descr *chan_desc)
{
	if (chan_desc->ccch_conf == RSL_BCCH_CCCH_CONF_1_C)
		return 3 - chan_desc->bs_ag_blks_res;
	else
		return 9 - chan_desc->bs_ag_blks_res;
}

/* Chapter 6.5.2 of TS 05.02 */
static inline unsigned int
gsm0502_get_ccch_group(uint64_t imsi, unsigned int bs_cc_chans,
			unsigned int n_pag_blocks)
{
	return (imsi % 1000) % (bs_cc_chans * n_pag_blocks) / n_pag_blocks;
}

/* Chapter 6.5.2 of TS 05.02 */
static inline unsigned int
gsm0502_get_paging_group(uint64_t imsi, unsigned int bs_cc_chans,
			 int n_pag_blocks)
{
	return (imsi % 1000) % (bs_cc_chans * n_pag_blocks) % n_pag_blocks;
}

unsigned int
gsm0502_calc_paging_group(struct gsm48_control_channel_descr *chan_desc, uint64_t imsi);

enum gsm0502_fn_remap_channel {
	FN_REMAP_TCH_F,
	FN_REMAP_TCH_H0,
	FN_REMAP_TCH_H1,
	FN_REMAP_FACCH_F,
	FN_REMAP_FACCH_H0,
	FN_REMAP_FACCH_H1,
	FN_REMAP_MAX,
};

uint32_t gsm0502_fn_remap(uint32_t fn, enum gsm0502_fn_remap_channel channel);

uint16_t gsm0502_hop_seq_gen(const struct gsm_time *t,
			     uint8_t hsn, uint8_t maio,
			     size_t n, const uint16_t *ma);
