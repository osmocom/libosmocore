/*! \file gsm0502.h */

#pragma once

#include <stdint.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>

/* 4.3.3 TDMA frame number : constants and modular arithmetic */
#define GSM_TDMA_FN_DURATION_nS		4615384		/* in 1e−9 seconds (approx) */
#define GSM_TDMA_FN_DURATION_uS		4615		/* in 1e-6 seconds (approx) */

#define GSM_TDMA_SUPERFRAME		(26 * 51)
#define GSM_TDMA_HYPERFRAME		(2048 * GSM_TDMA_SUPERFRAME)

/*! Return the sum of two specified TDMA frame numbers (summation) */
#define GSM_TDMA_FN_SUM(a, b) \
	(((a) + (b)) % GSM_TDMA_HYPERFRAME)
/*! Return the difference of two specified TDMA frame numbers (subtraction) */
#define GSM_TDMA_FN_SUB(a, b) \
	(((a) + GSM_TDMA_HYPERFRAME - (b)) % GSM_TDMA_HYPERFRAME)
/*! Return the *minimum* difference of two specified TDMA frame numbers (distance) */
#define GSM_TDMA_FN_DIFF(a, b) \
	OSMO_MIN(GSM_TDMA_FN_SUB(a, b), GSM_TDMA_FN_SUB(b, a))

/*! Increment the given TDMA frame number by 1 and return the result (like ++fn) */
#define GSM_TDMA_FN_INC(fn) \
	((fn) = GSM_TDMA_FN_SUM((fn), 1))
/*! Decrement the given TDMA frame number by 1 and return the result (like --fn) */
#define GSM_TDMA_FN_DEC(fn) \
	((fn) = GSM_TDMA_FN_SUB((fn), 1))

/* Table 5 Clause 7 TS 05.02 */
static inline unsigned int
gsm0502_get_n_pag_blocks(const struct gsm48_control_channel_descr *chan_desc)
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
gsm0502_calc_paging_group(const struct gsm48_control_channel_descr *chan_desc, uint64_t imsi);

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
