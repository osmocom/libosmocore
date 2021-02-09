/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface,
 * rest octet handling according to
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
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
 * SPDX-License-Identifier: GPL-2.0+
 *
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>

#include <osmocom/core/bitvec.h>
#include <osmocom/gsm/bitvec_gsm.h>
#include <osmocom/gsm/sysinfo.h>
#include <osmocom/gsm/gsm48_arfcn_range_encode.h>
#include <osmocom/gsm/gsm48_rest_octets.h>

/* generate SI1 rest octets */
int osmo_gsm48_rest_octets_si1_encode(uint8_t *data, uint8_t *nch_pos, int is1800_net)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = data;
	bv.data_len = 1;

	if (nch_pos) {
		bitvec_set_bit(&bv, H);
		bitvec_set_uint(&bv, *nch_pos, 5);
	} else {
		bitvec_set_bit(&bv, L);
	}

	if (is1800_net)
		bitvec_set_bit(&bv, L);
	else
		bitvec_set_bit(&bv, H);

	bitvec_spare_padding(&bv, 6);
	return bv.data_len;
}

/* Append Repeated E-UTRAN Neighbour Cell to bitvec: see 3GPP TS 44.018 Table 10.5.2.33b.1 */
static inline bool append_eutran_neib_cell(struct bitvec *bv, const struct osmo_earfcn_si2q *e, size_t *e_offset,
					   uint8_t budget)
{
	unsigned i, skip = 0;
	size_t offset = *e_offset;
	int16_t rem = budget - 6; /* account for mandatory stop bit and THRESH_E-UTRAN_high */
	uint8_t earfcn_budget;

	if (budget <= 6)
		return false;

	OSMO_ASSERT(budget <= SI2Q_MAX_LEN);

	/* first we have to properly adjust budget requirements */
	if (e->prio_valid) /* E-UTRAN_PRIORITY: 3GPP TS 45.008*/
		rem -= 4;
	else
		rem--;

	if (e->thresh_lo_valid) /* THRESH_E-UTRAN_low: */
		rem -= 6;
	else
		rem--;

	if (e->qrxlm_valid) /* E-UTRAN_QRXLEVMIN: */
		rem -= 6;
	else
		rem--;

	if (rem < 0)
		return false;

	/* now we can proceed with actually adding EARFCNs within adjusted budget limit */
	for (i = 0; i < e->length; i++) {
		if (e->arfcn[i] != OSMO_EARFCN_INVALID) {
			if (skip < offset) {
				skip++; /* ignore EARFCNs added on previous calls */
			} else {
				earfcn_budget = 17; /* compute budget per-EARFCN */
				if (OSMO_EARFCN_MEAS_INVALID == e->meas_bw[i])
					earfcn_budget++;
				else
					earfcn_budget += 4;

				if (rem - earfcn_budget < 0)
					break;
				else {
					(*e_offset)++;
					rem -= earfcn_budget;

					if (rem < 0)
						return false;

					bitvec_set_bit(bv, 1); /* EARFCN: */
					bitvec_set_uint(bv, e->arfcn[i], 16);

					if (OSMO_EARFCN_MEAS_INVALID == e->meas_bw[i])
						bitvec_set_bit(bv, 0);
					else { /* Measurement Bandwidth: 9.1.54 */
						bitvec_set_bit(bv, 1);
						bitvec_set_uint(bv, e->meas_bw[i], 3);
					}
				}
			}
		}
	}

	/* stop bit - end of EARFCN + Measurement Bandwidth sequence */
	bitvec_set_bit(bv, 0);

	/* Note: we don't support different EARFCN arrays each with different priority, threshold etc. */

	if (e->prio_valid) {
		/* E-UTRAN_PRIORITY: 3GPP TS 45.008*/
		bitvec_set_bit(bv, 1);
		bitvec_set_uint(bv, e->prio, 3);
	} else {
		bitvec_set_bit(bv, 0);
	}

	/* THRESH_E-UTRAN_high */
	bitvec_set_uint(bv, e->thresh_hi, 5);

	if (e->thresh_lo_valid) {
		/* THRESH_E-UTRAN_low: */
		bitvec_set_bit(bv, 1);
		bitvec_set_uint(bv, e->thresh_lo, 5);
	} else {
		bitvec_set_bit(bv, 0);
	}

	if (e->qrxlm_valid) {
		/* E-UTRAN_QRXLEVMIN: */
		bitvec_set_bit(bv, 1);
		bitvec_set_uint(bv, e->qrxlm, 5);
	} else {
		bitvec_set_bit(bv, 0);
	}

	return true;
}

static inline void append_earfcn(struct bitvec *bv, const struct osmo_earfcn_si2q *e, size_t *e_offset, uint8_t budget)
{
	bool appended;
	unsigned int old = bv->cur_bit; /* save current position to make rollback possible */
	int rem = ((int)budget) - 40;
	if (rem <= 0)
		return;

	OSMO_ASSERT(budget <= SI2Q_MAX_LEN);

	/* Additions in Rel-5: */
	bitvec_set_bit(bv, H);
	/* No 3G Additional Measurement Param. Descr. */
	bitvec_set_bit(bv, 0);
	/* No 3G ADDITIONAL MEASUREMENT Param. Descr. 2 */
	bitvec_set_bit(bv, 0);
	/* Additions in Rel-6: */
	bitvec_set_bit(bv, H);
	/* 3G_CCN_ACTIVE */
	bitvec_set_bit(bv, 0);
	/* Additions in Rel-7: */
	bitvec_set_bit(bv, H);
	/* No 700_REPORTING_OFFSET */
	bitvec_set_bit(bv, 0);
	/* No 810_REPORTING_OFFSET */
	bitvec_set_bit(bv, 0);
	/* Additions in Rel-8: */
	bitvec_set_bit(bv, H);

	/* Priority and E-UTRAN Parameters Description */
	bitvec_set_bit(bv, 1);

	/* budget: 10 bits used above */

	/* Serving Cell Priority Parameters Descr. is Present,
	* see also: 3GPP TS 44.018, Table 10.5.2.33b.1 */
	bitvec_set_bit(bv, 1);

	/* GERAN_PRIORITY */
	bitvec_set_uint(bv, 0, 3);

	/* THRESH_Priority_Search */
	bitvec_set_uint(bv, 0, 4);

	/* THRESH_GSM_low */
	bitvec_set_uint(bv, 0, 4);

	/* H_PRIO */
	bitvec_set_uint(bv, 0, 2);

	/* T_Reselection */
	bitvec_set_uint(bv, 0, 2);

	/* budget: 26 bits used above */

	/* No 3G Priority Parameters Description */
	bitvec_set_bit(bv, 0);
	/* E-UTRAN Parameters Description */
	bitvec_set_bit(bv, 1);

	/* E-UTRAN_CCN_ACTIVE */
	bitvec_set_bit(bv, 0);
	/* E-UTRAN_Start: 9.1.54 */
	bitvec_set_bit(bv, 1);
	/* E-UTRAN_Stop: 9.1.54 */
	bitvec_set_bit(bv, 1);

	/* No E-UTRAN Measurement Parameters Descr. */
	bitvec_set_bit(bv, 0);
	/* No GPRS E-UTRAN Measurement Param. Descr. */
	bitvec_set_bit(bv, 0);

	/* Note: each of next 3 "repeated" structures might be repeated any
	   (0, 1, 2...) times - we only support 1 and 0 */

	/* Repeated E-UTRAN Neighbour Cells */
	bitvec_set_bit(bv, 1);

	/* budget: 34 bits used above */

	appended = append_eutran_neib_cell(bv, e, e_offset, rem);
	if (!appended) { /* appending is impossible within current budget: rollback */
		bv->cur_bit = old;
		return;
	}

	/* budget: further 6 bits used below, totalling 40 bits */

	/* stop bit - end of Repeated E-UTRAN Neighbour Cells sequence: */
	bitvec_set_bit(bv, 0);

	/* Note: following 2 repeated structs are not supported ATM */
	/* stop bit - end of Repeated E-UTRAN Not Allowed Cells sequence: */
	bitvec_set_bit(bv, 0);
	/* stop bit - end of Repeated E-UTRAN PCID to TA mapping sequence: */
	bitvec_set_bit(bv, 0);

	/* Priority and E-UTRAN Parameters Description ends here */
	/* No 3G CSG Description */
	bitvec_set_bit(bv, 0);
	/* No E-UTRAN CSG Description */
	bitvec_set_bit(bv, 0);
	/* No Additions in Rel-9: */
	bitvec_set_bit(bv, L);
}

static int range_encode(enum osmo_gsm48_range r, int *arfcns, int arfcns_used, int *w,
			int f0, uint8_t *chan_list)
{
	/*
	 * Manipulate the ARFCN list according to the rules in J4 depending
	 * on the selected range.
	 */
	int rc, f0_included;

	osmo_gsm48_range_enc_filter_arfcns(arfcns, arfcns_used, f0, &f0_included);

	rc = osmo_gsm48_range_enc_arfcns(r, arfcns, arfcns_used, w, 0);
	if (rc < 0)
		return rc;

	/* Select the range and the amount of bits needed */
	switch (r) {
	case OSMO_GSM48_ARFCN_RANGE_128:
		return osmo_gsm48_range_enc_128(chan_list, f0, w);
	case OSMO_GSM48_ARFCN_RANGE_256:
		return osmo_gsm48_range_enc_256(chan_list, f0, w);
	case OSMO_GSM48_ARFCN_RANGE_512:
		return osmo_gsm48_range_enc_512(chan_list, f0, w);
	case OSMO_GSM48_ARFCN_RANGE_1024:
		return osmo_gsm48_range_enc_1024(chan_list, f0, f0_included, w);
	default:
		return -ERANGE;
	};

	return f0_included;
}

static inline int f0_helper(int *sc, size_t length, uint8_t *chan_list)
{
	int w[OSMO_GSM48_RANGE_ENC_MAX_ARFCNS] = { 0 };

	return range_encode(OSMO_GSM48_ARFCN_RANGE_1024, sc, length, w, 0, chan_list);
}

/* Return p(n) for given NR_OF_TDD_CELLS - see Table 9.1.54.1a, 3GPP TS 44.018 */
static unsigned range1024_p(unsigned n)
{
	switch (n) {
	case 0: return 0;
	case 1: return 10;
	case 2: return 19;
	case 3: return 28;
	case 4: return 36;
	case 5: return 44;
	case 6: return 52;
	case 7: return 60;
	case 8: return 67;
	case 9: return 74;
	case 10: return 81;
	case 11: return 88;
	case 12: return 95;
	case 13: return 102;
	case 14: return 109;
	case 15: return 116;
	case 16: return 122;
	default: return 0;
	}
}

/* Estimate how many bits it'll take to append single FDD UARFCN */
static inline int append_utran_fdd_length(uint16_t u, const int *sc, size_t sc_len, size_t length)
{
	uint8_t chan_list[16] = { 0 };
	int tmp[sc_len], f0;

	memcpy(tmp, sc, sizeof(tmp));

	f0 = f0_helper(tmp, length, chan_list);
	if (f0 < 0)
		return f0;

	return 21 + range1024_p(length);
}

/* Append single FDD UARFCN */
static inline int append_utran_fdd(struct bitvec *bv, uint16_t u, int *sc, size_t length)
{
	uint8_t chan_list[16] = { 0 };
	int f0 = f0_helper(sc, length, chan_list);

	if (f0 < 0)
		return f0;

	/* Repeated UTRAN FDD Neighbour Cells */
	bitvec_set_bit(bv, 1);

	/* FDD-ARFCN */
	bitvec_set_bit(bv, 0);
	bitvec_set_uint(bv, u, 14);

	/* FDD_Indic0: parameter value '0000000000' is a member of the set? */
	bitvec_set_bit(bv, f0);
	/* NR_OF_FDD_CELLS */
	bitvec_set_uint(bv, length, 5);

	f0 = bv->cur_bit;
	bitvec_add_range1024(bv, (struct gsm48_range_1024 *)chan_list);
	bv->cur_bit = f0 + range1024_p(length);

	return 21 + range1024_p(length);
}

static inline int try_adding_uarfcn(struct bitvec *bv, uint16_t *scramble_list,
				    size_t uarfcn_length, size_t *u_offset,
				    uint16_t uarfcn, uint8_t num_sc, uint8_t start_pos, uint8_t budget)
{
	int i, k, rc, a[uarfcn_length];

	if (budget < 23)
		return -ENOMEM;

	/* copy corresponding Scrambling Codes: range encoder make in-place modifications */
	for (i = start_pos, k = 0; i < num_sc; a[k++] = scramble_list[i++]);

	/* estimate bit length requirements */
	rc = append_utran_fdd_length(uarfcn, a, uarfcn_length, k);
	if (rc < 0)
		return rc; /* range encoder failure */

	if (budget - rc <= 0)
		return -ENOMEM; /* we have ran out of budget in current SI2q */

	/* compute next offset */
	*u_offset += k;

	return budget - append_utran_fdd(bv, uarfcn, a, k);
}

/* Append multiple FDD UARFCNs */
static inline void append_uarfcns(struct bitvec *bv, const uint16_t *uarfcn_list, size_t *u_offset,
				  size_t uarfcn_length, uint16_t *scramble_list, uint8_t budget)
{
	int i, rem = budget - 7, st = *u_offset; /* account for constant bits right away */
	uint16_t cu = uarfcn_list[*u_offset]; /* caller ensures that length is positive */

	OSMO_ASSERT(budget <= SI2Q_MAX_LEN);

	if (budget <= 7)
		return;

	/* 3G Neighbour Cell Description */
	bitvec_set_bit(bv, 1);
	/* No Index_Start_3G */
	bitvec_set_bit(bv, 0);
	/* No Absolute_Index_Start_EMR */
	bitvec_set_bit(bv, 0);

	/* UTRAN FDD Description */
	bitvec_set_bit(bv, 1);
	/* No Bandwidth_FDD */
	bitvec_set_bit(bv, 0);

	for (i = *u_offset; i <= uarfcn_length; i++)
		if (uarfcn_list[i] != cu) { /* we've reached new UARFCN */
			rem = try_adding_uarfcn(bv, scramble_list, uarfcn_length, u_offset, cu, i, st, rem);
			if (rem < 0)
				break;

			if (i < uarfcn_length) {
				cu = uarfcn_list[i];
				st = i;
			} else {
				break;
			}
		}

	/* stop bit - end of Repeated UTRAN FDD Neighbour Cells */
	bitvec_set_bit(bv, 0);

	/* UTRAN TDD Description */
	bitvec_set_bit(bv, 0);
}

static size_t si2q_earfcn_count(const struct osmo_earfcn_si2q *e)
{
	unsigned i, ret = 0;

	if (!e)
		return 0;

	for (i = 0; i < e->length; i++)
		if (e->arfcn[i] != OSMO_EARFCN_INVALID)
			ret++;

	return ret;
}

/* generate SI2quater rest octets: 3GPP TS 44.018 § 10.5.2.33b */
int osmo_gsm48_rest_octets_si2quater_encode(uint8_t *data, uint8_t si2q_index, uint8_t si2q_count,
					    const uint16_t *uarfcn_list, size_t *u_offset,
					    size_t uarfcn_length, uint16_t *scramble_list,
					    struct osmo_earfcn_si2q *si2quater_neigh_list,
					    size_t *e_offset)
{
	int rc;
	struct bitvec bv;

	if (si2q_count < si2q_index)
		return -EINVAL;

	bv.data = data;
	bv.data_len = 20;
	bitvec_zero(&bv);

	/* BA_IND: Set to '0' as that's what we use for SI2xxx type,
	 * whereas '1' is used for SI5xxx type messages. The point here
	 * is to be able to correlate whether a given MS measurement
	 * report was using the neighbor cells advertised in SI2 or in
	 * SI5, as those two could very well be different */
	bitvec_set_bit(&bv, 0);
	/* 3G_BA_IND */
	bitvec_set_bit(&bv, 1);
	/* MP_CHANGE_MARK */
	bitvec_set_bit(&bv, 0);

	/* SI2quater_INDEX */
	bitvec_set_uint(&bv, si2q_index, 4);
	/* SI2quater_COUNT */
	bitvec_set_uint(&bv, si2q_count, 4);

	/* No Measurement_Parameters Description */
	bitvec_set_bit(&bv, 0);
	/* No GPRS_Real Time Difference Description */
	bitvec_set_bit(&bv, 0);
	/* No GPRS_BSIC Description */
	bitvec_set_bit(&bv, 0);
	/* No GPRS_REPORT PRIORITY Description */
	bitvec_set_bit(&bv, 0);
	/* No GPRS_MEASUREMENT_Parameters Description */
	bitvec_set_bit(&bv, 0);
	/* No NC Measurement Parameters */
	bitvec_set_bit(&bv, 0);
	/* No extension (length) */
	bitvec_set_bit(&bv, 0);

	rc = SI2Q_MAX_LEN - (bv.cur_bit + 3);
	if (rc > 0 && uarfcn_length - *u_offset > 0)
		append_uarfcns(&bv, uarfcn_list, u_offset, uarfcn_length, scramble_list, rc);
	else /* No 3G Neighbour Cell Description */
		bitvec_set_bit(&bv, 0);

	/* No 3G Measurement Parameters Description */
	bitvec_set_bit(&bv, 0);
	/* No GPRS_3G_MEASUREMENT Parameters Descr. */
	bitvec_set_bit(&bv, 0);

	rc = SI2Q_MAX_LEN - bv.cur_bit;
	if (rc > 0 && si2q_earfcn_count(si2quater_neigh_list) - *e_offset > 0)
		append_earfcn(&bv, si2quater_neigh_list, e_offset, rc);
	else /* No Additions in Rel-5: */
		bitvec_set_bit(&bv, L);

	bitvec_spare_padding(&bv, (bv.data_len * 8) - 1);
	return bv.data_len;
}

/* Append selection parameters to bitvec */
static void append_selection_params(struct bitvec *bv,
				    const struct osmo_gsm48_si_selection_params *sp)
{
	if (sp->present) {
		bitvec_set_bit(bv, H);
		bitvec_set_bit(bv, sp->cbq);
		bitvec_set_uint(bv, sp->cell_resel_off, 6);
		bitvec_set_uint(bv, sp->temp_offs, 3);
		bitvec_set_uint(bv, sp->penalty_time, 5);
	} else {
		bitvec_set_bit(bv, L);
	}
}

/* Append power offset to bitvec */
static void append_power_offset(struct bitvec *bv,
				const struct osmo_gsm48_si_power_offset *po)
{
	if (po->present) {
		bitvec_set_bit(bv, H);
		bitvec_set_uint(bv, po->power_offset, 2);
	} else {
		bitvec_set_bit(bv, L);
	}
}

/* Append GPRS indicator to bitvec */
static void append_gprs_ind(struct bitvec *bv,
			    const struct osmo_gsm48_si3_gprs_ind *gi)
{
	if (gi->present) {
		bitvec_set_bit(bv, H);
		bitvec_set_uint(bv, gi->ra_colour, 3);
		/* 0 == SI13 in BCCH Norm, 1 == SI13 sent on BCCH Ext */
		bitvec_set_bit(bv, gi->si13_position);
	} else {
		bitvec_set_bit(bv, L);
	}
}

/* Generate SI3 Rest Octests (Chapter 10.5.2.34 / Table 10.4.72) */
int osmo_gsm48_rest_octets_si3_encode(uint8_t *data, const struct osmo_gsm48_si_ro_info *si3)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = data;
	bv.data_len = 4;

	/* Optional Selection Parameters */
	append_selection_params(&bv, &si3->selection_params);

	/* Optional Power Offset */
	append_power_offset(&bv, &si3->power_offset);

	/* Do we have a SI2ter on the BCCH? */
	if (si3->si2ter_indicator)
		bitvec_set_bit(&bv, H);
	else
		bitvec_set_bit(&bv, L);

	/* Early Classmark Sending Control */
	if (si3->early_cm_ctrl)
		bitvec_set_bit(&bv, H);
	else
		bitvec_set_bit(&bv, L);

	/* Do we have a SI Type 9 on the BCCH? */
	if (si3->scheduling.present) {
		bitvec_set_bit(&bv, H);
		bitvec_set_uint(&bv, si3->scheduling.where, 3);
	} else {
		bitvec_set_bit(&bv, L);
	}

	/* GPRS Indicator */
	append_gprs_ind(&bv, &si3->gprs_ind);

	/* 3G Early Classmark Sending Restriction. If H, then controlled by
	 * early_cm_ctrl above */
	if (si3->early_cm_restrict_3g)
		bitvec_set_bit(&bv, L);
	else
		bitvec_set_bit(&bv, H);

	if (si3->si2quater_indicator) {
		bitvec_set_bit(&bv, H); /* indicator struct present */
		bitvec_set_uint(&bv, 0, 1); /* message is sent on BCCH Norm */
	}

	bitvec_spare_padding(&bv, (bv.data_len*8)-1);
	return bv.data_len;
}

static int append_lsa_params(struct bitvec *bv,
			     const struct osmo_gsm48_lsa_params *lsa_params)
{
	/* FIXME */
	return -1;
}

/* Generate SI4 Rest Octets (Chapter 10.5.2.35) */
int osmo_gsm48_rest_octets_si4_encode(uint8_t *data, const struct osmo_gsm48_si_ro_info *si4, int len)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = data;
	bv.data_len = len;

	/* SI4 Rest Octets O */
	append_selection_params(&bv, &si4->selection_params);
	append_power_offset(&bv, &si4->power_offset);
	append_gprs_ind(&bv, &si4->gprs_ind);

	if (0 /* FIXME */) {
		/* H and SI4 Rest Octets S */
		bitvec_set_bit(&bv, H);

		/* LSA Parameters */
		if (si4->lsa_params.present) {
			bitvec_set_bit(&bv, H);
			append_lsa_params(&bv, &si4->lsa_params);
		} else {
			bitvec_set_bit(&bv, L);
		}

		/* Cell Identity */
		if (1) {
			bitvec_set_bit(&bv, H);
			bitvec_set_uint(&bv, si4->cell_id, 16);
		} else {
			bitvec_set_bit(&bv, L);
		}

		/* LSA ID Information */
		if (0) {
			bitvec_set_bit(&bv, H);
			/* FIXME */
		} else {
			bitvec_set_bit(&bv, L);
		}
	} else {
		/* L and break indicator */
		bitvec_set_bit(&bv, L);
		bitvec_set_bit(&bv, si4->break_ind ? H : L);
	}

	return bv.data_len;
}


/* GSM 04.18 ETSI TS 101 503 V8.27.0 (2006-05)

<SI6 rest octets> ::=
{L | H <PCH and NCH info>}
{L | H <VBS/VGCS options : bit(2)>}
{ < DTM_support : bit == L > I < DTM_support : bit == H >
< RAC : bit (8) >
< MAX_LAPDm : bit (3) > }
< Band indicator >
{ L | H < GPRS_MS_TXPWR_MAX_CCH : bit (5) > }
<implicit spare >;
*/
int osmo_gsm48_rest_octets_si6_encode(uint8_t *data, const struct osmo_gsm48_si6_ro_info *in)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = data;
	bv.data_len = 1;

	if (in->pch_nch_info.present) {
		bitvec_set_bit(&bv, H);
		bitvec_set_bit(&bv, !!in->pch_nch_info.paging_channel_restructuring);
		bitvec_set_uint(&bv, in->pch_nch_info.nln_sacch, 2);
		if (in->pch_nch_info.call_priority_present) {
			bitvec_set_bit(&bv, 1);
			bitvec_set_uint(&bv, in->pch_nch_info.call_priority, 3);
		} else {
			bitvec_set_bit(&bv, 0);
		}
		bitvec_set_bit(&bv, !!in->pch_nch_info.nln_status_sacch);
	} else {
		bitvec_set_bit(&bv, L);
	}

	if (in->vbs_vgcs_options.present) {
		bitvec_set_bit(&bv, H);
		bitvec_set_bit(&bv, !!in->vbs_vgcs_options.inband_notifications);
		bitvec_set_bit(&bv, !!in->vbs_vgcs_options.inband_pagings);
	} else {
		bitvec_set_bit(&bv, L);
	}

	if (in->dtm_support.present) {
		bitvec_set_bit(&bv, H);
		bitvec_set_uint(&bv, in->dtm_support.rac, 8);
		bitvec_set_uint(&bv, in->dtm_support.max_lapdm, 3);
	} else {
		bitvec_set_bit(&bv, L);
	}

	if (in->band_indicator_1900)
		bitvec_set_bit(&bv, H);
	else
		bitvec_set_bit(&bv, L);

	if (in->gprs_ms_txpwr_max_ccch.present) {
		bitvec_set_bit(&bv, H);
		bitvec_set_uint(&bv, in->gprs_ms_txpwr_max_ccch.max_txpwr, 5);
	} else {
		bitvec_set_bit(&bv, L);
	}

	bitvec_spare_padding(&bv, (bv.data_len * 8) - 1);
	return bv.data_len;
}


static unsigned int decode_t3192(unsigned int t3192)
{
	/* See also 3GPP TS 44.060
	   Table 12.24.2: GPRS Cell Options information element details */
	static const unsigned int decode_t3192_tbl[8] = {500, 1000, 1500, 0, 80, 120, 160, 200};
	OSMO_ASSERT(t3192 <= 7);
	return decode_t3192_tbl[t3192];
}

static unsigned int decode_drx_timer(unsigned int drx)
{
	static const unsigned int decode_drx_timer_tbl[8] = {0, 1, 2, 4, 8, 16, 32, 64};
	OSMO_ASSERT(drx <= 7);
	return decode_drx_timer_tbl[drx];
}

static int decode_gprs_cell_opt(struct osmo_gprs_cell_options *gco, struct bitvec *bv)
{
	gco->nmo = bitvec_get_uint(bv, 2);
	gco->t3168 = (bitvec_get_uint(bv, 3) + 1) * 500;
	gco->t3192 = decode_t3192(bitvec_get_uint(bv, 3));
	gco->drx_timer_max = decode_drx_timer(bitvec_get_uint(bv, 3));

	/* ACCESS_BURST_TYPE: */
	bitvec_get_uint(bv, 1);
	/* CONTROL_ACK_TYPE: */
	gco->ctrl_ack_type_use_block = bitvec_get_uint(bv, 1);
	gco->bs_cv_max = bitvec_get_uint(bv, 4);

	if (bitvec_get_uint(bv, 1)) {
		bitvec_get_uint(bv, 3);	/* DEC */
		bitvec_get_uint(bv, 3);	/* INC */
		bitvec_get_uint(bv, 3);	/* MAX */
	}

	if (bitvec_get_uint(bv, 1)) {
		int ext_len = bitvec_get_uint(bv, 6);
		if (ext_len < 0)
			return ext_len;
		unsigned int cur_bit = bv->cur_bit;
		/* Extension Information */
		/* R99 extension: */
		gco->ext_info.egprs_supported = bitvec_get_uint(bv, 1);
		if (gco->ext_info.egprs_supported) {
			gco->ext_info.use_egprs_p_ch_req = !bitvec_get_uint(bv, 1);
			gco->ext_info.bep_period = bitvec_get_uint(bv, 4);
		}
		gco->ext_info.pfc_supported = bitvec_get_uint(bv, 1);
		gco->ext_info.dtm_supported = bitvec_get_uint(bv, 1);
		gco->ext_info.bss_paging_coordination = bitvec_get_uint(bv, 1);
		/* REL-4 extension: */
		gco->ext_info.ccn_active = bitvec_get_uint(bv, 1);
		bitvec_get_uint(bv, 1); /* NW_EXT_UTBF */
		bv->cur_bit = cur_bit + ext_len + 1;
	}
	return 0;
}

static void decode_gprs_pwr_ctrl_pars(struct osmo_gprs_power_ctrl_pars *pcp, struct bitvec *bv)
{
	pcp->alpha = bitvec_get_uint(bv, 4);
	pcp->t_avg_w = bitvec_get_uint(bv,5);
	pcp->t_avg_t = bitvec_get_uint(bv, 5);
	pcp->pc_meas_chan = bitvec_get_uint(bv, 1);
	pcp->n_avg_i = bitvec_get_uint(bv, 4);
}

/*! Decode SI13 Rest Octests (04.08 Chapter 10.5.2.37b).
 *  \param[out] si13 decoded SI13 rest octets
 *  \param[in] encoded SI13 rest octets
 *  \returns parsed bits on success, negative on error */
int osmo_gsm48_rest_octets_si13_decode(struct osmo_gsm48_si13_info *si13, const uint8_t *data)
{
	struct osmo_gprs_cell_options *co = &si13->cell_opts;
	struct osmo_gprs_power_ctrl_pars *pcp = &si13->pwr_ctrl_pars;
	struct bitvec bv;
	int rc;

	memset(&bv, 0, sizeof(bv));
	bv.data = (uint8_t *) data;
	bv.data_len = 20;

	memset(si13, 0, sizeof(*si13));


	if (bitvec_get_bit_high(&bv) == H) {
		si13->bcch_change_mark = bitvec_get_uint(&bv, 3);
		si13->si_change_field = bitvec_get_uint(&bv, 4);
		if (bitvec_get_uint(&bv, 1)) {
			si13->bcch_change_mark = bitvec_get_uint(&bv, 2);
			/* FIXME: implement parsing GPRS Mobile Allocation IE */
			return -ENOTSUP;
		}
		if (bitvec_get_uint(&bv, 1)) {
			/* PBCCH present in cell */
			/* FIXME: parse not implemented */
			return -ENOTSUP;
		} else {
			/* PBCCH not present in cell */
			si13->rac = bitvec_get_uint(&bv, 8);
			si13->spgc_ccch_sup = bitvec_get_uint(&bv, 1);
			si13->prio_acc_thr = bitvec_get_uint(&bv, 3);
			si13->net_ctrl_ord = bitvec_get_uint(&bv, 2);
			if ((rc = decode_gprs_cell_opt(co, &bv)) < 0)
				return rc;

			decode_gprs_pwr_ctrl_pars(pcp, &bv);
		}
	}
	return bv.cur_bit;
}

/* GPRS Mobile Allocation as per TS 04.60 Chapter 12.10a:
   < GPRS Mobile Allocation IE > ::=
     < HSN : bit (6) >
     { 0 | 1 < RFL number list : < RFL number list struct > > }
     { 0 < MA_LENGTH : bit (6) >
         < MA_BITMAP: bit (val(MA_LENGTH) + 1) >
     | 1 { 0 | 1 <ARFCN index list : < ARFCN index list struct > > } } ;

     < RFL number list struct > :: =
       < RFL_NUMBER : bit (4) >
       { 0 | 1 < RFL number list struct > } ;
     < ARFCN index list struct > ::=
       < ARFCN_INDEX : bit(6) >
       { 0 | 1 < ARFCN index list struct > } ;
 */
static int append_gprs_mobile_alloc(struct bitvec *bv)
{
	/* Hopping Sequence Number */
	bitvec_set_uint(bv, 0, 6);

	if (0) {
		/* We want to use a RFL number list */
		bitvec_set_bit(bv, 1);
		/* FIXME: RFL number list */
	} else {
		bitvec_set_bit(bv, 0);
	}

	if (0) {
		/* We want to use a MA_BITMAP */
		bitvec_set_bit(bv, 0);
		/* FIXME: MA_LENGTH, MA_BITMAP, ... */
	} else {
		bitvec_set_bit(bv, 1);
		if (0) {
			/* We want to provide an ARFCN index list */
			bitvec_set_bit(bv, 1);
			/* FIXME */
		} else {
			bitvec_set_bit(bv, 0);
		}
	}
	return 0;
}

static int encode_t3192(unsigned int t3192)
{
	/* See also 3GPP TS 44.060
	   Table 12.24.2: GPRS Cell Options information element details */
	if (t3192 == 0)
		return 3;
	else if (t3192 <= 80)
		return 4;
	else if (t3192 <= 120)
		return 5;
	else if (t3192 <= 160)
		return 6;
	else if (t3192 <= 200)
		return 7;
	else if (t3192 <= 500)
		return 0;
	else if (t3192 <= 1000)
		return 1;
	else if (t3192 <= 1500)
		return 2;
	else
		return -EINVAL;
}

static int encode_drx_timer(unsigned int drx)
{
	if (drx == 0)
		return 0;
	else if (drx == 1)
		return 1;
	else if (drx == 2)
		return 2;
	else if (drx <= 4)
		return 3;
	else if (drx <= 8)
		return 4;
	else if (drx <= 16)
		return 5;
	else if (drx <= 32)
		return 6;
	else if (drx <= 64)
		return 7;
	else
		return -EINVAL;
}

/* GPRS Cell Options as per TS 04.60 Chapter 12.24
	< GPRS Cell Options IE > ::=
		< NMO : bit(2) >
		< T3168 : bit(3) >
		< T3192 : bit(3) >
		< DRX_TIMER_MAX: bit(3) >
		< ACCESS_BURST_TYPE: bit >
		< CONTROL_ACK_TYPE : bit >
		< BS_CV_MAX: bit(4) >
		{ 0 | 1 < PAN_DEC : bit(3) >
			< PAN_INC : bit(3) >
			< PAN_MAX : bit(3) >
		{ 0 | 1 < Extension Length : bit(6) >
			< bit (val(Extension Length) + 1
			& { < Extension Information > ! { bit ** = <no string> } } ;
	< Extension Information > ::=
		{ 0 | 1 < EGPRS_PACKET_CHANNEL_REQUEST : bit >
			< BEP_PERIOD : bit(4) > }
		< PFC_FEATURE_MODE : bit >
		< DTM_SUPPORT : bit >
		<BSS_PAGING_COORDINATION: bit >
		<spare bit > ** ;
 */
static int append_gprs_cell_opt(struct bitvec *bv,
				const struct osmo_gprs_cell_options *gco)
{
	int t3192, drx_timer_max;

	t3192 = encode_t3192(gco->t3192);
	if (t3192 < 0)
		return t3192;

	drx_timer_max = encode_drx_timer(gco->drx_timer_max);
	if (drx_timer_max < 0)
		return drx_timer_max;

	bitvec_set_uint(bv, gco->nmo, 2);

	/* See also 3GPP TS 44.060
	   Table 12.24.2: GPRS Cell Options information element details */
	bitvec_set_uint(bv, gco->t3168 / 500 - 1, 3);

	bitvec_set_uint(bv, t3192, 3);
	bitvec_set_uint(bv, drx_timer_max, 3);
	/* ACCESS_BURST_TYPE: Hard-code 8bit */
	bitvec_set_bit(bv, 0);
	/* CONTROL_ACK_TYPE: */
	bitvec_set_bit(bv, gco->ctrl_ack_type_use_block);
	bitvec_set_uint(bv, gco->bs_cv_max, 4);

	if (0) {
		/* hard-code no PAN_{DEC,INC,MAX} */
		bitvec_set_bit(bv, 0);
	} else {
		/* copied from ip.access BSC protocol trace */
		bitvec_set_bit(bv, 1);
		bitvec_set_uint(bv, 1, 3);	/* DEC */
		bitvec_set_uint(bv, 1, 3);	/* INC */
		bitvec_set_uint(bv, 15, 3);	/* MAX */
	}

	if (!gco->ext_info_present) {
		/* no extension information */
		bitvec_set_bit(bv, 0);
	} else {
		/* extension information */
		bitvec_set_bit(bv, 1);
		/* R99 extension: */
		if (!gco->ext_info.egprs_supported) {
			/* 6bit length of extension */
			bitvec_set_uint(bv, (1 + 5)-1, 6);
			/* EGPRS supported in the cell */
			bitvec_set_bit(bv, 0);
		} else {
			/* 6bit length of extension */
			bitvec_set_uint(bv, (1 + 5 + 5)-1, 6);
			/* EGPRS supported in the cell */
			bitvec_set_bit(bv, 1);

			/* 1bit EGPRS PACKET CHANNEL REQUEST (inverted logic) */
			bitvec_set_bit(bv, !gco->ext_info.use_egprs_p_ch_req);

			/* 4bit BEP PERIOD */
			bitvec_set_uint(bv, gco->ext_info.bep_period, 4);
		}
		bitvec_set_bit(bv, gco->ext_info.pfc_supported);
		bitvec_set_bit(bv, gco->ext_info.dtm_supported);
		bitvec_set_bit(bv, gco->ext_info.bss_paging_coordination);

		/* REL-4 extension: */
		bitvec_set_bit(bv, gco->ext_info.ccn_active);
		bitvec_set_bit(bv, 0); /* NW_EXT_UTBF disabled */
	}

	return 0;
}

static void append_gprs_pwr_ctrl_pars(struct bitvec *bv,
				      const struct osmo_gprs_power_ctrl_pars *pcp)
{
	bitvec_set_uint(bv, pcp->alpha, 4);
	bitvec_set_uint(bv, pcp->t_avg_w, 5);
	bitvec_set_uint(bv, pcp->t_avg_t, 5);
	bitvec_set_uint(bv, pcp->pc_meas_chan, 1);
	bitvec_set_uint(bv, pcp->n_avg_i, 4);
}

/* Generate SI13 Rest Octests (04.08 Chapter 10.5.2.37b) */
int osmo_gsm48_rest_octets_si13_encode(uint8_t *data, const struct osmo_gsm48_si13_info *si13)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = data;
	bv.data_len = 20;

	if (0) {
		/* No rest octets */
		bitvec_set_bit(&bv, L);
	} else {
		bitvec_set_bit(&bv, H);
		bitvec_set_uint(&bv, si13->bcch_change_mark, 3);
		bitvec_set_uint(&bv, si13->si_change_field, 4);
		if (1) {
			bitvec_set_bit(&bv, 0);
		} else {
			bitvec_set_bit(&bv, 1);
			bitvec_set_uint(&bv, si13->bcch_change_mark, 2);
			append_gprs_mobile_alloc(&bv);
		}
		/* PBCCH not present in cell:
		   it shall never be indicated according to 3GPP TS 44.018 Table 10.5.2.37b.1 */
		bitvec_set_bit(&bv, 0);
		bitvec_set_uint(&bv, si13->rac, 8);
		bitvec_set_bit(&bv, si13->spgc_ccch_sup);
		bitvec_set_uint(&bv, si13->prio_acc_thr, 3);
		bitvec_set_uint(&bv, si13->net_ctrl_ord, 2);
		append_gprs_cell_opt(&bv, &si13->cell_opts);
		append_gprs_pwr_ctrl_pars(&bv, &si13->pwr_ctrl_pars);

		/* 3GPP TS 44.018 Release 6 / 10.5.2.37b */
		bitvec_set_bit(&bv, H);	/* added Release 99 */
		/* claim our SGSN is compatible with Release 99, as EDGE and EGPRS
		 * was only added in this Release */
		bitvec_set_bit(&bv, 1);
	}
	bitvec_spare_padding(&bv, (bv.data_len*8)-1);
	return bv.data_len;
}


/***********************************************************************
 * Decoder
 ***********************************************************************/

/*! Decode SI3 Rest Octests (Chapter 10.5.2.34 / Table 10.4.72).
 *  \param[out] si3 decoded SI3 rest octets
 *  \param[in] encoded SI3 rest octets, 4 octets long */
void osmo_gsm48_rest_octets_si3_decode(struct osmo_gsm48_si_ro_info *si3, const uint8_t *data)
{
	struct osmo_gsm48_si_selection_params *sp = &si3->selection_params;
	struct osmo_gsm48_si_power_offset *po = &si3->power_offset;
	struct osmo_gsm48_si3_gprs_ind *gi = &si3->gprs_ind;
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = (uint8_t *) data;
	bv.data_len = 4;

	memset(si3, 0, sizeof(*si3));

	/* Optional Selection Parameters */
	if (bitvec_get_bit_high(&bv) == H) {
		sp->present = 1;
		sp->cbq = bitvec_get_uint(&bv, 1);
		sp->cell_resel_off = bitvec_get_uint(&bv, 6);
		sp->temp_offs = bitvec_get_uint(&bv, 3);
		sp->penalty_time = bitvec_get_uint(&bv, 5);
	} else {
		sp->present = 0;
	}

	/* Optional Power Offset */
	if (bitvec_get_bit_high(&bv) == H) {
		po->present = 1;
		po->power_offset = bitvec_get_uint(&bv, 2);
	} else {
		po->present = 0;
	}

	/* System Information 2ter Indicator */
	if (bitvec_get_bit_high(&bv) == H)
		si3->si2ter_indicator = 1;
	else
		si3->si2ter_indicator = 0;

	/* Early Classmark Sending Control */
	if (bitvec_get_bit_high(&bv) == H)
		si3->early_cm_ctrl = 1;
	else
		si3->early_cm_ctrl = 0;

	/* Scheduling if and where */
	if (bitvec_get_bit_high(&bv) == H) {
		si3->scheduling.present = 1;
		si3->scheduling.where = bitvec_get_uint(&bv, 3);
	} else {
		si3->scheduling.present = 0;
	}

	/* GPRS Indicator */
	if (bitvec_get_bit_high(&bv) == H) {
		gi->present = 1;
		gi->ra_colour = bitvec_get_uint(&bv, 3);
		gi->si13_position = bitvec_get_uint(&bv, 1);
	} else {
		gi->present = 0;
	}

	/* 3G Early Classmark Sending Restriction. If H, then controlled by
	 * early_cm_ctrl above */
	if (bitvec_get_bit_high(&bv) == H)
		si3->early_cm_restrict_3g = 0;
	else
		si3->early_cm_restrict_3g = 1;

	if (bitvec_get_bit_high(&bv) == H)
		si3->si2quater_indicator = 1;
	else
		si3->si2quater_indicator = 0;
}


void osmo_gsm48_rest_octets_si4_decode(struct osmo_gsm48_si_ro_info *si4, const uint8_t *data, int len)
{
	struct osmo_gsm48_si_selection_params *sp = &si4->selection_params;
	struct osmo_gsm48_si_power_offset *po = &si4->power_offset;
	struct osmo_gsm48_si3_gprs_ind *gi = &si4->gprs_ind;
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = (uint8_t *) data;
	bv.data_len = len;

	memset(si4, 0, sizeof(*si4));

	/* Optional Selection Parameters */
	if (bitvec_get_bit_high(&bv) == H) {
		sp->present = 1;
		sp->cbq = bitvec_get_uint(&bv, 1);
		sp->cell_resel_off = bitvec_get_uint(&bv, 6);
		sp->temp_offs = bitvec_get_uint(&bv, 3);
		sp->penalty_time = bitvec_get_uint(&bv, 5);
	} else {
		sp->present = 0;
	}

	/* Optional Power Offset */
	if (bitvec_get_bit_high(&bv) == H) {
		po->present = 1;
		po->power_offset = bitvec_get_uint(&bv, 2);
	} else {
		po->present = 0;
	}

	/* GPRS Indicator */
	if (bitvec_get_bit_high(&bv) == H) {
		gi->present = 1;
		gi->ra_colour = bitvec_get_uint(&bv, 3);
		gi->si13_position = bitvec_get_uint(&bv, 1);
	} else {
		gi->present = 0;
	}
}
