/*
 * (C) 2012 by Harald Welte <laforge@gnumonks.org>
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
 */

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm48_arfcn_range_encode.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/mncc.h>
#include <osmocom/core/backtrace.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>


static const uint8_t csd_9600_v110_lv[] = { 0x07, 0xa1, 0xb8, 0x89, 0x21, 0x15, 0x63, 0x80 };

static const struct gsm_mncc_bearer_cap bcap_csd_9600_v110 = {
	.transfer =	GSM48_BCAP_ITCAP_UNR_DIG_INF,
	.mode =		GSM48_BCAP_TMOD_CIRCUIT,
	.coding =	GSM48_BCAP_CODING_GSM_STD,
	.radio =	GSM48_BCAP_RRQ_FR_ONLY,
	.speech_ver[0]=	-1,
	.data = {
		.rate_adaption =	GSM48_BCAP_RA_V110_X30,
		.sig_access =		GSM48_BCAP_SA_I440_I450,
		.async =		1,
		.nr_stop_bits =		1,
		.nr_data_bits =		8,
		.user_rate =		GSM48_BCAP_UR_9600,
		.parity =		GSM48_BCAP_PAR_NONE,
		.interm_rate =		GSM48_BCAP_IR_16k,
		.transp =		GSM48_BCAP_TR_TRANSP,
		.modem_type =		GSM48_BCAP_MT_NONE,
	},
};

static const uint8_t speech_all_lv[] = { 0x06, 0x60, 0x04, 0x02, 0x00, 0x05, 0x81 };

static const struct gsm_mncc_bearer_cap bcap_speech_all = {
	.transfer =	GSM48_BCAP_ITCAP_SPEECH,
	.mode =		GSM48_BCAP_TMOD_CIRCUIT,
	.coding =	GSM48_BCAP_CODING_GSM_STD,
	.radio =	GSM48_BCAP_RRQ_DUAL_FR,
	.speech_ver = {
		4, 2, 0, 5, 1, -1,
	},
};

static const uint8_t speech_no3a_lv[] = { 0x01, 0xa0 };

static const struct gsm_mncc_bearer_cap bcap_speech_no3a = {
	.transfer =	GSM48_BCAP_ITCAP_SPEECH,
	.mode =		GSM48_BCAP_TMOD_CIRCUIT,
	.coding =	GSM48_BCAP_CODING_GSM_STD,
	.radio =	GSM48_BCAP_RRQ_FR_ONLY,
	.speech_ver = {
		0, -1,
	},
};


struct bcap_test {
	const uint8_t *lv;
	const struct gsm_mncc_bearer_cap *bc;
	const char *name;
};

static const struct bcap_test bcap_tests[] = {
	{ csd_9600_v110_lv, &bcap_csd_9600_v110, "CSD 9600/V.110/transparent" },
	{ speech_all_lv, &bcap_speech_all, "Speech, all codecs" },
	{ speech_no3a_lv, &bcap_speech_no3a, "Speech, without octet 3a" },
};

static int test_bearer_cap(void)
{
	struct gsm_mncc_bearer_cap bc;
	int i, rc;

	for (i = 0; i < ARRAY_SIZE(bcap_tests); i++) {
		struct msgb *msg = msgb_alloc(100, "test");
		bool pass = false;
		int lv_len;

		memset(&bc, 0, sizeof(bc));

		/* test decoding */
		rc = gsm48_decode_bearer_cap(&bc, bcap_tests[i].lv);
		if (rc < 0) {
			fprintf(stderr, "Error decoding %s\n",
				bcap_tests[i].name);
			goto verdict;
		}
		if (memcmp(&bc, bcap_tests[i].bc, sizeof(bc))) {
			fprintf(stderr, "Incorrect decoded result of %s:\n",
				bcap_tests[i].name);
			fprintf(stderr, " should: %s\n",
				osmo_hexdump((uint8_t *) bcap_tests[i].bc, sizeof(bc)));
			fprintf(stderr, " is:     %s\n",
				osmo_hexdump((uint8_t *) &bc, sizeof(bc)));
			goto verdict;
		}

		/* also test re-encode? */
		rc = gsm48_encode_bearer_cap(msg, 1, &bc);
		if (rc < 0) {
			fprintf(stderr, "Error encoding %s\n",
				bcap_tests[i].name);
			goto verdict;
		}
		lv_len = bcap_tests[i].lv[0]+1;
		if (memcmp(msg->data, bcap_tests[i].lv, lv_len)) {
			fprintf(stderr, "Incorrect encoded result of %s:\n",
				bcap_tests[i].name);
			fprintf(stderr, " should: %s\n",
				osmo_hexdump(bcap_tests[i].lv, lv_len));
			fprintf(stderr, " is:     %s\n",
				osmo_hexdump(msg->data, msg->len));
			goto verdict;
		}

		/* all checks passed */
		pass = true;

verdict:
		printf("Test `%s' %sed\n", bcap_tests[i].name, pass ? "pass" : "fail");
		msgb_free(msg);
	}

	return 0;
}

static inline void dump_ra(const struct gprs_ra_id *raid)
{
	printf("%s%s\n", osmo_rai_name(raid), raid->mnc_3_digits ? " (3-digit MNC)" : "");
}

static inline void check_ra(const struct gprs_ra_id *raid)
{
	struct gsm48_ra_id ra;
	struct gprs_ra_id raid0 = {
		.mnc = 0,
		.mcc = 0,
		.lac = 0,
		.rac = 0,
	};

	gsm48_encode_ra(&ra, raid);
	printf("Constructed RA:\n");

	gsm48_parse_ra(&raid0, (const uint8_t *)&ra);
	dump_ra(raid);
	printf("MCC+MNC in BCD: %s\n", osmo_hexdump(ra.digits, sizeof(ra.digits)));
	dump_ra(&raid0);
	printf("RA test...");
	if (raid->mnc != raid0.mnc || raid->mcc != raid0.mcc || raid->lac != raid0.lac || raid->rac != raid0.rac
	    || (raid->mnc_3_digits || raid->mnc > 99) != raid0.mnc_3_digits)
		printf("FAIL\n");
	else
		printf("passed\n");
}

static inline void check_lai(const struct gprs_ra_id *raid)
{
	int rc;
	struct gsm48_loc_area_id lai = {};
	struct gprs_ra_id decoded = {};
	struct gprs_ra_id _laid = *raid;
	struct gprs_ra_id *laid = &_laid;
	laid->rac = 0;

	printf("- gsm48_generate_lai() from "); dump_ra(laid);

	gsm48_generate_lai(&lai, laid->mcc, laid->mnc, laid->lac);
	printf("  Encoded %s\n", osmo_hexdump((unsigned char*)&lai, sizeof(lai)));
	rc = gsm48_decode_lai(&lai, &decoded.mcc, &decoded.mnc, &decoded.lac);
	if (rc) {
		printf("  gsm48_decode_lai() returned %d --> FAIL\n", rc);
		return;
	}
	printf("  gsm48_decode_lai() gives  "); dump_ra(&decoded);
	if (decoded.mcc == laid->mcc
	    && decoded.mnc == laid->mnc
	    && decoded.lac == laid->lac)
		printf("  passed\n");
	else
		printf("  FAIL\n");
}

static inline void dump_lai(const struct osmo_location_area_id *lai)
{
	printf("%s%s\n", osmo_lai_name(lai), lai->plmn.mnc_3_digits ? " (3-digit MNC)" : "");
}

static inline void check_lai2(const struct gprs_ra_id *raid)
{
	struct gsm48_loc_area_id lai = {};
	struct osmo_location_area_id decoded = {};
	struct osmo_location_area_id laid = {
		.plmn = {
			.mcc = raid->mcc,
			.mnc = raid->mnc,
			.mnc_3_digits = raid->mnc_3_digits,
		},
		.lac = raid->lac,
	};

	printf("- gsm48_generate_lai2() from "); dump_lai(&laid);

	gsm48_generate_lai2(&lai, &laid);
	printf("  Encoded %s\n", osmo_hexdump((unsigned char*)&lai, sizeof(lai)));
	gsm48_decode_lai2(&lai, &decoded);
	printf("  gsm48_decode_lai2() gives  "); dump_lai(&decoded);
	if (decoded.plmn.mcc == laid.plmn.mcc
	    && decoded.plmn.mnc == laid.plmn.mnc
	    && decoded.lac == laid.lac
	    && decoded.plmn.mnc_3_digits == (laid.plmn.mnc_3_digits || laid.plmn.mnc > 99))
		printf("  passed\n");
	else
		printf("  FAIL\n");
}

static struct gprs_ra_id test_ra_cap_items[] = {
	{
		.mcc = 77,
		.mnc = 121,
		.lac = 666,
		.rac = 5,
	},
	{
		.mcc = 84,
		.mnc = 98,
		.lac = 11,
		.rac = 89,
	},
	{
		.mcc = 0,
		.mnc = 0,
		.lac = 0,
		.rac = 0,
		.mnc_3_digits = false,
		/* expecting 000-00, BCD = 00 f0 00 */
	},
	{
		.mcc = 0,
		.mnc = 0,
		.lac = 0,
		.rac = 0,
		.mnc_3_digits = true,
		/* expecting 000-000, BCD = 00 00 00 */
	},
	{
		.mcc = 999,
		.mnc = 999,
		.lac = 65535,
		.rac = 255,
	},
	{
		.mcc = 1,
		.mnc = 2,
		.lac = 23,
		.rac = 42,
		.mnc_3_digits = false,
		/* expecting 001-02, BCD = 00 f1 20 */
	},
	{
		.mcc = 1,
		.mnc = 2,
		.lac = 23,
		.rac = 42,
		.mnc_3_digits = true,
		/* expecting 001-002, BCD = 00 21 00 */
	},
	{
		.mcc = 12,
		.mnc = 34,
		.lac = 56,
		.rac = 78,
		.mnc_3_digits = false,
		/* expecting 012-34, BCD = 10 f2 43 */
	},
	{
		.mcc = 12,
		.mnc = 34,
		.lac = 23,
		.rac = 42,
		.mnc_3_digits = true,
		/* expecting 012-034, BCD = 10 42 30 */
	},
	{
		.mcc = 123,
		.mnc = 456,
		.lac = 23,
		.rac = 42,
		.mnc_3_digits = false,
		/* expecting 123-456, BCD = 21 63 54 (false flag has no effect) */
	},
	{
		.mcc = 123,
		.mnc = 456,
		.lac = 23,
		.rac = 42,
		.mnc_3_digits = true,
		/* expecting 123-456, BCD = 21 63 54 (same) */
	},
};

static void test_ra_cap(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(test_ra_cap_items); i++)
		check_ra(&test_ra_cap_items[i]);
}

static void test_lai_encode_decode(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(test_ra_cap_items); i++) {
		check_lai(&test_ra_cap_items[i]);
		check_lai2(&test_ra_cap_items[i]);
	}
}

static void dump_cm3(struct gsm48_classmark3 *cm3)
{
	printf("mult_band_supp=%02x\n", cm3->mult_band_supp);
	printf("a5_bits=%02x\n", cm3->a5_bits);
	printf("assoc_radio_cap_1=%02x\n", cm3->assoc_radio_cap_1);
	printf("assoc_radio_cap_2=%02x\n", cm3->assoc_radio_cap_2);
	printf("\n");
	printf("r_support.present=%u\n", cm3->r_support.present);
	printf("r_support.r_gsm_assoc_radio_cap=%02x\n",
	       cm3->r_support.r_gsm_assoc_radio_cap);
	printf("\n");
	printf("hscsd_mult_slot_cap.present=%u\n",
	       cm3->hscsd_mult_slot_cap.present);
	printf("hscsd_mult_slot_cap.mslot_class=%02x\n",
	       cm3->hscsd_mult_slot_cap.mslot_class);
	printf("\n");
	printf("ucs2_treatment=%u\n", cm3->ucs2_treatment);
	printf("extended_meas_cap=%u\n", cm3->extended_meas_cap);
	printf("\n");
	printf("ms_meas_cap.present=%u\n", cm3->ms_meas_cap.present);
	printf("ms_meas_cap.sms_value=%02x\n", cm3->ms_meas_cap.sms_value);
	printf("ms_meas_cap.sm_value=%02x\n", cm3->ms_meas_cap.sm_value);
	printf("\n");
	printf("ms_pos_method_cap.present=%u\n",
	       cm3->ms_pos_method_cap.present);
	printf("ms_pos_method_cap.method=%02x\n",
	       cm3->ms_pos_method_cap.method);
	printf("\n");
	printf("ecsd_multislot_cap.present=%u\n",
	       cm3->ecsd_multislot_cap.present);
	printf("ecsd_multislot_cap.mslot_class=%02x\n",
	       cm3->ecsd_multislot_cap.mslot_class);
	printf("\n");
	printf("psk8_struct.present=%u\n", cm3->psk8_struct.present);
	printf("psk8_struct.mod_cap=%u\n", cm3->psk8_struct.mod_cap);
	printf("psk8_struct.rf_pwr_cap_1.present=%u\n",
	       cm3->psk8_struct.rf_pwr_cap_1.present);
	printf("psk8_struct.rf_pwr_cap_1.value=%02x\n",
	       cm3->psk8_struct.rf_pwr_cap_1.value);
	printf("psk8_struct.rf_pwr_cap_2.present=%u\n",
	       cm3->psk8_struct.rf_pwr_cap_2.present);
	printf("psk8_struct.rf_pwr_cap_2.value=%02x\n",
	       cm3->psk8_struct.rf_pwr_cap_2.value);
	printf("\n");
	printf("gsm_400_bands_supp.present=%u\n",
	       cm3->gsm_400_bands_supp.present);
	printf("gsm_400_bands_supp.value=%02x\n",
	       cm3->gsm_400_bands_supp.value);
	printf("gsm_400_bands_supp.assoc_radio_cap=%02x\n",
	       cm3->gsm_400_bands_supp.assoc_radio_cap);
	printf("\n");
	printf("gsm_850_assoc_radio_cap.present=%u\n",
	       cm3->gsm_850_assoc_radio_cap.present);
	printf("gsm_850_assoc_radio_cap.value=%02x\n",
	       cm3->gsm_850_assoc_radio_cap.value);
	printf("\n");
	printf("gsm_1900_assoc_radio_cap.present=%u\n",
	       cm3->gsm_1900_assoc_radio_cap.present);
	printf("gsm_1900_assoc_radio_cap.value=%02x\n",
	       cm3->gsm_1900_assoc_radio_cap.value);
	printf("\n");
	printf("umts_fdd_rat_cap=%u\n", cm3->umts_fdd_rat_cap);
	printf("umts_tdd_rat_cap=%u\n", cm3->umts_tdd_rat_cap);
	printf("cdma200_rat_cap=%u\n", cm3->cdma200_rat_cap);
	printf("\n");
	printf("dtm_gprs_multislot_cap.present=%u\n",
	       cm3->dtm_gprs_multislot_cap.present);
	printf("dtm_gprs_multislot_cap.mslot_class=%02x\n",
	       cm3->dtm_gprs_multislot_cap.mslot_class);
	printf("dtm_gprs_multislot_cap.single_slot_dtm=%u\n",
	       cm3->dtm_gprs_multislot_cap.single_slot_dtm);
	printf("dtm_gprs_multislot_cap.dtm_egprs_multislot_cap.present=%u\n",
	       cm3->dtm_gprs_multislot_cap.dtm_egprs_multislot_cap.present);
	printf("dtm_gprs_multislot_cap.dtm_egprs_multislot_cap.mslot_class=%02x\n",
	       cm3->dtm_gprs_multislot_cap.dtm_egprs_multislot_cap.mslot_class);
	printf("\n");
	printf("single_band_supp.present=%u\n", cm3->single_band_supp.present);
	printf("single_band_supp.value=%u\n", cm3->single_band_supp.value);
	printf("\n");
	printf("gsm_750_assoc_radio_cap.present=%u\n",
	       cm3->gsm_750_assoc_radio_cap.present);
	printf("gsm_750_assoc_radio_cap.value=%02x\n",
	       cm3->gsm_750_assoc_radio_cap.value);
	printf("\n");
	printf("umts_1_28_mcps_tdd_rat_cap=%u\n",
	       cm3->umts_1_28_mcps_tdd_rat_cap);
	printf("geran_feature_package=%u\n", cm3->geran_feature_package);
	printf("\n");
	printf("extended_dtm_gprs_multislot_cap.present=%u\n",
	       cm3->extended_dtm_gprs_multislot_cap.present);
	printf("extended_dtm_gprs_multislot_cap.mslot_class=%02x\n",
	       cm3->extended_dtm_gprs_multislot_cap.mslot_class);
	printf
	    ("extended_dtm_gprs_multislot_cap.dtm_egprs_multislot_cap.present=%u\n",
	     cm3->extended_dtm_gprs_multislot_cap.
	     extended_dtm_egprs_multislot_cap.present);
	printf
	    ("extended_dtm_gprs_multislot_cap.dtm_egprs_multislot_cap.mslot_class=%02x\n",
	     cm3->extended_dtm_gprs_multislot_cap.
	     extended_dtm_egprs_multislot_cap.mslot_class);
	printf("\n");
	printf("high_multislot_cap.present=%u\n",
	       cm3->high_multislot_cap.present);
	printf("high_multislot_cap.value=%02x\n",
	       cm3->high_multislot_cap.value);
	printf("\n");
	printf("geran_feature_package_2=%u\n", cm3->geran_feature_package_2);
	printf("gmsk_multislot_power_prof=%02x\n",
	       cm3->gmsk_multislot_power_prof);
	printf("psk8_multislot_power_prof=%02x\n",
	       cm3->psk8_multislot_power_prof);
	printf("\n");
	printf("t_gsm_400_bands_supp.present=%u\n",
	       cm3->t_gsm_400_bands_supp.present);
	printf("t_gsm_400_bands_supp.value=%02x\n",
	       cm3->t_gsm_400_bands_supp.value);
	printf("t_gsm_400_bands_supp.assoc_radio_cap=%02x\n",
	       cm3->t_gsm_400_bands_supp.assoc_radio_cap);
	printf("\n");
	printf("dl_advanced_rx_perf=%02x\n", cm3->dl_advanced_rx_perf);
	printf("dtm_enhancements_cap=%u\n", cm3->dtm_enhancements_cap);
	printf("\n");
	printf("dtm_gprs_high_multislot_cap.present=%u\n",
	       cm3->dtm_gprs_high_multislot_cap.present);
	printf("dtm_gprs_high_multislot_cap.mslot_class=%02x\n",
	       cm3->dtm_gprs_high_multislot_cap.mslot_class);
	printf("dtm_gprs_high_multislot_cap.offset_required=%u\n",
	       cm3->dtm_gprs_high_multislot_cap.offset_required);
	printf
	    ("dtm_gprs_high_multislot_cap.dtm_egprs_high_multislot_cap.present=%u\n",
	     cm3->dtm_gprs_high_multislot_cap.dtm_egprs_high_multislot_cap.
	     present);
	printf
	    ("dtm_gprs_high_multislot_cap.dtm_egprs_high_multislot_cap.mslot_class=%02x\n",
	     cm3->dtm_gprs_high_multislot_cap.dtm_egprs_high_multislot_cap.
	     mslot_class);
	printf("\n");
	printf("repeated_acch_capability=%u\n", cm3->repeated_acch_capability);
	printf("\n");
	printf("gsm_710_assoc_radio_cap.present=%u\n",
	       cm3->gsm_710_assoc_radio_cap.present);
	printf("gsm_710_assoc_radio_cap.value=%02x\n",
	       cm3->gsm_710_assoc_radio_cap.value);
	printf("\n");
	printf("t_gsm_810_assoc_radio_cap.present=%u\n",
	       cm3->t_gsm_810_assoc_radio_cap.present);
	printf("t_gsm_810_assoc_radio_cap.value=%02x\n",
	       cm3->t_gsm_810_assoc_radio_cap.value);
	printf("\n");
	printf("ciphering_mode_setting_cap=%u\n",
	       cm3->ciphering_mode_setting_cap);
	printf("add_pos_cap=%u\n", cm3->add_pos_cap);
	printf("e_utra_fdd_supp=%u\n", cm3->e_utra_fdd_supp);
	printf("e_utra_tdd_supp=%u\n", cm3->e_utra_tdd_supp);
	printf("e_utra_meas_rep_supp=%u\n", cm3->e_utra_meas_rep_supp);
	printf("prio_resel_supp=%u\n", cm3->prio_resel_supp);
	printf("utra_csg_cells_rep=%u\n", cm3->utra_csg_cells_rep);
	printf("vamos_level=%02x\n", cm3->vamos_level);
	printf("tighter_capability=%02x\n", cm3->tighter_capability);
	printf("sel_ciph_dl_sacch=%u\n", cm3->sel_ciph_dl_sacch);
	printf("cs_ps_srvcc_geran_utra=%02x\n", cm3->cs_ps_srvcc_geran_utra);
	printf("cs_ps_srvcc_geran_eutra=%02x\n", cm3->cs_ps_srvcc_geran_eutra);
	printf("geran_net_sharing=%u\n", cm3->geran_net_sharing);
	printf("e_utra_wb_rsrq_meas_supp=%u\n", cm3->e_utra_wb_rsrq_meas_supp);
	printf("er_band_support=%u\n", cm3->er_band_support);
	printf("utra_mult_band_ind_supp=%u\n", cm3->utra_mult_band_ind_supp);
	printf("e_utra_mult_band_ind_supp=%u\n",
	       cm3->e_utra_mult_band_ind_supp);
	printf("extended_tsc_set_cap_supp=%u\n",
	       cm3->extended_tsc_set_cap_supp);
	printf("extended_earfcn_val_range=%u\n",
	       cm3->extended_earfcn_val_range);
}

static void test_decode_classmark3(void)
{
	struct gsm48_classmark3 cm3;
	const uint8_t cm3_1[] = { 0x60, 0x14, 0x04, 0x2f, 0x65, 0x00, 0x20, 0x03, 0x40, 0x4a };
	const uint8_t cm3_2[] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
	const uint8_t cm3_3[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};

	printf("=====cm3_1=====\n");
        gsm48_decode_classmark3(&cm3, cm3_1, sizeof(cm3_1));
	dump_cm3(&cm3);
	printf("\n");

	printf("=====cm3_2=====\n");
        gsm48_decode_classmark3(&cm3, cm3_2, sizeof(cm3_2));
	dump_cm3(&cm3);
	printf("\n");

	printf("=====cm3_3=====\n");
        gsm48_decode_classmark3(&cm3, cm3_3, sizeof(cm3_3));
	dump_cm3(&cm3);
	printf("\n");
}

static void test_mid_from_tmsi(void)
{
	static const uint8_t res[] = { 0x17, 0x05, 0xf4, 0xaa, 0xbb, 0xcc, 0xdd };


	uint32_t tmsi = 0xAABBCCDD;
	uint8_t buf[3 + sizeof(uint32_t)];

	printf("Simple TMSI encoding test....");

	memset(&buf, 0xFE, sizeof(buf));
	gsm48_generate_mid_from_tmsi(buf, tmsi);

	OSMO_ASSERT(memcmp(buf, res, sizeof(res)) == 0);
	printf("passed\n");
}

static void test_mid_from_imsi(void)
{
	char *imsi = "901700000004620";
	uint8_t buf[10], len;

	printf("Simple IMSI encoding test....");

	len = gsm48_generate_mid_from_imsi(buf, imsi);

	printf("passed: [%u] %s\n", len, osmo_hexdump(buf, len));
}

struct test_mid_encode_decode_test {
	uint8_t mi_type;
	const char *mi_str;
	const char *mi_name;
	size_t str_size;
	const char *expect_mi_tlv_hex;
	const char *expect_str;
	int expect_rc;
};

static const struct test_mid_encode_decode_test test_mid_encode_decode_tests[] = {
	{
		.mi_type = GSM_MI_TYPE_IMSI,
		.mi_str = "123456789012345",
		.mi_name = "IMSI-123456789012345",
		.expect_mi_tlv_hex = "17081932547698103254",
	},
	{
		.mi_type = GSM_MI_TYPE_IMSI,
		.mi_str = "12345678901234",
		.mi_name = "IMSI-12345678901234",
		.expect_mi_tlv_hex = "170811325476981032f4",
	},
	{
		.mi_type = GSM_MI_TYPE_IMSI,
		.mi_str = "423423",
		.mi_name = "IMSI-423423",
		.expect_mi_tlv_hex = "1704413224f3",
	},
	{
		.mi_type = GSM_MI_TYPE_IMSI | GSM_MI_ODD,
		.mi_str = "423423",
		.mi_name = "IMSI-423423",
		.expect_mi_tlv_hex = "1704413224f3",
	},
	{
		.mi_type = GSM_MI_TYPE_IMSI,
		.mi_str = "4234235",
		.mi_name = "IMSI-4234235",
		.expect_mi_tlv_hex = "170449322453",
	},
	{
		.mi_type = GSM_MI_TYPE_IMSI,
		.mi_str = "4234235",
		.mi_name = "IMSI-4234235",
		.expect_mi_tlv_hex = "170449322453",
		.str_size = 4,
		.expect_str = "423",
	},
	{
		.mi_type = GSM_MI_TYPE_IMEI,
		.mi_str = "123456789012345",
		.mi_name = "IMEI-123456789012345",
		.expect_mi_tlv_hex = "17081a32547698103254",
	},
	{
		.mi_type = GSM_MI_TYPE_IMEI,
		.mi_str = "98765432109876",
		.mi_name = "IMEI-98765432109876",
		.expect_mi_tlv_hex = "170892785634129078f6",
	},
	{
		.mi_type = GSM_MI_TYPE_IMEI,
		.mi_str = "987654321098765",
		.mi_name = "IMEI-987654321098765",
		.expect_mi_tlv_hex = "17089a78563412907856",
	},
	{
		.mi_type = GSM_MI_TYPE_IMEISV,
		.mi_str = "9876543210987654",
		.mi_name = "IMEI-SV-9876543210987654",
		.expect_mi_tlv_hex = "17099378563412907856f4",
	},
	{
		.mi_type = GSM_MI_TYPE_IMEISV,
		.mi_str = "9876543210987654",
		.mi_name = "IMEI-SV-9876543210987654",
		.expect_mi_tlv_hex = "17099378563412907856f4",
		.str_size = 17,
		.expect_str = "9876543210987654",
	},
	{
		/* gsm48 treats TMSI as decimal string */
		.mi_type = GSM_MI_TYPE_TMSI,
		.mi_str = "305419896", /* 0x12345678 as decimal */
		.mi_name = "TMSI-0x12345678",
		.expect_mi_tlv_hex = "1705f412345678",
		.expect_rc = 9, /* exception: gsm48_mi_to_string() for TMSI returns strlen(), not bytes! */
	},
	{
		.mi_type = GSM_MI_TYPE_TMSI,
		.mi_str = "12648430", /* 0xc0ffee as decimal */
		.mi_name = "TMSI-0x00C0FFEE",
		.expect_mi_tlv_hex = "1705f400c0ffee",
		.expect_rc = 8, /* exception: gsm48_mi_to_string() for TMSI returns strlen(), not bytes! */
	},
	{
		.mi_type = GSM_MI_TYPE_TMSI,
		.mi_str = "0",
		.mi_name = "TMSI-0x00000000",
		.expect_mi_tlv_hex = "1705f400000000",
		.expect_rc = 1, /* exception: gsm48_mi_to_string() for TMSI returns strlen(), not bytes! */
	},
	{
		/* gsm48 treats TMSI as decimal string */
		.mi_type = GSM_MI_TYPE_TMSI,
		.mi_str = "305419896", /* 0x12345678 as decimal */
		.mi_name = "TMSI-0x12345678",
		.expect_mi_tlv_hex = "1705f412345678",
		.str_size = 5,
		.expect_str = "3054",
		.expect_rc = 9, /* exception: gsm48_mi_to_string() for TMSI returns would-be strlen() like snprintf()! */
	},
	{
		.mi_type = GSM_MI_TYPE_NONE,
		.mi_str = "123",
		.mi_name = "unknown",
		.expect_mi_tlv_hex = "17021832", /* encoding invalid MI type */
		.expect_str = "",
	},
	{
		.mi_type = GSM_MI_TYPE_NONE,
		.mi_str = "1234",
		.mi_name = "unknown",
		.expect_mi_tlv_hex = "17031032f4", /* encoding invalid MI type */
		.expect_str = "",
	},
	{
		.mi_type = GSM_MI_ODD,
		.mi_str = "1234",
		.mi_name = "unknown",
		.expect_mi_tlv_hex = "17031032f4", /* encoding invalid MI type */
		.expect_str = "",
	},
};

static void test_mid_encode_decode(void)
{
	int i;

	printf("\nTesting Mobile Identity conversions\n");

	for (i = 0; i < ARRAY_SIZE(test_mid_encode_decode_tests); i++) {
		const struct test_mid_encode_decode_test *t = &test_mid_encode_decode_tests[i];
		uint8_t tlv_buf[64];
		uint8_t *mi_buf;
		int tlv_len;
		int mi_len;
		const char *tlv_hex;
		char str[64] = {};
		size_t str_size = t->str_size ? : sizeof(str);
		const char *expect_str = t->expect_str ? : t->mi_str;
		int expect_rc = t->expect_rc ? : strlen(expect_str)+1;
		int rc;
		int str_len;

		printf("- %s %s\n", gsm48_mi_type_name(t->mi_type), t->mi_str);
		if (t->mi_type == GSM_MI_TYPE_TMSI)
			tlv_len = gsm48_generate_mid_from_tmsi(tlv_buf, (uint32_t)atoll(t->mi_str));
		else
			tlv_len = gsm48_generate_mid(tlv_buf, t->mi_str, t->mi_type);
		tlv_hex = osmo_hexdump_nospc(tlv_buf, tlv_len);

		printf("  -> MI-TLV-hex='%s'\n", tlv_hex);
		if (t->expect_mi_tlv_hex && strcmp(tlv_hex, t->expect_mi_tlv_hex)) {
			printf("     ERROR: expected '%s'\n", t->expect_mi_tlv_hex);
		}

		/* skip the GSM48_IE_MOBILE_ID tag and length */
		mi_buf = tlv_buf + 2;
		mi_len = tlv_len - 2;

		rc = gsm48_mi_to_string(str, str_size, mi_buf, mi_len);
		printf("  -> MI-str=%s rc=%d\n", osmo_quote_str(str, -1), rc);
		if (strcmp(str, expect_str))
			printf("     ERROR: expected MI-str=%s\n", osmo_quote_str(expect_str, -1));
		if (rc != expect_rc)
			printf("     ERROR: expected rc=%d\n", expect_rc);

		if (t->mi_name) {
			const char *mi_name = osmo_mi_name(mi_buf, mi_len);
			printf("  -> MI-name=%s\n", osmo_quote_str(mi_name, -1));
			if (strcmp(mi_name, t->mi_name))
				printf("     ERROR: expected MI-name=%s\n", osmo_quote_str(t->mi_name, -1));
		}

		/* Now make sure the resulting string is always '\0' terminated.
		 * The above started out with a zeroed buffer, now repeat with a tainted one. */
		str_len = strlen(str);
		str[str_len] = '!';
		gsm48_mi_to_string(str, str_size, mi_buf, mi_len);
		if (strlen(str) != str_len)
			printf("     ERROR: resulting string is not explicitly nul terminated\n");
	}
}

static const uint8_t test_mid_decode_zero_length_types[] = { GSM_MI_TYPE_IMSI, GSM_MI_TYPE_TMSI, GSM_MI_TYPE_NONE };

static void test_mid_decode_zero_length(void)
{
	int odd;
	uint8_t valid_mi[64];
	int valid_mi_len;

	printf("\nDecoding zero length Mobile Identities\n");

	/* IMSI = 123456789012345 */
	valid_mi_len = osmo_hexparse("1932547698103254", valid_mi, sizeof(valid_mi));

	for (odd = 0; odd <= 1; odd++) {
		int i;
		for (i = 0; i < ARRAY_SIZE(test_mid_decode_zero_length_types); i++) {
			uint8_t mi_type = test_mid_decode_zero_length_types[i] | (odd ? GSM_MI_ODD : 0);
			char str[8] = {};
			int rc;

			printf("- MI type: %s%s\n", gsm48_mi_type_name(mi_type & GSM_MI_TYPE_MASK),
			       odd ? " | GSM_MI_ODD":"");
			valid_mi[0] = (valid_mi[0] & 0xf0) | mi_type;

			printf("  - writing to zero-length string:\n");
			memset(str, '!', sizeof(str) - 1);
			rc = gsm48_mi_to_string(str, 0, valid_mi, valid_mi_len);
			printf("    rc=%d\n", rc);
			if (str[0] == '!')
				printf("    nothing written\n");
			else
				printf("    ERROR: Wrote to invalid memory!\n");

			printf("  - writing to 1-byte-length string:\n");
			memset(str, '!', sizeof(str) - 1);
			rc = gsm48_mi_to_string(str, 1, valid_mi, valid_mi_len);
			printf("    rc=%d\n", rc);
			if (str[0] == '\0')
				printf("    returned empty string\n");
			else if (str[0] == '!')
				printf("    ERROR: nothing written, expected nul-terminated empty string\n");
			else
				printf("    ERROR: Wrote unexpected string %s\n", osmo_quote_str(str, 5));
			if (str[1] != '!')
				printf("    ERROR: Wrote to invalid memory!\n");

			printf("  - decode zero-length mi:\n");
			memset(str, '!', sizeof(str) - 1);
			rc = gsm48_mi_to_string(str, sizeof(str), valid_mi, 0);
			printf("    rc=%d\n", rc);
			if (str[0] == '\0')
				printf("    returned empty string\n");
			else if (str[0] == '!')
				printf("    ERROR: nothing written, expected nul-terminated empty string\n");
			else
				printf("    ERROR: expected empty string, got output string: %s\n", osmo_quote_str(str, -1));
		}
	}
	printf("\n");
}

struct msgb *msgb_from_hex(const char *label, uint16_t size, const char *hex)
{
	struct msgb *msg = msgb_alloc_headroom(size, 4, label);
	OSMO_ASSERT(msg);
	msg->l3h = msgb_put(msg, osmo_hexparse(hex, msg->data, msgb_tailroom(msg)));
	return msg;
}

struct mobile_identity_tc {
	const char *label;
	const char *compl_l3_msg;
	int expect_rc;
	struct osmo_mobile_identity expect_mi;
};

/* Some Complete Layer 3 messages copied from real GSM network traces. */
struct mobile_identity_tc mobile_identity_tests[] = {
	{
		.label = "LU with IMSI 901700000004620",
		.compl_l3_msg = "050802008168000130" "089910070000006402",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMSI,
			.imsi = "901700000004620",
		},
	},
	{
		.label = "LU with TMSI 0x0980ad8a",
		.compl_l3_msg = "05084262f224002a50" "05f40980ad8a",
		.expect_mi = {
			.type = GSM_MI_TYPE_TMSI,
			.tmsi = 0x0980ad8a,
		},
	},
	{
		.label = "LU with invalid MI type",
		.compl_l3_msg = "050802008168000130" "089d10070000006402",
		.expect_rc = -EINVAL,
	},
	{
		.label = "LU with truncated IMSI MI",
		.compl_l3_msg = "050802008168000130" "0899100700000064",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "LU with too short IMSI MI (12345)",
		.compl_l3_msg = "050802008168000130" "03193254",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "LU with just long enough IMSI MI 123456",
		.compl_l3_msg = "050802008168000130" "04113254f6",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMSI,
			.imsi = "123456",
		},
	},
	{
		.label = "LU with max length IMSI MI 123456789012345",
		.compl_l3_msg = "050802008168000130" "081932547698103254",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMSI,
			.imsi = "123456789012345",
		},
	},
	{
		.label = "LU with just too long IMSI MI 1234567890123456",
		.compl_l3_msg = "050802008168000130" "091132547698103254f6",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "LU with truncated TMSI MI",
		.compl_l3_msg = "05084262f224002a50" "05f40980ad",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "LU with odd length TMSI",
		.compl_l3_msg = "05084262f224002a50" "05fc0980ad8a",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "LU with too long TMSI MI",
		.compl_l3_msg = "05084262f224002a50" "06f40980ad23",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "LU with too short TMSI",
		.compl_l3_msg = "05084262f224002a50" "04f480ad8a",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "CM Service Request with IMSI 123456",
		.compl_l3_msg = "052401035058a6" "04113254f6",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMSI,
			.imsi = "123456",
		},
	},
	{
		.label = "CM Service Request with TMSI 0x5a42e404",
		.compl_l3_msg = "052401035058a6" "05f45a42e404",
		.expect_mi = {
			.type = GSM_MI_TYPE_TMSI,
			.tmsi = 0x5a42e404,
		},
	},
	{
		.label = "CM Service Request with shorter CM2, with IMSI 123456",
		.compl_l3_msg = "052401025058" "04113254f6",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMSI,
			.imsi = "123456",
		},
	},
	{
		.label = "CM Service Request with longer CM2, with IMSI 123456",
		.compl_l3_msg = "052401055058a62342" "04113254f6",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMSI,
			.imsi = "123456",
		},
	},
	{
		.label = "CM Service Request with shorter CM2, with TMSI 0x00000000",
		.compl_l3_msg = "052401025058" "05f400000000",
		.expect_mi = {
			.type = GSM_MI_TYPE_TMSI,
			.tmsi = 0,
		},
	},
	{
		.label = "CM Service Request with invalid MI type",
		.compl_l3_msg = "052401035058a6" "089d10070000006402",
		.expect_rc = -EINVAL,
	},
	{
		.label = "CM Service Request with truncated IMSI MI",
		.compl_l3_msg = "052401035058a6" "0899100700000064",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "CM Service Request with truncated TMSI MI",
		.compl_l3_msg = "0524010150" "05f40980ad",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "CM Service Request with odd length TMSI",
		.compl_l3_msg = "052401045058a623" "05fc0980ad8a",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "CM Service Request with too long TMSI MI",
		.compl_l3_msg = "052401035058a6" "06f40980ad23",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "CM Service Request with too short TMSI",
		.compl_l3_msg = "052401035058a6" "04f480ad8a",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "CM Service Reestablish Request with TMSI 0x5a42e404",
		.compl_l3_msg = "052801035058a6" "05f45a42e404",
		.expect_mi = {
			.type = GSM_MI_TYPE_TMSI,
			.tmsi = 0x5a42e404,
		},
	},
	{
		.label = "Paging Response with IMSI 1234567",
		.compl_l3_msg = "06270003505886" "0419325476",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMSI,
			.imsi = "1234567",
		},
	},
	{
		.label = "Paging Response with TMSI 0xb48883de",
		.compl_l3_msg = "06270003505886" "05f4b48883de",
		.expect_mi = {
			.type = GSM_MI_TYPE_TMSI,
			.tmsi = 0xb48883de,
		},
	},
	{
		.label = "Paging Response with TMSI, with unused nibble not 0xf",
		.compl_l3_msg = "06270003505886" "0504b48883de",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "Paging Response with too short IMEI (1234567)",
		.compl_l3_msg = "06270003505886" "041a325476",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "Paging Response with IMEI 123456789012345",
		.compl_l3_msg = "06270003505886" "081a32547698103254",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMEI,
			.imei = "123456789012345",
		},
	},
	{
		.label = "Paging Response with IMEI 12345678901234 (no Luhn checksum)",
		.compl_l3_msg = "06270003505886" "0812325476981032f4",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMEI,
			.imei = "12345678901234",
		},
	},
	{
		.label = "Paging Response with IMEISV 1234567890123456",
		.compl_l3_msg = "06270003505886" "091332547698103254f6",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMEISV,
			.imeisv = "1234567890123456",
		},
	},
	{
		.label = "Paging Response with too short IMEISV 123456789012345",
		.compl_l3_msg = "06270003505886" "081b32547698103254",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "Paging Response with too long IMEISV 12345678901234567",
		.compl_l3_msg = "06270003505886" "091b3254769810325476",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "Paging Response with IMSI 123456789012345 and flipped ODD bit",
		.compl_l3_msg = "06270003505886" "081132547698103254",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "IMSI-Detach with IMSI 901700000004620",
		.compl_l3_msg = "050130" "089910070000006402",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMSI,
			.imsi = "901700000004620",
		},
	},
	{
		.label = "IMSI-Detach with TMSI 0x0980ad8a",
		.compl_l3_msg = "050130" "05f40980ad8a",
		.expect_mi = {
			.type = GSM_MI_TYPE_TMSI,
			.tmsi = 0x0980ad8a,
		},
	},
	{
		.label = "IMSI-Detach with invalid MI type",
		.compl_l3_msg = "050130" "089d10070000006402",
		.expect_rc = -EINVAL,
	},
	{
		.label = "IMSI-Detach with truncated IMSI MI",
		.compl_l3_msg = "050130" "0899100700000064",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "IMSI-Detach with too short IMSI MI (12345)",
		.compl_l3_msg = "050130" "03193254",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "IMSI-Detach with just long enough IMSI MI 123456",
		.compl_l3_msg = "050130" "04113254f6",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMSI,
			.imsi = "123456",
		},
	},
	{
		.label = "IMSI-Detach with max length IMSI MI 123456789012345",
		.compl_l3_msg = "050130" "081932547698103254",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMSI,
			.imsi = "123456789012345",
		},
	},
	{
		.label = "IMSI-Detach with just too long IMSI MI 1234567890123456",
		.compl_l3_msg = "050130" "091132547698103254f6",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "IMSI-Detach with truncated TMSI MI",
		.compl_l3_msg = "050130" "05f40980ad",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "IMSI-Detach with odd length TMSI",
		.compl_l3_msg = "050130" "05fc0980ad8a",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "IMSI-Detach with too long TMSI MI",
		.compl_l3_msg = "050130" "06f40980ad23",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "IMSI-Detach with too short TMSI",
		.compl_l3_msg = "050130" "04f480ad8a",
		.expect_rc = -EBADMSG,
	},
	{
		.label = "Identity Response with IMSI 901700000004620",
		.compl_l3_msg = "0519" "089910070000006402",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMSI,
			.imsi = "901700000004620",
		},
	},
	{
		.label = "Identity Response with IMEI 123456789012345",
		.compl_l3_msg = "0519" "081a32547698103254",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMEI,
			.imei = "123456789012345",
		},
	},
	{
		.label = "Identity Response with IMEISV 9876543210987654",
		.compl_l3_msg = "0519" "099378563412907856f4",
		.expect_mi = {
			.type = GSM_MI_TYPE_IMEISV,
			.imeisv = "9876543210987654",
		},
	},
};

void test_struct_mobile_identity(void)
{
	struct mobile_identity_tc *t;
	printf("%s()\n", __func__);
	for (t = mobile_identity_tests; (t - mobile_identity_tests) < ARRAY_SIZE(mobile_identity_tests); t++) {
		struct osmo_mobile_identity mi;
		struct msgb *msg;
		int rc;
		memset(&mi, 0xff, sizeof(mi));

		msg = msgb_from_hex(t->label, 1024, t->compl_l3_msg);
		rc = osmo_mobile_identity_decode_from_l3(&mi, msg, false);
		msgb_free(msg);

		printf("%s: %s", t->label, rc ? "rc != 0" : "rc == 0");
		if (!rc) {
			printf(", mi = %s", osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));
		}

		if (rc == t->expect_rc
		    && ((rc != 0) || !osmo_mobile_identity_cmp(&mi, &t->expect_mi))) {
			printf(" ok");
		} else {
			printf("  ERROR: Got rc = %d, expected rc = %d", rc, t->expect_rc);
			if (!t->expect_rc)
				printf(", mi = %s", osmo_mobile_identity_to_str_c(OTC_SELECT, &t->expect_mi));
		}
		printf("\n");
	}
	printf("\n");
}

static const struct bcd_number_test {
	/* Human-readable test name */
	const char *test_name;

	/* To be encoded number in ASCII */
	const char *enc_ascii;
	/* Expected encoding result in HEX */
	const char *enc_hex;
	/* Optional header length (LHV) */
	uint8_t enc_h_len;
	/* Expected return code */
	int enc_rc;

	/* To be decoded buffer in HEX */
	const char *dec_hex;
	/* Expected decoding result in ASCII */
	const char *dec_ascii;
	/* Optional header length (LHV) */
	uint8_t dec_h_len;
	/* Expected return code */
	int dec_rc;

	/* Encoding buffer limit (0 means unlimited) */
	size_t enc_buf_lim;
	/* Decoding buffer limit (0 means unlimited) */
	size_t dec_buf_lim;
} bcd_number_test_set[] = {
	{
		.test_name = "regular 9-digit MSISDN",

		/* Encoding test */
		.enc_ascii = "123456789",
		.enc_hex   = "0521436587f9",
		.enc_rc    = 6,

		/* Decoding test */
		.dec_hex   = "0521436587f9",
		.dec_ascii = "123456789",
	},
	{
		.test_name = "regular 6-digit MSISDN with optional header (LHV)",

		/* Encoding test */
		.enc_ascii = "123456",
		.enc_hex   = "07ffffffff214365",
		.enc_h_len = 4, /* LHV */
		.enc_rc    = 4 + 4,

		/* Decoding test */
		.dec_hex   = "07deadbeef214365",
		.dec_ascii = "123456",
		.dec_h_len = 4, /* LHV */
	},
	{
		.test_name = "long 15-digit (maximum) MSISDN",

		/* Encoding test */
		.enc_ascii = "123456789012345",
		.enc_hex   = "0821436587092143f5",
		.enc_rc    = 9,

		/* Decoding test */
		.dec_hex   = "0821436587092143f5",
		.dec_ascii = "123456789012345",
	},
	{
		.test_name = "long 15-digit (maximum) MSISDN, limited buffer",

		/* Encoding test */
		.enc_ascii = "123456789012345",
		.enc_hex   = "0821436587092143f5",
		.enc_rc    = 9,

		/* Decoding test */
		.dec_hex   = "0821436587092143f5",
		.dec_ascii = "123456789012345",

		/* Buffer length limitations */
		.dec_buf_lim = 15 + 1,
		.enc_buf_lim = 9,
	},
	{
		.test_name = "to be truncated 20-digit MSISDN",

		/* Encoding test (not enough room in buffer) */
		.enc_ascii = "12345678901234567890",
		.enc_hex   = "", /* nothing */
		.enc_rc    = -EIO,

		/* Decoding test (one 5 digits do not fit) */
		.dec_hex   = "0a21436587092143658709",
		.dec_ascii = "123456789012345",
		.dec_rc    = -ENOSPC,

		/* Buffer length limitations */
		.dec_buf_lim = 15 + 1, /* 5 digits less */
		.enc_buf_lim = 9,
	},
	{
		.test_name = "LV incorrect length",
		.dec_hex   = "05214365", /* should be 0x03 */
		.dec_ascii = "(none)",
		.dec_rc    = -EINVAL,
	},
	{
		.test_name = "empty input buffer",

		/* Encoding test */
		.enc_ascii = "",
		.enc_hex   = "00",
		.enc_rc    = 1,

		/* Decoding test */
		.dec_hex   = "",
		.dec_ascii = "(none)",
		.dec_rc = -EIO,
	},
	{
		.test_name = "decoding buffer is one byte too small (OS#4049)",

		/* Decoding test */
		.dec_hex   = "022143", /* "1234" */
		.dec_ascii = "123",    /* '4' was truncated */
		.dec_rc    = -ENOSPC,

		/* Buffer length limitations */
		.dec_buf_lim = 4,
	},
};

static void test_bcd_number_encode_decode(void)
{
	const struct bcd_number_test *test;
	uint8_t buf_enc[0xff] = { 0xff };
	char buf_dec[0xff] = { 0xff };
	size_t buf_len, i;
	int rc;

	printf("BSD number encoding / decoding test\n");

	for (i = 0; i < ARRAY_SIZE(bcd_number_test_set); i++) {
		test = &bcd_number_test_set[i];
		printf("- Running test: %s\n", test->test_name);

		if (test->enc_ascii) {
			if (test->enc_buf_lim)
				buf_len = test->enc_buf_lim;
			else
				buf_len = sizeof(buf_enc);

			printf("  - Encoding ASCII (buffer limit=%zu) '%s'...\n",
			       test->enc_buf_lim, test->enc_ascii);

			rc = gsm48_encode_bcd_number(buf_enc, buf_len,
				test->enc_h_len, test->enc_ascii);
			printf("    - Expected: (rc=%d) '%s'\n",
			       test->enc_rc, test->enc_hex);
			printf("    -   Actual: (rc=%d) '%s'\n",
			       rc, osmo_hexdump_nospc(buf_enc, rc >= 0 ? rc : 0));
		}

		if (test->dec_hex) {
			/* Parse a HEX string */
			rc = osmo_hexparse(test->dec_hex, buf_enc, sizeof(buf_enc));
			OSMO_ASSERT(rc >= 0);

			if (test->dec_buf_lim)
				buf_len = test->dec_buf_lim;
			else
				buf_len = sizeof(buf_dec);

			printf("  - Decoding HEX (buffer limit=%zu) '%s'...\n",
			       test->dec_buf_lim, test->dec_hex);

			rc = gsm48_decode_bcd_number2(buf_dec, buf_len,
				buf_enc, rc, test->dec_h_len);
			printf("    - Expected: (rc=%d) '%s'\n",
			       test->dec_rc, test->dec_ascii);
			printf("    -   Actual: (rc=%d) '%s'\n",
			       rc, (rc == 0 || rc == -ENOSPC) ? buf_dec : "(none)");
		}

		/* Poison buffers between the test iterations */
		memset(buf_enc, 0xff, sizeof(buf_enc));
		memset(buf_dec, 0xff, sizeof(buf_dec));
	}

	printf("\n");
}

struct {
	int range;
	int arfcns_num;
	int arfcns[OSMO_GSM48_RANGE_ENC_MAX_ARFCNS];
} arfcn_test_ranges[] = {
	{OSMO_GSM48_ARFCN_RANGE_512, 12,
		{ 1, 12, 31, 51, 57, 91, 97, 98, 113, 117, 120, 125 }},
	{OSMO_GSM48_ARFCN_RANGE_512, 17,
		{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 }},
	{OSMO_GSM48_ARFCN_RANGE_512, 18,
		{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 }},
	{OSMO_GSM48_ARFCN_RANGE_512, 18,
		{ 1, 17, 31, 45, 58, 79, 81, 97,
		  113, 127, 213, 277, 287, 311, 331, 391,
		  417, 511 }},
	{OSMO_GSM48_ARFCN_RANGE_512, 6,
		{ 1, 17, 31, 45, 58, 79 }},
	{OSMO_GSM48_ARFCN_RANGE_512, 6,
		{ 10, 17, 31, 45, 58, 79 }},
	{OSMO_GSM48_ARFCN_RANGE_1024, 17,
		{ 0, 17, 31, 45, 58, 79, 81, 97,
		  113, 127, 213, 277, 287, 311, 331, 391,
		  1023 }},
	{OSMO_GSM48_ARFCN_RANGE_1024, 16,
		{ 17, 31, 45, 58, 79, 81, 97, 113,
		  127, 213, 277, 287, 311, 331, 391, 1023 }},
	{-1}
};

static int test_single_range_encoding(int range, const int *orig_arfcns, int arfcns_num, int silent)
{
	int arfcns[OSMO_GSM48_RANGE_ENC_MAX_ARFCNS];
	int w[OSMO_GSM48_RANGE_ENC_MAX_ARFCNS];
	int f0_included = 0;
	int rc, f0;
	uint8_t chan_list[16] = {0};
	struct gsm_sysinfo_freq dec_freq[1024] = {{0}};
	int dec_arfcns[OSMO_GSM48_RANGE_ENC_MAX_ARFCNS] = {0};
	int dec_arfcns_count = 0;
	int arfcns_used = 0;
	int i;

	arfcns_used = arfcns_num;
	memmove(arfcns, orig_arfcns, sizeof(arfcns));

	f0 = range == OSMO_GSM48_ARFCN_RANGE_1024 ? 0 : arfcns[0];
	/*
	 * Manipulate the ARFCN list according to the rules in J4 depending
	 * on the selected range.
	 */
	arfcns_used = osmo_gsm48_range_enc_filter_arfcns(arfcns, arfcns_used, f0, &f0_included);

	memset(w, 0, sizeof(w));
	osmo_gsm48_range_enc_arfcns(range, arfcns, arfcns_used, w, 0);

	if (!silent)
		printf("range=%d, arfcns_used=%d, f0=%d, f0_included=%d\n", range, arfcns_used, f0, f0_included);

	/* Select the range and the amount of bits needed */
	switch (range) {
	case OSMO_GSM48_ARFCN_RANGE_128:
		osmo_gsm48_range_enc_128(chan_list, f0, w);
		break;
	case OSMO_GSM48_ARFCN_RANGE_256:
		osmo_gsm48_range_enc_256(chan_list, f0, w);
		break;
	case OSMO_GSM48_ARFCN_RANGE_512:
		osmo_gsm48_range_enc_512(chan_list, f0, w);
		break;
	case OSMO_GSM48_ARFCN_RANGE_1024:
		osmo_gsm48_range_enc_1024(chan_list, f0, f0_included, w);
		break;
	default:
		return 1;
	};

	if (!silent)
		printf("chan_list = %s\n",
		       osmo_hexdump(chan_list, sizeof(chan_list)));

	rc = gsm48_decode_freq_list(dec_freq, chan_list, sizeof(chan_list),
				    0xfe, 1);
	if (rc != 0) {
		printf("Cannot decode freq list, rc = %d\n", rc);
		return 1;
	}

	for (i = 0; i < ARRAY_SIZE(dec_freq); i++) {
		if (dec_freq[i].mask &&
		    dec_arfcns_count < ARRAY_SIZE(dec_arfcns))
			dec_arfcns[dec_arfcns_count++] = i;
	}

	if (!silent) {
		printf("Decoded freqs %d (expected %d)\n",
		       dec_arfcns_count, arfcns_num);
		printf("Decoded: ");
		for (i = 0; i < dec_arfcns_count; i++) {
			printf("%d ", dec_arfcns[i]);
			if (dec_arfcns[i] != orig_arfcns[i])
				printf("(!= %d) ", orig_arfcns[i]);
		}
		printf("\n");
	}

	if (dec_arfcns_count != arfcns_num) {
		printf("Wrong number of arfcns\n");
		return 1;
	}

	if (memcmp(dec_arfcns, orig_arfcns, sizeof(dec_arfcns)) != 0) {
		printf("Decoding error, got wrong freqs\n");
		printf(" w = ");
		for (i = 0; i < ARRAY_SIZE(w); i++)
			printf("%d ", w[i]);
		printf("\n");
		return 1;
	}

	return 0;
}

static void test_random_range_encoding(int range, int max_arfcn_num)
{
	int arfcns_num = 0;
	int test_idx;
	int rc, max_count;
	int num_tests = 1024;

	printf("Random range test: range %d, max num ARFCNs %d\n",
	       range, max_arfcn_num);

	srandom(1);

	for (max_count = 1; max_count < max_arfcn_num; max_count++) {
		for (test_idx = 0; test_idx < num_tests; test_idx++) {
			int count;
			int i;
			int min_freq = 0;

			int rnd_arfcns[OSMO_GSM48_RANGE_ENC_MAX_ARFCNS] = {0};
			char rnd_arfcns_set[1024] = {0};

			if (range < OSMO_GSM48_ARFCN_RANGE_1024)
				min_freq = random() % (1023 - range);

			for (count = max_count; count; ) {
				int arfcn = min_freq + random() % (range + 1);
				OSMO_ASSERT(arfcn < ARRAY_SIZE(rnd_arfcns_set));

				if (!rnd_arfcns_set[arfcn]) {
					rnd_arfcns_set[arfcn] = 1;
					count -= 1;
				}
			}

			arfcns_num = 0;
			for (i = 0; i < ARRAY_SIZE(rnd_arfcns_set); i++)
				if (rnd_arfcns_set[i])
					rnd_arfcns[arfcns_num++] = i;

			rc = test_single_range_encoding(range, rnd_arfcns,
							arfcns_num, 1);
			if (rc != 0) {
				printf("Failed on test %d, range %d, num ARFCNs %d\n",
				       test_idx, range, max_count);
				test_single_range_encoding(range, rnd_arfcns,
							   arfcns_num, 0);
				return;
			}
		}
	}
}

static void test_range_encoding(void)
{
	int *arfcns;
	int arfcns_num = 0;
	int test_idx;
	int range;

	for (test_idx = 0; arfcn_test_ranges[test_idx].arfcns_num > 0; test_idx++)
	{
		arfcns_num = arfcn_test_ranges[test_idx].arfcns_num;
		arfcns = &arfcn_test_ranges[test_idx].arfcns[0];
		range = arfcn_test_ranges[test_idx].range;

		printf("Range test %d: range %d, num ARFCNs %d\n",
		       test_idx, range, arfcns_num);

		test_single_range_encoding(range, arfcns, arfcns_num, 0);
	}

	test_random_range_encoding(OSMO_GSM48_ARFCN_RANGE_128, 29);
	test_random_range_encoding(OSMO_GSM48_ARFCN_RANGE_256, 22);
	test_random_range_encoding(OSMO_GSM48_ARFCN_RANGE_512, 18);
	test_random_range_encoding(OSMO_GSM48_ARFCN_RANGE_1024, 16);
}

static int freqs1[] = {
	12, 70, 121, 190, 250, 320, 401, 475, 520, 574, 634, 700, 764, 830, 905, 980
};

static int freqs2[] = {
	402, 460, 1, 67, 131, 197, 272, 347,
};

static int freqs3[] = {
	68, 128, 198, 279, 353, 398, 452,

};

static int w_out[] = {
	122, 2, 69, 204, 75, 66, 60, 70, 83, 3, 24, 67, 54, 64, 70, 9,
};

static int range128[] = {
	1, 1 + 127,
};

static int range256[] = {
	1, 1 + 128,
};

static int range512[] = {
	1, 1+ 511,
};


#define VERIFY(res, cmp, wanted)					\
	if (!(res cmp wanted)) {					\
		printf("ASSERT failed: %s:%d Wanted: %d %s %d\n",	\
			__FILE__, __LINE__, (int) res, # cmp, (int) wanted);	\
	}

static void test_arfcn_filter(void)
{
	int arfcns[50], i, res, f0_included;
	for (i = 0; i < ARRAY_SIZE(arfcns); ++i)
		arfcns[i] = (i + 1) * 2;

	/* check that the arfcn is taken out. f0_included is only set for Range1024 */
	f0_included = 24;
	res = osmo_gsm48_range_enc_filter_arfcns(arfcns, ARRAY_SIZE(arfcns), arfcns[0], &f0_included);
	VERIFY(res, ==, ARRAY_SIZE(arfcns) - 1);
	VERIFY(f0_included, ==, 1);
	for (i = 0; i < res; ++i)
		VERIFY(arfcns[i], ==, ((i+2) * 2) - (2+1));

	/* check with range1024, ARFCN 0 is included */
	for (i = 0; i < ARRAY_SIZE(arfcns); ++i)
		arfcns[i] = i * 2;
	res = osmo_gsm48_range_enc_filter_arfcns(arfcns, ARRAY_SIZE(arfcns), 0, &f0_included);
	VERIFY(res, ==, ARRAY_SIZE(arfcns) - 1);
	VERIFY(f0_included, ==, 1);
	for (i = 0; i < res; ++i)
		VERIFY(arfcns[i], ==, (i + 1) * 2 - 1);

	/* check with range1024, ARFCN 0 not included */
	for (i = 0; i < ARRAY_SIZE(arfcns); ++i)
		arfcns[i] = (i + 1) * 2;
	res = osmo_gsm48_range_enc_filter_arfcns(arfcns, ARRAY_SIZE(arfcns), 0, &f0_included);
	VERIFY(res, ==, ARRAY_SIZE(arfcns));
	VERIFY(f0_included, ==, 0);
	for (i = 0; i < res; ++i)
		VERIFY(arfcns[i], ==, ((i + 1) * 2) - 1);
}

static void test_print_encoding(void)
{
	int rc;
	int w[17];
	uint8_t chan_list[16];
	memset(chan_list, 0x23, sizeof(chan_list));

	for (rc = 0; rc < ARRAY_SIZE(w); ++rc)
		switch (rc % 3) {
		case 0:
			w[rc] = 0xAAAA;
			break;
		case 1:
			w[rc] = 0x5555;
			break;
		case 2:
			w[rc] = 0x9696;
			break;
		}

	osmo_gsm48_range_enc_512(chan_list, (1 << 9) | 0x96, w);

	printf("Range512: %s\n", osmo_hexdump(chan_list, ARRAY_SIZE(chan_list)));
}

static void test_si_range_helpers(void)
{
	int ws[(sizeof(freqs1)/sizeof(freqs1[0]))];
	int i, f0 = 0xFFFFFF;

	memset(&ws[0], 0x23, sizeof(ws));

	i = osmo_gsm48_range_enc_find_index(1023, freqs1, ARRAY_SIZE(freqs1));
	printf("Element is: %d => freqs[i] = %d\n", i, i >= 0 ? freqs1[i] : -1);
	VERIFY(i, ==, 2);

	i = osmo_gsm48_range_enc_find_index(511, freqs2, ARRAY_SIZE(freqs2));
	printf("Element is: %d => freqs[i] = %d\n", i,  i >= 0 ? freqs2[i] : -1);
	VERIFY(i, ==, 2);

	i = osmo_gsm48_range_enc_find_index(511, freqs3, ARRAY_SIZE(freqs3));
	printf("Element is: %d => freqs[i] = %d\n", i,  i >= 0 ? freqs3[i] : -1);
	VERIFY(i, ==, 0);

	osmo_gsm48_range_enc_arfcns(1023, freqs1, ARRAY_SIZE(freqs1), ws, 0);

	for (i = 0; i < sizeof(freqs1)/sizeof(freqs1[0]); ++i) {
		printf("w[%d]=%d\n", i, ws[i]);
		VERIFY(ws[i], ==, w_out[i]);
	}

	i = osmo_gsm48_range_enc_determine_range(range128, ARRAY_SIZE(range128), &f0);
	VERIFY(i, ==, OSMO_GSM48_ARFCN_RANGE_128);
	VERIFY(f0, ==, 1);

	i = osmo_gsm48_range_enc_determine_range(range256, ARRAY_SIZE(range256), &f0);
	VERIFY(i, ==, OSMO_GSM48_ARFCN_RANGE_256);
	VERIFY(f0, ==, 1);

	i = osmo_gsm48_range_enc_determine_range(range512, ARRAY_SIZE(range512), &f0);
	VERIFY(i, ==, OSMO_GSM48_ARFCN_RANGE_512);
	VERIFY(f0, ==, 1);
}

static void test_power_ctrl(void)
{
	int8_t rc8;
	int rc;

	rc8 = osmo_gsm48_rfpowercap2powerclass(GSM_BAND_850, 0x00);
	VERIFY(rc8, ==, 1);
	rc8 = osmo_gsm48_rfpowercap2powerclass(GSM_BAND_900, 0x02);
	VERIFY(rc8, ==, 3);
	rc8 = osmo_gsm48_rfpowercap2powerclass(GSM_BAND_1800, 0x02);
	VERIFY(rc8, ==, 3);
	rc8 = osmo_gsm48_rfpowercap2powerclass(GSM_BAND_1900, 0x02);
	VERIFY(rc8, ==, 3);
	rc8 = osmo_gsm48_rfpowercap2powerclass(GSM_BAND_1900, 0x04);
	VERIFY(rc8, <, 0);
	rc8 = osmo_gsm48_rfpowercap2powerclass(GSM_BAND_900, 0x04);
	VERIFY(rc8, ==, 5);
	rc8 = osmo_gsm48_rfpowercap2powerclass(GSM_BAND_900, 0x05);
	VERIFY(rc8, <, 0);
	rc8 = osmo_gsm48_rfpowercap2powerclass(GSM_BAND_900, 0xf2);
	VERIFY(rc8, <, 0);

	rc = ms_class_gmsk_dbm(GSM_BAND_850, 0);
	VERIFY(rc, <, 0);
	rc = ms_class_gmsk_dbm(GSM_BAND_850, 1);
	VERIFY(rc, ==, 43);
	rc = ms_class_gmsk_dbm(GSM_BAND_900, 3);
	VERIFY(rc, ==, 37);
	rc = ms_class_gmsk_dbm(GSM_BAND_1800, 2);
	VERIFY(rc, ==, 24);
	rc = ms_class_gmsk_dbm(GSM_BAND_1800, 3);
	VERIFY(rc, ==, 36);
	rc = ms_class_gmsk_dbm(GSM_BAND_1900, 3);
	VERIFY(rc, ==, 33);
	rc = ms_class_gmsk_dbm(GSM_BAND_1900, 4);
	VERIFY(rc, <, 0);
	rc = ms_class_gmsk_dbm(GSM_BAND_900, 5);
	VERIFY(rc, ==, 29);
	rc = ms_class_gmsk_dbm(GSM_BAND_900, 6);
	VERIFY(rc, <, 0);
}

static void test_rach_tx_integer_raw2val(void)
{
	unsigned int raw;
	for (raw = 0; raw <= 0x0f; raw++) {
		unsigned int val = rach_tx_integer_raw2val(raw);
		printf("rach_tx_integer_raw2val(0x0%x): %u slots used to spread transmission\n",
			raw, val);
	}
}

static void test_gsm_gsmtime2fn(void)
{
	struct gsm_time gsm_time;
	uint32_t fn;
	uint32_t fn_recovered;

	for (fn = 0; fn < 42432; fn++) {
		gsm_time.t1 = (fn / 1326) % 32;
		gsm_time.t2 = fn % 26;
		gsm_time.t3 = fn % 51;

		fn_recovered = gsm_gsmtime2fn(&gsm_time);

		if (fn_recovered != fn) {
			printf(" Wrong frame number computed! t1=%d, t2=%d, t3=%d ==> fn=%d, expected fn=%d\n",
			       gsm_time.t1, gsm_time.t2, gsm_time.t3, fn_recovered, fn);
			OSMO_ASSERT(false);
		}
	}
}

int main(int argc, char **argv)
{
	test_bearer_cap();
	test_mid_from_tmsi();
	test_mid_from_imsi();
	test_mid_encode_decode();
	test_mid_decode_zero_length();
	test_struct_mobile_identity();
	test_bcd_number_encode_decode();
	test_ra_cap();
	test_lai_encode_decode();
	test_decode_classmark3();

	test_si_range_helpers();
	test_arfcn_filter();
	test_print_encoding();
	test_range_encoding();
	test_power_ctrl();
	test_rach_tx_integer_raw2val();
	test_gsm_gsmtime2fn();

	return EXIT_SUCCESS;
}
