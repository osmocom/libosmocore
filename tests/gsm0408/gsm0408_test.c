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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/gsm48.h>
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


struct bcap_test {
	const uint8_t *lv;
	const struct gsm_mncc_bearer_cap *bc;
	const char *name;
};

static const struct bcap_test bcap_tests[] = {
	{ csd_9600_v110_lv, &bcap_csd_9600_v110, "CSD 9600/V.110/transparent" },
	{ speech_all_lv, &bcap_speech_all, "Speech, all codecs" },
};

static int test_bearer_cap()
{
	struct gsm_mncc_bearer_cap bc;
	int i, rc;

	for (i = 0; i < ARRAY_SIZE(bcap_tests); i++) {
		struct msgb *msg = msgb_alloc(100, "test");
		int lv_len;

		memset(&bc, 0, sizeof(bc));

		/* test decoding */
		rc = gsm48_decode_bearer_cap(&bc, bcap_tests[i].lv);
		if (rc < 0) {
			fprintf(stderr, "Error decoding %s\n",
				bcap_tests[i].name);
			return rc;
		}
		if (memcmp(&bc, bcap_tests[i].bc, sizeof(bc))) {
			fprintf(stderr, "Incorrect decoded result of %s:\n",
				bcap_tests[i].name);
			fprintf(stderr, " should: %s\n",
				osmo_hexdump((uint8_t *) bcap_tests[i].bc, sizeof(bc)));
			fprintf(stderr, " is:     %s\n",
				osmo_hexdump((uint8_t *) &bc, sizeof(bc)));
			return -1;
		}

		/* also test re-encode? */
		rc = gsm48_encode_bearer_cap(msg, 1, &bc);
		if (rc < 0) {
			fprintf(stderr, "Error encoding %s\n",
				bcap_tests[i].name);
			return rc;
		}
		lv_len = bcap_tests[i].lv[0]+1;
		if (memcmp(msg->data, bcap_tests[i].lv, lv_len)) {
			fprintf(stderr, "Incorrect encoded result of %s:\n",
				bcap_tests[i].name);
			fprintf(stderr, " should: %s\n",
				osmo_hexdump(bcap_tests[i].lv, lv_len));
			fprintf(stderr, " is:     %s\n",
				osmo_hexdump(msg->data, msg->len));
			return -1;
		}

		printf("Test `%s' passed\n", bcap_tests[i].name);
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
	},
	{
		.mcc = 999,
		.mnc = 999,
		.lac = 65535,
		.rac = 255,
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

int main(int argc, char **argv)
{
	test_bearer_cap();
	test_mid_from_tmsi();
	test_mid_from_imsi();
	test_ra_cap();
	test_lai_encode_decode();

	return EXIT_SUCCESS;
}
