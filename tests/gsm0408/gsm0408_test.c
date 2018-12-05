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
	size_t str_size;
	const char *expect_mi_tlv_hex;
	const char *expect_str;
	int expect_rc;
};

static const struct test_mid_encode_decode_test test_mid_encode_decode_tests[] = {
	{
		.mi_type = GSM_MI_TYPE_IMSI,
		.mi_str = "123456789012345",
		.expect_mi_tlv_hex = "17081932547698103254",
	},
	{
		.mi_type = GSM_MI_TYPE_IMSI,
		.mi_str = "12345678901234",
		.expect_mi_tlv_hex = "170811325476981032f4",
	},
	{
		.mi_type = GSM_MI_TYPE_IMSI,
		.mi_str = "423423",
		.expect_mi_tlv_hex = "1704413224f3",
	},
	{
		.mi_type = GSM_MI_TYPE_IMSI | GSM_MI_ODD,
		.mi_str = "423423",
		.expect_mi_tlv_hex = "1704413224f3",
	},
	{
		.mi_type = GSM_MI_TYPE_IMSI,
		.mi_str = "4234235",
		.expect_mi_tlv_hex = "170449322453",
	},
	{
		.mi_type = GSM_MI_TYPE_IMSI,
		.mi_str = "4234235",
		.expect_mi_tlv_hex = "170449322453",
		.str_size = 4,
		.expect_str = "423",
	},
	{
		.mi_type = GSM_MI_TYPE_IMEI,
		.mi_str = "123456789012345",
		.expect_mi_tlv_hex = "17081a32547698103254",
	},
	{
		.mi_type = GSM_MI_TYPE_IMEI,
		.mi_str = "98765432109876",
		.expect_mi_tlv_hex = "170892785634129078f6",
	},
	{
		.mi_type = GSM_MI_TYPE_IMEI,
		.mi_str = "987654321098765",
		.expect_mi_tlv_hex = "17089a78563412907856",
	},
	{
		.mi_type = GSM_MI_TYPE_IMEISV,
		.mi_str = "987654321098765432",
		.expect_mi_tlv_hex = "170a937856341290785634f2",
	},
	{
		.mi_type = GSM_MI_TYPE_IMEISV,
		.mi_str = "987654321098765432",
		.expect_mi_tlv_hex = "170a937856341290785634f2",
		.str_size = 16,
		.expect_str = "987654321098765",
	},
	{
		/* gsm48 treats TMSI as decimal string */
		.mi_type = GSM_MI_TYPE_TMSI,
		.mi_str = "305419896", /* 0x12345678 as decimal */
		.expect_mi_tlv_hex = "1705f412345678",
		.expect_rc = 9, /* exception: gsm48_mi_to_string() for TMSI returns strlen(), not bytes! */
	},
	{
		.mi_type = GSM_MI_TYPE_TMSI,
		.mi_str = "12648430", /* 0xc0ffee as decimal */
		.expect_mi_tlv_hex = "1705f400c0ffee",
		.expect_rc = 8, /* exception: gsm48_mi_to_string() for TMSI returns strlen(), not bytes! */
	},
	{
		.mi_type = GSM_MI_TYPE_TMSI,
		.mi_str = "0",
		.expect_mi_tlv_hex = "1705f400000000",
		.expect_rc = 1, /* exception: gsm48_mi_to_string() for TMSI returns strlen(), not bytes! */
	},
	{
		/* gsm48 treats TMSI as decimal string */
		.mi_type = GSM_MI_TYPE_TMSI,
		.mi_str = "305419896", /* 0x12345678 as decimal */
		.expect_mi_tlv_hex = "1705f412345678",
		.str_size = 5,
		.expect_str = "3054",
		.expect_rc = 9, /* exception: gsm48_mi_to_string() for TMSI returns would-be strlen() like snprintf()! */
	},
	{
		.mi_type = GSM_MI_TYPE_NONE,
		.mi_str = "123",
		.expect_mi_tlv_hex = "17021832", /* encoding invalid MI type */
		.expect_str = "",
	},
	{
		.mi_type = GSM_MI_TYPE_NONE,
		.mi_str = "1234",
		.expect_mi_tlv_hex = "17031032f4", /* encoding invalid MI type */
		.expect_str = "",
	},
	{
		.mi_type = GSM_MI_ODD,
		.mi_str = "1234",
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

int main(int argc, char **argv)
{
	test_bearer_cap();
	test_mid_from_tmsi();
	test_mid_from_imsi();
	test_mid_encode_decode();
	test_mid_decode_zero_length();
	test_ra_cap();
	test_lai_encode_decode();

	return EXIT_SUCCESS;
}
