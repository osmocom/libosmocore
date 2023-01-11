/* tests for utilities of libmsomcore */
/*
 * (C) 2014 Holger Hans Peter Freyther
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
 */

#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>

#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>

static void hexdump_test(void)
{
	uint8_t data[4098];
	char buf[256];
	int i;

	for (i = 0; i < ARRAY_SIZE(data); ++i)
		data[i] = i & 0xff;

	printf("Plain dump\n");
	printf("%s\n", osmo_hexdump(data, 4));
	printf("%s\n", osmo_hexdump_nospc(data, 4));

	printf("Corner case\n");
	printf("%s\n", osmo_hexdump(data, ARRAY_SIZE(data)));
	printf("%s\n", osmo_hexdump_nospc(data, ARRAY_SIZE(data)));

#define _HEXDUMP_BUF_TEST(SIZE, DELIM, DELIM_AFTER) \
	buf[0] = '!'; \
	buf[1] = '\0'; \
	printf("osmo_hexdump_buf(buf, " #SIZE ", data, 4, %s, " #DELIM_AFTER ")\n = \"%s\"\n", \
	       DELIM ? #DELIM : "NULL", \
	       osmo_hexdump_buf(buf, SIZE, data, 4, DELIM, DELIM_AFTER))
#define HEXDUMP_BUF_TEST(DELIM) \
	_HEXDUMP_BUF_TEST(sizeof(buf), DELIM, false); \
	_HEXDUMP_BUF_TEST(sizeof(buf), DELIM, true); \
	_HEXDUMP_BUF_TEST(6, DELIM, false); \
	_HEXDUMP_BUF_TEST(7, DELIM, false); \
	_HEXDUMP_BUF_TEST(8, DELIM, false); \
	_HEXDUMP_BUF_TEST(6, DELIM, true); \
	_HEXDUMP_BUF_TEST(7, DELIM, true); \
	_HEXDUMP_BUF_TEST(8, DELIM, true)

	HEXDUMP_BUF_TEST("[delim]");
	HEXDUMP_BUF_TEST(" ");
	HEXDUMP_BUF_TEST(":");
	HEXDUMP_BUF_TEST("::");
	HEXDUMP_BUF_TEST("");
	HEXDUMP_BUF_TEST(NULL);
}

static void hexparse_test(void)
{
	int i;
	int rc;
	uint8_t data[256];

	printf("\nHexparse 0..255 in lower case\n");
	memset(data, 0, sizeof(data));
	rc = osmo_hexparse(
		"000102030405060708090a0b0c0d0e0f"
		"101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f"
		"303132333435363738393a3b3c3d3e3f"
		"404142434445464748494a4b4c4d4e4f"
		"505152535455565758595a5b5c5d5e5f"
		"606162636465666768696a6b6c6d6e6f"
		"707172737475767778797a7b7c7d7e7f"
		"808182838485868788898a8b8c8d8e8f"
		"909192939495969798999a9b9c9d9e9f"
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
		"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
		"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
		"e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
		, data, sizeof(data));
	printf("rc = %d\n", rc);
	printf("--> %s\n\n", osmo_hexdump(data, sizeof(data)));
	for (i = 0; i < sizeof(data); i++)
		OSMO_ASSERT(data[i] == i);

	printf("Hexparse 0..255 in upper case\n");
	memset(data, 0, sizeof(data));
	rc = osmo_hexparse(
		"000102030405060708090A0B0C0D0E0F"
		"101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F"
		"303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F"
		"505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F"
		"707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F"
		"909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
		"B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
		"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
		"E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
		, data, sizeof(data));
	printf("rc = %d\n", rc);
	printf("--> %s\n\n", osmo_hexdump(data, sizeof(data)));
	for (i = 0; i < sizeof(data); i++)
		OSMO_ASSERT(data[i] == i);

	printf("Hexparse 0..255 in mixed case\n");
	memset(data, 0, sizeof(data));
	rc = osmo_hexparse(
		"000102030405060708090A0B0C0D0E0F"
		"101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F"
		"303132333435363738393a3b3c3d3e3f"
		"404142434445464748494A4B4C4D4E4F"
		"505152535455565758595a5b5c5d5e5f"
		"606162636465666768696A6B6C6D6E6F"
		"707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F"
		"909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3a4a5a6a7a8a9AAABACADAEAF"
		"B0B1B2B3b4b5b6b7b8b9BABBBCBDBEBF"
		"C0C1C2C3c4c5c6c7c8c9CACBCCCDCECF"
		"D0D1D2D3d4d5d6d7d8d9DADBDCDDDEDF"
		"E0E1E2E3e4e5e6e7e8e9EAEBECEDEEEF"
		"F0F1F2F3f4f5f6f7f8f9FAFBFCFDFEFF"
		, data, sizeof(data));
	printf("rc = %d\n", rc);
	printf("--> %s\n\n", osmo_hexdump(data, sizeof(data)));
	for (i = 0; i < sizeof(data); i++)
		OSMO_ASSERT(data[i] == i);

	printf("Hexparse 0..255 with whitespace\n");
	memset(data, 0, sizeof(data));
	rc = osmo_hexparse(
		"00 01\t02\r030405060708090A0B0C0D0 E  0    F\n"
		"10 11\t12\r131415161718191A1B1C1D1 E  1    F\n"
		"20 21\t22\r232425262728292A2B2C2D2 E  2    F\n"
		"30 31\t32\r333435363738393a3b3c3d3 e  3    f\n"
		"40 41\t42\r434445464748494A4B4C4D4 E  4    F\n"
		"50 51\t52\r535455565758595a5b5c5d5 e  5    f\n"
		"60 61\t62\r636465666768696A6B6C6D6 E  6    F\n"
		"70 71\t72\r737475767778797A7B7C7D7 E  7    F\n"
		"80 81\t82\r838485868788898A8B8C8D8 E  8    F\n"
		"90 91\t92\r939495969798999A9B9C9D9 E  9    F\n"
		"A0 A1\tA2\rA3a4a5a6a7a8a9AAABACADA E  A    F\n"
		"B0 B1\tB2\rB3b4b5b6b7b8b9BABBBCBDB E  B    F\n"
		"C0 C1\tC2\rC3c4c5c6c7c8c9CACBCCCDC E  C    F \n"
		"D0 D1\tD2\rD3d4d5d6d7d8d9DADBDCDDD E  D    F\t\n"
		"E0 E1\tE2\rE3e4e5e6e7e8e9EAEBECEDE E  E    F \t\n"
		"F0 F1\tF2\rF3f4f5f6f7f8f9FAFBFCFDF E  F    F \t\r\n"
		, data, sizeof(data));
	printf("rc = %d\n", rc);
	printf("--> %s\n\n", osmo_hexdump(data, sizeof(data)));
	for (i = 0; i < sizeof(data); i++)
		OSMO_ASSERT(data[i] == i);

	printf("Hexparse with buffer too short\n");
	memset(data, 0, sizeof(data));
	rc = osmo_hexparse("000102030405060708090a0b0c0d0e0f", data, 15);
	printf("rc = %d\n", rc);

	printf("Hexparse with uneven amount of digits\n");
	memset(data, 0, sizeof(data));
	rc = osmo_hexparse("000102030405060708090a0b0c0d0e0", data, 16);
	printf("rc = %d\n", rc);

	printf("Hexparse with invalid char\n");
	memset(data, 0, sizeof(data));
	rc = osmo_hexparse("0001020304050X0708090a0b0c0d0e0f", data, 16);
	printf("rc = %d\n", rc);
}

static void test_ipa_ccm_id_resp_parsing(void)
{
	struct tlv_parsed tvp;
	int rc;

	static const uint8_t id_resp_data[] = {
		0x00, 0x13,	IPAC_IDTAG_MACADDR,
			'0','0',':','0','2',':','9','5',':','0','0',':','6','2',':','9','e','\0',
		0x00, 0x11,	IPAC_IDTAG_IPADDR,
			'1','9','2','.','1','6','8','.','1','0','0','.','1','9','0','\0',
		0x00, 0x0a,	IPAC_IDTAG_UNIT,
			'1','2','3','4','/','0','/','0','\0',
		0x00, 0x02,	IPAC_IDTAG_LOCATION1,
			'\0',
		0x00, 0x0d,	IPAC_IDTAG_LOCATION2,
			'B','T','S','_','N','B','T','1','3','1','G','\0',
		0x00, 0x0c,	IPAC_IDTAG_EQUIPVERS,
			'1','6','5','a','0','2','9','_','5','5','\0',
		0x00, 0x14,	IPAC_IDTAG_SWVERSION,
			'1','6','8','d','4','7','2','_','v','2','0','0','b','4','1','1','d','0','\0',
		0x00, 0x18,	IPAC_IDTAG_UNITNAME,
			'n','b','t','s','-','0','0','-','0','2','-','9','5','-','0','0','-','6','2','-','9','E','\0',
		0x00, 0x0a,	IPAC_IDTAG_SERNR,
			'0','0','1','1','0','7','8','1','\0'
	};

	printf("\nTesting IPA CCM ID RESP parsing\n");

	rc = ipa_ccm_id_resp_parse(&tvp, (uint8_t *) id_resp_data, sizeof(id_resp_data));
	OSMO_ASSERT(rc == 0);

	OSMO_ASSERT(TLVP_PRESENT(&tvp, IPAC_IDTAG_MACADDR));
	OSMO_ASSERT(TLVP_LEN(&tvp, IPAC_IDTAG_MACADDR) == 0x12);
	OSMO_ASSERT(TLVP_PRESENT(&tvp, IPAC_IDTAG_IPADDR));
	OSMO_ASSERT(TLVP_LEN(&tvp, IPAC_IDTAG_IPADDR) == 0x10);
	OSMO_ASSERT(TLVP_PRESENT(&tvp, IPAC_IDTAG_UNIT));
	OSMO_ASSERT(TLVP_LEN(&tvp, IPAC_IDTAG_UNIT) == 0x09);
	OSMO_ASSERT(TLVP_PRESENT(&tvp, IPAC_IDTAG_LOCATION1));
	OSMO_ASSERT(TLVP_LEN(&tvp, IPAC_IDTAG_LOCATION1) == 0x01);
	OSMO_ASSERT(TLVP_PRESENT(&tvp, IPAC_IDTAG_LOCATION2));
	OSMO_ASSERT(TLVP_LEN(&tvp, IPAC_IDTAG_LOCATION2) == 0x0c);
	OSMO_ASSERT(TLVP_PRESENT(&tvp, IPAC_IDTAG_EQUIPVERS));
	OSMO_ASSERT(TLVP_LEN(&tvp, IPAC_IDTAG_EQUIPVERS) == 0x0b);
	OSMO_ASSERT(TLVP_PRESENT(&tvp, IPAC_IDTAG_SWVERSION));
	OSMO_ASSERT(TLVP_LEN(&tvp, IPAC_IDTAG_EQUIPVERS) == 0x0b);
	OSMO_ASSERT(TLVP_LEN(&tvp, IPAC_IDTAG_SWVERSION) == 0x13);
	OSMO_ASSERT(TLVP_PRESENT(&tvp, IPAC_IDTAG_UNITNAME));
	OSMO_ASSERT(TLVP_LEN(&tvp, IPAC_IDTAG_UNITNAME) == 0x17);
	OSMO_ASSERT(TLVP_PRESENT(&tvp, IPAC_IDTAG_SERNR));
	OSMO_ASSERT(TLVP_LEN(&tvp, IPAC_IDTAG_SERNR) == 0x09);
}

static void test_ipa_ccm_id_get_parsing(void)
{
	struct tlv_parsed tvp;
	int rc;

	/* IPA CCM IDENTITY REQUEST message: 8bit length followed by respective value */
        static const uint8_t id_get_data[] = {
		0x01, 0x08,
		0x01, 0x07,
		0x01, 0x02,
		0x01, 0x03,
		0x01, 0x04,
		0x01, 0x05,
		0x01, 0x01,
		0x01, 0x00,
		0x11, 0x23, 0x4e, 0x6a, 0x28, 0xd2, 0xa2, 0x53, 0x3a, 0x2a, 0x82, 0xa7, 0x7a, 0xef, 0x29, 0xd4, 0x44, 0x30,
		0x11, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

	printf("\nTesting IPA CCM ID GET parsing\n");

	rc = ipa_ccm_id_get_parse(&tvp, id_get_data, sizeof(id_get_data));
	OSMO_ASSERT(rc == 0);

	OSMO_ASSERT(TLVP_PRESENT(&tvp, 8));
	OSMO_ASSERT(TLVP_LEN(&tvp, 8) == 0);

	OSMO_ASSERT(TLVP_PRESENT(&tvp, 7));
	OSMO_ASSERT(TLVP_LEN(&tvp, 7) == 0);

	OSMO_ASSERT(TLVP_PRESENT(&tvp, 2));
	OSMO_ASSERT(TLVP_LEN(&tvp, 2) == 0);

	OSMO_ASSERT(TLVP_PRESENT(&tvp, 3));
	OSMO_ASSERT(TLVP_LEN(&tvp, 3) == 0);

	OSMO_ASSERT(TLVP_PRESENT(&tvp, 4));
	OSMO_ASSERT(TLVP_LEN(&tvp, 4) == 0);

	OSMO_ASSERT(TLVP_PRESENT(&tvp, 5));
	OSMO_ASSERT(TLVP_LEN(&tvp, 5) == 0);

	OSMO_ASSERT(TLVP_PRESENT(&tvp, 1));
	OSMO_ASSERT(TLVP_LEN(&tvp, 1) == 0);

	OSMO_ASSERT(TLVP_PRESENT(&tvp, 0));
	OSMO_ASSERT(TLVP_LEN(&tvp, 0) == 0);

	OSMO_ASSERT(TLVP_PRESENT(&tvp, 0x23));
	OSMO_ASSERT(TLVP_LEN(&tvp, 0x23) == 16);

	OSMO_ASSERT(TLVP_PRESENT(&tvp, 0x24));
	OSMO_ASSERT(TLVP_LEN(&tvp, 0x24) == 16);

	OSMO_ASSERT(!TLVP_PRESENT(&tvp, 0x25));
}

static struct {
	const char *str;
	int min_digits;
	int max_digits;
	bool require_even;
	bool expect_ok;
} test_hexstrs[] = {
	{ NULL, 0, 10, false, true },
	{ NULL, 1, 10, false, false },
	{ "", 0, 10, false, true },
	{ "", 1, 10, false, false },
	{ " ", 0, 10, false, false },
	{ "1", 0, 10, false, true },
	{ "1", 1, 10, false, true },
	{ "1", 1, 10, true, false },
	{ "1", 2, 10, false, false },
	{ "123", 1, 10, false, true },
	{ "123", 1, 10, true, false },
	{ "123", 4, 10, false, false },
	{ "1234", 4, 10, true, true },
	{ "12345", 4, 10, true, false },
	{ "123456", 4, 10, true, true },
	{ "1234567", 4, 10, true, false },
	{ "12345678", 4, 10, true, true },
	{ "123456789", 4, 10, true, false },
	{ "123456789a", 4, 10, true, true },
	{ "123456789ab", 4, 10, true, false },
	{ "123456789abc", 4, 10, true, false },
	{ "123456789ab", 4, 10, false, false },
	{ "123456789abc", 4, 10, false, false },
	{ "0123456789abcdefABCDEF", 0, 100, false, true },
	{ "0123456789 abcdef ABCDEF", 0, 100, false, false },
	{ "foobar", 0, 100, false, false },
	{ "BeadedBeeAced1EbbedDefacedFacade", 32, 32, true, true },
	{ "C01ffedC1cadaeAc1d1f1edAcac1aB0a", 32, 32, false, true },
	{ "DeafBeddedBabeAcceededFadedDecaff", 32, 32, false, false },
};

bool test_is_hexstr(void)
{
	int i;
	bool pass = true;
	bool ok = true;
	printf("\n----- %s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(test_hexstrs); i++) {
		ok = osmo_is_hexstr(test_hexstrs[i].str,
				    test_hexstrs[i].min_digits,
				    test_hexstrs[i].max_digits,
				    test_hexstrs[i].require_even);
		pass = pass && (ok == test_hexstrs[i].expect_ok);
		printf("%2d: %s str='%s' min=%d max=%d even=%d expect=%s\n",
		       i, test_hexstrs[i].expect_ok == ok ? "pass" : "FAIL",
		       test_hexstrs[i].str,
		       test_hexstrs[i].min_digits,
		       test_hexstrs[i].max_digits,
		       test_hexstrs[i].require_even,
		       test_hexstrs[i].expect_ok ? "valid" : "invalid");
	}
	return pass;
}

struct bcdcheck {
	uint8_t bcd;
	char ch;
};

static const struct bcdcheck bcdchecks[]  = {
	{ 0, '0' },
	{ 1, '1' },
	{ 2, '2' },
	{ 3, '3' },
	{ 4, '4' },
	{ 5, '5' },
	{ 6, '6' },
	{ 7, '7' },
	{ 8, '8' },
	{ 9, '9' },
	{ 0xA, 'A' },
	{ 0xB, 'B' },
	{ 0xC, 'C' },
	{ 0xD, 'D' },
	{ 0xE, 'E' },
	{ 0xF, 'F' },
};

static void bcd_test(void)
{
	int i;

	printf("\nTesting BCD conversion\n");
	for (i = 0; i < ARRAY_SIZE(bcdchecks); i++) {
		const struct bcdcheck *check = &bcdchecks[i];
		char ch = osmo_bcd2char(check->bcd);
		printf("\tval=0x%x, expected=%c, found=%c\n", check->bcd, check->ch, ch);
		OSMO_ASSERT(osmo_bcd2char(check->bcd) == check->ch);
		/* test char -> bcd back-coversion */
		OSMO_ASSERT(osmo_char2bcd(ch) == check->bcd);
		/* test for lowercase hex char */
		OSMO_ASSERT(osmo_char2bcd(tolower(ch)) == check->bcd);
	}
}

struct bcd2str_test {
	const char *bcd_hex;
	int start_nibble;
	int end_nibble;
	bool allow_hex;
	size_t str_size;
	const char *expect_str;
	int expect_rc;
};

static const struct bcd2str_test bcd2str_tests[] = {
	{
		.bcd_hex = "1a 32 54 76 98 f0",
		.start_nibble = 1,
		.end_nibble = 11,
		.expect_str = "1234567890",
		.expect_rc = 10,
	},
	{
		.bcd_hex = "1a 32 a4 cb 9d f0",
		.start_nibble = 1,
		.end_nibble = 11,
		.expect_str = "1234ABCD90",
		.expect_rc = -EINVAL,
	},
	{
		.bcd_hex = "1a 32 a4 cb 9d f0",
		.start_nibble = 1,
		.end_nibble = 11,
		.allow_hex = true,
		.expect_str = "1234ABCD90",
		.expect_rc = 10,
	},
	{
		.bcd_hex = "1a 32 54 76 98 f0",
		.start_nibble = 1,
		.end_nibble = 12,
		.expect_str = "1234567890F",
		.expect_rc = -EINVAL,
	},
	{
		.bcd_hex = "1a 32 54 76 98 f0",
		.start_nibble = 1,
		.end_nibble = 12,
		.allow_hex = true,
		.expect_str = "1234567890F",
		.expect_rc = 11,
	},
	{
		.bcd_hex = "1a 32 54 76 98 f0",
		.start_nibble = 0,
		.end_nibble = 12,
		.allow_hex = true,
		.expect_str = "A1234567890F",
		.expect_rc = 12,
	},
	{
		.bcd_hex = "1a 32 54 76 98 f0",
		.start_nibble = 1,
		.end_nibble = 12,
		.str_size = 5,
		.expect_str = "1234",
		.expect_rc = 11,
	},
	{
		.bcd_hex = "",
		.start_nibble = 1,
		.end_nibble = 1,
		.expect_str = "",
		.expect_rc = 0,
	},
};

static void bcd2str_test(void)
{
	int i;
	uint8_t bcd[64];
	uint8_t bcd2[64];
	int rc;

	printf("\nTesting bcd to string conversion\n");

	for (i = 0; i < ARRAY_SIZE(bcd2str_tests); i++) {
		const struct bcd2str_test *t = &bcd2str_tests[i];
		char str[64] = {};
		size_t str_size = t->str_size ? : sizeof(str);

		osmo_hexparse(t->bcd_hex, bcd, sizeof(bcd));

		printf("- BCD-input='%s' nibbles=[%d..%d[ str_size=%zu\n", t->bcd_hex,
		       t->start_nibble, t->end_nibble, str_size);
		rc = osmo_bcd2str(str, str_size, bcd, t->start_nibble, t->end_nibble, t->allow_hex);

		printf("  rc=%d\n", rc);

		OSMO_ASSERT(str[str_size-1] == '\0');
		printf("  -> %s\n", osmo_quote_str(str, -1));

		if (rc != t->expect_rc)
			printf("    ERROR: expected rc=%d\n", t->expect_rc);
		if (strcmp(str, t->expect_str))
			printf("    ERROR: expected result %s\n", osmo_quote_str(t->expect_str, -1));

		memset(bcd2, 0xff, sizeof(bcd2));
		rc = osmo_str2bcd(bcd2, sizeof(bcd2), str, t->start_nibble, -1, t->allow_hex);
		printf("osmo_str2bcd(start_nibble=%d) -> rc=%d\n", t->start_nibble, rc);
		if (rc > 0)
			printf(" = %s\n", osmo_hexdump(bcd2, rc));
	}

	printf("- zero output buffer\n");
	rc = osmo_bcd2str(NULL, 100, bcd, 1, 2, false);
	printf("  bcd2str(NULL, ...) -> %d\n", rc);
	OSMO_ASSERT(rc < 0);
	rc = osmo_bcd2str((char*)23, 0, bcd, 1, 2, false);
	printf("  bcd2str(dst, 0, ...) -> %d\n", rc);
	OSMO_ASSERT(rc < 0);
}

static void str_escape_test(void)
{
	int i;
	int j;
	uint8_t in_buf[32];
	char out_buf[11];
	const char *printable = "printable";
	const char *res;

	printf("\nTesting string escaping: osmo_escape_str()\n");
	printf("- all chars from 0 to 255 in batches of 16:\n");
	in_buf[16] = '\0';
	for (j = 0; j < 16; j++) {
		for (i = 0; i < 16; i++)
			in_buf[i] = (j << 4) | i;
		printf("\"%s\"\n", osmo_escape_str((const char*)in_buf, 16));
	}

	printf("- nul terminated:\n");
	printf("\"%s\"\n", osmo_escape_str("termi\nated", -1));

	printf("- passthru:\n");
	res = osmo_escape_str(printable, -1);
	if (strcmp(res, printable))
		printf("NOT passed through! \"%s\"\n", res);
	else
		printf("passed through unchanged \"%s\"\n", res);

	printf("- zero length:\n");
	printf("\"%s\"\n", osmo_escape_str("omitted", 0));

	printf("- truncation when too long:\n");
	memset(in_buf, 'x', sizeof(in_buf));
	in_buf[0] = '\a';
	in_buf[7] = 'E';
	memset(out_buf, 0x7f, sizeof(out_buf));
	printf("\"%s\"\n", osmo_escape_str_buf((const char *)in_buf, sizeof(in_buf), out_buf, 10));
	OSMO_ASSERT(out_buf[10] == 0x7f);
}

static void str_quote_test(void)
{
	int i;
	int j;
	uint8_t in_buf[32];
	char out_buf[11];
	const char *printable = "printable";
	const char *res;

	printf("\nTesting string quoting: osmo_quote_str()\n");
	printf("- all chars from 0 to 255 in batches of 16:\n");
	in_buf[16] = '\0';
	for (j = 0; j < 16; j++) {
		for (i = 0; i < 16; i++)
			in_buf[i] = (j << 4) | i;
		printf("'%s'\n", osmo_quote_str((const char*)in_buf, 16));
	}

	printf("- nul terminated:\n");
	printf("'%s'\n", osmo_quote_str("termi\nated", -1));

	printf("- never passthru:\n");
	res = osmo_quote_str(printable, -1);
	if (strcmp(res, printable))
		printf("NOT passed through. '%s'\n", res);
	else
		printf("passed through unchanged '%s'\n", res);

	printf("- zero length:\n");
	printf("'%s'\n", osmo_quote_str("omitted", 0));

	printf("- truncation when too long:\n");
	memset(in_buf, 'x', sizeof(in_buf));
	in_buf[0] = '\a';
	in_buf[6] = 'E';
	memset(out_buf, 0x7f, sizeof(out_buf));
	printf("'%s'\n", osmo_quote_str_buf((const char *)in_buf, sizeof(in_buf), out_buf, 10));
	OSMO_ASSERT(out_buf[10] == 0x7f);

	printf("- always truncation, even when no escaping needed:\n");
	memset(in_buf, 'x', sizeof(in_buf));
	in_buf[7] = 'E'; /* dst has 10, less 1 quote and nul, leaves 8, i.e. in[7] is last */
	in_buf[20] = '\0';
	memset(out_buf, 0x7f, sizeof(out_buf));
	printf("'%s'\n", osmo_quote_str_buf((const char *)in_buf, -1, out_buf, 10));
	OSMO_ASSERT(out_buf[0] == '"');

	printf("- try to feed too little buf for quoting:\n");
	printf("'%s'\n", osmo_quote_str_buf("", -1, out_buf, 2));

	printf("- NULL string becomes a \"NULL\" literal:\n");
	printf("'%s'\n", osmo_quote_str_buf(NULL, -1, out_buf, 10));
}

static void str_escape3_test(void)
{
	int i;
	int j;
	uint8_t in_buf[32];
	char out_buf[11];
	const char *printable = "printable";
	const char *res;
	void *ctx = talloc_named_const(NULL, 0, __func__);

	printf("\nTesting string escaping: osmo_escape_cstr_buf()\n");
	printf("- all chars from 0 to 255 in batches of 16:\n");
	in_buf[16] = '\0';
	for (j = 0; j < 16; j++) {
		for (i = 0; i < 16; i++)
			in_buf[i] = (j << 4) | i;
		printf("\"%s\"\n", osmo_escape_cstr_c(ctx, (const char*)in_buf, 16));
	}

	printf("- nul terminated:\n");
	printf("\"%s\"\n", osmo_escape_cstr_c(ctx, "termi\nated", -1));

	printf("- passthru:\n");
	res = osmo_escape_cstr_c(ctx, printable, -1);
	if (strcmp(res, printable))
		printf("NOT passed through! \"%s\"\n", res);
	else
		printf("passed through unchanged \"%s\"\n", res);

	printf("- zero length:\n");
	printf("\"%s\"\n", osmo_escape_cstr_c(ctx, "omitted", 0));

	printf("- truncation when too long:\n");
	memset(in_buf, 'x', sizeof(in_buf));
	in_buf[0] = '\a';
	in_buf[7] = 'E';
	memset(out_buf, 0x7f, sizeof(out_buf));
	osmo_escape_cstr_buf(out_buf, 10, (const char *)in_buf, sizeof(in_buf));
	printf("\"%s\"\n", out_buf);
	OSMO_ASSERT(out_buf[10] == 0x7f);

	printf("- Test escaping an escaped string:\n");
	res = "\x02\x03\n";
	for (i = 0; i <= 3; i++) {
		res = osmo_escape_cstr_c(ctx, res, -1);
		printf("%d: '%s'\n", i, res);
	}

	talloc_free(ctx);
}

static void str_quote3_test(void)
{
	int i;
	int j;
	uint8_t in_buf[32];
	char out_buf[11];
	const char *printable = "printable";
	const char *res;
	void *ctx = talloc_named_const(NULL, 0, __func__);

	printf("\nTesting string quoting: osmo_quote_cstr_buf()\n");
	printf("- all chars from 0 to 255 in batches of 16:\n");
	in_buf[16] = '\0';
	for (j = 0; j < 16; j++) {
		for (i = 0; i < 16; i++)
			in_buf[i] = (j << 4) | i;
		printf("%s\n", osmo_quote_cstr_c(ctx, (const char*)in_buf, 16));
	}

	printf("- nul terminated:\n");
	printf("'%s'\n", osmo_quote_cstr_c(ctx, "termi\nated", -1));

	printf("- never passthru:\n");
	res = osmo_quote_cstr_c(ctx, printable, -1);
	if (strcmp(res, printable))
		printf("NOT passed through. '%s'\n", res);
	else
		printf("passed through unchanged '%s'\n", res);

	printf("- zero length:\n");
	printf("'%s'\n", osmo_quote_cstr_c(ctx, "omitted", 0));

	printf("- truncation when too long:\n");
	memset(in_buf, 'x', sizeof(in_buf));
	in_buf[0] = '\a';
	in_buf[6] = 'E';
	memset(out_buf, 0x7f, sizeof(out_buf));
	osmo_quote_cstr_buf(out_buf, 10, (const char *)in_buf, sizeof(in_buf));
	printf("'%s'\n", out_buf);
	OSMO_ASSERT(out_buf[10] == 0x7f);

	printf("- always truncation, even when no escaping needed:\n");
	memset(in_buf, 'x', sizeof(in_buf));
	in_buf[7] = 'E'; /* dst has 10, less 1 quote and nul, leaves 8, i.e. in[7] is last */
	in_buf[20] = '\0';
	memset(out_buf, 0x7f, sizeof(out_buf));
	osmo_quote_cstr_buf(out_buf, 10, (const char *)in_buf, -1);
	printf("'%s'\n", out_buf);
	OSMO_ASSERT(out_buf[0] == '"');
	OSMO_ASSERT(out_buf[10] == 0x7f);

	printf("- try to feed too little buf for quoting:\n");
	osmo_quote_cstr_buf(out_buf, 2, "", -1);
	printf("'%s'\n", out_buf);

	printf("- Test quoting a quoted+escaped string:\n");
	res = "\x02\x03\n";
	for (i = 0; i <= 3; i++) {
		res = osmo_quote_cstr_c(ctx, res, -1);
		printf("%d: %s\n", i, res);
	}

	printf("- Test C-string equivalence:\n");
#define TEST_STR "\0\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
#define EMPTY_STR ""
	printf("strcmp(OSMO_STRINGIFY_VAL(TEST_STR), osmo_quote_cstr_c(ctx, TEST_STR, 256)) == %d\n",
	       strcmp(OSMO_STRINGIFY_VAL(TEST_STR), osmo_quote_cstr_c(ctx, TEST_STR, 256)));
	printf("strcmp(OSMO_STRINGIFY_VAL(EMPTY_STR), osmo_quote_cstr_c(ctx, EMPTY_STR, -1)) == %d\n",
	       strcmp(OSMO_STRINGIFY_VAL(EMPTY_STR), osmo_quote_cstr_c(ctx, EMPTY_STR, -1)));
	printf("strcmp(\"NULL\", osmo_quote_cstr_c(ctx, NULL, -1)) == %d\n",
	       strcmp("NULL", osmo_quote_cstr_c(ctx, NULL, -1)));

	talloc_free(ctx);
}

static void isqrt_test(void)
{
	int i;

	printf("\nTesting integer square-root\n");
	srand(time(NULL));
	for (i = 0; i < 1024; i++) {
		uint16_t x;
		uint32_t r = rand();
		if (RAND_MAX < UINT16_MAX)
			x = r * (UINT16_MAX/RAND_MAX);
		else
			x = r;
		uint32_t sq = (uint32_t)x*x;
		uint32_t y = osmo_isqrt32(sq);
		if (y != x)
			printf("ERROR: x=%u, sq=%u, osmo_isqrt(%u) = %u\n", x, sq, sq, y);
	}
}

static void mod_test_mod(int x, int y, int expected_result)
{
	int result;
	result = x % y;
	printf(" %d mod %d = %d = %d\n", x, y, result, expected_result);
	OSMO_ASSERT(result == expected_result);
}

static void mod_test_mod_flr(int x, int y, int expected_result)
{
	int result;
	result = OSMO_MOD_FLR(x, y);
	printf(" %d mod_flr %d = %d = %d\n", x, y, result, expected_result);
	OSMO_ASSERT(result == expected_result);
}

static void mod_test_mod_euc(int x, int y, int expected_result)
{
	int result;
	result = OSMO_MOD_EUC(x, y);
	printf(" %d mod_euc %d = %d = %d\n", x, y, result, expected_result);
	OSMO_ASSERT(result == expected_result);
}

static void mod_test(void)
{
	/* See also: Daan Leijen, Division and Modulus for Computer
	 * Scientists, section 1.3 */

	printf("\nTesting built in truncated modulo for comparison:\n");
	mod_test_mod(8, 3, 2);
	mod_test_mod(8, -3, 2);
	mod_test_mod(-8, 3, -2);
	mod_test_mod(-8, -3, -2);
	mod_test_mod(1, 2, 1);
	mod_test_mod(1, -2, 1);
	mod_test_mod(-1, 2, -1);
	mod_test_mod(-1, -2, -1);

	printf("\nTesting OSMO_MOD_FLR():\n");
	mod_test_mod_flr(8, 3, 2);
	mod_test_mod_flr(8, -3, -1);
	mod_test_mod_flr(-8, 3, 1);
	mod_test_mod_flr(-8, -3, -2);
	mod_test_mod_flr(1, 2, 1);
	mod_test_mod_flr(1, -2, -1);
	mod_test_mod_flr(-1, 2, 1);
	mod_test_mod_flr(-1, -2, -1);

	printf("\nTesting OSMO_MOD_EUC():\n");
	mod_test_mod_euc(8, 3, 2);
	mod_test_mod_euc(8, -3, 2);
	mod_test_mod_euc(-8, 3, 1);
	mod_test_mod_euc(-8, -3, 1);
	mod_test_mod_euc(1, 2, 1);
	mod_test_mod_euc(1, -2, 1);
	mod_test_mod_euc(-1, 2, 1);
	mod_test_mod_euc(-1, -2, 1);
}

struct osmo_sockaddr_to_str_and_uint_test_case {
	uint16_t port;
	bool omit_port;
	const char *addr;
	unsigned int addr_len;
	int address_family; /* AF_INET / AF_INET6 */
	bool omit_addr;
	unsigned int expect_rc;
	const char *expect_returned_addr;
};

struct osmo_sockaddr_to_str_and_uint_test_case osmo_sockaddr_to_str_and_uint_test_data[] = {
	{
		.port = 0,
		.addr = "0.0.0.0",
		.addr_len = 20,
		.address_family = AF_INET,
		.expect_rc = 7,
	},
	{
		.port = 65535,
		.addr = "255.255.255.255",
		.addr_len = 20,
		.address_family = AF_INET,
		.expect_rc = 15,
	},
	{
		.port = 1234,
		.addr = "234.23.42.123",
		.addr_len = 20,
		.address_family = AF_INET,
		.expect_rc = 13,
	},
	{
		.port = 1234,
		.addr = "234.23.42.123",
		.addr_len = 10,
		.address_family = AF_INET,
		.expect_rc = 13,
		.expect_returned_addr = "234.23.42",
	},
	{
		.port = 1234,
		.omit_port = true,
		.addr = "234.23.42.123",
		.addr_len = 20,
		.address_family = AF_INET,
		.expect_rc = 13,
	},
	{
		.port = 1234,
		.addr = "234.23.42.123",
		.address_family = AF_INET,
		.omit_addr = true,
		.expect_rc = 0,
		.expect_returned_addr = "",
	},
	{
		.port = 1234,
		.addr = "234.23.42.123",
		.addr_len = 0,
		.address_family = AF_INET,
		.expect_rc = 13,
		.expect_returned_addr = "",
	},
	{
		.port = 1234,
		.addr = "234.23.42.123",
		.address_family = AF_INET,
		.omit_port = true,
		.omit_addr = true,
		.expect_rc = 0,
		.expect_returned_addr = "",
	},
	{
		.port = 1234,
		.addr = "::",
		.addr_len = 20,
		.address_family = AF_INET6,
		.expect_rc = 2,
	},
	{
		.port = 1234,
		.addr = "::1",
		.addr_len = 20,
		.address_family = AF_INET6,
		.expect_rc = 3,
	},
	{
		.port = 1234,
		.addr = "::1",
		.addr_len = 20,
		.address_family = AF_INET6,
		.omit_port = true,
		.omit_addr = false,
		.expect_rc = 3,
	},
	{
		.port = 1234,
		.addr = "::1",
		.addr_len = 20,
		.address_family = AF_INET6,
		.omit_port = false,
		.omit_addr = true,
		.expect_rc = 0,
		.expect_returned_addr = "",
	},
	{
		.port = 1234,
		.addr = "fd02:db8:1::1",
		.addr_len = 20,
		.address_family = AF_INET6,
		.expect_rc = 13,
	},
	{
		.port = 1234,
		.addr = "2001:db8:1::ab9:C0A8:102",
		.addr_len = 40,
		.address_family = AF_INET6,
		.expect_rc = 24,
		.expect_returned_addr = "2001:db8:1::ab9:c0a8:102",
	},
	{
		.port = 1234,
		.addr = "2001:0db8:0001:0000:0000:0ab9:C0A8:0102",
		.addr_len = 32,
		.address_family = AF_INET6,
		.expect_rc = 24,
		.expect_returned_addr = "2001:db8:1::ab9:c0a8:102",
	},
	{
		.port = 1234,
		.addr = "::ffff:192.168.20.34",
		.addr_len = 32,
		.address_family = AF_INET6,
		.expect_rc = 20,
		.expect_returned_addr = "::ffff:192.168.20.34",
	}
};

static void osmo_sockaddr_to_str_and_uint_test(void)
{
	int i;
	printf("\n%s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(osmo_sockaddr_to_str_and_uint_test_data); i++) {
		struct osmo_sockaddr_to_str_and_uint_test_case *t =
			&osmo_sockaddr_to_str_and_uint_test_data[i];

		struct sockaddr_storage sa;
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;
		sa.ss_family = t->address_family;
		switch (t->address_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)&sa;
			OSMO_ASSERT(inet_pton(t->address_family, t->addr, &sin->sin_addr) == 1);
			sin->sin_port = htons(t->port);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)&sa;
			OSMO_ASSERT(inet_pton(t->address_family, t->addr, &sin6->sin6_addr) == 1);
			sin6->sin6_port = htons(t->port);
			break;
		default:
			OSMO_ASSERT(0);
		}

		char addr[INET6_ADDRSTRLEN] = {};
		uint16_t port = 0;
		unsigned int rc;

		rc = osmo_sockaddr_to_str_and_uint(
			t->omit_addr? NULL : addr, t->addr_len,
			t->omit_port? NULL : &port,
			(const struct sockaddr *)&sa);

		printf("[%d] [%s]:%u%s%s addr_len=%u --> [%s]:%u rc=%u\n",
		       i,
		       t->addr ? : "-",
		       t->port,
		       t->omit_addr ? " (omit addr)" : "",
		       t->omit_port ? " (omit port)" : "",
		       t->addr_len,
		       addr, port, rc);
		if (rc != t->expect_rc)
			printf("ERROR: Expected rc = %u\n", t->expect_rc);
		if (!t->expect_returned_addr)
			t->expect_returned_addr = t->addr;
		if (strcmp(t->expect_returned_addr, addr))
			printf("ERROR: Expected addr = '%s'\n", t->expect_returned_addr);
		if (!t->omit_port && port != t->port)
			printf("ERROR: Expected port = %u\n", t->port);
	}
}

struct osmo_str_tolowupper_test_data {
	const char *in;
	bool use_static_buf;
	size_t buflen;
	const char *expect_lower;
	const char *expect_upper;
	size_t expect_rc;
	size_t expect_rc_inplace;
};

struct osmo_str_tolowupper_test_data osmo_str_tolowupper_tests[] = {
	{
		.in = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()",
		.use_static_buf = true,
		.expect_lower = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz!@#$%^&*()",
		.expect_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()",
	},
	{
		.in = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()",
		.buflen = 99,
		.expect_lower = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz!@#$%^&*()",
		.expect_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()",
		.expect_rc = 62,
		.expect_rc_inplace = 62,
	},
	{
		.in = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()",
		.buflen = 0,
		.expect_lower = "Unset",
		.expect_upper = "Unset",
		.expect_rc = 62,
		.expect_rc_inplace = 0,
	},
	{
		.in = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()",
		.buflen = 1,
		.expect_lower = "",
		.expect_upper = "",
		.expect_rc = 62,
		.expect_rc_inplace = 0,
	},
	{
		.in = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()",
		.buflen = 2,
		.expect_lower = "a",
		.expect_upper = "A",
		.expect_rc = 62,
		.expect_rc_inplace = 1,
	},
	{
		.in = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()",
		.buflen = 28,
		.expect_lower = "abcdefghijklmnopqrstuvwxyza",
		.expect_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZA",
		.expect_rc = 62,
		.expect_rc_inplace = 27,
	},
};


static void osmo_str_tolowupper_test(void)
{
	int i;
	char buf[128];
	bool ok = true;
	printf("\n%s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(osmo_str_tolowupper_tests); i++) {
		struct osmo_str_tolowupper_test_data *d = &osmo_str_tolowupper_tests[i];
		size_t rc = 0;
		const char *res;

		/* tolower */
		if (d->use_static_buf) {
			res = osmo_str_tolower(d->in);
			printf("osmo_str_tolower(%s)\n", osmo_quote_str(d->in, -1));
			printf("               = %s\n", osmo_quote_str(res, -1));
		} else {
			OSMO_ASSERT(sizeof(buf) >= d->buflen);
			osmo_strlcpy(buf, "Unset", sizeof(buf));
			rc = osmo_str_tolower_buf(buf, d->buflen, d->in);
			res = buf;
			printf("osmo_str_tolower_buf(%zu, %s)\n", d->buflen, osmo_quote_str(d->in, -1));
			printf("                   = %zu, %s\n", rc, osmo_quote_str(res, -1));
		}

		if (strcmp(res, d->expect_lower)) {
			printf("ERROR: osmo_str_tolowupper_test[%d] tolower\n"
			       "       got %s\n", i, osmo_quote_str(res, -1));
			printf("  expected %s\n", osmo_quote_str(d->expect_lower, -1));
			ok = false;
		}

		if (!d->use_static_buf && d->expect_rc != rc) {
			printf("ERROR: osmo_str_tolowupper_test[%d] tolower\n"
			       "       got rc=%zu, expected rc=%zu\n", i, rc, d->expect_rc);
			ok = false;
		}

		/* tolower, in-place */
		if (!d->use_static_buf) {
			osmo_strlcpy(buf,
				     d->buflen ? d->in : "Unset",
				     sizeof(buf));
			rc = osmo_str_tolower_buf(buf, d->buflen, buf);
			res = buf;
			printf("osmo_str_tolower_buf(%zu, %s, in-place)\n",
			       d->buflen, osmo_quote_str(d->in, -1));
			printf("                   = %zu, %s\n", rc, osmo_quote_str(res, -1));

			if (strcmp(res, d->expect_lower)) {
				printf("ERROR: osmo_str_tolowupper_test[%d] tolower in-place\n"
				       "       got %s\n", i, osmo_quote_str(res, -1));
				printf("  expected %s\n", osmo_quote_str(d->expect_lower, -1));
				ok = false;
			}

			if (d->expect_rc_inplace != rc) {
				printf("ERROR: osmo_str_tolowupper_test[%d] tolower in-place\n"
				       "       got rc=%zu, expected rc=%zu\n",
				       i, rc, d->expect_rc_inplace);
				ok = false;
			}
		}

		/* toupper */
		if (d->use_static_buf) {
			res = osmo_str_toupper(d->in);
			printf("osmo_str_toupper(%s)\n", osmo_quote_str(d->in, -1));
			printf("               = %s\n", osmo_quote_str(res, -1));
		} else {
			OSMO_ASSERT(sizeof(buf) >= d->buflen);
			osmo_strlcpy(buf, "Unset", sizeof(buf));
			rc = osmo_str_toupper_buf(buf, d->buflen, d->in);
			res = buf;
			printf("osmo_str_toupper_buf(%zu, %s)\n", d->buflen, osmo_quote_str(d->in, -1));
			printf("                   = %zu, %s\n", rc, osmo_quote_str(res, -1));
		}

		if (strcmp(res, d->expect_upper)) {
			printf("ERROR: osmo_str_tolowupper_test[%d] toupper\n"
			       "       got %s\n", i, osmo_quote_str(res, -1));
			printf("  expected %s\n", osmo_quote_str(d->expect_upper, -1));
			ok = false;
		}

		if (!d->use_static_buf && d->expect_rc != rc) {
			printf("ERROR: osmo_str_tolowupper_test[%d] toupper\n"
			       "       got rc=%zu, expected rc=%zu\n", i, rc, d->expect_rc);
			ok = false;
		}

		/* toupper, in-place */
		if (!d->use_static_buf) {
			osmo_strlcpy(buf,
				     d->buflen ? d->in : "Unset",
				     sizeof(buf));
			rc = osmo_str_toupper_buf(buf, d->buflen, buf);
			res = buf;
			printf("osmo_str_toupper_buf(%zu, %s, in-place)\n",
			       d->buflen, osmo_quote_str(d->in, -1));
			printf("                   = %zu, %s\n", rc, osmo_quote_str(res, -1));

			if (strcmp(res, d->expect_upper)) {
				printf("ERROR: osmo_str_tolowupper_test[%d] toupper in-place\n"
				       "       got %s\n", i, osmo_quote_str(res, -1));
				printf("  expected %s\n", osmo_quote_str(d->expect_upper, -1));
				ok = false;
			}

			if (d->expect_rc_inplace != rc) {
				printf("ERROR: osmo_str_tolowupper_test[%d] toupper in-place\n"
				       "       got rc=%zu, expected rc=%zu\n",
				       i, rc, d->expect_rc_inplace);
				ok = false;
			}
		}
	}

	OSMO_ASSERT(ok);
}

/* Copy of the examples from OSMO_STRBUF_APPEND() */
int print_spaces(char *dst, size_t dst_len, int argument)
{
	int i;
	if (argument < 0)
		return -EINVAL;
	for (i = 0; i < argument && i < dst_len; i++)
		dst[i] = ' ';
	if (dst_len)
		dst[OSMO_MIN(dst_len - 1, argument)] = '\0';
	return argument;
}

void strbuf_example(char *buf, size_t buflen)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };

	OSMO_STRBUF_APPEND(sb, print_spaces, 5);
	OSMO_STRBUF_APPEND(sb, snprintf, "The answer is %d but what is the question?", 42);
	OSMO_STRBUF_APPEND(sb, print_spaces, 423423);

	printf("%s\n", buf);
	printf("would have needed %zu bytes\n", sb.chars_needed);
}

/* Copy of the examples from OSMO_STRBUF_PRINTF() */
int strbuf_example2(char *buf, size_t buflen)
{
	int i;
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };

	OSMO_STRBUF_PRINTF(sb, "T minus");
	for (i = 10; i; i--)
		OSMO_STRBUF_PRINTF(sb, " %d", i);
	OSMO_STRBUF_PRINTF(sb, " ... Lift off!");

	return sb.chars_needed;
}

int strbuf_cascade(char *buf, size_t buflen)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };

	OSMO_STRBUF_APPEND(sb, strbuf_example2);
	OSMO_STRBUF_PRINTF(sb, " -- ");
	OSMO_STRBUF_APPEND(sb, strbuf_example2);
	OSMO_STRBUF_PRINTF(sb, " -- ");
	OSMO_STRBUF_APPEND(sb, strbuf_example2);

	return sb.chars_needed;
}

void strbuf_test(void)
{
	char buf[256];
	int rc;
	printf("\n%s\n", __func__);

	printf("OSMO_STRBUF_APPEND():\n");
	strbuf_example(buf, 23);

	printf("\nOSMO_STRBUF_PRINTF():\n");
	rc = strbuf_example2(buf, 23);
	printf("1: (need %d chars, had size=23) %s\n", rc, buf);

	rc = strbuf_example2(buf, rc);
	printf("2: (need %d chars, had size=%d) %s\n", rc, rc, buf);

	rc = strbuf_example2(buf, rc + 1);
	printf("3: (need %d chars, had size=%d+1) %s\n", rc, rc, buf);

	rc = strbuf_example2(buf, 0);
	snprintf(buf, sizeof(buf), "0x2b 0x2b 0x2b...");
	printf("4: (need %d chars, had size=0) %s\n", rc, buf);

	rc = strbuf_example2(NULL, 99);
	printf("5: (need %d chars, had NULL buffer)\n", rc);

	printf("\ncascade:\n");
	rc = strbuf_cascade(buf, sizeof(buf));
	printf("(need %d chars)\n%s\n", rc, buf);
	rc = strbuf_cascade(buf, 63);
	printf("(need %d chars, had size=63) %s\n", rc, buf);
}

void strbuf_test_nolen(void)
{
	char buf[20];
	struct osmo_strbuf sb = { .buf = buf, .len = sizeof(buf) };
	uint8_t ubits[] = {0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0};
	printf("\n%s\n", __func__);

	OSMO_STRBUF_APPEND_NOLEN(sb, osmo_ubit_dump_buf, ubits, sizeof(ubits));
	printf("%zu: %s (need=%zu)\n", sb.len, buf, sb.chars_needed);
	OSMO_STRBUF_APPEND_NOLEN(sb, osmo_ubit_dump_buf, ubits, sizeof(ubits));
	printf("more: %s (need=%zu)\n", buf, sb.chars_needed);

	sb = (struct osmo_strbuf){ .buf = buf, .len = 10 };
	OSMO_STRBUF_APPEND_NOLEN(sb, osmo_ubit_dump_buf, ubits, sizeof(ubits));
	printf("%zu: %s (need=%zu)\n", sb.len, buf, sb.chars_needed);
}

static void startswith_test_str(const char *str, const char *startswith_str, bool expect_rc)
{
	bool rc = osmo_str_startswith(str, startswith_str);
	printf("osmo_str_startswith(%s, ", osmo_quote_str(str, -1));
	printf("%s) == %s\n", osmo_quote_str(startswith_str, -1), rc ? "true" : "false");
	if (rc != expect_rc)
		printf("   ERROR: EXPECTED %s\n", expect_rc ? "true" : "false");
}

static void startswith_test(void)
{
	printf("\n%s()\n", __func__);
	startswith_test_str(NULL, NULL, true);
	startswith_test_str("", NULL, true);
	startswith_test_str(NULL, "", true);
	startswith_test_str("", "", true);
	startswith_test_str("abc", NULL, true);
	startswith_test_str("abc", "", true);
	startswith_test_str(NULL, "abc", false);
	startswith_test_str("", "abc", false);
	startswith_test_str("abc", "a", true);
	startswith_test_str("abc", "ab", true);
	startswith_test_str("abc", "abc", true);
	startswith_test_str("abc", "abcd", false);
	startswith_test_str("abc", "xyz", false);
}

static int foo_name_buf(char *buf, size_t buflen, const char *arg)
{
	if (!arg)
		return -EINVAL;
	return snprintf(buf, buflen, "%s", arg);
}

static char *foo_name_c(void *ctx, const char *arg)
{
        OSMO_NAME_C_IMPL(ctx, 10, "ERROR", foo_name_buf, arg)
}

static char *foo_name_c_null(void *ctx, const char *arg)
{
	OSMO_NAME_C_IMPL(ctx, 10, NULL, foo_name_buf, arg)
}

static char *foo_name_c_zero(void *ctx, const char *arg)
{
        OSMO_NAME_C_IMPL(ctx, 0, "ERROR", foo_name_buf, arg)
}

static char *foo_name_c_zero_null(void *ctx, const char *arg)
{
        OSMO_NAME_C_IMPL(ctx, 0, NULL, foo_name_buf, arg)
}

static void name_c_impl_test(void)
{
	char *test_strs[] = {
		"test",
		"longer than 10 chars",
		NULL,
	};
	struct {
		const char *label;
		char *(*func)(void *, const char*);
	} funcs[] = {
		{
			"OSMO_NAME_C_IMPL(10, \"ERROR\")",
			foo_name_c,
		},
		{
			"OSMO_NAME_C_IMPL(10, NULL)",
			foo_name_c_null,
		},
		{
			"OSMO_NAME_C_IMPL(0, \"ERROR\")",
			foo_name_c_zero,
		},
		{
			"OSMO_NAME_C_IMPL(0, NULL)",
			foo_name_c_zero_null,
		},
	};

	int i;
	void *ctx = talloc_named_const(NULL, 0, __func__);
	int allocs = talloc_total_blocks(ctx);

	printf("\n%s\n", __func__);
	for (i = 0; i < ARRAY_SIZE(test_strs); i++) {
		char *test_str = test_strs[i];
		int j;
		printf("%2d: %s\n", i, osmo_quote_str(test_str, -1));

		for (j = 0; j < ARRAY_SIZE(funcs); j++) {
			char *str = funcs[j].func(ctx, test_str);
			printf("  %30s -> %s", funcs[j].label, osmo_quote_str(str, -1));
			printf("  allocated %d", (int)talloc_total_blocks(ctx) - allocs);
			if (str) {
				printf("  %zu bytes, name '%s'", talloc_total_size(str), talloc_get_name(str));
				talloc_free(str);
			}
			printf("\n");
		}
	}
	talloc_free(ctx);
}

static void osmo_print_n_test(void)
{
	struct token_test {
		const char *src;
		size_t token_len;
		size_t buf_size;
		const char *expect_token;
		int expect_rc;
	};
	struct token_test tests[] = {
		{ "foo=bar", 3, 100, "foo", 3 },
		{ "foo", 10, 100, "foo", 3 },
		{ "foo", 3, 100, "foo", 3 },
		{ NULL, 10, 100, "", 0 },
		{ "", 10, 100, "", 0 },
		{ "foo=bar", 0, 100, "", 0 },

		{ "foo=bar", 3, 2, "f", 3 },
		{ "foo", 10, 2, "f", 3 },
		{ "foo", 3, 2, "f", 3 },
		{ NULL, 10, 2, "", 0 },
		{ "", 10, 2, "", 0 },
		{ "foo=bar", 0, 2, "", 0 },

		{ "foo=bar", 3, 1, "", 3 },
		{ "foo", 10, 1, "", 3 },
		{ "foo", 3, 1, "", 3 },
		{ NULL, 10, 1, "", 0 },
		{ "", 10, 1, "", 0 },
		{ "foo=bar", 0, 1, "", 0 },

		{ "foo=bar", 3, 0, "unchanged", 3 },
		{ "foo", 10, 0, "unchanged", 3 },
		{ "foo", 3, 0, "unchanged", 3 },
		{ NULL, 10, 0, "unchanged", 0 },
		{ "", 10, 0, "unchanged", 0 },
		{ "foo=bar", 0, 0, "unchanged", 0 },
	};
	struct token_test *t;
	printf("\n%s()\n", __func__);
	for (t = tests; t - tests < ARRAY_SIZE(tests); t++) {
		char buf[100] = "unchanged";
		int rc = osmo_print_n(buf, t->buf_size, t->src, t->token_len);
		printf("%s token_len=%zu buf_size=%zu", osmo_quote_str(t->src, -1), t->token_len, t->buf_size);
		printf(" -> token=%s rc=%d", osmo_quote_str(buf, -1), rc);
		if (strcmp(buf, t->expect_token))
			printf(" ERROR: expected token %s", osmo_quote_str(t->expect_token, -1));
		if (rc != t->expect_rc)
			printf(" ERROR: expected rc %d", t->expect_rc);
		printf("\n");
	}
}

static void osmo_strnchr_test(void)
{
	struct test {
		const char *haystack;
		size_t haystack_len;
		const char *needle;
		int expect_offset;
	};
	struct test tests[] = {
		{ "foo=bar", 8, "=", 3 },
		{ "foo=bar", 4, "=", 3 },
		{ "foo=bar", 3, "=", -1 },
		{ "foo=bar", 0, "=", -1 },
		{ "foo\0=bar", 9, "=", -1 },
		{ "foo\0=bar", 9, "\0", 3 },
	};
	struct test *t;
	printf("\n%s()\n", __func__);
	for (t = tests; t - tests < ARRAY_SIZE(tests); t++) {
		const char *r = osmo_strnchr(t->haystack, t->haystack_len, t->needle[0]);
		int offset = -1;
		if (r)
			offset = r - t->haystack;
		printf("osmo_strnchr(%s, %zu, ",
		       osmo_quote_str(t->haystack, -1), t->haystack_len);
		printf("'%s') -> %d",
		       osmo_escape_str(t->needle, 1), offset);
		if (offset != t->expect_offset)
			printf(" ERROR expected %d", t->expect_offset);
		printf("\n");
	}
}

struct float_str_to_int_test {
	unsigned int precision;
	const char *str;
	int64_t expect_val;
	int expect_err;
};
struct float_str_to_int_test float_str_to_int_tests[] = {
	{ 0, "0", 0 },
	{ 0, "1", 1 },
	{ 0, "12.345", 12 },
	{ 0, "+12.345", 12 },
	{ 0, "-12.345", -12 },
	{ 0, "0.345", 0 },
	{ 0, ".345", 0 },
	{ 0, "-0.345", 0 },
	{ 0, "-.345", 0 },
	{ 0, "12.", 12 },
	{ 0, "-180", -180 },
	{ 0, "180", 180 },
	{ 0, "360", 360 },
	{ 0, "123.4567890123", 123 },
	{ 0, "123.4567890123456789012345", 123 },
	{ 0, "9223372036854775807", 9223372036854775807LL },
	{ 0, "-9223372036854775807", -9223372036854775807LL },
	{ 0, "-9223372036854775808", .expect_err = -ERANGE },
	{ 0, "9223372036854775808", .expect_err = -ERANGE },
	{ 0, "-9223372036854775809", .expect_err = -ERANGE },
	{ 0, "100000000000000000000", .expect_err = -ERANGE },
	{ 0, "-100000000000000000000", .expect_err = -ERANGE },
	{ 0, "999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 0, "-999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 0, "1.2.3", .expect_err = -EINVAL },
	{ 0, "foo", .expect_err = -EINVAL },
	{ 0, "1.foo", .expect_err = -EINVAL },
	{ 0, "1.foo", .expect_err = -EINVAL },
	{ 0, "12.-345", .expect_err = -EINVAL },
	{ 0, "-12.-345", .expect_err = -EINVAL },
	{ 0, "12.+345", .expect_err = -EINVAL },
	{ 0, "+12.+345", .expect_err = -EINVAL },
	{ 0, "", .expect_err = -EINVAL },
	{ 0, NULL, .expect_err = -EINVAL },

	{ 1, "0", 0 },
	{ 1, "1", 10 },
	{ 1, "12.345", 123 },
	{ 1, "+12.345", 123 },
	{ 1, "-12.345", -123 },
	{ 1, "0.345", 3 },
	{ 1, ".345", 3 },
	{ 1, "-0.345", -3 },
	{ 1, "-.345", -3 },
	{ 1, "12.", 120 },
	{ 1, "-180", -1800 },
	{ 1, "180", 1800 },
	{ 1, "360", 3600 },
	{ 1, "123.4567890123", 1234 },
	{ 1, "123.4567890123456789012345", 1234 },
	{ 1, "922337203685477580.7", 9223372036854775807LL },
	{ 1, "-922337203685477580.7", -9223372036854775807LL },
	{ 1, "-922337203685477580.8", .expect_err = -ERANGE },
	{ 1, "922337203685477580.8", .expect_err = -ERANGE },
	{ 1, "-922337203685477580.9", .expect_err = -ERANGE },
	{ 1, "100000000000000000000", .expect_err = -ERANGE },
	{ 1, "-100000000000000000000", .expect_err = -ERANGE },
	{ 1, "999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 1, "-999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 1, "1.2.3", .expect_err = -EINVAL },
	{ 1, "foo", .expect_err = -EINVAL },
	{ 1, "1.foo", .expect_err = -EINVAL },
	{ 1, "1.foo", .expect_err = -EINVAL },
	{ 1, "12.-345", .expect_err = -EINVAL },
	{ 1, "-12.-345", .expect_err = -EINVAL },
	{ 1, "12.+345", .expect_err = -EINVAL },
	{ 1, "+12.+345", .expect_err = -EINVAL },
	{ 1, "", .expect_err = -EINVAL },
	{ 1, NULL, .expect_err = -EINVAL },

	{ 6, "0", 0 },
	{ 6, "1", 1000000 },
	{ 6, "12.345", 12345000 },
	{ 6, "+12.345", 12345000 },
	{ 6, "-12.345", -12345000 },
	{ 6, "0.345", 345000 },
	{ 6, ".345", 345000 },
	{ 6, "-0.345", -345000 },
	{ 6, "-.345", -345000 },
	{ 6, "12.", 12000000 },
	{ 6, "-180", -180000000 },
	{ 6, "180", 180000000 },
	{ 6, "360", 360000000 },
	{ 6, "123.4567890123", 123456789 },
	{ 6, "123.4567890123456789012345", 123456789 },
	{ 6, "9223372036854.775807", 9223372036854775807LL },
	{ 6, "-9223372036854.775807", -9223372036854775807LL },
	{ 6, "-9223372036854.775808", .expect_err = -ERANGE },
	{ 6, "9223372036854.775808", .expect_err = -ERANGE },
	{ 6, "-9223372036854.775809", .expect_err = -ERANGE },
	{ 6, "100000000000000000000", .expect_err = -ERANGE },
	{ 6, "-100000000000000000000", .expect_err = -ERANGE },
	{ 6, "999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 6, "-999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 6, "1.2.3", .expect_err = -EINVAL },
	{ 6, "foo", .expect_err = -EINVAL },
	{ 6, "1.foo", .expect_err = -EINVAL },
	{ 6, "1.foo", .expect_err = -EINVAL },
	{ 6, "12.-345", .expect_err = -EINVAL },
	{ 6, "-12.-345", .expect_err = -EINVAL },
	{ 6, "12.+345", .expect_err = -EINVAL },
	{ 6, "+12.+345", .expect_err = -EINVAL },
	{ 6, "", .expect_err = -EINVAL },
	{ 6, NULL, .expect_err = -EINVAL },

	{ 18, "0", 0 },
	{ 18, "1", 1000000000000000000LL },
	{ 18, "1.2345", 1234500000000000000LL },
	{ 18, "+1.2345", 1234500000000000000LL },
	{ 18, "-1.2345", -1234500000000000000LL },
	{ 18, "0.345", 345000000000000000LL },
	{ 18, ".345", 345000000000000000LL },
	{ 18, "-0.345", -345000000000000000LL },
	{ 18, "-.345", -345000000000000000LL },
	{ 18, "2.", 2000000000000000000LL },
	{ 18, "-8", -8000000000000000000LL },
	{ 18, "1.234567890123", 1234567890123000000LL },
	{ 18, "1.234567890123456789012345", 1234567890123456789LL },
	{ 18, "123.4567890123", .expect_err = -ERANGE },
	{ 18, "9.223372036854775807", 9223372036854775807LL },
	{ 18, "-9.223372036854775807", -9223372036854775807LL },
	{ 18, "-9.223372036854775808", .expect_err = -ERANGE },
	{ 18, "9.223372036854775808", .expect_err = -ERANGE },
	{ 18, "-9.223372036854775809", .expect_err = -ERANGE },
	{ 18, "100000000000000000000", .expect_err = -ERANGE },
	{ 18, "-100000000000000000000", .expect_err = -ERANGE },
	{ 18, "999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 18, "-999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 18, "1.2.3", .expect_err = -EINVAL },
	{ 18, "foo", .expect_err = -EINVAL },
	{ 18, "1.foo", .expect_err = -EINVAL },
	{ 18, "1.foo", .expect_err = -EINVAL },
	{ 18, "12.-345", .expect_err = -EINVAL },
	{ 18, "-12.-345", .expect_err = -EINVAL },
	{ 18, "12.+345", .expect_err = -EINVAL },
	{ 18, "+12.+345", .expect_err = -EINVAL },
	{ 18, "", .expect_err = -EINVAL },
	{ 18, NULL, .expect_err = -EINVAL },

	{ 19, "0", 0 },
	{ 19, ".1", 1000000000000000000LL },
	{ 19, ".12345", 1234500000000000000LL },
	{ 19, "+.12345", 1234500000000000000LL },
	{ 19, "-.12345", -1234500000000000000LL },
	{ 19, "0.0345", 345000000000000000LL },
	{ 19, ".0345", 345000000000000000LL },
	{ 19, "-0.0345", -345000000000000000LL },
	{ 19, "-.0345", -345000000000000000LL },
	{ 19, ".2", 2000000000000000000LL },
	{ 19, "-.8", -8000000000000000000LL },
	{ 19, ".1234567890123", 1234567890123000000LL },
	{ 19, ".1234567890123456789012345", 1234567890123456789LL },
	{ 19, "123.4567890123", .expect_err = -ERANGE },
	{ 19, ".9223372036854775807", 9223372036854775807LL },
	{ 19, "-.9223372036854775807", -9223372036854775807LL },
	{ 19, "-.9223372036854775808", .expect_err = -ERANGE },
	{ 19, ".9223372036854775808", .expect_err = -ERANGE },
	{ 19, "-.9223372036854775809", .expect_err = -ERANGE },
	{ 19, "100000000000000000000", .expect_err = -ERANGE },
	{ 19, "-100000000000000000000", .expect_err = -ERANGE },
	{ 19, "999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 19, "-999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 19, "1.2.3", .expect_err = -EINVAL },
	{ 19, "foo", .expect_err = -EINVAL },
	{ 19, "1.foo", .expect_err = -EINVAL },
	{ 19, "1.foo", .expect_err = -EINVAL },
	{ 19, "12.-345", .expect_err = -EINVAL },
	{ 19, "-12.-345", .expect_err = -EINVAL },
	{ 19, "12.+345", .expect_err = -EINVAL },
	{ 19, "+12.+345", .expect_err = -EINVAL },
	{ 19, "", .expect_err = -EINVAL },
	{ 19, NULL, .expect_err = -EINVAL },

	{ 20, "0", 0 },
	{ 20, ".01", 1000000000000000000LL },
	{ 20, ".012345", 1234500000000000000LL },
	{ 20, "+.012345", 1234500000000000000LL },
	{ 20, "-.012345", -1234500000000000000LL },
	{ 20, "0.00345", 345000000000000000LL },
	{ 20, ".00345", 345000000000000000LL },
	{ 20, "-0.00345", -345000000000000000LL },
	{ 20, "-.00345", -345000000000000000LL },
	{ 20, ".02", 2000000000000000000LL },
	{ 20, "-.08", -8000000000000000000LL },
	{ 20, ".01234567890123", 1234567890123000000LL },
	{ 20, ".01234567890123456789012345", 1234567890123456789LL },
	{ 20, "12.34567890123", .expect_err = -ERANGE },
	{ 20, ".09223372036854775807", 9223372036854775807LL },
	{ 20, "-.09223372036854775807", -9223372036854775807LL },
	{ 20, "-.09223372036854775808", .expect_err = -ERANGE },
	{ 20, ".09223372036854775808", .expect_err = -ERANGE },
	{ 20, "-.09223372036854775809", .expect_err = -ERANGE },
	{ 20, ".1", .expect_err = -ERANGE },
	{ 20, "-.1", .expect_err = -ERANGE },
	{ 20, "999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 20, "-999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 20, "1.2.3", .expect_err = -EINVAL },
	{ 20, "foo", .expect_err = -EINVAL },
	{ 20, "1.foo", .expect_err = -EINVAL },
	{ 20, "1.foo", .expect_err = -EINVAL },
	{ 20, "12.-345", .expect_err = -EINVAL },
	{ 20, "-12.-345", .expect_err = -EINVAL },
	{ 20, "12.+345", .expect_err = -EINVAL },
	{ 20, "+12.+345", .expect_err = -EINVAL },
	{ 20, "", .expect_err = -EINVAL },
	{ 20, NULL, .expect_err = -EINVAL },

	{ 25, "0", 0 },
	{ 25, ".0000001", 1000000000000000000LL },
	{ 25, ".00000012345", 1234500000000000000LL },
	{ 25, "+.00000012345", 1234500000000000000LL },
	{ 25, "-.00000012345", -1234500000000000000LL },
	{ 25, "0.0000000345", 345000000000000000LL },
	{ 25, ".0000000345", 345000000000000000LL },
	{ 25, "-0.0000000345", -345000000000000000LL },
	{ 25, "-.0000000345", -345000000000000000LL },
	{ 25, ".0000002", 2000000000000000000LL },
	{ 25, "-.0000008", -8000000000000000000LL },
	{ 25, ".0000001234567890123", 1234567890123000000LL },
	{ 25, ".0000001234567890123456789012345", 1234567890123456789LL },
	{ 25, ".0001234567890123", .expect_err = -ERANGE },
	{ 25, ".0000009223372036854775807", 9223372036854775807LL },
	{ 25, "-.0000009223372036854775807", -9223372036854775807LL },
	{ 25, "-.0000009223372036854775808", .expect_err = -ERANGE },
	{ 25, ".0000009223372036854775808", .expect_err = -ERANGE },
	{ 25, "-.0000009223372036854775809", .expect_err = -ERANGE },
	{ 25, ".000001", .expect_err = -ERANGE },
	{ 25, "-.000001", .expect_err = -ERANGE },
	{ 25, "999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 25, "-999999999999999999999999999.99", .expect_err = -ERANGE },
	{ 25, "1.2.3", .expect_err = -EINVAL },
	{ 25, "foo", .expect_err = -EINVAL },
	{ 25, "1.foo", .expect_err = -EINVAL },
	{ 25, "1.foo", .expect_err = -EINVAL },
	{ 25, "12.-345", .expect_err = -EINVAL },
	{ 25, "-12.-345", .expect_err = -EINVAL },
	{ 25, "12.+345", .expect_err = -EINVAL },
	{ 25, "+12.+345", .expect_err = -EINVAL },
	{ 25, "", .expect_err = -EINVAL },
	{ 25, NULL, .expect_err = -EINVAL },
};
const char *errno_str(int rc)
{
	switch (rc) {
	case -EINVAL:
		return "=-EINVAL";
	case -ERANGE:
		return "=-ERANGE";
	case -E2BIG:
		return "=-E2BIG";
	case -EOVERFLOW:
		return "=-EOVERFLOW";
	default:
		return "";
	}
}
void test_float_str_to_int(void)
{
	const struct float_str_to_int_test *t;
	printf("--- %s\n", __func__);
	for (t = float_str_to_int_tests; (t - float_str_to_int_tests) < ARRAY_SIZE(float_str_to_int_tests); t++) {
		int rc;
		int64_t val;
		rc = osmo_float_str_to_int(&val, t->str, t->precision);
		printf("osmo_float_str_to_int(%s, %u) -> rc=%d%s val=%" PRId64 "\n",
		       osmo_quote_str(t->str, -1), t->precision, rc, errno_str(rc), val);

		if (rc != t->expect_err)
			printf("  ERROR: expected rc=%d%s\n", t->expect_err, errno_str(t->expect_err));
		if (val != t->expect_val)
			printf("  ERROR: expected val=%" PRId64 "\n", t->expect_val);
		if (rc != t->expect_err||val != t->expect_val)
		exit(0);
	}
}

struct int_to_float_str_test {
	unsigned int precision;
	int64_t val;
	const char *expect_str;
};
struct int_to_float_str_test int_to_float_str_tests[] = {
	{ 0, 0, "0" },
	{ 0, 1, "1" },
	{ 0, 1000000, "1000000" },
	{ 0, -1000000, "-1000000" },
	{ 0, 1000001, "1000001" },
	{ 0, -1000001, "-1000001" },
	{ 0, 1000100, "1000100" },
	{ 0, -1010000, "-1010000" },
	{ 0, 1100000, "1100000" },
	{ 0, 10000000, "10000000" },
	{ 0, -10000000, "-10000000" },
	{ 0, 100000000, "100000000" },
	{ 0, -100000000, "-100000000" },
	{ 0, 9223372036854775807, "9223372036854775807" },
	{ 0, -9223372036854775807, "-9223372036854775807" },
	{ 0, INT64_MIN, "-ERR" },

	{ 1, 0, "0" },
	{ 1, 1, "0.1" },
	{ 1, 1000000, "100000" },
	{ 1, -1000000, "-100000" },
	{ 1, 1000001, "100000.1" },
	{ 1, -1000001, "-100000.1" },
	{ 1, 1000100, "100010" },
	{ 1, -1010000, "-101000" },
	{ 1, 1100000, "110000" },
	{ 1, 10000000, "1000000" },
	{ 1, -10000000, "-1000000" },
	{ 1, 100000000, "10000000" },
	{ 1, -100000000, "-10000000" },
	{ 1, 9223372036854775807, "922337203685477580.7" },
	{ 1, -9223372036854775807, "-922337203685477580.7" },
	{ 1, INT64_MIN, "-ERR" },

	{ 3, 0, "0" },
	{ 3, 1, "0.001" },
	{ 3, 1000000, "1000" },
	{ 3, -1000000, "-1000" },
	{ 3, 1000001, "1000.001" },
	{ 3, -1000001, "-1000.001" },
	{ 3, 1000100, "1000.1" },
	{ 3, -1010000, "-1010" },
	{ 3, 1100000, "1100" },
	{ 3, 10000000, "10000" },
	{ 3, -10000000, "-10000" },
	{ 3, 100000000, "100000" },
	{ 3, -100000000, "-100000" },
	{ 3, 9223372036854775807, "9223372036854775.807" },
	{ 3, -9223372036854775807, "-9223372036854775.807" },
	{ 3, INT64_MIN, "-ERR" },

	{ 6, 0, "0" },
	{ 6, 1, "0.000001" },
	{ 6, 1000000, "1" },
	{ 6, -1000000, "-1" },
	{ 6, 1000001, "1.000001" },
	{ 6, -1000001, "-1.000001" },
	{ 6, 1000100, "1.0001" },
	{ 6, -1010000, "-1.01" },
	{ 6, 1100000, "1.1" },
	{ 6, 10000000, "10" },
	{ 6, -10000000, "-10" },
	{ 6, 100000000, "100" },
	{ 6, -100000000, "-100" },
	{ 6, 9223372036854775807, "9223372036854.775807" },
	{ 6, -9223372036854775807, "-9223372036854.775807" },
	{ 6, INT64_MIN, "-ERR" },

	{ 17, 0, "0" },
	{ 17, 1, "0.00000000000000001" },
	{ 17, 1000000, "0.00000000001" },
	{ 17, -1000000, "-0.00000000001" },
	{ 17, 1000001, "0.00000000001000001" },
	{ 17, -1000001, "-0.00000000001000001" },
	{ 17, 1000100, "0.000000000010001" },
	{ 17, -1010000, "-0.0000000000101" },
	{ 17, 1100000, "0.000000000011" },
	{ 17, 10000000, "0.0000000001" },
	{ 17, -10000000, "-0.0000000001" },
	{ 17, 100000000, "0.000000001" },
	{ 17, -100000000, "-0.000000001" },
	{ 17, 9223372036854775807, "92.23372036854775807" },
	{ 17, -9223372036854775807, "-92.23372036854775807" },
	{ 17, INT64_MIN, "-ERR" },

	{ 18, 0, "0" },
	{ 18, 1, "0.000000000000000001" },
	{ 18, 1000000, "0.000000000001" },
	{ 18, -1000000, "-0.000000000001" },
	{ 18, 1000001, "0.000000000001000001" },
	{ 18, -1000001, "-0.000000000001000001" },
	{ 18, 1000100, "0.0000000000010001" },
	{ 18, -1010000, "-0.00000000000101" },
	{ 18, 1100000, "0.0000000000011" },
	{ 18, 10000000, "0.00000000001" },
	{ 18, -10000000, "-0.00000000001" },
	{ 18, 100000000, "0.0000000001" },
	{ 18, -100000000, "-0.0000000001" },
	{ 18, 9223372036854775807, "9.223372036854775807" },
	{ 18, -9223372036854775807, "-9.223372036854775807" },
	{ 18, INT64_MIN, "-ERR" },

	{ 19, 0, "0" },
	{ 19, 1, "0.0000000000000000001" },
	{ 19, 1000000, "0.0000000000001" },
	{ 19, -1000000, "-0.0000000000001" },
	{ 19, 1000001, "0.0000000000001000001" },
	{ 19, -1000001, "-0.0000000000001000001" },
	{ 19, 1000100, "0.00000000000010001" },
	{ 19, -1010000, "-0.000000000000101" },
	{ 19, 1100000, "0.00000000000011" },
	{ 19, 10000000, "0.000000000001" },
	{ 19, -10000000, "-0.000000000001" },
	{ 19, 100000000, "0.00000000001" },
	{ 19, -100000000, "-0.00000000001" },
	{ 19, 9223372036854775807, "0.9223372036854775807" },
	{ 19, -9223372036854775807, "-0.9223372036854775807" },
	{ 19, INT64_MIN, "-ERR" },

	{ 23, 0, "0" },
	{ 23, 1, "0.00000000000000000000001" },
	{ 23, 1000000, "0.00000000000000001" },
	{ 23, -1000000, "-0.00000000000000001" },
	{ 23, 1000001, "0.00000000000000001000001" },
	{ 23, -1000001, "-0.00000000000000001000001" },
	{ 23, 1000100, "0.000000000000000010001" },
	{ 23, -1010000, "-0.0000000000000000101" },
	{ 23, 1100000, "0.000000000000000011" },
	{ 23, 10000000, "0.0000000000000001" },
	{ 23, -10000000, "-0.0000000000000001" },
	{ 23, 100000000, "0.000000000000001" },
	{ 23, -100000000, "-0.000000000000001" },
	{ 23, 9223372036854775807, "0.00009223372036854775807" },
	{ 23, -9223372036854775807, "-0.00009223372036854775807" },
	{ 23, INT64_MIN, "-ERR" },
};
void test_int_to_float_str(void)
{
	const struct int_to_float_str_test *t;
	printf("--- %s\n", __func__);
	for (t = int_to_float_str_tests;
	     (t - int_to_float_str_tests) < ARRAY_SIZE(int_to_float_str_tests);
	     t++) {
		char buf[128];
		int rc;
		rc = osmo_int_to_float_str_buf(buf, sizeof(buf), t->val, t->precision);
		printf("osmo_int_to_float_str_buf(%" PRId64 ", %u) -> rc=%d str=%s\n", t->val, t->precision, rc,
		       osmo_quote_str(buf, -1));

		if (rc != strlen(buf))
			printf("  ERROR: expected rc=%zu\n", strlen(buf));
		if (strcmp(buf, t->expect_str))
			printf("  ERROR: expected str=%s\n", osmo_quote_str(t->expect_str, -1));
		if (rc != strlen(buf) || strcmp(buf, t->expect_str))
			exit(0);
	}
}

struct str_to_int_test {
	const char *str;
	int base;
	int min_val;
	int max_val;
	int expect_rc;
	int expect_val;
};
/* Avoid using INT_MAX and INT_MIN because that would produce different test output on different architectures */
struct str_to_int_test str_to_int_tests[] = {
	{ NULL, 10, -1000, 1000, -EINVAL, 0 },
	{ "", 10, -1000, 1000, -EINVAL, 0 },
	{ " ", 10, -1000, 1000, -EINVAL, 0 },
	{ "-", 10, -1000, 1000, -EINVAL, 0 },
	{ "--", 10, -1000, 1000, -EINVAL, 0 },
	{ "+", 10, -1000, 1000, -EINVAL, 0 },
	{ "++", 10, -1000, 1000, -EINVAL, 0 },

	{ "0", 10, -1000, 1000, 0, 0 },
	{ "1", 10, -1000, 1000, 0, 1 },
	{ "+1", 10, -1000, 1000, 0, 1 },
	{ "-1", 10, -1000, 1000, 0, -1 },
	{ "1000", 10, -1000, 1000, 0, 1000 },
	{ "+1000", 10, -1000, 1000, 0, 1000 },
	{ "-1000", 10, -1000, 1000, 0, -1000 },
	{ "1001", 10, -1000, 1000, -ERANGE, 1001 },
	{ "+1001", 10, -1000, 1000, -ERANGE, 1001 },
	{ "-1001", 10, -1000, 1000, -ERANGE, -1001 },

	{ "0", 16, -1000, 1000, 0, 0 },
	{ "1", 16, -1000, 1000, 0, 1 },
	{ "0x1", 16, -1000, 1000, 0, 1 },
	{ "+1", 16, -1000, 1000, 0, 1 },
	{ "-1", 16, -1000, 1000, 0, -1 },
	{ "+0x1", 16, -1000, 1000, 0, 1 },
	{ "-0x1", 16, -1000, 1000, 0, -1 },
	{ "3e8", 16, -1000, 1000, 0, 1000 },
	{ "3E8", 16, -1000, 1000, 0, 1000 },
	{ "0x3e8", 16, -1000, 1000, 0, 1000 },
	{ "0x3E8", 16, -1000, 1000, 0, 1000 },
	{ "+3e8", 16, -1000, 1000, 0, 1000 },
	{ "+3E8", 16, -1000, 1000, 0, 1000 },
	{ "+0x3e8", 16, -1000, 1000, 0, 1000 },
	{ "+0x3E8", 16, -1000, 1000, 0, 1000 },
	{ "-3e8", 16, -1000, 1000, 0, -1000 },
	{ "-3E8", 16, -1000, 1000, 0, -1000 },
	{ "-0x3e8", 16, -1000, 1000, 0, -1000 },
	{ "-0x3E8", 16, -1000, 1000, 0, -1000 },
	{ "3e9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "3E9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "0x3e9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "0x3E9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "+3e9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "+3E9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "+0x3e9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "+0x3E9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "-3e9", 16, -1000, 1000, -ERANGE, -1001 },
	{ "-3E9", 16, -1000, 1000, -ERANGE, -1001 },
	{ "-0x3e9", 16, -1000, 1000, -ERANGE, -1001 },
	{ "-0x3E9", 16, -1000, 1000, -ERANGE, -1001 },

	{ "garble", 10, -1000, 1000, -EINVAL, 0 },
	{ "-garble", 10, -1000, 1000, -EINVAL, 0 },
	{ "0x123", 10, -1000, 1000, -E2BIG, 0 },
	{ "123potatoes", 10, -1000, 1000, -E2BIG, 123 },
	{ "123 potatoes", 10, -1000, 1000, -E2BIG, 123 },
	{ "123 ", 10, -1000, 1000, -E2BIG, 123 },
	{ "123.4", 10, -1000, 1000, -E2BIG, 123 },
};
void test_str_to_int(void)
{
	const struct str_to_int_test *t;
	printf("--- %s\n", __func__);
	for (t = str_to_int_tests; (t - str_to_int_tests) < ARRAY_SIZE(str_to_int_tests); t++) {
		int rc;
		int val;
		rc = osmo_str_to_int(&val, t->str, t->base, t->min_val, t->max_val);
		printf("osmo_str_to_int(%s, %d, %d, %d) -> rc=%d%s val=%d\n",
		       osmo_quote_str(t->str, -1), t->base, t->min_val, t->max_val, rc, errno_str(rc), val);

		if (rc != t->expect_rc)
			printf("  ERROR: expected rc=%d%s\n", t->expect_rc, errno_str(t->expect_rc));
		if (val != t->expect_val)
			printf("  ERROR: expected val=%d\n", t->expect_val);
	}
}

struct str_to_int64_test {
	const char *str;
	int base;
	int64_t min_val;
	int64_t max_val;
	int expect_rc;
	int64_t expect_val;
};
struct str_to_int64_test str_to_int64_tests[] = {
	{ NULL, 10, -1000, 1000, -EINVAL, 0 },
	{ "", 10, -1000, 1000, -EINVAL, 0 },
	{ " ", 10, -1000, 1000, -EINVAL, 0 },
	{ "-", 10, -1000, 1000, -EINVAL, 0 },
	{ "--", 10, -1000, 1000, -EINVAL, 0 },
	{ "+", 10, -1000, 1000, -EINVAL, 0 },
	{ "++", 10, -1000, 1000, -EINVAL, 0 },

	{ "0", 10, -1000, 1000, 0, 0 },
	{ "1", 10, -1000, 1000, 0, 1 },
	{ "+1", 10, -1000, 1000, 0, 1 },
	{ "-1", 10, -1000, 1000, 0, -1 },
	{ "1000", 10, -1000, 1000, 0, 1000 },
	{ "+1000", 10, -1000, 1000, 0, 1000 },
	{ "-1000", 10, -1000, 1000, 0, -1000 },
	{ "1001", 10, -1000, 1000, -ERANGE, 1001 },
	{ "+1001", 10, -1000, 1000, -ERANGE, 1001 },
	{ "-1001", 10, -1000, 1000, -ERANGE, -1001 },

	{ "0", 16, -1000, 1000, 0, 0 },
	{ "1", 16, -1000, 1000, 0, 1 },
	{ "0x1", 16, -1000, 1000, 0, 1 },
	{ "+1", 16, -1000, 1000, 0, 1 },
	{ "-1", 16, -1000, 1000, 0, -1 },
	{ "+0x1", 16, -1000, 1000, 0, 1 },
	{ "-0x1", 16, -1000, 1000, 0, -1 },
	{ "3e8", 16, -1000, 1000, 0, 1000 },
	{ "3E8", 16, -1000, 1000, 0, 1000 },
	{ "0x3e8", 16, -1000, 1000, 0, 1000 },
	{ "0x3E8", 16, -1000, 1000, 0, 1000 },
	{ "+3e8", 16, -1000, 1000, 0, 1000 },
	{ "+3E8", 16, -1000, 1000, 0, 1000 },
	{ "+0x3e8", 16, -1000, 1000, 0, 1000 },
	{ "+0x3E8", 16, -1000, 1000, 0, 1000 },
	{ "-3e8", 16, -1000, 1000, 0, -1000 },
	{ "-3E8", 16, -1000, 1000, 0, -1000 },
	{ "-0x3e8", 16, -1000, 1000, 0, -1000 },
	{ "-0x3E8", 16, -1000, 1000, 0, -1000 },
	{ "3e9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "3E9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "0x3e9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "0x3E9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "+3e9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "+3E9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "+0x3e9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "+0x3E9", 16, -1000, 1000, -ERANGE, 1001 },
	{ "-3e9", 16, -1000, 1000, -ERANGE, -1001 },
	{ "-3E9", 16, -1000, 1000, -ERANGE, -1001 },
	{ "-0x3e9", 16, -1000, 1000, -ERANGE, -1001 },
	{ "-0x3E9", 16, -1000, 1000, -ERANGE, -1001 },

	{ "garble", 10, -1000, 1000, -EINVAL, 0 },
	{ "-garble", 10, -1000, 1000, -EINVAL, 0 },
	{ "0x123", 10, -1000, 1000, -E2BIG, 0 },
	{ "123potatoes", 10, -1000, 1000, -E2BIG, 123 },
	{ "123 potatoes", 10, -1000, 1000, -E2BIG, 123 },
	{ "123 ", 10, -1000, 1000, -E2BIG, 123 },
	{ "123.4", 10, -1000, 1000, -E2BIG, 123 },

	{ "-9223372036854775808", 10, INT64_MIN, INT64_MAX, 0, INT64_MIN },
	{ "9223372036854775807", 10, INT64_MIN, INT64_MAX, 0, INT64_MAX },

	{ "-9223372036854775809", 10, INT64_MIN, INT64_MAX, -EOVERFLOW, INT64_MIN },
	{ "9223372036854775808", 10, INT64_MIN, INT64_MAX, -EOVERFLOW, INT64_MAX },

	{ "-9223372036854775808", 10, -1000, 1000, -ERANGE, INT64_MIN },
	{ "9223372036854775807", 10, -1000, 1000, -ERANGE, INT64_MAX },
	{ "-9223372036854775809", 10, -1000, 1000, -EOVERFLOW, INT64_MIN },
	{ "9223372036854775808", 10, -1000, 1000, -EOVERFLOW, INT64_MAX },
};
void test_str_to_int64(void)
{
	const struct str_to_int64_test *t;
	printf("--- %s\n", __func__);
	for (t = str_to_int64_tests; (t - str_to_int64_tests) < ARRAY_SIZE(str_to_int64_tests); t++) {
		int rc;
		int64_t val;
		rc = osmo_str_to_int64(&val, t->str, t->base, t->min_val, t->max_val);
		printf("osmo_str_to_int64(%s, %d, %"PRId64", %"PRId64") -> rc=%d%s val=%"PRId64"\n",
		       osmo_quote_str(t->str, -1), t->base, t->min_val, t->max_val, rc, errno_str(rc), val);

		if (rc != t->expect_rc)
			printf("  ERROR: expected rc=%d%s\n", t->expect_rc, errno_str(t->expect_rc));
		if (val != t->expect_val)
			printf("  ERROR: expected val=%"PRId64"\n", t->expect_val);
	}
}

int main(int argc, char **argv)
{
	static const struct log_info log_info = {};
	log_init(&log_info, NULL);

	hexdump_test();
	hexparse_test();
	test_ipa_ccm_id_get_parsing();
	test_ipa_ccm_id_resp_parsing();
	test_is_hexstr();
	bcd_test();
	bcd2str_test();
	str_escape_test();
	str_quote_test();
	str_escape3_test();
	str_quote3_test();
	isqrt_test();
	mod_test();
	osmo_sockaddr_to_str_and_uint_test();
	osmo_str_tolowupper_test();
	strbuf_test();
	strbuf_test_nolen();
	startswith_test();
	name_c_impl_test();
	osmo_print_n_test();
	osmo_strnchr_test();
	test_float_str_to_int();
	test_int_to_float_str();
	test_str_to_int();
	test_str_to_int64();
	return 0;
}
