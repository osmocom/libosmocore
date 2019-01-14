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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

bool test_is_hexstr()
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

	printf("\nTesting string escaping\n");
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
	if (res != printable)
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

	printf("- passthrough without truncation when no escaping needed:\n");
	memset(in_buf, 'x', sizeof(in_buf));
	in_buf[19] = 'E';
	in_buf[20] = '\0';
	memset(out_buf, 0x7f, sizeof(out_buf));
	printf("\"%s\"\n", osmo_escape_str_buf((const char *)in_buf, -1, out_buf, 10));
	OSMO_ASSERT(out_buf[0] == 0x7f);
}

static void str_quote_test(void)
{
	int i;
	int j;
	uint8_t in_buf[32];
	char out_buf[11];
	const char *printable = "printable";
	const char *res;

	printf("\nTesting string quoting\n");
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
	if (res != printable)
		printf("NOT passed through. '%s'\n", res);
	else
		printf("passed through unchanged '%s'\n", res);

	printf("- zero length:\n");
	printf("'%s'\n", osmo_quote_str("omitted", 0));

	printf("- truncation when too long:\n");
	memset(in_buf, 'x', sizeof(in_buf));
	in_buf[0] = '\a';
	in_buf[5] = 'E';
	memset(out_buf, 0x7f, sizeof(out_buf));
	printf("'%s'\n", osmo_quote_str_buf((const char *)in_buf, sizeof(in_buf), out_buf, 10));
	OSMO_ASSERT(out_buf[10] == 0x7f);

	printf("- always truncation, even when no escaping needed:\n");
	memset(in_buf, 'x', sizeof(in_buf));
	in_buf[6] = 'E'; /* dst has 10, less 2 quotes and nul, leaves 7, i.e. in[6] is last */
	in_buf[20] = '\0';
	memset(out_buf, 0x7f, sizeof(out_buf));
	printf("'%s'\n", osmo_quote_str_buf((const char *)in_buf, -1, out_buf, 10));
	OSMO_ASSERT(out_buf[0] == '"');

	printf("- try to feed too little buf for quoting:\n");
	printf("'%s'\n", osmo_quote_str_buf("", -1, out_buf, 2));

	printf("- NULL string becomes a \"NULL\" literal:\n");
	printf("'%s'\n", osmo_quote_str_buf(NULL, -1, out_buf, 10));
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


struct osmo_sockaddr_to_str_and_uint_test_case {
	uint16_t port;
	bool omit_port;
	const char *addr;
	unsigned int addr_len;
	bool omit_addr;
	unsigned int expect_rc;
	const char *expect_returned_addr;
};

struct osmo_sockaddr_to_str_and_uint_test_case osmo_sockaddr_to_str_and_uint_test_data[] = {
	{
		.port = 0,
		.addr = "0.0.0.0",
		.addr_len = 20,
		.expect_rc = 7,
	},
	{
		.port = 65535,
		.addr = "255.255.255.255",
		.addr_len = 20,
		.expect_rc = 15,
	},
	{
		.port = 1234,
		.addr = "234.23.42.123",
		.addr_len = 20,
		.expect_rc = 13,
	},
	{
		.port = 1234,
		.addr = "234.23.42.123",
		.addr_len = 10,
		.expect_rc = 13,
		.expect_returned_addr = "234.23.42",
	},
	{
		.port = 1234,
		.omit_port = true,
		.addr = "234.23.42.123",
		.addr_len = 20,
		.expect_rc = 13,
	},
	{
		.port = 1234,
		.addr = "234.23.42.123",
		.omit_addr = true,
		.expect_rc = 0,
		.expect_returned_addr = "",
	},
	{
		.port = 1234,
		.addr = "234.23.42.123",
		.addr_len = 0,
		.expect_rc = 13,
		.expect_returned_addr = "",
	},
	{
		.port = 1234,
		.addr = "234.23.42.123",
		.omit_port = true,
		.omit_addr = true,
		.expect_rc = 0,
		.expect_returned_addr = "",
	},
};

static void osmo_sockaddr_to_str_and_uint_test(void)
{
	int i;
	printf("\n%s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(osmo_sockaddr_to_str_and_uint_test_data); i++) {
		struct osmo_sockaddr_to_str_and_uint_test_case *t =
			&osmo_sockaddr_to_str_and_uint_test_data[i];

		struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_port = htons(t->port),
		};
		inet_aton(t->addr, &sin.sin_addr);

		char addr[20] = {};
		uint16_t port = 0;
		unsigned int rc;

		rc = osmo_sockaddr_to_str_and_uint(
			t->omit_addr? NULL : addr, t->addr_len,
			t->omit_port? NULL : &port,
			(const struct sockaddr*)&sin);

		printf("[%d] %s:%u%s%s addr_len=%u --> %s:%u rc=%u\n",
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


static void osmo_str_tolowupper_test()
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
	isqrt_test();
	osmo_sockaddr_to_str_and_uint_test();
	osmo_str_tolowupper_test();
	return 0;
}
