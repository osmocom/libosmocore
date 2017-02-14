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

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>

#include <stdio.h>

static void hexdump_test(void)
{
	uint8_t data[4098];
	int i;

	for (i = 0; i < ARRAY_SIZE(data); ++i)
		data[i] = i & 0xff;

	printf("Plain dump\n");
	printf("%s\n", osmo_hexdump(data, 4));

	printf("Corner case\n");
	printf("%s\n", osmo_hexdump(data, ARRAY_SIZE(data)));
	printf("%s\n", osmo_hexdump_nospc(data, ARRAY_SIZE(data)));
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

static void test_idtag_parsing(void)
{
	struct tlv_parsed tvp;
	int rc;

        static uint8_t data[] = {
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

	rc = ipa_ccm_idtag_parse_off(&tvp, data, sizeof(data), 1);
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

int main(int argc, char **argv)
{
	static const struct log_info log_info = {};
	log_init(&log_info, NULL);

	hexdump_test();
	hexparse_test();
	test_idtag_parsing();
	return 0;
}
