/*
 * (C) 2013 by Andreas Eversberg <jolly@eversberg.eu>
 * (C) 2015 by Alexander Chemeris <Alexander.Chemeris@fairwaves.co>
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
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <osmocom/core/bits.h>
#include <osmocom/core/utils.h>

#include <osmocom/coding/gsm0503_coding.h>

#define ASSERT_TRUE(rc) \
	if (!(rc)) { \
		printf("Assert failed in %s:%d.\n",  \
		       __FILE__, __LINE__);          \
		abort();			     \
	}

#define DUMP_U_AT(b, x, u) do {						\
		printf("%s %02x  %02x  ", osmo_ubit_dump(b + x, 57), b[57 + x], b[58 + x]); \
		printf("%s\n",            osmo_ubit_dump(b + 59 + x, 57)); \
		if (u <= x)					\
			return;						\
	} while(0)

#define DUMP_S_AT(b, x, u) do {						\
		printf("%s %02x  %02x  ", osmo_hexdump(b + x, 57), b[57 + x], b[58 + x]); \
		printf("%s\n",            osmo_hexdump(b + 59 + x, 57)); \
		if (u <= x)					\
			return;						\
	} while(0)

inline void dump_ubits(ubit_t *bursts_u, unsigned until)
{
	printf("U-Bits:\n");
	DUMP_U_AT(bursts_u, 0, until);
	DUMP_U_AT(bursts_u, 116, until);
	DUMP_U_AT(bursts_u, 232, until);
	DUMP_U_AT(bursts_u, 348, until);
	DUMP_U_AT(bursts_u, 464, until);
	DUMP_U_AT(bursts_u, 580, until);
	DUMP_U_AT(bursts_u, 696, until);
	DUMP_U_AT(bursts_u, 812, until);
}

inline void dump_sbits(uint8_t *bursts_s, unsigned until)
{
	printf("S-Bits:\n");
	DUMP_S_AT(bursts_s, 0, until);
	DUMP_S_AT(bursts_s, 116, until);
	DUMP_S_AT(bursts_s, 232, until);
	DUMP_S_AT(bursts_s, 348, until);
	DUMP_S_AT(bursts_s, 464, until);
	DUMP_S_AT(bursts_s, 580, until);
	DUMP_S_AT(bursts_s, 696, until);
	DUMP_S_AT(bursts_s, 812, until);
}

static void test_xcch(uint8_t *l2)
{
	uint8_t result[23];
	ubit_t bursts_u[116 * 4];
	sbit_t bursts_s[116 * 4];
	int n_errors, n_bits_total;

	/* Encode L2 message */
	printf("Encoding: %s\n", osmo_hexdump(l2, 23));
	gsm0503_xcch_encode(bursts_u, l2);

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 116 * 4);
	dump_ubits(bursts_u, 348);
	dump_sbits((uint8_t *)bursts_s, 348);

	/* Destroy some bits */
	memset(bursts_s, 0, 30);
	memset(bursts_s + 116, 0, 30);

	/* Decode, correcting errors */
	gsm0503_xcch_decode(result, bursts_s, &n_errors, &n_bits_total);
	printf("Decoded: %s\n", osmo_hexdump(result, 23));
	printf("xcch_decode: n_errors=%d n_bits_total=%d ber=%.2f\n",
		n_errors, n_bits_total, (float) n_errors / n_bits_total);

	ASSERT_TRUE(n_bits_total == 456);
	ASSERT_TRUE(!memcmp(l2, result, 23));

	printf("\n");
}

static void test_rach(uint8_t bsic, uint8_t ra)
{
	uint8_t result;
	ubit_t bursts_u[36];
	sbit_t bursts_s[36];

	/* Encode L2 message */
	printf("Encoding: %02x\n", ra);
	gsm0503_rach_encode(bursts_u, &ra, bsic);

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 36);

	printf("U-Bits: %s\n", osmo_ubit_dump(bursts_u, 36));

	printf("S-Bits: %s\n", osmo_hexdump((uint8_t *)bursts_s, 36));

	/* Destroy some bits */
	memset(bursts_s + 6, 0, 8);

	/* Decode, correcting errors */
	gsm0503_rach_decode(&result, bursts_s, bsic);
	printf("Decoded: %02x\n", result);

	ASSERT_TRUE(ra == result);

	printf("\n");
}

static void test_sch(uint8_t *info)
{
	uint8_t result[4];
	ubit_t bursts_u[78];
	sbit_t bursts_s[78];

	/* Zero bits 25 and above */
	info[3] &= 1;
	result[3] = 0;

	/* Encode L2 message */
	printf("Encoding: %s\n", osmo_hexdump(info, 4));
	gsm0503_sch_encode(bursts_u, info);

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 78);

	printf("U-Bits: %s\n", osmo_ubit_dump(bursts_u, 78));

	printf("S-Bits: %s\n", osmo_hexdump((uint8_t *)bursts_s, 78));

	/* Destroy some bits */
	memset(bursts_s + 6, 0, 10);

	/* Decode, correcting errors */
	gsm0503_sch_decode(result, bursts_s);
	printf("Decoded: %s\n", osmo_hexdump(result, 4));

	ASSERT_TRUE(!memcmp(info, result, 4));

	printf("\n");
}

static void test_fr(uint8_t *speech, int len)
{
	uint8_t result[33];
	ubit_t bursts_u[116 * 8];
	sbit_t bursts_s[116 * 8];
	int n_errors, n_bits_total;
	int rc;

	memset(bursts_u, 0x23, sizeof(bursts_u));
	memset(bursts_s, 0, sizeof(bursts_s));

	/* Encode L2 message */
	printf("Encoding: %s\n", osmo_hexdump(speech, len));
	gsm0503_tch_fr_encode(bursts_u, speech, len, 1);

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 116 * 8);

	dump_ubits(bursts_u, 812);
	dump_sbits((uint8_t *)bursts_s, 812);

	/* Destroy some bits */
	memset(bursts_s + 6, 0, 20);

	/* Decode, correcting errors */
	rc = gsm0503_tch_fr_decode(result, bursts_s, 1, len == 31,
		&n_errors, &n_bits_total);
	printf("Decoded: %s\n", osmo_hexdump(result, len));
	printf("tch_fr_decode: n_errors=%d n_bits_total=%d ber=%.2f\n",
		n_errors, n_bits_total, (float)n_errors/n_bits_total);

	ASSERT_TRUE(rc == len);
	ASSERT_TRUE(!memcmp(speech, result, len));

	printf("\n");
}

static void test_hr(uint8_t *speech, int len)
{
	uint8_t result[23];
	ubit_t bursts_u[116 * 6];
	sbit_t bursts_s[116 * 6];
	int n_errors, n_bits_total;
	int rc;

	memset(bursts_u, 0x23, sizeof(bursts_u));
	memset(bursts_s, 0, sizeof(bursts_s));

	/* Encode L2 message */
	printf("Encoding: %s\n", osmo_hexdump(speech, len));
	gsm0503_tch_hr_encode(bursts_u, speech, len);

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 116 * 6);

	dump_ubits(bursts_u, 580);
	dump_sbits((uint8_t *)bursts_s, 580);

	/* Destroy some bits */
	memset(bursts_s + 6, 0, 20);

	/* Decode, correcting errors */
	rc = gsm0503_tch_hr_decode(result, bursts_s, 0,
		&n_errors, &n_bits_total);
	printf("Decoded: %s\n", osmo_hexdump(result, len));
	printf("tch_hr_decode: n_errors=%d n_bits_total=%d ber=%.2f\n",
		n_errors, n_bits_total, (float)n_errors/n_bits_total);

	ASSERT_TRUE(rc == len);
	ASSERT_TRUE(!memcmp(speech, result, len));

	printf("\n");
}

static void test_pdtch(uint8_t *l2, int len)
{
	uint8_t result[len];
	ubit_t bursts_u[116 * 4];
	sbit_t bursts_s[116 * 4];
	int n_errors, n_bits_total;
	int rc;

	/* Zero the not coded tail bits */
	switch (len) {
	case 34:
	case 54:
		l2[len - 1] &= 0x7f;
		result[len - 1] &= 0x7f;
		break;
	case 40:
		l2[len - 1] &= 0x07;
		result[len - 1] &= 0x07;
		break;
	}

	/* Encode L2 message */
	printf("Encoding: %s\n", osmo_hexdump(l2, len));
	gsm0503_pdtch_encode(bursts_u, l2, len);

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 116 * 4);

	dump_ubits(bursts_u, 348);
	dump_sbits((uint8_t *)bursts_s, 348);

	/* Decode */
	rc = gsm0503_pdtch_decode(result, bursts_s, NULL,
		&n_errors, &n_bits_total);
	printf("Decoded: %s\n", osmo_hexdump(result, len));
	printf("pdtch_decode: n_errors=%d n_bits_total=%d ber=%.2f\n",
		n_errors, n_bits_total, (float)n_errors/n_bits_total);

	ASSERT_TRUE(rc == len);
	ASSERT_TRUE(!memcmp(l2, result, len));

	printf("\n");
}

uint8_t test_l2[][23] = {
	/* Dummy frame */
	{ 0x03, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	/* Random frame */
	{ 0xa3, 0xaf, 0x5f, 0xc6, 0x36, 0x43, 0x44, 0xab,
	0xd9, 0x6d, 0x7d, 0x62, 0x24, 0xc9, 0xd2, 0x92,
	0xfa, 0x27, 0x5d, 0x71, 0x7a, 0x59, 0xa8 },
	/* jolly frame */
	{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
};

uint8_t test_macblock[][54] = {
	/* Random frame */
	{ 0xa3, 0xaf, 0x5f, 0xc6, 0x36, 0x43, 0x44, 0xab,
	0xd9, 0x6d, 0x7d, 0x62, 0x24, 0xc9, 0xd2, 0x92,
	0xfa, 0x27, 0x5d, 0x71, 0x7a, 0x59, 0xa8, 0x42,
	0xa3, 0xaf, 0x5f, 0xc6, 0x36, 0x43, 0x44, 0xab,
	0xa3, 0xaf, 0x5f, 0xc6, 0x36, 0x43, 0x44, 0xab,
	0xd9, 0x6d, 0x7d, 0x62, 0x24, 0xc9, 0xd2, 0x92,
	0xfa, 0x27, 0x5d, 0x71, 0x7a, 0xa8 },
	/* jolly frame */
	{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
};

uint8_t test_speech_fr[33];
uint8_t test_speech_efr[31];
uint8_t test_speech_hr[15];

int main(int argc, char **argv)
{
	int i, len_l2, len_mb;

	len_l2 = sizeof(test_l2) / sizeof(test_l2[0]);
	len_mb = sizeof(test_macblock) / sizeof(test_macblock[0]);

	for (i = 0; i < len_l2; i++)
		test_xcch(test_l2[i]);

	for (i = 0; i < 256; i++) {
		test_rach(0x3f, i);
		test_rach(0x00, i);
		test_rach(0x1a, i);
	}

	for (i = 0; i < len_l2; i++)
		test_sch(test_l2[i]);

	for (i = 0; i < sizeof(test_speech_fr); i++)
		test_speech_fr[i] = i;
	test_speech_fr[0] = 0xd0;
	test_fr(test_speech_fr, sizeof(test_speech_fr));

	for (i = 0; i < sizeof(test_speech_efr); i++)
		test_speech_efr[i] = i;
	test_speech_efr[0] = 0xc0;
	test_fr(test_speech_efr, sizeof(test_speech_efr));

	for (i = 0; i < len_l2; i++)
		test_fr(test_l2[i], sizeof(test_l2[0]));

	for (i = 0; i < sizeof(test_speech_hr); i++)
		test_speech_hr[i] = i * 17;
	test_speech_hr[0] = 0x00;
	test_hr(test_speech_hr, sizeof(test_speech_hr));

	for (i = 0; i < len_l2; i++)
		test_hr(test_l2[i], sizeof(test_l2[0]));

	for (i = 0; i < len_mb; i++) {
		test_pdtch(test_macblock[i], 23);
		test_pdtch(test_macblock[i], 34);
		test_pdtch(test_macblock[i], 40);
		test_pdtch(test_macblock[i], 54);
	}

	printf("Success\n");

	return 0;
}
