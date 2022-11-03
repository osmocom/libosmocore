/*
 * (C) 2008 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2010 by Nico Golde <nico@ngolde.de>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <osmocom/gsm/protocol/gsm_03_40.h>

#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsm0411_utils.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

struct log_info fake_log_info = {};

struct test_case {
	const uint8_t *input;
	const uint16_t input_length;

	const uint8_t *expected;
	const uint16_t expected_octet_length;
	const uint16_t expected_septet_length;
	const uint8_t ud_hdr_ind;
};

static const char simple_text[] = "test text";
#define simple_septet_length 9
static const uint8_t simple_enc[] = {
	0xf4, 0xf2, 0x9c, 0x0e, 0xa2, 0x97, 0xf1, 0x74
};

static const char escape_text[] = "!$ a more#^- complicated test@@?_%! case";
#define escape_septet_length 41 /* note: the ^ counts as two, because it is a extension character */
static const uint8_t escape_enc[] = {
	0x21, 0x01, 0x28, 0x0c, 0x6a, 0xbf, 0xe5, 0xe5, 0xd1,
	0x86, 0xd2, 0x02, 0x8d, 0xdf, 0x6d, 0x38, 0x3b, 0x3d,
	0x0e, 0xd3, 0xcb, 0x64, 0x10, 0xbd, 0x3c, 0xa7, 0x03,
	0x00, 0xbf, 0x48, 0x29, 0x04, 0x1a, 0x87, 0xe7, 0x65,
};

static const char enhanced_text[] = "enhanced ^ {][} test |+~ ^ test";
#define enhanced_septet_length 39 /* note: the characters { } [ ] ^ | ~ count as two (each of them), because they are extension characters */
static const uint8_t enhanced_enc[] = {
	0x65, 0x37, 0x3A, 0xEC, 0x1E, 0x97, 0xC9, 0xA0, 0x0D,
	0x05, 0xB4, 0x41, 0x6D, 0x7C, 0x1B, 0xDE, 0x26, 0x05,
	0xA2, 0x97, 0xE7, 0x74, 0xD0, 0x06, 0xB8, 0xDA, 0xF4,
	0x40, 0x1B, 0x0A, 0x88, 0x5E, 0x9E, 0xD3, 0x01,
};

static const char enhancedV2_text[] = "enhanced ^ {][} test |+~ ^ tests";
#define enhancedV2_septet_length 40 /* note: number of octets are equal to the enhanced_text! */
static const uint8_t enhancedV2_enc[] = {
	0x65, 0x37, 0x3A, 0xEC, 0x1E, 0x97, 0xC9, 0xA0, 0x0D,
	0x05, 0xB4, 0x41, 0x6D, 0x7C, 0x1B, 0xDE, 0x26, 0x05,
	0xA2, 0x97, 0xE7, 0x74, 0xD0, 0x06, 0xB8, 0xDA, 0xF4,
	0x40, 0x1B, 0x0A, 0x88, 0x5E, 0x9E, 0xD3, 0xE7,
};



static const char concatenated_text[] =
		"this is a testmessage. this is a testmessage. this is a testmessage. this is a testmessage. "
		"this is a testmessage. this is a testmessage. cut here .....: this is a second testmessage. end here.";

static const char splitted_text_part1[] =
		"this is a testmessage. this is a testmessage. this is a testmessage. this is a testmessage. "
		"this is a testmessage. this is a testmessage. cut here .....:";
#define concatenated_part1_septet_length_with_header 160
#define concatenated_part1_septet_length 153
static const uint8_t concatenated_part1_enc[] = {
		0x05, 0x00, 0x03, 0x6f, 0x02, 0x01,
		0xe8, 0xe8, 0xf4, 0x1c, 0x94, 0x9e, 0x83, 0xc2,
		0x20, 0x7a, 0x79, 0x4e, 0x6f, 0x97, 0xe7, 0xf3,
		0xf0, 0xb9, 0xec, 0x02, 0xd1, 0xd1, 0xe9, 0x39,
		0x28, 0x3d, 0x07, 0x85, 0x41, 0xf4, 0xf2, 0x9c,
		0xde, 0x2e, 0xcf, 0xe7, 0xe1, 0x73, 0xd9, 0x05,
		0xa2, 0xa3, 0xd3, 0x73, 0x50, 0x7a, 0x0e, 0x0a,
		0x83, 0xe8, 0xe5, 0x39, 0xbd, 0x5d, 0x9e, 0xcf,
		0xc3, 0xe7, 0xb2, 0x0b, 0x44, 0x47, 0xa7, 0xe7,
		0xa0, 0xf4, 0x1c, 0x14, 0x06, 0xd1, 0xcb, 0x73,
		0x7a, 0xbb, 0x3c, 0x9f, 0x87, 0xcf, 0x65, 0x17,
		0x88, 0x8e, 0x4e, 0xcf, 0x41, 0xe9, 0x39, 0x28,
		0x0c, 0xa2, 0x97, 0xe7, 0xf4, 0x76, 0x79, 0x3e,
		0x0f, 0x9f, 0xcb, 0x2e, 0x10, 0x1d, 0x9d, 0x9e,
		0x83, 0xd2, 0x73, 0x50, 0x18, 0x44, 0x2f, 0xcf,
		0xe9, 0xed, 0xf2, 0x7c, 0x1e, 0x3e, 0x97, 0x5d,
		0xa0, 0x71, 0x9d, 0x0e, 0x42, 0x97, 0xe5, 0x65,
		0x90, 0xcb, 0xe5, 0x72, 0xb9, 0x74,
};

static const char splitted_text_part2[] = " this is a second testmessage. end here.";
#define concatenated_part2_septet_length_with_header 47
#define concatenated_part2_septet_length 40
static const uint8_t concatenated_part2_enc[] = {
		0x05, 0x00, 0x03, 0x6f, 0x02, 0x02,
		0x40, 0x74, 0x74, 0x7a, 0x0e, 0x4a, 0xcf, 0x41,
		0x61, 0xd0, 0xbc, 0x3c, 0x7e, 0xbb, 0xc9, 0x20,
		0x7a, 0x79, 0x4e, 0x6f, 0x97, 0xe7, 0xf3, 0xf0,
		0xb9, 0xec, 0x02, 0x95, 0xdd, 0x64, 0x10, 0xba,
		0x2c, 0x2f, 0xbb, 0x00,
};

static const struct test_case test_multiple_encode[] =
{
	{
		.input = (const uint8_t *) concatenated_text,
		.expected = concatenated_part1_enc,
		.expected_octet_length = sizeof(concatenated_part1_enc),
		.expected_septet_length = concatenated_part1_septet_length,
		.ud_hdr_ind = 1,
	},
	{
		.input = (const uint8_t *) concatenated_text,
		.expected = concatenated_part2_enc,
		.expected_octet_length = sizeof(concatenated_part2_enc),
		.expected_septet_length = concatenated_part2_septet_length,
		.ud_hdr_ind = 1,
	},
};

static const struct test_case test_encode[] =
{
	{
		.input = (const uint8_t *) simple_text,
		.expected = simple_enc,
		.expected_octet_length = sizeof(simple_enc),
		.expected_septet_length = simple_septet_length,
		.ud_hdr_ind = 0,
	},
	{
		.input = (const uint8_t *) escape_text,
		.expected = escape_enc,
		.expected_octet_length = sizeof(escape_enc),
		.expected_septet_length = escape_septet_length,
		.ud_hdr_ind = 0,
	},
	{
		.input = (const uint8_t *) enhanced_text,
		.expected = enhanced_enc,
		.expected_octet_length = sizeof(enhanced_enc),
		.expected_septet_length = enhanced_septet_length,
		.ud_hdr_ind = 0,
	},
	{
		.input = (const uint8_t *) enhancedV2_text,
		.expected = enhancedV2_enc,
		.expected_octet_length = sizeof(enhancedV2_enc),
		.expected_septet_length = enhancedV2_septet_length,
		.ud_hdr_ind = 0,
	},
};

static const struct test_case test_decode[] =
{
	{
		.input = simple_enc,
		.input_length = sizeof(simple_enc),
		.expected = (const uint8_t *) simple_text,
		.expected_septet_length = simple_septet_length,
		.ud_hdr_ind = 0,
	},
	{
		.input = escape_enc,
		.input_length = sizeof(escape_enc),
		.expected = (const uint8_t *) escape_text,
		.expected_septet_length = escape_septet_length,
		.ud_hdr_ind = 0,
	},
	{
		.input = enhanced_enc,
		.input_length = sizeof(enhanced_enc),
		.expected = (const uint8_t *) enhanced_text,
		.expected_septet_length = enhanced_septet_length,
		.ud_hdr_ind = 0,
	},
	{
		.input = enhancedV2_enc,
		.input_length = sizeof(enhancedV2_enc),
		.expected = (const uint8_t *) enhancedV2_text,
		.expected_septet_length = enhancedV2_septet_length,
		.ud_hdr_ind = 0,
	},
	{
		.input = concatenated_part1_enc,
		.input_length = sizeof(concatenated_part1_enc),
		.expected = (const uint8_t *) splitted_text_part1,
		.expected_septet_length = concatenated_part1_septet_length_with_header,
		.ud_hdr_ind = 1,
	},
	{
		.input = concatenated_part2_enc,
		.input_length = sizeof(concatenated_part2_enc),
		.expected = (const uint8_t *) splitted_text_part2,
		.expected_septet_length = concatenated_part2_septet_length_with_header,
		.ud_hdr_ind = 1,
	},
};

static void test_octet_return(void)
{
	char out[256];
	int oct, septets;

	printf("Encoding some tests and printing number of septets/octets\n");

	septets = gsm_7bit_encode_n((uint8_t *) out, sizeof(out), "test1234", &oct);
	printf("SEPTETS: %d OCTETS: %d\n", septets, oct);

	printf("Done\n");
}

static void test_gen_oa(void)
{
	uint8_t oa[12];
	int len;

	printf("Testing gsm340_gen_oa\n");

	/* first try... */
	len = gsm340_gen_oa(oa, ARRAY_SIZE(oa), GSM340_TYPE_UNKNOWN,
			GSM340_PLAN_ISDN, "12345678901234567891");
	OSMO_ASSERT(len == 12);
	printf("Result: len(%d) data(%s)\n", len, osmo_hexdump(oa, len));
	len = gsm340_gen_oa(oa, ARRAY_SIZE(oa), GSM340_TYPE_NATIONAL,
			GSM340_PLAN_ISDN, "12345678901234567891");
	OSMO_ASSERT(len == 12);
	printf("Result: len(%d) data(%s)\n", len, osmo_hexdump(oa, len));

	/* long input.. will fail and just prints the header*/
	len = gsm340_gen_oa(oa, ARRAY_SIZE(oa), GSM340_TYPE_INTERNATIONAL,
			GSM340_PLAN_ISDN, "123456789123456789120");
	OSMO_ASSERT(len == 2);
	printf("Result: len(%d) data(%s)\n", len, osmo_hexdump(oa, len));

	/* try the alpha numeric encoding */
	len = gsm340_gen_oa(oa, ARRAY_SIZE(oa), GSM340_TYPE_ALPHA_NUMERIC,
			GSM340_PLAN_UNKNOWN, "OpenBSC");
	OSMO_ASSERT(len == 9);
	printf("Result: len(%d) data(%s)\n", len, osmo_hexdump(oa, len));

	/* long alpha numeric text */
	len = gsm340_gen_oa(oa, ARRAY_SIZE(oa), GSM340_TYPE_ALPHA_NUMERIC,
			GSM340_PLAN_UNKNOWN, "OpenBSCabcdefghijklm");
	OSMO_ASSERT(len == 12);
	printf("Result: len(%d) data(%s)\n", len, osmo_hexdump(oa, len));
}

static void test_enc_large_msg(void)
{
	uint8_t enc_buf[2048 * 7 / 8];
	char large_msg[2048 + 1];
	int i, j, nsep, noct = 0;

	printf("\nRunning %s\n", __func__);

	/* Expected chunks (repeated) in the output buffer */
	const uint8_t exp_chunk[] = { 0xc1, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x83 };

	/* Length variants to be tested */
	static const size_t nlen[] = { 2048, 1024, 555, 512, 260, 255, 250 };

	memset(&large_msg[0], (int) 'A', sizeof(large_msg) - 1);

	for (i = 0; i < ARRAY_SIZE(nlen); i++) {
		/* Clear the output buffer first */
		memset(&enc_buf[0], 0x00, sizeof(enc_buf));
		/* Limit length of the input string */
		large_msg[nlen[i]] = '\0';

		/* How many octets we expect to be used? */
		int noct_exp = nlen[i] * 7 / 8;
		if (nlen[i] % 8 != 0)
			noct_exp++;

		/* Encode a sequence of 'A' repeated nlen[i] times */
		nsep = gsm_7bit_encode_n(&enc_buf[0], sizeof(enc_buf), large_msg, &noct);
		printf("gsm_7bit_encode_n(len=%zu) processed %d septets (expected %zu): %s\n",
		       nlen[i], nsep, nlen[i], nsep == nlen[i] ? "OK" : "FAIL");
		printf("gsm_7bit_encode_n(len=%zu) used %d octets in the buffer (expected %d): %s\n",
		       nlen[i], noct, noct_exp, noct == noct_exp ? "OK" : "FAIL");

		/* The encoding result is expected to consist of repeated chunks */
		for (j = 0; j < noct_exp; j += sizeof(exp_chunk)) {
			size_t len = OSMO_MIN(noct_exp - j, sizeof(exp_chunk));
			if (nlen[i] % 8 != 0) /* skip incomplete octets */
				len--;
			if (memcmp(&enc_buf[j], exp_chunk, len) != 0) {
				printf("\tUnexpected chunk at enc_buf[%d:%zu]: %s\n",
				       j, len, osmo_hexdump(&enc_buf[j], len));
				break; /* No need to show them all */
			}
		}
	}
}

int main(int argc, char** argv)
{
	printf("SMS testing\n");
	uint8_t i;
	uint16_t buffer_size;
	uint8_t octet_length;
	int octets_written;
	uint8_t computed_octet_length;
	uint8_t septet_length;
	uint8_t coded[256];
	uint8_t tmp[160];
	uint8_t septet_data[256];
	int nchars;
	char result[256];
	void *ctx = talloc_named_const(NULL, 0, "sms_test");

	/* Fake logging. */
	osmo_init_logging2(ctx, &fake_log_info);

	/* test 7-bit encoding */
	for (i = 0; i < ARRAY_SIZE(test_encode); ++i) {
		/* Test new function */
		memset(coded, 0x42, sizeof(coded));
		septet_length = gsm_7bit_encode_n(coded, sizeof(coded),
			       			  (const char *) test_encode[i].input,
						  &octets_written);
		computed_octet_length = gsm_get_octet_len(septet_length);
		printf("Encode case %d: "
		       "Octet length %d (expected %d, computed %d), "
		       "septet length %d (expected %d)\n"
		       , i
		       , octets_written, test_encode[i].expected_octet_length, computed_octet_length
		       , septet_length, test_encode[i].expected_septet_length
		      );

		OSMO_ASSERT (octets_written == test_encode[i].expected_octet_length);
		OSMO_ASSERT (octets_written == computed_octet_length);
		OSMO_ASSERT (memcmp(coded, test_encode[i].expected, octets_written) == 0);
		OSMO_ASSERT (septet_length == test_encode[i].expected_septet_length);

		/* check buffer limiting */
		memset(coded, 0xaa, sizeof(coded));

		for (buffer_size = 0;
		     buffer_size < test_encode[i].expected_octet_length + 1
		     && buffer_size < sizeof(coded) - 1;
		     ++buffer_size)
		{
			gsm_7bit_encode_n(coded, buffer_size,
				       	  (const char *) test_encode[i].input,
					  &octets_written);

			OSMO_ASSERT(octets_written <= buffer_size);
			OSMO_ASSERT(coded[buffer_size] == 0xaa);
		}
	}


	/* Test: encode multiple SMS */
	int number_of_septets = gsm_septet_encode(septet_data, (const char *) test_multiple_encode[0].input);
	(void) number_of_septets;

	/* SMS part 1 */
	memset(tmp, 0x42, sizeof(tmp));
	memset(coded, 0x42, sizeof(coded));
	memcpy(tmp, septet_data, concatenated_part1_septet_length);

	/* In our case: test_multiple_decode[0].ud_hdr_ind equals number of padding bits*/
	octet_length = gsm_septet_pack(coded, tmp, concatenated_part1_septet_length, test_multiple_encode[0].ud_hdr_ind);

	/* copy header */
	memset(tmp, 0x42, sizeof(tmp));
	int udh_length = test_multiple_encode[0].expected[0] + 1;
	memcpy(tmp, test_multiple_encode[0].expected, udh_length);
	memcpy(tmp + udh_length, coded, octet_length);
	memset(coded, 0x42, sizeof(coded));
	memcpy(coded, tmp, octet_length + 6);

	OSMO_ASSERT(memcmp(coded, test_multiple_encode[0].expected, octet_length) == 0);

	/* SMS part 2 */
	memset(tmp, 0x42, sizeof(tmp));
	memset(coded, 0x42, sizeof(coded));
	memcpy(tmp, septet_data + concatenated_part1_septet_length, concatenated_part2_septet_length);

	/* In our case: test_multiple_decode[1].ud_hdr_ind equals number of padding bits*/
	octet_length = gsm_septet_pack(coded, tmp, concatenated_part2_septet_length, test_multiple_encode[1].ud_hdr_ind);

	/* copy header */
	memset(tmp, 0x42, sizeof(tmp));
	udh_length = test_multiple_encode[1].expected[0] + 1;
	memcpy(tmp, test_multiple_encode[1].expected, udh_length);
	memcpy(tmp + udh_length, coded, octet_length);
	memset(coded, 0x42, sizeof(coded));
	memcpy(coded, tmp, octet_length + 6);

	OSMO_ASSERT(memcmp(coded, test_multiple_encode[1].expected, octet_length) == 0);

	/* test 7-bit decoding */
	for (i = 0; i < ARRAY_SIZE(test_decode); ++i) {
		/* Test new function */
		memset(result, 0x42, sizeof(result));
		nchars = gsm_7bit_decode_n_hdr(result, sizeof(result), test_decode[i].input,
				test_decode[i].expected_septet_length, test_decode[i].ud_hdr_ind);
		printf("Decode case %d: return value %d (expected %zu)\n", i, nchars, strlen(result));

		OSMO_ASSERT(strcmp(result, (const char *) test_decode[i].expected) == 0);
		OSMO_ASSERT(nchars == strlen(result));

		/* check buffer limiting */
		memset(result, 0xaa, sizeof(result));

		for (buffer_size = 1;
		     buffer_size < test_decode[i].expected_septet_length + 1
		     && buffer_size < sizeof(result) - 1;
		     ++buffer_size)
		{
			nchars = gsm_7bit_decode_n_hdr(result, buffer_size, test_decode[i].input,
					test_decode[i].expected_septet_length, test_decode[i].ud_hdr_ind);

			OSMO_ASSERT(nchars <= buffer_size);
			OSMO_ASSERT(result[buffer_size] == (char)0xaa);
			OSMO_ASSERT(result[nchars] == '\0');
		}
	}

	test_octet_return();
	test_gen_oa();
	test_enc_large_msg();

	printf("OK\n");
	return 0;
}
