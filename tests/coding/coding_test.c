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
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <osmocom/core/bits.h>
#include <osmocom/core/utils.h>

#include <osmocom/coding/gsm0503_coding.h>

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

/* Similar to OSMO_ASSERT, but does not panic() */
#define CHECK_RC_OR_RET(exp, action) \
	if (!(exp)) { \
		printf("%s(%s): assert %s failed\n", __func__, action, #exp); \
		return; \
	}

#ifdef DEBUG
#define printd(fmt, args...) printf(fmt, ##args)
#else
#define printd(fmt, args...)
#endif

static inline void dump_ubits(ubit_t *bursts_u, unsigned until)
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

static inline void dump_sbits(uint8_t *bursts_s, unsigned until)
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
	int rc;

	/* Encode L2 message */
	printf("Encoding: %s\n", osmo_hexdump(l2, 23));
	rc = gsm0503_xcch_encode(bursts_u, l2);
	CHECK_RC_OR_RET(rc == 0, "encoding");

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 116 * 4);
	dump_ubits(bursts_u, 348);
	dump_sbits((uint8_t *)bursts_s, 348);

	/* Destroy some bits */
	memset(bursts_s, 0, 30);
	memset(bursts_s + 116, 0, 30);

	/* Decode, correcting errors */
	rc = gsm0503_xcch_decode(result, bursts_s, &n_errors, &n_bits_total);
	CHECK_RC_OR_RET(rc == 0, "decoding");

	printf("Decoded: %s\n", osmo_hexdump(result, 23));
	printf("xcch_decode: n_errors=%d n_bits_total=%d ber=%.2f\n",
		n_errors, n_bits_total, (float) n_errors / n_bits_total);

	OSMO_ASSERT(n_bits_total == 456);
	OSMO_ASSERT(!memcmp(l2, result, 23));

	printf("\n");
}

static void test_rach(uint8_t bsic, uint8_t ra)
{
	int rc;
	uint8_t result;
	ubit_t bursts_u[36];
	sbit_t bursts_s[36];

	/* Encode L2 message */
	printd("Encoding: %02x\n", ra);
	rc = gsm0503_rach_ext_encode(bursts_u, ra, bsic, false);
	CHECK_RC_OR_RET(rc == 0, "encoding");

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 36);

	printd("U-Bits: %s\n", osmo_ubit_dump(bursts_u, 36));

	printd("S-Bits: %s\n", osmo_hexdump((uint8_t *)bursts_s, 36));

	/* Destroy some bits */
	memset(bursts_s + 6, 0, 8);

	/* Decode, correcting errors */
	rc = gsm0503_rach_decode_ber(&result, bursts_s, bsic, NULL, NULL);
	CHECK_RC_OR_RET(rc == 0, "decoding");

	printd("Decoded: %02x\n", result);
	if (ra != result)
		printf("FAIL [RACH]: encoded %u != %u decoded\n", ra, result);

	printd("\n");
}

static void test_rach_ext(uint8_t bsic, uint16_t ra)
{
	int rc;
	uint16_t result = 3000; /* Max ext. RA is 2^11 = 2048 */
	ubit_t bursts_u[36];
	sbit_t bursts_s[36];

	/* Encode L2 message */
	printd("Encoding: %02x\n", ra);
	rc = gsm0503_rach_ext_encode(bursts_u, ra, bsic, true);
	CHECK_RC_OR_RET(rc == 0, "encoding");

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 36);

	printd("U-Bits: %s\n", osmo_ubit_dump(bursts_u, 36));

	printd("S-Bits: %s\n", osmo_hexdump((uint8_t *)bursts_s, 36));

	/* Destroy some bits */
	memset(bursts_s + 9, 0, 8);

	/* Decode, correcting errors */
	rc = gsm0503_rach_ext_decode_ber(&result, bursts_s, bsic, NULL, NULL);
	CHECK_RC_OR_RET(rc == 0, "decoding");

	printd("Decoded: %02x\n", result);
	if (ra != result)
		printf("FAIL [RACH ext]: encoded %u != %u decoded\n", ra, result);

	printd("\n");
}

static void test_rach_11bit_sample(uint8_t bsic, const sbit_t *payload)
{
	int n_errors, n_bits_total;
	uint16_t ra11;
	int rc;

	/* Decode, correcting errors */
	rc = gsm0503_rach_ext_decode_ber(&ra11, payload, bsic, &n_errors, &n_bits_total);
	if (rc) {
		printf("%s(): decoding failed (rc=%d)\n", __func__, rc);
		return;
	}

	printf("Decoded RA11: 0x%03x\n", ra11);
}

static void test_sch(uint8_t *info)
{
	uint8_t result[4];
	ubit_t bursts_u[78];
	sbit_t bursts_s[78];
	int rc;

	/* Zero bits 25 and above */
	info[3] &= 1;
	result[3] = 0;

	/* Encode L2 message */
	printf("Encoding: %s\n", osmo_hexdump(info, 4));
	rc = gsm0503_sch_encode(bursts_u, info);
	CHECK_RC_OR_RET(rc == 0, "encoding");

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 78);

	printf("U-Bits: %s\n", osmo_ubit_dump(bursts_u, 78));

	printf("S-Bits: %s\n", osmo_hexdump((uint8_t *)bursts_s, 78));

	/* Destroy some bits */
	memset(bursts_s + 6, 0, 10);

	/* Decode, correcting errors */
	rc = gsm0503_sch_decode(result, bursts_s);
	CHECK_RC_OR_RET(rc == 0, "decoding");

	printf("Decoded: %s\n", osmo_hexdump(result, 4));

	OSMO_ASSERT(!memcmp(info, result, 4));

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
	rc = gsm0503_tch_fr_encode(bursts_u, speech, len, 1);
	CHECK_RC_OR_RET(rc == 0, "encoding");

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 116 * 8);

	dump_ubits(bursts_u, 812);
	dump_sbits((uint8_t *)bursts_s, 812);

	/* Destroy some bits */
	memset(bursts_s + 6, 0, 20);

	/* Decode, correcting errors */
	rc = gsm0503_tch_fr_decode(result, bursts_s, 1, len == 31,
		&n_errors, &n_bits_total);
	CHECK_RC_OR_RET(rc == len, "decoding");

	printf("Decoded: %s\n", osmo_hexdump(result, len));
	printf("tch_fr_decode: n_errors=%d n_bits_total=%d ber=%.2f\n",
		n_errors, n_bits_total, (float)n_errors/n_bits_total);

	OSMO_ASSERT(!memcmp(speech, result, len));

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
	rc = gsm0503_tch_hr_encode(bursts_u, speech, len);
	CHECK_RC_OR_RET(rc == 0, "encoding");

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 116 * 6);

	dump_ubits(bursts_u, 580);
	dump_sbits((uint8_t *)bursts_s, 580);

	/* Destroy some bits */
	memset(bursts_s + 6, 0, 20);

	/* Decode, correcting errors */
	rc = gsm0503_tch_hr_decode(result, bursts_s, 0,
		&n_errors, &n_bits_total);
	CHECK_RC_OR_RET(rc == len, "decoding");

	printf("Decoded: %s\n", osmo_hexdump(result, len));
	printf("tch_hr_decode: n_errors=%d n_bits_total=%d ber=%.2f\n",
		n_errors, n_bits_total, (float)n_errors/n_bits_total);

	OSMO_ASSERT(!memcmp(speech, result, len));

	printf("\n");
}

struct test_macblock {
	bool is_egprs;
	uint16_t exp_burst_bits;
	uint16_t l2_len;
	uint8_t l2[54];
};

static const struct test_macblock test_macblock[] = {
	/* Random frame */
	{	false,
		GSM0503_GPRS_BURSTS_NBITS,
		54,
		{ 0xa3, 0xaf, 0x5f, 0xc6, 0x36, 0x43, 0x44, 0xab,
		  0xd9, 0x6d, 0x7d, 0x62, 0x24, 0xc9, 0xd2, 0x92,
		  0xfa, 0x27, 0x5d, 0x71, 0x7a, 0x59, 0xa8, 0x42,
		  0xa3, 0xaf, 0x5f, 0xc6, 0x36, 0x43, 0x44, 0xab,
		  0xa3, 0xaf, 0x5f, 0xc6, 0x36, 0x43, 0x44, 0xab,
		  0xd9, 0x6d, 0x7d, 0x62, 0x24, 0xc9, 0xd2, 0x92,
		  0xfa, 0x27, 0x5d, 0x71, 0x7a, 0xa8 }
	},
	/* jolly frame */
	{	false,
		GSM0503_GPRS_BURSTS_NBITS,
		23,
		{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 }
	},
/*
GSM RLC/MAC: EGPRS DL HEADER
    0... .... .... 0000 = DL TFI: 0
    0... .... crumb 1 of DL TFI (decoded above)
    .00. .... = RRBP: Reserved Block: (N+13) mod 2715648 (0)
    ...0 0... = ES/P: RRBP field is not valid (no Polling) (0)
    .... .111 = USF: 7
    01.. .... 0000 0000 .... ...0 = BSN: 1
    01.. .... crumb 2 of BSN (decoded above)
    ..00 .... = PR: 0 dB (included) to 3 dB (excluded) less than BCCH level - P0 (0)
    .... 0000 crumb 0 of DL TFI (decoded above)
    0000 0000 crumb 1 of BSN (decoded above)
    .00. .... = SPB (DL): No retransmission (0)
    ...1 011. = CPS: MCS-1/P1 (0x0b)
    .... ...0 crumb 0 of BSN (decoded above)
GSM RLC/MAC: EGPRS DL DATA BLOCK 1 (BSN 1)
    .... ..0. = FBI: Current Block is not last RLC data block in TBF
    .... ...0 = Extension: Extension octet follows immediately
    0000 100. = Length Indicator: 4
    .... ...0 = Extension: Extension octet follows immediately
    0010 000. = Length Indicator: 16
    .... ...1 = Extension: No extension octet follows
    data segment: LI[0]=4 indicates: (Last segment of) LLC frame (4 octets)
        Data (4 bytes)
            Data: 012b2b2b
            [Length: 4]
    data segment: LI[1]=16 indicates: (Last segment of) LLC frame (16 octets)
        Data (16 bytes)
            Data: 43c0012b2b2b2b2b2b2b2b2b2b2b2b2b
            [Length: 16]
*/
	{	true,
		GSM0503_GPRS_BURSTS_NBITS,
		27,
		{ 0x07, 0x40, 0x00, 0x16, 0x10, 0x42, 0x02, 0x56,
		  0x56, 0x56, 0x86, 0x80, 0x03, 0x56, 0x56, 0x56,
		  0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56,
		  0x56, 0x56, 0x00 }
	},
};

static void test_pdtch(const struct test_macblock *tmb, int len)
{
	uint8_t l2[len], result[len];
	ubit_t bursts_u[116 * 4];
	sbit_t bursts_s[116 * 4];
	int n_errors, n_bits_total;
	int rc;

	/* Zero the not coded tail bits */
	memcpy(l2, tmb->l2, len);
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
	if (tmb->is_egprs)
		rc = gsm0503_pdtch_egprs_encode(bursts_u, l2, len);
	else
		rc = gsm0503_pdtch_encode(bursts_u, l2, len);
	CHECK_RC_OR_RET(rc == (int)tmb->exp_burst_bits, "encoding");

	/* Prepare soft-bits */
	osmo_ubit2sbit(bursts_s, bursts_u, 116 * 4);

	dump_ubits(bursts_u, 348);
	dump_sbits((uint8_t *)bursts_s, 348);

	/* Decode */
	if (tmb->is_egprs) {
		/* gsm0503_pdtch_egprs_decode() is meant to decode EGPRS UL frames, so we cannot use it here */
		rc = gsm0503_pdtch_egprs_decode(result, bursts_s, rc, NULL, &n_errors, &n_bits_total);
		OSMO_ASSERT(rc == -EIO);
		return;
	} else {
		rc = gsm0503_pdtch_decode(result, bursts_s, NULL, &n_errors, &n_bits_total);
	}
	CHECK_RC_OR_RET(rc == len, "decoding");

	printf("Decoded: %s\n", osmo_hexdump(result, len));
	printf("pdtch_decode: n_errors=%d n_bits_total=%d ber=%.2f\n",
		n_errors, n_bits_total, (float)n_errors/n_bits_total);

	OSMO_ASSERT(!memcmp(l2, result, len));

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

/* 11-bit Access Burst soft-bits (payload only) from an EGPRS capable phone (BSIC 63) */
static const sbit_t test_rach_11bit[6][36] = {
	{  103,  109, -108, -110,  107,  108, -106, -120, -121,
	  -120, -105,  122, -104, -109,  108,  109, -109, -111,
	   107,  111, -105, -119, -121, -104,  122, -120,  121,
	   -99, -121, -120, -122, -106,  109,  109, -108, -111  },

	{  103,  109, -109, -109,  106,  107, -106, -121, -121,
	  -120, -106,  121, -120,  117, -122,  101,  109, -122,
	   120, -120,  101,  118,  120,  102, -125,  101,  110,
	  -120,  121, -101, -121, -118, -121, -106,  108,  121  },

	{ -121, -122, -104,  123, -104, -108,  122, -104, -121,
	  -121, -102,  124, -105, -110,  107,  109, -108, -109,
	   121, -122,  101,  107, -121,  105,  108, -110, -107,
	   124, -104, -109,  120, -122,  100,  122,  104, -123  },

	{ -122, -123, -103,  123, -105, -109,  122, -105, -121,
	  -120, -104,  122, -120,  121, -101, -122, -120, -120,
	  -119, -105,  120, -106, -108,  123, -104, -113,  105,
	   122,  101, -122,  119, -122,  117, -121,  119, -122  },

	{  105,  110, -109, -109,  107,  108, -108, -120, -120,
	  -121, -106,  121, -104, -107,  106,  108, -108, -108,
	   108,  107, -105, -120, -122, -104,  122, -119,  121,
	  -103, -122, -118, -120, -106,  108,  108, -110, -111  },

	{  120, -103, -123, -104,  119, -121,  100,  123,  106,
	  -109, -107,  121, -122,  118, -121,  103,  108, -122,
	   120, -119,  121, -103, -121, -119, -121, -103,  124,
	  -106, -108,  122, -103, -106,  121, -120,  119, -121  },
};

uint8_t test_speech_fr[33];
uint8_t test_speech_efr[31];
uint8_t test_speech_hr[15];

int main(int argc, char **argv)
{
	int i, len_l2, len_mb;

	len_l2 = ARRAY_SIZE(test_l2);
	len_mb = ARRAY_SIZE(test_macblock);

	for (i = 0; i < len_l2; i++)
		test_xcch(test_l2[i]);

	for (i = 0; i < 256; i++) {
		test_rach(0x3f, i);
		test_rach(0x00, i);
		test_rach(0x1a, i);
	}

	for (i = 0; i < 2048; i++) {
		test_rach_ext(0x3f, i);
		test_rach_ext(0x00, i);
		test_rach_ext(0x1a, i);
	}

	for (i = 0; i < ARRAY_SIZE(test_rach_11bit); i++)
		test_rach_11bit_sample(0x3f, test_rach_11bit[i]);
	printf("\n");

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
		if (test_macblock[i].is_egprs) {
			test_pdtch(&test_macblock[i], test_macblock[i].l2_len);
		} else {
			test_pdtch(&test_macblock[i], 23);
			test_pdtch(&test_macblock[i], 34);
			test_pdtch(&test_macblock[i], 40);
			test_pdtch(&test_macblock[i], 54);
		}
	}

	printf("Success\n");

	return 0;
}
