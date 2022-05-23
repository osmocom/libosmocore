/*
 * (C) 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Philipp Maier <pmaier@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
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

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <osmocom/core/utils.h>
#include <osmocom/coding/gsm0503_coding.h>
#include <osmocom/coding/gsm0503_amr_dtx.h>

/* Length of payload bits in a Normal Burst */
#define BURST_PLEN	(57 * 2 + 2)

char sample_afs_sid_frame[] =
    {
"111111110000000011001100101010100100010011111111001000100111011110011001001100111100110010011001111011100100010011111111001000100111011110011001001100111100110010011001111011100100010011111111001000100111011110011001001100111100110010011001111011100100010011111111001000100111011110011001001100111100110010011001111011100100010011111111001000100111011110011001001100111100110010011001111011100100010011111111001000100111011110011001001100111100110010011001"
};

char sample_afs_sid_update_frame[] =
    {
"111111110000000011001100101010100000010000001111111100101011011110001001000000110111110000001001011111101111010011001111100000101000011111001001111100110111110011111001001111101100010001001111000000100100011100111001100000111000110000111001010011101111010011111111010000101100011100111001111100110111110011111001110011101000010010001111110000100000011111001001011100110011110010111001101111100011010001111111001100100100011111111001000000110000110000001001"
};

char sample_afs_onset_frame[] =
    {
"111111110000000011001100101010100000111100000000111111000100101000111111100000000111110010001010001111110100000011111100111110100100111111000000110011001011101001001111011100001011110000001010010011111100000000111100111110101000111110110000111111000000101011111111010000001100110000111010111111111000000010111100000010100100111100110000100011001000101000111111101100001011110000111010011111110011000010111100101110101100111111000000010011001111101000001111"
};

char sample_ahs_sid_update_frame[] =
    {
"111100001100101010110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110000110110100011001000011010000000000000001111010010000000000001000000000010110000000011001000000000000000100000101000000000000000001010100000010010000000000010000111110001110110110011001101000000000100100011001000001010000100100000000011"
};

char sample_ahs_sid_first_p1_frame[] =
    {
"111100001100101001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001111001001001011010110001101100101001110001111001110100110010000111101110110110000100100011111001001110000011110110001010010101100001010100000111101110110001010000111110001110110110011001101001111000011101001010011100011000111010110000011"
};

char sample_ahs_sid_first_p2_frame[] =
    {
"111110100100000010100000110111001110101100000100101001011101100011101010010000001010010010001100101010100100010111110101110011011110101000010100111000001001110111101110010101001110000010001101101011110000000011100100110110011111100011001000001101100101001110001111001110100110010000111101110110110000100100011111001001110000011110110001010010101100001010100000111101110110001010000111110001110110110011001101001111000011101001010011100011000111010110000011"
};

char sample_ahs_onset_frame[] =
    {
"111101011000101001010000111001000111011110000000011110001110010011011111100000101101101001101110011111010000000001010010110001101101110100000010011110101100010001011101101010000111100011101100111101011010100011110010110001001111100011001000011010000000000000001010010010000000000001000000000000100000000011001000000000000000100000101000000000000000010010000101010010000000000010101100111110101000110110011001000000000100100011001000001010000100100000001100"
};

char sample_sid_first_inh_frame[] =
    {
"xBxBxBxBxBxBxBxBxBxBxBxBxBxBxBxBx1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0x0x0x0x1x1x0x1x1x0"
};

char sample_sid_update_inh_frame[] =
    {
"xBxBxBxBxBxBxBxBxBxBxBxBxBxBxBxBx0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1x1x1x1x0x0x1x0x0x1"
};

unsigned int string_to_sbit(sbit_t *sbits, char *string)
{
	unsigned int len;
	unsigned int i;

	len = strlen(string);

	for (i = 0; i < len; i++) {
		sbits[i] = string[i] == '1' ? -127 : 127;
	}

	return len;
}

void test_gsm0503_detect_afs_dtx_frame(char *string)
{
	sbit_t sbits[512];
	uint8_t dtx_frame_type;
	int n_errors;
	int n_bits_total;
	int mode_id = -1;

	string_to_sbit(sbits, string);
	dtx_frame_type = gsm0503_detect_afs_dtx_frame2(&n_errors, &n_bits_total, &mode_id, sbits);
	printf(" ==> %s, n_errors=%d, n_bits_total=%d, mode_id=%d\n",
	       gsm0503_amr_dtx_frame_name(dtx_frame_type),
	       n_errors, n_bits_total, mode_id);
}

void test_gsm0503_detect_ahs_dtx_frame(char *string)
{
	sbit_t sbits[512];
	uint8_t dtx_frame_type;
	int n_errors;
	int n_bits_total;
	int mode_id = -1;

	string_to_sbit(sbits, string);
	dtx_frame_type = gsm0503_detect_ahs_dtx_frame2(&n_errors, &n_bits_total, &mode_id, sbits);
	printf(" ==> %s, n_errors=%d, n_bits_total=%d, mode_id=%d\n",
	       gsm0503_amr_dtx_frame_name(dtx_frame_type),
	       n_errors, n_bits_total, mode_id);
}

static void test_gsm0503_tch_afhs_decode_dtx(const sbit_t *bursts, size_t offset,
					     enum gsm0503_amr_dtx_frames *amr_last_dtx,
					     bool full_rate, const char *test_desc)
{
	uint8_t tch_data[128]; /* just to be safe */
	int n_errors = 0, n_bits_total = 0;
	int rc;

	printf("Running %s(at offset=%zu): testing %s\n", __func__, offset, test_desc);

	/* Dummy (not really important) values */
	uint8_t codec[4] = { 0, 1, 2, 3 };
	int codecs = ARRAY_SIZE(codec);
	uint8_t ul_cmr = 0;
	uint8_t ul_ft = 0;

	if (full_rate) {
		rc = gsm0503_tch_afs_decode_dtx(&tch_data[0], &bursts[offset], false,
						codec, codecs, &ul_ft, &ul_cmr,
						&n_errors, &n_bits_total,
						(uint8_t *)amr_last_dtx);
	} else {
		rc = gsm0503_tch_ahs_decode_dtx(&tch_data[0], &bursts[offset], false, false,
						codec, codecs, &ul_ft, &ul_cmr,
						&n_errors, &n_bits_total,
						(uint8_t *)amr_last_dtx);
	}
	printf(" ==> gsm0503_tch_a%cs_decode_dtx() yields '%s' (rc=%d, BER %d/%d)\n",
	       full_rate ? 'f' : 'h', gsm0503_amr_dtx_frame_name(*amr_last_dtx),
	       rc, n_errors, n_bits_total);
	if (rc > 0)
		printf(" ====> tch_data[] = { %s }\n", osmo_hexdump_nospc(tch_data, rc));
}

static void test_gsm0503_tch_afhs_decode_dtx_sid_update(void)
{
	enum gsm0503_amr_dtx_frames amr_last_dtx = AMR_OTHER;
	sbit_t bursts[BURST_PLEN * 12]; /* 12 bursts */
	int rc;

	/* 456 soft-bits containing an AFS_SID_UPDATE frame (captured on the air) */
	const char *afs_sid_update = \
		"94 81 83 76 7b 81 6b 7f 76 8c 81 81 81 86 71 7f 75 81 6d 7a 81 6b 7f 78 8a 87 70 75 8e"
		"81 8d 7f 81 70 72 81 7f 85 86 7f 93 81 8a 74 7f 71 89 8a 75 7f 7f 78 8c 81 8b 7f 81 7f"
		"7f 7f 70 8a 8b 7f 90 81 81 81 8a 77 7f 7f 70 81 70 71 86 8e 7f 81 7f 81 75 72 87 8c 76"
		"7f 72 8e 81 81 81 81 92 7f 8c 81 92 7f 8c 89 7f 81 7f 8f 8b 77 76 86 8c 78 73 88 81 8b"
		"81 7f 8c 85 77 7b 8d 81 81 81 8b 7f 81 7f 8e 81 8e 7f 8a 8a 7f 93 85 6b 7f 7f 72 81 6f"
		"76 89 81 81 81 8a 73 7f 72 88 87 73 7f 73 81 7f 81 7f 92 87 73 78 81 6f 7f 71 81 76 77"
		"6f 81 7f 81 71 7f 6e 81 75 77 83 81 81 90 7f 8b 88 76 76 8a 8d 76 74 81 7f 92 81 81 8b"
		"78 72 81 77 76 81 6c 7c 8b 81 81 8d 7f 8b 81 8e 74 7f 7f 72 81 7f 81 74 7f 71 81 75 7f"
		"8e 81 81 8c 72 79 85 8c 78 75 8c 8a 7f 90 81 8e 77 77 81 70 7f 7f 71 81 7f 81 7f 8e 89"
		"7f 8f 81 8f 7f 8c 8d 7f 81 7f 81 6f 7f 71 8a 87 7f 81 6f 77 81 7f 8d 88 73 79 8a 8a 7f"
		"7f 7f 7f 7f 76 8b 81 8c 77 7c 8a 81 91 7f 81 76 79 81 71 7f 7f 6f 84 8e 78 7f 7f 7f 74"
		"88 86 7b 77 81 6f 7f 7f 7f 7f 7f 75 81 70 7f 76 89 81 81 81 8d 78 74 84 81 8e 7f 8d 8a"
		"7f 79 8c 87 7f 81 7f 81 6f 7f 75 8d 8a 7f 81 7f 92 81 81 85 76 7f 6f 8c 88 6c 7f 73 91"
		"81 8d 71 7f 7f 73 8d 88 7f 81 7f 91 86 6f 7f 73 8e 81 8d 79 78 81 72 74 8c 86 72 7f 77"
		"6e 81 7f 81 77 76 81 72 74 81 6f 7f 6f 8d 81 91 7f 81 6d 7f 6d 81 6c 7f 6c 81 7f 81 7f"
		"8c 8b 7f 8e 89 74 74 8c 81 81 81 81 81 92 7f 8e 8b 7f 93 81 8f 7f 90 81 8d 74 7b 8b 89";

	memset(&bursts[0], 0, sizeof(bursts));
	rc = osmo_hexparse(afs_sid_update, (uint8_t *)&bursts[BURST_PLEN * 4], BURST_PLEN * 8);
	OSMO_ASSERT(rc == BURST_PLEN * 4);

	/* Test detection of AFS_SID_UPDATE (marker) */
	test_gsm0503_tch_afhs_decode_dtx(&bursts[0], BURST_PLEN * 0, &amr_last_dtx, true /* AFS */,
					 "detection of AFS_SID_UPDATE");

	/* Test decoding of AFS_SID_UPDATE_CN (actual SID) */
	test_gsm0503_tch_afhs_decode_dtx(&bursts[0], BURST_PLEN * 4, &amr_last_dtx, true /* AFS */,
					 "decoding of AFS_SID_UPDATE");

	/* 456 soft-bits containing an AHS_SID_UPDATE frame (captured on the air) */
	const char *ahs_sid_update = \
		"81 67 7f 7f 7f 71 8f 88 6f 73 81 7e 81 6b 7f 7e 7d 6f 8f 8a 72 76 92 81 82 81 8f 6d 6f"
		"81 7f 92 8c 7f 97 81 8e 6f 7f 7c 7f 6e 81 7e 81 6e 73 81 7f 93 8d 6f 7f 6c 81 6b 7f 72"
		"7c 7c 7d 7f 6f 8f 81 94 7f 92 8d 6e 7d 7d 7f 6c 8b 8e 73 71 81 7f 92 90 7f 81 6e 6e 81"
		"7f 94 8e 70 7f 6e 8c 8d 77 7f 6a 81 7f 81 70 6d 81 6c 71 8c 91 7f 90 8e 73 6e 81 6d 7f"
		"81 8b 71 6e 81 7f 82 7c 81 7f 81 6d 73 81 6c 6d 81 6d 7f 6e 81 7e 81 6b 7f 7f 7f 6b 81"
		"6e 6f 81 68 7f 71 91 81 82 81 8e 70 7f 7c 7d 7f 70 81 7f 91 8f 7f 81 6c 7f 71 81 6d 74"
		"6f 8f 81 92 7f 82 7f 91 8b 7f 81 6b 7f 6d 81 6b 6f 81 6f 6e 90 81 81 92 7f 94 81 95 7f"
		"96 81 96 70 7f 72 8f 81 95 7f 81 6f 70 81 7f 90 92 7f 81 6c 70 81 6b 7f 6f 8d 8d 7f 81"
		"77 81 6a 7e 7e 73 92 8c 7f 81 6a 7f 6c 8e 8e 6e 7f 71 8e 8d 7e 81 6d 7f 6c 81 6d 6c 81"
		"7f 94 81 92 7f 97 81 92 6e 7f 70 8c 8b 73 73 91 81 93 7f 81 70 72 81 7d 81 71 70 81 7f"
		"7d 7f 6d 90 8d 73 76 92 81 92 6f 7d 7d 70 91 81 8f 73 75 8c 90 7f 94 81 91 70 7f 7d 7e"
		"70 8d 8d 73 7f 7c 7e 6a 81 7e 81 6d 7f 6a 81 6f 7f 7f 71 8e 81 82 81 81 81 96 72 7e 7d"
		"81 8d 7f 81 68 7f 7e 7c 7b 7f 6c 81 6a 7f 7f 71 8f 8d 7f 81 6c 72 8e 88 70 70 81 6d 70"
		"8d 90 7f 81 7e 95 81 94 7f 92 8b 6e 7f 7f 70 8c 8c 73 75 91 81 91 6d 7d 7e 7b 7c 7d 71"
		"6c 89 91 7f 81 7f 95 81 93 7f 95 90 7f 81 6d 70 81 6f 75 8c 8e 75 71 81 6e 70 8d 8d 7f"
		"91 92 7f 81 7f 94 8d 70 71 81 6e 6d 81 6e 75 8e 81 93 70 7f 70 8f 8c 7f 81 6d 6f 81 6a";

	memset(&bursts[0], 0, sizeof(bursts));
	rc = osmo_hexparse(ahs_sid_update, (uint8_t *)&bursts[BURST_PLEN * 2], BURST_PLEN * 10);
	OSMO_ASSERT(rc == BURST_PLEN * 4);

	/* Test detection and decoding of AHS_SID_UPDATE */
	test_gsm0503_tch_afhs_decode_dtx(&bursts[0], BURST_PLEN * 0, &amr_last_dtx, false /* AHS */,
					 "detection/decoding of AHS_SID_UPDATE");
	test_gsm0503_tch_afhs_decode_dtx(&bursts[0], BURST_PLEN * 2, &amr_last_dtx, false /* AHS */,
					 "detection/decoding of AHS_SID_UPDATE");
	test_gsm0503_tch_afhs_decode_dtx(&bursts[0], BURST_PLEN * 4, &amr_last_dtx, false /* AHS */,
					 "detection/decoding of AHS_SID_UPDATE");
}

static void test_gsm0503_tch_afhs_decode_dtx_facch(void)
{
	enum gsm0503_amr_dtx_frames amr_last_dtx;
	sbit_t bursts[BURST_PLEN * 8]; /* 8 bursts */
	unsigned int i;

	/* Set stealing bits to provoke FACCH/[FH] detection */
	for (i = 0; i < 8; i++) {
		sbit_t *burst = &bursts[BURST_PLEN * i];
		memset(&burst[0], 0, BURST_PLEN);
		burst[i >> 2 ? 57 : 58] = -127;
	}

	amr_last_dtx = AFS_SID_UPDATE;
	test_gsm0503_tch_afhs_decode_dtx(&bursts[0], BURST_PLEN * 0,
					 &amr_last_dtx, true /* AFS */,
					 "tagging of FACCH/F");
	OSMO_ASSERT(amr_last_dtx == AMR_OTHER);

	amr_last_dtx = AHS_SID_UPDATE;
	test_gsm0503_tch_afhs_decode_dtx(&bursts[0], BURST_PLEN * 0,
					 &amr_last_dtx, false /* AHS */,
					 "tagging of FACCH/H");
	OSMO_ASSERT(amr_last_dtx == AMR_OTHER);
}

int main(int argc, char **argv)
{
	printf("FR AMR DTX FRAMES:\n");
	test_gsm0503_detect_afs_dtx_frame(sample_afs_sid_frame);
	test_gsm0503_detect_afs_dtx_frame(sample_afs_sid_update_frame);
	test_gsm0503_detect_afs_dtx_frame(sample_afs_onset_frame);
	printf("HR AMR DTX FRAMES:\n");
	test_gsm0503_detect_ahs_dtx_frame(sample_ahs_sid_update_frame);
	test_gsm0503_detect_ahs_dtx_frame(sample_ahs_sid_first_p1_frame);
	test_gsm0503_detect_ahs_dtx_frame(sample_ahs_sid_first_p2_frame);
	test_gsm0503_detect_ahs_dtx_frame(sample_ahs_onset_frame);
	test_gsm0503_detect_ahs_dtx_frame(sample_sid_first_inh_frame);
	test_gsm0503_detect_ahs_dtx_frame(sample_sid_update_inh_frame);

	test_gsm0503_tch_afhs_decode_dtx_sid_update();
	test_gsm0503_tch_afhs_decode_dtx_facch();

	return EXIT_SUCCESS;
}
