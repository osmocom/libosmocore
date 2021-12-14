/*
 * (C) 2010 by Holger Hans Peter Freyther
 * (C) 2010 by On-Waves
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

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/gsm_utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t ussd_request[] = {
	0x0b, 0x7b, 0x1c, 0x15, 0xa1, 0x13, 0x02, 0x01,
	0x03, 0x02, 0x01, 0x3b, 0x30, 0x0b, 0x04, 0x01,
	0x0f, 0x04, 0x06, 0x2a, 0xd5, 0x4c, 0x16, 0x1b,
	0x01, 0x7f, 0x01, 0x00
};

static const uint8_t ussd_facility[] = {
	0x1b, 0x3a, 0x12, 0xa2, 0x10, 0x02, 0x01, 0x01,
	0x30, 0x0b, 0x02, 0x01, 0x3c, 0x30, 0x06, 0x04,
	0x01, 0x0f, 0x04, 0x01, 0x32
};

static const uint8_t ussd_release[] = {
	0x8b, 0x2a, 0x1c, 0x08, 0xa3, 0x06, 0x02, 0x01,
	0x05, 0x02, 0x01, 0x24
};

static const uint8_t interrogate_ss[] = {
	0x0b, 0x7b, 0x1c, 0x0d, 0xa1, 0x0b, 0x02, 0x01,
	0x03, 0x02, 0x01, 0x0e, 0x30, 0x03, 0x04, 0x01,
	0x21, 0x7f, 0x01, 0x00
};

static int parse_ussd(const uint8_t *_data, int len)
{
	uint8_t *data;
	int rc;
	struct ss_request req;
	struct gsm48_hdr *hdr;

	data = malloc(len);
	memcpy(data, _data, len);
	hdr = (struct gsm48_hdr *) &data[0];
	rc = gsm0480_decode_ss_request(hdr, len, &req);
	free(data);

	return rc;
}

static int parse_mangle_ussd(const uint8_t *_data, int len)
{
	uint8_t *data;
	int rc;
	struct ss_request req;
	struct gsm48_hdr *hdr;

	data = malloc(len);
	memcpy(data, _data, len);
	hdr = (struct gsm48_hdr *) &data[0];
	hdr->data[1] = len - sizeof(*hdr) - 2;
	rc = gsm0480_decode_ss_request(hdr, len, &req);
	free(data);

	return rc;
}

struct log_info info = {};

static void test_7bit_ussd(const char *text, const char *encoded_hex, const char *appended_after_decode)
{
	uint8_t coded[256];
	char decoded[256];
	int octets_written;
	int buffer_size;
	int nchars;

	printf("original = %s\n", osmo_hexdump((uint8_t *)text, strlen(text)));
	gsm_7bit_encode_n_ussd(coded, sizeof(coded), text, &octets_written);
	printf("encoded = %s\n", osmo_hexdump(coded, octets_written));

	OSMO_ASSERT(strcmp(encoded_hex, osmo_hexdump_nospc(coded, octets_written)) == 0);

	gsm_7bit_decode_n_ussd(decoded, sizeof(decoded), coded, octets_written * 8 / 7);
	printf("decoded = %s\n\n", osmo_hexdump((uint8_t *)decoded, strlen(decoded)));

	OSMO_ASSERT(strncmp(text, decoded, strlen(text)) == 0);
	OSMO_ASSERT(strcmp(appended_after_decode, decoded + strlen(text)) == 0);

	/* check buffer limiting */
	memset(decoded, 0xaa, sizeof(decoded));

	for (buffer_size = 1; buffer_size < sizeof(decoded) - 1; ++buffer_size)
	{
		nchars = gsm_7bit_decode_n_ussd(decoded, buffer_size, coded, octets_written * 8 / 7);
		OSMO_ASSERT(nchars <= buffer_size);
		OSMO_ASSERT(decoded[buffer_size] == (char)0xaa);
		OSMO_ASSERT(decoded[nchars] == '\0');
	}

	memset(coded, 0xaa, sizeof(coded));

	for (buffer_size = 0; buffer_size < sizeof(coded) - 1; ++buffer_size)
	{
		gsm_7bit_encode_n_ussd(coded, buffer_size, text, &octets_written);
		OSMO_ASSERT(octets_written <= buffer_size);
		OSMO_ASSERT(coded[buffer_size] == 0xaa);
	}
}

static void test_extract_ie_by_tag(void)
{
	uint16_t ie_len;
	uint8_t *ie;
	int rc;

	printf("[i] Testing gsm0480_extract_ie_by_tag()\n");

	/* REGISTER message with Facility IE */
	rc = gsm0480_extract_ie_by_tag((struct gsm48_hdr *) ussd_request,
		sizeof(ussd_request), &ie, &ie_len, GSM0480_IE_FACILITY);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(ie != NULL && ie_len > 0);
	printf("[?] REGISTER message with Facility IE "
		"(len=%u): %s\n", ie_len, osmo_hexdump(ie, ie_len));

	/* REGISTER message with SS version IE */
	rc = gsm0480_extract_ie_by_tag((struct gsm48_hdr *) ussd_request,
		sizeof(ussd_request), &ie, &ie_len, GSM0480_IE_SS_VERSION);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(ie != NULL && ie_len > 0);
	printf("[?] REGISTER message with SS version IE "
		"(len=%u): %s\n", ie_len, osmo_hexdump(ie, ie_len));

	/* REGISTER message with unknown IE */
	rc = gsm0480_extract_ie_by_tag((struct gsm48_hdr *) ussd_request,
		sizeof(ussd_request), &ie, &ie_len, 0xff);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(ie == NULL && ie_len == 0);

	/* FACILITY message with Facility IE */
	rc = gsm0480_extract_ie_by_tag((struct gsm48_hdr *) ussd_facility,
		sizeof(ussd_facility), &ie, &ie_len, GSM0480_IE_FACILITY);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(ie != NULL && ie_len > 0);
	printf("[?] FACILITY message with Facility IE "
		"(len=%u): %s\n", ie_len, osmo_hexdump(ie, ie_len));

	/* FACILITY message with unknown IE */
	rc = gsm0480_extract_ie_by_tag((struct gsm48_hdr *) ussd_facility,
		sizeof(ussd_facility), &ie, &ie_len, 0xff);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(ie == NULL && ie_len == 0);

	/* RELEASE COMPLETE message with Facility IE */
	rc = gsm0480_extract_ie_by_tag((struct gsm48_hdr *) ussd_release,
		sizeof(ussd_release), &ie, &ie_len, GSM0480_IE_FACILITY);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(ie != NULL && ie_len > 0);
	printf("[?] RELEASE COMPLETE message with Facility IE "
		"(len=%u): %s\n", ie_len, osmo_hexdump(ie, ie_len));

	/* RELEASE COMPLETE message without Facility IE */
	rc = gsm0480_extract_ie_by_tag((struct gsm48_hdr *) ussd_release,
		sizeof(struct gsm48_hdr), &ie, &ie_len, GSM0480_IE_FACILITY);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(ie == NULL && ie_len == 0);

	printf("\n");
}

static void test_parse_facility_ie(void)
{
	struct ss_request req;
	uint16_t ie_len;
	uint8_t *ie;
	int rc;

	printf("[i] Testing gsm0480_parse_facility_ie()\n");

	/* Extract Facility IE from FACILITY message */
	rc = gsm0480_extract_ie_by_tag((struct gsm48_hdr *) ussd_facility,
		sizeof(ussd_facility), &ie, &ie_len, GSM0480_IE_FACILITY);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(ie != NULL && ie_len > 0);
	printf("[?] FACILITY message with Facility IE "
		"(len=%u): %s\n", ie_len, osmo_hexdump(ie, ie_len));

	/* Attempt to decode */
	memset(&req, 0x00, sizeof(req));
	rc = gsm0480_parse_facility_ie(ie, ie_len, &req);
	OSMO_ASSERT(rc == 0);

	/* Verify expected vs decoded data */
	printf("[?] InvokeID: expected 0x%02x, decoded 0x%02x\n",
		0x01, req.invoke_id);
	printf("[?] Operation code: expected 0x%02x, decoded 0x%02x\n",
		0x3c, req.opcode);
	printf("[?] Data Coding Scheme: expected 0x%02x, decoded 0x%02x\n",
		0x0f, req.ussd_data_dcs);
	printf("[?] Data length: expected 0x%02x, decoded 0x%02x\n",
		0x01, req.ussd_data_len);
	printf("[?] Data: expected %s, decoded %s\n", "32",
		osmo_hexdump_nospc(req.ussd_data, req.ussd_data_len));

	printf("\n");
}

int main(int argc, char **argv)
{
	struct ss_request req;
	uint16_t size;
	int i;
	struct msgb *msg;
	void *ctx = talloc_named_const(NULL, 0, "ussd_test");

	osmo_init_logging2(ctx, &info);

	/* Test gsm0480_extract_ie_by_tag() */
	test_extract_ie_by_tag();

	/* Test gsm0480_parse_facility_ie() */
	test_parse_facility_ie();

	memset(&req, 0, sizeof(req));
	gsm0480_decode_ss_request((struct gsm48_hdr *) ussd_request,
		sizeof(ussd_request), &req);
	printf("Tested if it still works. Text was: %s\n", req.ussd_text);

	memset(&req, 0, sizeof(req));
	gsm0480_decode_ss_request((struct gsm48_hdr *) interrogate_ss,
		sizeof(interrogate_ss), &req);
	OSMO_ASSERT(strlen((char *) req.ussd_text) == 0);
	OSMO_ASSERT(req.ss_code == 33);
	printf("interrogateSS CFU text..'%s' code %d\n", req.ussd_text, req.ss_code);

	printf("Testing parsing a USSD request and truncated versions\n");

	size = sizeof(ussd_request);

	for (i = size; i > sizeof(struct gsm48_hdr); --i) {
		int rc = parse_ussd(&ussd_request[0], i);
		printf("Result for len=%d is %d\n", i, rc);
	}

	printf("Mangling the container now\n");
	for (i = size; i > sizeof(struct gsm48_hdr) + 2; --i) {
		int rc = parse_mangle_ussd(&ussd_request[0], i);
		printf("Result for len=%d is %d\n", i, rc);
	}

	printf("<CR> case test for 7 bit encode\n");
	test_7bit_ussd("01234567",   "b0986c46abd96e",   "");
	test_7bit_ussd("0123456",    "b0986c46abd91a",   "");
	test_7bit_ussd("01234567\r", "b0986c46abd96e0d", "");
        /* The appended \r is compliant to GSM 03.38 section 6.1.2.3.1: */
	test_7bit_ussd("0123456\r",  "b0986c46abd91a0d", "\r");
	test_7bit_ussd("012345\r",   "b0986c46ab351a",   "");

	printf("Checking GSM 04.80 USSD message generation.\n");

	test_7bit_ussd("", "", "");
	msg = gsm0480_create_unstructuredSS_Notify (0x00, "");
	printf ("Created unstructuredSS_Notify (0x00): %s\n",
			osmo_hexdump(msgb_data(msg), msgb_length(msg)));
	msgb_free (msg);

	test_7bit_ussd("forty-two", "e6b79c9e6fd1ef6f", "");
	msg = gsm0480_create_unstructuredSS_Notify (0x42, "forty-two");
	printf ("Created unstructuredSS_Notify (0x42): %s\n",
			osmo_hexdump(msgb_data(msg), msgb_length(msg)));
	msgb_free (msg);
	return 0;
}
