/*
 * (C) 2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2017 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
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
#include <osmocom/core/utils.h>
#include <osmocom/gsm/lapdm.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>

static struct log_info info = {};

static const uint8_t simple_config[] = { 66, 18, 0, 3, 1, 2, 3, 19, 0, 3, 3, 4, 5 };

static const uint8_t dual_config[] = {
	66, 18, 0, 3, 1, 2, 3, 19, 0, 3, 3, 4, 5,
	66, 18, 0, 3, 9, 7, 5, 19, 0, 3, 6, 7, 8,
};

static void test_simple_sw_config(void)
{
	struct abis_nm_sw_desc desc[1];
	uint16_t len;
	int rc;

	rc = abis_nm_get_sw_conf(simple_config, ARRAY_SIZE(simple_config), &desc[0], ARRAY_SIZE(desc));
	if (rc != 1) {
		printf("%s(): FAILED to parse the File Id/File version: %d\n", __func__, rc);
		abort();
	}

	len = abis_nm_sw_desc_len(&desc[0], true);
	if (len != 13) {
		printf("WRONG SIZE: %u\n", len);
		abort();
	}

	printf("len: %u\n", len);
	printf("file_id:  %s\n", osmo_hexdump(desc[0].file_id, desc[0].file_id_len));
	printf("file_ver: %s\n", osmo_hexdump(desc[0].file_version, desc[0].file_version_len));
	printf("%s(): OK\n", __func__);
}

static void test_simple_sw_short(void)
{
	struct abis_nm_sw_desc desc[1];
	int i;

	for (i = 1; i < ARRAY_SIZE(simple_config); ++i) {
		int rc = abis_nm_get_sw_conf(simple_config, ARRAY_SIZE(simple_config) - i, &desc[0], ARRAY_SIZE(desc));
		if (rc >= 1) {
			printf("SHOULD not have parsed: %d\n", rc);
			abort();
		}
	}
	printf("%s(): OK\n", __func__);
}

static void test_dual_sw_config(void)
{
	struct abis_nm_sw_desc desc[2];
	uint16_t len0, len1;
	int rc;

	rc = abis_nm_get_sw_conf(dual_config, ARRAY_SIZE(dual_config), &desc[0], ARRAY_SIZE(desc));
	if (rc != 2) {
		printf("%s(): FAILED to parse the File Id/File version: %d (%d,%d)\n",
		       __func__, -rc, EBADF, EBADMSG);
		abort();
	}

	len0 = abis_nm_sw_desc_len(&desc[0], true);
	if (len0 != 13) {
		printf("WRONG SIZE0: %u\n", len0);
		abort();
	}

	len1 = abis_nm_sw_desc_len(&desc[1], true);
	if (len1 != 13) {
		printf("WRONG SIZE1: %u\n", len1);
		abort();
	}

	printf("len: %u\n", len0);
	printf("file_id:  %s\n", osmo_hexdump(desc[0].file_id, desc[0].file_id_len));
	printf("file_ver: %s\n", osmo_hexdump(desc[0].file_version, desc[0].file_version_len));

	printf("len: %u\n", len1);
	printf("file_id:  %s\n", osmo_hexdump(desc[1].file_id, desc[1].file_id_len));
	printf("file_ver: %s\n", osmo_hexdump(desc[1].file_version, desc[1].file_version_len));
	printf("%s(): OK\n", __func__);
}

static inline void print_chk(const char *what, uint8_t len1, uint8_t len2, const uint8_t *x1, const uint8_t *x2)
{
	int cmp = memcmp(x1, x2, len2);
	printf("\tFILE %s [%u == %u -> %d, %s] %d => %s\n", what, len1, len2, len1 == len2, len1 != len2 ? "fail" : "ok",
	       cmp, cmp != 0 ? "FAIL" : "OK");
}

static inline void chk_raw(const char *what, const uint8_t *data, uint16_t len)
{
	/* = { 0 } triggers a warning in some gcc versions due to a bug: gcc issue #53119 */
	struct abis_nm_sw_desc sw = { {0} };
	int res = abis_nm_get_sw_conf(data, len, &sw, 1);
	uint16_t xlen = abis_nm_get_sw_desc_len(data, len);

	printf("parsing chained %s <1st: %d, total: %d>\n\tSW Descr (%s)\n", osmo_hexdump(data, len), xlen, len, what);

	if (res < 0)
		printf("\tFAIL: %d\n", -res);
	else {
		printf("\tFILE ID: [%d] %s => OK\n", sw.file_id_len, osmo_hexdump(sw.file_id, sw.file_id_len));
		printf("\tFILE VERSION: [%d] %s => OK\n", sw.file_version_len,
		       osmo_hexdump(sw.file_version, sw.file_version_len));
	}

	if (len != xlen)
		chk_raw(" 2nd", data + xlen, len - xlen);
}

static inline void chk_descr(struct msgb *msg, const char *f_id, const char *f_ver, const char *desc, bool header)
{
	int res;
	uint16_t len;
	/* = { 0 } triggers a warning in some gcc versions due to a bug: gcc issue #53119 */
	struct abis_nm_sw_desc sw = { {0} }, put = {
		.file_id_len = strlen(f_id),
		.file_version_len = strlen(f_ver),
	};

	memcpy(put.file_id, f_id, put.file_id_len);
	memcpy(put.file_version, f_ver, put.file_version_len);
	len = abis_nm_put_sw_file(msg, f_id, f_ver, header);

	printf("msgb[%u] :: {msgb->len} %u == %u {len}  - %s]:\n\tSW DESCR (%s)\n"
	       "\tlength: {extracted} %u = %u {expected} - %s, failsafe - %s\n",
	       msg->data_len, msg->len, len, len != msg->len ? "fail" : "ok", desc,
	       abis_nm_get_sw_desc_len(msgb_data(msg), msg->len), msg->len,
	       abis_nm_get_sw_desc_len(msgb_data(msg), msg->len) != msg->len ? "FAIL" : "OK",
	       len > put.file_version_len + put.file_id_len ? "OK" : "FAIL");

	res = abis_nm_get_sw_conf(msgb_data(msg), msg->len, &sw, 1);
	if (res < 0)
		printf("\tSW DESCR (%s) parsing error code %d!\n", desc, -res);
	else {
		print_chk("ID", sw.file_id_len, put.file_id_len, sw.file_id, put.file_id);
		print_chk("VERSION", sw.file_version_len, put.file_version_len, sw.file_version, put.file_version);
	}
}

static void test_sw_descr(void)
{
	const char *f_id = "TEST.L0L", *f_ver = "0.1.666~deadbeeffacefeed-dirty";
	uint8_t chain[] = { 0x42, 0x12, 0x00, 0x03, 0x01, 0x02, 0x03, 0x13, 0x00, 0x03, 0x03, 0x04, 0x05, 0x42, 0x12,
			    0x00, 0x03, 0x09, 0x07, 0x05, 0x13, 0x00, 0x03, 0x06, 0x07, 0x08 };
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "sw");

	printf("Testing SW Description (de)serialization...\n");

	/* check that parsing |SW|ID|VER| works: */
	chk_descr(msg, f_id, f_ver, "with header", true);
	msgb_reset(msg);

	/* check that parsing |ID|VER| works: */
	chk_descr(msg, f_id, f_ver, "without header", false);

	/* check that parsing |ID|VER|SW|ID|VER| fails - notice the lack of msgb_reset() to create bogus msgb data: */
	chk_descr(msg, f_id, f_ver, "expected failure", true);

	/* check multiple, chained SW-descr: */
	chk_raw("half", chain, sizeof(chain) / 2);
	chk_raw("full", chain, sizeof(chain));

	msgb_free(msg);
}

/* Test decode IPAC_DLCX_IND obtained from SYS#5915 */
static void test_dec_ipac_dlc_indx(void)
{
/* Radio Signalling Link (RSL)
	0111 111. = Message discriminator: ip.access Vendor Specific messages (63)
	.... ...0 = T bit: Not considered transparent by BTS
	.111 0110 = Message type: ip.access DLCX INDication (0x76)
	Channel number IE
		Element identifier: Channel Number (0x01)
		0000 1... = C-bits: Bm + ACCH (1)
		.... .110 = Time slot number (TN): 6
	Element identifier: Connection Identifier (0xf8)
		ip.access Connection ID: 0
	Element identifier: Connection Statistics (0xf6)
		[1 byte length here, val = 28 (0x1c)]
		Packets Sent: 1202
		Octets Sent: 45052
		Packets Received: 556
		Octets Received: 24580
		Packets Lost: 0
		Inter-arrival Jitter: 0
		Average Tx Delay: 0
	Cause IE
		Element identifier: Cause (0x1a)
		Length: 1
		0... .... = Extension: No Extension
		.000 .... = Class: Normal event (0)
		.000 1111 = Cause Value: normal event, unspecified (15)
*/
	const uint8_t hex[] = {
		0x7e, 0x76, 0x01, 0x0e, 0xf8, 0x00, 0x00, 0xf6, 0x1c, 0x00, 0x00, 0x04, 0xb2, 0x00, 0x00, 0xaf,
		0xfc, 0x00, 0x00, 0x02, 0x2c, 0x00, 0x00, 0x60, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x01, 0x0f
	};
	struct abis_rsl_dchan_hdr *dh = (struct abis_rsl_dchan_hdr *)&hex[0];

	struct tlv_parsed tp;
	int rc;

	printf("Testing decoding IPAC_DLCX_IND\n");

	rc = rsl_tlv_parse(&tp, dh->data, sizeof(hex) - sizeof(*dh));

	OSMO_ASSERT(rc == 3);
}

int main(int argc, char **argv)
{
	void *ctx = talloc_named_const(NULL, 0, "abis_test");
	osmo_init_logging2(ctx, &info);

	test_sw_descr();
	test_simple_sw_config();
	test_simple_sw_short();
	test_dual_sw_config();
	test_dec_ipac_dlc_indx();

	printf("OK.\n");

	return 0;
}
