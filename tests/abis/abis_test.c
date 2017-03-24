/*
 * (C) 2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2017 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
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
	struct abis_nm_sw_desc sw = { 0 };
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
	struct abis_nm_sw_desc sw = { 0 }, put = {
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

static void test_sw_descr()
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
}

int main(int argc, char **argv)
{
	osmo_init_logging(&info);

	test_sw_descr();
	test_simple_sw_config();
	test_simple_sw_short();
	test_dual_sw_config();

	printf("OK.\n");

	return 0;
}
