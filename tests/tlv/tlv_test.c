/* Copyright (C) 2014 sysmocom - s.f.m.c. GmbH. All rights reserved
 * Author: Daniel Laszlo Sitzer <dlsitzer@sysmocom.de>
 *
 * This program is iree software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <osmocom/gsm/tlv.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const struct tlv_definition dummy_tlvdef = {
	.def = {
		[1] = { TLV_TYPE_T7L9V },
		[4] = { TLV_TYPE_TV },
	},
};

static const struct tlv_definition lldp_tlvdef = {
	.def = {
		[1] = { TLV_TYPE_T7L9V },
		[2] = { TLV_TYPE_T7L9V },
		[3] = { TLV_TYPE_T7L9V },
		[0] = { TLV_TYPE_T7L9V },
	},
};

static void test_lldp_tlv(void)
{
	struct msgb *m;
	struct tlv_parsed tp;
	int nparsed;
	uint8_t *res;

	printf("%s\n", __func__);

	m = msgb_alloc(128, "lldp_tlv");

	res = msgb_t7l9_put(m, 1, 7);
	OSMO_ASSERT(m->len == 2);
	OSMO_ASSERT(m->data[0] == 2);
	OSMO_ASSERT(m->data[1] == 7);
	OSMO_ASSERT(res == &m->data[2]);

	m->len += 7;
	m->tail += 7;

	msgb_tv_put(m, 4, 0x55);

	nparsed = tlv_parse(&tp, &dummy_tlvdef, m->data, m->len, 0, 0);
	OSMO_ASSERT(nparsed == 2);
	OSMO_ASSERT(!TLVP_PRESENT(&tp, 0));
	OSMO_ASSERT(TLVP_PRESENT(&tp, 1));
	OSMO_ASSERT(TLVP_PRESENT(&tp, 4));
	OSMO_ASSERT(TLVP_LEN(&tp, 1) == 7);
	OSMO_ASSERT(TLVP_VAL(&tp, 1) == &m->data[2]);
	OSMO_ASSERT(*TLVP_VAL(&tp, 4) == 0x55);

	msgb_free(m);
}

static void test_lldp_tlv_col(void)
{
	struct msgb *m;
	struct tlv_parsed tp;
	int nparsed;
	uint8_t *res;

	printf("%s\n", __func__);

	m = msgb_alloc(512, "lldp_tlv");

	res = msgb_t7l9_put(m, 1, 256);
	OSMO_ASSERT(m->len == 2);
	OSMO_ASSERT(m->data[0] == 3);
	OSMO_ASSERT(m->data[1] == 0);
	OSMO_ASSERT(res == &m->data[2]);

	m->len += 256;
	m->tail += 256;

	msgb_tv_put(m, 4, 0xAA);

	nparsed = tlv_parse(&tp, &dummy_tlvdef, m->data, m->len, 0, 0);
	OSMO_ASSERT(nparsed == 2);
	OSMO_ASSERT(!TLVP_PRESENT(&tp, 0));
	OSMO_ASSERT(TLVP_PRESENT(&tp, 1));
	OSMO_ASSERT(TLVP_PRESENT(&tp, 4));
	OSMO_ASSERT(TLVP_LEN(&tp, 1) == 256);
	OSMO_ASSERT(TLVP_VAL(&tp, 1) == &m->data[2]);
	OSMO_ASSERT(*TLVP_VAL(&tp, 4) == 0xAA);

	msgb_free(m);
}

static struct msgb *create_lldp_frame(const uint8_t *mac)
{
	int i;
	struct msgb *m;

	m = msgb_alloc(512, "lldp_tlv");

	/* Chassis ID TLV */
	msgb_t7l9_put(m, 1, 7);
	msgb_put_u8(m, 4); /* Chassis ID Subtype: MAC address */
	for (i = 0; i < 6; ++i)
		msgb_put_u8(m, mac[i]);

	/* Port ID TLV */
	msgb_t7l9_put(m, 2, 7);
	msgb_put_u8(m, 3); /* Port ID Subtype: MAC address */
	for (i = 0; i < 6; ++i)
		msgb_put_u8(m, mac[i]);

	/* TTL TLV */
	msgb_t7l9_put(m, 3, 2);
	msgb_put_u16(m, 127);

	/* EOLLDPDU TLV */
	msgb_t7l9_put(m, 0, 0);

	return m;
}

static void test_lldp_tlv_lldpdu(void)
{
	struct msgb *m;
	struct tlv_parsed tp;
	int nparsed;
	const uint8_t mac[] = {0xF0, 0xDE, 0xF1, 0x02, 0x43, 0x01};

	printf("%s\n", __func__);

	m = create_lldp_frame(mac);

	nparsed = tlv_parse(&tp, &lldp_tlvdef, m->data, m->len, 0, 0);
	OSMO_ASSERT(nparsed == 4);
	OSMO_ASSERT(TLVP_PRESENT(&tp, 1));
	OSMO_ASSERT(TLVP_PRESENT(&tp, 2));
	OSMO_ASSERT(TLVP_PRESENT(&tp, 3));
	OSMO_ASSERT(TLVP_PRESENT(&tp, 0));
	OSMO_ASSERT(TLVP_LEN(&tp, 1) == 1 + ARRAY_SIZE(mac));
	OSMO_ASSERT(TLVP_LEN(&tp, 2) == 1 + ARRAY_SIZE(mac));
	OSMO_ASSERT(TLVP_LEN(&tp, 3) == 2);
	OSMO_ASSERT(TLVP_LEN(&tp, 0) == 0);
	OSMO_ASSERT(*TLVP_VAL(&tp, 1) == 4);
	OSMO_ASSERT(*TLVP_VAL(&tp, 2) == 3);
	OSMO_ASSERT(memcmp(TLVP_VAL(&tp, 1)+1, mac, ARRAY_SIZE(mac)) == 0);
	OSMO_ASSERT(memcmp(TLVP_VAL(&tp, 2)+1, mac, ARRAY_SIZE(mac)) == 0);
	OSMO_ASSERT(*TLVP_VAL(&tp, 3) == 0);
	OSMO_ASSERT(*(TLVP_VAL(&tp, 3)+1) == 127);

	msgb_free(m);
}

static void test_lldp_truncated(void)
{
	struct msgb *m;
	const uint8_t mac[] = {0xF0, 0xDE, 0xF1, 0x02, 0x43, 0x01};
	size_t i;
	int success = 0;

	printf("%s\n", __func__);

	m = create_lldp_frame(mac);

	/* test truncated messages and expect the parse failure */
	for (i = m->len; i > 0; --i) {
		int nparsed;
		struct tlv_parsed tp;

		nparsed = tlv_parse(&tp, &lldp_tlvdef, m->data, i, 0, 0);
		if (nparsed >= 0) {
			printf("Success on %zu with %d\n", i, nparsed);
			success += 1;
		}
	}

	/* if we truncate a frame enough it becomes parable again */
	OSMO_ASSERT(success == 4);
	msgb_free(m);	
}

int main(int argc, char *argv[])
{
	test_lldp_tlv();
	test_lldp_tlv_col();
	test_lldp_tlv_lldpdu();
	test_lldp_truncated();

	return EXIT_SUCCESS;
}
