/*
 * (C) 2012 by Holger Hans Peter Freyther
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

#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define VERIFY(msg, data, len) 						\
	if (msgb_l3len(msg) != len) {					\
		printf("%s:%d Length don't match: %d vs. %d. %s\n", 	\
			__func__, __LINE__, msgb_l3len(msg), (int) len,	\
			osmo_hexdump(msg->l3h, msgb_l3len(msg))); 	\
		abort();						\
	} else if (memcmp(msg->l3h, data, len) != 0) {			\
		printf("%s:%d didn't match: got: %s\n",			\
			__func__, __LINE__,				\
			osmo_hexdump(msg->l3h, msgb_l3len(msg)));	\
		abort();						\
	}

/* Setup a fake codec list for testing */
static void setup_codec_list(struct gsm0808_speech_codec_list *scl)
{
	memset(scl, 0, sizeof(*scl));

	scl->codec[0].pi = true;
	scl->codec[0].tf = true;
	scl->codec[0].type = GSM0808_SCT_FR3;
	scl->codec[0].cfg = 0xcdef;

	scl->codec[1].fi = true;
	scl->codec[1].pt = true;
	scl->codec[1].type = GSM0808_SCT_FR2;

	scl->codec[2].fi = true;
	scl->codec[2].tf = true;
	scl->codec[2].type = GSM0808_SCT_CSD;
	scl->codec[2].cfg = 0xc0;

	scl->len = 3;
}

static void test_create_layer3(void)
{
	static const uint8_t res[] = {
		0x00, 0x0e, 0x57, 0x05, 0x08, 0x00, 0x77, 0x62,
		0x83, 0x33, 0x66, 0x44, 0x88, 0x17, 0x01, 0x23 };
	struct msgb *msg, *in_msg;
	printf("Testing creating Layer3\n");

	in_msg = msgb_alloc_headroom(512, 128, "foo");
	in_msg->l3h = in_msg->data;
	msgb_v_put(in_msg, 0x23);

	msg = gsm0808_create_layer3(in_msg, 0x1122, 0x2244, 0x3366, 0x4488);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
	msgb_free(in_msg);
}

static void test_create_layer3_aoip()
{
	static const uint8_t res[] = {
		0x00, 0x17, 0x57, 0x05, 0x08, 0x00, 0x77, 0x62,
		0x83, 0x33, 0x66, 0x44, 0x88, 0x17, 0x01, 0x23,
		GSM0808_IE_SPEECH_CODEC_LIST, 0x07, GSM0808_SCT_FR3 | 0x50,
		0xcd, 0xef, GSM0808_SCT_FR2 | 0xa0, 0x9f,
		GSM0808_SCT_CSD | 0x90, 0xc0
	};

	struct msgb *msg, *in_msg;
	struct gsm0808_speech_codec_list sc_list;
	printf("Testing creating Layer3 (AoIP)\n");

	setup_codec_list(&sc_list);

	in_msg = msgb_alloc_headroom(512, 128, "foo");
	in_msg->l3h = in_msg->data;
	msgb_v_put(in_msg, 0x23);

	msg =
	    gsm0808_create_layer3_aoip(in_msg, 0x1122, 0x2244, 0x3366, 0x4488,
				       &sc_list);
	VERIFY(msg, res, ARRAY_SIZE(res));

	msgb_free(msg);
	msgb_free(in_msg);
}

static void test_create_reset()
{
	static const uint8_t res[] = { 0x00, 0x04, 0x30, 0x04, 0x01, 0x20 };
	struct msgb *msg;

	printf("Testing creating Reset\n");
	msg = gsm0808_create_reset();
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_reset_ack()
{
	static const uint8_t res[] = { 0x00, 0x01, 0x31 };
	struct msgb *msg;

	printf("Testing creating Reset Ack\n");
	msg = gsm0808_create_reset_ack();
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}


static void test_create_clear_command()
{
	static const uint8_t res[] = { 0x20, 0x04, 0x01, 0x23 };
	struct msgb *msg;

	printf("Testing creating Clear Command\n");
	msg = gsm0808_create_clear_command(0x23);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_clear_complete()
{
	static const uint8_t res[] = { 0x00, 0x01, 0x21 };
	struct msgb *msg;

	printf("Testing creating Clear Complete\n");
	msg = gsm0808_create_clear_complete();
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_cipher()
{
	static const uint8_t res[] =
	    { 0x00, 0x0c, 0x53, 0x0a, 0x09, 0x03, 0xaa,
	      0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x23, 0x42 };
	static const uint8_t res2[] =
	    { 0x00, 0x0e, 0x53, 0x0a, 0x09, 0x03, 0xaa,
	      0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x23, 0x42,
	      GSM0808_IE_CIPHER_RESPONSE_MODE, 0x01 };
	struct msgb *msg;
	struct gsm0808_encrypt_info ei;
	uint8_t include_imeisv;

	memset(&ei, 0, sizeof(ei));
	ei.perm_algo[0] = GSM0808_ALG_ID_A5_0;
	ei.perm_algo[1] = GSM0808_ALG_ID_A5_1;
	ei.perm_algo_len = 2;
	ei.key[0] = 0xaa;
	ei.key[1] = 0xbb;
	ei.key[2] = 0xcc;
	ei.key[3] = 0xdd;
	ei.key[4] = 0xee;
	ei.key[5] = 0xff;
	ei.key[6] = 0x23;
	ei.key[7] = 0x42;
	ei.key_len = 8;
	include_imeisv = 1;

	printf("Testing creating Chipher Mode Command\n");
	msg = gsm0808_create_cipher(&ei, NULL);
	OSMO_ASSERT(msg);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);

	msg = gsm0808_create_cipher(&ei, &include_imeisv);
	OSMO_ASSERT(msg);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);
}

static void test_create_cipher_complete()
{
	static const uint8_t res1[] = {
		0x00, 0x08, 0x55, 0x20, 0x03, 0x23, 0x42, 0x21, 0x2c, 0x04 };
	static const uint8_t res2[] = { 0x00, 0x03, 0x55, 0x2c, 0x04};
	struct msgb *l3, *msg;

	printf("Testing creating Cipher Complete\n");
	l3 = msgb_alloc_headroom(512, 128, "l3h");
	l3->l3h = l3->data;
	msgb_v_put(l3, 0x23);
	msgb_v_put(l3, 0x42);
	msgb_v_put(l3, 0x21);

	/* with l3 data */
	msg = gsm0808_create_cipher_complete(l3, 4);
	VERIFY(msg, res1, ARRAY_SIZE(res1));
	msgb_free(msg);

	/* with l3 data but short */
	l3->len -= 1;
	l3->tail -= 1;
	msg = gsm0808_create_cipher_complete(l3, 4);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);

	/* without l3 data */
	msg = gsm0808_create_cipher_complete(NULL, 4);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);


	msgb_free(l3);
}

static void test_create_cipher_reject()
{
	static const uint8_t res[] = { 0x00, 0x02, 0x59, 0x23 };
	struct msgb *msg;

	printf("Testing creating Cipher Reject\n");
	msg = gsm0808_create_cipher_reject(0x23);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_cm_u()
{
	static const uint8_t res[] = {
		0x00, 0x07, 0x54, 0x12, 0x01, 0x23, 0x13, 0x01, 0x42 };
	static const uint8_t res2o[] = {
		0x00, 0x04, 0x54, 0x12, 0x01, 0x23 };
	struct msgb *msg;
	const uint8_t cm2 = 0x23;
	const uint8_t cm3 = 0x42;

	printf("Testing creating CM U\n");
	msg = gsm0808_create_classmark_update(&cm2, 1, &cm3, 1);
	VERIFY(msg, res, ARRAY_SIZE(res));

	msg = gsm0808_create_classmark_update(&cm2, 1, NULL, 0);
	VERIFY(msg, res2o, ARRAY_SIZE(res2o));

	msgb_free(msg);
}

static void test_create_sapi_reject()
{
	static const uint8_t res[] = { 0x00, 0x03, 0x25, 0x03, 0x25 };
	struct msgb *msg;

	printf("Testing creating SAPI Reject\n");
	msg = gsm0808_create_sapi_reject(3);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_ass()
{
	static const uint8_t res1[] =
	    { 0x00, 0x0a, 0x01, 0x0b, 0x04, 0x01, 0x0b, 0xa1, 0x25, 0x01, 0x00,
	      0x04 };
	static const uint8_t res2[] =
	    { 0x00, 0x20, 0x01, 0x0b, 0x04, 0x01, 0x0b, 0xa1, 0x25, 0x01, 0x00,
	      0x04, GSM0808_IE_AOIP_TRASP_ADDR, 0x06, 0xc0, 0xa8, 0x64, 0x17,
	      0x04, 0xd2, GSM0808_IE_SPEECH_CODEC_LIST, 0x07,
	      GSM0808_SCT_FR3 | 0x50, 0xcd, 0xef, GSM0808_SCT_FR2 | 0xa0, 0x9f,
	      GSM0808_SCT_CSD | 0x90, 0xc0, GSM0808_IE_CALL_ID, 0xaa, 0xbb,
	      0xcc, 0xdd };

	struct msgb *msg;
	struct gsm0808_channel_type ct;
	uint16_t cic = 0004;
	struct sockaddr_storage ss;
	struct sockaddr_in sin;
	struct gsm0808_speech_codec_list sc_list;
	uint32_t call_id = 0xAABBCCDD;

	memset(&ct, 0, sizeof(ct));
	ct.ch_indctr = GSM0808_CHAN_SPEECH;
	ct.ch_rate_type = GSM0808_SPEECH_HALF_PREF;
	ct.perm_spch[0] = GSM0808_PERM_FR3;
	ct.perm_spch[1] = GSM0808_PERM_HR3;
	ct.perm_spch_len = 2;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(1234);
	inet_aton("192.168.100.23", &sin.sin_addr);

	memset(&ss, 0, sizeof(ss));
	memcpy(&ss, &sin, sizeof(sin));

	setup_codec_list(&sc_list);

	printf("Testing creating Assignment Request\n");
	msg = gsm0808_create_ass(&ct, &cic, NULL, NULL, NULL);
	OSMO_ASSERT(msg);
	VERIFY(msg, res1, ARRAY_SIZE(res1));
	msgb_free(msg);

	msg = gsm0808_create_ass(&ct, &cic, &ss, &sc_list, &call_id);
	OSMO_ASSERT(msg);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);
}

static void test_create_ass_compl()
{
	static const uint8_t res1[] = {
		0x00, 0x09, 0x02, 0x15, 0x23, 0x21, 0x42, 0x2c,
		0x11, 0x40, 0x22 };
	static const uint8_t res2[] = {
		0x00, 0x07, 0x02, 0x15, 0x23, 0x21, 0x42, 0x2c, 0x11};
	struct msgb *msg;

	printf("Testing creating Assignment Complete\n");
	msg = gsm0808_create_assignment_completed(0x23, 0x42, 0x11, 0x22);
	VERIFY(msg, res1, ARRAY_SIZE(res1));
	msgb_free(msg);

	msg = gsm0808_create_assignment_completed(0x23, 0x42, 0x11, 0);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);
}

static void test_create_ass_compl_aoip()
{
	struct sockaddr_storage ss;
	struct sockaddr_in sin;
	struct gsm0808_speech_codec sc;
	struct gsm0808_speech_codec_list sc_list;
	static const uint8_t res[] =
	    { 0x00, 0x1d, 0x02, 0x15, 0x23, 0x21, 0x42, 0x2c, 0x11, 0x40, 0x22,
	      GSM0808_IE_AOIP_TRASP_ADDR, 0x06, 0xc0, 0xa8, 0x64, 0x17, 0x04,
	      0xd2, GSM0808_IE_SPEECH_CODEC, 0x01, GSM0808_SCT_HR1 | 0x90,
	      GSM0808_IE_SPEECH_CODEC_LIST, 0x07, GSM0808_SCT_FR3 | 0x50, 0xcd,
	      0xef, GSM0808_SCT_FR2 | 0xa0, 0x9f, GSM0808_SCT_CSD | 0x90, 0xc0 };
	struct msgb *msg;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(1234);
	inet_aton("192.168.100.23", &sin.sin_addr);

	memset(&ss, 0, sizeof(ss));
	memcpy(&ss, &sin, sizeof(sin));

	memset(&sc, 0, sizeof(sc));
	sc.fi = true;
	sc.tf = true;
	sc.type = GSM0808_SCT_HR1;

	setup_codec_list(&sc_list);

	printf("Testing creating Assignment Complete (AoIP)\n");
	msg = gsm0808_create_ass_compl(0x23, 0x42, 0x11, 0x22,
				       &ss, &sc, &sc_list);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_ass_fail()
{
	static const uint8_t res1[] = { 0x00, 0x04, 0x03, 0x04, 0x01, 0x23 };
	static const uint8_t res2[] = {
		0x00, 0x06, 0x03, 0x04, 0x01, 0x23, 0x15, 0x02};
	uint8_t rr_res = 2;
	struct msgb *msg;

	printf("Testing creating Assignment Failure\n");
	msg = gsm0808_create_assignment_failure(0x23, NULL);
	VERIFY(msg, res1, ARRAY_SIZE(res1));
	msgb_free(msg);

	msg = gsm0808_create_assignment_failure(0x23, &rr_res);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);
}

static void test_create_ass_fail_aoip()
{
	static const uint8_t res1[] =
	    { 0x00, 0x0d, 0x03, 0x04, 0x01, 0x23, GSM0808_IE_SPEECH_CODEC_LIST,
	      0x07, GSM0808_SCT_FR3 | 0x50, 0xcd, 0xef, GSM0808_SCT_FR2 | 0xa0,
	      0x9f, GSM0808_SCT_CSD | 0x90, 0xc0 };
	static const uint8_t res2[] =
	    { 0x00, 0x0f, 0x03, 0x04, 0x01, 0x23, 0x15, 0x02,
	      GSM0808_IE_SPEECH_CODEC_LIST, 0x07, GSM0808_SCT_FR3 | 0x50, 0xcd,
	      0xef, GSM0808_SCT_FR2 | 0xa0, 0x9f, GSM0808_SCT_CSD | 0x90, 0xc0 };
	uint8_t rr_res = 2;
	struct msgb *msg;
	struct gsm0808_speech_codec_list sc_list;

	setup_codec_list(&sc_list);

	printf("Testing creating Assignment Failure (AoIP)\n");
	msg = gsm0808_create_ass_fail(0x23, NULL, &sc_list);
	VERIFY(msg, res1, ARRAY_SIZE(res1));
	msgb_free(msg);

	msg = gsm0808_create_ass_fail(0x23, &rr_res, &sc_list);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);
}

static void test_create_clear_rqst()
{
	static const uint8_t res[] = { 0x00, 0x04, 0x22, 0x04, 0x01, 0x23 };
	struct msgb *msg;

	printf("Testing creating Clear Request\n");
	msg = gsm0808_create_clear_rqst(0x23);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_paging()
{
	static const uint8_t res[] =
	    { 0x00, 0x10, 0x52, 0x08, 0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00,
	      0x21, 0x43, 0x1a, 0x03, 0x05, 0x23, 0x42 };
	static const uint8_t res2[] =
	    { 0x00, 0x16, 0x52, 0x08, 0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00,
	      0x21, 0x43, GSM0808_IE_TMSI, 0x04, 0x12, 0x34, 0x56, 0x78, 0x1a,
	      0x03, 0x05, 0x23, 0x42 };
	static const uint8_t res3[] =
	    { 0x00, 0x18, 0x52, 0x08, 0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00,
	      0x21, 0x43, GSM0808_IE_TMSI, 0x04, 0x12, 0x34, 0x56, 0x78, 0x1a,
	      0x03, 0x05, 0x23, 0x42, GSM0808_IE_CHANNEL_NEEDED,
	      RSL_CHANNEED_TCH_ForH };

	struct msgb *msg;
	struct gsm0808_cell_id_list cil;
	uint32_t tmsi = 0x12345678;
	uint8_t chan_needed = RSL_CHANNEED_TCH_ForH;

	char imsi[] = "001010000001234";

	cil.id_discr = CELL_IDENT_LAC;
	cil.id_list_lac[0] = 0x2342;
	cil.id_list_len = 1;

	printf("Testing creating Paging Request\n");
	msg = gsm0808_create_paging(imsi, NULL, &cil, NULL);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);

	msg = gsm0808_create_paging(imsi, &tmsi, &cil, NULL);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);

	msg = gsm0808_create_paging(imsi, &tmsi, &cil, &chan_needed);
	VERIFY(msg, res3, ARRAY_SIZE(res3));
	msgb_free(msg);
}

static void test_create_dtap()
{
	static const uint8_t res[] = { 0x01, 0x03, 0x02, 0x23, 0x42 };
	struct msgb *msg, *l3;

	printf("Testing creating DTAP\n");
	l3 = msgb_alloc_headroom(512, 128, "test");
	l3->l3h = l3->data;
	msgb_v_put(l3, 0x23);
	msgb_v_put(l3, 0x42);

	msg = gsm0808_create_dtap(l3, 0x3);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
	msgb_free(l3);
}

static void test_prepend_dtap()
{
	static const uint8_t res[] = { 0x01, 0x03, 0x02, 0x23, 0x42 };
	struct msgb *in_msg;

	printf("Testing prepend DTAP\n");

	in_msg = msgb_alloc_headroom(512, 128, "test");
	msgb_v_put(in_msg, 0x23);
	msgb_v_put(in_msg, 0x42);

	gsm0808_prepend_dtap_header(in_msg, 0x3);
	in_msg->l3h = in_msg->data;
	VERIFY(in_msg, res, ARRAY_SIZE(res));
	msgb_free(in_msg);
}

static void test_enc_dec_aoip_trasp_addr_v4()
{
	struct sockaddr_storage enc_addr;
	struct sockaddr_storage dec_addr;
	struct sockaddr_in enc_addr_in;
	struct msgb *msg;
	uint8_t rc_enc;
	int rc_dec;

	memset(&enc_addr_in, 0, sizeof(enc_addr_in));
	enc_addr_in.sin_family = AF_INET;
	enc_addr_in.sin_port = htons(1234);
	inet_aton("255.0.255.255", &enc_addr_in.sin_addr);

	memset(&enc_addr, 0, sizeof(enc_addr));
	memcpy(&enc_addr, &enc_addr_in, sizeof(enc_addr_in));

	msg = msgb_alloc(1024, "output buffer");
	rc_enc = gsm0808_enc_aoip_trasp_addr(msg, &enc_addr);
	OSMO_ASSERT(rc_enc == 8);
	rc_dec =
	    gsm0808_dec_aoip_trasp_addr(&dec_addr, msg->data + 2, msg->len - 2);
	OSMO_ASSERT(rc_dec == 6);
	OSMO_ASSERT(memcmp(&enc_addr, &dec_addr, sizeof(enc_addr)) == 0);

	msgb_free(msg);
}

static void test_enc_dec_aoip_trasp_addr_v6()
{
	struct sockaddr_storage enc_addr;
	struct sockaddr_storage dec_addr;
	struct sockaddr_in6 enc_addr_in;
	struct msgb *msg;
	uint8_t rc_enc;
	int rc_dec;

	memset(&enc_addr_in, 0, sizeof(enc_addr_in));
	enc_addr_in.sin6_family = AF_INET6;
	enc_addr_in.sin6_port = htons(4567);
	inet_pton(AF_INET6, "2001:0db8:85a3:08d3:1319:8a2e:0370:7344",
		  &enc_addr_in.sin6_addr);

	memset(&enc_addr, 0, sizeof(enc_addr));
	memcpy(&enc_addr, &enc_addr_in, sizeof(enc_addr_in));

	msg = msgb_alloc(1024, "output buffer");
	rc_enc = gsm0808_enc_aoip_trasp_addr(msg, &enc_addr);
	OSMO_ASSERT(rc_enc == 20);
	rc_dec =
	    gsm0808_dec_aoip_trasp_addr(&dec_addr, msg->data + 2, msg->len - 2);
	OSMO_ASSERT(rc_dec == 18);
	OSMO_ASSERT(memcmp(&enc_addr, &dec_addr, sizeof(enc_addr)) == 0);

	msgb_free(msg);
}

static void test_gsm0808_enc_dec_speech_codec()
{
	struct gsm0808_speech_codec enc_sc;
	struct gsm0808_speech_codec dec_sc;
	struct msgb *msg;
	uint8_t rc_enc;
	int rc_dec;

	memset(&enc_sc, 0, sizeof(enc_sc));
	enc_sc.fi = true;
	enc_sc.pt = true;
	enc_sc.type = GSM0808_SCT_FR2;

	msg = msgb_alloc(1024, "output buffer");
	rc_enc = gsm0808_enc_speech_codec(msg, &enc_sc);
	OSMO_ASSERT(rc_enc == 3);

	rc_dec = gsm0808_dec_speech_codec(&dec_sc, msg->data + 2, msg->len - 2);
	OSMO_ASSERT(rc_dec == 1);

	OSMO_ASSERT(memcmp(&enc_sc, &dec_sc, sizeof(enc_sc)) == 0);

	msgb_free(msg);
}


static void test_gsm0808_enc_dec_speech_codec_with_cfg()
{
	struct gsm0808_speech_codec enc_sc;
	struct gsm0808_speech_codec dec_sc;
	struct msgb *msg;
	uint8_t rc_enc;
	int rc_dec;

	enc_sc.pi = true;
	enc_sc.tf = true;
	enc_sc.type = GSM0808_SCT_FR3;
	enc_sc.cfg = 0xabcd;

	msg = msgb_alloc(1024, "output buffer");
	rc_enc = gsm0808_enc_speech_codec(msg, &enc_sc);
	OSMO_ASSERT(rc_enc == 5);

	rc_dec = gsm0808_dec_speech_codec(&dec_sc, msg->data + 2, msg->len - 2);
	OSMO_ASSERT(rc_dec == 3);

	OSMO_ASSERT(memcmp(&enc_sc, &dec_sc, sizeof(enc_sc)) == 0);

	msgb_free(msg);
}

static void test_gsm0808_enc_dec_speech_codec_ext_with_cfg()
{
	struct gsm0808_speech_codec enc_sc;
	struct gsm0808_speech_codec dec_sc;
	struct msgb *msg;
	uint8_t rc_enc;
	int rc_dec;

	enc_sc.pi = true;
	enc_sc.tf = true;
	enc_sc.type = GSM0808_SCT_CSD;
	enc_sc.cfg = 0xc0;

	msg = msgb_alloc(1024, "output buffer");
	rc_enc = gsm0808_enc_speech_codec(msg, &enc_sc);
	OSMO_ASSERT(rc_enc == 5);

	rc_dec = gsm0808_dec_speech_codec(&dec_sc, msg->data + 2, msg->len - 2);
	OSMO_ASSERT(rc_dec == 3);

	OSMO_ASSERT(memcmp(&enc_sc, &dec_sc, sizeof(enc_sc)) == 0);

	msgb_free(msg);
}

static void test_gsm0808_enc_dec_speech_codec_list()
{
	struct gsm0808_speech_codec_list enc_scl;
	struct gsm0808_speech_codec_list dec_scl;
	struct msgb *msg;
	uint8_t rc_enc;
	int rc_dec;

	memset(&enc_scl, 0, sizeof(enc_scl));

	enc_scl.codec[0].pi = true;
	enc_scl.codec[0].tf = true;
	enc_scl.codec[0].type = GSM0808_SCT_FR3;
	enc_scl.codec[0].cfg = 0xcdef;

	enc_scl.codec[1].fi = true;
	enc_scl.codec[1].pt = true;
	enc_scl.codec[1].type = GSM0808_SCT_FR2;

	enc_scl.codec[2].fi = true;
	enc_scl.codec[2].tf = true;
	enc_scl.codec[2].type = GSM0808_SCT_CSD;
	enc_scl.codec[2].cfg = 0xc0;

	enc_scl.len = 3;

	msg = msgb_alloc(1024, "output buffer");
	rc_enc = gsm0808_enc_speech_codec_list(msg, &enc_scl);
	OSMO_ASSERT(rc_enc == 9);

	rc_dec = gsm0808_dec_speech_codec_list(&dec_scl, msg->data + 2, msg->len - 2);
	OSMO_ASSERT(rc_dec == 7);

	OSMO_ASSERT(memcmp(&enc_scl, &dec_scl, sizeof(enc_scl)) == 0);

	msgb_free(msg);
}

static void test_gsm0808_enc_dec_channel_type()
{
	struct gsm0808_channel_type enc_ct;
	struct gsm0808_channel_type dec_ct;
	struct msgb *msg;
	uint8_t ct_enc_expected[] = { GSM0808_IE_CHANNEL_TYPE,
		0x04, 0x01, 0x0b, 0xa1, 0x25
	};
	uint8_t rc_enc;
	int rc_dec;

	memset(&enc_ct, 0, sizeof(enc_ct));
	enc_ct.ch_indctr = GSM0808_CHAN_SPEECH;
	enc_ct.ch_rate_type = GSM0808_SPEECH_HALF_PREF;
	enc_ct.perm_spch[0] = GSM0808_PERM_FR3;
	enc_ct.perm_spch[1] = GSM0808_PERM_HR3;
	enc_ct.perm_spch_len = 2;

	msg = msgb_alloc(1024, "output buffer");
	rc_enc = gsm0808_enc_channel_type(msg, &enc_ct);
	OSMO_ASSERT(rc_enc == 6);
	OSMO_ASSERT(memcmp(ct_enc_expected, msg->data, msg->len) == 0);

	rc_dec = gsm0808_dec_channel_type(&dec_ct, msg->data + 2, msg->len - 2);
	OSMO_ASSERT(rc_dec == 4);
	OSMO_ASSERT(memcmp(&enc_ct, &dec_ct, sizeof(enc_ct)) == 0);

	msgb_free(msg);
}

static void test_gsm0808_enc_dec_encrypt_info()
{
	struct gsm0808_encrypt_info enc_ei;
	struct gsm0808_encrypt_info dec_ei;
	struct msgb *msg;
	uint8_t ei_enc_expected[] =
	    { GSM0808_IE_ENCRYPTION_INFORMATION, 0x09, 0x03, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff, 0x23, 0x42
	};
	uint8_t rc_enc;
	int rc_dec;

	memset(&enc_ei, 0, sizeof(enc_ei));
	enc_ei.perm_algo[0] = GSM0808_ALG_ID_A5_0;
	enc_ei.perm_algo[1] = GSM0808_ALG_ID_A5_1;
	enc_ei.perm_algo_len = 2;
	enc_ei.key[0] = 0xaa;
	enc_ei.key[1] = 0xbb;
	enc_ei.key[2] = 0xcc;
	enc_ei.key[3] = 0xdd;
	enc_ei.key[4] = 0xee;
	enc_ei.key[5] = 0xff;
	enc_ei.key[6] = 0x23;
	enc_ei.key[7] = 0x42;
	enc_ei.key_len = 8;

	msg = msgb_alloc(1024, "output buffer");
	rc_enc = gsm0808_enc_encrypt_info(msg, &enc_ei);
	OSMO_ASSERT(rc_enc == 11);
	OSMO_ASSERT(memcmp(ei_enc_expected, msg->data, msg->len) == 0);

	rc_dec = gsm0808_dec_encrypt_info(&dec_ei, msg->data + 2, msg->len - 2);
	OSMO_ASSERT(rc_dec == 9);

	OSMO_ASSERT(memcmp(&enc_ei, &dec_ei, sizeof(enc_ei)) == 0);

	msgb_free(msg);
}

static void test_gsm0808_enc_dec_cell_id_list_lac()
{
	struct gsm0808_cell_id_list enc_cil;
	struct gsm0808_cell_id_list dec_cil;
	struct msgb *msg;
	uint8_t rc_enc;
	int rc_dec;

	memset(&enc_cil, 0, sizeof(enc_cil));
	enc_cil.id_discr = CELL_IDENT_LAC;
	enc_cil.id_list_lac[0] = 0x0124;
	enc_cil.id_list_lac[1] = 0xABCD;
	enc_cil.id_list_lac[2] = 0x5678;
	enc_cil.id_list_len = 3;

	msg = msgb_alloc(1024, "output buffer");
	rc_enc = gsm0808_enc_cell_id_list(msg, &enc_cil);
	OSMO_ASSERT(rc_enc == 9);

	rc_dec = gsm0808_dec_cell_id_list(&dec_cil, msg->data + 2,
					  msg->len - 2);
	OSMO_ASSERT(rc_dec == 7);

	OSMO_ASSERT(memcmp(&enc_cil, &dec_cil, sizeof(enc_cil)) == 0);

	msgb_free(msg);
}

static void test_gsm0808_enc_dec_cell_id_list_single_lac()
{
	struct gsm0808_cell_id_list enc_cil;
	struct gsm0808_cell_id_list dec_cil;
	struct msgb *msg;
	uint8_t cil_enc_expected[] = { GSM0808_IE_CELL_IDENTIFIER_LIST, 0x03,
		0x05, 0x23, 0x42
	};
	uint8_t rc_enc;
	int rc_dec;

	memset(&enc_cil, 0, sizeof(enc_cil));
	enc_cil.id_discr = CELL_IDENT_LAC;
	enc_cil.id_list_lac[0] = 0x2342;
	enc_cil.id_list_len = 1;

	msg = msgb_alloc(1024, "output buffer");
	rc_enc = gsm0808_enc_cell_id_list(msg, &enc_cil);
	OSMO_ASSERT(rc_enc == 5);
	OSMO_ASSERT(memcmp(cil_enc_expected, msg->data, msg->len) == 0);

	rc_dec = gsm0808_dec_cell_id_list(&dec_cil, msg->data + 2,
					  msg->len - 2);
	OSMO_ASSERT(rc_dec == 3);

	OSMO_ASSERT(memcmp(&enc_cil, &dec_cil, sizeof(enc_cil)) == 0);

	msgb_free(msg);
}

static void test_gsm0808_enc_dec_cell_id_list_bss()
{
	struct gsm0808_cell_id_list enc_cil;
	struct gsm0808_cell_id_list dec_cil;
	struct msgb *msg;
	uint8_t rc_enc;
	int rc_dec;

	memset(&enc_cil, 0, sizeof(enc_cil));
	enc_cil.id_discr = CELL_IDENT_LAC;

	msg = msgb_alloc(1024, "output buffer");
	rc_enc = gsm0808_enc_cell_id_list(msg, &enc_cil);
	OSMO_ASSERT(rc_enc == 3);

	rc_dec = gsm0808_dec_cell_id_list(&dec_cil, msg->data + 2,
					  msg->len - 2);
	OSMO_ASSERT(rc_dec == 1);

	OSMO_ASSERT(memcmp(&enc_cil, &dec_cil, sizeof(enc_cil)) == 0);

	msgb_free(msg);
}

int main(int argc, char **argv)
{
	printf("Testing generation of GSM0808 messages\n");
	test_create_layer3();
	test_create_layer3_aoip();
	test_create_reset();
	test_create_reset_ack();
	test_create_clear_command();
	test_create_clear_complete();
	test_create_cipher();
	test_create_cipher_complete();
	test_create_cipher_reject();
	test_create_cm_u();
	test_create_sapi_reject();
	test_create_ass();
	test_create_ass_compl();
	test_create_ass_compl_aoip();
	test_create_ass_fail();
	test_create_ass_fail_aoip();
	test_create_clear_rqst();
	test_create_paging();
	test_create_dtap();
	test_prepend_dtap();
	test_enc_dec_aoip_trasp_addr_v4();
	test_enc_dec_aoip_trasp_addr_v6();
	test_gsm0808_enc_dec_speech_codec();
	test_gsm0808_enc_dec_speech_codec_ext_with_cfg();
	test_gsm0808_enc_dec_speech_codec_with_cfg();
	test_gsm0808_enc_dec_speech_codec_list();
	test_gsm0808_enc_dec_channel_type();
	test_gsm0808_enc_dec_encrypt_info();
	test_gsm0808_enc_dec_cell_id_list_lac();
	test_gsm0808_enc_dec_cell_id_list_single_lac();
	test_gsm0808_enc_dec_cell_id_list_bss();

	printf("Done\n");
	return EXIT_SUCCESS;
}
