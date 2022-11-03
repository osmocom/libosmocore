#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm0808.h>

static void check_tlv_parse(uint8_t **data, size_t *data_len,
			    uint8_t exp_tag, size_t exp_len, const uint8_t *exp_val)
{
	uint8_t *value;
	size_t value_len;
	uint8_t tag;
	int rc;
	uint8_t *saved_data = *data;
	size_t saved_data_len = *data_len;

	rc = osmo_match_shift_tlv(data, data_len, exp_tag ^ 1, NULL, NULL);
	OSMO_ASSERT(rc == 0);

	rc = osmo_match_shift_tlv(data, data_len, exp_tag, &value, &value_len);
	OSMO_ASSERT(rc == (int)value_len + 2);
	OSMO_ASSERT(value_len == exp_len);
	OSMO_ASSERT(memcmp(value, exp_val, exp_len) == 0);

	/* restore data/data_len */
	*data = saved_data;
	*data_len = saved_data_len;

	rc = osmo_shift_tlv(data, data_len, &tag, &value, &value_len);
	OSMO_ASSERT(rc == (int)value_len + 2);
	OSMO_ASSERT(tag == exp_tag);
	OSMO_ASSERT(value_len == exp_len);
	OSMO_ASSERT(memcmp(value, exp_val, exp_len) == 0);
}

static void check_tv_fixed_match(uint8_t **data, size_t *data_len,
				 uint8_t tag, size_t len, const uint8_t *exp_val)
{
	uint8_t *value;
	int rc;

	rc = osmo_match_shift_tv_fixed(data, data_len, tag ^ 1, len, NULL);
	OSMO_ASSERT(rc == 0);

	rc = osmo_match_shift_tv_fixed(data, data_len, tag, len, &value);
	OSMO_ASSERT(rc == (int)len + 1);
	OSMO_ASSERT(memcmp(value, exp_val, len) == 0);
}

static void check_v_fixed_shift(uint8_t **data, size_t *data_len,
				size_t len, const uint8_t *exp_val)
{
	uint8_t *value;
	int rc;

	rc = osmo_shift_v_fixed(data, data_len, len, &value);
	OSMO_ASSERT(rc == (int)len);
	OSMO_ASSERT(memcmp(value, exp_val, len) == 0);
}

static void check_lv_shift(uint8_t **data, size_t *data_len,
			   size_t exp_len, const uint8_t *exp_val)
{
	uint8_t *value;
	size_t value_len;
	int rc;

	rc = osmo_shift_lv(data, data_len, &value, &value_len);
	OSMO_ASSERT(rc == (int)value_len + 1);
	OSMO_ASSERT(value_len == exp_len);
	OSMO_ASSERT(memcmp(value, exp_val, exp_len) == 0);
}

static void check_tlv_match_data_len(size_t data_len, uint8_t tag, size_t len,
				     const uint8_t *test_data)
{
	uint8_t buf[301] = {0};
	*buf = 0xfe;

	uint8_t *unchanged_ptr = buf;
	size_t unchanged_len = 0xdead;
	size_t tmp_data_len = data_len;
	uint8_t *value = unchanged_ptr;
	size_t value_len = unchanged_len;
	uint8_t *data = buf + 1;

	OSMO_ASSERT(data_len <= sizeof(buf) - 1);

	tlv_put(data, tag, len, test_data);
	if (data_len < len + 2) {
		OSMO_ASSERT(-1 == osmo_match_shift_tlv(&data, &tmp_data_len,
					    tag, &value, &value_len));
		OSMO_ASSERT(tmp_data_len == 0);
		OSMO_ASSERT(data == buf + 1 + data_len);
		OSMO_ASSERT(value == unchanged_ptr);
		OSMO_ASSERT(value_len == unchanged_len);
	} else {
		OSMO_ASSERT(0 <= osmo_match_shift_tlv(&data, &tmp_data_len,
					   tag, &value, &value_len));
		OSMO_ASSERT(value != unchanged_ptr);
		OSMO_ASSERT(value_len != unchanged_len);
	}
}

static void check_tv_fixed_match_data_len(size_t data_len,
					  uint8_t tag, size_t len,
					  const uint8_t *test_data)
{
	uint8_t buf[301] = {0};
	*buf = 0xfe;

	uint8_t *unchanged_ptr = buf;
	size_t tmp_data_len = data_len;
	uint8_t *value = unchanged_ptr;
	uint8_t *data = buf + 1;

	OSMO_ASSERT(data_len <= sizeof(buf) - 1);

	tv_fixed_put(data, tag, len, test_data);

	if (data_len < len + 1) {
		OSMO_ASSERT(-1 == osmo_match_shift_tv_fixed(&data, &tmp_data_len,
						 tag, len, &value));
		OSMO_ASSERT(tmp_data_len == 0);
		OSMO_ASSERT(data == buf + 1 + data_len);
		OSMO_ASSERT(value == unchanged_ptr);
	} else {
		OSMO_ASSERT(0 <= osmo_match_shift_tv_fixed(&data, &tmp_data_len,
						tag, len, &value));
		OSMO_ASSERT(value != unchanged_ptr);
	}
}

static void check_v_fixed_shift_data_len(size_t data_len,
					 size_t len, const uint8_t *test_data)
{
	uint8_t buf[301] = {0};
	*buf = 0xfe;

	uint8_t *unchanged_ptr = buf;
	size_t tmp_data_len = data_len;
	uint8_t *value = unchanged_ptr;
	uint8_t *data = buf + 1;

	OSMO_ASSERT(data_len <= sizeof(buf) - 1);

	memcpy(data, test_data, len);

	if (data_len < len) {
		OSMO_ASSERT(-1 == osmo_shift_v_fixed(&data, &tmp_data_len,
						len, &value));
		OSMO_ASSERT(tmp_data_len == 0);
		OSMO_ASSERT(data == buf + 1 + data_len);
		OSMO_ASSERT(value == unchanged_ptr);
	} else {
		OSMO_ASSERT(0 <= osmo_shift_v_fixed(&data, &tmp_data_len,
					       len, &value));
		OSMO_ASSERT(value != unchanged_ptr);
	}
}

static void check_lv_shift_data_len(size_t data_len,
				    size_t len, const uint8_t *test_data)
{
	uint8_t buf[301] = {0};
	*buf = 0xfe;

	uint8_t *unchanged_ptr = buf;
	size_t unchanged_len = 0xdead;
	size_t tmp_data_len = data_len;
	uint8_t *value = unchanged_ptr;
	size_t value_len = unchanged_len;
	uint8_t *data = buf + 1;

	OSMO_ASSERT(data_len <= sizeof(buf) - 1);

	lv_put(data, len, test_data);
	if (data_len < len + 1) {
		OSMO_ASSERT(-1 == osmo_shift_lv(&data, &tmp_data_len,
					   &value, &value_len));
		OSMO_ASSERT(tmp_data_len == 0);
		OSMO_ASSERT(data == buf + 1 + data_len);
		OSMO_ASSERT(value == unchanged_ptr);
		OSMO_ASSERT(value_len == unchanged_len);
	} else {
		OSMO_ASSERT(0 <= osmo_shift_lv(&data, &tmp_data_len,
					  &value, &value_len));
		OSMO_ASSERT(value != unchanged_ptr);
		OSMO_ASSERT(value_len != unchanged_len);
	}
}

static void test_tlv_shift_functions(void)
{
	uint8_t test_data[1024];
	uint8_t buf[1024];
	uint8_t *data_end;
	unsigned i, len;
	uint8_t *data;
	size_t data_len;
	const uint8_t tag = 0x1a;

	printf("Test shift functions\n");

	for (i = 0; i < ARRAY_SIZE(test_data); i++)
		test_data[i] = (uint8_t)i;

	for (len = 0; len < 256; len++) {
		const unsigned iterations = sizeof(buf) / (len + 2) / 4;

		memset(buf, 0xee, sizeof(buf));
		data_end = data = buf;

		for (i = 0; i < iterations; i++) {
			data_end = tlv_put(data_end, tag, len, test_data);
			data_end = tv_fixed_put(data_end, tag, len, test_data);
			/* v_fixed_put */
			memcpy(data_end, test_data, len);
			data_end += len;
			data_end = lv_put(data_end, len, test_data);
		}

		data_len = data_end - data;
		OSMO_ASSERT(data_len <= sizeof(buf));

		for (i = 0; i < iterations; i++) {
			check_tlv_parse(&data, &data_len, tag, len, test_data);
			check_tv_fixed_match(&data, &data_len, tag, len, test_data);
			check_v_fixed_shift(&data, &data_len, len, test_data);
			check_lv_shift(&data, &data_len, len, test_data);
		}

		OSMO_ASSERT(data == data_end);

		/* Test at end of data */

		OSMO_ASSERT(-1 == osmo_match_shift_tlv(&data, &data_len, tag, NULL, NULL));
		OSMO_ASSERT(-1 == osmo_match_shift_tv_fixed(&data, &data_len, tag, len, NULL));
		OSMO_ASSERT((len ? -1 : 0) == osmo_shift_v_fixed(&data, &data_len, len, NULL));
		OSMO_ASSERT(-1 == osmo_shift_lv(&data, &data_len, NULL, NULL));

		/* Test invalid data_len */
		for (data_len = 0; data_len <= len + 2 + 1; data_len += 1) {
			check_tlv_match_data_len(data_len, tag, len, test_data);
			check_tv_fixed_match_data_len(data_len, tag, len, test_data);
			check_v_fixed_shift_data_len(data_len, len, test_data);
			check_lv_shift_data_len(data_len, len, test_data);
		}
	}
}

/* Most GSM related protocols clearly indicate that in case of duplicate
 * IEs, only the first occurrence shall be used, while any further occurrences
 * shall be ignored.  See e.g. 3GPP TS 24.008 Section 8.6.3 */
static void test_tlv_repeated_ie(void)
{
	uint8_t test_data[768];
	int i, rc;
	const uint8_t tag = 0x1a;
	struct tlv_parsed dec;
	struct tlv_parsed dec3[3];
	struct tlv_definition def;

	memset(&def, 0, sizeof(def));

	/* tag:1:255, tag:1:254, tag:1:253, ..., tag:1:3, tag:1:2, tag:1:1, tag:1:0 */
	for (i = 0; i < ARRAY_SIZE(test_data) - 1; i += 3) {
		test_data[i] = tag;
		test_data[i + 1] = 1;
		test_data[i + 2] = (uint8_t)(0xff - i/2);
	}

	def.def[tag].type = TLV_TYPE_TLV;

	rc = tlv_parse(&dec, &def, &test_data[1], sizeof(test_data) - 1, tag, 0);
	OSMO_ASSERT(rc == i/3);
	OSMO_ASSERT(dec.lv[tag].len == 1);
	/* Value pointer should point at first value in test data array. */
	OSMO_ASSERT(dec.lv[tag].val == &test_data[2]);
	OSMO_ASSERT(*dec.lv[tag].val == test_data[2]);

	/* Accept three decodings, pointing at first, second and third val */
	rc = tlv_parse2(dec3, 3, &def, &test_data[1], sizeof(test_data) - 1, tag, 0);
	OSMO_ASSERT(rc == i/3);
	OSMO_ASSERT(dec3[0].lv[tag].len == 1);
	OSMO_ASSERT(dec3[0].lv[tag].val == &test_data[2]);
	OSMO_ASSERT(dec3[1].lv[tag].len == 1);
	OSMO_ASSERT(dec3[1].lv[tag].val == &test_data[2 + 3]);
	OSMO_ASSERT(dec3[2].lv[tag].len == 1);
	OSMO_ASSERT(dec3[2].lv[tag].val == &test_data[2 + 3 + 3]);
}

static void test_tlv_encoder(void)
{
	const uint8_t enc_ies[] = {
		0x17, 0x14,	0x06, 0x2b, 0x12, 0x2b, 0x0b, 0x40, 0x2b, 0xb7, 0x05, 0xd0, 0x63, 0x82, 0x95, 0x03, 0x05, 0x40,
				0x07, 0x08, 0x43, 0x90,
		0x2c,		0x04,
		0x40,		0x42,
	};
	const uint8_t ie_order[] = { 0x2c, 0x40, 0x17 };
	const uint8_t enc_ies_reordered[] = {
		0x2c,		0x04,
		0x40,		0x42,
		0x17, 0x14,	0x06, 0x2b, 0x12, 0x2b, 0x0b, 0x40, 0x2b, 0xb7, 0x05, 0xd0, 0x63, 0x82, 0x95, 0x03, 0x05, 0x40,
				0x07, 0x08, 0x43, 0x90,
	};
	struct tlv_parsed tp;
	struct msgb *msg = msgb_alloc(1024, __func__);
	int rc;

	printf("Testing TLV encoder by decoding + re-encoding binary\n");

	OSMO_ASSERT(msg);

	/* decode BSSAP IEs specified above */
	rc = osmo_bssap_tlv_parse(&tp, enc_ies, ARRAY_SIZE(enc_ies));
	OSMO_ASSERT(rc == 3);

	/* re-encode it */
	rc = tlv_encode(msg, gsm0808_att_tlvdef(), &tp);
	OSMO_ASSERT(rc == ARRAY_SIZE(enc_ies));
	OSMO_ASSERT(!memcmp(msgb_data(msg), enc_ies, ARRAY_SIZE(enc_ies)));

	msgb_reset(msg);

	printf("Testing TLV encoder with IE ordering\n");

	/* re-encodei in different order */
	rc = tlv_encode_ordered(msg, gsm0808_att_tlvdef(), &tp, ie_order, ARRAY_SIZE(ie_order));
	OSMO_ASSERT(rc == ARRAY_SIZE(enc_ies));
	OSMO_ASSERT(!memcmp(msgb_data(msg), enc_ies_reordered, ARRAY_SIZE(enc_ies_reordered)));

	msgb_free(msg);
}

static void test_tlv_parser_bounds(void)
{
	struct tlv_definition tdef;
	struct tlv_parsed dec;
	uint8_t buf[32];

	memset(&tdef, 0, sizeof(tdef));

	printf("Testing TLV_TYPE_T decoder for out-of-bounds\n");
	tdef.def[0x23].type = TLV_TYPE_T;
	buf[0] = 0x23;
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 1, 0, 0) == 1);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 0, 0, 0) == 0);

	printf("Testing TLV_TYPE_TV decoder for out-of-bounds\n");
	tdef.def[0x23].type = TLV_TYPE_TV;
	buf[0] = 0x23;
	buf[1] = 0x42;
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 2, 0, 0) == 1);
	OSMO_ASSERT(*TLVP_VAL(&dec, 0x23) == buf[1]);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 1, 0, 0) == OSMO_TLVP_ERR_OFS_LEN_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);

	printf("Testing TLV_TYPE_FIXED decoder for out-of-bounds\n");
	tdef.def[0x23].type = TLV_TYPE_FIXED;
	tdef.def[0x23].fixed_len = 2;
	buf[0] = 0x23;
	buf[1] = 0x42;
	buf[2] = 0x55;
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 3, 0, 0) == 1);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 2, 0, 0) == OSMO_TLVP_ERR_OFS_LEN_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);

	printf("Testing TLV_TYPE_TLV decoder for out-of-bounds\n");
	tdef.def[0x23].type = TLV_TYPE_TLV;
	buf[0] = 0x23;
	buf[1] = 0x02;
	buf[2] = 0x55;
	buf[3] = 0xAA;
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 4, 0, 0) == 1);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == &buf[2]);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 3, 0, 0) == OSMO_TLVP_ERR_OFS_LEN_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 2, 0, 0) == OSMO_TLVP_ERR_OFS_LEN_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 1, 0, 0) == OSMO_TLVP_ERR_OFS_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);

	printf("Testing TLV_TYPE_vTvLV_GAN decoder for out-of-bounds\n");
	tdef.def[0x23].type = TLV_TYPE_vTvLV_GAN;
	buf[0] = 0x23;
	buf[1] = 0x80;
	buf[2] = 0x01;
	buf[3] = 0xAA;
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 4, 0, 0) == 1);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == &buf[3]);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 3, 0, 0) == OSMO_TLVP_ERR_OFS_LEN_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 2, 0, 0) == OSMO_TLVP_ERR_OFS_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 1, 0, 0) == OSMO_TLVP_ERR_OFS_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);

	printf("Testing TLV_TYPE_TvLV decoder for out-of-bounds\n");
	tdef.def[0x23].type = TLV_TYPE_TvLV;
	buf[0] = 0x23;
	buf[1] = 0x81;
	buf[2] = 0xAA;
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 3, 0, 0) == 1);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == &buf[2]);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 2, 0, 0) == OSMO_TLVP_ERR_OFS_LEN_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 1, 0, 0) == OSMO_TLVP_ERR_OFS_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);

	printf("Testing TLV_TYPE_TL16V decoder for out-of-bounds\n");
	tdef.def[0x23].type = TLV_TYPE_TL16V;
	buf[0] = 0x23;
	buf[1] = 0x00;
	buf[2] = 0x01;
	buf[3] = 0xAA;
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 4, 0, 0) == 1);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == &buf[3]);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 3, 0, 0) == OSMO_TLVP_ERR_OFS_LEN_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 2, 0, 0) == OSMO_TLVP_ERR_OFS_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);
	OSMO_ASSERT(tlv_parse(&dec, &tdef, buf, 1, 0, 0) == OSMO_TLVP_ERR_OFS_BEYOND_BUFFER);
	OSMO_ASSERT(TLVP_VAL(&dec, 0x23) == NULL);
}

static void test_tlv_lens(void)
{
	uint16_t buf_len;
	uint8_t buf[512];
	uint8_t val[512] = { 0 };
	uint16_t x;


	for (x = 0; x < 16; x++) {
		buf_len  = lv_put(buf, x, val) - buf;
		OSMO_ASSERT(buf_len == LV_GROSS_LEN(x));
		buf_len = tlv_put(buf, 0x23, x, val) - buf;
		OSMO_ASSERT(buf_len == TLV_GROSS_LEN(x));
		buf_len = tlv16_put(buf, 0x23, x, (uint16_t *) val) - buf;
		OSMO_ASSERT(buf_len == TLV16_GROSS_LEN(x));
		buf_len = tl16v_put(buf, 0x23, x, val) - buf;
		OSMO_ASSERT(buf_len == TL16V_GROSS_LEN(x));
		buf_len = t16lv_put(buf, 0x2342, x, val) - buf;
		OSMO_ASSERT(buf_len == T16LV_GROSS_LEN(x));
		buf_len = tvlv_put(buf, 0x23, x, val) - buf;
		OSMO_ASSERT(buf_len == TVLV_GROSS_LEN(x));
	}

	for (x = 250; x < 300; x++) {
		buf_len = tl16v_put(buf, 0x23, x, val) - buf;
		OSMO_ASSERT(buf_len == TL16V_GROSS_LEN(x));
		buf_len = tvlv_put(buf, 0x23, x, val) - buf;
		OSMO_ASSERT(buf_len == TVLV_GROSS_LEN(x));
	}
}

int main(int argc, char **argv)
{
	//osmo_init_logging2(ctx, &info);

	test_tlv_shift_functions();
	test_tlv_repeated_ie();
	test_tlv_encoder();
	test_tlv_parser_bounds();
	test_tlv_lens();

	printf("Done.\n");
	return EXIT_SUCCESS;
}
