#include <stdio.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/gad.h>

void test_gad_lat_lon_dec_enc_stability(void)
{
	uint32_t lat_enc;
	uint32_t lon_enc;
	printf("--- %s\n", __func__);
	for (lat_enc = 0x0; lat_enc <= 0xffffff; lat_enc++) {
		int32_t lat_dec = osmo_gad_dec_lat(lat_enc);
		uint32_t enc2 = osmo_gad_enc_lat(lat_dec);
		uint32_t want_enc = lat_enc;
		/* "-0" == 0, because the highest bit is defined as a sign bit. */
		if (lat_enc == 0x800000)
			want_enc = 0;
		if (enc2 != want_enc) {
			printf("ERR: lat=%u --> %d --> %u\n", lat_enc, lat_dec, enc2);
			printf("%d -> %u\n", lat_dec + 1, osmo_gad_enc_lat(lat_dec + 1));
			OSMO_ASSERT(false);
		}
	}
	printf("osmo_gad_dec_lat() -> osmo_gad_enc_lat() of %u values successful\n", lat_enc);
	for (lon_enc = 0; lon_enc <= 0xffffff; lon_enc++) {
		int32_t lon_dec = osmo_gad_dec_lon(lon_enc);
		uint32_t enc2 = osmo_gad_enc_lon(lon_dec);
		uint32_t want_enc = lon_enc;
		if (enc2 != want_enc) {
			printf("ERR: lon=%u 0x%x --> %d --> %u\n", lon_enc, lon_enc, lon_dec, enc2);
			printf("%d -> %u\n", lon_dec + 1, osmo_gad_enc_lon(lon_dec + 1));
			printf("%d -> %u\n", lon_dec - 1, osmo_gad_enc_lon(lon_dec - 1));
			OSMO_ASSERT(false);
		}
	}
	printf("osmo_gad_dec_lon() -> osmo_gad_enc_lon() of %u values successful\n", lon_enc);
}

struct osmo_gad gad_test_values[] = {
	{
		.type = GAD_TYPE_ELL_POINT_UNC_CIRCLE,
		.ell_point_unc_circle = {
			/* Values rounded to the nearest encodable value, for test result matching */
			.lat = 23000006,
			.lon = 42000002,
			.unc = 442592,
		},
	},
};

void test_gad_enc_dec(void)
{
	int i;
	printf("--- %s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(gad_test_values); i++) {
		struct osmo_gad *t = &gad_test_values[i];
		struct msgb *msg = msgb_alloc(1024, __func__);
		union gad_raw raw_write;
		union gad_raw raw_read;
		struct osmo_gad dec_pdu;
		int rc;
		struct osmo_gad_err *err;
		void *loop_ctx = msg;
		rc = osmo_gad_enc(&raw_write, t);
		if (rc <= 0) {
			printf("[%d] %s: ERROR: osmo_gad_enc() failed\n", i, osmo_gad_type_name(t->type));
			goto loop_end;
		}
		rc = osmo_gad_raw_write(msg, &raw_write);
		if (rc <= 0) {
			printf("[%d] %s: ERROR: osmo_gad_raw_write() failed\n", i, osmo_gad_type_name(t->type));
			goto loop_end;
		}
		if (rc != msg->len) {
			printf("[%d] %s: ERROR: osmo_gad_raw_write() returned length %d but msgb has %d bytes\n",
			       i, osmo_gad_type_name(t->type),
			       rc, msg->len);
			goto loop_end;
		}

		memset(&raw_read, 0xff, sizeof(raw_read));
		rc = osmo_gad_raw_read(&raw_read, &err, loop_ctx, msg->data, msg->len);
		if (rc) {
			printf("[%d] ERROR: osmo_gad_raw_read() failed: %s\n", i, err->logmsg);
			printf("    encoded data: %s\n", osmo_hexdump(msg->data, msg->len));
			goto loop_end;
		}

		memset(&dec_pdu, 0xff, sizeof(dec_pdu));
		rc = osmo_gad_dec(&dec_pdu, &err, loop_ctx, &raw_read);
		if (rc) {
			printf("[%d] ERROR: failed to decode pdu: %s\n", i, err->logmsg);
			printf("    encoded data: %s\n", osmo_hexdump(msg->data, msg->len));
			goto loop_end;
		}

		if (memcmp(t, &dec_pdu, sizeof(dec_pdu))) {
			char strbuf[128];
			printf("[%d] %s: ERROR: decoded PDU != encoded PDU\n", i,
			       osmo_gad_type_name(t->type));
			osmo_gad_to_str_buf(strbuf, sizeof(strbuf), t);
			printf("     original struct: %s\n", strbuf);
			osmo_gad_to_str_buf(strbuf, sizeof(strbuf), &dec_pdu);
			printf("      decoded struct: %s\n", strbuf);
			goto loop_end;
		}

		printf("[%d] %s: ok\n", i, osmo_gad_type_name(t->type));
		printf("    encoded data: %s\n", msgb_hexdump(msg));

loop_end:
		msgb_free(msg);
	}
}

void test_gad_to_str(void)
{
	int i;
	printf("--- %s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(gad_test_values); i++) {
		struct osmo_gad *t = &gad_test_values[i];
		char buf[1024];
		int rc;
		rc = osmo_gad_to_str_buf(buf, sizeof(buf), t);

		printf("[%d] ", i);
		if (rc <= 0)
			printf("%s: ERROR: osmo_gad_to_str_buf() failed\n", osmo_gad_type_name(t->type));
		else
			printf("%s\n", buf);
	}
}

int main(int argc, char **argv)
{
	test_gad_lat_lon_dec_enc_stability();
	test_gad_enc_dec();
	test_gad_to_str();
	return 0;
}
