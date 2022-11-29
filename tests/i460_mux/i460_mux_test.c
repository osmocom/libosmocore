
#include <osmocom/core/utils.h>

#include <osmocom/isdn/i460_mux.h>

static void bits_cb(struct osmo_i460_subchan *schan, void *user_data,
		    const ubit_t *bits, unsigned int num_bits)
{
	char *str = user_data;
	printf("demux_bits_cb '%s': %s\n", str, osmo_ubit_dump(bits, num_bits));
}


const struct osmo_i460_schan_desc scd64 = {
	.rate = OSMO_I460_RATE_64k,
	.bit_offset = 0,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "64k",
	},
};

const struct osmo_i460_schan_desc scd32_0 = {
	.rate = OSMO_I460_RATE_32k,
	.bit_offset = 0,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "32k_0",
	},
};
const struct osmo_i460_schan_desc scd32_4 = {
	.rate = OSMO_I460_RATE_32k,
	.bit_offset = 4,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "32k_4",
	},
};

const struct osmo_i460_schan_desc scd16_0 = {
	.rate = OSMO_I460_RATE_16k,
	.bit_offset = 0,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "16k_0",
	},
};
const struct osmo_i460_schan_desc scd16_2 = {
	.rate = OSMO_I460_RATE_16k,
	.bit_offset = 2,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "16k_2",
	},
};
const struct osmo_i460_schan_desc scd16_4 = {
	.rate = OSMO_I460_RATE_16k,
	.bit_offset = 4,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "16k_4",
	},
};
const struct osmo_i460_schan_desc scd16_6 = {
	.rate = OSMO_I460_RATE_16k,
	.bit_offset = 6,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "16k_6",
	},
};

const struct osmo_i460_schan_desc scd8_0 = {
	.rate = OSMO_I460_RATE_8k,
	.bit_offset = 0,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "8k_0",
	},
};
const struct osmo_i460_schan_desc scd8_1 = {
	.rate = OSMO_I460_RATE_8k,
	.bit_offset = 1,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "8k_1",
	},
};
const struct osmo_i460_schan_desc scd8_2 = {
	.rate = OSMO_I460_RATE_8k,
	.bit_offset = 2,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "8k_2",
	},
};
const struct osmo_i460_schan_desc scd8_3 = {
	.rate = OSMO_I460_RATE_8k,
	.bit_offset = 3,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "8k_3",
	},
};
const struct osmo_i460_schan_desc scd8_4 = {
	.rate = OSMO_I460_RATE_8k,
	.bit_offset = 4,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "8k_4",
	},
};
const struct osmo_i460_schan_desc scd8_5 = {
	.rate = OSMO_I460_RATE_8k,
	.bit_offset = 5,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "8k_5",
	},
};
const struct osmo_i460_schan_desc scd8_6 = {
	.rate = OSMO_I460_RATE_8k,
	.bit_offset = 6,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "8k_6",
	},
};
const struct osmo_i460_schan_desc scd8_7 = {
	.rate = OSMO_I460_RATE_8k,
	.bit_offset = 7,
	.demux = {
		.num_bits = 40,
		.out_cb_bits = bits_cb,
		.out_cb_bytes = NULL,
		.user_data = "8k_7",
	},
};

static void test_no_subchan(void)
{
	struct osmo_i460_timeslot _ts, *ts = &_ts;

	/* Initialization */
	printf("\n==> %s\n", __func__);
	osmo_i460_ts_init(ts);

	/* feed in some data; expect nothing to happen */
	const uint8_t nothing[128] = { 0, };
	osmo_i460_demux_in(ts, nothing, sizeof(nothing));

	/* pull bytes out of mux (should be all 0xff) */
	uint8_t buf[128];
	osmo_i460_mux_out(ts, buf, sizeof(buf));
	printf("out: %s\n", osmo_hexdump(buf, sizeof(buf)));
}

static struct msgb *gen_alternating_bitmsg(unsigned int num_bits)
{
	struct msgb *msg = msgb_alloc(num_bits, "mux-in");
	int i;
	for (i = 0; i < num_bits; i++)
		msgb_put_u8(msg, i & 1);
	return msg;
}

static void test_64k_subchan(void)
{
	struct osmo_i460_timeslot _ts, *ts = &_ts;

	/* Initialization */
	printf("\n==> %s\n", __func__);
	osmo_i460_ts_init(ts);
	osmo_i460_subchan_add(NULL, ts, &scd64);

	/* demux */
	uint8_t sequence[128];
	int i;
	for (i = 0; i < sizeof(sequence); i++)
		sequence[i] = i;
	osmo_i460_demux_in(ts, sequence, sizeof(sequence));

	/* mux */
	struct msgb *msg = gen_alternating_bitmsg(128);
	osmo_i460_mux_enqueue(&ts->schan[0], msg);

	uint8_t buf[16];
	osmo_i460_mux_out(ts, buf, sizeof(buf));
	printf("mux_out: %s\n", osmo_hexdump(buf, sizeof(buf)));

	osmo_i460_subchan_del(&ts->schan[0]);
}

static void test_32k_subchan(void)
{
	struct osmo_i460_timeslot _ts, *ts = &_ts;

	/* Initialization */
	printf("\n==> %s\n", __func__);
	osmo_i460_ts_init(ts);
	osmo_i460_subchan_add(NULL, ts, &scd32_0);
	osmo_i460_subchan_add(NULL, ts, &scd32_4);

	/* demux */
	uint8_t sequence[10];
	int i;
	for (i = 0; i < sizeof(sequence); i++)
		sequence[i] = 0;
	sequence[1] = 0xf0;
	sequence[0] = 0x0f;
	sequence[2] = 0xff;
	osmo_i460_demux_in(ts, sequence, sizeof(sequence));

	/* mux */

	/* test with only a single channel active */
	for (i = 0; i < 2; i++) {
		struct msgb *msg = gen_alternating_bitmsg(128);
		osmo_i460_mux_enqueue(&ts->schan[i], msg);
		printf("%s-single-%u\n", __func__, i);

		uint8_t buf[16];
		int j;
		for (j = 0; j < 3; j++) {
			osmo_i460_mux_out(ts, buf, sizeof(buf));
			printf("mux_out: %s\n", osmo_hexdump(buf, sizeof(buf)));
		}
	}

	for (i = 0; i < 4; i++)
		osmo_i460_subchan_del(&ts->schan[i]);
}



static void test_16k_subchan(void)
{
	struct osmo_i460_timeslot _ts, *ts = &_ts;

	/* Initialization */
	printf("\n==> %s\n", __func__);
	osmo_i460_ts_init(ts);
	osmo_i460_subchan_add(NULL, ts, &scd16_0);
	osmo_i460_subchan_add(NULL, ts, &scd16_2);
	osmo_i460_subchan_add(NULL, ts, &scd16_4);
	osmo_i460_subchan_add(NULL, ts, &scd16_6);

	/* demux */
	uint8_t sequence[20];
	int i;
	for (i = 0; i < sizeof(sequence); i++)
		sequence[i] = 0;
	sequence[0] = 0xC0;
	sequence[1] = 0x30;
	sequence[2] = 0x0c;
	sequence[3] = 0x03;
	sequence[4] = 0xff;
	osmo_i460_demux_in(ts, sequence, sizeof(sequence));

	/* mux */

	/* test with only a single channel active */
	for (i = 0; i < 4; i++) {
		struct msgb *msg = gen_alternating_bitmsg(128);
		osmo_i460_mux_enqueue(&ts->schan[i], msg);
		printf("%s-single-%u\n", __func__, i);

		uint8_t buf[16];
		int j;
		for (j = 0; j < 5; j++) {
			osmo_i460_mux_out(ts, buf, sizeof(buf));
			printf("mux_out: %s\n", osmo_hexdump(buf, sizeof(buf)));
		}
	}

	for (i = 0; i < 4; i++)
		osmo_i460_subchan_del(&ts->schan[i]);
}


static void test_8k_subchan(void)
{
	struct osmo_i460_timeslot _ts, *ts = &_ts;

	/* Initialization */
	printf("\n==> %s\n", __func__);
	osmo_i460_ts_init(ts);
	osmo_i460_subchan_add(NULL, ts, &scd8_0);
	osmo_i460_subchan_add(NULL, ts, &scd8_1);
	osmo_i460_subchan_add(NULL, ts, &scd8_2);
	osmo_i460_subchan_add(NULL, ts, &scd8_3);
	osmo_i460_subchan_add(NULL, ts, &scd8_4);
	osmo_i460_subchan_add(NULL, ts, &scd8_5);
	osmo_i460_subchan_add(NULL, ts, &scd8_6);
	osmo_i460_subchan_add(NULL, ts, &scd8_7);

	/* demux */
	uint8_t sequence[40];
	int i;
	for (i = 0; i < sizeof(sequence); i++)
		sequence[i] = 0;
	i = 0;
	sequence[i++] = 0x80;
	sequence[i++] = 0x40;
	sequence[i++] = 0x20;
	sequence[i++] = 0x10;
	sequence[i++] = 0xf0;
	sequence[i++] = 0x08;
	sequence[i++] = 0x04;
	sequence[i++] = 0x02;
	sequence[i++] = 0x01;
	sequence[i++] = 0x0f;
	sequence[i++] = 0xff;
	osmo_i460_demux_in(ts, sequence, sizeof(sequence));

	/* mux */

	/* test with only a single channel active */
	for (i = 0; i < 8; i++) {
		struct msgb *msg = gen_alternating_bitmsg(64);
		osmo_i460_mux_enqueue(&ts->schan[i], msg);
		printf("%s-single-%u\n", __func__, i);

		uint8_t buf[16];
		int j;
		for (j = 0; j < 5; j++) {
			osmo_i460_mux_out(ts, buf, sizeof(buf));
			printf("mux_out: %s\n", osmo_hexdump(buf, sizeof(buf)));
		}
	}

	for (i = 0; i < 8; i++)
		osmo_i460_subchan_del(&ts->schan[i]);
}

/* activate only one sub-channel; expect unused bits to be '1' */
static void test_unused_subchan(void)
{
	struct osmo_i460_timeslot _ts, *ts = &_ts;

	/* Initialization */
	printf("\n==> %s\n", __func__);
	osmo_i460_ts_init(ts);
	osmo_i460_subchan_add(NULL, ts, &scd16_0);

	/* mux */
	struct msgb *msg = gen_alternating_bitmsg(128);
	memset(msgb_data(msg), 0, msgb_length(msg));
	osmo_i460_mux_enqueue(&ts->schan[0], msg);
	printf("%s-single\n", __func__);

	uint8_t buf[16];
	int j;
	for (j = 0; j < 5; j++) {
		osmo_i460_mux_out(ts, buf, sizeof(buf));
		printf("mux_out: %s\n", osmo_hexdump(buf, sizeof(buf)));
	}

	osmo_i460_subchan_del(&ts->schan[0]);
}

int main(int argc, char **argv)
{
	test_no_subchan();
	test_64k_subchan();
	test_32k_subchan();
	test_16k_subchan();
	test_8k_subchan();
	test_unused_subchan();
	return 0;
}
