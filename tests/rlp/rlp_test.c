#include <osmocom/core/utils.h>
#include <osmocom/gsm/rlp.h>

struct rlp_testcase {
	const char *name;
	const char *encoded_hex;
	struct osmo_rlp_frame_decoded decoded;
};


const struct rlp_testcase testcases[] = {
	{
		.name = "XID1",
		.encoded_hex = "f95f1100213d313d414e6108510600000000000000000000000000c13c6b",
		.decoded = {
			.version = 0,
			.ftype = OSMO_RLP_FT_U,
			.u_ftype = OSMO_RLP_U_FT_XID,
			.s_ftype = 0,
			.c_r = 1,
			.p_f = 1,
			.s_bits = 0,
			.n_s = 0,
			.n_r = 0,
			.fcs = 0x6b3cc1,
			.info = { 0x11, 0x00, 0x21, 0x3d, 0x31, 0x3d, 0x41, 0x4e, 0x61, 0x08,
				  0x51, 0x06, },
			.info_len = 25,
		},
	}, {
		.name = "XID2",
		.encoded_hex = "f95f1101213d313d41305106610774000008060000000000000000ba14a0",
		.decoded = {
			.version = 0,
			.ftype = OSMO_RLP_FT_U,
			.u_ftype = OSMO_RLP_U_FT_XID,
			.s_ftype = 0,
			.c_r = 1,
			.p_f = 1,
			.s_bits = 0,
			.n_s = 0,
			.n_r = 0,
			.fcs = 0xa014ba,
			.info = { 0x11, 0x01, 0x21, 0x3d, 0x31, 0x3d, 0x41, 0x30, 0x51, 0x06,
				  0x61, 0x07, 0x74, 0x00, 0x00, 0x08, 0x06, },
			.info_len = 25,
		},
	}, {
		.name = "SABM",
		.encoded_hex = "f91f0000000000000000000000000000000000000000000000000063b2f3",
		.decoded = {
			.version = 0,
			.ftype = OSMO_RLP_FT_U,
			.u_ftype = OSMO_RLP_U_FT_SABM,
			.s_ftype = 0,
			.c_r = 1,
			.p_f = 1,
			.s_bits = 0,
			.n_s = 0,
			.n_r = 0,
			.fcs = 0xf3b263,
			.info = {},
			.info_len = 0,
		},
	}, {
		.name = "UA",
		.encoded_hex = "f8330000000000000000000000000000000000000000000000000029d801",
		.decoded = {
			.version = 0,
			.ftype = OSMO_RLP_FT_U,
			.u_ftype = OSMO_RLP_U_FT_UA,
			.s_ftype = 0,
			.c_r = 0,
			.p_f = 1,
			.s_bits = 0,
			.n_s = 0,
			.n_r = 0,
			.fcs = 0x01d829,
			.info = {},
			.info_len = 0,
		},
	}, {
		.name = "IS1",
		.encoded_hex = "01001f000000000000000000000000000000000000000000000000f174ad",
		.decoded = {
			.version = 0,
			.ftype = OSMO_RLP_FT_IS,
			.u_ftype = 0,
			.s_ftype = 0,
			.c_r = 1,
			.p_f = 0,
			.s_bits = 0,
			.n_s = 0,
			.n_r = 0,
			.fcs = 0xad74f1,
			.info = { 0x1f, },
			.info_len = 25,
		},
	}, {
		.name = "IS2",
		.encoded_hex = "010401661fffffffffffffffffffffffffffffffffffffffffffff388cd3",
		.decoded = {
			.version = 0,
			.ftype = OSMO_RLP_FT_IS,
			.u_ftype = 0,
			.s_ftype = 0,
			.c_r = 1,
			.p_f = 0,
			.s_bits = 0,
			.n_s = 0,
			.n_r = 1,
			.fcs = 0xd38c38,
			.info = { 0x01, 0x66, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				  0xff, 0xff, 0xff, 0xff, 0xff },
			.info_len = 25,
		},
	}, {
		.name = "DISC",
		.encoded_hex = "f923000000000000000000000000000000000000000000000000007986f2",
		.decoded = {
			.version = 0,
			.ftype = OSMO_RLP_FT_U,
			.u_ftype = OSMO_RLP_U_FT_DISC,
			.s_ftype = 0,
			.c_r = 1,
			.p_f = 1,
			.s_bits = 0,
			.n_s = 0,
			.n_r = 0,
			.fcs = 0xf28679,
			.info = { },
			.info_len = 0,
		},
	}
};

static void rlp_frame_print_u(const struct osmo_rlp_frame_decoded *rf)
{
	OSMO_ASSERT(rf->ftype == OSMO_RLP_FT_U);
	printf("C/R=%u P/F=%u  U %s (FCS=0x%06x) %s\n", rf->c_r, rf->p_f,
		get_value_string(osmo_rlp_ftype_u_vals, rf->u_ftype),
		rf->fcs,
		rf->u_ftype == OSMO_RLP_U_FT_XID ? osmo_hexdump_nospc(rf->info, rf->info_len) : "");
}

static void rlp_frame_print_s(const struct osmo_rlp_frame_decoded *rf)
{
	OSMO_ASSERT(rf->ftype == OSMO_RLP_FT_S);
	printf("C/R=%u P/F=%u  S N(R)=%u %s (FCS=0x%06x)\n", rf->c_r, rf->p_f,
		rf->n_r, get_value_string(osmo_rlp_ftype_s_vals, rf->s_ftype),
		rf->fcs);
}

static void rlp_frame_print_is(const struct osmo_rlp_frame_decoded *rf)
{
	OSMO_ASSERT(rf->ftype == OSMO_RLP_FT_IS);
	printf("C/R=%u P/F=%u IS N(R)=%u N(S)=%u %s (FCS=0x%06x) %s\n", rf->c_r, rf->p_f,
		rf->n_r, rf->n_s, get_value_string(osmo_rlp_ftype_s_vals, rf->s_ftype),
		rf->fcs, osmo_hexdump_nospc(rf->info, rf->info_len));
}

static void rlp_frame_print(const struct osmo_rlp_frame_decoded *rf)
{
	switch (rf->ftype) {
	case OSMO_RLP_FT_U:
		rlp_frame_print_u(rf);
		break;
	case OSMO_RLP_FT_S:
		rlp_frame_print_s(rf);
		break;
	case OSMO_RLP_FT_IS:
		rlp_frame_print_is(rf);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void execute_rlp_test(const struct rlp_testcase *tc)
{
	struct osmo_rlp_frame_decoded decoded;
	uint8_t inbuf[240/8];
	int rc;

	printf("=== STARTING TESTCASE '%s'\n", tc->name);

	rc = osmo_hexparse(tc->encoded_hex, inbuf, sizeof(inbuf));
	OSMO_ASSERT(rc == 240/8);

	printf("Decoding %s:\n", tc->encoded_hex);
	rc = osmo_rlp_decode(&decoded, 0, inbuf, rc);
	OSMO_ASSERT(rc == 0);

	printf("Comparing...\n");
	rlp_frame_print(&decoded);
	if (memcmp(&decoded, &tc->decoded, sizeof(decoded))) {
		printf("DOESN'T MATCH EXPECTED DECODE:\n");
		rlp_frame_print(&tc->decoded);
	}

	printf("Reencoding...\n");
	uint8_t reencoded[240/8];
	rc = osmo_rlp_encode(reencoded, sizeof(reencoded), &tc->decoded);
	OSMO_ASSERT(rc == 240/8);
	if (memcmp(inbuf, reencoded, sizeof(inbuf)))
		printf("DOESN'T MATCH EXPECTED ENCODE FROM ABOVE\n");
}

int main(int argc, char **argv)
{
	for (unsigned int i = 0; i < ARRAY_SIZE(testcases); i++) {
		const struct rlp_testcase *tc = &testcases[i];
		execute_rlp_test(tc);
	}

}
