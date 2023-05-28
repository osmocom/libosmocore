
#include <stdint.h>
#include <osmocom/core/utils.h>
#include "gsm/tuak/tuak.h"

/* user-friendly test specification, uses hex-strings for all parameters for
 * copy+pasting from the spec. */
struct tuak_testspec {
	const char *name;
	struct {
		const char *k;
		const char *rand;
		const char *sqn;
		const char *amf;
		const char *top;
		unsigned int keccak_iterations;
	} in;
	struct {
		const char *topc;
		const char *f1;
		const char *f1star;
		const char *f2;
		const char *f3;
		const char *f4;
		const char *f5;
		const char *f5star;
	} out;
};

static const struct tuak_testspec testspecs[] = {
	{
		.name = "TS 35.233 Section 6.3 Test Set 1",
		.in = {
			.k = "abababababababababababababababab",
			.rand = "42424242424242424242424242424242",
			.sqn = "111111111111",
			.amf = "ffff",
			.top = "5555555555555555555555555555555555555555555555555555555555555555",
			.keccak_iterations = 1,
		},
		.out = {
			.topc = "bd04d9530e87513c5d837ac2ad954623a8e2330c115305a73eb45d1f40cccbff",
			.f1 = "f9a54e6aeaa8618d",
			.f1star = "e94b4dc6c7297df3",
			.f2 = "657acd64",
			.f3 = "d71a1e5c6caffe986a26f783e5c78be1",
			.f4 = "be849fa2564f869aecee6f62d4337e72",
			.f5 = "719f1e9b9054",
			.f5star = "e7af6b3d0e38",
		},
	}, {
		.name = "TS 35.233 Section 6.4 Test Set 2",
		.in = {
			.k = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
			.rand = "0123456789abcdef0123456789abcdef",
			.sqn = "0123456789ab",
			.amf = "abcd",
			.top = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
			.keccak_iterations = 1,
		},
		.out = {
			.topc = "305425427e18c503c8a4b294ea72c95d0c36c6c6b29d0c65de5974d5977f8524",
			.f1 = "c0b8c2d4148ec7aa5f1d78a97e4d1d58",
			.f1star = "ef81af7290f7842c6ceafa537fa0745b",
			.f2 = "e9d749dc4eea0035",
			.f3 = "a4cb6f6529ab17f8337f27baa8234d47",
			.f4 = "2274155ccf4199d5e2abcbf621907f90",
			.f5 = "480a9345cc1e",
			.f5star = "f84eb338848c",
		},
	}, {
		.name = "TS 35.233 Section 6.5 Test Set 3",
		.in = {
			.k = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
			.rand = "0123456789abcdef0123456789abcdef",
			.sqn = "0123456789ab",
			.amf = "abcd",
			.top = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
			.keccak_iterations = 1,
		},
		.out = {
			.topc = "305425427e18c503c8a4b294ea72c95d0c36c6c6b29d0c65de5974d5977f8524",
			.f1 = "d97b75a1776065271b1e212bc3b1bf173f438b21e6c64a55a96c372e085e5cc5",
			.f1star = "427bbf07c6e3a86c54f8c5216499f3909a6fd4a164c9fe235b1550258111b821",
			.f2 = "07021c73e7635c7d",
			.f3 = "4d59ac796834eb85d11fa148a5058c3c",
			.f4 = "126d47500136fdc5ddfd14f19ebf16749ce4b6435323fbb5715a3a796a6082bd",
			.f5 = "1d6622c4e59a",
			.f5star = "f84eb338848c",
		},
	}, {
		.name = "TS 35.233 Section 6.6 Test Set 4",
		.in = {
			.k = "b8da837a50652d6ac7c97da14f6acc61",
			.rand = "6887e55425a966bd86c9661a5fa72be8",
			.sqn = "0dea2ee2c5af",
			.amf = "df1e",
			.top = "0952be13556c32ebc58195d9dd930493e12a9003669988ffde5fa1f0fe35cc01",
			.keccak_iterations = 1,
		},
		.out = {
			.topc = "2bc16eb657a68e1f446f08f57c0efb1d493527a2e652ce281eb6ca0e4487760a",
			.f1 = "749214087958dd8f58bfcdf869d8ae3f",
			.f1star = "619e865afe80e382aee13063f9dfb56d",
			.f2 = "4041ce438e3e38e8aa96562eed83ac43",
			.f3 = "3e3bc01bea0cd914c4c2c83ce2d92757",
			.f4 = "666a8e6f577b1aa77b7fd53cebb8a3d6",
			.f5 = "1f880d005119",
			.f5star = "45e617d77fe5",
		},
	}, {
		.name = "TS 35.233 Section 6.7 Test Set 5",
		.in = {
			.k = "1574ca56881d05c189c82880f789c9cd4244955f4426aa2b69c29f15770e5aa5",
			.rand = "c570aac68cde651fb1e3088322498bef",
			.sqn = "c89bb71f3a41",
			.amf = "297d",
			.top = "e59f6eb10ea406813f4991b0b9e02f181edf4c7e17b480f66d34da35ee88c95e",
			.keccak_iterations = 1,
		},
		.out = {
			.topc = "3c6052e41532a28a47aa3cbb89f223e8f3aaa976aecd48bc3e7d6165a55eff62",
			.f1 = "d7340dad02b4cb01",
			.f1star = "c6021e2e66accb15",
			.f2 = "84d89b41db1867ffd4c7ba1d82163f4d526a20fbae5418fbb526940b1eeb905c",
			.f3 = "d419676afe5ab58c1d8bee0d43523a4d2f52ef0b31a4676a0c334427a988fe65",
			.f4 = "205533e505661b61d05cc0eac87818f4",
			.f5 = "d7b3d2d4980a",
			.f5star = "ca9655264986",
		},
	}, {
		.name = "TS 35.233 Section 6.8 Test Set 6",
		.in = {
			.k = "1574ca56881d05c189c82880f789c9cd4244955f4426aa2b69c29f15770e5aa5",
			.rand = "c570aac68cde651fb1e3088322498bef",
			.sqn = "c89bb71f3a41",
			.amf = "297d",
			.top = "e59f6eb10ea406813f4991b0b9e02f181edf4c7e17b480f66d34da35ee88c95e",
			.keccak_iterations = 2,
		},
		.out = {
			.topc = "b04a66f26c62fcd6c82de22a179ab65506ecf47f56245cd149966cfa9cec7a51",
			.f1 = "90d2289ed1ca1c3dbc2247bb480d431ac71d2e4a7677f6e997cfddb0cbad88b7",
			.f1star = "427355dbac30e825063aba61b556e87583abac638e3ab01c4c884ad9d458dc2f",
			.f2 = "d67e6e64590d22eecba7324afa4af4460c93f01b24506d6e12047d789a94c867",
			.f3 = "ede57edfc57cdffe1aae75066a1b7479bbc3837438e88d37a801cccc9f972b89",
			.f4 = "48ed9299126e5057402fe01f9201cf25249f9c5c0ed2afcf084755daff1d3999",
			.f5 = "6aae8d18c448",
			.f5star = "8c5f33b61f4e",
		},
	},
};


struct tuak_testset {
	const char *name;
	struct {
		uint8_t k[32];
		uint8_t k_len_bytes;
		uint8_t rand[16];
		uint8_t sqn[6];
		uint8_t amf[2];
		uint8_t top[32];
		unsigned int keccak_iterations;
	} in;
	struct {
		uint8_t topc[32];
		uint8_t mac_a[32];
		uint8_t mac_s[32];
		uint8_t mac_len_bytes;

		uint8_t res[32];
		uint8_t res_len_bytes;

		uint8_t ck[32];
		uint8_t ck_len_bytes;
		uint8_t ik[32];
		uint8_t ik_len_bytes;
		uint8_t ak[6];
		uint8_t f5star[6];
	} out;
};

static void expect_equal(const char *name, const uint8_t *actual, const uint8_t *expected, size_t len)
{
	if (!memcmp(actual, expected, len)) {
		printf("\t%s: %s\r\n", name, osmo_hexdump_nospc(actual, len));
	} else {
		char buf[len*2+1];
		printf("\t%s: %s != %s\r\n", name, osmo_hexdump_nospc(actual, len),
			osmo_hexdump_buf(buf, sizeof(buf), expected, len, "", true));
	}
}

static void execute_testset(const struct tuak_testset *tset)
{
	uint8_t topc[32];

	printf("==> %s\n", tset->name);

	tuak_set_keccak_iterations(tset->in.keccak_iterations);
	tuak_opc_gen(topc, tset->in.k, tset->in.k_len_bytes, tset->in.top);
	expect_equal("TOPc", topc, tset->out.topc, sizeof(topc));

	if (tset->out.mac_len_bytes) {
		uint8_t mac_a[32];
		uint8_t mac_s[32];

		tuak_f1(topc, tset->in.k, tset->in.k_len_bytes, tset->in.rand, tset->in.sqn, tset->in.amf,
			mac_a, tset->out.mac_len_bytes, tset->in.keccak_iterations);
		expect_equal("MAC_A", mac_a, tset->out.mac_a, tset->out.mac_len_bytes);

		tuak_f1star(topc, tset->in.k, tset->in.k_len_bytes, tset->in.rand, tset->in.sqn, tset->in.amf,
			    mac_s, tset->out.mac_len_bytes, tset->in.keccak_iterations);
		expect_equal("MAC_S", mac_s, tset->out.mac_s, tset->out.mac_len_bytes);
	}

	if (tset->out.ck_len_bytes || tset->out.ik_len_bytes || tset->out.res_len_bytes) {
		uint8_t res[32];
		uint8_t ck[32];
		uint8_t ik[32];
		uint8_t ak[6];

		tuak_f2345(topc, tset->in.k, tset->in.k_len_bytes, tset->in.rand,
			   tset->out.res_len_bytes ? res : NULL, tset->out.res_len_bytes,
			   tset->out.ck_len_bytes ? ck : NULL, tset->out.ck_len_bytes,
			   tset->out.ik_len_bytes ? ik : NULL, tset->out.ik_len_bytes,
			   ak, tset->in.keccak_iterations);

		if (tset->out.res_len_bytes)
			expect_equal("RES", res, tset->out.res, tset->out.res_len_bytes);

		if (tset->out.ck_len_bytes)
			expect_equal("CK", ck, tset->out.ck, tset->out.ck_len_bytes);

		if (tset->out.ik_len_bytes)
			expect_equal("IK", ik, tset->out.ik, tset->out.ik_len_bytes);

		expect_equal("AK", ak, tset->out.ak, 6);
	}
}

/* convert string-testspec to binary-testset and execute it */
static void execute_testspec(const struct tuak_testspec *tcase)
{
	struct tuak_testset _tset, *tset = &_tset;

	tset->name = tcase->name;
	tset->in.keccak_iterations = tcase->in.keccak_iterations;

	osmo_hexparse(tcase->in.k, tset->in.k, sizeof(tset->in.k));
	tset->in.k_len_bytes = strlen(tcase->in.k)/2;
	OSMO_ASSERT(tset->in.k_len_bytes == 16 || tset->in.k_len_bytes == 32);

	osmo_hexparse(tcase->in.rand, tset->in.rand, sizeof(tset->in.rand));
	OSMO_ASSERT(strlen(tcase->in.rand)/2 == 16);

	osmo_hexparse(tcase->in.sqn, tset->in.sqn, sizeof(tset->in.sqn));
	OSMO_ASSERT(strlen(tcase->in.sqn)/2 == 6);

	osmo_hexparse(tcase->in.amf, tset->in.amf, sizeof(tset->in.amf));
	OSMO_ASSERT(strlen(tcase->in.amf)/2 == 2);

	osmo_hexparse(tcase->in.top, tset->in.top, sizeof(tset->in.top));
	OSMO_ASSERT(strlen(tcase->in.top)/2 == 32);

	osmo_hexparse(tcase->out.topc, tset->out.topc, sizeof(tset->out.topc));
	OSMO_ASSERT(strlen(tcase->out.topc)/2 == 32);

	osmo_hexparse(tcase->out.f1, tset->out.mac_a, sizeof(tset->out.mac_a));
	osmo_hexparse(tcase->out.f1star, tset->out.mac_s, sizeof(tset->out.mac_s));
	OSMO_ASSERT(strlen(tcase->out.f1) == strlen(tcase->out.f1star));
	tset->out.mac_len_bytes = strlen(tcase->out.f1)/2;
	OSMO_ASSERT(tset->out.mac_len_bytes == 8 || tset->out.mac_len_bytes == 16 ||
		    tset->out.mac_len_bytes == 32);

	osmo_hexparse(tcase->out.f2, tset->out.res, sizeof(tset->out.res));
	tset->out.res_len_bytes = strlen(tcase->out.f2)/2;
	OSMO_ASSERT(tset->out.res_len_bytes == 4 || tset->out.res_len_bytes == 8 ||
		    tset->out.res_len_bytes == 16 || tset->out.res_len_bytes == 32);

	osmo_hexparse(tcase->out.f3, tset->out.ck, sizeof(tset->out.ck));
	tset->out.ck_len_bytes = strlen(tcase->out.f3)/2;
	OSMO_ASSERT(tset->out.ck_len_bytes == 16 || tset->out.ck_len_bytes == 32);

	osmo_hexparse(tcase->out.f4, tset->out.ik, sizeof(tset->out.ik));
	tset->out.ik_len_bytes = strlen(tcase->out.f4)/2;
	OSMO_ASSERT(tset->out.ik_len_bytes == 16 || tset->out.ik_len_bytes == 32);

	osmo_hexparse(tcase->out.f5, tset->out.ak, sizeof(tset->out.ak));
	OSMO_ASSERT(strlen(tcase->out.f5)/2 == 6);

	osmo_hexparse(tcase->out.f5star, tset->out.f5star, sizeof(tset->out.f5star));
	OSMO_ASSERT(strlen(tcase->out.f5star)/2 == 6);

	execute_testset(tset);
}

int main(int argc, char **argv)
{
#if 0
	for (unsigned int i = 0; i < ARRAY_SIZE(testsets); i++)
		execute_testset(&testsets[i]);
#endif

	for (unsigned int i = 0; i < ARRAY_SIZE(testspecs); i++)
		execute_testspec(&testspecs[i]);

}
