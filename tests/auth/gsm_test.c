#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <osmocom/crypt/auth.h>
#include <osmocom/core/utils.h>


static const uint8_t test_ki[16] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};
static const uint8_t test_rand[16] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};

static struct {
	enum osmo_auth_algo algo;
	const uint8_t sres[4];
	const uint8_t kc[8];
} test_results[] = {
	{ OSMO_AUTH_ALG_COMP128v1,
		{ 0x53, 0x51, 0x3e, 0xbd },
		{ 0x13, 0xc2, 0x6b, 0x8f, 0x82, 0xab, 0x74, 0x00 },
	},
	{ OSMO_AUTH_ALG_COMP128v2,
		{ 0x28, 0xe3, 0xcf, 0xa4 },
		{ 0x8f, 0x0f, 0xf5, 0x68, 0x53, 0x3a, 0x54, 0x00 },
	},
	{ OSMO_AUTH_ALG_COMP128v3,
		{ 0x28, 0xe3, 0xcf, 0xa4 },
		{ 0x8f, 0x0f, 0xf5, 0x68, 0x53, 0x3a, 0x57, 0xb9 },
	},
	{ OSMO_AUTH_ALG_XOR,
		{ 0x01, 0x32, 0x67, 0x54 },
		{ 0xcd, 0xfe, 0xab, 0x98, 0x76, 0x45, 0x10, 0x23 },
	},
	{ OSMO_AUTH_ALG_NONE }	/* Sentinel */
};


int main(int argc, char **argv)
{
	struct osmo_auth_vector _vec, *vec = &_vec;
	struct osmo_sub_auth_data _aud, *aud = &_aud;
	int i, fail;

	for (i=0; test_results[i].algo != OSMO_AUTH_ALG_NONE; i++)
	{
		if (!osmo_auth_supported(test_results[i].algo)) {
			printf("UNSUPPORTED ALGO: %d\n", test_results[i].algo);
			continue;
		}

		memset(aud, 0, sizeof(*aud));
		memset(vec, 0, sizeof(*vec));

		aud->type = OSMO_AUTH_TYPE_GSM;
		aud->algo = test_results[i].algo;
		memcpy(aud->u.gsm.ki, test_ki, 16);

		osmo_auth_gen_vec(vec, aud, test_rand);

		fail = 0;
		fail |= memcmp(test_results[i].sres, vec->sres, 4);
		fail |= memcmp(test_results[i].kc,   vec->kc,   8);

		printf("%s: %s\n", osmo_auth_alg_name(aud->algo), fail ? "FAIL" : "PASS");

		if (fail) {
			printf("SRES ref : %s\n", osmo_hexdump(test_results[i].sres, 4));
			printf("     got : %s\n", osmo_hexdump(vec->sres, 4));
			printf("Kc   ref : %s\n", osmo_hexdump(test_results[i].kc, 8));
			printf("     got : %s\n", osmo_hexdump(vec->kc, 8));
		}
	}

	return 0;
}
