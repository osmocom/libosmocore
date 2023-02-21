
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include <osmocom/crypt/auth.h>
#include <osmocom/core/utils.h>

static void dump_auth_vec(struct osmo_auth_vector *vec)
{
	printf("RAND:\t%s\n", osmo_hexdump(vec->rand, sizeof(vec->rand)));

	if (vec->auth_types & OSMO_AUTH_TYPE_UMTS) {
		printf("AUTN:\t%s\n", osmo_hexdump(vec->autn, sizeof(vec->autn)));
		printf("IK:\t%s\n", osmo_hexdump(vec->ik, sizeof(vec->ik)));
		printf("CK:\t%s\n", osmo_hexdump(vec->ck, sizeof(vec->ck)));
		printf("RES:\t%s\n", osmo_hexdump(vec->res, vec->res_len));
	}

	if (vec->auth_types & OSMO_AUTH_TYPE_GSM) {
		printf("SRES:\t%s\n", osmo_hexdump(vec->sres, sizeof(vec->sres)));
		/* According to 3GPP TS 55.205 Sec. 4 the GSM-MILENAGE output is limited to 64 bits.
		   According to 3GPP TS 33.102 Annex. B5 in UMTS security context Kc can be 128 bits.
		   Here we test the former, so make sure we only print interesting Kc bits. */
		printf("Kc:\t%s\n", osmo_hexdump(vec->kc, OSMO_A5_MAX_KEY_LEN_BYTES/2));
	}
}

static struct osmo_sub_auth_data test_aud = {
	.type = OSMO_AUTH_TYPE_GSM,
	.algo = OSMO_AUTH_ALG_XOR_2G,
	.u.gsm = {
		.ki =  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
	},
};

int main(int argc, char **argv)
{
	struct osmo_auth_vector _vec;
	struct osmo_auth_vector *vec = &_vec;
	uint8_t _rand[16];
	int rc;

#if 0
	srand(time(NULL));
	*(uint32_t *)&_rand[0] = rand();
	*(uint32_t *)(&_rand[4]) = rand();
	*(uint32_t *)(&_rand[8]) = rand();
	*(uint32_t *)(&_rand[12]) = rand();
#else
	memset(_rand, 0, sizeof(_rand));
#endif
	memset(vec, 0, sizeof(*vec));

	rc = osmo_auth_gen_vec(vec, &test_aud, _rand);
	if (rc < 0) {
		fprintf(stderr, "error generating auth vector\n");
		exit(1);
	}
	dump_auth_vec(vec);

	/* test once more with non-zero RAND to see it show in result */
	for (int i = 0; i < sizeof(_rand); i++)
		_rand[i] = i << 4;

	rc = osmo_auth_gen_vec(vec, &test_aud, _rand);
	if (rc < 0) {
		fprintf(stderr, "error generating auth vector\n");
		exit(1);
	}
	dump_auth_vec(vec);

	exit(0);
}
