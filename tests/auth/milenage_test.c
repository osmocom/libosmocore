
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include <osmocom/crypt/auth.h>
#include <osmocom/core/utils.h>

int milenage_opc_gen(uint8_t *opc, const uint8_t *k, const uint8_t *op);

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
	.type = OSMO_AUTH_TYPE_UMTS,
	.algo = OSMO_AUTH_ALG_MILENAGE,
	.u.umts = {
		.opc = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
		.k =   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
		.amf = { 0x00, 0x00 },
		.sqn = 0x21,
		.ind_bitlen = 0,
		.ind = 0,
	},
};

static int opc_test(const struct osmo_sub_auth_data *aud)
{
	int rc;
	uint8_t opc[16];
#if 0
	const uint8_t op[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
#else
	const uint8_t op[16] = { 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0 };
#endif

	printf("MILENAGE supported: %d\n",
	       osmo_auth_supported(osmo_auth_alg_parse("MILENAGE")));

	rc = milenage_opc_gen(opc, aud->u.umts.k, op);

	printf("OP:\t%s\n", osmo_hexdump(op, sizeof(op)));
	printf("OPC:\t%s\n", osmo_hexdump(opc, sizeof(opc)));
	return rc;
}

#define RECALC_AUTS 0
#if RECALC_AUTS
typedef uint8_t u8;
extern int milenage_f2345(const u8 *opc, const u8 *k, const u8 *_rand,
			  u8 *res, u8 *ck, u8 *ik, u8 *ak, u8 *akstar);
extern int milenage_f1(const u8 *opc, const u8 *k, const u8 *_rand,
		       const u8 *sqn, const u8 *amf, u8 *mac_a, u8 *mac_s);
#endif

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

	/* ind_bitlen == 0 uses the legacy mode of incrementing SQN by 1.
	 * sqn == 0x21 == 33, so the SQN used to generate the vector is
	 * sqn + 1 == 34. */
	rc = osmo_auth_gen_vec(vec, &test_aud, _rand);
	if (rc < 0) {
		fprintf(stderr, "error generating auth vector\n");
		exit(1);
	}

	dump_auth_vec(vec);

	/* The USIM generates an AUTS to tell us it is at SQN == 31:
	 *
	 * SQN_MS = 00000000001f
	 *
	 * AUTS = Conc(SQN_MS) || MAC-S
	 * Conc(SQN_MS) = SQN_MS ⊕ f5*[K](RAND)
	 * MAC-S = f1*[K] (SQN MS || RAND || AMF)
	 *
	 *    K = 000102030405060708090a0b0c0d0e0f
	 * RAND = 00000000000000000000000000000000
	 *
	 * f5*--> Conc(SQN_MS) = SQN_MS ^ f5*(K,RAND)
	 *                     = 00000000001f ^ 8711a0ec9e09
	 *                     = 8711a0ec9e16
	 * AMF = 0000 (TS 33.102 v7.0.0, 6.3.3)
	 * MAC-S = f1*[K] (SQN MS || RAND || AMF)
	 *       = f1*[K] (00000000001f || 00000000000000000000000000000000 || 0000)
	 *       = 37df17f80b384ee4
	 *
	 * AUTS = 8711a0ec9e16 || 37df17f80b384ee4
	 */
#if RECALC_AUTS
	uint8_t ak[6];
	uint8_t akstar[6];
	uint8_t opc[16];
	uint8_t k[16];
	uint8_t rand[16];
	osmo_hexparse("000102030405060708090a0b0c0d0e0f", k, sizeof(k));
	osmo_hexparse("000102030405060708090a0b0c0d0e0f", opc, sizeof(opc));
	osmo_hexparse("00000000000000000000000000000000", rand, sizeof(rand));
	milenage_f2345(opc, k, rand, NULL, NULL, NULL, ak, akstar);
	printf("ak = %s\n", osmo_hexdump_nospc(ak, sizeof(ak)));
	printf("akstar = %s\n", osmo_hexdump_nospc(akstar, sizeof(akstar)));

	uint8_t sqn_ms[6] = { 0, 0, 0, 0, 0, 31 };
	uint8_t amf[2] = {};
	uint8_t mac_s[8];
	milenage_f1(opc, k, rand, sqn_ms, amf, NULL, mac_s);
	printf("mac_s = %s\n", osmo_hexdump_nospc(mac_s, sizeof(mac_s)));
	/* verify valid AUTS resulting in SQN 31 with:
	   osmo-auc-gen -3 -a milenage -k 000102030405060708090a0b0c0d0e0f \
	                -o 000102030405060708090a0b0c0d0e0f \
	                -r 00000000000000000000000000000000 \
	                -A 8711a0ec9e1637df17f80b384ee4
	 */
#endif

	const uint8_t auts[14] = { 0x87, 0x11, 0xa0, 0xec, 0x9e, 0x16, 0x37, 0xdf,
			     0x17, 0xf8, 0x0b, 0x38, 0x4e, 0xe4 };

	/* Invoking with ind_bitlen == 0, the next SQN after 31 is 32. */
	rc = osmo_auth_gen_vec_auts(vec, &test_aud, auts, _rand, _rand);
	if (rc < 0) {
		printf("AUTS failed\n");
	} else {
		printf("AUTS success: tuple generated with SQN = %" PRIu64 "\n",
		       test_aud.u.umts.sqn);
	}

	/* Now test SQN incrementing scheme using SEQ and IND parts:
	 * with ind_bitlen == 5 and ind == 10, the next SQN after 31 is
	 * 32 + 10 == 42. */
	test_aud.u.umts.ind_bitlen = 5;
	test_aud.u.umts.ind = 10;
	rc = osmo_auth_gen_vec_auts(vec, &test_aud, auts, _rand, _rand);
	if (rc < 0)
		printf("AUTS failed\n");
	else
		printf("AUTS success: tuple generated with SQN = %" PRIu64 "\n",
		       test_aud.u.umts.sqn);

	/* And the one after that is 64 + 10 == 74 */
	rc = osmo_auth_gen_vec(vec, &test_aud, _rand);
	if (rc < 0)
		printf("generating vector failed\n");
	else
		printf("tuple generated with SQN = %" PRIu64 "\n",
		       test_aud.u.umts.sqn);

	/* And the one after *that* is 96 + 10 == 106 */
	rc = osmo_auth_gen_vec(vec, &test_aud, _rand);
	if (rc < 0)
		printf("generating vector failed\n");
	else
		printf("tuple generated with SQN = %" PRIu64 "\n",
		       test_aud.u.umts.sqn);

	opc_test(&test_aud);

	exit(0);

}
