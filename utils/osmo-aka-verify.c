#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/bit64gen.h>

/* Utility program for implementing the SIM-side procedures of 3GPP Authentication and Key Agreement
 * as specified by 3GPP TS 33.102 Section 6.3.3
 *
 * (C) 2021 by Harald Welte <laforge@gnumonks.org>
 * Milenage library code used from libosmocore, which inherited it from wpa_supplicant
 */

/* FIXME: libosmogsm implements those, but doesn't declare them */
int milenage_f1(const uint8_t *opc, const uint8_t *k, const uint8_t *_rand,
		const uint8_t *sqn, const uint8_t *amf, uint8_t *mac_a, uint8_t *mac_s);
int milenage_f2345(const uint8_t *opc, const uint8_t *k, const uint8_t *_rand,
		   uint8_t *res, uint8_t *ck, uint8_t *ik, uint8_t *ak, uint8_t *akstar);
int milenage_opc_gen(uint8_t *opc, const uint8_t *k, const uint8_t *op);

static int milenage_check(const uint8_t *opc, const uint8_t *k, const uint8_t *sqn, const uint8_t *_rand,
			  const uint8_t *autn, uint8_t *ck, uint8_t *ik, uint8_t *res, size_t *res_len,
			  uint8_t *auts)
{
	int i;
	uint8_t xmac[8], ak[6], rx_sqn_bin[6];
	unsigned long long rx_sqn;
	const uint8_t *amf;

	printf("=== Static SIM parameters:\n");
	printf("Milenage SIM K: %s\n", osmo_hexdump_nospc(k, 16));
	printf("Milenage SIM OPc: %s\n", osmo_hexdump_nospc(opc, 16));
	printf("Milenage SIM SQN: %s\n", osmo_hexdump_nospc(sqn, 6));
	printf("\n");

	printf("=== Authentication Tuple as received from Network:\n");
	printf("Milenage Input RAND: %s\n", osmo_hexdump_nospc(_rand, 16));
	printf("Milenage Input AUTN: %s\n", osmo_hexdump_nospc(autn, 16));
	printf("\tAUTN(+)AK: %s\n", osmo_hexdump_nospc(autn, 6));
	printf("\tAMF: %s\n", osmo_hexdump_nospc(autn+6, 2));
	printf("\tMAC: %s\n", osmo_hexdump_nospc(autn+8, 8));
	printf("\n");

	if (milenage_f2345(opc, k, _rand, res, ck, ik, ak, NULL))
		return -1;

	*res_len = 8;
	printf("Milenage f2-Computed RES: %s\n", osmo_hexdump_nospc(res, *res_len));
	printf("Milenage f3-Computed CK: %s\n", osmo_hexdump_nospc(ck, 16));
	printf("Milenage f4-Computed IK: %s\n", osmo_hexdump_nospc(ik, 16));
	printf("Milenage f5-Computed AK: %s\n", osmo_hexdump_nospc(ak, 6));

	/* AUTN = (SQN ^ AK) || AMF || MAC */
	for (i = 0; i < 6; i++)
		rx_sqn_bin[i] = autn[i] ^ ak[i];
	rx_sqn = osmo_load64be_ext(rx_sqn_bin, 6);
	printf("Milenage Computed SQN: %s (%llu)\n", osmo_hexdump_nospc(rx_sqn_bin, 6), rx_sqn);

	if (memcmp(rx_sqn_bin, sqn, 6) <= 0) {
		printf("Milenage: RX-SQN differs from SIM SQN: Re-Sync!\n");
		uint8_t auts_amf[2] = { 0x00, 0x00 }; /* TS 33.102 v7.0.0, 6.3.3 */
		if (milenage_f2345(opc, k, _rand, NULL, NULL, NULL, NULL, ak))
			return -1;
		printf("Milenage Computed AK*: %s", osmo_hexdump_nospc(ak, 6));
		for (i = 0; i < 6; i++)
			auts[i] = sqn[i] ^ ak[i];
		if (milenage_f1(opc, k, _rand, sqn, auts_amf, NULL, auts + 6))
			return -1;
		printf("Milenage AUTS: %s\n", osmo_hexdump_nospc(auts, 14));
		return -2;
	}

	amf = autn + 6;
	if (milenage_f1(opc, k, _rand, rx_sqn_bin, amf, xmac, NULL))
		return -1;

	printf("Milenage f1-Computed XMAC: %s\n", osmo_hexdump_nospc(xmac, 8));

	if (memcmp(xmac, autn + 8, 8) != 0) {
		fprintf(stderr, "Milenage: MAC mismatch!\n");
		return -1;
	}

	return 0;
}


static void help()
{
	printf( "Static SIM card parameters:\n"
		"-k  --key\tSpecify Ki / K\n"
		"-o  --opc\tSpecify OPC\n"
		"-O  --op\tSpecify OP\n"
		"-f  --amf\tSpecify AMF\n"
		"-s  --sqn\tSpecify SQN\n"
	        "\n"
	        "Authentication Tuple by network:\n"
		//"-i  --ind\tSpecify IND slot for new SQN after AUTS\n"
		//"-l  --ind-len\tSpecify IND bit length (default=5)\n"
		"-r  --rand\tSpecify RAND random value\n"
		"-A  --autn\tSpecify AUTN authentication nonce\n"
	      );
}

static uint8_t g_k[16];
static uint8_t g_opc[16];
static uint8_t g_rand[16];
static uint8_t g_autn[16];
static uint8_t g_amf[16];
static unsigned long long g_sqn;


static int handle_options(int argc, char **argv)
{
	int rc, option_index;
	bool rand_is_set = false;
	bool autn_is_set = false;
	bool sqn_is_set = false;
	bool k_is_set = false;
	bool opc_is_set = false;
	bool amf_is_set = false;
	bool opc_is_op = false;
	int64_t val64;

	while (1) {
		int c;
		static struct option long_options[] = {
			{ "key", 1, 0, 'k' },
			{ "opc", 1, 0, 'o' },
			{ "op", 1, 0, 'O' },
			{ "amf", 1, 0, 'f' },
			{ "sqn", 1, 0, 's' },
			{ "rand", 1, 0, 'r' },
			{ "autn", 1, 0, 'A' },
			{ "help", 0, 0, 'h' },
			{ 0, 0, 0, 0 }
		};

		rc = 0;

		c = getopt_long(argc, argv, "k:o:O:f:s:r:A:h", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'k':
			rc = osmo_hexparse(optarg, g_k, sizeof(g_k));
			k_is_set = true;
			break;
		case 'o':
			rc = osmo_hexparse(optarg, g_opc, sizeof(g_opc));
			opc_is_op = false;
			opc_is_set = true;
			break;
		case 'O':
			rc = osmo_hexparse(optarg, g_opc, sizeof(g_opc));
			opc_is_op = true;
			opc_is_set = true;
			break;
		case 'A':
			rc = osmo_hexparse(optarg, g_autn, sizeof(g_autn));
			autn_is_set = true;
			break;
		case 'f':
			rc = osmo_hexparse(optarg, g_amf, sizeof(g_amf));
			amf_is_set = true;
			break;
		case 's':
			rc = osmo_str_to_int64(&val64, optarg, 10, 0, INT64_MAX);
			g_sqn = (unsigned long long)val64;
			sqn_is_set = true;
			break;
		case 'r':
			rc = osmo_hexparse(optarg, g_rand, sizeof(g_rand));
			rand_is_set = true;
			break;
		case 'h':
			help();
			exit(0);
		default:
			help();
			exit(1);
		}

		if (rc < 0) {
			help();
			fprintf(stderr, "\nError parsing argument of option `%c'\n", c);
			exit(2);
		}
	}

	if (!k_is_set || !opc_is_set || !autn_is_set || !rand_is_set) {
		fprintf(stderr, "Error: K, OP[c], AUTN and RAND are mandatory arguments\n");
		fprintf(stderr, "\n");
		help();
		exit(2);
	}

	if (!sqn_is_set)
		printf("Warning: You may want to specify SQN\n");

	if (!amf_is_set)
		printf("Warning: You may want to specify AMF\n");

	if (opc_is_op) {
		uint8_t op[16];
		memcpy(op, g_opc, 16);
		rc = milenage_opc_gen(g_opc, g_k, op);
		OSMO_ASSERT(rc == 0);
	}

	return 0;
}



int main(int argc, char **argv)
{
	printf("osmo-aka-check (C) 2021 by Harald Welte\n");
	printf("This is FREE SOFTWARE with ABSOLUTELY NO WARRANTY\n\n");

	handle_options(argc, argv);

	printf("\n");

	uint8_t ck[16];
	uint8_t ik[16];
	uint8_t res[16];
	size_t res_len;
	uint8_t auts[14];
	uint8_t sqn_bin[6];
	int rc;

	osmo_store64be_ext(g_sqn, sqn_bin, 6);

	rc = milenage_check(g_opc, g_k, sqn_bin, g_rand, g_autn, ck, ik, res, &res_len, auts);

	if (rc < 0) {
		fprintf(stderr, "Authentication FAILED!\n");
		exit(1);
	} else {
		printf("Authentication SUCCEEDED\n");
		exit(0);
	}
}
