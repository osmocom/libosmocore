#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <osmocom/core/bits.h>
#include <osmocom/core/conv.h>
#include <osmocom/core/utils.h>

#include "conv.h"

static void fill_random(ubit_t *b, int n)
{
	int i;

	for (i = 0; i < n; i++)
		b[i] = random() & 1;
}

int do_check(const struct conv_test_vector *test)
{
	ubit_t *bu0, *bu1;
	sbit_t *bs;
	int len, j;

	bu0 = malloc(sizeof(ubit_t) * MAX_LEN_BITS);
	bu1 = malloc(sizeof(ubit_t) * MAX_LEN_BITS);
	bs  = malloc(sizeof(sbit_t) * MAX_LEN_BITS);

	srandom(time(NULL));

	/* Test name */
	printf("[+] Testing: %s\n", test->name);

	/* Check length */
	len = osmo_conv_get_input_length(test->code, 0);
	printf("[.] Input length  : ret = %3d  exp = %3d -> %s\n",
		len, test->in_len, len == test->in_len ? "OK" : "Bad !");

	if (len != test->in_len) {
		fprintf(stderr, "[!] Failure for input length computation\n");
		return -1;
	}

	len = osmo_conv_get_output_length(test->code, 0);
	printf("[.] Output length : ret = %3d  exp = %3d -> %s\n",
		len, test->out_len, len == test->out_len ? "OK" : "Bad !");

	if (len != test->out_len) {
		fprintf(stderr, "[!] Failure for output length computation\n");
		return -1;
	}

	/* Check pre-computed vector */
	if (test->has_vec) {
		printf("[.] Pre computed vector checks:\n");

		printf("[..] Encoding: ");

		osmo_pbit2ubit(bu0, test->vec_in, test->in_len);

		len = osmo_conv_encode(test->code, bu0, bu1);
		if (len != test->out_len) {
			printf("ERROR !\n");
			fprintf(stderr, "[!] Failed encoding length check\n");
			return -1;
		}

		osmo_pbit2ubit(bu0, test->vec_out, test->out_len);

		if (memcmp(bu0, bu1, test->out_len)) {
			printf("ERROR !\n");
			fprintf(stderr, "[!] Failed encoding: Results don't match\n");
			return -1;
		};

		printf("OK\n");


		printf("[..] Decoding: ");

		osmo_ubit2sbit(bs, bu0, len);

		len = osmo_conv_decode(test->code, bs, bu1);
		if (len != 0) {
			printf("ERROR !\n");
			fprintf(stderr, "[!] Failed decoding: non-zero path (%d)\n", len);
			return -1;
		}

		osmo_pbit2ubit(bu0, test->vec_in, test->in_len);

		if (memcmp(bu0, bu1, test->in_len)) {
			printf("ERROR !\n");
			fprintf(stderr, "[!] Failed decoding: Results don't match\n");
			return -1;
		}

		printf("OK\n");
	}

	/* Check random vector */
	printf("[.] Random vector checks:\n");

	for (j = 0; j < 3; j++) {
		printf("[..] Encoding / Decoding cycle : ");

		fill_random(bu0, test->in_len);

		len = osmo_conv_encode(test->code, bu0, bu1);
		if (len != test->out_len) {
			printf("ERROR !\n");
			fprintf(stderr, "[!] Failed encoding length check\n");
			return -1;
		}

		osmo_ubit2sbit(bs, bu1, len);

		len = osmo_conv_decode(test->code, bs, bu1);
		if (len != 0) {
			printf("ERROR !\n");
			fprintf(stderr, "[!] Failed decoding: non-zero path (%d)\n", len);
			return -1;
		}

		if (memcmp(bu0, bu1, test->in_len)) {
			printf("ERROR !\n");
			fprintf(stderr, "[!] Failed decoding: Results don't match\n");
			return -1;
		}

		printf("OK\n");
	}

	/* Spacing */
	printf("\n");

	free(bs);
	free(bu1);
	free(bu0);

	return 0;
}
