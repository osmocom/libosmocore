#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <osmocom/core/prbs.h>

static void dump_bits(const ubit_t *bits, unsigned int num_bits)
{
	unsigned int i;

	for (i = 0; i < num_bits; i++) {
		if (bits[i])
			fputc('1', stdout);
		else
			fputc('0', stdout);
	}
	fputc('\n',stdout);
}

static void test_prbs(const struct osmo_prbs *prbs)
{
	struct osmo_prbs_state st;
	unsigned int i;

	printf("Testing PRBS sequence generation '%s'\n", prbs->name);
	osmo_prbs_state_init(&st, prbs);

	/* 2 lines */
	for (i = 0; i < 2; i++) {
		unsigned int seq_len = (1 << prbs->len)-1;
		ubit_t bits[seq_len];
		memset(bits, 0, sizeof(bits));
		osmo_prbs_get_ubits(bits, sizeof(bits), &st);
		dump_bits(bits, sizeof(bits));
	}

	printf("\n");
}

int main(int argc, char **argv)
{
	test_prbs(&osmo_prbs7);
	test_prbs(&osmo_prbs9);
	test_prbs(&osmo_prbs11);
	test_prbs(&osmo_prbs15);

	exit(0);
}
