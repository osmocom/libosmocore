#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <osmocom/core/bits.h>
#include <osmocom/isdn/v110.h>


static void test_ra1(enum osmo_v100_sync_ra1_rate rate)
{
	int user_rate = osmo_v110_sync_ra1_get_user_data_rate(rate);
	int user_data_chunk_bits = osmo_v110_sync_ra1_get_user_data_chunk_bitlen(rate);
	struct osmo_v110_decoded_frame fr;
	ubit_t user_bits[48];
	ubit_t bits[80];
	unsigned int i;
	int rc;

	printf("\n======= User data rate %u\n", user_rate);

	/* we abuse the fact that ubit_t is 8bit so we can actually
	 * store integer values to clearly identify which bit ends up where */
	memset(user_bits, 0xFE, sizeof(user_bits));
	for (i = 0; i < user_data_chunk_bits; i++)
		user_bits[i] = 101 + i;

	printf("user_bits: ");
	for (i = 0; i < user_data_chunk_bits; i++)
		printf("%03d ", user_bits[i]);
	printf("\n");

	/* generate the decoded v.110 frame */
	memset(&fr, 0, sizeof(fr));
	rc = osmo_v110_sync_ra1_user_to_ir(rate, &fr, user_bits, user_data_chunk_bits);
	OSMO_ASSERT(rc == 0);

	/* run encoder and dump to stdout */
	memset(bits, 0xff, sizeof(bits));
	osmo_v110_encode_frame(bits, sizeof(bits), &fr);
	printf("dumping %u encoded bits in V.110 frame:\n", user_data_chunk_bits);
	osmo_v110_ubit_dump(stdout, bits, sizeof(bits));

	/* run decoder on what we just encoded */
	memset(&fr, 0, sizeof(fr));
	osmo_v110_decode_frame(&fr, bits, sizeof(bits));
	printf("dumping re-decoded V.110 frame:\n");
	printf("E-bits: %s\n", osmo_hexdump(fr.e_bits, sizeof(fr.e_bits)));
	printf("S-bits: %s\n", osmo_hexdump(fr.s_bits, sizeof(fr.s_bits)));

	/* re-encode and dump again 'expout' will match it. */
	memset(user_bits, 0xff, sizeof(user_bits));
	rc = osmo_v110_sync_ra1_ir_to_user(rate, user_bits, sizeof(user_bits), &fr);
	if (rc != user_data_chunk_bits) {
		fprintf(stderr, "ERROR: adapt_ir_to_user() returned %d, expected %u\n", rc,
			user_data_chunk_bits);
		exit(23);
	}
	fprintf(stdout, "re-decoded user bits: ");
	for (i = 0; i < user_data_chunk_bits; i++)
		printf("%03d ", user_bits[i]);
	printf("\n");
}


int main(int argc, char **argv)
{
	for (int i = 0; i < _NUM_OSMO_V110_SYNC_RA1; i++)
		test_ra1(i);
}

