#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <osmocom/core/bits.h>
#include <osmocom/isdn/v110.h>
#include <osmocom/gsm/gsm44021.h>


static void fill_v110_frame(struct osmo_v110_decoded_frame *fr)
{
	unsigned int i;

	memset(fr, 0, sizeof(*fr));

	/* we abuse the fact that ubit_t is 8bit so we can actually
	 * store integer values to clearly identify which bit ends up where */

	/* D1..D48: 101..148 */
	for (i = 0; i < ARRAY_SIZE(fr->d_bits); i++)
		fr->d_bits[i] = 101 + i;
	/* E1..E7: 201..207 */
	for (i = 0; i < ARRAY_SIZE(fr->e_bits); i++)
		fr->e_bits[i] = 201 + i;
	/* S1..S9: 211..219 */
	for (i = 0; i < ARRAY_SIZE(fr->s_bits); i++)
		fr->s_bits[i] = 211 + i;
	/* X1..X2: 221..222 */
	for (i = 0; i < ARRAY_SIZE(fr->x_bits); i++)
		fr->x_bits[i] = 221 + i;
}


static void test_frame_enc_12k_6k(void)
{
	struct osmo_v110_decoded_frame fr;
	ubit_t bits[60];

	printf("Testing Frame Encoding for 12k/6k radio interface rate\n");

	fill_v110_frame(&fr);

	/* run encoder and dump to stdout */
	memset(bits, 0xff, sizeof(bits));
	osmo_csd_12k_6k_encode_frame(bits, sizeof(bits), &fr);
	osmo_csd_ubit_dump(stdout, bits, sizeof(bits));

	/* run decoder on what we just encoded */
	memset(&fr, 0, sizeof(fr));
	osmo_csd_12k_6k_decode_frame(&fr, bits, sizeof(bits));

	/* re-encode and dump again 'expout' will match it. */
	memset(bits, 0xff, sizeof(bits));
	osmo_csd_12k_6k_encode_frame(bits, sizeof(bits), &fr);
	osmo_csd_ubit_dump(stdout, bits, sizeof(bits));
}

static void test_frame_enc_3k6(void)
{
	struct osmo_v110_decoded_frame fr;
	ubit_t bits[36];

	printf("Testing Frame Encoding for 3.6k radio interface rate\n");

	fill_v110_frame(&fr);
	/* different D-bit numbering for 3k6, see TS 44.021 Section 8.1.4 */
	for (unsigned int i = 0; i < ARRAY_SIZE(fr.d_bits); i++)
		fr.d_bits[i] = 101 + i/2;

	/* run encoder and dump to stdout */
	memset(bits, 0xff, sizeof(bits));
	osmo_csd_3k6_encode_frame(bits, sizeof(bits), &fr);
	osmo_csd_ubit_dump(stdout, bits, sizeof(bits));

	/* run decoder on what we just encoded */
	memset(&fr, 0, sizeof(fr));
	osmo_csd_3k6_decode_frame(&fr, bits, sizeof(bits));

	/* re-encode and dump again 'expout' will match it. */
	memset(bits, 0xff, sizeof(bits));
	osmo_csd_3k6_encode_frame(bits, sizeof(bits), &fr);
	osmo_csd_ubit_dump(stdout, bits, sizeof(bits));
}


int main(int argc, char **argv)
{
	test_frame_enc_12k_6k();
	printf("\n");
	test_frame_enc_3k6();
}

