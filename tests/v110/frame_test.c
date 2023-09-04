#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <osmocom/core/bits.h>
#include <osmocom/isdn/v110.h>


static void test_frame_enc(void)
{
	struct osmo_v110_decoded_frame fr;
	ubit_t bits[80];
	unsigned int i;

	memset(&fr, 0, sizeof(fr));

	/* we abuse the fact that ubit_t is 8bit so we can actually
	 * store integer values to clearly identify which bit ends up where */

	/* D1..D48: 101..148 */
	for (i = 0; i < ARRAY_SIZE(fr.d_bits); i++)
		fr.d_bits[i] = 101 + i;
	/* E1..E7: 201..207 */
	for (i = 0; i < ARRAY_SIZE(fr.e_bits); i++)
		fr.e_bits[i] = 201 + i;
	/* S1..S9: 211..219 */
	for (i = 0; i < ARRAY_SIZE(fr.s_bits); i++)
		fr.s_bits[i] = 211 + i;
	/* X1..X2: 221..222 */
	for (i = 0; i < ARRAY_SIZE(fr.x_bits); i++)
		fr.x_bits[i] = 221 + i;

	/* run encoder and dump to stdout */
	memset(bits, 0xff, sizeof(bits));
	osmo_v110_encode_frame(bits, sizeof(bits), &fr);
	osmo_v110_ubit_dump(stdout, bits, sizeof(bits));

	/* run decoder on what we just encoded */
	memset(&fr, 0, sizeof(fr));
	osmo_v110_decode_frame(&fr, bits, sizeof(bits));

	/* re-encode and dump again 'expout' will match it. */
	memset(bits, 0xff, sizeof(bits));
	osmo_v110_encode_frame(bits, sizeof(bits), &fr);
	osmo_v110_ubit_dump(stdout, bits, sizeof(bits));
}


int main(int argc, char **argv)
{
	test_frame_enc();
}

