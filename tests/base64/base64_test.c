#include <osmocom/core/base64.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const unsigned char base64_test_dec[64] = {
	0x24, 0x48, 0x6E, 0x56, 0x87, 0x62, 0x5A, 0xBD,
	0xBF, 0x17, 0xD9, 0xA2, 0xC4, 0x17, 0x1A, 0x01,
	0x94, 0xED, 0x8F, 0x1E, 0x11, 0xB3, 0xD7, 0x09,
	0x0C, 0xB6, 0xE9, 0x10, 0x6F, 0x22, 0xEE, 0x13,
	0xCA, 0xB3, 0x07, 0x05, 0x76, 0xC9, 0xFA, 0x31,
	0x6C, 0x08, 0x34, 0xFF, 0x8D, 0xC2, 0x6C, 0x38,
	0x00, 0x43, 0xE9, 0x54, 0x97, 0xAF, 0x50, 0x4B,
	0xD1, 0x41, 0xBA, 0x95, 0x31, 0x5A, 0x0B, 0x97
};

static const unsigned char base64_test_enc[] =
    "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPK"
    "swcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==";

/*
 * Checkup routine
 */
int main(int argc, char **argv)
{
	size_t len;
	const unsigned char *src;
	unsigned char buffer[128];

	printf("  Base64 encoding test: ");

	src = base64_test_dec;

	if (osmo_base64_encode(buffer, sizeof(buffer), &len, src, 64) != 0 ||
	    memcmp(base64_test_enc, buffer, 88) != 0) {
		printf("failed\n");

		exit(1);
	}

	printf("passed\n  Base64 decoding test: ");

	src = base64_test_enc;

	if (osmo_base64_decode(buffer, sizeof(buffer), &len, src, 88) != 0 ||
	    memcmp(base64_test_dec, buffer, 64) != 0) {
		printf("failed\n");

		exit(1);
	}

	printf("passed\n\n");

	exit(0);
}
