#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <osmocom/core/bits.h>
#include <osmocom/core/conv.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm0503.h>

#include "conv.h"

/* Forward declaration of GSM 05.03 specific test vectors */
extern const struct conv_test_vector gsm0503_vectors[];
extern const int gsm0503_vectors_len;

int main(int argc, char *argv[])
{
	int rc, i;

	for (i = 0; i < gsm0503_vectors_len; i++) {
		rc = do_check(&gsm0503_vectors[i]);
		if (rc)
			return rc;
	}

	return 0;
}
