#pragma once

#define MAX_LEN_BITS	2048
#define MAX_LEN_BYTES	(2048 / 8)

struct conv_test_vector {
	const char *name;
	const struct osmo_conv_code *code;
	int in_len;
	int out_len;
	int has_vec;
	pbit_t vec_in[MAX_LEN_BYTES];
	pbit_t vec_out[MAX_LEN_BYTES];
};

int do_check(const struct conv_test_vector *test);
