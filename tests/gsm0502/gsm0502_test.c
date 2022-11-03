/*
 * (C) 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Philipp Maier <pmaier@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm0502.h>

/* TCH-F, block endings, 3x 104-frame cycles */
uint32_t tch_f_fn_samples[] = { 1036987, 1036991, 1036995, 1037000, 1037004, 1037008, 1037013, 1037017,
	1037021, 1037026, 1037030, 1037034, 1037039, 1037043, 1037047, 1037052,
	1037056, 1037060, 1037065,
	1037069, 1037073, 1037078, 1037082, 1037086, 1037091, 1037095, 1037099,
	1037104, 1037108, 1037112,
	1037117, 1037121, 1037125, 1037130, 1037134, 1037138, 1037143, 1037147,
	1037151, 1037156, 1037160,
	1037164, 1037169, 1037173, 1037177, 1037182, 1037186, 1037190, 1037195,
	1037199, 1037203, 1037208,
	1037212, 1037216, 1037221, 1037225, 1037229, 1037234, 1037238, 1037242,
	1037247, 1037251, 1037255,
	1037260, 1037264, 1037268, 1037273, 1037277, 1037281, 1037286, 1037290,
	1037294
};

/* TCH-H0, block endings, 3x 104-frame cycles */
uint32_t tch_h0_fn_samples[] = { 1175826, 1175830, 1175834, 1175839, 1175843, 1175847, 1175852, 1175856,
	1175860, 1175865, 1175869, 1175873, 1175878, 1175882, 1175886, 1175891,
	1175895, 1175899, 1175904,
	1175908, 1175912, 1175917, 1175921, 1175925, 1175930, 1175934, 1175938,
	1175943, 1175947, 1175951,
	1175956, 1175960, 1175964, 1175969, 1175973, 1175977, 1175982, 1175986,
	1175990, 1175995, 1175999,
	1176003, 1176008, 1176012, 1176016, 1176021, 1176025, 1176029, 1176034,
	1176038, 1176042, 1176047,
	1176051, 1176055, 1176060, 1176064, 1176068, 1176073, 1176077, 1176081,
	1176086, 1176090, 1176094,
	1176099, 1176103, 1176107, 1176112, 1176116, 1176120, 1176125, 1176129,
	1176133
};

/* TCH-H1, block endings, 3x 104-frame cycles */
unsigned int tch_h1_fn_samples[] = { 1175827, 1175831, 1175835, 1175840, 1175844, 1175848, 1175853, 1175857,
	1175861, 1175866, 1175870, 1175874, 1175879, 1175883, 1175887, 1175892,
	1175896, 1175900, 1175905,
	1175909, 1175913, 1175918, 1175922, 1175926, 1175931, 1175935, 1175939,
	1175944, 1175948, 1175952,
	1175957, 1175961, 1175965, 1175970, 1175974, 1175978, 1175983, 1175987,
	1175991, 1175996, 1176000,
	1176004, 1176009, 1176013, 1176017, 1176022, 1176026, 1176030, 1176035,
	1176039, 1176043, 1176048,
	1176052, 1176056, 1176061, 1176065, 1176069, 1176074, 1176078, 1176082,
	1176087, 1176091, 1176095,
	1176100, 1176104, 1176108, 1176113, 1176117, 1176121, 1176126, 1176130,
	1176134
};

/* FACCH-F, block endings */
uint32_t facch_f_fn_samples[] = { 177275, 177314, 177336, 177375, 177396, 177435, 178328, 178367, 178393,
	180014, 180053, 180079, 180113, 180144, 180183
};

/* FACCH-H0, block endings */
uint32_t facch_h0_fn_samples[] = { 499956, 499999, 500034, 500077, 500952, 501836, 501880, 502850, 502894,
	502937, 503006, 503050
};

/* FACCH-H1, block endings */
uint32_t facch_h1_fn_samples[] = { 500728, 500771, 500797, 500841, 500875, 500919, 501751, 501794, 501837,
	502782, 502825, 502869, 502903, 502955, 502999
};

static void test_gsm0502_fn_remap(void)
{
	unsigned int i;
        uint32_t fn_begin;
        uint32_t fn_end;

	printf("Testing gsm0502_fn_remap()\n");
	printf("TCH/F\n");
	for (i = 0; i < ARRAY_SIZE(tch_h1_fn_samples); i++) {
		fn_end = tch_f_fn_samples[i];
		fn_begin = gsm0502_fn_remap(fn_end, FN_REMAP_TCH_F);
		printf("fn_end=%u, fn_end%%104=%u, fn_begin=%u, fn_begin%%104=%u\n", fn_end, fn_end % 104, fn_begin,
		       fn_begin % 104);
	}
	printf("\n");

	printf("TCH/H0\n");
	for (i = 0; i < ARRAY_SIZE(tch_h0_fn_samples); i++) {
		fn_end = tch_h0_fn_samples[i];
		fn_begin = gsm0502_fn_remap(fn_end, FN_REMAP_TCH_H0);
		printf("fn_end=%u, fn_end%%104=%u, fn_begin=%u, fn_begin%%104=%u\n", fn_end, fn_end % 104, fn_begin,
		       fn_begin % 104);
	}
	printf("\n");

	printf("TCH/H1\n");
	for (i = 0; i < ARRAY_SIZE(tch_h1_fn_samples); i++) {
		fn_end = tch_h1_fn_samples[i];
		fn_begin = gsm0502_fn_remap(fn_end, FN_REMAP_TCH_H1);
		printf("fn_end=%u, fn_end%%104=%u, fn_begin=%u, fn_begin%%104=%u\n", fn_end, fn_end % 104, fn_begin,
		       fn_begin % 104);
	}
	printf("\n");

	printf("FACCH/F\n");
	for (i = 0; i < ARRAY_SIZE(facch_f_fn_samples); i++) {
		fn_end = facch_f_fn_samples[i];
		fn_begin = gsm0502_fn_remap(fn_end, FN_REMAP_FACCH_F);
		printf("fn_end=%u, fn_end%%104=%u, fn_begin=%u, fn_begin%%104=%u\n", fn_end, fn_end % 104, fn_begin,
		       fn_begin % 104);
	}
	printf("\n");

	printf("FACCH/H0\n");
	for (i = 0; i < ARRAY_SIZE(facch_h0_fn_samples); i++) {
		fn_end = facch_h0_fn_samples[i];
		fn_begin = gsm0502_fn_remap(fn_end, FN_REMAP_FACCH_H0);
		printf("fn_end=%u, fn_end%%104=%u, fn_begin=%u, fn_begin%%104=%u\n", fn_end, fn_end % 104, fn_begin,
		       fn_begin % 104);
	}
	printf("\n");

	printf("FACCH/H1\n");
	for (i = 0; i < ARRAY_SIZE(facch_h1_fn_samples); i++) {
		fn_end = facch_h1_fn_samples[i];
		fn_begin = gsm0502_fn_remap(fn_end, FN_REMAP_FACCH_H1);
		printf("fn_end=%u, fn_end%%104=%u, fn_begin=%u, fn_begin%%104=%u\n", fn_end, fn_end % 104, fn_begin,
		       fn_begin % 104);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	test_gsm0502_fn_remap();
	return EXIT_SUCCESS;
}
