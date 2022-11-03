/*
 * (C) 2021 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 * All Rights Reserved
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
#include <stdlib.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48_rest_octets.h>

struct si13_test {
	const char *name;
	const struct osmo_gsm48_si13_info si;
	int enc_rc;
	int dec_rc;
	void (*post_dec_cb)(const struct si13_test *test, const struct osmo_gsm48_si13_info* dec);
};

void post_dec_cb_test_alpha(const struct si13_test *test, const struct osmo_gsm48_si13_info* dec)
{
	OSMO_ASSERT(test->si.pwr_ctrl_pars.alpha == dec->pwr_ctrl_pars.alpha);
}

static const struct si13_test test_si13_arr[] = {
	{
		.name = "test alpha",
		.si = {
			.cell_opts = {
				.nmo 		= GPRS_NMO_II,
				.t3168		= 2000,
				.t3192		= 1500,
				.drx_timer_max	= 3,
				.bs_cv_max	= 15,
				.ctrl_ack_type_use_block = true,
				.ext_info_present = 0,
				.ext_info = {
					.egprs_supported = 1,
					.use_egprs_p_ch_req = 1,
					.bep_period = 5,
					.pfc_supported = 0,
					.dtm_supported = 0,
					.bss_paging_coordination = 0,
					.ccn_active = true,
				},
			},
			.pwr_ctrl_pars = {
				.alpha		= 5,
				.t_avg_w	= 16,
				.t_avg_t	= 16,
				.pc_meas_chan	= 0,
				.n_avg_i	= 8,
			},
			.bcch_change_mark	= 1,
			.si_change_field	= 0,
			.rac		= 0x03,
			.spgc_ccch_sup 	= 0,
			.net_ctrl_ord	= 0,
			.prio_acc_thr	= 6,
		},
		.enc_rc = 20,
		.dec_rc = 71,
		.post_dec_cb = post_dec_cb_test_alpha,
	},
};

static void test_si13(void)
{
	int i, rc;
	uint8_t data[GSM_MACBLOCK_LEN];
	struct osmo_gsm48_si13_info si13;

	for (i = 0; i < ARRAY_SIZE(test_si13_arr); i++) {
		memset(data, 0, sizeof(data));
		rc = osmo_gsm48_rest_octets_si13_encode(data, &test_si13_arr[i].si);
		if (rc >= 0) {
			printf("si13_encode (%d): %s\n", rc, osmo_hexdump(data, rc));
		} else {
			printf("si13_encode failed (%d)\n", rc);
		}
		OSMO_ASSERT(rc == test_si13_arr[i].enc_rc);
		if (rc <= 0)
			continue;
		memset(&si13, 0 , sizeof(si13));
		rc = osmo_gsm48_rest_octets_si13_decode(&si13, data);
		if (rc >= 0) {
			printf("si13_decode (%d)\n", rc);
		} else {
			printf("si13_decode failed (%d)\n", rc);
		}
		OSMO_ASSERT(rc == test_si13_arr[i].dec_rc);
		if (test_si13_arr[i].post_dec_cb) {
			test_si13_arr[i].post_dec_cb(&test_si13_arr[i], &si13);
		}
	}
}

int main(int argc, char **argv)
{
	test_si13();

	return EXIT_SUCCESS;
}
