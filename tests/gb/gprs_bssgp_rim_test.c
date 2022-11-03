/* Test routines for the BSSGP implementation in libosmogb
 *
 * (C) 2020 by sysmocom - s.f.m.c. GmbH
 * Author: Philipp Maier <pmaier@sysmocom.de>
 *
 * Skeleton based on bssgp_fc_test.c
 * (C) 2012 by Harald Welte <laforge@gnumonks.org>
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/gprs/gprs_bssgp_rim.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

void dump_rim_ri(struct bssgp_rim_routing_info *ri)
{
	switch (ri->discr) {
	case BSSGP_RIM_ROUTING_INFO_GERAN:
		printf("GERAN cell identifier\n");
		printf(" * mcc: %u\n", ri->geran.raid.mcc);
		printf("   mnc: %u\n", ri->geran.raid.mnc);
		printf("   mnc 3 digits: %u\n", ri->geran.raid.mnc_3_digits);
		printf("   lac: %u\n", ri->geran.raid.lac);
		printf("   rac: %u\n", ri->geran.raid.rac);
		printf(" * cell id: %04x\n", ri->geran.cid);
		break;
	case BSSGP_RIM_ROUTING_INFO_UTRAN:
		printf("UTRAN RNC identifier\n");
		printf(" * mcc: %u\n", ri->utran.raid.mcc);
		printf("   mnc: %u\n", ri->utran.raid.mnc);
		printf("   mnc 3 digits: %u\n", ri->utran.raid.mnc_3_digits);
		printf("   lac: %u\n", ri->utran.raid.lac);
		printf("   rac: %u\n", ri->utran.raid.rac);
		printf(" * rnc id: %04x\n", ri->utran.rncid);
		break;
	case BSSGP_RIM_ROUTING_INFO_EUTRAN:
		printf("EUTRAN eNB identifier\n");
		printf(" * mcc: %u\n", ri->eutran.tai.mcc);
		printf("   mnc: %u\n", ri->eutran.tai.mnc);
		printf("   mnc 3 digits: %u\n", ri->eutran.tai.mnc_3_digits);
		printf("   tac: %u\n", ri->eutran.tai.tac);
		printf(" * global_enb_id: %s\n",
		       osmo_hexdump_nospc(ri->eutran.global_enb_id,
					  ri->eutran.global_enb_id_len));
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void test_bssgp_parse_rim_ri(void)
{
	int rc;
	struct bssgp_rim_routing_info result;
	uint8_t testvec_geran[] =
	    { 0x00, 0x62, 0xf2, 0x24, 0x33, 0x90, 0x00, 0x51, 0xe1 };
	uint8_t testvec_utran[] =
	    { 0x01, 0x62, 0xf2, 0x24, 0x33, 0x90, 0x00, 0x51, 0xe1 };
	uint8_t testvec_eutran[] =
	    { 0x02, 0x62, 0xf2, 0x24, 0x33, 0x90, 0x00, 0x51, 0xe1 };

	printf("----- %s START\n", __func__);

	rc = bssgp_parse_rim_ri(&result, testvec_geran,
				sizeof(testvec_geran));
	printf("rc=%d\n", rc);
	dump_rim_ri(&result);
	printf("\n");

	rc = bssgp_parse_rim_ri(&result, testvec_utran,
				sizeof(testvec_utran));
	printf("rc=%d\n", rc);
	dump_rim_ri(&result);
	printf("\n");

	rc = bssgp_parse_rim_ri(&result, testvec_eutran,
				sizeof(testvec_eutran));
	printf("rc=%d\n", rc);
	dump_rim_ri(&result);
	printf("\n");

	printf("----- %s END\n", __func__);
}

static void test_bssgp_create_rim_ri(void)
{
	int rc;
	struct bssgp_rim_routing_info ri;
	uint8_t result[15];

	printf("----- %s START\n", __func__);
	memset(&ri, 0, sizeof(ri));
	memset(result, 0, sizeof(result));
	ri.discr = BSSGP_RIM_ROUTING_INFO_GERAN;

	ri.geran.raid.mcc = 262;
	ri.geran.raid.mnc = 42;
	ri.geran.raid.mnc_3_digits = false;
	ri.geran.raid.lac = 13200;
	ri.geran.raid.rac = 0;
	ri.geran.cid = 0x51e1;
	dump_rim_ri(&ri);
	rc = bssgp_create_rim_ri(result, &ri);
	printf("rc=%d, ", rc);
	if (rc > 0)
		printf("result=%s", osmo_hexdump_nospc(result, rc));
	printf("\n\n");

	memset(&ri, 0, sizeof(ri));
	memset(result, 0, sizeof(result));
	ri.discr = BSSGP_RIM_ROUTING_INFO_UTRAN;
	ri.utran.raid.mcc = 262;
	ri.utran.raid.mnc = 42;
	ri.utran.raid.mnc_3_digits = 0;
	ri.utran.raid.lac = 13200;
	ri.utran.raid.rac = 0;
	ri.utran.rncid = 0x51e1;
	dump_rim_ri(&ri);
	rc = bssgp_create_rim_ri(result, &ri);
	printf("rc=%d, ", rc);
	if (rc > 0)
		printf("result=%s", osmo_hexdump_nospc(result, rc));
	printf("\n\n");

	memset(&ri, 0, sizeof(ri));
	memset(result, 0, sizeof(result));
	ri.discr = BSSGP_RIM_ROUTING_INFO_EUTRAN;
	ri.eutran.tai.mcc = 262;
	ri.eutran.tai.mnc = 42;
	ri.eutran.tai.mnc_3_digits = 0;
	ri.eutran.tai.tac = 13200;
	ri.eutran.global_enb_id[0] = 0x00;
	ri.eutran.global_enb_id[1] = 0x51;
	ri.eutran.global_enb_id[2] = 0xe1;
	ri.eutran.global_enb_id_len = 3;
	dump_rim_ri(&ri);
	rc = bssgp_create_rim_ri(result, &ri);
	printf("rc=%d, ", rc);
	if (rc > 0)
		printf("result=%s", osmo_hexdump_nospc(result, rc));
	printf("\n\n");

	printf("----- %s END\n", __func__);
}

void dump_bssgp_ran_inf_req_app_cont_nacc(struct bssgp_ran_inf_req_app_cont_nacc *app_cont)
{
	printf(" app_cont: bssgp_ran_inf_req_app_cont_nacc:\n");
	printf("  reprt_cell.rai.lac.plmn.mcc = %u\n", app_cont->reprt_cell.rai.lac.plmn.mcc);
	printf("  reprt_cell.rai.lac.plmn.mnc = %u\n", app_cont->reprt_cell.rai.lac.plmn.mnc);
	printf("  reprt_cell.rai.lac.plmn.mnc_3_digits = %u\n", app_cont->reprt_cell.rai.lac.plmn.mnc_3_digits);
	printf("  reprt_cell.rai.lac.lac = %u\n", app_cont->reprt_cell.rai.lac.lac);
	printf("  reprt_cell.rai.rac = %u\n", app_cont->reprt_cell.rai.rac);
	printf("  reprt_cell.cell_identity = %04x\n", app_cont->reprt_cell.cell_identity);
}

void dump_bssgp_ran_inf_req_rim_cont(struct bssgp_ran_inf_req_rim_cont *rim_cont)
{
	printf("bssgp_ran_inf_req_rim_cont:\n");
	printf(" app_id = %02x\n", rim_cont->app_id);
	printf(" seq_num = %08x\n", rim_cont->seq_num);
	printf(" pdu_ind.ack_requested = %u\n", rim_cont->pdu_ind.ack_requested);
	printf(" pdu_ind.pdu_type_ext = %u\n", rim_cont->pdu_ind.pdu_type_ext);
	printf(" prot_ver = %u\n", rim_cont->prot_ver);
	switch (rim_cont->app_id) {
	case BSSGP_RAN_INF_APP_ID_NACC:
		dump_bssgp_ran_inf_req_app_cont_nacc(&rim_cont->u.app_cont_nacc);
		break;
	case BSSGP_RAN_INF_APP_ID_SI3:
	case BSSGP_RAN_INF_APP_ID_MBMS:
	case BSSGP_RAN_INF_APP_ID_SON:
	case BSSGP_RAN_INF_APP_ID_UTRA_SI:
		printf(" app_cont: (not implemented yet)\n");
		break;
	default:
		printf(" app_cont: (illegal application identifier)\n");
	}
	if (rim_cont->son_trans_app_id) {
		printf(" son_trans_app_id: %s\n",
		       osmo_hexdump_nospc(rim_cont->son_trans_app_id, rim_cont->son_trans_app_id_len));
		printf(" son_trans_app_id_len: %zu\n", rim_cont->son_trans_app_id_len);
	}
}

static void test_bssgp_dec_ran_inf_req_rim_cont_nacc(void)
{
	int rc;
	struct bssgp_ran_inf_req_rim_cont rim_cont_dec;
	uint8_t testvec[] =
	    { 0x4b, 0x81, 0x01, 0x4c, 0x84, 0x00, 0x00, 0x00, 0x01, 0x4f, 0x81, 0x02, 0x55, 0x81, 0x01, 0x4d, 0x88,
    0x62, 0xf2, 0x24, 0x33, 0x90, 0x00, 0x51, 0xe1 };

	printf("----- %s START\n", __func__);

	rc = bssgp_dec_ran_inf_req_rim_cont(&rim_cont_dec, testvec, sizeof(testvec));
	printf("rc=%d, ", rc);
	if (rc == 0)
		dump_bssgp_ran_inf_req_rim_cont(&rim_cont_dec);

	printf("----- %s END\n", __func__);
}

static void test_bssgp_enc_ran_inf_req_rim_cont_nacc(void)
{
	int rc;
	struct bssgp_ran_inf_req_rim_cont rim_cont = { };
	uint8_t result[256];
	printf("----- %s START\n", __func__);

	rim_cont.app_id = BSSGP_RAN_INF_APP_ID_NACC;
	rim_cont.seq_num = 1;
	rim_cont.pdu_ind.ack_requested = 0;
	rim_cont.pdu_ind.pdu_type_ext = 1;
	rim_cont.prot_ver = 1;
	rim_cont.son_trans_app_id = NULL;
	rim_cont.son_trans_app_id_len = 0;
	rim_cont.u.app_cont_nacc.reprt_cell.rai.lac.plmn.mcc = 262;
	rim_cont.u.app_cont_nacc.reprt_cell.rai.lac.plmn.mnc = 42;
	rim_cont.u.app_cont_nacc.reprt_cell.rai.lac.plmn.mnc_3_digits = 0;
	rim_cont.u.app_cont_nacc.reprt_cell.rai.lac.lac = 13200;
	rim_cont.u.app_cont_nacc.reprt_cell.rai.rac = 0;
	rim_cont.u.app_cont_nacc.reprt_cell.cell_identity = 0x51e1;

	dump_bssgp_ran_inf_req_rim_cont(&rim_cont);

	rc = bssgp_enc_ran_inf_req_rim_cont(result, sizeof(result), &rim_cont);
	printf("rc=%d, ", rc);
	if (rc > 0)
		printf("result=%s", osmo_hexdump_nospc(result, rc));
	printf("\n");
	printf("----- %s END\n", __func__);
}

static void dump_bssgp_ran_inf_app_cont_nacc(struct bssgp_ran_inf_app_cont_nacc *app_cont)
{
	unsigned int i;
	unsigned int silen;
	printf(" app_cont: bssgp_ran_inf_app_cont_nacc:\n");
	printf("  reprt_cell.rai.lac.plmn.mcc = %u\n", app_cont->reprt_cell.rai.lac.plmn.mcc);
	printf("  reprt_cell.rai.lac.plmn.mnc = %u\n", app_cont->reprt_cell.rai.lac.plmn.mnc);
	printf("  reprt_cell.rai.lac.plmn.mnc_3_digits = %u\n", app_cont->reprt_cell.rai.lac.plmn.mnc_3_digits);
	printf("  reprt_cell.rai.lac.lac = %u\n", app_cont->reprt_cell.rai.lac.lac);
	printf("  reprt_cell.rai.rac = %u\n", app_cont->reprt_cell.rai.rac);
	printf("  reprt_cell.cell_identity = %04x\n", app_cont->reprt_cell.cell_identity);
	printf("  type_psi = %u\n", app_cont->type_psi);
	printf("  num_si = %u\n", app_cont->num_si);

	if (app_cont->type_psi)
		silen = 22;
	else
		silen = 21;

	for (i = 0; i < app_cont->num_si; i++)
		printf(" si[%u] = %s\n", i, osmo_hexdump_nospc(app_cont->si[i], silen));
}

static void dump_bssgp_app_err_cont_nacc(struct bssgp_app_err_cont_nacc *app_cont)
{
	printf(" app_err_cont: bssgp_app_err_cont_nacc:\n");
	printf("  macc_cause = %02x\n", app_cont->nacc_cause);
	if (app_cont->err_app_cont) {
		printf("  err_app_cont: %s\n", osmo_hexdump_nospc(app_cont->err_app_cont, app_cont->err_app_cont_len));
		printf("  err_app_cont_len: %zu\n", app_cont->err_app_cont_len);
	}
}

static void dump_bssgp_ran_inf_rim_cont(struct bssgp_ran_inf_rim_cont *rim_cont)
{
	printf("bssgp_ran_inf_rim_cont:\n");
	printf(" app_id = %02x\n", rim_cont->app_id);
	printf(" seq_num = %08x\n", rim_cont->seq_num);
	printf(" pdu_ind.ack_requested = %u\n", rim_cont->pdu_ind.ack_requested);
	printf(" pdu_ind.pdu_type_ext = %u\n", rim_cont->pdu_ind.pdu_type_ext);
	printf(" prot_ver = %u\n", rim_cont->prot_ver);
	printf(" app_err = %u\n", rim_cont->app_err);
	if (rim_cont->app_err) {
		switch (rim_cont->app_id) {
		case BSSGP_RAN_INF_APP_ID_NACC:
			dump_bssgp_app_err_cont_nacc(&rim_cont->u.app_err_cont_nacc);
			break;
		case BSSGP_RAN_INF_APP_ID_SI3:
		case BSSGP_RAN_INF_APP_ID_MBMS:
		case BSSGP_RAN_INF_APP_ID_SON:
		case BSSGP_RAN_INF_APP_ID_UTRA_SI:
			printf(" app_err_cont: (not implemented yet)\n");
			break;
		default:
			printf(" app_err_cont: (illegal application identifier)\n");
		}
	} else {
		switch (rim_cont->app_id) {
		case BSSGP_RAN_INF_APP_ID_NACC:
			dump_bssgp_ran_inf_app_cont_nacc(&rim_cont->u.app_cont_nacc);
			break;
		case BSSGP_RAN_INF_APP_ID_SI3:
		case BSSGP_RAN_INF_APP_ID_MBMS:
		case BSSGP_RAN_INF_APP_ID_SON:
		case BSSGP_RAN_INF_APP_ID_UTRA_SI:
			printf(" app_cont: (not implemented yet)\n");
			break;
		default:
			printf(" app_cont: (illegal application identifier)\n");
		}
	}
	if (rim_cont->son_trans_app_id) {
		printf(" son_trans_app_id: %s\n",
		       osmo_hexdump_nospc(rim_cont->son_trans_app_id, rim_cont->son_trans_app_id_len));
		printf(" son_trans_app_id_len: %zu\n", rim_cont->son_trans_app_id_len);
	}
}

static void test_bssgp_dec_ran_inf_rim_cont_nacc(void)
{
	int rc;
	struct bssgp_ran_inf_rim_cont rim_cont_dec;
	uint8_t testvec[] =
	    { 0x4b, 0x81, 0x01, 0x4c, 0x84, 0x00, 0x00, 0x00, 0x02, 0x4f, 0x81, 0x02, 0x55, 0x81, 0x01, 0x4e, 0xc8,
		0x62, 0xf2, 0x24, 0x33, 0x4f, 0x00, 0x51, 0xe0, 0x06, 0x19, 0x8f, 0xb1, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x2b, 0x1b, 0x75, 0x30, 0x00, 0xf1, 0x10,
		    0x23, 0x6e,
		0xc9, 0x03, 0x3c, 0x27, 0x47, 0x40, 0x79, 0x00, 0x00, 0x3c, 0x0b, 0x2b, 0x2b, 0x00, 0x90, 0x00, 0x18,
		    0x5a, 0x6f,
		0xc9, 0xe0, 0x84, 0x10, 0xab, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b
	};

	printf("----- %s START\n", __func__);

	rc = bssgp_dec_ran_inf_rim_cont(&rim_cont_dec, testvec, sizeof(testvec));
	printf("rc=%d, ", rc);
	if (rc == 0)
		dump_bssgp_ran_inf_rim_cont(&rim_cont_dec);

	printf("----- %s END\n", __func__);
}

static void test_bssgp_dec_ran_inf_rim_cont_err_nacc(void)
{
	int rc;
	struct bssgp_ran_inf_rim_cont rim_cont_dec;
	uint8_t testvec[] =
	    { 0x4b, 0x81, 0x01, 0x4c, 0x84, 0x00, 0x00, 0x00, 0x01, 0x4f, 0x81, 0x02, 0x55, 0x81, 0x01, 0x56, 0x86,
    0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };

	printf("----- %s START\n", __func__);

	rc = bssgp_dec_ran_inf_rim_cont(&rim_cont_dec, testvec, sizeof(testvec));
	printf("rc=%d, ", rc);
	if (rc == 0)
		dump_bssgp_ran_inf_rim_cont(&rim_cont_dec);

	printf("----- %s END\n", __func__);
}

static void test_bssgp_enc_ran_inf_rim_cont_nacc(void)
{
	int rc;
	struct bssgp_ran_inf_rim_cont rim_cont = { };

	uint8_t si1[] =
	    { 0x19, 0x8f, 0xb1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x79, 0x00, 0x00, 0x2b
	};
	uint8_t si3[] =
	    { 0x1b, 0x75, 0x30, 0x00, 0xf1, 0x10, 0x23, 0x6e, 0xc9, 0x03, 0x3c, 0x27, 0x47, 0x40, 0x79, 0x00, 0x00,
		0x3c, 0x0b, 0x2b, 0x2b
	};
	uint8_t si13[] =
	    { 0x00, 0x90, 0x00, 0x18, 0x5a, 0x6f, 0xc9, 0xe0, 0x84, 0x10, 0xab, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b,
		0x2b, 0x2b, 0x2b, 0x2b
	};

	uint8_t result[256];
	printf("----- %s START\n", __func__);

	rim_cont.app_id = BSSGP_RAN_INF_APP_ID_NACC;
	rim_cont.seq_num = 1;
	rim_cont.pdu_ind.ack_requested = 0;
	rim_cont.pdu_ind.pdu_type_ext = 1;
	rim_cont.prot_ver = 1;
	rim_cont.son_trans_app_id = NULL;
	rim_cont.son_trans_app_id_len = 0;
	rim_cont.app_err = false;
	rim_cont.u.app_cont_nacc.reprt_cell.rai.lac.plmn.mcc = 262;
	rim_cont.u.app_cont_nacc.reprt_cell.rai.lac.plmn.mnc = 42;
	rim_cont.u.app_cont_nacc.reprt_cell.rai.lac.plmn.mnc_3_digits = 0;
	rim_cont.u.app_cont_nacc.reprt_cell.rai.lac.lac = 13135;
	rim_cont.u.app_cont_nacc.reprt_cell.rai.rac = 0;
	rim_cont.u.app_cont_nacc.reprt_cell.cell_identity = 0x51e0;
	rim_cont.u.app_cont_nacc.type_psi = 0;
	rim_cont.u.app_cont_nacc.num_si = 3;
	rim_cont.u.app_cont_nacc.si[0] = si1;
	rim_cont.u.app_cont_nacc.si[1] = si3;
	rim_cont.u.app_cont_nacc.si[2] = si13;

	dump_bssgp_ran_inf_rim_cont(&rim_cont);

	rc = bssgp_enc_ran_inf_rim_cont(result, sizeof(result), &rim_cont);
	printf("rc=%d, ", rc);
	if (rc > 0)
		printf("result=%s", osmo_hexdump_nospc(result, rc));
	printf("\n");
	printf("----- %s END\n", __func__);
}

static void test_bssgp_enc_ran_inf_rim_cont_err_nacc(void)
{
	int rc;
	struct bssgp_ran_inf_rim_cont rim_cont = { };
	uint8_t err_app_cont[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee };

	uint8_t result[256];
	printf("----- %s START\n", __func__);

	rim_cont.app_id = BSSGP_RAN_INF_APP_ID_NACC;
	rim_cont.seq_num = 1;
	rim_cont.pdu_ind.ack_requested = 0;
	rim_cont.pdu_ind.pdu_type_ext = 1;
	rim_cont.prot_ver = 1;
	rim_cont.son_trans_app_id = NULL;
	rim_cont.son_trans_app_id_len = 0;
	rim_cont.app_err = true;
	rim_cont.u.app_err_cont_nacc.nacc_cause = BSSGP_NACC_CAUSE_SYNTAX_ERR;
	rim_cont.u.app_err_cont_nacc.err_app_cont = err_app_cont;
	rim_cont.u.app_err_cont_nacc.err_app_cont_len = sizeof(err_app_cont);
	dump_bssgp_ran_inf_rim_cont(&rim_cont);

	rc = bssgp_enc_ran_inf_rim_cont(result, sizeof(result), &rim_cont);
	printf("rc=%d, ", rc);
	if (rc > 0)
		printf("result=%s", osmo_hexdump_nospc(result, rc));
	printf("\n");
	printf("----- %s END\n", __func__);
}

static void dump_bssgp_ran_inf_ack_rim_cont(struct bssgp_ran_inf_ack_rim_cont *rim_cont)
{
	printf("bssgp_ran_inf_ack_rim_cont:\n");
	printf(" app_id = %02x\n", rim_cont->app_id);
	printf(" seq_num = %08x\n", rim_cont->seq_num);
	printf(" prot_ver = %u\n", rim_cont->prot_ver);
	if (rim_cont->son_trans_app_id) {
		printf(" son_trans_app_id: %s\n",
		       osmo_hexdump_nospc(rim_cont->son_trans_app_id, rim_cont->son_trans_app_id_len));
		printf(" son_trans_app_id_len: %zu\n", rim_cont->son_trans_app_id_len);
	}
}

static void test_bssgp_dec_ran_inf_ack_rim_cont(void)
{
	int rc;
	struct bssgp_ran_inf_ack_rim_cont rim_cont_dec;
	uint8_t testvec[] = { 0x4b, 0x81, 0x01, 0x4c, 0x84, 0x00, 0x00, 0x00, 0x01, 0x55, 0x81, 0x01 };

	printf("----- %s START\n", __func__);

	rc = bssgp_dec_ran_inf_ack_rim_cont(&rim_cont_dec, testvec, sizeof(testvec));
	printf("rc=%d, ", rc);
	if (rc == 0)
		dump_bssgp_ran_inf_ack_rim_cont(&rim_cont_dec);

	printf("----- %s END\n", __func__);
}

static void test_bssgp_enc_ran_inf_ack_rim_cont(void)
{
	int rc;
	struct bssgp_ran_inf_ack_rim_cont rim_cont = { };
	uint8_t result[256];
	printf("----- %s START\n", __func__);

	rim_cont.app_id = BSSGP_RAN_INF_APP_ID_NACC;
	rim_cont.seq_num = 1;
	rim_cont.prot_ver = 1;
	rim_cont.son_trans_app_id = NULL;
	rim_cont.son_trans_app_id_len = 0;
	dump_bssgp_ran_inf_ack_rim_cont(&rim_cont);

	rc = bssgp_enc_ran_inf_ack_rim_cont(result, sizeof(result), &rim_cont);
	printf("rc=%d, ", rc);
	if (rc > 0)
		printf("result=%s", osmo_hexdump_nospc(result, rc));
	printf("\n");
	printf("----- %s END\n", __func__);
}

void dump_bssgp_ran_inf_err_rim_cont(struct bssgp_ran_inf_err_rim_cont *rim_cont)
{
	printf("bssgp_ran_inf_err_rim_cont:\n");
	printf(" app_id = %02x\n", rim_cont->app_id);
	printf(" cause = %02x\n", rim_cont->cause);
	printf(" prot_ver = %u\n", rim_cont->prot_ver);
	if (rim_cont->err_pdu) {
		printf(" err_pdu: %s\n", osmo_hexdump_nospc(rim_cont->err_pdu, rim_cont->err_pdu_len));
		printf(" err_pdu_len: %zu\n", rim_cont->err_pdu_len);
	}
	if (rim_cont->son_trans_app_id) {
		printf(" son_trans_app_id: %s\n",
		       osmo_hexdump_nospc(rim_cont->son_trans_app_id, rim_cont->son_trans_app_id_len));
		printf(" son_trans_app_id_len: %zu\n", rim_cont->son_trans_app_id_len);
	}
}

static void test_bssgp_dec_ran_inf_err_rim_cont(void)
{
	int rc;
	struct bssgp_ran_inf_err_rim_cont rim_cont_dec;
	uint8_t testvec[] =
	    { 0x4b, 0x81, 0x17, 0x07, 0x81, 0x2b, 0x55, 0x81, 0x01, 0x15, 0x85, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };

	printf("----- %s START\n", __func__);

	rc = bssgp_dec_ran_inf_err_rim_cont(&rim_cont_dec, testvec, sizeof(testvec));
	printf("rc=%d, ", rc);
	if (rc == 0)
		dump_bssgp_ran_inf_err_rim_cont(&rim_cont_dec);

	printf("----- %s END\n", __func__);
}

static void test_bssgp_enc_ran_inf_err_rim_cont(void)
{
	int rc;
	struct bssgp_ran_inf_err_rim_cont rim_cont = { };
	uint8_t err_pdu[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
	uint8_t result[256];
	printf("----- %s START\n", __func__);

	rim_cont.app_id = 23;
	rim_cont.cause = 0x2b;
	rim_cont.prot_ver = 1;
	rim_cont.err_pdu = err_pdu;
	rim_cont.err_pdu_len = sizeof(err_pdu);
	rim_cont.son_trans_app_id = NULL;
	rim_cont.son_trans_app_id_len = 0;
	dump_bssgp_ran_inf_err_rim_cont(&rim_cont);

	rc = bssgp_enc_ran_inf_err_rim_cont(result, sizeof(result), &rim_cont);
	printf("rc=%d, ", rc);
	if (rc > 0)
		printf("result=%s", osmo_hexdump_nospc(result, rc));
	printf("\n");
	printf("----- %s END\n", __func__);
}

void dump_bssgp_ran_inf_app_err_rim_cont(struct bssgp_ran_inf_app_err_rim_cont *rim_cont)
{
	printf("bssgp_ran_inf_app_err_rim_cont:\n");
	printf(" app_id = %02x\n", rim_cont->app_id);
	printf(" seq_num = %08x\n", rim_cont->seq_num);
	printf(" pdu_ind.ack_requested = %u\n", rim_cont->pdu_ind.ack_requested);
	printf(" pdu_ind.pdu_type_ext = %u\n", rim_cont->pdu_ind.pdu_type_ext);
	printf(" prot_ver = %u\n", rim_cont->prot_ver);
	switch (rim_cont->app_id) {
	case BSSGP_RAN_INF_APP_ID_NACC:
		dump_bssgp_app_err_cont_nacc(&rim_cont->u.app_err_cont_nacc);
		break;
	case BSSGP_RAN_INF_APP_ID_SI3:
	case BSSGP_RAN_INF_APP_ID_MBMS:
	case BSSGP_RAN_INF_APP_ID_SON:
	case BSSGP_RAN_INF_APP_ID_UTRA_SI:
		printf(" app_err_cont: (not implemented yet)\n");
		break;
	default:
		printf(" app_err_cont: (illegal application identifier)\n");
	}
}

static void test_bssgp_dec_ran_inf_app_err_rim_cont_nacc(void)
{
	int rc;
	struct bssgp_ran_inf_app_err_rim_cont rim_cont_dec;
	uint8_t testvec[] =
	    { 0x4b, 0x81, 0x01, 0x4c, 0x84, 0x00, 0x00, 0x00, 0x01, 0x4f, 0x81, 0x02, 0x55, 0x81, 0x01, 0x56, 0x85,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee
	};

	printf("----- %s START\n", __func__);

	rc = bssgp_dec_ran_inf_app_err_rim_cont(&rim_cont_dec, testvec, sizeof(testvec));
	printf("rc=%d, ", rc);
	if (rc == 0)
		dump_bssgp_ran_inf_app_err_rim_cont(&rim_cont_dec);

	printf("----- %s END\n", __func__);
}

static void test_bssgp_enc_ran_inf_app_err_rim_cont_nacc(void)
{
	int rc;
	struct bssgp_ran_inf_app_err_rim_cont rim_cont = { };
	uint8_t err_app_cont[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
	uint8_t result[256];

	printf("----- %s START\n", __func__);
	rim_cont.app_id = BSSGP_RAN_INF_APP_ID_NACC;
	rim_cont.seq_num = 1;
	rim_cont.pdu_ind.ack_requested = 0;
	rim_cont.pdu_ind.pdu_type_ext = 1;
	rim_cont.prot_ver = 1;
	rim_cont.u.app_err_cont_nacc.nacc_cause = BSSGP_NACC_CAUSE_SYNTAX_ERR;
	rim_cont.u.app_err_cont_nacc.err_app_cont = err_app_cont;
	rim_cont.u.app_err_cont_nacc.err_app_cont_len = sizeof(err_app_cont);
	dump_bssgp_ran_inf_app_err_rim_cont(&rim_cont);

	rc = bssgp_enc_ran_inf_app_err_rim_cont(result, sizeof(result), &rim_cont);
	printf("rc=%d, ", rc);
	if (rc > 0)
		printf("result=%s", osmo_hexdump_nospc(result, rc));
	printf("\n");
	printf("----- %s END\n", __func__);
}

static void test_bssgp_dec_ran_inf_req_app_cont_nacc(void)
{
	int rc;
	struct bssgp_ran_inf_req_app_cont_nacc app_cont_dec;
	uint8_t testvec[] = { 0x62, 0xf2, 0x24, 0x33, 0x90, 0x00, 0x51, 0xe1 };

	printf("----- %s START\n", __func__);

	rc = bssgp_dec_ran_inf_req_app_cont_nacc(&app_cont_dec, testvec, sizeof(testvec));
	printf("rc=%d, ", rc);
	if (rc == 0)
		dump_bssgp_ran_inf_req_app_cont_nacc(&app_cont_dec);

	printf("----- %s END\n", __func__);
}

static void test_bssgp_enc_ran_inf_req_app_cont_nacc(void)
{
	int rc;
	struct bssgp_ran_inf_req_app_cont_nacc app_cont = { };
	uint8_t result[256];
	printf("----- %s START\n", __func__);

	app_cont.reprt_cell.rai.lac.plmn.mcc = 262;
	app_cont.reprt_cell.rai.lac.plmn.mnc = 42;
	app_cont.reprt_cell.rai.lac.plmn.mnc_3_digits = 0;
	app_cont.reprt_cell.rai.lac.lac = 13200;
	app_cont.reprt_cell.rai.rac = 0;
	app_cont.reprt_cell.cell_identity = 0x51e1;
	dump_bssgp_ran_inf_req_app_cont_nacc(&app_cont);

	rc = bssgp_enc_ran_inf_req_app_cont_nacc(result, sizeof(result), &app_cont);
	printf("rc=%d, ", rc);
	if (rc > 0)
		printf("result=%s", osmo_hexdump_nospc(result, rc));
	printf("\n");
	printf("----- %s END\n", __func__);
}

static void test_bssgp_dec_ran_inf_app_cont_nacc(void)
{
	int rc;
	struct bssgp_ran_inf_app_cont_nacc app_cont_dec;
	uint8_t testvec[] =
	    { 0x62, 0xf2, 0x24, 0x33, 0x4f, 0x00, 0x51, 0xe0, 0x06, 0x19, 0x8f, 0xb1, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x2b, 0x1b, 0x75, 0x30, 0x00, 0xf1, 0x10,
    0x23, 0x6e, 0xc9, 0x03, 0x3c, 0x27, 0x47, 0x40, 0x79, 0x00, 0x00, 0x3c, 0x0b, 0x2b, 0x2b, 0x00, 0x90, 0x00, 0x18,
    0x5a, 0x6f, 0xc9, 0xe0, 0x84, 0x10, 0xab, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b };

	printf("----- %s START\n", __func__);

	rc = bssgp_dec_ran_inf_app_cont_nacc(&app_cont_dec, testvec, sizeof(testvec));
	printf("rc=%d, ", rc);
	if (rc == 0)
		dump_bssgp_ran_inf_app_cont_nacc(&app_cont_dec);

	printf("----- %s END\n", __func__);
}

static void test_bssgp_enc_ran_inf_app_cont_nacc(void)
{
	int rc;
	struct bssgp_ran_inf_app_cont_nacc app_cont = { };

	uint8_t si1[] =
	    { 0x19, 0x8f, 0xb1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x79, 0x00, 0x00, 0x2b };
	uint8_t si3[] =
	    { 0x1b, 0x75, 0x30, 0x00, 0xf1, 0x10, 0x23, 0x6e, 0xc9, 0x03, 0x3c, 0x27, 0x47, 0x40, 0x79, 0x00, 0x00,
	0x3c, 0x0b, 0x2b, 0x2b };
	uint8_t si13[] =
	    { 0x00, 0x90, 0x00, 0x18, 0x5a, 0x6f, 0xc9, 0xe0, 0x84, 0x10, 0xab, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b,
       0x2b, 0x2b, 0x2b, 0x2b };

	uint8_t result[256];
	printf("----- %s START\n", __func__);

	app_cont.reprt_cell.rai.lac.plmn.mcc = 262;
	app_cont.reprt_cell.rai.lac.plmn.mnc = 42;
	app_cont.reprt_cell.rai.lac.plmn.mnc_3_digits = 0;
	app_cont.reprt_cell.rai.lac.lac = 13135;
	app_cont.reprt_cell.rai.rac = 0;
	app_cont.reprt_cell.cell_identity = 0x51e1;
	app_cont.type_psi = false;
	app_cont.num_si = 3;
	app_cont.si[0] = si1;
	app_cont.si[1] = si3;
	app_cont.si[2] = si13;
	dump_bssgp_ran_inf_app_cont_nacc(&app_cont);

	rc = bssgp_enc_ran_inf_app_cont_nacc(result, sizeof(result), &app_cont);
	printf("rc=%d, ", rc);
	if (rc > 0)
		printf("result=%s", osmo_hexdump_nospc(result, rc));
	printf("\n");
	printf("----- %s END\n", __func__);
}

static void test_bssgp_dec_app_err_cont_nacc(void)
{
	int rc;
	struct bssgp_app_err_cont_nacc app_cont_dec;
	uint8_t testvec[] = { 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };

	printf("----- %s START\n", __func__);

	rc = bssgp_dec_app_err_cont_nacc(&app_cont_dec, testvec, sizeof(testvec));
	printf("rc=%d, ", rc);
	if (rc == 0)
		dump_bssgp_app_err_cont_nacc(&app_cont_dec);

	printf("----- %s END\n", __func__);
}

static void test_bssgp_enc_app_err_cont_nacc(void)
{
	int rc;
	struct bssgp_app_err_cont_nacc app_cont = { };
	uint8_t err_app_cont[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
	uint8_t result[256];
	printf("----- %s START\n", __func__);

	app_cont.nacc_cause = BSSGP_NACC_CAUSE_SYNTAX_ERR;
	app_cont.err_app_cont = err_app_cont;
	app_cont.err_app_cont_len = sizeof(err_app_cont);
	dump_bssgp_app_err_cont_nacc(&app_cont);

	rc = bssgp_enc_app_err_cont_nacc(result, sizeof(result), &app_cont);
	printf("rc=%d, ", rc);
	if (rc > 0)
		printf("result=%s", osmo_hexdump_nospc(result, rc));
	printf("\n");
	printf("----- %s END\n", __func__);
}

int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	return 0;
}

int main(int argc, char **argv)
{
	printf("===== BSSGP RIM test START\n");

	/* RIM routing information */
	test_bssgp_parse_rim_ri();
	test_bssgp_create_rim_ri();

	/* RIM containers */
	test_bssgp_dec_ran_inf_req_rim_cont_nacc();
	test_bssgp_enc_ran_inf_req_rim_cont_nacc();
	test_bssgp_dec_ran_inf_rim_cont_nacc();
	test_bssgp_dec_ran_inf_rim_cont_err_nacc();
	test_bssgp_enc_ran_inf_rim_cont_nacc();
	test_bssgp_enc_ran_inf_rim_cont_err_nacc();
	test_bssgp_dec_ran_inf_ack_rim_cont();
	test_bssgp_enc_ran_inf_ack_rim_cont();
	test_bssgp_dec_ran_inf_err_rim_cont();
	test_bssgp_enc_ran_inf_err_rim_cont();
	test_bssgp_dec_ran_inf_app_err_rim_cont_nacc();
	test_bssgp_enc_ran_inf_app_err_rim_cont_nacc();

	/* Application containers */
	test_bssgp_dec_ran_inf_req_app_cont_nacc();
	test_bssgp_enc_ran_inf_req_app_cont_nacc();
	test_bssgp_dec_ran_inf_app_cont_nacc();
	test_bssgp_enc_ran_inf_app_cont_nacc();
	test_bssgp_dec_app_err_cont_nacc();
	test_bssgp_enc_app_err_cont_nacc();

	printf("===== BSSGP RIM test END\n\n");

	exit(EXIT_SUCCESS);
}
