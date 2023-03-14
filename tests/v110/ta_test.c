/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Vadim Yanitskiy <vyanitskiy@sysmocom.de>
 *
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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/bits.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <osmocom/isdn/v110.h>
#include <osmocom/isdn/v110_ta.h>

static void *test_ctx = NULL;

/* inverse logic: ON = binary 0; OFF = binary 1 */
#define V110_SX_BIT_ON		0
#define V110_SX_BIT_OFF		1

/*********************************************************************************
 * V.110 TA configuration and callbacks
 *********************************************************************************/

static void v110_ta_test_rx_cb(void *priv, const ubit_t *buf, size_t buf_size)
{
	fprintf(stderr, "%s(buf_size=%zu): %s\n",
		__func__, buf_size, osmo_ubit_dump(buf, buf_size));
}

static void v110_ta_test_tx_cb(void *priv, ubit_t *buf, size_t buf_size)
{
	for (size_t i = 0; i < buf_size; i++)
		buf[i] = (i & 1);
	fprintf(stderr, "%s(buf_size=%zu): %s\n",
		__func__, buf_size, osmo_ubit_dump(buf, buf_size));
}

static void v110_ta_test_status_update_cb(void *priv, unsigned int status)
{
	fprintf(stderr, "%s(status=0x%08x)\n", __func__, status);
}

static const struct osmo_v110_ta_cfg v110_ta_test_cfg = {
	.rate = OSMO_V110_SYNC_RA1_9600,
	.rx_cb = &v110_ta_test_rx_cb,
	.tx_cb = &v110_ta_test_tx_cb,
	.status_update_cb = &v110_ta_test_status_update_cb,
};

/*********************************************************************************
 * various helper functions
 *********************************************************************************/

static void v110_ta_test_init_df(struct osmo_v110_decoded_frame *df)
{
	/* quickly set all the bits to binary '1' */
	memset(df, 1, sizeof(*df));
	/* D-bits: 0101... pattern */
	for (unsigned int i = 0; i < MAX_D_BITS; i += 2)
		df->d_bits[i] = 0;
	/* E-bits: E1/E2/E3 indicate 9600 bps */
	df->e_bits[0] = 0;
}

static void v110_ta_test_dump_df(const struct osmo_v110_decoded_frame *df)
{
	fprintf(stderr, "    D-bits: %s\n", osmo_ubit_dump(&df->d_bits[0], MAX_D_BITS));
	fprintf(stderr, "    E-bits: %s\n", osmo_ubit_dump(&df->e_bits[0], MAX_E_BITS));
	fprintf(stderr, "    S-bits: %s\n", osmo_ubit_dump(&df->s_bits[0], MAX_S_BITS));
	fprintf(stderr, "    X-bits: %s\n", osmo_ubit_dump(&df->x_bits[0], MAX_X_BITS));
}

static void v110_ta_test_dump_circuit(const struct osmo_v110_ta *ta,
				      enum osmo_v110_ta_circuit circuit,
				      bool exp_state)
{
	bool state = osmo_v110_ta_get_circuit(ta, circuit);

	fprintf(stderr, "circuit %s (%s) is %s (expected to be %s)\n",
		osmo_v110_ta_circuit_name(circuit),
		osmo_v110_ta_circuit_desc(circuit),
		state ? "ON" : "OFF",
		exp_state ? "ON" : "OFF");
}

static void v110_ta_test_set_circuit(struct osmo_v110_ta *ta,
				     enum osmo_v110_ta_circuit circuit,
				     bool active)
{
	int rc;

	fprintf(stderr, "setting circuit %s (%s) %s\n",
		osmo_v110_ta_circuit_name(circuit),
		osmo_v110_ta_circuit_desc(circuit),
		active ? "ON" : "OFF");

	rc = osmo_v110_ta_set_circuit(ta, circuit, active);
	fprintf(stderr, "osmo_v110_ta_set_circuit() returns %d\n", rc);
}

/*********************************************************************************
 * the actual tests
 *********************************************************************************/

static void test_idle_ready(void)
{
	struct osmo_v110_decoded_frame df = { 0 };
	struct osmo_v110_ta *ta;
	int rc;

	fprintf(stderr, "\n==== Running %s()\n", __func__);

	ta = osmo_v110_ta_alloc(test_ctx, __func__, &v110_ta_test_cfg);
	OSMO_ASSERT(ta != NULL);

	/* we expect the TA FSM to be in V110_TA_ST_IDLE_READY */

	fprintf(stderr, "Initial status: 0x%08x\n", osmo_v110_ta_get_status(ta));
	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_106, false);
	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_107, false);
	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_109, false);

	fprintf(stderr, "osmo_v110_ta_frame_in(): all bits set to binary '1'\n");
	memset(&df, 1, sizeof(df));
	v110_ta_test_dump_df(&df);
	rc = osmo_v110_ta_frame_in(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_in() returns %d\n", rc);

	fprintf(stderr, "osmo_v110_ta_frame_out(): expecting all bits set to binary '1'\n");
	rc = osmo_v110_ta_frame_out(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_out() returns %d\n", rc);
	if (rc == 0)
		v110_ta_test_dump_df(&df);

	v110_ta_test_set_circuit(ta, OSMO_V110_TA_C_108, true);
	v110_ta_test_set_circuit(ta, OSMO_V110_TA_C_108, false);
	v110_ta_test_set_circuit(ta, OSMO_V110_TA_C_108, true);

	osmo_v110_ta_free(ta);
}

static void test_conn_ta_line(void)
{
	struct osmo_v110_decoded_frame df = { 0 };
	struct osmo_v110_ta *ta;
	int rc;

	fprintf(stderr, "\n==== Running %s()\n", __func__);

	ta = osmo_v110_ta_alloc(test_ctx, __func__, &v110_ta_test_cfg);
	OSMO_ASSERT(ta != NULL);

	/* we expect the TA FSM to be in V110_TA_ST_IDLE_READY */

	v110_ta_test_set_circuit(ta, OSMO_V110_TA_C_108, true);

	/* we expect the TA FSM to be in V110_TA_ST_CON_TA_TO_LINE */

	fprintf(stderr, "osmo_v110_ta_frame_out(): S-/X-bits are expected to be 1 (OFF)\n");
	fprintf(stderr, "osmo_v110_ta_frame_out(): D-/E-bits are all expected to be 1\n");
	rc = osmo_v110_ta_frame_out(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_out() returns %d\n", rc);
	if (rc == 0)
		v110_ta_test_dump_df(&df);

	/* TODO: test implicit sync by sending V110_TA_EV_RX_FRAME_IND */

	fprintf(stderr, "osmo_v110_ta_sync_ind(): the lower layer indicates sync event\n");
	osmo_v110_ta_sync_ind(ta);

	fprintf(stderr, "osmo_v110_ta_frame_out(): S-/X-bits are expected to be 0 (ON)\n");
	fprintf(stderr, "osmo_v110_ta_frame_out(): D-/E-bits are all expected to be 1\n");
	rc = osmo_v110_ta_frame_out(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_out() returns %d\n", rc);
	if (rc == 0)
		v110_ta_test_dump_df(&df);

	fprintf(stderr, "osmo_v110_ta_frame_in(): S-/X-bits are OFF, expect no state change\n");
	v110_ta_test_init_df(&df);
	v110_ta_test_dump_df(&df);
	rc = osmo_v110_ta_frame_in(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_in() returns %d\n", rc);

	fprintf(stderr, "osmo_v110_ta_frame_in(): S-/X-bits are ON, expect state change\n");
	memset(&df.s_bits[0], V110_SX_BIT_ON, sizeof(df.s_bits));
	memset(&df.x_bits[0], V110_SX_BIT_ON, sizeof(df.x_bits));
	v110_ta_test_dump_df(&df);
	rc = osmo_v110_ta_frame_in(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_in() returns %d\n", rc);

	/* we expect the TA FSM to be in V110_TA_ST_DATA_TRANSFER */

	osmo_v110_ta_free(ta);
}

static void _test_data_transfer_enter(struct osmo_v110_ta *ta)
{
	struct osmo_v110_decoded_frame df;
	int rc;

	OSMO_ASSERT(osmo_v110_ta_get_circuit(ta, OSMO_V110_TA_C_108) == false);

	/* we expect the TA FSM to be in V110_TA_ST_IDLE_READY */

	v110_ta_test_set_circuit(ta, OSMO_V110_TA_C_108, true);

	/* we expect the TA FSM to be in V110_TA_ST_CON_TA_TO_LINE */

	fprintf(stderr, "osmo_v110_ta_sync_ind(): the lower layer indicates sync event\n");
	osmo_v110_ta_sync_ind(ta);

	fprintf(stderr, "osmo_v110_ta_frame_in(): S-/X-bits are ON, expect state change\n");
	v110_ta_test_init_df(&df);
	memset(&df.s_bits[0], V110_SX_BIT_ON, sizeof(df.s_bits));
	memset(&df.x_bits[0], V110_SX_BIT_ON, sizeof(df.x_bits));
	v110_ta_test_dump_df(&df);
	rc = osmo_v110_ta_frame_in(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_in() returns %d\n", rc);

	/* we expect the TA FSM to be in V110_TA_ST_DATA_TRANSFER */
}

static void test_data_transfer(void)
{
	struct osmo_v110_decoded_frame df = { 0 };
	struct osmo_v110_ta *ta;
	int rc;

	fprintf(stderr, "\n==== Running %s()\n", __func__);

	ta = osmo_v110_ta_alloc(test_ctx, __func__, &v110_ta_test_cfg);
	OSMO_ASSERT(ta != NULL);

	/* we expect the TA FSM to be in V110_TA_ST_IDLE_READY */

	_test_data_transfer_enter(ta);

	/* we expect the TA FSM to be in V110_TA_ST_DATA_TRANSFER */

	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_106, true);
	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_107, true);
	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_109, true);

	fprintf(stderr, "osmo_v110_ta_frame_out(): S-/X-bits are expected to be 0 (ON)\n");
	fprintf(stderr, "osmo_v110_ta_frame_out(): E1..E3-bits are expected to be 011 (9600)\n");
	fprintf(stderr, "osmo_v110_ta_frame_out(): we also expect the .tx_cb() to be called\n");
	rc = osmo_v110_ta_frame_out(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_out() returns %d\n", rc);
	if (rc == 0)
		v110_ta_test_dump_df(&df);

	fprintf(stderr, "osmo_v110_ta_frame_in(): feed that frame that we pulled out back into the TA\n");
	rc = osmo_v110_ta_frame_in(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_in() returns %d\n", rc);

	osmo_v110_ta_free(ta);
}

static void test_data_transfer_disc_local(void)
{
	struct osmo_v110_decoded_frame df = { 0 };
	struct osmo_v110_ta *ta;
	int rc;

	fprintf(stderr, "\n==== Running %s()\n", __func__);

	ta = osmo_v110_ta_alloc(test_ctx, __func__, &v110_ta_test_cfg);
	OSMO_ASSERT(ta != NULL);

	/* we expect the TA FSM to be in V110_TA_ST_IDLE_READY */

	_test_data_transfer_enter(ta);

	/* we expect the TA FSM to be in V110_TA_ST_DATA_TRANSFER */

	fprintf(stderr, "local TE initiates disconnection\n");
	v110_ta_test_set_circuit(ta, OSMO_V110_TA_C_108, false);

	/* we expect the TA FSM to be in V110_TA_ST_DISCONNECTING */

	fprintf(stderr, "osmo_v110_ta_frame_out(): S-bits are expected to be 1 (OFF)\n");
	fprintf(stderr, "osmo_v110_ta_frame_out(): X-bits are expected to be 0 (ON)\n");
	fprintf(stderr, "osmo_v110_ta_frame_out(): D-bits are all expected to be 0\n");
	rc = osmo_v110_ta_frame_out(ta, &df); /* TODO: what E-bits do we expect? */
	fprintf(stderr, "osmo_v110_ta_frame_out() returns %d\n", rc);
	if (rc == 0)
		v110_ta_test_dump_df(&df);

	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_106, false);
	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_107, true);
	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_109, true);

	fprintf(stderr, "osmo_v110_ta_frame_in(): S-/X-bits are ON, expect no state change\n");
	v110_ta_test_init_df(&df);
	memset(&df.s_bits[0], V110_SX_BIT_ON, sizeof(df.s_bits));
	memset(&df.x_bits[0], V110_SX_BIT_ON, sizeof(df.x_bits));
	v110_ta_test_dump_df(&df);
	rc = osmo_v110_ta_frame_in(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_in() returns %d\n", rc);

	fprintf(stderr, "osmo_v110_ta_frame_in(): S-bits are OFF, expect state change\n");
	v110_ta_test_init_df(&df);
	memset(&df.s_bits[0], V110_SX_BIT_OFF, sizeof(df.s_bits));
	memset(&df.x_bits[0], V110_SX_BIT_ON, sizeof(df.x_bits));
	v110_ta_test_dump_df(&df);
	rc = osmo_v110_ta_frame_in(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_in() returns %d\n", rc);

	/* we expect the TA FSM to be in V110_TA_ST_IDLE_READY */

	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_106, false);
	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_107, false);
	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_109, false);

	osmo_v110_ta_free(ta);
}

static void test_data_transfer_disc_remote(void)
{
	struct osmo_v110_decoded_frame df = { 0 };
	struct osmo_v110_ta *ta;
	int rc;

	fprintf(stderr, "\n==== Running %s()\n", __func__);

	ta = osmo_v110_ta_alloc(test_ctx, __func__, &v110_ta_test_cfg);
	OSMO_ASSERT(ta != NULL);

	/* we expect the TA FSM to be in V110_TA_ST_IDLE_READY */

	_test_data_transfer_enter(ta);

	/* we expect the TA FSM to be in V110_TA_ST_DATA_TRANSFER */

	fprintf(stderr, "remote TE initiates disconnection\n");
	fprintf(stderr, "osmo_v110_ta_frame_in(): S-bits are OFF, X-bits are ON\n");
	fprintf(stderr, "osmo_v110_ta_frame_in(): D-bits are all set to 0\n");
	v110_ta_test_init_df(&df);
	memset(&df.s_bits[0], V110_SX_BIT_OFF, sizeof(df.s_bits));
	memset(&df.x_bits[0], V110_SX_BIT_ON, sizeof(df.x_bits));
	memset(&df.d_bits[0], 0, sizeof(df.d_bits));
	v110_ta_test_dump_df(&df);
	rc = osmo_v110_ta_frame_in(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_in() returns %d\n", rc);

	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_107, false);
	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_109, false);

	fprintf(stderr, "local TE confirms disconnection\n");
	v110_ta_test_set_circuit(ta, OSMO_V110_TA_C_108, false);

	/* we expect the TA FSM to be in V110_TA_ST_DISCONNECTING */

	osmo_v110_ta_desync_ind(ta);

	/* we expect the TA FSM to be in V110_TA_ST_IDLE_READY */

	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_106, false);
	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_107, false);
	v110_ta_test_dump_circuit(ta, OSMO_V110_TA_C_109, false);

	osmo_v110_ta_free(ta);
}

static void test_syncing(void)
{
	struct osmo_v110_decoded_frame df = { 0 };
	struct osmo_v110_ta *ta;
	int rc;

	fprintf(stderr, "\n==== Running %s()\n", __func__);

	ta = osmo_v110_ta_alloc(test_ctx, __func__, &v110_ta_test_cfg);
	OSMO_ASSERT(ta != NULL);

	/* we expect the TA FSM to be in V110_TA_ST_IDLE_READY */

	_test_data_transfer_enter(ta);

	/* we expect the TA FSM to be in V110_TA_ST_DATA_TRANSFER */

	fprintf(stderr, "osmo_v110_ta_sync_ind(): the lower layer indicates out-of-sync event\n");
	osmo_v110_ta_desync_ind(ta);

	/* we expect the TA FSM to be in V110_TA_ST_RESYNCING */

	fprintf(stderr, "osmo_v110_ta_frame_out(): S-bits are expected to be 0 (ON)\n");
	fprintf(stderr, "osmo_v110_ta_frame_out(): X-bits are expected to be 1 (OFF)\n");
	fprintf(stderr, "osmo_v110_ta_frame_out(): D-bits are to be set by .tx_cb()\n");
	rc = osmo_v110_ta_frame_out(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_out() returns %d\n", rc);
	if (rc == 0)
		v110_ta_test_dump_df(&df);

	fprintf(stderr, "osmo_v110_ta_sync_ind(): the lower layer indicates sync event\n");
	osmo_v110_ta_sync_ind(ta);

	/* we expect the TA FSM to be in V110_TA_ST_DATA_TRANSFER */

	fprintf(stderr, "osmo_v110_ta_frame_out(): S-bits are expected to be 0 (ON)\n");
	fprintf(stderr, "osmo_v110_ta_frame_out(): X-bits are expected to be 0 (ON)\n");
	fprintf(stderr, "osmo_v110_ta_frame_out(): D-bits are to be set by .tx_cb()\n");
	rc = osmo_v110_ta_frame_out(ta, &df);
	fprintf(stderr, "osmo_v110_ta_frame_out() returns %d\n", rc);
	if (rc == 0)
		v110_ta_test_dump_df(&df);

	osmo_v110_ta_free(ta);
}

int main(int argc, char **argv)
{
	test_ctx = talloc_named_const(NULL, 0, __FILE__);

	osmo_init_logging2(test_ctx, NULL);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);

	osmo_fsm_log_addr(false);
	osmo_fsm_log_timeouts(true);

	log_set_category_filter(osmo_stderr_target, DLGLOBAL, 1, LOGL_DEBUG);

	test_idle_ready();
	test_conn_ta_line();
	/* TODO: test_conn_ta_line_timeout() */
	test_data_transfer();
	test_data_transfer_disc_local();
	test_data_transfer_disc_remote();
	/* TODO: test_disc_timeout() */
	test_syncing();
	/* TODO: test_syncing_timeout() */

	log_fini();
	OSMO_ASSERT(talloc_total_blocks(test_ctx) == 1);
	talloc_free(test_ctx);

	return 0;
}
