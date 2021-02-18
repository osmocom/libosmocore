/* Test Osmocom Authentication Protocol */
/*
 * (C) 2015 by sysmocom s.f.m.c. GmbH
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPLv2+
 */

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/oap.h>

#include <osmocom/gsm/oap_client.h>

#include <stdio.h>
#include <string.h>

static void test_oap_api(void)
{
	printf("Testing OAP API\n");

	struct osmo_oap_client_config _config;
	struct osmo_oap_client_config *config = &_config;

	struct osmo_oap_client_state _state;
	struct osmo_oap_client_state *state = &_state;

	struct osmo_oap_message oap_rx;
	struct msgb *msg_rx;

	struct osmo_oap_message oap_tx;
	struct msgb *msg_tx;

	memset(config, 0, sizeof(*config));
	memset(state, 0, sizeof(*state));

	OSMO_ASSERT(osmo_hexparse("0102030405060708090a0b0c0d0e0f10", config->secret_k, 16) == 16);
	OSMO_ASSERT(osmo_hexparse("1112131415161718191a1b1c1d1e1f20", config->secret_opc, 16) == 16);

	fprintf(stderr, "- make sure filling with zeros means uninitialized\n");
	OSMO_ASSERT(state->state == OSMO_OAP_UNINITIALIZED);

	fprintf(stderr, "- reject messages in uninitialized state\n");
	memset(&oap_rx, 0, sizeof(oap_rx));
	state->client_id = 1;
	oap_rx.message_type = OAP_MSGT_REGISTER_ERROR;
	msg_rx = osmo_oap_client_encoded(&oap_rx);
	OSMO_ASSERT(osmo_oap_client_handle(state, msg_rx, &msg_tx) < 0);
	OSMO_ASSERT(state->state == OSMO_OAP_UNINITIALIZED);
	msgb_free(msg_rx);
	OSMO_ASSERT(!msg_tx);

	fprintf(stderr, "- NULL config should disable\n");
	OSMO_ASSERT( osmo_oap_client_init(NULL, state) == 0 );
	OSMO_ASSERT(state->state == OSMO_OAP_DISABLED);

	fprintf(stderr, "- reject messages in disabled state\n");
	memset(state, 0, sizeof(*state));
	memset(&oap_rx, 0, sizeof(oap_rx));
	state->state = OSMO_OAP_DISABLED;
	state->client_id = 1;
	oap_rx.message_type = OAP_MSGT_REGISTER_ERROR;
	msg_rx = osmo_oap_client_encoded(&oap_rx);
	OSMO_ASSERT(osmo_oap_client_handle(state, msg_rx, &msg_tx) < 0);
	OSMO_ASSERT(state->state == OSMO_OAP_DISABLED);
	msgb_free(msg_rx);
	OSMO_ASSERT(!msg_tx);

	fprintf(stderr, "- invalid client_id and shared secret\n");
	memset(state, 0, sizeof(*state));
	config->client_id = 0;
	config->secret_k_present = 0;
	config->secret_opc_present = 0;
	OSMO_ASSERT( osmo_oap_client_init(config, state) == 0 );
	OSMO_ASSERT(state->state == OSMO_OAP_DISABLED);

	fprintf(stderr, "- reset state\n");
	memset(state, 0, sizeof(*state));

	fprintf(stderr, "- only client_id is invalid\n");
	config->client_id = 0;
	config->secret_k_present = 1;
	config->secret_opc_present = 1;
	OSMO_ASSERT( osmo_oap_client_init(config, state) == 0 );
	OSMO_ASSERT(state->state == OSMO_OAP_DISABLED);

	memset(state, 0, sizeof(*state));

	fprintf(stderr, "- valid id, but omitted shared_secret (1/2)\n");
	config->client_id = 12345;
	config->secret_k_present = 0;
	config->secret_opc_present = 1;
	OSMO_ASSERT( osmo_oap_client_init(config, state) == 0 );
	OSMO_ASSERT(state->state == OSMO_OAP_DISABLED);

	memset(state, 0, sizeof(*state));

	fprintf(stderr, "- valid id, but omitted shared_secret (2/2)\n");
	config->client_id = 12345;
	config->secret_k_present = 1;
	config->secret_opc_present = 0;
	OSMO_ASSERT( osmo_oap_client_init(config, state) == 0 );
	OSMO_ASSERT(state->state == OSMO_OAP_DISABLED);

	memset(state, 0, sizeof(*state));


	fprintf(stderr, "- mint configuration\n");
	config->client_id = 12345;
	config->secret_k_present = 1;
	config->secret_opc_present = 1;
	/*config->secret_* buffers are still set from the top */
	OSMO_ASSERT( osmo_oap_client_init(config, state) == 0 );
	OSMO_ASSERT(state->state == OSMO_OAP_INITIALIZED);


	fprintf(stderr, "- Missing challenge data\n");
	memset(&oap_rx, 0, sizeof(oap_rx));
	oap_rx.message_type = OAP_MSGT_CHALLENGE_REQUEST;
	oap_rx.rand_present = 0;
	oap_rx.autn_present = 0;
	msg_rx = osmo_oap_client_encoded(&oap_rx);
	OSMO_ASSERT(osmo_oap_client_handle(state, msg_rx, &msg_tx) == -2);
	msgb_free(msg_rx);
	OSMO_ASSERT(!msg_tx);

	fprintf(stderr, "- AUTN missing\n");
	osmo_hexparse("0102030405060708090a0b0c0d0e0f10",
		      oap_rx.rand, 16);
	oap_rx.rand_present = 1;
	msg_rx = osmo_oap_client_encoded(&oap_rx);
	OSMO_ASSERT(osmo_oap_client_handle(state, msg_rx, &msg_tx) == -2);
	msgb_free(msg_rx);
	OSMO_ASSERT(!msg_tx);

	fprintf(stderr, "- RAND missing\n");
	oap_rx.rand_present = 0;
	osmo_hexparse("cec4e3848a33000086781158ca40f136",
		      oap_rx.autn, 16);
	oap_rx.autn_present = 1;
	msg_rx = osmo_oap_client_encoded(&oap_rx);
	OSMO_ASSERT(osmo_oap_client_handle(state, msg_rx, &msg_tx) == -2);
	msgb_free(msg_rx);
	OSMO_ASSERT(!msg_tx);

	fprintf(stderr, "- wrong autn (by one bit)\n");
	osmo_hexparse("0102030405060708090a0b0c0d0e0f10",
		      oap_rx.rand, 16);
	osmo_hexparse("dec4e3848a33000086781158ca40f136",
		      oap_rx.autn, 16);
	oap_rx.rand_present = 1;
	oap_rx.autn_present = 1;
	msg_rx = osmo_oap_client_encoded(&oap_rx);
	OSMO_ASSERT(osmo_oap_client_handle(state, msg_rx, &msg_tx) == -2);
	msgb_free(msg_rx);
	OSMO_ASSERT(!msg_tx);

	fprintf(stderr, "- all data correct\n");
	osmo_hexparse("cec4e3848a33000086781158ca40f136",
		      oap_rx.autn, 16);
	msg_rx = osmo_oap_client_encoded(&oap_rx);

	fprintf(stderr, "- but refuse to evaluate in uninitialized state\n");
	OSMO_ASSERT(state->state == OSMO_OAP_INITIALIZED);

	state->state = OSMO_OAP_UNINITIALIZED;
	OSMO_ASSERT(osmo_oap_client_handle(state, msg_rx, &msg_tx) < 0);
	OSMO_ASSERT(!msg_tx);

	state->state = OSMO_OAP_DISABLED;
	OSMO_ASSERT(osmo_oap_client_handle(state, msg_rx, &msg_tx) < 0);
	OSMO_ASSERT(!msg_tx);

	state->state = OSMO_OAP_INITIALIZED;

	fprintf(stderr, "- now everything is correct\n");
	/* a successful return value here indicates correct autn */
	OSMO_ASSERT(osmo_oap_client_handle(state, msg_rx, &msg_tx) == 0);
	msgb_free(msg_rx);

	fprintf(stderr, "- Expect the challenge response in msg_tx\n");
	OSMO_ASSERT(msg_tx);
	OSMO_ASSERT(osmo_oap_decode(&oap_tx, msg_tx->data, msg_tx->len) == 0);
	OSMO_ASSERT(oap_tx.message_type == OAP_MSGT_CHALLENGE_RESULT);
	OSMO_ASSERT(strcmp("e2d05b598c61d9ba",
			   osmo_hexdump_nospc(oap_tx.xres, sizeof(oap_tx.xres)))
		    == 0);
	OSMO_ASSERT(state->state == OSMO_OAP_SENT_CHALLENGE_RESULT);
	msgb_free(msg_tx);
	msg_tx = 0;

	struct osmo_oap_client_state saved_state = _state;

	fprintf(stderr, "- Receive registration error for the first time.\n");

	memset(&oap_rx, 0, sizeof(oap_rx));
	oap_rx.message_type = OAP_MSGT_REGISTER_ERROR;
	oap_rx.cause = GMM_CAUSE_PROTO_ERR_UNSPEC;
	msg_rx = osmo_oap_client_encoded(&oap_rx);

	OSMO_ASSERT(state->registration_failures == 0);
	OSMO_ASSERT(osmo_oap_client_handle(state, msg_rx, &msg_tx) == 0);
	OSMO_ASSERT(state->registration_failures == 1);
	OSMO_ASSERT(msg_tx);
	OSMO_ASSERT(osmo_oap_decode(&oap_tx, msg_tx->data, msg_tx->len) == 0);
	OSMO_ASSERT(oap_tx.message_type == OAP_MSGT_REGISTER_REQUEST);
	OSMO_ASSERT(state->state == OSMO_OAP_REQUESTED_CHALLENGE);
	msgb_free(msg_tx);
	msg_tx = 0;

	fprintf(stderr, "- Receive registration error for the Nth time.\n");
	state->registration_failures = 999;
	OSMO_ASSERT(osmo_oap_client_handle(state, msg_rx, &msg_tx) == -11);
	OSMO_ASSERT(!msg_tx);
	OSMO_ASSERT(state->state == OSMO_OAP_INITIALIZED);
	msgb_free(msg_tx);
	msg_tx = 0;

	msgb_free(msg_rx);

	fprintf(stderr, "- Registration success\n");

	_state = saved_state;
	memset(&oap_rx, 0, sizeof(oap_rx));
	oap_rx.message_type = OAP_MSGT_REGISTER_RESULT;
	msg_rx = osmo_oap_client_encoded(&oap_rx);
	OSMO_ASSERT(osmo_oap_client_handle(state, msg_rx, &msg_tx) == 0);
	OSMO_ASSERT(!msg_tx);
	OSMO_ASSERT(state->state == OSMO_OAP_REGISTERED);
	msgb_free(msg_rx);
}

static struct log_info_cat oap_client_test_categories[] = {
};

static struct log_info info = {
	.cat = oap_client_test_categories,
	.num_cat = ARRAY_SIZE(oap_client_test_categories),
};

int main(int argc, char **argv)
{
	void *ctx = talloc_named_const(NULL, 0, "oap_client_test");
	msgb_talloc_ctx_init(ctx, 0);
	osmo_init_logging2(ctx, &info);

	OSMO_ASSERT(osmo_stderr_target);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_parse_category_mask(osmo_stderr_target, "DLOAP,1");

	test_oap_api();
	printf("Done\n");

	return 0;
}

