/* Osmocom Authentication Protocol API */

/* (C) 2015 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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
 * SPDX-License-Identifier: GPL-2.0+
 *
 */

#include <string.h>
#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/gsm/oap.h>

#include <osmocom/gsm/oap_client.h>

int osmo_oap_client_init(struct osmo_oap_client_config *config,
			 struct osmo_oap_client_state *state)
{
	OSMO_ASSERT(state->state == OSMO_OAP_UNINITIALIZED);

	if (!config)
		goto disable;

	if (config->client_id == 0)
		goto disable;

	if (config->secret_k_present == 0) {
		LOGP(DLOAP, LOGL_NOTICE, "OAP: client ID set, but secret K missing.\n");
		goto disable;
	}

	if (config->secret_opc_present == 0) {
		LOGP(DLOAP, LOGL_NOTICE, "OAP: client ID set, but secret OPC missing.\n");
		goto disable;
	}

	state->client_id = config->client_id;
	memcpy(state->secret_k, config->secret_k, sizeof(state->secret_k));
	memcpy(state->secret_opc, config->secret_opc, sizeof(state->secret_opc));
	state->state = OSMO_OAP_INITIALIZED;
	return 0;

disable:
	state->state = OSMO_OAP_DISABLED;
	return 0;
}

/* From the given state and received RAND and AUTN octets, validate the
 * server's authenticity and formulate the matching milenage reply octets in
 * *tx_xres. The state is not modified.
 * On success, and if tx_res is not NULL, exactly 8 octets will be written to
 * *tx_res. If not NULL, tx_res must point at allocated memory of at least 8
 * octets. The caller will want to send XRES back to the server in a challenge
 * response message and update the state.
 * Return 0 on success; -1 if OAP is disabled; -2 if rx_random and rx_autn fail
 * the authentication check; -3 for any other errors. */
static int oap_evaluate_challenge(const struct osmo_oap_client_state *state,
				  const uint8_t *rx_random,
				  const uint8_t *rx_autn,
				  uint8_t *tx_xres)
{
	struct osmo_auth_vector vec;

	struct osmo_sub_auth_data auth = {
		.type		= OSMO_AUTH_TYPE_UMTS,
		.algo		= OSMO_AUTH_ALG_MILENAGE,
	};

	osmo_static_assert(sizeof(((struct osmo_sub_auth_data*)0)->u.umts.k)
			   == sizeof(state->secret_k), _secret_k_size_match);
	osmo_static_assert(sizeof(((struct osmo_sub_auth_data*)0)->u.umts.opc)
			   == sizeof(state->secret_opc), _secret_opc_size_match);

	switch (state->state) {
	case OSMO_OAP_UNINITIALIZED:
	case OSMO_OAP_DISABLED:
		return -1;
	default:
		break;
	}

	memcpy(auth.u.umts.k, state->secret_k, sizeof(auth.u.umts.k));
	memcpy(auth.u.umts.opc, state->secret_opc, sizeof(auth.u.umts.opc));
	memset(auth.u.umts.amf, '\0', sizeof(auth.u.umts.amf));
	auth.u.umts.sqn = 41; /* TODO use incrementing sequence nr */

	memset(&vec, 0, sizeof(vec));
	osmo_auth_gen_vec(&vec, &auth, rx_random);

	if (vec.res_len != 8) {
		LOGP(DLOAP, LOGL_ERROR, "OAP: Expected XRES to be 8 octets, got %d\n",
		     vec.res_len);
		return -3;
	}

	if (osmo_constant_time_cmp(vec.autn, rx_autn, sizeof(vec.autn)) != 0) {
		LOGP(DLOAP, LOGL_ERROR, "OAP: AUTN mismatch!\n");
		LOGP(DLOAP, LOGL_INFO, "OAP: AUTN from server: %s\n",
		     osmo_hexdump_nospc(rx_autn, sizeof(vec.autn)));
		LOGP(DLOAP, LOGL_INFO, "OAP: AUTN expected:    %s\n",
		     osmo_hexdump_nospc(vec.autn, sizeof(vec.autn)));
		return -2;
	}

	if (tx_xres != NULL)
		memcpy(tx_xres, vec.res, 8);
	return 0;
}

struct msgb *osmo_oap_client_encoded(const struct osmo_oap_message *oap_msg)
{
	struct msgb *msg = msgb_alloc_headroom(1000, 64, __func__);
	OSMO_ASSERT(msg);
	osmo_oap_encode(msg, oap_msg);
	return msg;
}

/* Create a new msgb containing an OAP registration message.
 * On error, return NULL. */
static struct msgb* oap_msg_register(uint16_t client_id)
{
	struct osmo_oap_message oap_msg = {0};

	if (client_id < 1) {
		LOGP(DLOAP, LOGL_ERROR, "OAP: Invalid client ID: %d\n", client_id);
		return NULL;
	}

	oap_msg.message_type = OAP_MSGT_REGISTER_REQUEST;
	oap_msg.client_id = client_id;
	return osmo_oap_client_encoded(&oap_msg);
}

int osmo_oap_client_register(struct osmo_oap_client_state *state, struct msgb **msg_tx)
{
	*msg_tx = oap_msg_register(state->client_id);
	if (!(*msg_tx))
		return -1;

	state->state = OSMO_OAP_REQUESTED_CHALLENGE;
	return 0;
}

/* Create a new msgb containing an OAP challenge response message.
 * xres must point at 8 octets to return as challenge response.
 * On error, return NULL. */
static struct msgb* oap_msg_challenge_response(uint8_t *xres)
{
	struct osmo_oap_message oap_reply = {0};

	oap_reply.message_type = OAP_MSGT_CHALLENGE_RESULT;
	memcpy(oap_reply.xres, xres, sizeof(oap_reply.xres));
	oap_reply.xres_present = 1;
	return osmo_oap_client_encoded(&oap_reply);
}

static int handle_challenge(struct osmo_oap_client_state *state,
			    struct osmo_oap_message *oap_rx,
			    struct msgb **msg_tx)
{
	int rc;
	uint8_t xres[8];

	if (!(oap_rx->rand_present && oap_rx->autn_present)) {
		LOGP(DLOAP, LOGL_ERROR,
		     "OAP challenge incomplete (rand_present: %d, autn_present: %d)\n",
		     oap_rx->rand_present, oap_rx->autn_present);
		rc = -2;
		goto failure;
	}

	rc = oap_evaluate_challenge(state,
				    oap_rx->rand,
				    oap_rx->autn,
				    xres);
	if (rc < 0)
		goto failure;

	*msg_tx = oap_msg_challenge_response(xres);
	if ((*msg_tx) == NULL) {
		rc = -1;
		goto failure;
	}

	state->state = OSMO_OAP_SENT_CHALLENGE_RESULT;
	return 0;

failure:
	OSMO_ASSERT(rc < 0);
	state->state = OSMO_OAP_INITIALIZED;
	return rc;
}

int osmo_oap_client_handle(struct osmo_oap_client_state *state,
			   const struct msgb *msg_rx, struct msgb **msg_tx)
{
	uint8_t *data = msgb_l2(msg_rx);
	size_t data_len = msgb_l2len(msg_rx);
	struct osmo_oap_message oap_msg = {0};
	int rc = 0;

	*msg_tx = NULL;

	OSMO_ASSERT(data);

	rc = osmo_oap_decode(&oap_msg, data, data_len);
	if (rc < 0) {
		LOGP(DLOAP, LOGL_ERROR,
		     "Decoding OAP message failed with error '%s' (%d)\n",
		     get_value_string(gsm48_gmm_cause_names, -rc), -rc);
		return -10;
	}

	switch (state->state) {
	case OSMO_OAP_UNINITIALIZED:
		LOGP(DLOAP, LOGL_ERROR,
		     "Received OAP message %d, but the OAP client is"
		     " not initialized\n", oap_msg.message_type);
		return -ENOTCONN;
	case OSMO_OAP_DISABLED:
		LOGP(DLOAP, LOGL_ERROR,
		     "Received OAP message %d, but the OAP client is"
		     " disabled\n", oap_msg.message_type);
		return -ENOTCONN;
	default:
		break;
	}

	switch (oap_msg.message_type) {
	case OAP_MSGT_CHALLENGE_REQUEST:
		return handle_challenge(state, &oap_msg, msg_tx);

	case OAP_MSGT_REGISTER_RESULT:
		/* successfully registered */
		state->state = OSMO_OAP_REGISTERED;
		break;

	case OAP_MSGT_REGISTER_ERROR:
		LOGP(DLOAP, LOGL_ERROR,
		     "OAP registration failed\n");
		state->state = OSMO_OAP_INITIALIZED;
		if (state->registration_failures < 3) {
			state->registration_failures++;
			return osmo_oap_client_register(state, msg_tx);
		}
		return -11;

	case OAP_MSGT_REGISTER_REQUEST:
	case OAP_MSGT_CHALLENGE_RESULT:
		LOGP(DLOAP, LOGL_ERROR,
		     "Received invalid OAP message type for OAP client side: %d\n",
		     (int)oap_msg.message_type);
		return -12;

	default:
		LOGP(DLOAP, LOGL_ERROR,
		     "Unknown OAP message type: %d\n",
		     (int)oap_msg.message_type);
		return -13;
	}

	return 0;
}
