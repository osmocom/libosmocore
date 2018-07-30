/* Osmocom Authentication Protocol API */

/* (C) 2015 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <stdint.h>

struct msgb;
struct osmo_oap_message;

/* This is the config part for vty. It is essentially copied in
 * oap_client_state, where values are copied over once the config is
 * considered valid. */
struct oap_client_config {
	uint16_t client_id;
	int secret_k_present;
	uint8_t secret_k[16];
	int secret_opc_present;
	uint8_t secret_opc[16];
};

/* The runtime state of the OAP client. client_id and the secrets are in fact
 * duplicated from oap_client_config, so that a separate validation of the
 * config data is possible, and so that only a struct oap_client_state* is
 * passed around. */
struct oap_client_state {
	enum {
		OAP_UNINITIALIZED = 0,	/* just allocated. */
		OAP_DISABLED,		/* disabled by config. */
		OAP_INITIALIZED,	/* enabled, config is valid. */
		OAP_REQUESTED_CHALLENGE,
		OAP_SENT_CHALLENGE_RESULT,
		OAP_REGISTERED
	} state;
	uint16_t client_id;
	uint8_t secret_k[16];
	uint8_t secret_opc[16];
	int registration_failures;
};

/* From config, initialize state. Return 0 on success. */
int oap_client_init(struct oap_client_config *config,
		    struct oap_client_state *state);

/* Construct an OAP registration message and return in *msg_tx. Use
 * state->client_id and update state->state.
 * Return 0 on success, or a negative value on error.
 * If an error is returned, *msg_tx is guaranteed to be NULL. */
int oap_client_register(struct oap_client_state *state, struct msgb **msg_tx);

/* Decode and act on a received OAP message msg_rx. Update state->state.  If a
 * non-NULL pointer is returned in *msg_tx, that msgb should be sent to the OAP
 * server (and freed) by the caller. The received msg_rx is not freed.
 * Return 0 on success, or a negative value on error.
 * If an error is returned, *msg_tx is guaranteed to be NULL. */
int oap_client_handle(struct oap_client_state *state,
		      const struct msgb *msg_rx, struct msgb **msg_tx);

/* Allocate a msgb and in it, return the encoded oap_client_msg. Return
 * NULL on error. (Like oap_client_encode(), but also allocates a msgb.)
 * About the name: the idea is do_something(oap_client_encoded(my_struct))
 */
struct msgb *oap_client_encoded(const struct osmo_oap_message *oap_client_msg);
