/* GSM/GPRS/3G authentication core infrastructure */

/* (C) 2014 by Sylvain Munaut <tnt@246tNt.com>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <osmocom/crypt/auth.h>

static int xor_gen_vec(struct osmo_auth_vector *vec,
                       struct osmo_sub_auth_data *aud,
                       const uint8_t *_rand)
{
	int i;

	for (i=0; i<4; i++)
		vec->sres[i] = _rand[i] ^ aud->u.gsm.ki[i];
	for (i=0; i<8; i++)
		vec->kc[i] = _rand[i+4] ^ aud->u.gsm.ki[i+4];

	vec->auth_types = OSMO_AUTH_TYPE_GSM;

	return 0;
}

static struct osmo_auth_impl xor_alg = {
	.algo = OSMO_AUTH_ALG_XOR,
	.name = "XOR (libosmogsm built-in)",
	.priority = 1000,
	.gen_vec = &xor_gen_vec,
};

static __attribute__((constructor)) void on_dso_load_xor(void)
{
	osmo_auth_register(&xor_alg);
}
