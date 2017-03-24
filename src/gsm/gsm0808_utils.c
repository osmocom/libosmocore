/* (C) 2016 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>

#define IP_V4_ADDR_LEN 4
#define IP_V6_ADDR_LEN 16
#define IP_PORT_LEN 2

/* Encode AoIP transport address element */
uint8_t gsm0808_enc_aoip_trasp_addr(struct msgb *msg,
				    const struct sockaddr_storage *ss)
{
	/* See also 3GPP TS 48.008 3.2.2.102 AoIP Transport Layer Address */
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	uint16_t port = 0;
	uint8_t *ptr;
	uint8_t *old_tail;
	uint8_t *tlv_len;

	OSMO_ASSERT(msg);
	OSMO_ASSERT(ss);
	OSMO_ASSERT(ss->ss_family == AF_INET || ss->ss_family == AF_INET6);

	msgb_put_u8(msg, GSM0808_IE_AOIP_TRASP_ADDR);
	tlv_len = msgb_put(msg,1);
	old_tail = msg->tail;

	switch (ss->ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)ss;
		port = ntohs(sin->sin_port);
		ptr = msgb_put(msg, IP_V4_ADDR_LEN);
		memcpy(ptr, &sin->sin_addr.s_addr, IP_V4_ADDR_LEN);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)ss;
		port = ntohs(sin6->sin6_port);
		ptr = msgb_put(msg, IP_V6_ADDR_LEN);
		memcpy(ptr, sin6->sin6_addr.s6_addr, IP_V6_ADDR_LEN);
		break;
	}

	msgb_put_u16(msg, port);

	*tlv_len = (uint8_t) (msg->tail - old_tail);
	return *tlv_len + 2;
}

/* Decode AoIP transport address element */
int gsm0808_dec_aoip_trasp_addr(struct sockaddr_storage *ss,
				const uint8_t *elem, uint8_t len)
{
	/* See also 3GPP TS 48.008 3.2.2.102 AoIP Transport Layer Address */
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	const uint8_t *old_elem = elem;

	OSMO_ASSERT(ss);
	if (!elem)
		return -EINVAL;
	if (len <= 0)
		return -EINVAL;

	memset(ss, 0, sizeof(*ss));

	switch (len) {
	case IP_V4_ADDR_LEN + IP_PORT_LEN:
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;

		memcpy(&sin.sin_addr.s_addr, elem, IP_V4_ADDR_LEN);
		elem += IP_V4_ADDR_LEN;
		sin.sin_port = osmo_load16le(elem);
		elem += IP_PORT_LEN;

		memcpy(ss, &sin, sizeof(sin));
		break;
	case IP_V6_ADDR_LEN + IP_PORT_LEN:
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;

		memcpy(sin6.sin6_addr.s6_addr, elem, IP_V6_ADDR_LEN);
		elem += IP_V6_ADDR_LEN;
		sin6.sin6_port = osmo_load16le(elem);
		elem += IP_PORT_LEN;

		memcpy(ss, &sin6, sizeof(sin6));
		break;
	default:
		/* Malformed element! */
		return -EINVAL;
		break;
	}

	return (int)(elem - old_elem);
}
