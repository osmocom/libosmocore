
/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
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

#include <stdio.h>
#include <errno.h>

#include <osmocom/core/sercomm.h>
#include <osmocom/core/msgb.h>

struct osmo_sercomm_inst g_osi;

static const uint8_t valid_dlci3[] = { 0x7E, 3, 0x03, 'f', 'o', 'o', 0x7E };
static const uint8_t valid_dlci23[] = { 0x7E, 23, 0x03, '2', '3', 0x7E };
static const uint8_t valid_dlci23esc[] = { 0x7E, 23, 0x03, 0x7D, '2' ^ (1 << 5), '3', 0x7E };
static const uint8_t valid_echo[] = { 0x7E, SC_DLCI_ECHO, 0x03, 'e', 'c', 'h', 'o', 0x7E };

static void rx_ser_data(struct osmo_sercomm_inst *sc, const uint8_t *data, unsigned int len)
{
	unsigned int i;

	printf("Feeding data into sercomm: %s\n", osmo_hexdump(data, len));
	for (i = 0; i < len; i++) {
		int rc = osmo_sercomm_drv_rx_char(sc, data[i]);
		OSMO_ASSERT(rc == 1);
	}
}


static void dlci_rx_cb(struct osmo_sercomm_inst *sercomm, uint8_t dlci, struct msgb *msg)
{
	printf("%s(): %s\n", __func__, msgb_hexdump(msg));
	msgb_free(msg);
}

static struct msgb *create_mahlzeit_msg(void)
{
	struct msgb *msg = osmo_sercomm_alloc_msgb(10);
	OSMO_ASSERT(msg);
	msgb_put_u8(msg, 'M');
	msgb_put_u8(msg, 'a');
	msgb_put_u8(msg, 'h');
	msgb_put_u8(msg, 'l');
	msgb_put_u8(msg, 'z');
	msgb_put_u8(msg, 'e');
	msgb_put_u8(msg, 'i');
	msgb_put_u8(msg, 't');
	return msg;
}

static void drain_from_uart_side(struct osmo_sercomm_inst *osi)
{
	uint8_t ch;
	int rc;

	printf("Draining from UART: ");
	while ((rc = osmo_sercomm_drv_pull(osi, &ch) == 1))
		printf("0x%02x ", ch);
	printf("\n");
}

static void test_echo(struct osmo_sercomm_inst *osi)
{
	printf("Testing built-in echo DLCI\n");
	OSMO_ASSERT(osmo_sercomm_tx_queue_depth(&g_osi, SC_DLCI_ECHO) == 0);
	rx_ser_data(osi, valid_echo, sizeof(valid_echo));
	OSMO_ASSERT(osmo_sercomm_tx_queue_depth(&g_osi, SC_DLCI_ECHO) == 1);
	drain_from_uart_side(osi);
	OSMO_ASSERT(osmo_sercomm_tx_queue_depth(&g_osi, SC_DLCI_ECHO) == 0);
}

static void test_sercomm(void)
{
	int rc;
	uint8_t ch;
	struct msgb *msg;

	printf("Initializing sercomm_inst\n");
	osmo_sercomm_init(&g_osi);
	g_osi.uart_id = 2342;

	printf("Registering callback for invalid DLCI\n");
	rc = osmo_sercomm_register_rx_cb(&g_osi, 255, NULL);
	OSMO_ASSERT(rc == -EINVAL);

	printf("Registering callback for valid DLCI\n");
	rc = osmo_sercomm_register_rx_cb(&g_osi, 23, &dlci_rx_cb);
	OSMO_ASSERT(rc == 0);

	printf("Checking reject of overlod of valid DLCI\n");
	rc = osmo_sercomm_register_rx_cb(&g_osi, 23, NULL);
	OSMO_ASSERT(rc == -EBUSY);

	printf("Checking Rx of incoming msg for valid DLCI\n");
	rx_ser_data(&g_osi, valid_dlci23, sizeof(valid_dlci23));
	printf("Checking Rx of incoming msg for unequipped DLCI\n");
	rx_ser_data(&g_osi, valid_dlci3, sizeof(valid_dlci3));
	printf("Checking Rx of incoming msg for valid DLCI\n");
	rx_ser_data(&g_osi, valid_dlci23, sizeof(valid_dlci23));
	printf("Checking Rx of incoming msg with escaped char for valid DLCI\n");
	rx_ser_data(&g_osi, valid_dlci23esc, sizeof(valid_dlci23esc));

	printf("Checking that no chars are to be transmitted\n");
	OSMO_ASSERT(osmo_sercomm_drv_pull(&g_osi, &ch) == 0);

	printf("Transmitting msgb through sercomm\n");
	OSMO_ASSERT(osmo_sercomm_tx_queue_depth(&g_osi, 42) == 0);
	msg = create_mahlzeit_msg();
	osmo_sercomm_sendmsg(&g_osi, 42, msg);
	OSMO_ASSERT(osmo_sercomm_tx_queue_depth(&g_osi, 42) == 1);
	drain_from_uart_side(&g_osi);
	OSMO_ASSERT(osmo_sercomm_tx_queue_depth(&g_osi, 42) == 0);

	test_echo(&g_osi);
}

int main(int argc, char **argv)
{
	test_sercomm();
	return 0;
}
