/*
 * (C) 2022 by sysmocom - s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gsm/protocol/gsm_48_049.h>
#include <osmocom/gsm/cbsp.h>

/*
CBSP WRITE-REPLACE FAILURE
 Message Type: WRITE-REPLACE FAILURE (3)
 Message Length: 44
 IE: Message Identifier: 0x0031
  Information Element Identifier: Message Identifier (14)
  Message Identifier: 0x0031
 IE: New Serial Number: 0x4170
  Information Element Identifier: New Serial Number (3)
  New Serial Number: 0x4170
 IE: Failure List: 2 items
  Information Element Identifier: Failure List (9)
  Information Element Length: 15
  Failure List Item: MCC 901 International Mobile, shared code, MNC 70 Clementvale Baltic OÜ, LAC 0x0018, CI 0x0030: Cause Cell-identity-not-valid
   Cell ID Discriminator: CGI (0)
   Mobile Country Code (MCC): International Mobile, shared code (901)
   Mobile Network Code (MNC): Clementvale Baltic OÜ (70)
   Location Area Code (LAC): 0x0018
   Cell Identifier (CI): 0x0030
   Cause: Cell-identity-not-valid (0x03)
  Failure List Item: LAC 02711, CI 0xc351: Cause LAI-or-LAC-not-valid
   Cell ID Discriminator: LAC+CI (1)
   Location Area Code (LAC): 0x2711
   Cell Identifier (CI): 0xc351
   Cause: LAI-or-LAC-not-valid (0x0f)
 IE: Cell List (CGI): 2 items
  Information Element Identifier: Cell List (4)
  Information Element Length: 15
  Cell ID Discriminator: CGI (0)
  Cell List Item: MCC 901 International Mobile, shared code, MNC 70 Clementvale Baltic OÜ, LAC 0x0017, CI 0x002a
   Mobile Country Code (MCC): International Mobile, shared code (901)
   Mobile Network Code (MNC): Clementvale Baltic OÜ (70)
   Location Area Code (LAC): 0x0017
   Cell Identifier (CI): 0x002a
  Cell List Item: MCC 901 International Mobile, shared code, MNC 70 Clementvale Baltic OÜ, LAC 0x0018, CI 0x002a
   Mobile Country Code (MCC): International Mobile, shared code (901)
   Mobile Network Code (MNC): Clementvale Baltic OÜ (70)
   Location Area Code (LAC): 0x0018
   Cell Identifier (CI): 0x002a
 IE: Channel Indicator: basic channel
  Information Element Identifier: Channel Indicator (18)
  Channel Indicator: basic channel (0x00)
*/
static const char write_repl_fail_with_failure_list[] =
	"0300002c0e003103417009000f0009f1070018003003012711c3510f04000f0009f1070017002a09f1070018002a1200";

static struct msgb *msgb_from_hex(unsigned int size, const char *hex)
{
	struct msgb *msg = msgb_alloc(size, "test_cbsp");
	OSMO_ASSERT(msg);
	msg->l1h = msgb_put(msg, osmo_hexparse(hex, msg->data, msgb_tailroom(msg)));
	msg->l2h = msg->l1h + sizeof(struct cbsp_header);
	return msg;
}

static void test_decode(void)
{
	struct msgb *msg;
	struct osmo_cbsp_decoded *cbsp_dec;

	printf("=== %s start ===\n", __func__);

	msg = msgb_from_hex(sizeof(write_repl_fail_with_failure_list),
			    write_repl_fail_with_failure_list);

	cbsp_dec = osmo_cbsp_decode(NULL, msg);
	OSMO_ASSERT(cbsp_dec);

	talloc_free(cbsp_dec);
	msgb_free(msg);

	printf("=== %s end ===\n", __func__);
}

int main(int argc, char **argv)
{
	test_decode();

	return EXIT_SUCCESS;
}
