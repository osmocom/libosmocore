/*
 * (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <osmocom/gsm/gsm23003.h>
#include <osmocom/core/utils.h>

#define BOOL_STR(b) ((b)? "true" : "false")

static struct {
	const char *imsi;
	bool expect_ok;
} test_imsis[] = {
	{ "", false },
	{ " ", false },
	{ "1", false },
	{ "123", false },
	{ "12345", false },
	{ "123456", true },
	{ "1234567", true },
	{ "1234567890123", true },
	{ "123456789012345", true },
	{ "000000000000000", true },
	{ "999999999999999", true },
	{ "1234567890123456", false },
	{ "a23456789012345", false },
	{ "1234567b9012345", false },
	{ "12345678901234c", false },
	{ "123456789 01234", false },
	{ "1234567\n123456", false },
	{ "123456\t123456", false },
	{ "123456\r123456", false },
};

bool test_valid_imsi()
{
	int i;
	bool pass = true;
	bool ok = true;
	printf("----- %s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(test_imsis); i++) {
		ok = osmo_imsi_str_valid(test_imsis[i].imsi);
		pass = pass && (ok == test_imsis[i].expect_ok);
		printf("%2d: expect=%s result=%s imsi='%s'\n",
		       i, BOOL_STR(test_imsis[i].expect_ok), BOOL_STR(ok),
		       test_imsis[i].imsi);
	}
	return pass;
}

static struct {
	const char *msisdn;
	bool expect_ok;
} test_msisdns[] = {
	{ "", false },
	{ " ", false },
	{ "1", true },
	{ "123", true },
	{ "12345", true },
	{ "123456", true },
	{ "1234567", true },
	{ "1234567890123", true },
	{ "123456789012345", true },
	{ "000000000000000", true },
	{ "999999999999999", true },
	{ "1234567890123456", false },
	{ "a23456789012345", false },
	{ "1234567b9012345", false },
	{ "12345678901234c", false },
	{ "123456789 01234", false },
	{ "1234567\n123456", false },
	{ "123456\t123456", false },
	{ "123456\r123456", false },
};

bool test_valid_msisdn()
{
	int i;
	bool pass = true;
	bool ok = true;
	printf("----- %s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(test_msisdns); i++) {
		ok = osmo_msisdn_str_valid(test_msisdns[i].msisdn);
		pass = pass && (ok == test_msisdns[i].expect_ok);
		printf("%2d: expect=%s result=%s msisdn='%s'\n",
		       i, BOOL_STR(test_msisdns[i].expect_ok), BOOL_STR(ok),
		       test_msisdns[i].msisdn);
	}
	return pass;
}

int main(int argc, char **argv)
{
	bool pass = true;

	pass = pass && test_valid_imsi();
	pass = pass && test_valid_msisdn();

	OSMO_ASSERT(pass);

	return EXIT_SUCCESS;
}
