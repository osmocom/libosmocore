/*
 * (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
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
#include <errno.h>
#include <strings.h>
#include <string.h>

#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
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
	{ NULL, false },
};

bool test_valid_imsi(void)
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
	{ NULL, false },
};

bool test_valid_msisdn(void)
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

static struct {
	bool with_15th_digit;
	const char *imei;
	bool expect_ok;
} test_imeis[] = {
	/* without 15th digit */
	{false, "12345678901234", true},
	{false, "1234567890123", false},
	{false, "123456789012345", false},

	/* with 15th digit: valid */
	{true, "357613004448485", true},
	{true, "357805023984447", true},
	{true, "352936001349777", true},
	{true, "357663017768551", true},

	/* with 15th digit: invalid */
	{true, "357613004448480", false},
	{true, "357613004448405", false},
	{true, "357613004448085", false},

	{ NULL, false, false },
};

bool test_valid_imei(void)
{
	int i;
	bool pass = true;
	bool ok = true;
	printf("----- %s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(test_imeis); i++) {
		ok = osmo_imei_str_valid(test_imeis[i].imei, test_imeis[i].with_15th_digit);
		pass = pass && (ok == test_imeis[i].expect_ok);
		printf("%2d: expect=%s result=%s imei='%s' with_15th_digit=%s\n",
		       i, BOOL_STR(test_imeis[i].expect_ok), BOOL_STR(ok),
		       test_imeis[i].imei, test_imeis[i].with_15th_digit ? "true" : "false");
	}
	return pass;
}

struct test_mnc_from_str_result {
	int rc;
	uint16_t mnc;
	bool mnc_3_digits;
};

struct test_mnc_from_str {
	const char *mnc_str;
	struct test_mnc_from_str_result expect;
};

static struct test_mnc_from_str test_mnc_from_strs[] = {
	{ "0",	 { 0, 0, false } },
	{ "00",	 { 0, 0, false } },
	{ "000", { 0, 0, true } },
	{ "1",	 { 0, 1, false } },
	{ "01",	 { 0, 1, false } },
	{ "001", { 0, 1, true } },
	{ "",	 { -EINVAL, 0, false } },
	{ " ",	 { -EINVAL, 0, false } },
	{ "-1",	 { -EINVAL, 0, false } },
	{ "1000", { -EINVAL, 0, false } },
	{ "0x",	 { -EINVAL, 0, false } },
	{ " 23", { -EINVAL, 0, false } },
	{ "23 ", { -EINVAL, 0, false } },
	{ " 023", { -EINVAL, 0, false } },
	{ "023 ", { -EINVAL, 0, false } },
	{ "023 ", { -EINVAL, 0, false } },
};

static bool test_mnc_from_str(void)
{
	int i;
	bool pass = true;
	printf("----- %s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(test_mnc_from_strs); i++) {
		struct test_mnc_from_str *t = &test_mnc_from_strs[i];
		struct test_mnc_from_str_result result = {};
		bool ok;

		result.rc = osmo_mnc_from_str(t->mnc_str, &result.mnc,
						     &result.mnc_3_digits);
		ok = (result.rc == t->expect.rc)
		     && (result.mnc == t->expect.mnc)
		     && (result.mnc_3_digits == t->expect.mnc_3_digits);
		printf("%2d: \"%s\" rc=%d mnc=%u mnc_3_digits=%u %s\n",
		       i, osmo_escape_str(t->mnc_str, -1), result.rc, result.mnc, result.mnc_3_digits,
		       ok ? "pass" : "FAIL");
		pass = pass && ok;
	}
	return pass;
}

static bool test_gummei_name(void)
{
	static const struct osmo_gummei gummei = {
		.plmn = { .mcc = 901, .mnc = 70 },
		.mme = { .group_id = 0xA123, .code = 0xB1 }
	};
	const char *out;
	bool pass = true;

	out = osmo_gummei_name(&gummei);
	printf("%s\n", out);
	if (strcmp(out, "901-70-a123-b1"))
		pass = false;

	return pass;
}

static bool test_domain_gen(void)
{
	static const struct osmo_gummei gummei = {
		.plmn = { .mcc = 901, .mnc = 70 },
		.mme = { .group_id = 0xA123, .code = 0xB1 }
	};
	char out[GSM23003_MME_DOMAIN_LEN];
	bool pass = true;
	int rc;

	rc = osmo_gen_home_network_domain(out, &gummei.plmn);
	if (rc < 0)
		pass = false;
	printf("%s -> %s\n", osmo_plmn_name(&gummei.plmn), out);
	if (strcmp(out, "epc.mnc070.mcc901.3gppnetwork.org"))
		pass = false;

	rc = osmo_gen_mme_domain(out, &gummei);
	printf("%s -> %s\n", osmo_gummei_name(&gummei), out);
	if (strcmp(out, "mmecb1.mmegia123.mme.epc.mnc070.mcc901.3gppnetwork.org"))
		pass = false;

	return pass;
}


static bool test_domain_parse(void)
{
	static const char *mme_dom_valid = "mmec01.mmegiA001.mme.epc.mnc070.mcc901.3gppnetwork.org";
	static const char *home_dom_valid = "epc.mnc070.mcc901.3gppnetwork.org";
	struct osmo_gummei gummei;
	struct osmo_plmn_id plmn;
	bool pass = true;
	int rc;

	rc = osmo_parse_home_network_domain(&plmn, home_dom_valid);
	if (rc < 0)
		pass = false;
	printf("%s -> %s\n", home_dom_valid, osmo_plmn_name(&plmn));
	if (plmn.mcc != 901 || plmn.mnc != 70)
		pass = false;

	rc = osmo_parse_mme_domain(&gummei, mme_dom_valid);
	if (rc < 0)
		pass = false;
	printf("%s -> %s\n", mme_dom_valid, osmo_gummei_name(&gummei));
	if (gummei.plmn.mcc != 901 || gummei.plmn.mnc != 70 ||
	    gummei.mme.group_id != 0xA001 || gummei.mme.code != 1)
		pass = false;

	return pass;
}

int main(int argc, char **argv)
{
	bool pass = true;

	pass = pass && test_valid_imsi();
	pass = pass && test_valid_msisdn();
	pass = pass && test_valid_imei();
	pass = pass && test_mnc_from_str();
	pass = pass && test_gummei_name();
	pass = pass && test_domain_gen();
	pass = pass && test_domain_parse();

	OSMO_ASSERT(pass);

	return EXIT_SUCCESS;
}
