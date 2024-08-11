/*
 * This program is a test for osmo_hr_sid_classify().  It reads a set of
 * TCH/HS Rx bit patterns in TI DSP format (originally captured from a
 * Calypso MS under conditions of induced radio errors), converts each
 * bit pattern to TS 101 318 format (using same bit reordering function
 * as libosmocoding gsm0503 implementation), and feeds each test line
 * to osmo_hr_sid_classify().  It then prints the output next to each input.
 *
 * Author: Mychaela N. Falconia <falcon@freecalypso.org>, 2024 - however,
 * Mother Mychaela's contributions are NOT subject to copyright.
 * No rights reserved, all rights relinquished.
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
 */

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <osmocom/core/bits.h>
#include <osmocom/core/utils.h>
#include <osmocom/codec/codec.h>

#define	HR_CODEC_BITS	(GSM_HR_BYTES * 8)
#define	HR_BYTES_TIDSP	(GSM_HR_BYTES + 1)

/* re-arrange according to TS 05.03 Table 3a (receiver) */
/* function copied from src/coding/gsm0503_coding.c */
static void tch_hr_d_to_b(ubit_t *b_bits, const ubit_t *d_bits)
{
	int i;

	const uint16_t *map;

	if (!d_bits[93] && !d_bits[94])
		map = gsm620_unvoiced_bitorder;
	else
		map = gsm620_voiced_bitorder;

	for (i = 0; i < 112; i++)
		b_bits[map[i]] = d_bits[i];
}

static void process_record(const char *hex_str, bool bci_flag)
{
	uint8_t dsp_rx_bytes[HR_BYTES_TIDSP];
	ubit_t bits_transmission_order[HR_BYTES_TIDSP * 8];
	ubit_t bits_codec_order[HR_CODEC_BITS];
	uint8_t hr_bytes_ts101318[GSM_HR_BYTES];
	bool bfi_flag = false;
	enum osmo_gsm631_sid_class sidc;

	osmo_hexparse(hex_str, dsp_rx_bytes, HR_BYTES_TIDSP);
	osmo_pbit2ubit(bits_transmission_order, dsp_rx_bytes,
			HR_BYTES_TIDSP * 8);
	/* TI DSP format has a gap of 4 bits between class 1 and class 2
	 * portions - get rid of it.  95 is the number of class 1 bits,
	 * 17 is the number of class 2 bits. */
	memmove(bits_transmission_order + 95,
		bits_transmission_order + 95 + 4, 17);
	tch_hr_d_to_b(bits_codec_order, bits_transmission_order);
	osmo_ubit2pbit(hr_bytes_ts101318, bits_codec_order, HR_CODEC_BITS);

	sidc = osmo_hr_sid_classify(hr_bytes_ts101318, bci_flag, &bfi_flag);
	printf("%s %d ==> %d %d\n", hex_str, (int) bci_flag,
		(int) sidc, (int) bfi_flag);
}

static void process_line(char *linebuf, const char *infname, int lineno)
{
	char *cp = linebuf, *hex_str;
	int ndig;
	bool bci_flag;

	while (isspace(*cp))
		cp++;
	if (*cp == '\0' || *cp == '#')
		return;
	/* expect string of 30 hex digits */
	hex_str = cp;
	for (ndig = 0; ndig < HR_BYTES_TIDSP * 2; ndig++) {
		if (!isxdigit(*cp))
			goto inv;
		cp++;
	}
	if (!isspace(*cp))
		goto inv;
	*cp++ = '\0';
	while (isspace(*cp))
		cp++;
	/* 0 or 1 must follow, giving BCI flag */
	if (*cp == '0')
		bci_flag = false;
	else if (*cp == '1')
		bci_flag = true;
	else
		goto inv;
	cp++;
	/* must be end of non-comment line */
	while (isspace(*cp))
		cp++;
	if (*cp != '\0' && *cp != '#')
		goto inv;

	process_record(hex_str, bci_flag);
	return;

inv:	fprintf(stderr, "%s line %d: invalid syntax\n", infname, lineno);
	exit(1);
}

int main(int argc, char **argv)
{
	const char *infname;
	FILE *inf;
	char linebuf[128];
	int lineno;

	if (argc != 2) {
		fprintf(stderr, "usage: %s input-file\n", argv[0]);
		exit(1);
	}
	infname = argv[1];
	inf = fopen(infname, "r");
	if (!inf) {
		perror(infname);
		exit(1);
	}
	for (lineno = 1; fgets(linebuf, sizeof(linebuf), inf); lineno++)
		process_line(linebuf, infname, lineno);
	fclose(inf);
	exit(0);
}
