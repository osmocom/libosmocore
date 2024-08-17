/*
 * This program is a test for osmo_efr_sid_classify().  It reads a set of
 * EFR codec frames in hex format (TS 101 318 RTP format represented in hex,
 * each frame as its own hex line) and feeds each test frame to
 * osmo_efr_sid_classify().  It then prints the output next to each input.
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

#include <osmocom/core/utils.h>
#include <osmocom/codec/codec.h>

static void process_record(const char *hex_str)
{
	uint8_t frame_bytes[GSM_EFR_BYTES];
	enum osmo_gsm631_sid_class sidc;

	osmo_hexparse(hex_str, frame_bytes, GSM_EFR_BYTES);
	sidc = osmo_efr_sid_classify(frame_bytes);
	printf("%s ==> %d\n", hex_str, (int) sidc);
}

static void process_line(char *linebuf, const char *infname, int lineno)
{
	char *cp = linebuf, *hex_str;
	int ndig;

	while (isspace(*cp))
		cp++;
	if (*cp == '\0' || *cp == '#')
		return;
	/* expect string of 62 hex digits */
	hex_str = cp;
	for (ndig = 0; ndig < GSM_EFR_BYTES * 2; ndig++) {
		if (!isxdigit(*cp))
			goto inv;
		cp++;
	}
	if (*cp) {
		if (!isspace(*cp))
			goto inv;
		*cp++ = '\0';
	}
	/* must be end of non-comment line */
	while (isspace(*cp))
		cp++;
	if (*cp != '\0' && *cp != '#')
		goto inv;

	process_record(hex_str);
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
