/*
 * (C) 2008 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2011 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * Authors: Holger Hans Peter Freyther <zecke@selfish.org>
 *	    Pablo Neira Ayuso <pablo@gnumonks.org>
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer_compat.h>

int main(int argc, char *argv[])
{

	struct timespec ts1 = { 123, 456 }, ts2 = {1, 200};
	struct timespec read1, read2, res;
	struct timespec *mono;

	osmo_clock_gettime(CLOCK_BOOTTIME, &read1);
	usleep(500);
	osmo_clock_gettime(CLOCK_BOOTTIME, &read2);
	if (!timespeccmp(&read2, &read1, >))
		return EXIT_FAILURE;
	printf("Non implemented clocks work fine\n");

	osmo_clock_gettime(CLOCK_MONOTONIC, &read1);
	usleep(500);
	osmo_clock_gettime(CLOCK_MONOTONIC, &read2);
	if (!timespeccmp(&read2, &read1, >))
		return EXIT_FAILURE;
	printf("Monotonic clock is working fine by default\n");

	osmo_clock_override_enable(CLOCK_MONOTONIC, true);
	printf("Monotonic clock override enabled\n");

	mono = osmo_clock_override_gettimespec(CLOCK_MONOTONIC);
	if (timespecisset(mono))
		return EXIT_FAILURE;
	printf("Monotonic override is cleared by default\n");

	memcpy(mono, &ts1, sizeof(struct timespec));
	osmo_clock_gettime(CLOCK_MONOTONIC, &read1);
	if (!timespeccmp(&ts1, &read1, ==))
		return EXIT_FAILURE;
	printf("Monotonic clock can be overriden\n");

	osmo_clock_override_add(CLOCK_MONOTONIC, ts2.tv_sec, ts2.tv_nsec);
	osmo_clock_gettime(CLOCK_MONOTONIC, &read1);
	timespecadd(&ts2, &ts1, &res);
	if (!timespeccmp(&res, &read1, ==))
		return EXIT_FAILURE;
	printf("osmo_clock_override_add works fine.\n");

	osmo_clock_override_enable(CLOCK_MONOTONIC, false);
	printf("Monotonic clock override disabled\n");

	osmo_clock_gettime(CLOCK_MONOTONIC, &read1);
	usleep(500);
	osmo_clock_gettime(CLOCK_MONOTONIC, &read2);
	if (!timespeccmp(&read2, &read1, >))
		return EXIT_FAILURE;
	printf("Monotonic clock is working fine after enable+disable.\n");

	return 0;
}
