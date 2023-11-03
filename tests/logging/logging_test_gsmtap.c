/* simple test for gsmtap logging */
/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
 */

#include <osmocom/core/select.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>

#include <stdlib.h>

static const struct log_info_cat default_categories[] = {};

const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

extern struct log_info *osmo_log_info;

int main(int argc, char **argv)
{
	struct log_target *stderr_target;
	struct log_target *gsmtap_target;

	log_init(&log_info, NULL);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);
	log_set_all_filter(stderr_target, 1);
	log_set_print_filename2(stderr_target, LOG_FILENAME_NONE);
	log_set_print_category_hex(stderr_target, 0);
	log_set_print_category(stderr_target, 1);
	log_set_use_color(stderr_target, 0);
	log_parse_category_mask(stderr_target, "DLGLOBAL,1");

	gsmtap_target = log_target_create_gsmtap("127.0.0.2", 4729, "gsmtap", 1, 1);
	log_add_target(gsmtap_target);
	log_set_all_filter(gsmtap_target, 1);
	log_parse_category_mask(gsmtap_target, "DLGLOBAL,1");

	log_target_file_switch_to_stream(stderr_target);

	log_set_category_filter(stderr_target, DLIO, 1, LOGL_DEBUG);

	for (int i = 0; i < 200; i++)
		DEBUGP(DLGLOBAL, "Repeating message (i = %d)\n", i);

	for (int i = 0; i < 200; i++)
		osmo_select_main(1);

	return 0;
}
