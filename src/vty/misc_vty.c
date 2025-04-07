/*
 * (C) 2025      by sysmocom - s.f.m.c. GmbH
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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

#include <stdlib.h>
#include <string.h>

#include "config.h"

#include <osmocom/core/osmo_io.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>

DEFUN(show_runtime, show_runtime_cmd,
      "show runtime",
      SHOW_STR "Display runtime information\n")
{
	enum osmo_io_backend io_backend = osmo_io_get_backend();
	vty_out(vty, "osmo-io backend: %s%s", osmo_io_backend_name(io_backend), VTY_NEWLINE);
	return CMD_SUCCESS;
}

void vty_misc_init(void)
{
	install_lib_element_ve(&show_runtime_cmd);
}
