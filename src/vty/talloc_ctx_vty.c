/*! \file talloc_ctx_vty.c
 * Osmocom talloc context introspection via VTY. */
/*
 * (C) 2017 by Vadim Yanitskiy <axilirator@gmail.com>
 *
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
#include <regex.h>
#include <string.h>

#include <osmocom/core/talloc.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>

extern void *tall_vty_ctx;
extern struct host host;

enum walk_filter_type {
	WALK_FILTER_NONE = 0,
	WALK_FILTER_REGEXP,
	WALK_FILTER_TREE,
};

struct walk_cb_params {
	enum walk_filter_type filter;
	unsigned int depth_pass;
	const void *chunk_ptr;
	struct vty *vty;
	regex_t regexp;
};

/*!
 * Print a talloc memory hierarchy to the given VTY.
 * To be called by the talloc_report_depth_cb().
 * If one of supported filters is specified, then
 * only satisfying memory trees would be printed.
 *
 * @param chunk     The talloc chunk to be printed
 * @param depth     Current depth value
 * @param max_depth Maximal depth of report (negative means full)
 * @param is_ref    Is this chunk a reference?
 * @param data      The walk_cb_params struct instance
 */
static void talloc_ctx_walk_cb(const void *chunk, int depth,
	int max_depth, int is_ref, void *data)
{
	struct walk_cb_params *p = (struct walk_cb_params *) data;
	const char *chunk_name = talloc_get_name(chunk);
	struct vty *vty = p->vty;
	size_t chunk_blocks;
	size_t chunk_size;
	int rc;

	if (depth > 0 && p->filter) {
		/**
		 * A filter is being bypassed while current depth value
		 * is higher than the 'depth_pass', i.e. the callback does
		 * processing the child memory chunks. As soon as this
		 * condition becomes false, we need to 'enable' a filter,
		 * and resume the processing other chunks.
		 */
		if (p->depth_pass && depth > p->depth_pass)
			goto filter_bypass;
		else
			p->depth_pass = 0;

		switch (p->filter) {
		case WALK_FILTER_REGEXP:
			/* Filter chunks using a regular expression */
			rc = regexec(&p->regexp, chunk_name, 0, NULL, 0);
			if (rc)
				return;
			break;
		case WALK_FILTER_TREE:
			/* Print a specific memory tree only */
			if (chunk != p->chunk_ptr)
				return;
			break;
		default:
			/* Unsupported filter or incorrect value */
			return;
		}

		/**
		 * As soon as a filter passes any chunk, all the memory
		 * tree starting from one would be printed. To do that,
		 * we need to temporary 'disable' a filter for child
		 * chunks (current_depth > depth_pass).
		 */
		p->depth_pass = depth;
	}

filter_bypass:

	if (is_ref) {
		vty_out(vty, "%*sreference to: %s%s",
			depth * 2, "", chunk_name, VTY_NEWLINE);
		return;
	}

	chunk_blocks = talloc_total_blocks(chunk);
	chunk_size = talloc_total_size(chunk);

	if (depth == 0) {
		vty_out(vty, "%stalloc report on '%s' "
			"(total %6zu bytes in %3zu blocks)%s",
			(max_depth < 0 ? "full " : ""), chunk_name,
			chunk_size, chunk_blocks, VTY_NEWLINE);
		return;
	}

	vty_out(vty, "%*s%-30s contains %6zu bytes "
		"in %3zu blocks (ref %zu) %p%s", depth * 2, "",
		chunk_name, chunk_size, chunk_blocks,
		talloc_reference_count(chunk),
		chunk, VTY_NEWLINE);
}

/*!
 * Parse talloc context and depth values from a VTY command.
 *
 * @param ctx    The context to be printed (a string from argv)
 * @param depth  The report depth (a string from argv)
 * @param params The walk_cb_params struct instance
 */
static void talloc_ctx_walk(const char *ctx, const char *depth,
	struct walk_cb_params *params)
{
	const void *talloc_ctx = NULL;
	int max_depth;

	/* Determine a context for report */
	if (!strncmp(ctx, "app", 3))
		talloc_ctx = host.app_info->tall_ctx;
	else if (!strcmp(ctx, "global"))
		talloc_ctx = OTC_GLOBAL;
	else if (!strncmp(ctx, "all", 3))
		talloc_ctx = NULL;

	/* Determine report depth */
	if (depth[0] == 'f')
		max_depth = -1;
	else if (depth[0] == 'b')
		max_depth = 1;
	else
		max_depth = atoi(depth);

	talloc_report_depth_cb(talloc_ctx, 0, max_depth,
		&talloc_ctx_walk_cb, params);
}

#define BASE_CMD_STR \
	"show talloc-context (application|global|all) (full|brief|DEPTH)"

#define BASE_CMD_DESCR \
	SHOW_STR "Show talloc memory hierarchy\n" \
	"Application's context\n" \
	"Global context (OTC_GLOBAL)\n" \
	"All contexts, if NULL-context tracking is enabled\n" \
	"Display a full talloc memory hierarchy\n" \
	"Display a brief talloc memory hierarchy\n" \
	"Specify required maximal depth value\n"

DEFUN(show_talloc_ctx, show_talloc_ctx_cmd,
	BASE_CMD_STR, BASE_CMD_DESCR)
{
	struct walk_cb_params params = { 0 };

	/* Set up callback parameters */
	params.filter = WALK_FILTER_NONE;
	params.vty = vty;

	talloc_ctx_walk(argv[0], argv[1], &params);
	return CMD_SUCCESS;
}

DEFUN(show_talloc_ctx_filter, show_talloc_ctx_filter_cmd,
	BASE_CMD_STR " filter REGEXP", BASE_CMD_DESCR
	"Filter chunks using regular expression\n"
	"Regular expression\n")
{
	struct walk_cb_params params = { 0 };
	int rc;

	/* Attempt to compile a regular expression */
	rc = regcomp(&params.regexp, argv[2], REG_NOSUB);
	if (rc) {
		vty_out(vty, "Invalid expression%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Set up callback parameters */
	params.filter = WALK_FILTER_REGEXP;
	params.vty = vty;

	talloc_ctx_walk(argv[0], argv[1], &params);
	regfree(&params.regexp);

	return CMD_SUCCESS;
}

DEFUN(show_talloc_ctx_tree, show_talloc_ctx_tree_cmd,
	BASE_CMD_STR " tree ADDRESS", BASE_CMD_DESCR
	"Display only a specific memory chunk\n"
	"Chunk address (e.g. 0xdeadbeef)\n")
{
	struct walk_cb_params params = { 0 };
	int rc;

	/* Attempt to parse an address */
	rc = sscanf(argv[2], "%p", &params.chunk_ptr);
	if (rc != 1) {
		vty_out(vty, "Invalid chunk address%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Set up callback parameters */
	params.filter = WALK_FILTER_TREE;
	params.vty = vty;

	talloc_ctx_walk(argv[0], argv[1], &params);
	return CMD_SUCCESS;
}

/*!
 * Install VTY commands for talloc context introspection.
 *
 * This installs a set of VTY commands for introspection of
 * a talloc context. Call this once from your application
 * if you want to support those commands.
 */
void osmo_talloc_vty_add_cmds(void)
{
	install_lib_element_ve(&show_talloc_ctx_cmd);
	install_lib_element_ve(&show_talloc_ctx_tree_cmd);
	install_lib_element_ve(&show_talloc_ctx_filter_cmd);
}
