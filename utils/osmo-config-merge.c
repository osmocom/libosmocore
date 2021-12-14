/*! \file osmo-config-merge.c
 * Utility program for merging config files with patches */
/*
 * (C) 2018 by Harald Welte <laforge@gnumonks.org>
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
 */

/*
    This utility allows you to merge an incremental config "patch"
    into an osmocom-style config file.

    The patch file follows the same syntax as the original config file.

    It works by appending the leaf nodes of the patch file to the respective
    nodes of the input config file.

    This process allows configuration file changes/updates to be performed
    in a more stable/reliable way than by means of [unified] diff files,
    as they break every time the context lines break.

    osmo-config-merge doesn't suffer from this problem, as it understands
    the tree-like nature of VTY config files.

    NITE: This only works with configuration files that have proper
    indenting, i.e. every level in the hierarchy must be indented excatly
    one character, not multiple.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgfile.h>

struct node {
	struct node *parent;		/* back-pointer */
	struct llist_head list;		/* part of parent->children */
	struct llist_head children;	/* our own children */
	char *line;
};

struct osmo_patch_entry {
	struct llist_head list;
	struct node *tree;
};

/* allocate a new node */
static struct node *node_alloc(void *ctx)
{
	struct node *node = talloc_zero(ctx, struct node);
	OSMO_ASSERT(node);
	INIT_LLIST_HEAD(&node->children);
	return node;
}

/* allocate a new node as child of given parent */
static struct node *node_alloc_child(struct node *parent)
{
	struct node *node = node_alloc(parent);
	node->parent = parent;
	llist_add_tail(&node->list, &parent->children);
	return node;
}

/* find a given child specified by name/line string within given parent */
static struct node *node_find_child(struct node *parent, const char *line)
{
	struct node *n;

	llist_for_each_entry(n, &parent->children, list) {
		if (!strcmp(line, n->line))
			return n;
	}
	return NULL;
}

/* count the number of spaces / indent level */
static int count_indent(const char *line)
{
	int i;

	for (i = 0; i < strlen(line); i++) {
		if (line[i] != ' ')
			return i;
	}
	return i;
}

/* strip any triling CR / LF */
static void chomp(char *line)
{
	while (1) {
		int len = strlen(line);
		if (len == 0)
			return;
		char *lastch = &line[len-1];
		switch (*lastch) {
		case '\n':
		case '\r':
			*lastch = '\0';
		default:
			return;
		}
	}
}

/* read a config file and parse it into a tree of nodes */
static struct node *file_read(void *ctx, const char *fname)
{
	struct node *root, *last;
	FILE *infile;
	char line[1024];
	int cur_indent = -1;
	unsigned int line_num = 0;

	infile = fopen(fname, "r");
	if (!infile) {
		fprintf(stderr, "Could not open file '%s': %s\n",
			fname, strerror(errno));
		return NULL;
	}

	root = node_alloc(ctx);
	last = root;
	while (fgets(line, sizeof(line), infile)) {
		line_num++;
		chomp(line);
		int indent = count_indent(line);
		struct node *n;
		if (indent > cur_indent) {
			if (indent > cur_indent+1) {
				fprintf(stderr, "File '%s' isn't well-formed in line %u, aborting!\n",
					fname, line_num);
				fclose(infile);
				return NULL;
			}
			/* new child to last node */
			n = node_alloc_child(last);
		} else if (indent < cur_indent) {
			int i;
			for (i = 0; i < cur_indent - indent; i++) {
				/* go to parent, add another sibling */
				if (last->parent)
					last = last->parent;
			}
			n = node_alloc_child(last->parent);
		} else {
			/* add a new sibling (child of parent) */
			n = node_alloc_child(last->parent);
		}
		n->line = talloc_strdup(n, line);

		last = n;
		cur_indent = indent;
	}

	fclose(infile);
	return root;
}

static void append_patch(struct node *cfg, struct node *patch)
{
	struct node *n;

	llist_for_each_entry(n, &patch->children, list) {
		if (llist_empty(&n->children)) {
			struct node *t;
			/* we are an end-node, i.e. something that needs to be
			 * patched into the original tree.  We do this by simply
			 * appending it to the list of siblings */
			t = node_alloc_child(cfg);
			t->line = talloc_strdup(t, n->line);
		} else {
			struct node *c;
			/* we need to iterate / recurse further */

			/* try to find the matching original node */
			c = node_find_child(cfg, n->line);
			if (!c) {
				/* create it, if it's missing */
				c = node_alloc_child(cfg);
				c->line = talloc_strdup(c, n->line);
			}
			append_patch(c, n);
		}
	}
}


static int level = -1;

static void dump_node(struct node *root, FILE *out, bool print_node_depth)
{
	struct node *n;
	level++;

	if (root->line) {
		if (print_node_depth) {
			int i;
			for (i = 0; i < level; i++)
				fputc('*', out);
		}

		fprintf(out, "%s\n", root->line);
	}

	llist_for_each_entry(n, &root->children, list) {
		dump_node(n, out, print_node_depth);
	}
	level--;
}

static void exit_usage(int rc)
{
	fprintf(stderr, "Usage: osmo-config-merge <config-file> <config-patch>...<config-patch> [--debug]\n");
	exit(rc);
}


int main(int argc, char **argv)
{
	struct node *base_tree;
	struct osmo_config_list *trees;
	struct osmo_patch_entry *entry;
	bool debug_enabled = false;
	unsigned i;
	void *ctx;

	if (argc < 3)
		exit_usage(1);

	ctx = talloc_named_const(NULL, 0, "root");

	base_tree = file_read(ctx, argv[1]);
	trees = talloc_zero(ctx, struct osmo_config_list);
	if (!base_tree || !trees) {
		talloc_free(ctx);
		return 2;
	}

	INIT_LLIST_HEAD(&trees->entry);
	for (i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "--debug"))
			debug_enabled = true;
		else {
			entry = talloc_zero(trees, struct osmo_patch_entry);
			if (!entry) {
				talloc_free(ctx);
				return 3;
			}

			entry->tree = file_read(ctx, argv[i]);
			if (!entry->tree) {
				talloc_free(ctx);
				return 4;
			}
			llist_add_tail(&entry->list, &trees->entry);
		}
	}

	if (llist_empty(&trees->entry))
		exit_usage(1);

	if (debug_enabled) {
		fprintf(stderr, "====== dumping tree (base)\n");
		dump_node(base_tree, stderr, true);
	}

	llist_for_each_entry(entry, &trees->entry, list) {
		append_patch(base_tree, entry->tree);
		if (debug_enabled) {
			fprintf(stderr, "====== dumping tree (patch)\n");
			dump_node(entry->tree, stderr, true);
		}
	}

	if (debug_enabled)
		fprintf(stderr, "====== dumping tree (patched)\n");
	dump_node(base_tree, stdout, false);
	fflush(stdout);

	/* make AddressSanitizer / LeakSanitizer happy by recursively freeing the trees */
	talloc_free(trees);
	talloc_free(base_tree);
	talloc_free(ctx);

	return 0;
}
