/*! \file tdef_vty.c
 * Implementation to configure osmo_tdef Tnnn timers from VTY configuration.
 */
/* (C) 2018-2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPLv2+
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/tdef_vty.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/fsm.h>

/*! \addtogroup Tdef_VTY
 *
 * VTY API for \ref Tdef.
 *
 * @{
 * \file tdef_vty.c
 */

/*! Parse an argument like "1234", "T1234", "t1234", or "X1234", "x1234", as from OSMO_TDEF_VTY_ARG_T.
 * \param[in] vty  VTY context for vty_out() of error messages.
 * \param[in] tdefs  Array of timer definitions to look up T timer.
 * \param[in] T_str  Argument string. It is not validated, expected to be checked by VTY input.
 * \return the corresponding osmo_tdef entry from the tdefs array, or NULL if no such entry exists.
 */
struct osmo_tdef *osmo_tdef_vty_parse_T_arg(struct vty *vty, struct osmo_tdef *tdefs, const char *T_str)
{
	int l;
	int T;
	struct osmo_tdef *t;
	const char *T_nr_str;
	int sign = 1;

	if (!tdefs) {
		vty_out(vty, "%% Error: no timers found%s", VTY_NEWLINE);
		return NULL;
	}

	T_nr_str = T_str;
	if (T_nr_str[0] == 't' || T_nr_str[0] == 'T') {
		sign = 1;
		T_nr_str++;
	} else if (T_nr_str[0] == 'x' || T_nr_str[0] == 'X') {
		T_nr_str++;
		sign = -1;
	}

	/* Make sure to disallow any characters changing the signedness of the parsed int */
	if (T_nr_str[0] < '0' || T_nr_str[0] > '9') {
		vty_out(vty, "%% Invalid T timer argument (should be 'T1234' or 'X1234'): '%s'%s", T_str, VTY_NEWLINE);
		return NULL;
	}

	if (osmo_str_to_int(&l, T_nr_str, 10, 0, INT_MAX)) {
		vty_out(vty, "%% Invalid T timer argument (should be 'T1234' or 'X1234'): '%s'%s", T_str, VTY_NEWLINE);
		return NULL;
	}
	T = l * sign;

	t = osmo_tdef_get_entry(tdefs, T);
	if (!t)
		vty_out(vty, "%% No such timer: " OSMO_T_FMT "%s", OSMO_T_FMT_ARGS(T), VTY_NEWLINE);
	return t;
}

/*! Parse an argument of the form "(0-2147483647|default)", as from OSMO_TDEF_VTY_ARG_VAL.
 * \param[in] val_arg  Argument string (not format checked).
 * \param[in] default_val  Value to return in case of val_arg being "default".
 * \return Parsed value or default_val.
 */
unsigned long osmo_tdef_vty_parse_val_arg(const char *val_arg, unsigned long default_val)
{
        if (!strcmp(val_arg, "default"))
                return default_val;
	return atoll(val_arg);
}

/*! Apply a timer configuration from VTY argument strings.
 * Employ both osmo_tdef_vty_parse_T_arg() and osmo_tdef_vty_parse_val_arg() to configure a T timer in an array of
 * tdefs. Evaluate two arguments, a "T1234" argument and a "(0-2147483647|default)" argument, as from
 * OSMO_TDEF_VTY_ARGS.  If the T timer given in the first argument is found in tdefs, set it to the value given in the
 * second argument.
 * \param[in] vty  VTY context for vty_out() of error messages.
 * \param[in] tdefs  Array of timer definitions to look up T timer.
 * \param[in] args  Array of string arguments like { "T1234", "23" }.
 * \return CMD_SUCCESS, or CMD_WARNING if no such timer is found in tdefs.
 */
int osmo_tdef_vty_set_cmd(struct vty *vty, struct osmo_tdef *tdefs, const char **args)
{
	unsigned long new_val;
	const char *T_arg = args[0];
	const char *val_arg = args[1];
	struct osmo_tdef *t = osmo_tdef_vty_parse_T_arg(vty, tdefs, T_arg);
	if (!t)
		return CMD_WARNING;
	new_val = osmo_tdef_vty_parse_val_arg(val_arg, t->default_val);

	if (!osmo_tdef_val_in_range(t, new_val)) {
		char range_str[64];
		osmo_tdef_range_str_buf(range_str, sizeof(range_str), t);
		vty_out(vty, "%% Timer " OSMO_T_FMT " value %lu is out of range %s%s",
		        OSMO_T_FMT_ARGS(t->T), new_val, range_str, VTY_NEWLINE);
		return CMD_WARNING;
	}
	t->val = new_val;
	return CMD_SUCCESS;
}

/*! Output one or all timers to the VTY, as for a VTY command like 'show timer [TNNNN]'.
 * If T_arg is NULL, print all timers in tdefs to the VTY.
 * If T_arg is not NULL, employ osmo_tdef_vty_parse_T_arg() to select one timer from tdefs and print only that to the
 * VTY.
 * \param[in] vty  VTY context for vty_out() of error messages.
 * \param[in] tdefs  Array of timer definitions.
 * \param[in] T_arg  Argument string like "T1234", or NULL.
 * \param[in] prefix_fmt  Arbitrary string to start each line with, with variable printf like arguments.
 * \return CMD_SUCCESS, or CMD_WARNING if no such timer is found in tdefs.
 */
int osmo_tdef_vty_show_cmd(struct vty *vty, struct osmo_tdef *tdefs, const char *T_arg,
			   const char *prefix_fmt, ...)
{
	va_list va;
	if (T_arg) {
		struct osmo_tdef *t = osmo_tdef_vty_parse_T_arg(vty, tdefs, T_arg);
		if (!t)
			return CMD_WARNING;
		va_start(va, prefix_fmt);
		osmo_tdef_vty_out_one_va(vty, t, prefix_fmt, va);
		va_end(va);
	} else {
		va_start(va, prefix_fmt);
		osmo_tdef_vty_out_all_va(vty, tdefs, prefix_fmt, va);
		va_end(va);
	}
	return CMD_SUCCESS;
}

/*! Write to VTY the current status of one timer.
 * \param[in] vty  VTY context for vty_out().
 * \param[in] t  The timer to print.
 * \param[in] prefix_fmt  Arbitrary string to start each line with, with variable vprintf like arguments.
 * \param[in] va  va_list instance. As always, call va_start() before, and va_end() after this call.
 */
void osmo_tdef_vty_out_one_va(struct vty *vty, struct osmo_tdef *t, const char *prefix_fmt, va_list va)
{
	char range_str[64];

	if (!t) {
		vty_out(vty, "%% Error: no such timer%s", VTY_NEWLINE);
		return;
	}
	if (prefix_fmt)
		vty_out_va(vty, prefix_fmt, va);

	vty_out(vty, OSMO_T_FMT " = %lu", OSMO_T_FMT_ARGS(t->T), t->val);
	if (t->unit != OSMO_TDEF_CUSTOM)
		vty_out(vty, " %s", osmo_tdef_unit_name(t->unit));

	vty_out(vty, "\t%s (default: %lu", t->desc, t->default_val);
	if (t->unit != OSMO_TDEF_CUSTOM)
		vty_out(vty, " %s", osmo_tdef_unit_name(t->unit));

	if (t->min_val || t->max_val) {
		osmo_tdef_range_str_buf(range_str, sizeof(range_str), t);
		vty_out(vty, ", range: %s", range_str);
	}

	vty_out(vty, ")%s", VTY_NEWLINE);
}

/*! Write to VTY the current status of one timer.
 * \param[in] vty  VTY context for vty_out().
 * \param[in] t  The timer to print.
 * \param[in] prefix_fmt  Arbitrary string to start each line with, with variable printf like arguments.
 */
void osmo_tdef_vty_out_one(struct vty *vty, struct osmo_tdef *t, const char *prefix_fmt, ...)
{
	va_list va;
	va_start(va, prefix_fmt);
	osmo_tdef_vty_out_one_va(vty, t, prefix_fmt, va);
	va_end(va);
}

/*! Write to VTY the current status of all given timers.
 * \param[in] vty  VTY context for vty_out().
 * \param[in] tdefs  Array of timers to print, ended with a fully zero-initialized entry.
 * \param[in] prefix_fmt  Arbitrary string to start each line with, with variable vprintf like arguments.
 * \param[in] va  va_list instance. As always, call va_start() before, and va_end() after this call.
 */
void osmo_tdef_vty_out_all_va(struct vty *vty, struct osmo_tdef *tdefs, const char *prefix_fmt, va_list va)
{
	struct osmo_tdef *t;
	if (!tdefs) {
		vty_out(vty, "%% Error: no such timers%s", VTY_NEWLINE);
		return;
	}
	osmo_tdef_for_each(t, tdefs) {
		va_list va2;
		va_copy(va2, va);
		osmo_tdef_vty_out_one_va(vty, t, prefix_fmt, va);
		va_end(va2);
	}
}

/*! Write to VTY the current status of all given timers.
 * \param[in] vty  VTY context for vty_out().
 * \param[in] tdefs  Array of timers to print, ended with a fully zero-initialized entry.
 * \param[in] prefix_fmt  Arbitrary string to start each line with, with variable printf like arguments.
 */
void osmo_tdef_vty_out_all(struct vty *vty, struct osmo_tdef *tdefs, const char *prefix_fmt, ...)
{
	va_list va;
	va_start(va, prefix_fmt);
	osmo_tdef_vty_out_all_va(vty, tdefs, prefix_fmt, va);
	va_end(va);
}

/*! Write current timer configuration arguments to the vty. Skip all entries that reflect their default value.
 * The passed prefix string must contain both necessary indent and the VTY command the specific implementation is using.
 * See tdef_vty_test_config_subnode.c and tdef_vty_test_dynamic.c for examples.
 * \param[in] vty  VTY context.
 * \param[in] tdefs  Array of timers to print, ended with a fully zero-initialized entry.
 * \param[in] prefix_fmt  Arbitrary string to start each line with, with variable printf like arguments.
 */
void osmo_tdef_vty_write(struct vty *vty, struct osmo_tdef *tdefs, const char *prefix_fmt, ...)
{
	va_list va;
	struct osmo_tdef *t;
	osmo_tdef_for_each(t, tdefs) {
		if (t->val == t->default_val)
			continue;
		if (prefix_fmt && *prefix_fmt) {
			va_start(va, prefix_fmt);
			vty_out_va(vty, prefix_fmt, va);
			va_end(va);
		}
		vty_out(vty, OSMO_T_FMT " %lu%s", OSMO_T_FMT_ARGS(t->T), t->val, VTY_NEWLINE);
	}
}

/*! Singleton Tnnn groups definition as set by osmo_tdef_vty_groups_init(). */
static struct osmo_tdef_group *global_tdef_groups;

DEFUN(show_timer, show_timer_cmd, "DYNAMIC", "DYNAMIC")
      /* show timer [(alpha|beta|gamma)] [TNNNN] */
{
	const char *group_arg = argc > 0 ? argv[0] : NULL;
	const char *T_arg = argc > 1 ? argv[1] : NULL;
	struct osmo_tdef_group *g;

	/* The argument should be either "tea" or "software", but the VTY also allows partial arguments
	 * like "softw" or "t" (which can also be ambiguous). */

	osmo_tdef_groups_for_each(g, global_tdef_groups) {
		if (!group_arg || osmo_str_startswith(g->name, group_arg))
			osmo_tdef_vty_show_cmd(vty, g->tdefs, T_arg, "%s: ", g->name);
	}
	return CMD_SUCCESS;
}

DEFUN(cfg_timer, cfg_timer_cmd, "DYNAMIC", "DYNAMIC")
      /* show timer [(alpha|beta|gamma)] [TNNNN] [(<0-2147483647>|default)] */
{
	const char *group_arg;
	const char **timer_args;
	struct osmo_tdef *tdefs = NULL;
	struct osmo_tdef_group *g = NULL;

	/* If any arguments are missing, redirect to 'show' */
	if (argc < 3)
		return show_timer(self, vty, argc, argv);

	/* If all arguments are passed, this is configuring a timer. */
	group_arg = argv[0];
	timer_args = argv + 1;
	osmo_tdef_groups_for_each(g, global_tdef_groups) {
		if (strcmp(g->name, group_arg))
			continue;
		if (tdefs) {
			vty_out(vty, "%% Error: ambiguous timer group match%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		tdefs = g->tdefs;
	}

	return osmo_tdef_vty_set_cmd(vty, tdefs, timer_args);
}

static char *add_group_args(void *talloc_ctx, char *dest)
{
	struct osmo_tdef_group *g;
	osmo_talloc_asprintf(talloc_ctx, dest, "[(");
	osmo_tdef_groups_for_each(g, global_tdef_groups) {
		osmo_talloc_asprintf(talloc_ctx, dest, "%s%s",
				     (g == global_tdef_groups) ? "" : "|",
				     g->name);
	}
	osmo_talloc_asprintf(talloc_ctx, dest, ")]");
	return dest;
}

static char *add_group_docs(void *talloc_ctx, char *dest)
{
	struct osmo_tdef_group *g;
	osmo_tdef_groups_for_each(g, global_tdef_groups) {
		osmo_talloc_asprintf(talloc_ctx, dest, "%s\n", g->desc);
	}
	return dest;
}

static char *timer_command_string(const char *prefix, const char *suffix)
{
	char *dest = NULL;
	osmo_talloc_asprintf(tall_vty_cmd_ctx, dest, "%s ", prefix);
	dest = add_group_args(tall_vty_cmd_ctx, dest);
	osmo_talloc_asprintf(tall_vty_cmd_ctx, dest, " %s", suffix);
	return dest;
}

static char *timer_doc_string(const char *prefix, const char *suffix)
{
	char *dest = NULL;
	osmo_talloc_asprintf(tall_vty_cmd_ctx, dest, "%s ", prefix);
	dest = add_group_docs(tall_vty_cmd_ctx, dest);
	osmo_talloc_asprintf(tall_vty_cmd_ctx, dest, " %s", suffix);
	return dest;
}

/*! Convenience implementation for keeping a fixed set of timer groups in a program.
 * Install a 'timer [(group|names|...)] [TNNN] [(<val>|default)]' command under the given parent_node,
 * and install a 'show timer...' command on VIEW_NODE and ENABLE_NODE.
 * For a usage example, see \ref tdef_test_config_root.c.
 * The given timer definitions group is stored in a global pointer, so this can be done only once per main() scope.
 * It would also be possible to have distinct timer groups on separate VTY subnodes, with a "manual" implementation, but
 * not with this API.
 * \param[in] parent_cfg_node  VTY node at which to add the timer configuration commands, e.g. CONFIG_NODE.
 * \param[in] groups  Global timer groups definition.
 */
void osmo_tdef_vty_groups_init(unsigned int parent_cfg_node, struct osmo_tdef_group *groups)
{
	struct osmo_tdef_group *g;
	OSMO_ASSERT(!global_tdef_groups);
	global_tdef_groups = groups;

	osmo_tdef_groups_for_each(g, global_tdef_groups)
		osmo_tdefs_reset(g->tdefs);

	show_timer_cmd.string = timer_command_string("show timer", OSMO_TDEF_VTY_ARG_T_OPTIONAL);
	show_timer_cmd.doc = timer_doc_string(SHOW_STR "Show timers\n", OSMO_TDEF_VTY_DOC_T);

	cfg_timer_cmd.string = timer_command_string("timer", OSMO_TDEF_VTY_ARG_SET_OPTIONAL);
	cfg_timer_cmd.doc = timer_doc_string("Configure or show timers\n", OSMO_TDEF_VTY_DOC_SET);

	install_lib_element_ve(&show_timer_cmd);
	install_lib_element(parent_cfg_node, &cfg_timer_cmd);
}

/*! Write the global osmo_tdef_group configuration to VTY, as previously passed to osmo_tdef_vty_groups_init().
 * \param[in] vty  VTY context.
 * \param[in] indent  String to print before each line.
 */
void osmo_tdef_vty_groups_write(struct vty *vty, const char *indent)
{
	struct osmo_tdef_group *g;
	osmo_tdef_groups_for_each(g, global_tdef_groups)
		osmo_tdef_vty_write(vty, g->tdefs, "%stimer %s ", indent ? : "", g->name);
}

/*! @} */
