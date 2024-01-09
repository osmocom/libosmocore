/*
 * (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2014 by Holger Hans Peter Freyther
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

#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/logging_internal.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/strrb.h>
#include <osmocom/core/loggingrb.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/core/application.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>

#define LOG_STR "Configure logging sub-system\n"
#define LEVEL_STR "Set the log level for a specified category\n"

#define CATEGORY_ALL_STR "Deprecated alias for 'force-all'\n"
#define FORCE_ALL_STR \
	"Globally force all logging categories to a specific level. This is released by the" \
	" 'no logging level force-all' command. Note: any 'logging level <category> <level>'" \
	" commands will have no visible effect after this, until the forced level is released.\n"
#define NO_FORCE_ALL_STR \
	"Release any globally forced log level set with 'logging level force-all <level>'\n"

#define LOG_LEVEL_ARGS "(debug|info|notice|error|fatal)"
#define LOG_LEVEL_STRS \
	"Log debug messages and higher levels\n" \
	"Log informational messages and higher levels\n" \
	"Log noticeable messages and higher levels\n" \
	"Log error messages and higher levels\n" \
	"Log only fatal messages\n"

#define EVERYTHING_STR "Deprecated alias for 'no logging level force-all'\n"

/*! \file logging_vty.c
 *  Configuration of logging from VTY
 *
 *  This module implements
 *  - functions that permit configuration of the libosmocore logging
 *    framework from VTY commands in the configure -> logging node.
 *
 *  - functions that permit logging *to* a VTY session.  Basically each
 *    VTY session gets its own log target, with configurable
 *    per-subsystem log levels.  This is performed internally via the
 *    \ref log_target_create_vty function.
 *
 *  You have to call \ref logging_vty_add_cmds from your application
 *  once to enable both of the above.
 *
 */

static void _vty_output(struct log_target *tgt,
			unsigned int level, const char *line)
{
	struct vty *vty = tgt->tgt_vty.vty;
	vty_out(vty, "%s", line);
	/* This is an ugly hack, but there is no easy way... */
	if (strchr(line, '\n'))
		vty_out(vty, "\r");
}

struct log_target *log_target_create_vty(struct vty *vty)
{
	struct log_target *target;

	target = log_target_create();
	if (!target)
		return NULL;

	target->tgt_vty.vty = vty;
	target->output = _vty_output;
	return target;
}

/*! Get tgt with log lock acquired, return and release lock with warning if tgt
 *  is not found. Lock must be released later with log_tgt_mutex_unlock().
 */
#define ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt) \
	do { \
		log_tgt_mutex_lock(); \
		tgt = osmo_log_vty2tgt(vty); \
		if (!(tgt)) { \
			log_tgt_mutex_unlock(); \
			return CMD_WARNING; \
		} \
	} while (0)

#define RET_WITH_UNLOCK(ret) \
	do { \
		log_tgt_mutex_unlock(); \
		return (ret); \
	} while (0)

DEFUN(enable_logging,
      enable_logging_cmd,
      "logging enable",
	LOGGING_STR
      "Enables logging to this vty\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (conn->dbg) {
		vty_out(vty, "%% Logging already enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	conn->dbg = log_target_create_vty(vty);
	if (!conn->dbg)
		return CMD_WARNING;
	log_tgt_mutex_lock();
	log_add_target(conn->dbg);
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

/*! Get log target associated to VTY console.
 *  \param[in] vty Log target type
 *  \returns Log target (if logging enabled), NULL otherwise
 *  Must be called with mutex osmo_log_tgt_mutex held, see log_tgt_mutex_lock.
 */
struct log_target *osmo_log_vty2tgt(struct vty *vty)
{
	struct telnet_connection *conn;

	if (vty->node == CFG_LOG_NODE)
		return vty->index;


	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg)
		vty_out(vty, "%% Logging was not enabled.%s", VTY_NEWLINE);

	return conn->dbg;
}

DEFUN(logging_fltr_all,
      logging_fltr_all_cmd,
      "logging filter all (0|1)",
	LOGGING_STR FILTER_STR
	"Do you want to log all messages?\n"
	"Only print messages matched by other filters\n"
	"Bypass filter and print all messages\n")
{
	struct log_target *tgt;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_set_all_filter(tgt, atoi(argv[0]));
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(logging_use_clr,
      logging_use_clr_cmd,
      "logging color (0|1)",
	LOGGING_STR "Configure color-printing for log messages\n"
      "Don't use color for printing messages\n"
      "Use color for printing messages\n")
{
	struct log_target *tgt;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_set_use_color(tgt, atoi(argv[0]));
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(logging_prnt_timestamp,
      logging_prnt_timestamp_cmd,
      "logging timestamp (0|1)",
	LOGGING_STR "Configure log message timestamping\n"
	"Don't prefix each log message\n"
	"Prefix each log message with current timestamp\n")
{
	struct log_target *tgt;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_set_print_timestamp(tgt, atoi(argv[0]));
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(logging_prnt_ext_timestamp,
      logging_prnt_ext_timestamp_cmd,
      "logging print extended-timestamp (0|1)",
	LOGGING_STR "Log output settings\n"
	"Configure log message timestamping\n"
	"Don't prefix each log message\n"
	"Prefix each log message with current timestamp with YYYYMMDDhhmmssnnn\n")
{
	struct log_target *tgt;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_set_print_extended_timestamp(tgt, atoi(argv[0]));
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(logging_prnt_tid,
      logging_prnt_tid_cmd,
      "logging print thread-id (0|1)",
	LOGGING_STR "Log output settings\n"
	"Configure log message logging Thread ID\n"
	"Don't prefix each log message\n"
	"Prefix each log message with current Thread ID\n")
{
	struct log_target *tgt;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_set_print_tid(tgt, atoi(argv[0]));
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(logging_prnt_cat,
      logging_prnt_cat_cmd,
      "logging print category (0|1)",
	LOGGING_STR "Log output settings\n"
	"Configure log message\n"
	"Don't prefix each log message\n"
	"Prefix each log message with category/subsystem name\n")
{
	struct log_target *tgt;
	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_set_print_category(tgt, atoi(argv[0]));
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(logging_prnt_cat_hex,
      logging_prnt_cat_hex_cmd,
      "logging print category-hex (0|1)",
	LOGGING_STR "Log output settings\n"
	"Configure log message\n"
	"Don't prefix each log message\n"
	"Prefix each log message with category/subsystem nr in hex ('<000b>')\n")
{
	struct log_target *tgt;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_set_print_category_hex(tgt, atoi(argv[0]));
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(logging_prnt_level,
      logging_prnt_level_cmd,
      "logging print level (0|1)",
      LOGGING_STR "Log output settings\n"
      "Configure log message\n"
      "Don't prefix each log message\n"
      "Prefix each log message with the log level name\n")
{
	struct log_target *tgt;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_set_print_level(tgt, atoi(argv[0]));
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

static const struct value_string logging_print_file_args[] = {
	{ LOG_FILENAME_NONE, "0" },
	{ LOG_FILENAME_PATH, "1" },
	{ LOG_FILENAME_BASENAME, "basename" },
	{ 0, NULL }
};

DEFUN(logging_prnt_file,
      logging_prnt_file_cmd,
      "logging print file (0|1|basename) [last]",
      LOGGING_STR "Log output settings\n"
      "Configure log message\n"
      "Don't prefix each log message\n"
      "Prefix each log message with the source file and line\n"
      "Prefix each log message with the source file's basename (strip leading paths) and line\n"
      "Log source file info at the end of a log line. If omitted, log source file info just"
      " before the log text.\n")
{
	struct log_target *tgt;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_set_print_filename2(tgt, get_string_value(logging_print_file_args, argv[0]));
	if (argc > 1)
		log_set_print_filename_pos(tgt, LOG_FILENAME_POS_LINE_END);
	else
		log_set_print_filename_pos(tgt, LOG_FILENAME_POS_HEADER_END);
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

static void add_category_strings(char **cmd_str_p, char **doc_str_p,
				 const struct log_info *categories)
{
	char buf[128];
	int i;
	for (i = 0; i < categories->num_cat; i++) {
		if (categories->cat[i].name == NULL)
			continue;
		/* skip the leading 'D' in each category name, hence '+ 1' */
		osmo_str_tolower_buf(buf, sizeof(buf), categories->cat[i].name + 1);
		osmo_talloc_asprintf(tall_log_ctx, *cmd_str_p, "%s%s",
				     i ? "|" : "", buf);
		osmo_talloc_asprintf(tall_log_ctx, *doc_str_p, "%s\n",
				     categories->cat[i].description);
	}
}

static void gen_logging_level_cmd_strs(struct cmd_element *cmd,
				       const char *level_args, const char *level_strs)
{
	char *cmd_str = NULL;
	char *doc_str = NULL;

	assert_loginfo(__func__);

	OSMO_ASSERT(cmd->string == NULL);
	OSMO_ASSERT(cmd->doc == NULL);

	osmo_talloc_asprintf(tall_log_ctx, cmd_str, "logging level (");
	osmo_talloc_asprintf(tall_log_ctx, doc_str,
			     LOGGING_STR
			     LEVEL_STR);
	add_category_strings(&cmd_str, &doc_str, osmo_log_info);
	osmo_talloc_asprintf(tall_log_ctx, cmd_str, ") %s", level_args);
	osmo_talloc_asprintf(tall_log_ctx, doc_str, "%s", level_strs);

	talloc_set_name_const(cmd_str, "vty_log_level_cmd_str");
	talloc_set_name_const(doc_str, "vty_log_level_doc_str");

	cmd->string = cmd_str;
	cmd->doc = doc_str;
}

/* logging level (<categories>) (debug|...|fatal) */
DEFUN(logging_level,
      logging_level_cmd,
      NULL, /* cmdstr is dynamically set in logging_vty_add_cmds(). */
      NULL) /* same thing for helpstr. */
{
	struct log_target *tgt;
	int category = log_parse_category(argv[0]);
	int level = log_parse_level(argv[1]);

	if (level < 0) {
		vty_out(vty, "%% Invalid level '%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (category < 0) {
		vty_out(vty, "%% Invalid category '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	tgt->categories[category].enabled = 1;
	tgt->categories[category].loglevel = level;

	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(logging_level_set_all, logging_level_set_all_cmd,
      "logging level set-all " LOG_LEVEL_ARGS,
      LOGGING_STR LEVEL_STR
      "Once-off set all categories to the given log level. There is no single command"
      " to take back these changes -- each category is set to the given level, period.\n"
      LOG_LEVEL_STRS)
{
	struct log_target *tgt;
	int level = log_parse_level(argv[0]);
	int i;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	for (i = 0; i < osmo_log_info->num_cat; i++) {
		struct log_category *cat = &tgt->categories[i];
		/* skip empty entries in the array */
		if (!osmo_log_info->cat[i].name)
			continue;

		cat->enabled = 1;
		cat->loglevel = level;
	}
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

/* logging level (<categories>) everything */
DEFUN_DEPRECATED(deprecated_logging_level_everything, deprecated_logging_level_everything_cmd,
		 NULL, /* cmdstr is dynamically set in logging_vty_add_cmds(). */
		 NULL) /* same thing for helpstr. */
{
	vty_out(vty, "%% Ignoring deprecated logging level 'everything' keyword%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(logging_level_force_all, logging_level_force_all_cmd,
      "logging level force-all " LOG_LEVEL_ARGS,
      LOGGING_STR LEVEL_STR FORCE_ALL_STR LOG_LEVEL_STRS)
{
	struct log_target *tgt;
	int level = log_parse_level(argv[0]);

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_set_log_level(tgt, level);
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(no_logging_level_force_all, no_logging_level_force_all_cmd,
      "no logging level force-all",
      NO_STR LOGGING_STR LEVEL_STR NO_FORCE_ALL_STR)
{
	struct log_target *tgt;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_set_log_level(tgt, 0);
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

/* 'logging level all (debug|...|fatal)' */
ALIAS_DEPRECATED(logging_level_force_all, deprecated_logging_level_all_cmd,
		 "logging level all " LOG_LEVEL_ARGS,
		 LOGGING_STR LEVEL_STR CATEGORY_ALL_STR LOG_LEVEL_STRS);

/* 'logging level all everything' */
ALIAS_DEPRECATED(no_logging_level_force_all, deprecated_logging_level_all_everything_cmd,
		 "logging level all everything",
		 LOGGING_STR LEVEL_STR CATEGORY_ALL_STR EVERYTHING_STR);

DEFUN(logging_set_category_mask,
      logging_set_category_mask_cmd,
      "logging set-log-mask MASK",
	LOGGING_STR
      "Set the logmask of this logging target\n"
      "List of logging categories to log, e.g. 'abc:mno:xyz'. Available log categories depend on the specific"
      " application, refer to the 'logging level' command. Optionally add individual log levels like"
      " 'abc,1:mno,3:xyz,5', where the level numbers are"
      " " OSMO_STRINGIFY(LOGL_DEBUG) "=" OSMO_STRINGIFY_VAL(LOGL_DEBUG)
      " " OSMO_STRINGIFY(LOGL_INFO) "=" OSMO_STRINGIFY_VAL(LOGL_INFO)
      " " OSMO_STRINGIFY(LOGL_NOTICE) "=" OSMO_STRINGIFY_VAL(LOGL_NOTICE)
      " " OSMO_STRINGIFY(LOGL_ERROR) "=" OSMO_STRINGIFY_VAL(LOGL_ERROR)
      " " OSMO_STRINGIFY(LOGL_FATAL) "=" OSMO_STRINGIFY_VAL(LOGL_FATAL)
      "\n")
{
	struct log_target *tgt;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_parse_category_mask(tgt, argv[0]);
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

ALIAS_DEPRECATED(logging_set_category_mask,
		 logging_set_category_mask_old_cmd,
		 "logging set log mask MASK",
		 LOGGING_STR
		 "Decide which categories to output.\n"
		 "Log commands\n" "Mask commands\n"
		 "'set log mask' is deprecated, please refer to the docs of 'set-log-mask' instead\n");


DEFUN(diable_logging,
      disable_logging_cmd,
      "logging disable",
	LOGGING_STR
      "Disables logging to this vty\n")
{
	struct log_target *tgt;
	struct telnet_connection *conn = (struct telnet_connection *) vty->priv;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	log_del_target(tgt);
	talloc_free(tgt);
	conn->dbg = NULL;

	RET_WITH_UNLOCK(CMD_SUCCESS);
}

static void vty_print_logtarget(struct vty *vty, const struct log_info *info,
				const struct log_target *tgt)
{
	unsigned int i;

	vty_out(vty, " Global Loglevel: %s%s",
		log_level_str(tgt->loglevel), VTY_NEWLINE);
	vty_out(vty, " Use color: %s, Print Timestamp: %s%s",
		tgt->use_color ? "On" : "Off",
		tgt->print_timestamp ? "On" : "Off", VTY_NEWLINE);

	vty_out(vty, " Log Level specific information:%s", VTY_NEWLINE);

	for (i = 0; i < info->num_cat; i++) {
		const struct log_category *cat = &tgt->categories[i];
		/* Skip categories that were not initialized */
		if (!info->cat[i].name)
			continue;
		vty_out(vty, "  %-10s %-10s %-8s %s%s",
			info->cat[i].name+1, log_level_str(cat->loglevel),
			cat->enabled ? "Enabled" : "Disabled",
 			info->cat[i].description,
			VTY_NEWLINE);
	}

	vty_out(vty, " Log Filter 'ALL': %s%s",
		tgt->filter_map & (1 << LOG_FLT_ALL) ? "Enabled" : "Disabled",
		VTY_NEWLINE);

	/* print application specific filters */
	if (info->print_fn)
		info->print_fn(vty, info, tgt);
}

#define SHOW_LOG_STR "Show current logging configuration\n"

DEFUN(show_logging_vty,
	show_logging_vty_cmd,
	"show logging vty",
	SHOW_STR SHOW_LOG_STR
	"Show current logging configuration for this vty\n")
{
	struct log_target *tgt;

	ACQUIRE_VTY_LOG_TGT_WITH_LOCK(vty, tgt);

	vty_print_logtarget(vty, osmo_log_info, tgt);
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(show_alarms,
	show_alarms_cmd,
	"show alarms",
	SHOW_STR SHOW_LOG_STR
	"Show the contents of the logging ringbuffer\n")
{
	int i, num_alarms;
	struct osmo_strrb *rb;
	struct log_target *tgt;

	log_tgt_mutex_lock();
	tgt = log_target_find(LOG_TGT_TYPE_STRRB, NULL);
	if (!tgt) {
		vty_out(vty, "%% No alarms, run 'log alarms <2-32700>'%s",
			VTY_NEWLINE);
		RET_WITH_UNLOCK(CMD_WARNING);
	}

	rb = tgt->tgt_rb.rb;
	num_alarms = osmo_strrb_elements(rb);

	vty_out(vty, "%% Showing %i alarms%s", num_alarms, VTY_NEWLINE);

	for (i = 0; i < num_alarms; i++)
		vty_out(vty, "%% %s%s", osmo_strrb_get_nth(rb, i),
			VTY_NEWLINE);
	RET_WITH_UNLOCK(CMD_SUCCESS);
}

gDEFUN(cfg_description, cfg_description_cmd,
	"description .TEXT",
	"Save human-readable description of the object\n"
	"Text until the end of the line\n")
{
	char **dptr = vty->index_sub;

	if (!dptr) {
		vty_out(vty, "%% vty->index_sub == NULL%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (*dptr)
		talloc_free(*dptr);
	*dptr = argv_concat(argv, argc, 0);
	if (!*dptr)
		return CMD_WARNING;

	return CMD_SUCCESS;
}

gDEFUN(cfg_no_description, cfg_no_description_cmd,
	"no description",
	NO_STR
	"Remove description of the object\n")
{
	char **dptr = vty->index_sub;

	if (!dptr) {
		vty_out(vty, "%% vty->index_sub == NULL%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (*dptr) {
		talloc_free(*dptr);
		*dptr = NULL;
	}

	return CMD_SUCCESS;
}

/* Support for configuration of log targets != the current vty */

struct cmd_node cfg_log_node = {
	CFG_LOG_NODE,
	"%s(config-log)# ",
	1
};

#ifdef HAVE_SYSLOG_H

#include <syslog.h>

static const int local_sysl_map[] = {
	[0] = LOG_LOCAL0,
	[1] = LOG_LOCAL1,
	[2] = LOG_LOCAL2,
	[3] = LOG_LOCAL3,
	[4] = LOG_LOCAL4,
	[5] = LOG_LOCAL5,
	[6] = LOG_LOCAL6,
	[7] = LOG_LOCAL7
};

/* From VTY core code */
extern struct host host;

static int _cfg_log_syslog(struct vty *vty, int facility)
{
	struct log_target *tgt;

	log_tgt_mutex_lock();
	/* First delete the old syslog target, if any */
	tgt = log_target_find(LOG_TGT_TYPE_SYSLOG, NULL);
	if (tgt)
		log_target_destroy(tgt);

	tgt = log_target_create_syslog(host.app_info->name, 0, facility);
	if (!tgt) {
		vty_out(vty, "%% Unable to open syslog%s", VTY_NEWLINE);
		RET_WITH_UNLOCK(CMD_WARNING);
	}
	log_add_target(tgt);

	vty->index = tgt;
	vty->node = CFG_LOG_NODE;

	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(cfg_log_syslog_local, cfg_log_syslog_local_cmd,
      "log syslog local <0-7>",
	LOG_STR "Logging via syslog\n" "Syslog LOCAL facility\n"
	"Local facility number\n")
{
	int local = atoi(argv[0]);
	int facility = local_sysl_map[local];

	return _cfg_log_syslog(vty, facility);
}

static struct value_string sysl_level_names[] = {
	{ LOG_AUTHPRIV, "authpriv" },
	{ LOG_CRON, 	"cron" },
	{ LOG_DAEMON,	"daemon" },
	{ LOG_FTP,	"ftp" },
	{ LOG_LPR,	"lpr" },
	{ LOG_MAIL,	"mail" },
	{ LOG_NEWS,	"news" },
	{ LOG_USER,	"user" },
	{ LOG_UUCP,	"uucp" },
	/* only for value -> string conversion */
	{ LOG_LOCAL0,	"local 0" },
	{ LOG_LOCAL1,	"local 1" },
	{ LOG_LOCAL2,	"local 2" },
	{ LOG_LOCAL3,	"local 3" },
	{ LOG_LOCAL4,	"local 4" },
	{ LOG_LOCAL5,	"local 5" },
	{ LOG_LOCAL6,	"local 6" },
	{ LOG_LOCAL7,	"local 7" },
	{ 0, NULL }
};

DEFUN(cfg_log_syslog, cfg_log_syslog_cmd,
      "log syslog (authpriv|cron|daemon|ftp|lpr|mail|news|user|uucp)",
	LOG_STR "Logging via syslog\n"
	"Security/authorization messages facility\n"
	"Clock daemon (cron/at) facility\n"
	"General system daemon facility\n"
	"Ftp daemon facility\n"
	"Line printer facility\n"
	"Mail facility\n"
	"News facility\n"
	"Generic facility\n"
	"UUCP facility\n")
{
	int facility = get_string_value(sysl_level_names, argv[0]);

	return _cfg_log_syslog(vty, facility);
}

DEFUN(cfg_no_log_syslog, cfg_no_log_syslog_cmd,
	"no log syslog",
	NO_STR LOG_STR "Logging via syslog\n")
{
	struct log_target *tgt;

	log_tgt_mutex_lock();
	tgt = log_target_find(LOG_TGT_TYPE_SYSLOG, NULL);
	if (!tgt) {
		vty_out(vty, "%% No syslog target found%s",
			VTY_NEWLINE);
		RET_WITH_UNLOCK(CMD_WARNING);
	}

	log_target_destroy(tgt);

	RET_WITH_UNLOCK(CMD_SUCCESS);
}
#endif /* HAVE_SYSLOG_H */

DEFUN(cfg_log_systemd_journal, cfg_log_systemd_journal_cmd,
      "log systemd-journal [raw]",
      LOG_STR "Logging to systemd-journal\n"
      "Offload rendering of the meta information (location, category) to systemd\n")
{
#ifdef ENABLE_SYSTEMD_LOGGING
	struct log_target *tgt;
	bool raw = argc > 0;

	log_tgt_mutex_lock();
	tgt = log_target_find(LOG_TGT_TYPE_SYSTEMD, NULL);
	if (tgt == NULL) {
		tgt = log_target_create_systemd(raw);
		if (tgt == NULL) {
			vty_out(vty, "%% Unable to create systemd-journal "
				"log target%s", VTY_NEWLINE);
			RET_WITH_UNLOCK(CMD_WARNING);
		}
		log_add_target(tgt);
	} else if (tgt->sd_journal.raw != raw) {
		log_target_systemd_set_raw(tgt, raw);
	}

	vty->index = tgt;
	vty->node = CFG_LOG_NODE;

	RET_WITH_UNLOCK(CMD_SUCCESS);
#else
	vty_out(vty, "%% systemd-journal logging is not available "
		"in this build of libosmocore%s", VTY_NEWLINE);
	return CMD_WARNING;
#endif /* ENABLE_SYSTEMD_LOGGING */
}

DEFUN(cfg_no_log_systemd_journal, cfg_no_log_systemd_journal_cmd,
	"no log systemd-journal",
	NO_STR LOG_STR "Logging to systemd-journal\n")
{
#ifdef ENABLE_SYSTEMD_LOGGING
	struct log_target *tgt;

	log_tgt_mutex_lock();
	tgt = log_target_find(LOG_TGT_TYPE_SYSTEMD, NULL);
	if (!tgt) {
		vty_out(vty, "%% No systemd-journal logging active%s", VTY_NEWLINE);
		RET_WITH_UNLOCK(CMD_WARNING);
	}

	log_target_destroy(tgt);

	RET_WITH_UNLOCK(CMD_SUCCESS);
#else
	vty_out(vty, "%% systemd-journal logging is not available "
		"in this build of libosmocore%s", VTY_NEWLINE);
	return CMD_WARNING;
#endif /* ENABLE_SYSTEMD_LOGGING */
}

DEFUN(cfg_log_gsmtap, cfg_log_gsmtap_cmd,
	"log gsmtap [HOSTNAME]",
	LOG_STR "Logging via GSMTAP\n"
	"Host name to send the GSMTAP logging to (UDP port 4729)\n")
{
	const char *hostname = argc ? argv[0] : "127.0.0.1";
	struct log_target *tgt;

	log_tgt_mutex_lock();
	tgt = log_target_find(LOG_TGT_TYPE_GSMTAP, hostname);
	if (!tgt) {
		tgt = log_target_create_gsmtap(hostname, GSMTAP_UDP_PORT,
					       host.app_info->name, false,
					       true);
		if (!tgt) {
			vty_out(vty, "%% Unable to create GSMTAP log for %s%s",
				hostname, VTY_NEWLINE);
			RET_WITH_UNLOCK(CMD_WARNING);
		}
		log_add_target(tgt);
	}

	vty->index = tgt;
	vty->node = CFG_LOG_NODE;

	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(cfg_no_log_gsmtap, cfg_no_log_gsmtap_cmd,
	"no log gsmtap [HOSTNAME]",
	NO_STR LOG_STR "Logging via GSMTAP\n"
	"Host name to send the GSMTAP logging to (UDP port 4729)\n")
{
	const char *hostname = argc ? argv[0] : "127.0.0.1";
	struct log_target *tgt;

	log_tgt_mutex_lock();
	tgt = log_target_find(LOG_TGT_TYPE_GSMTAP, hostname);
	if (tgt == NULL) {
		vty_out(vty, "%% Unable to find GSMTAP log target for %s%s",
			hostname, VTY_NEWLINE);
		RET_WITH_UNLOCK(CMD_WARNING);
	}

	log_target_destroy(tgt);

	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(cfg_log_stderr, cfg_log_stderr_cmd,
	"log stderr [blocking-io]",
	LOG_STR "Logging via STDERR of the process\n"
	"Use blocking, synchronous I/O\n")
{
	struct log_target *tgt;

	log_tgt_mutex_lock();
	tgt = log_target_find(LOG_TGT_TYPE_STDERR, NULL);
	if (!tgt) {
		tgt = log_target_create_stderr();
		if (!tgt) {
			vty_out(vty, "%% Unable to create stderr log%s",
				VTY_NEWLINE);
			RET_WITH_UNLOCK(CMD_WARNING);
		}
		log_add_target(tgt);
	}

	if (argc > 0 && !strcmp(argv[0], "blocking-io"))
		log_target_file_switch_to_stream(tgt);
	else
		log_target_file_switch_to_wqueue(tgt);

	vty->index = tgt;
	vty->node = CFG_LOG_NODE;

	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(cfg_no_log_stderr, cfg_no_log_stderr_cmd,
	"no log stderr",
	NO_STR LOG_STR "Logging via STDERR of the process\n")
{
	struct log_target *tgt;

	log_tgt_mutex_lock();
	tgt = log_target_find(LOG_TGT_TYPE_STDERR, NULL);
	if (!tgt) {
		vty_out(vty, "%% No stderr logging active%s", VTY_NEWLINE);
		RET_WITH_UNLOCK(CMD_WARNING);
	}

	log_target_destroy(tgt);
	osmo_stderr_target = NULL;

	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(cfg_log_file, cfg_log_file_cmd,
	"log file FILENAME [blocking-io]",
	LOG_STR "Logging to text file\n" "Filename\n"
	"Use blocking, synchronous I/O\n")
{
	const char *fname = argv[0];
	struct log_target *tgt;

	log_tgt_mutex_lock();
	tgt = log_target_find(LOG_TGT_TYPE_FILE, fname);
	if (!tgt) {
		tgt = log_target_create_file(fname);
		if (!tgt) {
			vty_out(vty, "%% Unable to create file '%s'%s",
				fname, VTY_NEWLINE);
			RET_WITH_UNLOCK(CMD_WARNING);
		}
		log_add_target(tgt);
	}

	if (argc > 1 && !strcmp(argv[1], "blocking-io"))
		log_target_file_switch_to_stream(tgt);
	else
		log_target_file_switch_to_wqueue(tgt);

	vty->index = tgt;
	vty->node = CFG_LOG_NODE;

	RET_WITH_UNLOCK(CMD_SUCCESS);
}


DEFUN(cfg_no_log_file, cfg_no_log_file_cmd,
	"no log file FILENAME",
	NO_STR LOG_STR "Logging to text file\n" "Filename\n")
{
	const char *fname = argv[0];
	struct log_target *tgt;

	log_tgt_mutex_lock();
	tgt = log_target_find(LOG_TGT_TYPE_FILE, fname);
	if (!tgt) {
		vty_out(vty, "%% No such log file '%s'%s",
			fname, VTY_NEWLINE);
		RET_WITH_UNLOCK(CMD_WARNING);
	}

	log_target_destroy(tgt);

	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(cfg_log_alarms, cfg_log_alarms_cmd,
	"log alarms <2-32700>",
	LOG_STR "Logging alarms to osmo_strrb\n"
	"Maximum number of messages to log\n")
{
	struct log_target *tgt;
	unsigned int rbsize = atoi(argv[0]);


	log_tgt_mutex_lock();
	tgt = log_target_find(LOG_TGT_TYPE_STRRB, NULL);
	if (tgt)
		log_target_destroy(tgt);

	tgt = log_target_create_rb(rbsize);
	if (!tgt) {
		vty_out(vty, "%% Unable to create osmo_strrb (size %u)%s",
			rbsize, VTY_NEWLINE);
		RET_WITH_UNLOCK(CMD_WARNING);
	}
	log_add_target(tgt);

	vty->index = tgt;
	vty->node = CFG_LOG_NODE;

	RET_WITH_UNLOCK(CMD_SUCCESS);
}

DEFUN(cfg_no_log_alarms, cfg_no_log_alarms_cmd,
	"no log alarms",
	NO_STR LOG_STR "Logging alarms to osmo_strrb\n")
{
	struct log_target *tgt;

	log_tgt_mutex_lock();
	tgt = log_target_find(LOG_TGT_TYPE_STRRB, NULL);
	if (!tgt) {
		vty_out(vty, "%% No osmo_strrb target found%s", VTY_NEWLINE);
		RET_WITH_UNLOCK(CMD_WARNING);
	}

	log_target_destroy(tgt);

	RET_WITH_UNLOCK(CMD_SUCCESS);
}

static int config_write_log_single(struct vty *vty, struct log_target *tgt)
{
	char level_buf[128];
	int i;

	switch (tgt->type) {
	case LOG_TGT_TYPE_VTY:
		return 1;
		break;
	case LOG_TGT_TYPE_STDERR:
		if (tgt->tgt_file.wqueue)
			vty_out(vty, "log stderr%s", VTY_NEWLINE);
		else
			vty_out(vty, "log stderr blocking-io%s", VTY_NEWLINE);
		break;
	case LOG_TGT_TYPE_SYSLOG:
#ifdef HAVE_SYSLOG_H
		vty_out(vty, "log syslog %s%s",
			get_value_string(sysl_level_names,
					 tgt->tgt_syslog.facility),
			VTY_NEWLINE);
#endif
		break;
	case LOG_TGT_TYPE_FILE:
		if (tgt->tgt_file.wqueue)
			vty_out(vty, "log file %s%s", tgt->tgt_file.fname, VTY_NEWLINE);
		else
			vty_out(vty, "log file %s blocking-io%s", tgt->tgt_file.fname, VTY_NEWLINE);
		break;
	case LOG_TGT_TYPE_STRRB:
		vty_out(vty, "log alarms %zu%s",
			log_target_rb_avail_size(tgt), VTY_NEWLINE);
		break;
	case LOG_TGT_TYPE_GSMTAP:
		vty_out(vty, "log gsmtap %s%s",
			tgt->tgt_gsmtap.hostname, VTY_NEWLINE);
		break;
	case LOG_TGT_TYPE_SYSTEMD:
		vty_out(vty, "log systemd-journal%s%s",
			tgt->sd_journal.raw ? " raw" : "",
			VTY_NEWLINE);
		break;
	}

	vty_out(vty, " logging filter all %u%s",
		tgt->filter_map & (1 << LOG_FLT_ALL) ? 1 : 0, VTY_NEWLINE);
	/* save filters outside of libosmocore, i.e. in app code */
	if (osmo_log_info->save_fn)
		osmo_log_info->save_fn(vty, osmo_log_info, tgt);

	vty_out(vty, " logging color %u%s", tgt->use_color ? 1 : 0,
		VTY_NEWLINE);
	vty_out(vty, " logging print category-hex %d%s",
		tgt->print_category_hex ? 1 : 0, VTY_NEWLINE);
	vty_out(vty, " logging print category %d%s",
		tgt->print_category ? 1 : 0, VTY_NEWLINE);
	vty_out(vty, " logging print thread-id %d%s",
		tgt->print_tid ? 1 : 0, VTY_NEWLINE);
	if (tgt->print_ext_timestamp)
		vty_out(vty, " logging print extended-timestamp 1%s", VTY_NEWLINE);
	else
		vty_out(vty, " logging timestamp %u%s",
			tgt->print_timestamp ? 1 : 0, VTY_NEWLINE);
	if (tgt->print_level)
		vty_out(vty, " logging print level 1%s", VTY_NEWLINE);
	vty_out(vty, " logging print file %s%s%s",
		get_value_string(logging_print_file_args, tgt->print_filename2),
		tgt->print_filename_pos == LOG_FILENAME_POS_LINE_END ? " last" : "",
		VTY_NEWLINE);

	if (tgt->loglevel) {
		const char *level_str = get_value_string_or_null(loglevel_strs, tgt->loglevel);
		if (!level_str) {
			vty_out(vty, "%% Invalid log level %u for 'force-all'%s",
				tgt->loglevel, VTY_NEWLINE);
		} else {
			osmo_str_tolower_buf(level_buf, sizeof(level_buf), level_str);
			vty_out(vty, " logging level force-all %s%s", level_buf, VTY_NEWLINE);
		}
	}

	for (i = 0; i < osmo_log_info->num_cat; i++) {
		const struct log_category *cat = &tgt->categories[i];
		char cat_name[128];
		const char *level_str;

		/* skip empty entries in the array */
		if (!osmo_log_info->cat[i].name)
			continue;

		osmo_str_tolower_buf(cat_name, sizeof(cat_name), osmo_log_info->cat[i].name + 1);

		level_str = get_value_string_or_null(loglevel_strs, cat->loglevel);
		if (!level_str) {
			vty_out(vty, "%% Invalid log level %u for %s%s", cat->loglevel, cat_name,
				VTY_NEWLINE);
			continue;
		}

		osmo_str_tolower_buf(level_buf, sizeof(level_buf), level_str);
		vty_out(vty, " logging level %s", cat_name);
		vty_out(vty, " %s%s", level_buf, VTY_NEWLINE);
	}

	return 1;
}

static int config_write_log(struct vty *vty)
{
	log_tgt_mutex_lock();
	struct log_target *dbg = vty->index;

	llist_for_each_entry(dbg, &osmo_log_target_list, entry)
		config_write_log_single(vty, dbg);

	log_tgt_mutex_unlock();
	return 1;
}

static int log_deprecated_func(struct cmd_element *cmd, struct vty *vty, int argc, const char *argv[])
{
	vty_out(vty, "%% Ignoring deprecated '%s'%s", cmd->string, VTY_NEWLINE);
	return CMD_SUCCESS; /* Otherwise the process would terminate */
}

void logging_vty_add_deprecated_subsys(void *ctx, const char *name)
{
	struct cmd_element *cmd = talloc_zero(ctx, struct cmd_element);
	OSMO_ASSERT(cmd);
	cmd->string = talloc_asprintf(cmd, "logging level %s " LOG_LEVEL_ARGS, name);
	cmd->func = log_deprecated_func;
	cmd->doc = LEVEL_STR
		   "Deprecated Category\n";
	cmd->attr = CMD_ATTR_DEPRECATED;

	install_lib_element(CFG_LOG_NODE, cmd);
}

/* logp (<categories>) (debug|...|fatal) .LOGMESSAGE*/
DEFUN(vty_logp,
      vty_logp_cmd,
      NULL, /* cmdstr is dynamically set in gen_vty_logp_cmd_strs(). */
      NULL) /* same thing for helpstr. */
{
	int category = log_parse_category(argv[0]);
	int level = log_parse_level(argv[1]);
	char *str = argv_concat(argv, argc, 2);

	if (level < 0) {
		vty_out(vty, "%% Invalid level '%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (category < 0) {
		vty_out(vty, "%% Invalid category '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Properly handle library specific sub-systems */
	if ((unsigned int) category >= osmo_log_info->num_cat_user) {
		category -= osmo_log_info->num_cat_user - 1;
		category *= -1;
	}

	LOGP(category, level, "%s\n", str);
	return CMD_SUCCESS;
}

static void gen_vty_logp_cmd_strs(struct cmd_element *cmd)
{
	char *cmd_str = NULL;
	char *doc_str = NULL;

	assert_loginfo(__func__);

	OSMO_ASSERT(cmd->string == NULL);
	OSMO_ASSERT(cmd->doc == NULL);

	osmo_talloc_asprintf(tall_log_ctx, cmd_str, "logp (");
	osmo_talloc_asprintf(tall_log_ctx, doc_str,
			     "Print a message on all log outputs; useful for placing markers in test logs\n");
	add_category_strings(&cmd_str, &doc_str, osmo_log_info);
	osmo_talloc_asprintf(tall_log_ctx, cmd_str, ") %s", LOG_LEVEL_ARGS);
	osmo_talloc_asprintf(tall_log_ctx, doc_str, "%s", LOG_LEVEL_STRS);

	osmo_talloc_asprintf(tall_log_ctx, cmd_str, " .LOGMESSAGE");
	osmo_talloc_asprintf(tall_log_ctx, doc_str,
			     "Arbitrary message to log on given category and log level\n");

	talloc_set_name_const(cmd_str, "vty_logp_cmd_str");
	talloc_set_name_const(doc_str, "vty_logp_doc_str");

	cmd->string = cmd_str;
	cmd->doc = doc_str;
}

/*! Register logging related commands to the VTY. Call this once from
 *  your application if you want to support those commands. */
void logging_vty_add_cmds(void)
{
	install_lib_element_ve(&enable_logging_cmd);
	install_lib_element_ve(&disable_logging_cmd);
	install_lib_element_ve(&logging_fltr_all_cmd);
	install_lib_element_ve(&logging_use_clr_cmd);
	install_lib_element_ve(&logging_prnt_timestamp_cmd);
	install_lib_element_ve(&logging_prnt_ext_timestamp_cmd);
	install_lib_element_ve(&logging_prnt_tid_cmd);
	install_lib_element_ve(&logging_prnt_cat_cmd);
	install_lib_element_ve(&logging_prnt_cat_hex_cmd);
	install_lib_element_ve(&logging_prnt_level_cmd);
	install_lib_element_ve(&logging_prnt_file_cmd);
	install_lib_element_ve(&logging_set_category_mask_cmd);
	install_lib_element_ve(&logging_set_category_mask_old_cmd);

	/* logging level (<categories>) (debug|...|fatal) */
	gen_logging_level_cmd_strs(&logging_level_cmd,
				   LOG_LEVEL_ARGS,
				   LOG_LEVEL_STRS);
	/* logging level (<categories>) everything */
	gen_logging_level_cmd_strs(&deprecated_logging_level_everything_cmd,
				   "everything", EVERYTHING_STR);

	install_lib_element_ve(&logging_level_cmd);
	install_lib_element_ve(&logging_level_set_all_cmd);
	install_lib_element_ve(&logging_level_force_all_cmd);
	install_lib_element_ve(&no_logging_level_force_all_cmd);
	install_lib_element_ve(&deprecated_logging_level_everything_cmd);
	install_lib_element_ve(&deprecated_logging_level_all_cmd);
	install_lib_element_ve(&deprecated_logging_level_all_everything_cmd);

	gen_vty_logp_cmd_strs(&vty_logp_cmd);
	install_lib_element_ve(&vty_logp_cmd);

	install_lib_element_ve(&show_logging_vty_cmd);
	install_lib_element_ve(&show_alarms_cmd);

	install_node(&cfg_log_node, config_write_log);
	install_lib_element(CFG_LOG_NODE, &logging_fltr_all_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_use_clr_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_prnt_timestamp_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_prnt_ext_timestamp_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_prnt_tid_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_prnt_cat_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_prnt_cat_hex_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_prnt_level_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_prnt_file_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_level_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_level_set_all_cmd);
	install_lib_element(CFG_LOG_NODE, &logging_level_force_all_cmd);
	install_lib_element(CFG_LOG_NODE, &no_logging_level_force_all_cmd);
	install_lib_element(CFG_LOG_NODE, &deprecated_logging_level_everything_cmd);
	install_lib_element(CFG_LOG_NODE, &deprecated_logging_level_all_cmd);
	install_lib_element(CFG_LOG_NODE, &deprecated_logging_level_all_everything_cmd);

	install_lib_element(CONFIG_NODE, &cfg_log_stderr_cmd);
	install_lib_element(CONFIG_NODE, &cfg_no_log_stderr_cmd);
	install_lib_element(CONFIG_NODE, &cfg_log_file_cmd);
	install_lib_element(CONFIG_NODE, &cfg_no_log_file_cmd);
	install_lib_element(CONFIG_NODE, &cfg_log_alarms_cmd);
	install_lib_element(CONFIG_NODE, &cfg_no_log_alarms_cmd);
#ifdef HAVE_SYSLOG_H
	install_lib_element(CONFIG_NODE, &cfg_log_syslog_cmd);
	install_lib_element(CONFIG_NODE, &cfg_log_syslog_local_cmd);
	install_lib_element(CONFIG_NODE, &cfg_no_log_syslog_cmd);
#endif
	install_lib_element(CONFIG_NODE, &cfg_log_systemd_journal_cmd);
	install_lib_element(CONFIG_NODE, &cfg_no_log_systemd_journal_cmd);
	install_lib_element(CONFIG_NODE, &cfg_log_gsmtap_cmd);
	install_lib_element(CONFIG_NODE, &cfg_no_log_gsmtap_cmd);
}
