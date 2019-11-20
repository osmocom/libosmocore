/*! \file logging.c
 * Debugging/Logging support code. */
/*
 * (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008 by Holger Hans Peter Freyther <zecke@selfish.org>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

/*! \addtogroup logging
 * @{
 * libosmocore Logging sub-system
 *
 * \file logging.c */

#include "../config.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <pthread.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>

#include <osmocom/vty/logging.h>	/* for LOGGING_STR. */

osmo_static_assert(_LOG_CTX_COUNT <= ARRAY_SIZE(((struct log_context*)NULL)->ctx),
		   enum_logging_ctx_items_fit_in_struct_log_context);
osmo_static_assert(_LOG_FLT_COUNT <= ARRAY_SIZE(((struct log_target*)NULL)->filter_data),
		   enum_logging_filters_fit_in_log_target_filter_data);
osmo_static_assert(_LOG_FLT_COUNT <= 8*sizeof(((struct log_target*)NULL)->filter_map),
		   enum_logging_filters_fit_in_log_target_filter_map);

struct log_info *osmo_log_info;

static struct log_context log_context;
void *tall_log_ctx = NULL;
LLIST_HEAD(osmo_log_target_list);

#if (!EMBEDDED)
/*! This mutex must be held while using osmo_log_target_list or any of its
  log_targets in a multithread program. Prevents race conditions between threads
  like producing unordered timestamps or VTY deleting a target while another
  thread is writing to it */
static pthread_mutex_t osmo_log_tgt_mutex;
static bool osmo_log_tgt_mutex_on = false;

/*! Enable multithread support (mutex) in libosmocore logging system.
 * Must be called by processes willing to use logging subsystem from several
 * threads. Once enabled, it's not possible to disable it again.
 */
void log_enable_multithread(void) {
	if (osmo_log_tgt_mutex_on)
		return;
	pthread_mutex_init(&osmo_log_tgt_mutex, NULL);
	osmo_log_tgt_mutex_on = true;
}

/*! Acquire the osmo_log_tgt_mutex. Don't use this function directly, always use
 *  macro log_tgt_mutex_lock() instead.
 */
void log_tgt_mutex_lock_impl(void) {
	/* These lines are useful to debug scenarios where there's only 1 thread
	   and a double lock appears, for instance during startup and some
	   unlock() missing somewhere:
	if (osmo_log_tgt_mutex_on && pthread_mutex_trylock(&osmo_log_tgt_mutex) != 0)
		osmo_panic("acquiring already locked mutex!\n");
	return;
	*/

	if (osmo_log_tgt_mutex_on)
		pthread_mutex_lock(&osmo_log_tgt_mutex);
}

/*! Release the osmo_log_tgt_mutex. Don't use this function directly, always use
 *  macro log_tgt_mutex_unlock() instead.
 */
void log_tgt_mutex_unlock_impl(void) {
	if (osmo_log_tgt_mutex_on)
		pthread_mutex_unlock(&osmo_log_tgt_mutex);
}

#else /* if (!EMBEDDED) */
#pragma message ("logging multithread support disabled in embedded build")
void log_enable_multithread(void) {}
void log_tgt_mutex_lock_impl(void) {}
void log_tgt_mutex_unlock_impl(void) {}
#endif /* if (!EMBEDDED) */

const struct value_string loglevel_strs[] = {
	{ LOGL_DEBUG,	"DEBUG" },
	{ LOGL_INFO,	"INFO" },
	{ LOGL_NOTICE,	"NOTICE" },
	{ LOGL_ERROR,	"ERROR" },
	{ LOGL_FATAL,	"FATAL" },
	{ 0, NULL },
};

#define INT2IDX(x)	(-1*(x)-1)
static const struct log_info_cat internal_cat[OSMO_NUM_DLIB] = {
	[INT2IDX(DLGLOBAL)] = {	/* -1 becomes 0 */
		.name = "DLGLOBAL",
		.description = "Library-internal global log family",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[INT2IDX(DLLAPD)] = {	/* -2 becomes 1 */
		.name = "DLLAPD",
		.description = "LAPD in libosmogsm",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[INT2IDX(DLINP)] = {
		.name = "DLINP",
		.description = "A-bis Intput Subsystem",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[INT2IDX(DLMUX)] = {
		.name = "DLMUX",
		.description = "A-bis B-Subchannel TRAU Frame Multiplex",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[INT2IDX(DLMI)] = {
		.name = "DLMI",
		.description = "A-bis Input Driver for Signalling",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLMIB)] = {
		.name = "DLMIB",
		.description = "A-bis Input Driver for B-Channels (voice)",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLSMS)] = {
		.name = "DLSMS",
		.description = "Layer3 Short Message Service (SMS)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
		.color = OSMO_LOGCOLOR_BRIGHTWHITE,
	},
	[INT2IDX(DLCTRL)] = {
		.name = "DLCTRL",
		.description = "Control Interface",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLGTP)] = {
		.name = "DLGTP",
		.description = "GPRS GTP library",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLSTATS)] = {
		.name = "DLSTATS",
		.description = "Statistics messages and logging",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLGSUP)] = {
		.name = "DLGSUP",
		.description = "Generic Subscriber Update Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLOAP)] = {
		.name = "DLOAP",
		.description = "Osmocom Authentication Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLSS7)] = {
		.name = "DLSS7",
		.description = "libosmo-sigtran Signalling System 7",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLSCCP)] = {
		.name = "DLSCCP",
		.description = "libosmo-sigtran SCCP Implementation",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLSUA)] = {
		.name = "DLSUA",
		.description = "libosmo-sigtran SCCP User Adaptation",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLM3UA)] = {
		.name = "DLM3UA",
		.description = "libosmo-sigtran MTP3 User Adaptation",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLMGCP)] = {
		.name = "DLMGCP",
		.description = "libosmo-mgcp Media Gateway Control Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLJIBUF)] = {
		.name = "DLJIBUF",
		.description = "libosmo-netif Jitter Buffer",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[INT2IDX(DLRSPRO)] = {
		.name = "DLRSPRO",
		.description = "Remote SIM protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

void assert_loginfo(const char *src)
{
	if (!osmo_log_info) {
		fprintf(stderr, "ERROR: osmo_log_info == NULL! "
			"You must call log_init() before using logging in %s()!\n", src);
		OSMO_ASSERT(osmo_log_info);
	}
}

/* special magic for negative (library-internal) log subsystem numbers */
static int subsys_lib2index(int subsys)
{
	return (subsys * -1) + (osmo_log_info->num_cat_user-1);
}

/*! Parse a human-readable log level into a numeric value
 *  \param[in] lvl zero-terminated string containing log level name
 *  \returns numeric log level
 */
int log_parse_level(const char *lvl)
{
	return get_string_value(loglevel_strs, lvl);
}

/*! convert a numeric log level into human-readable string
 *  \param[in] lvl numeric log level
 *  \returns zero-terminated string (log level name)
 */
const char *log_level_str(unsigned int lvl)
{
	return get_value_string(loglevel_strs, lvl);
}

/*! parse a human-readable log category into numeric form
 *  \param[in] category human-readable log category name
 *  \returns numeric category value, or -EINVAL otherwise
 */
int log_parse_category(const char *category)
{
	int i;

	assert_loginfo(__func__);

	for (i = 0; i < osmo_log_info->num_cat; ++i) {
		if (osmo_log_info->cat[i].name == NULL)
			continue;
		if (!strcasecmp(osmo_log_info->cat[i].name+1, category))
			return i;
	}

	return -EINVAL;
}

/*! parse the log category mask
 *  \param[in] target log target to be configured
 *  \param[in] _mask log category mask string
 *
 * The format can be this: category1:category2:category3
 * or category1,2:category2,3:...
 */
void log_parse_category_mask(struct log_target* target, const char *_mask)
{
	int i = 0;
	char *mask = strdup(_mask);
	char *category_token = NULL;

	assert_loginfo(__func__);

	/* Disable everything to enable it afterwards */
	for (i = 0; i < osmo_log_info->num_cat; ++i)
		target->categories[i].enabled = 0;

	category_token = strtok(mask, ":");
	OSMO_ASSERT(category_token);
	do {
		for (i = 0; i < osmo_log_info->num_cat; ++i) {
			size_t length, cat_length;
			char* colon = strstr(category_token, ",");

			if (!osmo_log_info->cat[i].name)
				continue;

			length = strlen(category_token);
			cat_length = strlen(osmo_log_info->cat[i].name);

			/* Use longest length not to match subocurrences. */
			if (cat_length > length)
				length = cat_length;

			if (colon)
			    length = colon - category_token;

			if (strncasecmp(osmo_log_info->cat[i].name,
					category_token, length) == 0) {
				int level = 0;

				if (colon)
					level = atoi(colon+1);

				target->categories[i].enabled = 1;
				target->categories[i].loglevel = level;
			}
		}
	} while ((category_token = strtok(NULL, ":")));

	free(mask);
}

static const char* color(int subsys)
{
	if (subsys < osmo_log_info->num_cat)
		return osmo_log_info->cat[subsys].color;

	return NULL;
}

static const struct value_string level_colors[] = {
	{ LOGL_DEBUG, OSMO_LOGCOLOR_BLUE },
	{ LOGL_INFO, OSMO_LOGCOLOR_GREEN },
	{ LOGL_NOTICE, OSMO_LOGCOLOR_YELLOW },
	{ LOGL_ERROR, OSMO_LOGCOLOR_RED },
	{ LOGL_FATAL, OSMO_LOGCOLOR_RED },
	{ 0, NULL }
};

static const char *level_color(int level)
{
	const char *c = get_value_string_or_null(level_colors, level);
	if (!c)
		return get_value_string(level_colors, LOGL_FATAL);
	return c;
}

const char* log_category_name(int subsys)
{
	if (subsys < osmo_log_info->num_cat)
		return osmo_log_info->cat[subsys].name;

	return NULL;
}

static const char *const_basename(const char *path)
{
	const char *bn = strrchr(path, '/');
	if (!bn || !bn[1])
		return path;
	return bn + 1;
}

static void _output(struct log_target *target, unsigned int subsys,
		    unsigned int level, const char *file, int line, int cont,
		    const char *format, va_list ap)
{
	char buf[4096];
	int ret, len = 0, offset = 0, rem = sizeof(buf);
	const char *c_subsys = NULL;

	/* are we using color */
	if (target->use_color) {
		c_subsys = color(subsys);
		if (c_subsys) {
			ret = snprintf(buf + offset, rem, "%s", c_subsys);
			if (ret < 0)
				goto err;
			OSMO_SNPRINTF_RET(ret, rem, offset, len);
		}
	}
	if (!cont) {
		if (target->print_ext_timestamp) {
#ifdef HAVE_LOCALTIME_R
			struct tm tm;
			struct timeval tv;
			osmo_gettimeofday(&tv, NULL);
			localtime_r(&tv.tv_sec, &tm);
			ret = snprintf(buf + offset, rem, "%04d%02d%02d%02d%02d%02d%03d ",
					tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
					tm.tm_hour, tm.tm_min, tm.tm_sec,
					(int)(tv.tv_usec / 1000));
			if (ret < 0)
				goto err;
			OSMO_SNPRINTF_RET(ret, rem, offset, len);
#endif
		} else if (target->print_timestamp) {
			time_t tm;
			if ((tm = time(NULL)) == (time_t) -1)
				goto err;
			/* Get human-readable representation of time.
			   man ctime: we need at least 26 bytes in buf */
			if (rem < 26 || !ctime_r(&tm, buf + offset))
				goto err;
			ret = strlen(buf + offset);
			if (ret <= 0)
				goto err;
			/* Get rid of useless final '\n' added by ctime_r. We want a space instead. */
			buf[offset + ret - 1] = ' ';
			OSMO_SNPRINTF_RET(ret, rem, offset, len);
		}
		if (target->print_category) {
			ret = snprintf(buf + offset, rem, "%s%s%s%s ",
				       target->use_color ? level_color(level) : "",
				       log_category_name(subsys),
				       target->use_color ? OSMO_LOGCOLOR_END : "",
				       c_subsys ? c_subsys : "");
			if (ret < 0)
				goto err;
			OSMO_SNPRINTF_RET(ret, rem, offset, len);
		}
		if (target->print_level) {
			ret = snprintf(buf + offset, rem, "%s%s%s%s ",
				       target->use_color ? level_color(level) : "",
				       log_level_str(level),
				       target->use_color ? OSMO_LOGCOLOR_END : "",
				       c_subsys ? c_subsys : "");
			if (ret < 0)
				goto err;
			OSMO_SNPRINTF_RET(ret, rem, offset, len);
		}
		if (target->print_category_hex) {
			ret = snprintf(buf + offset, rem, "<%4.4x> ", subsys);
			if (ret < 0)
				goto err;
			OSMO_SNPRINTF_RET(ret, rem, offset, len);
		}

		if (target->print_filename_pos == LOG_FILENAME_POS_HEADER_END) {
			switch (target->print_filename2) {
			case LOG_FILENAME_NONE:
				break;
			case LOG_FILENAME_PATH:
				ret = snprintf(buf + offset, rem, "%s:%d ", file, line);
				if (ret < 0)
					goto err;
				OSMO_SNPRINTF_RET(ret, rem, offset, len);
				break;
			case LOG_FILENAME_BASENAME:
				ret = snprintf(buf + offset, rem, "%s:%d ", const_basename(file), line);
				if (ret < 0)
					goto err;
				OSMO_SNPRINTF_RET(ret, rem, offset, len);
				break;
			}
		}
	}
	ret = vsnprintf(buf + offset, rem, format, ap);
	if (ret < 0)
		goto err;
	OSMO_SNPRINTF_RET(ret, rem, offset, len);

	/* For LOG_FILENAME_POS_LAST, print the source file info only when the caller ended the log
	 * message in '\n'. If so, nip the last '\n' away, insert the source file info and re-append an
	 * '\n'. All this to allow LOGP("start..."); LOGPC("...end\n") constructs. */
	if (target->print_filename_pos == LOG_FILENAME_POS_LINE_END
	    && offset > 0 && buf[offset-1] == '\n') {
		switch (target->print_filename2) {
		case LOG_FILENAME_NONE:
			break;
		case LOG_FILENAME_PATH:
			offset --;
			ret = snprintf(buf + offset, rem, " (%s:%d)\n", file, line);
			if (ret < 0)
				goto err;
			OSMO_SNPRINTF_RET(ret, rem, offset, len);
			break;
		case LOG_FILENAME_BASENAME:
			offset --;
			ret = snprintf(buf + offset, rem, " (%s:%d)\n", const_basename(file), line);
			if (ret < 0)
				goto err;
			OSMO_SNPRINTF_RET(ret, rem, offset, len);
			break;
		}
	}

	if (target->use_color) {
		ret = snprintf(buf + offset, rem, OSMO_LOGCOLOR_END);
		if (ret < 0)
			goto err;
		OSMO_SNPRINTF_RET(ret, rem, offset, len);
	}
err:
	buf[sizeof(buf)-1] = '\0';
	target->output(target, level, buf);
}

/* Catch internal logging category indexes as well as out-of-bounds indexes.
 * For internal categories, the ID is negative starting with -1; and internal
 * logging categories are added behind the user categories. For out-of-bounds
 * indexes, return the index of DLGLOBAL. The returned category index is
 * guaranteed to exist in osmo_log_info, otherwise the program would abort,
 * which should never happen unless even the DLGLOBAL category is missing. */
static inline int map_subsys(int subsys)
{
	/* Note: comparing signed and unsigned integers */

	if (subsys > 0 && ((unsigned int)subsys) >= osmo_log_info->num_cat_user)
		subsys = DLGLOBAL;

	if (subsys < 0)
		subsys = subsys_lib2index(subsys);

	if (subsys < 0 || subsys >= osmo_log_info->num_cat)
		subsys = subsys_lib2index(DLGLOBAL);

	OSMO_ASSERT(!(subsys < 0 || subsys >= osmo_log_info->num_cat));

	return subsys;
}

static inline bool should_log_to_target(struct log_target *tar, int subsys,
					int level)
{
	struct log_category *category;

	category = &tar->categories[subsys];

	/* subsystem is not supposed to be logged */
	if (!category->enabled)
		return false;

	/* Check the global log level */
	if (tar->loglevel != 0 && level < tar->loglevel)
		return false;

	/* Check the category log level */
	if (tar->loglevel == 0 && category->loglevel != 0 &&
	    level < category->loglevel)
		return false;

	/* Apply filters here... if that becomes messy we will
	 * need to put filters in a list and each filter will
	 * say stop, continue, output */
	if ((tar->filter_map & (1 << LOG_FLT_ALL)) != 0)
		return true;

	if (osmo_log_info->filter_fn)
		return osmo_log_info->filter_fn(&log_context, tar);

	/* TODO: Check the filter/selector too? */
	return true;
}

/*! vararg version of logging function
 *  \param[in] subsys Logging sub-system
 *  \param[in] level Log level
 *  \param[in] file name of source code file
 *  \param[in] cont continuation (1) or new line (0)
 *  \param[in] format format string
 *  \param[in] ap vararg-list containing format string arguments
 */
void osmo_vlogp(int subsys, int level, const char *file, int line,
		int cont, const char *format, va_list ap)
{
	struct log_target *tar;

	subsys = map_subsys(subsys);

	log_tgt_mutex_lock();

	llist_for_each_entry(tar, &osmo_log_target_list, entry) {
		va_list bp;

		if (!should_log_to_target(tar, subsys, level))
			continue;

		/* According to the manpage, vsnprintf leaves the value of ap
		 * in undefined state. Since _output uses vsnprintf and it may
		 * be called several times, we have to pass a copy of ap. */
		va_copy(bp, ap);
		if (tar->raw_output)
			tar->raw_output(tar, subsys, level, file, line, cont, format, bp);
		else
			_output(tar, subsys, level, file, line, cont, format, bp);
		va_end(bp);
	}

	log_tgt_mutex_unlock();
}

/*! logging function used by DEBUGP() macro
 *  \param[in] subsys Logging sub-system
 *  \param[in] file name of source code file
 *  \param[in] cont continuation (1) or new line (0)
 *  \param[in] format format string
 */
void logp(int subsys, const char *file, int line, int cont,
	  const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	osmo_vlogp(subsys, LOGL_DEBUG, file, line, cont, format, ap);
	va_end(ap);
}

/*! logging function used by LOGP() macro
 *  \param[in] subsys Logging sub-system
 *  \param[in] level Log level
 *  \param[in] file name of source code file
 *  \param[in] cont continuation (1) or new line (0)
 *  \param[in] format format string
 */
void logp2(int subsys, unsigned int level, const char *file, int line, int cont, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	osmo_vlogp(subsys, level, file, line, cont, format, ap);
	va_end(ap);
}

/*! Register a new log target with the logging core
 *  \param[in] target Log target to be registered
 */
void log_add_target(struct log_target *target)
{
	llist_add_tail(&target->entry, &osmo_log_target_list);
}

/*! Unregister a log target from the logging core
 *  \param[in] target Log target to be unregistered
 */
void log_del_target(struct log_target *target)
{
	llist_del(&target->entry);
}

/*! Reset (clear) the logging context */
void log_reset_context(void)
{
	memset(&log_context, 0, sizeof(log_context));
}

/*! Set the logging context
 *  \param[in] ctx_nr logging context number
 *  \param[in] value value to which the context is to be set
 *  \returns 0 in case of success; negative otherwise
 *
 * A logging context is something like the subscriber identity to which
 * the currently processed message relates, or the BTS through which it
 * was received.  As soon as this data is known, it can be set using
 * this function.  The main use of context information is for logging
 * filters.
 */
int log_set_context(uint8_t ctx_nr, void *value)
{
	if (ctx_nr > LOG_MAX_CTX)
		return -EINVAL;

	log_context.ctx[ctx_nr] = value;

	return 0;
}

/*! Enable the \ref LOG_FLT_ALL log filter
 *  \param[in] target Log target to be affected
 *  \param[in] all enable (1) or disable (0) the ALL filter
 *
 * When the \ref LOG_FLT_ALL filter is enabled, all log messages will be
 * printed.  It acts as a wildcard.  Setting it to \a 1 means there is no
 * filtering.
 */
void log_set_all_filter(struct log_target *target, int all)
{
	if (all)
		target->filter_map |= (1 << LOG_FLT_ALL);
	else
		target->filter_map &= ~(1 << LOG_FLT_ALL);
}

/*! Enable or disable the use of colored output
 *  \param[in] target Log target to be affected
 *  \param[in] use_color Use color (1) or don't use color (0)
 */
void log_set_use_color(struct log_target *target, int use_color)
{
	target->use_color = use_color;
}

/*! Enable or disable printing of timestamps while logging
 *  \param[in] target Log target to be affected
 *  \param[in] print_timestamp Enable (1) or disable (0) timestamps
 */
void log_set_print_timestamp(struct log_target *target, int print_timestamp)
{
	target->print_timestamp = print_timestamp;
}

/*! Enable or disable printing of extended timestamps while logging
 *  \param[in] target Log target to be affected
 *  \param[in] print_timestamp Enable (1) or disable (0) timestamps
 *
 * When both timestamp and extended timestamp is enabled then only
 * the extended timestamp will be used. The format of the timestamp
 * is YYYYMMDDhhmmssnnn.
 */
void log_set_print_extended_timestamp(struct log_target *target, int print_timestamp)
{
	target->print_ext_timestamp = print_timestamp;
}

/*! Use log_set_print_filename2() instead.
 * Call log_set_print_filename2() with LOG_FILENAME_PATH or LOG_FILENAME_NONE, *as well as* call
 * log_set_print_category_hex() with the argument passed to this function. This is to mirror legacy
 * behavior, which combined the category in hex with the filename. For example, if the category-hex
 * output were no longer affected by log_set_print_filename(), many unit tests (in libosmocore as well as
 * dependent projects) would fail since they expect the category to disappear along with the filename.
 *  \param[in] target Log target to be affected
 *  \param[in] print_filename Enable (1) or disable (0) filenames
 */
void log_set_print_filename(struct log_target *target, int print_filename)
{
	log_set_print_filename2(target, print_filename ? LOG_FILENAME_PATH : LOG_FILENAME_NONE);
	log_set_print_category_hex(target, print_filename);
}

/*! Enable or disable printing of the filename while logging.
 *  \param[in] target Log target to be affected.
 *  \param[in] lft An LOG_FILENAME_* enum value.
 * LOG_FILENAME_NONE omits the source file and line information from logs.
 * LOG_FILENAME_PATH prints the entire source file path as passed to LOGP macros.
 */
void log_set_print_filename2(struct log_target *target, enum log_filename_type lft)
{
	target->print_filename2 = lft;
}

/*! Set the position where on a log line the source file info should be logged.
 *  \param[in] target Log target to be affected.
 *  \param[in] pos A LOG_FILENAME_POS_* enum value.
 * LOG_FILENAME_POS_DEFAULT logs just before the caller supplied log message.
 * LOG_FILENAME_POS_LAST logs only at the end of a log line, where the caller issued an '\n' to end the
 */
void log_set_print_filename_pos(struct log_target *target, enum log_filename_pos pos)
{
	target->print_filename_pos = pos;
}

/*! Enable or disable printing of the category name
 *  \param[in] target Log target to be affected
 *  \param[in] print_category Enable (1) or disable (0) filenames
 *
 *  Print the category/subsys name in front of every log message.
 */
void log_set_print_category(struct log_target *target, int print_category)
{
	target->print_category = print_category;
}

/*! Enable or disable printing of the category number in hex ('<000b>').
 *  \param[in] target Log target to be affected.
 *  \param[in] print_category_hex Enable (1) or disable (0) hex category.
 */
void log_set_print_category_hex(struct log_target *target, int print_category_hex)
{
	target->print_category_hex = print_category_hex;
}

/*! Enable or disable printing of the log level name.
 *  \param[in] target Log target to be affected
 *  \param[in] print_level Enable (1) or disable (0) log level name
 *
 *  Print the log level name in front of every log message.
 */
void log_set_print_level(struct log_target *target, int print_level)
{
	target->print_level = (bool)print_level;
}

/*! Set the global log level for a given log target
 *  \param[in] target Log target to be affected
 *  \param[in] log_level New global log level
 */
void log_set_log_level(struct log_target *target, int log_level)
{
	target->loglevel = log_level;
}

/*! Set a category filter on a given log target
 *  \param[in] target Log target to be affected
 *  \param[in] category Log category to be affected
 *  \param[in] enable whether to enable or disable the filter
 *  \param[in] level Log level of the filter
 */
void log_set_category_filter(struct log_target *target, int category,
			       int enable, int level)
{
	if (!target)
		return;
	category = map_subsys(category);
	target->categories[category].enabled = !!enable;
	target->categories[category].loglevel = level;
}

#if (!EMBEDDED)
static void _file_output(struct log_target *target, unsigned int level,
			 const char *log)
{
	fprintf(target->tgt_file.out, "%s", log);
	fflush(target->tgt_file.out);
}
#endif

/*! Create a new log target skeleton
 *  \returns dynamically-allocated log target
 *  This funcition allocates a \ref log_target and initializes it
 *  with some default values.  The newly created target is not
 *  registered yet.
 */
struct log_target *log_target_create(void)
{
	struct log_target *target;
	unsigned int i;

	assert_loginfo(__func__);

	target = talloc_zero(tall_log_ctx, struct log_target);
	if (!target)
		return NULL;

	target->categories = talloc_zero_array(target,
						struct log_category,
						osmo_log_info->num_cat);
	if (!target->categories) {
		talloc_free(target);
		return NULL;
	}

	INIT_LLIST_HEAD(&target->entry);

	/* initialize the per-category enabled/loglevel from defaults */
	for (i = 0; i < osmo_log_info->num_cat; i++) {
		struct log_category *cat = &target->categories[i];
		cat->enabled = osmo_log_info->cat[i].enabled;
		cat->loglevel = osmo_log_info->cat[i].loglevel;
	}

	/* global settings */
	target->use_color = 1;
	target->print_timestamp = 0;
	target->print_filename2 = LOG_FILENAME_PATH;
	target->print_category_hex = true;

	/* global log level */
	target->loglevel = 0;
	return target;
}

/*! Create the STDERR log target
 *  \returns dynamically-allocated \ref log_target for STDERR */
struct log_target *log_target_create_stderr(void)
{
/* since C89/C99 says stderr is a macro, we can safely do this! */
#if !EMBEDDED && defined(stderr)
	struct log_target *target;

	target = log_target_create();
	if (!target)
		return NULL;

	target->type = LOG_TGT_TYPE_STDERR;
	target->tgt_file.out = stderr;
	target->output = _file_output;
	return target;
#else
	return NULL;
#endif /* stderr */
}

#if (!EMBEDDED)
/*! Create a new file-based log target
 *  \param[in] fname File name of the new log file
 *  \returns Log target in case of success, NULL otherwise
 */
struct log_target *log_target_create_file(const char *fname)
{
	struct log_target *target;

	target = log_target_create();
	if (!target)
		return NULL;

	target->type = LOG_TGT_TYPE_FILE;
	target->tgt_file.out = fopen(fname, "a");
	if (!target->tgt_file.out)
		return NULL;

	target->output = _file_output;

	target->tgt_file.fname = talloc_strdup(target, fname);

	return target;
}
#endif

/*! Find a registered log target
 *  \param[in] type Log target type
 *  \param[in] fname File name
 *  \returns Log target (if found), NULL otherwise
 *  Must be called with mutex osmo_log_tgt_mutex held, see log_tgt_mutex_lock.
 */
struct log_target *log_target_find(int type, const char *fname)
{
	struct log_target *tgt;

	llist_for_each_entry(tgt, &osmo_log_target_list, entry) {
		if (tgt->type != type)
			continue;
		switch (tgt->type) {
		case LOG_TGT_TYPE_FILE:
			if (!strcmp(fname, tgt->tgt_file.fname))
				return tgt;
			break;
		case LOG_TGT_TYPE_GSMTAP:
			if (!strcmp(fname, tgt->tgt_gsmtap.hostname))
				return tgt;
			break;
		default:
			return tgt;
		}
	}
	return NULL;
}

/*! Unregister, close and delete a log target
 *  \param[in] target log target to unregister, close and delete */
void log_target_destroy(struct log_target *target)
{

	/* just in case, to make sure we don't have any references */
	log_del_target(target);

#if (!EMBEDDED)
	if (target->output == &_file_output) {
/* since C89/C99 says stderr is a macro, we can safely do this! */
#ifdef stderr
		/* don't close stderr */
		if (target->tgt_file.out != stderr)
#endif
		{
			fclose(target->tgt_file.out);
			target->tgt_file.out = NULL;
		}
	}
#endif

	talloc_free(target);
}

/*! close and re-open a log file (for log file rotation)
 *  \param[in] target log target to re-open
 *  \returns 0 in case of success; negative otherwise */
int log_target_file_reopen(struct log_target *target)
{
	fclose(target->tgt_file.out);

	target->tgt_file.out = fopen(target->tgt_file.fname, "a");
	if (!target->tgt_file.out)
		return -errno;

	/* we assume target->output already to be set */

	return 0;
}

/*! close and re-open all log files (for log file rotation)
 *  \returns 0 in case of success; negative otherwise */
int log_targets_reopen(void)
{
	struct log_target *tar;
	int rc = 0;

	log_tgt_mutex_lock();

	llist_for_each_entry(tar, &osmo_log_target_list, entry) {
		switch (tar->type) {
		case LOG_TGT_TYPE_FILE:
			if (log_target_file_reopen(tar) < 0)
				rc = -1;
			break;
		default:
			break;
		}
	}

	log_tgt_mutex_unlock();

	return rc;
}

/*! Initialize the Osmocom logging core
 *  \param[in] inf Information regarding logging categories, could be NULL
 *  \param[in] ctx talloc context for logging allocations
 *  \returns 0 in case of success, negative in case of error
 *
 *  If inf is NULL then only library-internal categories are initialized.
 */
int log_init(const struct log_info *inf, void *ctx)
{
	int i;

	tall_log_ctx = talloc_named_const(ctx, 1, "logging");
	if (!tall_log_ctx)
		return -ENOMEM;

	osmo_log_info = talloc_zero(tall_log_ctx, struct log_info);
	if (!osmo_log_info)
		return -ENOMEM;

	osmo_log_info->num_cat = ARRAY_SIZE(internal_cat);

	if (inf) {
		osmo_log_info->filter_fn = inf->filter_fn;
		osmo_log_info->num_cat_user = inf->num_cat;
		osmo_log_info->num_cat += inf->num_cat;
	}

	osmo_log_info->cat = talloc_zero_array(osmo_log_info,
					struct log_info_cat,
					osmo_log_info->num_cat);
	if (!osmo_log_info->cat) {
		talloc_free(osmo_log_info);
		osmo_log_info = NULL;
		return -ENOMEM;
	}

	if (inf) { /* copy over the user part */
		for (i = 0; i < inf->num_cat; i++) {
			memcpy((struct log_info_cat *) &osmo_log_info->cat[i],
			       &inf->cat[i], sizeof(struct log_info_cat));
		}
	}

	/* copy over the library part */
	for (i = 0; i < ARRAY_SIZE(internal_cat); i++) {
		unsigned int cn = osmo_log_info->num_cat_user + i;
		memcpy((struct log_info_cat *) &osmo_log_info->cat[cn],
			&internal_cat[i], sizeof(struct log_info_cat));
	}

	return 0;
}

/* De-initialize the Osmocom logging core
 * This function destroys all targets and releases associated memory */
void log_fini(void)
{
	struct log_target *tar, *tar2;

	log_tgt_mutex_lock();

	llist_for_each_entry_safe(tar, tar2, &osmo_log_target_list, entry)
		log_target_destroy(tar);

	talloc_free(osmo_log_info);
	osmo_log_info = NULL;
	talloc_free(tall_log_ctx);
	tall_log_ctx = NULL;

	log_tgt_mutex_unlock();
}

/*! Check whether a log entry will be generated.
 *  \returns != 0 if a log entry might get generated by at least one target */
int log_check_level(int subsys, unsigned int level)
{
	struct log_target *tar;

	assert_loginfo(__func__);

	subsys = map_subsys(subsys);

	/* TODO: The following could/should be cached (update on config) */

	log_tgt_mutex_lock();

	llist_for_each_entry(tar, &osmo_log_target_list, entry) {
		if (!should_log_to_target(tar, subsys, level))
			continue;

		/* This might get logged (ignoring filters) */
		log_tgt_mutex_unlock();
		return 1;
	}

	/* We are sure, that this will not be logged. */
	log_tgt_mutex_unlock();
	return 0;
}

/*! @} */
