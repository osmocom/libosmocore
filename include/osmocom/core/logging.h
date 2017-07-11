#pragma once

/*! \defgroup logging Osmocom logging framework
 *  @{
 * \file logging.h */

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <osmocom/core/defs.h>
#include <osmocom/core/linuxlist.h>

/*! Maximum number of logging contexts */
#define LOG_MAX_CTX		8
/*! Maximum number of logging filters */
#define LOG_MAX_FILTERS	8

#define DEBUG

#ifdef DEBUG
/*! Log a debug message through the Osmocom logging framework
 *  \param[in] ss logging subsystem (e.g. \ref DLGLOBAL)
 *  \param[in] fmt format string
 *  \param[in] args variable argument list
 */
#define DEBUGP(ss, fmt, args...) LOGP(ss, LOGL_DEBUG, fmt, ##args)
#define DEBUGPC(ss, fmt, args...) LOGPC(ss, LOGL_DEBUG, fmt, ##args)
#else
#define DEBUGP(xss, fmt, args...)
#define DEBUGPC(ss, fmt, args...)
#endif


void osmo_vlogp(int subsys, int level, const char *file, int line,
		int cont, const char *format, va_list ap);

void logp(int subsys, const char *file, int line, int cont, const char *format, ...) OSMO_DEPRECATED("Use DEBUGP* macros instead");

/*! Log a new message through the Osmocom logging framework
 *  \param[in] ss logging subsystem (e.g. \ref DLGLOBAL)
 *  \param[in] level logging level (e.g. \ref LOGL_NOTICE)
 *  \param[in] fmt format string
 *  \param[in] args variable argument list
 */
#define LOGP(ss, level, fmt, args...) \
	LOGPSRC(ss, level, NULL, 0, fmt, ## args)

/*! Continue a log message through the Osmocom logging framework
 *  \param[in] ss logging subsystem (e.g. \ref DLGLOBAL)
 *  \param[in] level logging level (e.g. \ref LOGL_NOTICE)
 *  \param[in] fmt format string
 *  \param[in] args variable argument list
 */
#define LOGPC(ss, level, fmt, args...) \
	do { \
		if (log_check_level(ss, level)) \
			logp2(ss, level, __BASE_FILE__, __LINE__, 1, fmt, ##args); \
	} while(0)

/*! Log through the Osmocom logging framework with explicit source.
 *  If caller_file is passed as NULL, __BASE_FILE__ and __LINE__ are used
 *  instead of caller_file and caller_line (so that this macro here defines
 *  both cases in the same place, and to catch cases where callers fail to pass
 *  a non-null filename string).
 *  \param[in] ss logging subsystem (e.g. \ref DLGLOBAL)
 *  \param[in] level logging level (e.g. \ref LOGL_NOTICE)
 *  \param[in] caller_file caller's source file string (e.g. __BASE_FILE__)
 *  \param[in] caller_line caller's source line nr (e.g. __LINE__)
 *  \param[in] fmt format string
 *  \param[in] args variable argument list
 */
#define LOGPSRC(ss, level, caller_file, caller_line, fmt, args...) \
	do { \
		if (log_check_level(ss, level)) {\
			if (caller_file) \
				logp2(ss, level, caller_file, caller_line, 0, fmt, ##args); \
			else \
				logp2(ss, level, __BASE_FILE__, __LINE__, 0, fmt, ##args); \
		}\
	} while(0)

/*! different log levels */
#define LOGL_DEBUG	1	/*!< debugging information */
#define LOGL_INFO	3	/*!< general information */
#define LOGL_NOTICE	5	/*!< abnormal/unexpected condition */
#define LOGL_ERROR	7	/*!< error condition, requires user action */
#define LOGL_FATAL	8	/*!< fatal, program aborted */

/* logging levels defined by the library itself */
#define DLGLOBAL	-1	/*!< global logging */
#define DLLAPD		-2	/*!< LAPD implementation */
#define DLINP		-3	/*!< (A-bis) Input sub-system */
#define DLMUX		-4	/*!< Osmocom Multiplex (Osmux) */
#define DLMI		-5	/*!< ISDN-layer below input sub-system */
#define DLMIB		-6	/*!< ISDN layer B-channel */
#define DLSMS		-7	/*!< SMS sub-system */
#define DLCTRL		-8	/*!< Control Interface */
#define DLGTP		-9	/*!< GTP (GPRS Tunneling Protocol */
#define DLSTATS		-10	/*!< Statistics */
#define DLGSUP		-11	/*!< Generic Subscriber Update Protocol */
#define DLOAP		-12	/*!< Osmocom Authentication Protocol */
#define DLSS7		-13	/*!< Osmocom SS7 */
#define DLSCCP		-14	/*!< Osmocom SCCP */
#define DLSUA		-15	/*!< Osmocom SUA */
#define DLM3UA		-16	/*!< Osmocom M3UA */
#define DLMGCP		-17	/*!< Osmocom MGCP */
#define OSMO_NUM_DLIB	17	/*!< Number of logging sub-systems in libraries */

/*! Configuration of single log category / sub-system */
struct log_category {
	uint8_t loglevel;	/*!< configured log-level */
	uint8_t enabled;	/*!< is logging enabled? */
};

/*! Information regarding one logging category */
struct log_info_cat {
	const char *name;		/*!< name of category */
	const char *color;		/*!< color string for cateyory */
	const char *description;	/*!< description text */
	uint8_t loglevel;		/*!< currently selected log-level */
	uint8_t enabled;		/*!< is this category enabled or not */
};

/*! Log context information, passed to filter */
struct log_context {
	void *ctx[LOG_MAX_CTX+1];
};

/*! Indexes to indicate the object currently acted upon.
 * Array indexes for the global \a log_context array. */
enum log_ctx_index {
	LOG_CTX_GB_NSVC,
	LOG_CTX_GB_BVC,
	LOG_CTX_BSC_SUBSCR,
	LOG_CTX_VLR_SUBSCR,
	_LOG_CTX_COUNT
};

/*! Indexes to indicate objects that should be logged.
 * Array indexes to log_target->filter_data and bit indexes for
 * log_target->filter_map. */
enum log_filter_index {
	LOG_FLT_ALL,
	LOG_FLT_GB_NSVC,
	LOG_FLT_GB_BVC,
	LOG_FLT_BSC_SUBSCR,
	LOG_FLT_VLR_SUBSCR,
	_LOG_FLT_COUNT
};

/*! Compatibility with older libosmocore versions */
#define LOG_FILTER_ALL (1<<LOG_FLT_ALL)
/*! Compatibility with older libosmocore versions */
#define GPRS_CTX_NSVC LOG_CTX_GB_NSVC
/*! Compatibility with older libosmocore versions */
#define GPRS_CTX_BVC LOG_CTX_GB_BVC
/*! Indexes to indicate the object currently acted upon.
 * Array indexes for the global \a log_context array. */

struct log_target;

/*! Log filter function */
typedef int log_filter(const struct log_context *ctx,
		       struct log_target *target);

struct log_info;
struct vty;
struct gsmtap_inst;

typedef void log_print_filters(struct vty *vty,
			       const struct log_info *info,
			       const struct log_target *tgt);

typedef void log_save_filters(struct vty *vty,
			      const struct log_info *info,
			      const struct log_target *tgt);

/*! Logging configuration, passed to \ref log_init */
struct log_info {
	/* filter callback function */
	log_filter *filter_fn;

	/*! per-category information */
	const struct log_info_cat *cat;
	/*! total number of categories */
	unsigned int num_cat;
	/*! total number of user categories (not library) */
	unsigned int num_cat_user;

	/*! filter saving function */
	log_save_filters *save_fn;
	/*! filter saving function */
	log_print_filters *print_fn;
};

/*! Type of logging target */
enum log_target_type {
	LOG_TGT_TYPE_VTY,	/*!< VTY logging */
	LOG_TGT_TYPE_SYSLOG,	/*!< syslog based logging */
	LOG_TGT_TYPE_FILE,	/*!< text file logging */
	LOG_TGT_TYPE_STDERR,	/*!< stderr logging */
	LOG_TGT_TYPE_STRRB,	/*!< osmo_strrb-backed logging */
	LOG_TGT_TYPE_GSMTAP,	/*!< GSMTAP network logging */
};

/*! structure representing a logging target */
struct log_target {
        struct llist_head entry;		/*!< linked list */

	/*! Internal data for filtering */
	int filter_map;
	/*! Internal data for filtering */
	void *filter_data[LOG_MAX_FILTERS+1];

	/*! logging categories */
	struct log_category *categories;

	/*! global log level */
	uint8_t loglevel;
	/*! should color be used when printing log messages? */
	unsigned int use_color:1;
	/*! should log messages be prefixed with a timestamp? */
	unsigned int print_timestamp:1;
	/*! should log messages be prefixed with a filename? */
	unsigned int print_filename:1;
	/*! should log messages be prefixed with a category name? */
	unsigned int print_category:1;
	/*! should log messages be prefixed with an extended timestamp? */
	unsigned int print_ext_timestamp:1;

	/*! the type of this log taget */
	enum log_target_type type;

	union {
		struct {
			FILE *out;
			const char *fname;
		} tgt_file;

		struct {
			int priority;
			int facility;
		} tgt_syslog;

		struct {
			void *vty;
		} tgt_vty;

		struct {
			void *rb;
		} tgt_rb;

		struct {
			struct gsmtap_inst *gsmtap_inst;
			const char *ident;
			const char *hostname;
		} tgt_gsmtap;
	};

	/*! call-back function to be called when the logging framework
	 *	   wants to log a fully formatted string
	 *  \param[in] target logging target
	 *  \param[in] level log level of currnet message
	 *  \param[in] string the string that is to be written to the log
	 */
        void (*output) (struct log_target *target, unsigned int level,
			const char *string);

	/*! alternative call-back function to which the logging
	 *	   framework passes the unfortmatted input arguments,
	 *	   i.e. bypassing the internal string formatter
	 *  \param[in] target logging target
	 *  \param[in] subsys logging sub-system
	 *  \param[in] level logging level
	 *  \param[in] file soure code file name
	 *  \param[in] line source code file line number
	 *  \param[in] cont continuation of previous statement?
	 *  \param[in] format format string
	 *  \param[in] ap vararg list of printf arguments
	 */
	void (*raw_output)(struct log_target *target, int subsys,
			   unsigned int level, const char *file, int line,
			   int cont, const char *format, va_list ap);
};

/* use the above macros */
void logp2(int subsys, unsigned int level, const char *file,
	   int line, int cont, const char *format, ...)
				__attribute__ ((format (printf, 6, 7)));
int log_init(const struct log_info *inf, void *talloc_ctx);
void log_fini(void);
int log_check_level(int subsys, unsigned int level);

/* context management */
void log_reset_context(void);
int log_set_context(uint8_t ctx, void *value);

/* filter on the targets */
void log_set_all_filter(struct log_target *target, int);

void log_set_use_color(struct log_target *target, int);
void log_set_print_extended_timestamp(struct log_target *target, int);
void log_set_print_timestamp(struct log_target *target, int);
void log_set_print_filename(struct log_target *target, int);
void log_set_print_category(struct log_target *target, int);
void log_set_log_level(struct log_target *target, int log_level);
void log_parse_category_mask(struct log_target *target, const char* mask);
const char* log_category_name(int subsys);
int log_parse_level(const char *lvl) OSMO_DEPRECATED_OUTSIDE_LIBOSMOCORE;
const char *log_level_str(unsigned int lvl) OSMO_DEPRECATED_OUTSIDE_LIBOSMOCORE;
int log_parse_category(const char *category);
void log_set_category_filter(struct log_target *target, int category,
			       int enable, int level);

/* management of the targets */
struct log_target *log_target_create(void);
void log_target_destroy(struct log_target *target);
struct log_target *log_target_create_stderr(void);
struct log_target *log_target_create_file(const char *fname);
struct log_target *log_target_create_syslog(const char *ident, int option,
					    int facility);
struct log_target *log_target_create_gsmtap(const char *host, uint16_t port,
					    const char *ident,
					    bool ofd_wq_mode,
					    bool add_sink);
int log_target_file_reopen(struct log_target *tgt);
int log_targets_reopen(void);

void log_add_target(struct log_target *target);
void log_del_target(struct log_target *target);

/* Generate command string for VTY use */
const char *log_vty_command_string() OSMO_DEPRECATED_OUTSIDE_LIBOSMOCORE;
const char *log_vty_command_description() OSMO_DEPRECATED_OUTSIDE_LIBOSMOCORE;

struct log_target *log_target_find(int type, const char *fname);
extern struct llist_head osmo_log_target_list;

/*! @} */
