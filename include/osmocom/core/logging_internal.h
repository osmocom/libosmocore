#pragma once

/*! \defgroup logging_internal Osmocom logging internals
 *  @{
 * \file logging_internal.h */

#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>

/* maximum length of the log string of a single log event (typically  line) */
#define MAX_LOG_SIZE   4096

/*! Log context information, passed to filter */
struct log_context {
	void *ctx[LOG_MAX_CTX+1] OSMO_DEPRECATED_OUTSIDE("Accessing struct log_context members directly is deprecated");
};

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
	/*! should log messages be prefixed with the logger Thread ID? */
	unsigned int print_tid:1;
	/*! DEPRECATED: use print_filename2 instead. */
	unsigned int print_filename:1;
	/*! should log messages be prefixed with a category name? */
	unsigned int print_category:1;
	/*! should log messages be prefixed with an extended timestamp? */
	unsigned int print_ext_timestamp:1;

	/*! the type of this log taget */
	enum log_target_type type;

	union {
		struct {
			/* direct, blocking output via stdio */
			FILE *out;
			const char *fname;
			/* indirect output via write_queue and osmo_select_main() */
			struct osmo_wqueue *wqueue;
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

		struct {
			bool raw;
		} sd_journal;
	};

	/*! call-back function to be called when the logging framework
	 *	   wants to log a fully formatted string
	 *  \param[in] target logging target
	 *  \param[in] level log level of currnet message
	 *  \param[in] string the string that is to be written to the log
	 */
	void (*output)(struct log_target *target, unsigned int level,
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

	/* Should the log level be printed? */
	bool print_level;
	/* Should we print the subsys in hex like '<000b>'? */
	bool print_category_hex;
	/* Should we print the source file and line, and in which way? */
	enum log_filename_type print_filename2;
	/* Where on a log line to put the source file info. */
	enum log_filename_pos print_filename_pos;
};

extern void *tall_log_ctx;
extern struct log_info *osmo_log_info;
extern const struct value_string loglevel_strs[];
extern struct llist_head osmo_log_target_list;

void assert_loginfo(const char *src);

int log_output_buf(char *buf, int buf_len, struct log_target *target, unsigned int subsys,
		   unsigned int level, const char *file, int line, int cont,
		   const char *format, va_list ap);

void log_target_file_destroy(struct log_target *target);

/*! @} */
