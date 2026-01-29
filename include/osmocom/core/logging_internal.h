#pragma once

/*! \defgroup logging_internal Osmocom logging internals
 *  @{
 * \file logging_internal.h */

#include <stdbool.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>

/* maximum length of the log string of a single log event (typically  line) */
#define MAX_LOG_SIZE   4096

/* maximum number of log statements we queue in file/stderr target write queue */
#define LOG_WQUEUE_LEN	156

struct log_thread_state {
	/* Whether we are inside a code path to generate logging output: */
	bool logging_active;
	/* Cache TID: */
	long int tid;
};

extern void *tall_log_ctx;
extern struct log_info *osmo_log_info;
extern const struct value_string loglevel_strs[];
extern struct llist_head osmo_log_target_list;
extern __thread struct log_thread_state log_thread_state;

void assert_loginfo(const char *src);

int log_output_buf(char *buf, int buf_len, struct log_target *target, unsigned int subsys,
		   unsigned int level, const char *file, int line, int cont,
		   const char *format, va_list ap);

void log_target_file_destroy(struct log_target *target);

/*! @} */
