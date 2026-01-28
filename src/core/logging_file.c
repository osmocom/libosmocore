/*! \file logging_file.c
 * File & stderr logging support code. */
/*
 * (C) 2025-2026 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
 */

/*! \addtogroup logging
 *  @{
 * \file logging_file.c */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/select.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/logging_internal.h>

/* maximum number of log statements we queue in file/stderr target write queue */
#define LOG_WQUEUE_LEN	156


/*! close and re-open a log file (for log file rotation)
 *  \param[in] target log target to re-open
 *  \returns 0 in case of success; negative otherwise */
int log_target_file_reopen(struct log_target *target)
{
	struct osmo_wqueue *wq;
	int rc;

	OSMO_ASSERT(target->type == LOG_TGT_TYPE_FILE || target->type == LOG_TGT_TYPE_STDERR);
	OSMO_ASSERT(target->tgt_file.out || target->tgt_file.wqueue);

	if (target->type == LOG_TGT_TYPE_STDERR)
		return -ENOTSUP;

	if (target->tgt_file.out) {
		fclose(target->tgt_file.out);
		target->tgt_file.out = fopen(target->tgt_file.fname, "a");
		if (!target->tgt_file.out)
			return -errno;
	} else {
		wq = target->tgt_file.wqueue;
		if (wq->bfd.fd >= 0) {
			osmo_fd_unregister(&wq->bfd);
			close(wq->bfd.fd);
			wq->bfd.fd = -1;
		}

		rc = open(target->tgt_file.fname, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0660);
		if (rc < 0)
			return -errno;
		wq->bfd.fd = rc;
		rc = osmo_fd_register(&wq->bfd);
		if (rc < 0)
			return rc;
	}

	return 0;
}

#if (!EMBEDDED)

/* This is the file-specific subclass destructor logic, called from
 * log_target_destroy(). User should call log_target_destroy() to destroy this
 * object. */
void log_target_file_destroy(struct log_target *target)
{
	struct osmo_wqueue *wq;

	OSMO_ASSERT(target->type == LOG_TGT_TYPE_FILE ||
		    target->type == LOG_TGT_TYPE_STDERR);

	if (target->tgt_file.out) {
		if (target->type == LOG_TGT_TYPE_FILE)
			fclose(target->tgt_file.out);
		target->tgt_file.out = NULL;
	}
	wq = target->tgt_file.wqueue;
	if (wq) {
		if (wq->bfd.fd >= 0) {
			osmo_fd_unregister(&wq->bfd);
			if (target->type == LOG_TGT_TYPE_FILE)
				close(wq->bfd.fd);
			wq->bfd.fd = -1;
		}
		osmo_wqueue_clear(wq);
		talloc_free(wq);
		target->tgt_file.wqueue = NULL;
	}
	talloc_free((void *)target->tgt_file.fname);
	target->tgt_file.fname = NULL;
}

/* write-queue tells us we should write another msgb (log line) to the output fd */
static int _file_wq_write_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	int rc;

	rc = write(ofd->fd, msgb_data(msg), msgb_length(msg));
	if (rc < 0)
		return rc;
	if (rc != msgb_length(msg)) {
		/* pull the number of bytes we have already written */
		msgb_pull(msg, rc);
		/* ask write_queue to re-insert the msgb at the head of the queue */
		return -EAGAIN;
	}
	return 0;
}

/* output via buffered, blocking stdio streams */
static void _file_output_stream(struct log_target *target, unsigned int level,
			 const char *log)
{
	OSMO_ASSERT(target->tgt_file.out);
	fputs(log, target->tgt_file.out);
	fflush(target->tgt_file.out);
}

/* output via non-blocking write_queue, doing internal buffering */
static void _file_raw_output(struct log_target *target, int subsys, unsigned int level, const char *file,
			     int line, int cont, const char *format, va_list ap)
{
	struct msgb *msg;
	int rc;

	OSMO_ASSERT(target->tgt_file.wqueue);
	msg = msgb_alloc_c(target->tgt_file.wqueue, MAX_LOG_SIZE, "log_file_msg");
	if (!msg)
		return;

	/* we simply enqueue the log message to a write queue here, to avoid any blocking
	 * writes on the output file.  The write queue will tell us once the file is writable
	 * and call _file_wq_write_cb() */
	rc = log_output_buf((char *)msgb_data(msg), msgb_tailroom(msg), target, subsys, level, file, line, cont, format, ap);
	msgb_put(msg, rc);

	/* attempt a synchronous, non-blocking write, if the write queue is empty */
	if (target->tgt_file.wqueue->current_length == 0) {
		rc = _file_wq_write_cb(&target->tgt_file.wqueue->bfd, msg);
		if (rc == 0) {
			/* the write was complete, we can exit early */
			msgb_free(msg);
			return;
		}
	}
	/* if we reach here, either we already had elements in the write_queue, or the synchronous write
	 * failed: enqueue the message to the write_queue (backlog) */
	if (osmo_wqueue_enqueue_quiet(target->tgt_file.wqueue, msg) < 0) {
		msgb_free(msg);
		/* TODO: increment some counter so we can see that messages were dropped */
	}
}

/*! switch from non-blocking/write-queue to blocking + buffered stream output
 *  \param[in] target log target which we should switch
 *  \return 0 on success; 1 if already switched before; negative on error
 *  Must be called with mutex osmo_log_tgt_mutex held, see log_tgt_mutex_lock.
 */
int log_target_file_switch_to_stream(struct log_target *target)
{
	struct osmo_wqueue *wq;

	if (!target)
		return -ENODEV;

	if (target->tgt_file.out) {
		/* target has already been switched over */
		return 1;
	}

	wq = target->tgt_file.wqueue;
	OSMO_ASSERT(wq);

	/* re-open output as stream */
	if (target->type == LOG_TGT_TYPE_STDERR)
		target->tgt_file.out = stderr;
	else
		target->tgt_file.out = fopen(target->tgt_file.fname, "a");
	if (!target->tgt_file.out)
		return -EIO;

	/* synchronously write anything left in the queue */
	while (!llist_empty(&wq->msg_queue)) {
		struct msgb *msg = msgb_dequeue(&wq->msg_queue);
		fwrite(msgb_data(msg), msgb_length(msg), 1, target->tgt_file.out);
		msgb_free(msg);
	}

	/* now that everything succeeded, we can finally close the old output fd */
	if (target->type == LOG_TGT_TYPE_FILE) {
		osmo_fd_unregister(&wq->bfd);
		close(wq->bfd.fd);
		wq->bfd.fd = -1;
	}

	/* release the queue itself */
	talloc_free(wq);
	target->tgt_file.wqueue = NULL;
	target->output = _file_output_stream;
	target->raw_output = NULL;

	return 0;
}

/*! switch from blocking + buffered file output to non-blocking write-queue based output.
 *  \param[in] target log target which we should switch
 *  \return 0 on success; 1 if already switched before; negative on error
 *  Must be called with mutex osmo_log_tgt_mutex held, see log_tgt_mutex_lock.
 */
int log_target_file_switch_to_wqueue(struct log_target *target)
{
	struct osmo_wqueue *wq;
	int rc;

	if (!target)
		return -ENODEV;

	if (!target->tgt_file.out) {
		/* target has already been switched over */
		return 1;
	}

	/* we create a ~640kB sized talloc pool within the write-queue to ensure individual
	 * log lines (stored as msgbs) will not put result in malloc() calls, and also to
	 * reduce the OOM probability within logging, as the pool is already allocated */
	wq = talloc_pooled_object(target, struct osmo_wqueue, LOG_WQUEUE_LEN,
				  LOG_WQUEUE_LEN*(sizeof(struct msgb)+MAX_LOG_SIZE));
	if (!wq)
		return -ENOMEM;
	osmo_wqueue_init(wq, LOG_WQUEUE_LEN);

	fflush(target->tgt_file.out);
	if (target->type == LOG_TGT_TYPE_FILE) {
		rc = open(target->tgt_file.fname, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0660);
		if (rc < 0) {
			talloc_free(wq);
			return -errno;
		}
	} else {
		rc = STDERR_FILENO;
	}
	wq->bfd.fd = rc;
	wq->bfd.when = OSMO_FD_WRITE;
	wq->write_cb = _file_wq_write_cb;

	rc = osmo_fd_register(&wq->bfd);
	if (rc < 0) {
		talloc_free(wq);
		return -EIO;
	}
	target->tgt_file.wqueue = wq;
	target->raw_output = _file_raw_output;
	target->output = NULL;

	/* now that everything succeeded, we can finally close the old output stream */
	if (target->type == LOG_TGT_TYPE_FILE)
		fclose(target->tgt_file.out);
	target->tgt_file.out = NULL;

	return 0;
}

/*! Create a new file-based log target using non-blocking write_queue
 *  \param[in] fname File name of the new log file
 *  \returns Log target in case of success, NULL otherwise
 */
struct log_target *log_target_create_file(const char *fname)
{
	struct log_target *target;
	struct osmo_wqueue *wq;
	int rc;

	target = log_target_create();
	if (!target)
		return NULL;

	target->type = LOG_TGT_TYPE_FILE;
	/* we create a ~640kB sized talloc pool within the write-queue to ensure individual
	 * log lines (stored as msgbs) will not put result in malloc() calls, and also to
	 * reduce the OOM probability within logging, as the pool is already allocated */
	wq = talloc_pooled_object(target, struct osmo_wqueue, LOG_WQUEUE_LEN,
				  LOG_WQUEUE_LEN*(sizeof(struct msgb)+MAX_LOG_SIZE));
	if (!wq) {
		log_target_destroy(target);
		return NULL;
	}
	osmo_wqueue_init(wq, LOG_WQUEUE_LEN);
	wq->bfd.fd = open(fname, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0660);
	if (wq->bfd.fd < 0) {
		talloc_free(wq);
		log_target_destroy(target);
		return NULL;
	}
	wq->bfd.when = OSMO_FD_WRITE;
	wq->write_cb = _file_wq_write_cb;

	rc = osmo_fd_register(&wq->bfd);
	if (rc < 0) {
		talloc_free(wq);
		log_target_destroy(target);
		return NULL;
	}

	target->tgt_file.wqueue = wq;
	target->raw_output = _file_raw_output;
	target->tgt_file.fname = talloc_strdup(target, fname);

	return target;
}
#endif

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
	target->output = _file_output_stream;
	return target;
#else
	return NULL;
#endif /* stderr */
}

/* @} */
