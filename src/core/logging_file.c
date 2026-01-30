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
#include <osmocom/core/osmo_io.h>
#include <osmocom/core/logging_internal.h>

/* NOTE: We use target->tgt_file.wqueue->except_cb to store the struct osmo_io_fd, because the
 * struct log_target is public and we cannot add pointers to it under tgt->tgt_file...
 * It can be moved to target->tgt_file.iofd if we are ever able to make struct log_target private... */

/*! close and re-open a log file (for log file rotation)
 *  \param[in] target log target to re-open
 *  \returns 0 in case of success; negative otherwise */
int log_target_file_reopen(struct log_target *target)
{
	struct osmo_io_fd *iofd;
	int rc;

	OSMO_ASSERT(target->type == LOG_TGT_TYPE_FILE ||
		    target->type == LOG_TGT_TYPE_STDERR);

	if (target->type == LOG_TGT_TYPE_STDERR)
		return -ENOTSUP;

	if (target->tgt_file.out) { /* stream mode */
		fclose(target->tgt_file.out);
		target->tgt_file.out = fopen(target->tgt_file.fname, "a");
		if (!target->tgt_file.out)
			return -errno;
		return 0;
	}

	OSMO_ASSERT(target->tgt_file.wqueue);
	iofd = (struct osmo_io_fd *)target->tgt_file.wqueue->except_cb;
	OSMO_ASSERT(iofd);
	osmo_iofd_close(iofd);
	target->tgt_file.wqueue->bfd.fd = -1; /* Keep public field changes despite not used internally... */

	rc = open(target->tgt_file.fname, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0660);
	if (rc < 0)
		return -errno;

	rc = osmo_iofd_register(iofd, rc);
	if (rc < 0) {
		osmo_iofd_free(iofd);
		target->tgt_file.wqueue->except_cb = NULL; /* target->tgt_file.iofd = NULL */
		return -EIO;
	}
	target->tgt_file.wqueue->bfd.fd = rc; /* Keep public field changes despite not used internally... */
	return 0;
}

#if (!EMBEDDED)

/* This is the file-specific subclass destructor logic, called from
 * log_target_destroy(). User should call log_target_destroy() to destroy this
 * object. */
void log_target_file_destroy(struct log_target *target)
{

	OSMO_ASSERT(target->type == LOG_TGT_TYPE_FILE ||
		    target->type == LOG_TGT_TYPE_STDERR);

	if (target->tgt_file.out) {
		if (target->type == LOG_TGT_TYPE_FILE)
			fclose(target->tgt_file.out);
		target->tgt_file.out = NULL;
	}

	if (target->tgt_file.wqueue && target->tgt_file.wqueue->except_cb) { /* target->tgt_file.iofd */
		osmo_iofd_free((struct osmo_io_fd *)target->tgt_file.wqueue->except_cb);
		target->tgt_file.wqueue->except_cb = NULL; /* target->tgt_file.iofd = NULL */
		target->tgt_file.wqueue->bfd.fd = -1; /* Keep public field changes despite not used internally... */
	}

	talloc_free((void *)target->tgt_file.fname);
	target->tgt_file.fname = NULL;
}

static struct osmo_io_ops log_target_file_io_ops = {
	.read_cb = NULL,
	.write_cb = NULL,
};

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
	OSMO_ASSERT(target->tgt_file.wqueue && target->tgt_file.wqueue->except_cb);
	struct msgb *msg;
	struct osmo_io_fd *iofd = (struct osmo_io_fd *)target->tgt_file.wqueue->except_cb;
	void *pool_ctx = osmo_iofd_get_data(iofd);
	int rc;

	msg = msgb_alloc_c(pool_ctx, MAX_LOG_SIZE, "log_file_msg");
	if (!msg)
		return;

	/* we simply enqueue the log message to a write queue here, to avoid any blocking
	 * writes on the output file.  The write queue will tell us once the file is writable
	 * and call _file_wq_write_cb() */
	rc = log_output_buf((char *)msgb_data(msg), msgb_tailroom(msg), target, subsys, level,
			     file, line, cont, format, ap);
	msgb_put(msg, rc);

	rc = osmo_iofd_write_msgb(iofd, msg);
	if (rc < 0) {
		msgb_free(msg);
		/* TODO: increment some counter so we can see that messages were dropped */
	}
}

void _log_target_file_setup_talloc_pool(struct log_target *target)
{
	OSMO_ASSERT(target->tgt_file.wqueue && target->tgt_file.wqueue->except_cb);
	struct osmo_io_fd *iofd = (struct osmo_io_fd *)target->tgt_file.wqueue->except_cb;
	if (osmo_iofd_get_data(iofd))
		return; /* mempool already allocated */

#ifndef ENABLE_PSEUDOTALLOC
	void *pool_ctx;
	/* Allocate a talloc pool to avoid malloc() on the first 156
	* concurrently queued msgbs (~640KB per gsmtap_log target).
	* Once the talloc_pool is full, new normal talloc chunks will be used. */
	pool_ctx = _talloc_pooled_object(target, 0, "file_log_msgb_pool",
					 LOG_WQUEUE_LEN,
					 (sizeof(struct msgb) + MAX_LOG_SIZE) * LOG_WQUEUE_LEN);
	osmo_iofd_set_data(iofd, pool_ctx);
#else
	/* talloc pools not supported by pseudotalloc, allocate on usual msgb ctx instead: */
	extern void *tall_msgb_ctx;
	osmo_iofd_set_data(iofd, tall_msgb_ctx);
#endif /* ifndef ENABLE_PSEUDOTALLOC */
}

/*! switch from non-blocking/write-queue to blocking + buffered stream output
 *  \param[in] target log target which we should switch
 *  \return 0 on success; 1 if already switched before; negative on error
 *  Must be called with mutex osmo_log_tgt_mutex held, see log_tgt_mutex_lock.
 */
int log_target_file_switch_to_stream(struct log_target *target)
{
	struct osmo_io_fd *iofd;
	unsigned int prev_queue_len;

	if (!target)
		return -ENODEV;

	if (target->tgt_file.out) {
		/* target has already been switched over */
		return 1;
	}

	/* re-open output as stream */
	if (target->type == LOG_TGT_TYPE_STDERR)
		target->tgt_file.out = stderr;
	else
		target->tgt_file.out = fopen(target->tgt_file.fname, "a");

	if (!target->tgt_file.out)
		return -EIO;

	iofd = (struct osmo_io_fd *)target->tgt_file.wqueue->except_cb;
	prev_queue_len = osmo_iofd_txqueue_len(iofd);

	/* now that everything succeeded, we can finally close the old iofd */
	osmo_iofd_free(iofd);
	target->tgt_file.wqueue->except_cb = NULL; /* target->tgt_file.iofd = NULL */
	target->tgt_file.wqueue->bfd.fd = -1; /* Keep public field changes despite not used internally... */
	/* release the queue itself */
	talloc_free(target->tgt_file.wqueue);
	target->tgt_file.wqueue = NULL;
	target->output = _file_output_stream;
	target->raw_output = NULL;


	if (prev_queue_len > 0)
		LOGP(DLGLOBAL, LOGL_NOTICE,
		     "Dropped %u messages switching log target file to stream\n", prev_queue_len);

	return 0;
}

/* Owns fd on success, closes fd on error. */
int _log_target_file_setup_iofd(struct log_target *target, int fd)
{
	struct osmo_io_fd *iofd;
	int rc;

	/* XXX: This wq is only created to keep public log_target fields
	 * similar. It's not really used anymore internally, other than holding a
	 * struct osmo_io_fd in wq->except_cb...*/
	target->tgt_file.wqueue = talloc_zero(target, struct osmo_wqueue);
	OSMO_ASSERT(target->tgt_file.wqueue);
	osmo_wqueue_init(target->tgt_file.wqueue, LOG_WQUEUE_LEN);

	iofd = osmo_iofd_setup(target, fd, target->tgt_file.fname,
			       OSMO_IO_FD_MODE_READ_WRITE,
			       &log_target_file_io_ops, NULL);
	if (!iofd) {
		close(fd);
		return -EIO;
	}
	target->tgt_file.wqueue->except_cb = (int (*)(struct osmo_fd *))iofd;
	target->tgt_file.wqueue->bfd.fd = fd; /* Keep public field changes despite not used internally... */

	_log_target_file_setup_talloc_pool(target);
	osmo_iofd_set_txqueue_max_length(iofd, OSMO_MAX(osmo_iofd_get_txqueue_max_length(iofd), LOG_WQUEUE_LEN));

	/* Request to use 8 write buffers, or less if not as many are available: */
	rc = osmo_iofd_set_io_buffers(iofd, OSMO_IO_OP_WRITE, 0);
	rc = osmo_iofd_set_io_buffers(iofd, OSMO_IO_OP_WRITE, OSMO_MIN(rc, 8));

	rc = osmo_iofd_register(iofd, -1);
	if (rc < 0) {
		osmo_iofd_free(iofd);
		target->tgt_file.wqueue->except_cb = NULL;
		target->tgt_file.wqueue->bfd.fd = -1; /* Keep public field changes despite not used internally... */
		talloc_free(target->tgt_file.wqueue);
		return -EIO;
	}
	return 0;
}

/*! switch from blocking + buffered file output to non-blocking write-queue based output.
 *  \param[in] target log target which we should switch
 *  \return 0 on success; 1 if already switched before; negative on error
 *  Must be called with mutex osmo_log_tgt_mutex held, see log_tgt_mutex_lock.
 */
int log_target_file_switch_to_wqueue(struct log_target *target)
{
	int rc, fd;

	if (!target)
		return -ENODEV;

	if (!target->tgt_file.out) {
		/* target has already been switched over */
		return 1;
	}

	fflush(target->tgt_file.out);
	if (target->type == LOG_TGT_TYPE_FILE)
		fd = open(target->tgt_file.fname, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0660);
	else /* LOG_TGT_TYPE_STDERR: dup file so we can close it later with osmo_iofd_free() */
		fd = dup(STDERR_FILENO);

	if (fd < 0)
		return -errno;

	rc = _log_target_file_setup_iofd(target, fd);
	if (rc < 0)
		return rc;

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
	int rc, fd;

	target = log_target_create();
	if (!target)
		return NULL;

	target->type = LOG_TGT_TYPE_FILE;
	target->tgt_file.fname = talloc_strdup(target, fname);
	OSMO_ASSERT(target->tgt_file.fname);
	target->raw_output = _file_raw_output;

	fd = open(fname, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0660);
	if (fd < 0)
		goto free_ret;

	rc = _log_target_file_setup_iofd(target, fd);
	if (rc < 0)
		goto free_ret;

	return target;

free_ret:
	log_target_destroy(target);
	return NULL;
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
