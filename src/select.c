/*! \file select.c
 * select filedescriptor handling.
 * Taken from:
 * userspace logging daemon for the iptables ULOG target
 * of the linux 2.4 netfilter subsystem. */
/*
 * (C) 2000-2009 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserverd.
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301, USA.
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include "../config.h"

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>

/*! \addtogroup select
 *  @{
 *  select() loop abstraction
 *
 * \file select.c */

/* keep a set of file descriptors per-thread, so that each thread can have its own
 * distinct set of file descriptors to interact with */
static __thread int maxfd = 0;
static __thread struct llist_head osmo_fds; /* TLS cannot use LLIST_HEAD() */
static __thread int unregistered_count;

/*! Set up an osmo-fd. Will not register it.
 *  \param[inout] ofd Osmo FD to be set-up
 *  \param[in] fd OS-level file descriptor number
 *  \param[in] when bit-mask of OSMO_FD_{READ,WRITE,EXECEPT}
 *  \param[in] cb Call-back function to be called
 *  \param[in] data Private context pointer
 *  \param[in] priv_nr Private number
 */
void osmo_fd_setup(struct osmo_fd *ofd, int fd, unsigned int when,
		   int (*cb)(struct osmo_fd *fd, unsigned int what),
		   void *data, unsigned int priv_nr)
{
	ofd->fd = fd;
	ofd->when = when;
	ofd->cb = cb;
	ofd->data = data;
	ofd->priv_nr = priv_nr;
}

/*! Check if a file descriptor is already registered
 *  \param[in] fd osmocom file descriptor to be checked
 *  \returns true if registered; otherwise false
 */
bool osmo_fd_is_registered(struct osmo_fd *fd)
{
	struct osmo_fd *entry;
	llist_for_each_entry(entry, &osmo_fds, list) {
		if (entry == fd) {
			return true;
		}
	}

	return false;
}

/*! Register a new file descriptor with select loop abstraction
 *  \param[in] fd osmocom file descriptor to be registered
 *  \returns 0 on success; negative in case of error
 */
int osmo_fd_register(struct osmo_fd *fd)
{
	int flags;

	/* make FD nonblocking */
	flags = fcntl(fd->fd, F_GETFL);
	if (flags < 0)
		return flags;
	flags |= O_NONBLOCK;
	flags = fcntl(fd->fd, F_SETFL, flags);
	if (flags < 0)
		return flags;

	/* set close-on-exec flag */
	flags = fcntl(fd->fd, F_GETFD);
	if (flags < 0)
		return flags;
	flags |= FD_CLOEXEC;
	flags = fcntl(fd->fd, F_SETFD, flags);
	if (flags < 0)
		return flags;

	/* Register FD */
	if (fd->fd > maxfd)
		maxfd = fd->fd;

#ifdef OSMO_FD_CHECK
	if (osmo_fd_is_registered(fd)) {
		fprintf(stderr, "Adding a osmo_fd that is already in the list.\n");
		return 0;
	}
#endif

	llist_add_tail(&fd->list, &osmo_fds);

	return 0;
}

/*! Unregister a file descriptor from select loop abstraction
 *  \param[in] fd osmocom file descriptor to be unregistered
 */
void osmo_fd_unregister(struct osmo_fd *fd)
{
	/* Note: when fd is inside the osmo_fds list (not registered before)
	 * this function will crash! If in doubt, check file descriptor with
	 * osmo_fd_is_registered() */
	unregistered_count++;
	llist_del(&fd->list);
}

/*! Close a file descriptor, mark it as closed + unregister from select loop abstraction
 *  \param[in] fd osmocom file descriptor to be unregistered + closed
 *
 *  If \a fd is registered, we unregister it from the select() loop
 *  abstraction.  We then close the fd and set it to -1, as well as
 *  unsetting any 'when' flags */
void osmo_fd_close(struct osmo_fd *fd)
{
	if (osmo_fd_is_registered(fd))
		osmo_fd_unregister(fd);
	if (fd->fd != -1)
		close(fd->fd);
	fd->fd = -1;
	fd->when = 0;
}

/*! Populate the fd_sets and return the highest fd number
 *  \param[in] _rset The readfds to populate
 *  \param[in] _wset The wrtiefds to populate
 *  \param[in] _eset The errorfds to populate
 *
 *  \returns The highest file descriptor seen or 0 on an empty list
 */
inline int osmo_fd_fill_fds(void *_rset, void *_wset, void *_eset)
{
	fd_set *readset = _rset, *writeset = _wset, *exceptset = _eset;
	struct osmo_fd *ufd;
	int highfd = 0;

	llist_for_each_entry(ufd, &osmo_fds, list) {
		if (ufd->when & OSMO_FD_READ)
			FD_SET(ufd->fd, readset);

		if (ufd->when & OSMO_FD_WRITE)
			FD_SET(ufd->fd, writeset);

		if (ufd->when & OSMO_FD_EXCEPT)
			FD_SET(ufd->fd, exceptset);

		if (ufd->fd > highfd)
			highfd = ufd->fd;
	}

	return highfd;
}

inline int osmo_fd_disp_fds(void *_rset, void *_wset, void *_eset)
{
	struct osmo_fd *ufd, *tmp;
	int work = 0;
	fd_set *readset = _rset, *writeset = _wset, *exceptset = _eset;

restart:
	unregistered_count = 0;
	llist_for_each_entry_safe(ufd, tmp, &osmo_fds, list) {
		int flags = 0;

		if (FD_ISSET(ufd->fd, readset)) {
			flags |= OSMO_FD_READ;
			FD_CLR(ufd->fd, readset);
		}

		if (FD_ISSET(ufd->fd, writeset)) {
			flags |= OSMO_FD_WRITE;
			FD_CLR(ufd->fd, writeset);
		}

		if (FD_ISSET(ufd->fd, exceptset)) {
			flags |= OSMO_FD_EXCEPT;
			FD_CLR(ufd->fd, exceptset);
		}

		if (flags) {
			work = 1;
			/* make sure to clear any log context before processing the next incoming message
			 * as part of some file descriptor callback.  This effectively prevents "context
			 * leaking" from processing of one message into processing of the next message as part
			 * of one iteration through the list of file descriptors here.  See OS#3813 */
			log_reset_context();
			ufd->cb(ufd, flags);
		}
		/* ugly, ugly hack. If more than one filedescriptor was
		 * unregistered, they might have been consecutive and
		 * llist_for_each_entry_safe() is no longer safe */
		/* this seems to happen with the last element of the list as well */
		if (unregistered_count >= 1)
			goto restart;
	}

	return work;
}

static int _osmo_select_main(int polling)
{
	fd_set readset, writeset, exceptset;
	int rc;
	struct timeval no_time = {0, 0};

	FD_ZERO(&readset);
	FD_ZERO(&writeset);
	FD_ZERO(&exceptset);

	/* prepare read and write fdsets */
	osmo_fd_fill_fds(&readset, &writeset, &exceptset);

	if (!polling)
		osmo_timers_prepare();
	rc = select(maxfd+1, &readset, &writeset, &exceptset, polling ? &no_time : osmo_timers_nearest());
	if (rc < 0)
		return 0;

	/* fire timers */
	osmo_timers_update();

	OSMO_ASSERT(osmo_ctx->select);

	/* call registered callback functions */
	return osmo_fd_disp_fds(&readset, &writeset, &exceptset);
}

/*! select main loop integration
 *  \param[in] polling should we pollonly (1) or block on select (0)
 *  \returns 0 if no fd handled; 1 if fd handled; negative in case of error
 */
int osmo_select_main(int polling)
{
	int rc = _osmo_select_main(polling);
#ifndef EMBEDDED
	if (talloc_total_size(osmo_ctx->select) != 0) {
		osmo_panic("You cannot use the 'select' volatile "
			   "context if you don't use osmo_select_main_ctx()!\n");
	}
#endif
	return rc;
}

#ifndef EMBEDDED
/*! select main loop integration with temporary select-dispatch talloc context
 *  \param[in] polling should we pollonly (1) or block on select (0)
 *  \returns 0 if no fd handled; 1 if fd handled; negative in case of error
 */
int osmo_select_main_ctx(int polling)
{
	int rc = _osmo_select_main(polling);
	/* free all the children of the volatile 'select' scope context */
	talloc_free_children(osmo_ctx->select);
	return rc;
}
#endif

/*! find an osmo_fd based on the integer fd
 *  \param[in] fd file descriptor to use as search key
 *  \returns \ref osmo_fd for \ref fd; NULL in case it doesn't exist */
struct osmo_fd *osmo_fd_get_by_fd(int fd)
{
	struct osmo_fd *ofd;

	llist_for_each_entry(ofd, &osmo_fds, list) {
		if (ofd->fd == fd)
			return ofd;
	}
	return NULL;
}

/*! initialize the osmocom select abstraction for the current thread */
void osmo_select_init(void)
{
	INIT_LLIST_HEAD(&osmo_fds);
}

/* ensure main thread always has pre-initialized osmo_fds */
static __attribute__((constructor)) void on_dso_load_select(void)
{
	osmo_select_init();
}

#ifdef HAVE_SYS_TIMERFD_H
#include <sys/timerfd.h>

/*! disable the osmocom-wrapped timerfd */
int osmo_timerfd_disable(struct osmo_fd *ofd)
{
	const struct itimerspec its_null = {
		.it_value = { 0, 0 },
		.it_interval = { 0, 0 },
	};
	return timerfd_settime(ofd->fd, 0, &its_null, NULL);
}

/*! schedule the osmocom-wrapped timerfd to occur first at \a first, then periodically at \a interval
 *  \param[in] ofd Osmocom wrapped timerfd
 *  \param[in] first Relative time at which the timer should first execute (NULL = \a interval)
 *  \param[in] interval Time interval at which subsequent timer shall fire
 *  \returns 0 on success; negative on error */
int osmo_timerfd_schedule(struct osmo_fd *ofd, const struct timespec *first,
			  const struct timespec *interval)
{
	struct itimerspec its;

	if (ofd->fd < 0)
		return -EINVAL;

	/* first expiration */
	if (first)
		its.it_value = *first;
	else
		its.it_value = *interval;
	/* repeating interval */
	its.it_interval = *interval;

	return timerfd_settime(ofd->fd, 0, &its, NULL);
}

/*! setup osmocom-wrapped timerfd
 *  \param[inout] ofd Osmocom-wrapped timerfd on which to operate
 *  \param[in] cb Call-back function called when timerfd becomes readable
 *  \param[in] data Opaque data to be passed on to call-back
 *  \returns 0 on success; negative on error
 *
 *  We simply initialize the data structures here, but do not yet
 *  schedule the timer.
 */
int osmo_timerfd_setup(struct osmo_fd *ofd, int (*cb)(struct osmo_fd *, unsigned int), void *data)
{
	ofd->cb = cb;
	ofd->data = data;
	ofd->when = OSMO_FD_READ;

	if (ofd->fd < 0) {
		int rc;

		ofd->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
		if (ofd->fd < 0)
			return ofd->fd;

		rc = osmo_fd_register(ofd);
		if (rc < 0) {
			osmo_fd_unregister(ofd);
			close(ofd->fd);
			ofd->fd = -1;
			return rc;
		}
	}
	return 0;
}

#endif /* HAVE_SYS_TIMERFD_H */

#ifdef HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>

static int signalfd_callback(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_signalfd *osfd = ofd->data;
	struct signalfd_siginfo fdsi;
	int rc;

	rc = read(ofd->fd, &fdsi, sizeof(fdsi));
	if (rc < 0) {
		osmo_fd_unregister(ofd);
		close(ofd->fd);
		ofd->fd = -1;
		return rc;
	}

	osfd->cb(osfd, &fdsi);

	return 0;
};

/*! create a signalfd and register it with osmocom select loop.
 *  \param[in] ctx talloc context from which osmo_signalfd is to be allocated
 *  \param[in] set of signals to be accept via this file descriptor
 *  \param[in] cb call-back function to be called for each arriving signal
 *  \param[in] data opaque user-provided data to pass to callback
 *  \returns pointer to newly-allocated + registered osmo_signalfd; NULL on error */
struct osmo_signalfd *
osmo_signalfd_setup(void *ctx, sigset_t set, osmo_signalfd_cb *cb, void *data)
{
	struct osmo_signalfd *osfd = talloc_size(ctx, sizeof(*osfd));
	int fd, rc;

	if (!osfd)
		return NULL;

	osfd->data = data;
	osfd->sigset = set;
	osfd->cb = cb;

	fd = signalfd(-1, &osfd->sigset, SFD_NONBLOCK);
	if (fd < 0) {
		talloc_free(osfd);
		return NULL;
	}

	osmo_fd_setup(&osfd->ofd, fd, OSMO_FD_READ, signalfd_callback, osfd, 0);
	rc = osmo_fd_register(&osfd->ofd);
	if (rc < 0) {
		close(fd);
		talloc_free(osfd);
		return NULL;
	}

	return osfd;
}

#endif /* HAVE_SYS_SIGNALFD_H */

/*! @} */

#endif /* _HAVE_SYS_SELECT_H */
