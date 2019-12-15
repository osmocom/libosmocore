/* libosmocore integration with libusb-1.0
 *
 * (C) 2019 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <poll.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>

#include <libusb.h>

/***********************************************************************
 * logging integration
 ***********************************************************************/

#define DLUSB	DLINP

#ifdef LIBUSB_LOG_CB_CONTEXT /* introduced in 1.0.23 */
static const int usb2logl[] = {
	[LIBUSB_LOG_LEVEL_NONE] = LOGL_FATAL,
	[LIBUSB_LOG_LEVEL_ERROR] = LOGL_ERROR,
	[LIBUSB_LOG_LEVEL_WARNING] = LOGL_NOTICE,
	[LIBUSB_LOG_LEVEL_INFO] = LOGL_INFO,
	[LIBUSB_LOG_LEVEL_DEBUG] = LOGL_DEBUG,
};

/* called by libusb if it wants to log something */
static void libosmo_usb_log_cb(libusb_context *luctx, enum libusb_log_level level_usb, const char *str)
{
	int level = LOGL_NOTICE;

	if (level_usb < ARRAY_SIZE(usb2logl))
		level = usb2logl[level_usb];

	LOGP(DLUSB, level, "%s", str);
}
#endif /* LIBUSB_LOG_CB_CONTEXT */

/***********************************************************************
 * select loop integration
 ***********************************************************************/

static int osmo_usb_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	libusb_context *luctx = ofd->data;

	/* we assume that we're running Linux v2.6.27 with timerfd support here
	 * and hence don't have to perform manual timeout handling.  See
	 * "Notes on time-based events" at
	 * http://libusb.sourceforge.net/api-1.0/group__libusb__poll.html */
	struct timeval zero_tv = { 0, 0 };
	libusb_handle_events_timeout(luctx, &zero_tv);

	return 0;
}

/* called by libusb if it wants to add a file-descriptor */
static void osmo_usb_added_cb(int fd, short events, void *user_data)
{
	struct osmo_fd *ofd = talloc_zero(OTC_GLOBAL, struct osmo_fd);
	libusb_context *luctx = user_data;
	unsigned int when = 0;

	if (events & POLLIN)
		when |= OSMO_FD_READ;
	if (events & POLLOUT)
		when |= OSMO_FD_WRITE;

	osmo_fd_setup(ofd, fd, when, osmo_usb_fd_cb, luctx, 0);
	osmo_fd_register(ofd);
}

/* called by libusb if it wants to remove a file-descriptor */
static void osmo_usb_removed_cb(int fd, void *user_data)
{
	struct osmo_fd *ofd = osmo_fd_get_by_fd(fd);
	if (!fd)
		return;
	osmo_fd_unregister(ofd);
	talloc_free(ofd);
}


/***********************************************************************
 * initialization
 ***********************************************************************/

int osmo_libusb_init(libusb_context **pluctx)
{
	libusb_context *luctx = NULL;
	int rc;

	rc = libusb_init(pluctx);
	if (rc != 0)
		return rc;

	if (pluctx)
		luctx = *pluctx;

#ifdef LIBUSB_LOG_CB_CONTEXT /* introduced in 1.0.23 */
	libusb_set_log_cb(luctx, &libosmo_usb_log_cb, LIBUSB_LOG_CB_CONTEXT);
#endif

	libusb_set_pollfd_notifiers(luctx, osmo_usb_added_cb, osmo_usb_removed_cb, luctx);

	return 0;
}

void osmo_libusb_exit(libusb_context *luctx)
{
	/* we just assume libusb is cleaning up all the osmo_Fd's we've allocated */
	libusb_exit(luctx);
}
