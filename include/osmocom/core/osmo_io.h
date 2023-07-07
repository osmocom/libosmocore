/*! \file osmo_io.h
 *  io(_uring) abstraction osmo fd compatibility
 */

#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/utils.h>


#define LOGPIO(iofd, level, fmt, args...) \
	LOGP(DLIO, level, "iofd(%s)" fmt, iofd->name, ## args)

struct osmo_io_fd;

enum osmo_io_fd_mode {
	/*! use read() / write() calls */
	OSMO_IO_FD_MODE_READ_WRITE,
	/*! use recvfrom() / sendto() calls */
	OSMO_IO_FD_MODE_RECVFROM_SENDTO,
	/*! emulate sctp_recvmsg() and sctp_sendmsg() */
	OSMO_IO_FD_MODE_SCTP_RECVMSG_SENDMSG,
};

enum osmo_io_backend {
	OSMO_IO_BACKEND_POLL,
};

extern const struct value_string osmo_io_backend_names[];
static inline const char *osmo_io_backend_name(enum osmo_io_backend val)
{ return get_value_string(osmo_io_backend_names, val); }

struct osmo_io_ops {
	union {
		/* mode OSMO_IO_FD_MODE_READ_WRITE: */
		struct {
			/*! call-back function when something was read from fd */
			void (*read_cb)(struct osmo_io_fd *iofd, int res, struct msgb *msg);
			/*! call-back function when write has completed on fd */
			void (*write_cb)(struct osmo_io_fd *iofd, int res,
					 struct msgb *msg);
			/*! call-back function to segment the data at message boundaries.
			 *  Needs to return the size of the next message. If it returns
			 *  -EAGAIN or a value larger than msgb_length() (message is incomplete)
			 *  osmo_io will wait for more data to be read. Other negative values
			 *  cause the msg to be discarded.
			 *  If a full message was received (segmentation_cb() returns a value <= msgb_length())
			 *  the msgb will be trimmed to size by osmo_io and forwarded to the read call-back. Any
			 *  parsing done to the msgb by segmentation_cb() will be preserved for the read_cb()
			 *  (e.g. setting lxh or msgb->cb). */
			int (*segmentation_cb)(struct msgb *msg);
		};

		/* mode OSMO_IO_FD_MODE_RECVFROM_SENDTO: */
		struct {
			/*! call-back function emulating recvfrom */
			void (*recvfrom_cb)(struct osmo_io_fd *iofd, int res,
					    struct msgb *msg,
					    const struct osmo_sockaddr *saddr);
			/*! call-back function emulating sendto */
			void (*sendto_cb)(struct osmo_io_fd *iofd, int res,
					  struct msgb *msg,
					  const struct osmo_sockaddr *daddr);
		};
	};
};

void osmo_io_init(void);

struct osmo_io_fd *osmo_iofd_setup(const void *ctx, int fd, const char *name,
		  enum osmo_io_fd_mode mode, const struct osmo_io_ops *ioops, void *data);
int osmo_iofd_register(struct osmo_io_fd *iofd, int fd);
int osmo_iofd_unregister(struct osmo_io_fd *iofd);
unsigned int osmo_iofd_txqueue_len(struct osmo_io_fd *iofd);
void osmo_iofd_txqueue_clear(struct osmo_io_fd *iofd);
int osmo_iofd_close(struct osmo_io_fd *iofd);
void osmo_iofd_free(struct osmo_io_fd *iofd);

void osmo_iofd_notify_connected(struct osmo_io_fd *iofd);

int osmo_iofd_write_msgb(struct osmo_io_fd *iofd, struct msgb *msg);
int osmo_iofd_sendto_msgb(struct osmo_io_fd *iofd, struct msgb *msg, int sendto_flags,
			  const struct osmo_sockaddr *dest);

void osmo_iofd_set_alloc_info(struct osmo_io_fd *iofd, unsigned int size, unsigned int headroom);
void osmo_iofd_set_txqueue_max_length(struct osmo_io_fd *iofd, unsigned int size);
void *osmo_iofd_get_data(const struct osmo_io_fd *iofd);
void osmo_iofd_set_data(struct osmo_io_fd *iofd, void *data);

unsigned int osmo_iofd_get_priv_nr(const struct osmo_io_fd *iofd);
void osmo_iofd_set_priv_nr(struct osmo_io_fd *iofd, unsigned int priv_nr);

int osmo_iofd_get_fd(const struct osmo_io_fd *iofd);
const char *osmo_iofd_get_name(const struct osmo_io_fd *iofd);
void osmo_iofd_set_name(struct osmo_io_fd *iofd, const char *name);

void osmo_iofd_set_ioops(struct osmo_io_fd *iofd, const struct osmo_io_ops *ioops);
