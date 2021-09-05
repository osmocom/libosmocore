/*! \file control_if.c
 * SNMP-like status interface. */
/*
 * (C) 2010-2011 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2010-2011 by On-Waves
 * (C) 2014 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016-2017 by sysmocom - s.f.m.c. GmbH
 *
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

#include "config.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/select.h>
#include <osmocom/core/counter.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>

#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/gsm/ipa.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vector.h>

extern int osmo_fsm_ctrl_cmds_install(void);

vector ctrl_node_vec;

/* global list of control interface lookup helpers */
struct lookup_helper {
	struct llist_head list;
	ctrl_cmd_lookup lookup;
};
static LLIST_HEAD(ctrl_lookup_helpers);

/*! Parse ascii-encoded decimal number at vline[i]
 *  \param[in] vline vector containing a tokenized line
 *  \param[in] i index into the vector \a vline
 *  \param[out] num parsed decimal integer number at vline[i]
 *  \returns 1 on success; 0 in case of error */
int ctrl_parse_get_num(vector vline, int i, long *num)
{
	char *token;
	int64_t val;

	if (i >= vector_active(vline))
		return 0;
	token = vector_slot(vline, i);

	if (osmo_str_to_int64(&val, token, 10, LONG_MIN, LONG_MAX))
		return 0;
	*num = (long)val;
	return 1;
}

/*! Send a CTRL command to all connections.
 *  \param[in] ctrl global control handle
 *  \param[in] cmd command to send to all connections in \ctrl
 *  \returns number of times the command has been sent */
int ctrl_cmd_send_to_all(struct ctrl_handle *ctrl, struct ctrl_cmd *cmd)
{
	struct ctrl_connection *ccon;
	int ret = 0;

	llist_for_each_entry(ccon, &ctrl->ccon_list, list_entry) {
		if (ccon == cmd->ccon)
			continue;
		if (ctrl_cmd_send(&ccon->write_queue, cmd))
			ret++;
	}
	return ret;
}

/*! Encode a CTRL command and append it to the given write queue
 *  \param[inout] queue write queue to which encoded \a cmd shall be appended
 *  \param[in] cmd decoded command representation
 *  \returns 0 in case of success; negative on error */
int ctrl_cmd_send(struct osmo_wqueue *queue, struct ctrl_cmd *cmd)
{
	int ret;
	struct msgb *msg;

	msg = ctrl_cmd_make(cmd);
	if (!msg) {
		LOGP(DLCTRL, LOGL_ERROR, "Could not generate msg\n");
		return -1;
	}

	ipa_prepend_header_ext(msg, IPAC_PROTO_EXT_CTRL);
	ipa_prepend_header(msg, IPAC_PROTO_OSMO);

	ret = osmo_wqueue_enqueue(queue, msg);
	if (ret != 0) {
		LOGP(DLCTRL, LOGL_ERROR, "Failed to enqueue the command.\n");
		msgb_free(msg);
	}
	return ret;
}

/*! Send TRAP over given Control Interface
 *  \param[in] ctrl Control Interface over which TRAP will be sent
 *  \param[in] name Name of the TRAP variable
 *  \param[in] value Value of the TRAP variable
 *  \return Negative value on error, result of ctrl_cmd_send_to_all() otherwise
 */
int ctrl_cmd_send_trap(struct ctrl_handle *ctrl, const char *name, char *value)
{
	int r;
	struct ctrl_cmd *cmd = ctrl_cmd_create(NULL, CTRL_TYPE_TRAP);
	if (!cmd)
		return -ENOMEM;

	cmd->id = CTRL_CMD_TRAP_ID; /* It's a TRAP! */
	cmd->variable = (char *) name;
	cmd->reply = value;
	r = ctrl_cmd_send_to_all(ctrl, cmd);
	talloc_free(cmd);
	return r;
}

/*! Copy given \a cmd and convert copy to CTRL_TYPE_TRAP.
 *  \param[in] cmd command to be copied
 *  \returns pointer to newly-allocated copy of type TRAP. Allocated as sibling of \a cmd */
struct ctrl_cmd *ctrl_cmd_trap(struct ctrl_cmd *cmd)
{
	struct ctrl_cmd *trap;

	trap = ctrl_cmd_cpy(cmd, cmd);
	if (!trap)
		return NULL;

	trap->ccon = cmd->ccon;
	trap->type = CTRL_TYPE_TRAP;
	return trap;
}

static void control_close_conn(struct ctrl_connection *ccon)
{
	struct ctrl_cmd_def *cd, *cd2;
	char *name = osmo_sock_get_name(ccon, ccon->write_queue.bfd.fd);

	LOGP(DLCTRL, LOGL_INFO, "close()d CTRL connection %s\n", name);
	talloc_free(name);

	osmo_wqueue_clear(&ccon->write_queue);
	close(ccon->write_queue.bfd.fd);
	osmo_fd_unregister(&ccon->write_queue.bfd);
	llist_del(&ccon->list_entry);
	if (ccon->closed_cb)
		ccon->closed_cb(ccon);
	msgb_free(ccon->pending_msg);

	/* clean up deferred commands */
	llist_for_each_entry_safe(cd, cd2, &ccon->def_cmds, list) {
		/* delete from list of def_cmds for this ccon */
		llist_del(&cd->list);
		/* not strictly needed as this is a slave to the ccon which we
		 * are about to free anyway */
		talloc_free(cd->cmd);
		/* set the CMD to null, this is the indication to the user that
		 * the connection for this command has gone */
		cd->cmd = NULL;
	}

	talloc_free(ccon);
}

int ctrl_cmd_handle(struct ctrl_handle *ctrl, struct ctrl_cmd *cmd,
		    void *data)
{
	char *request;
	int i, j, ret, node;
	bool break_cycle = false;
	vector vline, cmdvec, cmds_vec;

	if (cmd->type == CTRL_TYPE_SET_REPLY ||
	    cmd->type == CTRL_TYPE_GET_REPLY) {
		if (ctrl->reply_cb) {
			ctrl->reply_cb(ctrl, cmd, data);
			return CTRL_CMD_HANDLED;
		}
		if (strncmp(cmd->reply, "OK", 2) == 0) {
			LOGP(DLCTRL, LOGL_DEBUG, "%s <%s> for %s is OK\n",
			     get_value_string(ctrl_type_vals, cmd->type),
			     cmd->id, cmd->variable);
			return CTRL_CMD_HANDLED;
		}
	}

	if (cmd->type == CTRL_TYPE_ERROR) {
			LOGP(DLCTRL, LOGL_ERROR, "%s <%s> for %s is %s\n",
			     get_value_string(ctrl_type_vals, cmd->type),
			     cmd->id, cmd->variable, cmd->reply);
			return CTRL_CMD_HANDLED;
	}

	ret = CTRL_CMD_ERROR;
	cmd->reply = NULL;
	node = CTRL_NODE_ROOT;
	cmd->node = data;

	request = talloc_strdup(cmd, cmd->variable);
	if (!request)
		goto err;

	for (i = 0; i < strlen(request); i++) {
		if (request[i] == '.')
			request[i] = ' ';
	}

	vline = cmd_make_strvec(request);
	talloc_free(request);
	if (!vline) {
		cmd->reply = "cmd_make_strvec failed.";
		goto err;
	}

	for (i = 0; i < vector_active(vline); i++) {
		struct lookup_helper *lh;
		int rc;

		if (ctrl->lookup)
			rc = ctrl->lookup(data, vline, &node, &cmd->node, &i);
		else
			rc = 0;

		if (!rc) {
			llist_for_each_entry(lh, &ctrl_lookup_helpers, list) {
				rc = lh->lookup(data, vline, &node, &cmd->node, &i);
				if (rc)
					break;
			}
		}

		switch (rc) {
		case 1: /* do nothing */
			break;
		case -ENODEV:
			cmd_free_strvec(vline);
			cmd->type = CTRL_TYPE_ERROR;
			cmd->reply = "Error while resolving object";
			return ret;
		case -ERANGE:
			cmd_free_strvec(vline);
			cmd->type = CTRL_TYPE_ERROR;
			cmd->reply = "Error while parsing the index.";
			return ret;
		default: /* If we're here the rest must be the command */
			cmdvec = vector_init(vector_active(vline)-i);
			for (j = i; j < vector_active(vline); j++) {
				vector_set(cmdvec, vector_slot(vline, j));
			}

			/* Get the command vector of the right node */
			cmds_vec = vector_lookup(ctrl_node_vec, node);

			if (!cmds_vec) {
				cmd->reply = "Command not found.";
				vector_free(cmdvec);
				break;
			}

			ret = ctrl_cmd_exec(cmdvec, cmd, cmds_vec, data);
			vector_free(cmdvec);
			break_cycle = true;
			break;
		}

		if (break_cycle)
			break;

		if (i+1 == vector_active(vline))
			cmd->reply = "Command not present.";
	}

	cmd_free_strvec(vline);

err:
	if (!cmd->reply) {
		if (ret == CTRL_CMD_ERROR) {
			cmd->reply = "An error has occurred.";
			LOGP(DLCTRL, LOGL_NOTICE,
			     "%s: cmd->reply has not been set (ERROR).\n",
			     cmd->variable);
		} else if (ret == CTRL_CMD_REPLY) {
			LOGP(DLCTRL, LOGL_NOTICE,
			     "%s: cmd->reply has not been set (type = %d).\n",
			     cmd->variable, cmd->type);
			cmd->reply = "";
		} else {
			cmd->reply = "Command has been handled.";
		}
	}

	if (ret == CTRL_CMD_ERROR)
		cmd->type = CTRL_TYPE_ERROR;
	return ret;
}


static int handle_control_read(struct osmo_fd * bfd)
{
	int ret;
	struct osmo_wqueue *queue;
	struct ctrl_connection *ccon;
	struct msgb *msg = NULL;
	struct ctrl_handle *ctrl = bfd->data;

	queue = container_of(bfd, struct osmo_wqueue, bfd);
	ccon = container_of(queue, struct ctrl_connection, write_queue);

	ret = ipa_msg_recv_buffered(bfd->fd, &msg, &ccon->pending_msg);
	if (ret == 0) {
		/* msg was already discarded. */
		goto close_fd;
	} else if (ret == -EAGAIN) {
		/* received part of a message, it is stored in ccon->pending_msg and there's
		 * nothing left to do now. */
		return 0;
	} else if (ret < 0) {
		LOGP(DLCTRL, LOGL_ERROR, "Failed to parse ip access message: %d (%s)\n", ret, strerror(-ret));
		return 0;
	}

	ret = ctrl_handle_msg(ctrl, ccon, msg);
	msgb_free(msg);
	if (ret)
		goto close_fd;

	return 0;

close_fd:
	control_close_conn(ccon);
	return -EBADF;
}

/*! Handle a received CTRL command contained in a \ref msgb.
 *  \param[in] ctrl CTRL interface handle
 *  \param[in] ccon CTRL connection through which the command was received
 *  \param[in] msg message buffer containing CTRL command including IPA+IPA_EXT headers
 *  \returns 0 on success; negative on error */
int ctrl_handle_msg(struct ctrl_handle *ctrl, struct ctrl_connection *ccon, struct msgb *msg)
{
	struct ctrl_cmd *cmd;
	bool parse_failed;
	struct ipaccess_head *iph;
	struct ipaccess_head_ext *iph_ext;
	int result;

	if (msg->len < sizeof(*iph)) {
		LOGP(DLCTRL, LOGL_ERROR, "The message is too short.\n");
		return -EINVAL;
	}
	iph = (struct ipaccess_head *) msg->data;
	if (iph->proto == IPAC_PROTO_IPACCESS) {
		uint8_t msg_type = *(msg->l2h);
		switch (msg_type) {
		case IPAC_MSGT_PING:
			if (ipa_ccm_send_pong(ccon->write_queue.bfd.fd) < 0)
				LOGP(DLINP, LOGL_ERROR, "Cannot send PONG message. Reason: %s\n", strerror(errno));
			break;
		case IPAC_MSGT_PONG:
			break;
		case IPAC_MSGT_ID_ACK:
			if (ipa_ccm_send_id_ack(ccon->write_queue.bfd.fd) < 0)
				LOGP(DLINP, LOGL_ERROR, "Cannot send ID_ACK message. Reason: %s\n", strerror(errno));
			break;
		default:
			LOGP(DLCTRL, LOGL_DEBUG, "Received unhandled IPACCESS protocol message of type 0x%x: %s\n",
			     msg_type, msgb_hexdump(msg));
			break;
		}
		return 0;
	}
	if (iph->proto != IPAC_PROTO_OSMO) {
		LOGP(DLCTRL, LOGL_ERROR, "Protocol mismatch. Received protocol 0x%x message: %s\n",
		     iph->proto, msgb_hexdump(msg));
		return -EINVAL;
	}
	if (msg->len < sizeof(*iph) + sizeof(*iph_ext)) {
		LOGP(DLCTRL, LOGL_ERROR, "The message is too short.\n");
		return -EINVAL;
	}
	iph_ext = (struct ipaccess_head_ext *) iph->data;
	if (iph_ext->proto != IPAC_PROTO_EXT_CTRL) {
		LOGP(DLCTRL, LOGL_ERROR, "Extended protocol mismatch. Received protocol 0x%x message: %s\n",
		     iph_ext->proto, msgb_hexdump(msg));
		return -EINVAL;
	}

	msg->l2h = iph_ext->data;

	cmd = ctrl_cmd_parse3(ccon, msg, &parse_failed);

	if (!cmd) {
		/* should never happen */
		cmd = talloc_zero(ccon, struct ctrl_cmd);
		if (!cmd)
			return -ENOMEM;
		LOGP(DLCTRL, LOGL_ERROR, "Command parser error.\n");
		cmd->type = CTRL_TYPE_ERROR;
		cmd->id = "err";
		cmd->reply = "Command parser error.";
	}

	/* In case of error, reply with the error message right away. */
	if (cmd->type == CTRL_TYPE_ERROR && parse_failed)
		goto send_reply;

	cmd->ccon = ccon;
	result = ctrl_cmd_handle(ctrl, cmd, ctrl->data);


	if (cmd->defer) {
		/* The command is still stored as ctrl_cmd_def.cmd, in the def_cmds list.
		 * Just leave hanging for deferred handling. Reply will happen later. */
		return 0;
	}

	/* On CTRL_CMD_HANDLED, no reply needs to be sent back. */
	if (result == CTRL_CMD_HANDLED)
		goto just_free;

send_reply:
	/* There is a reply or error that should be reported back to the sender. */
	ctrl_cmd_send(&ccon->write_queue, cmd);
just_free:
	talloc_free(cmd);
	return 0;
}

static int control_write_cb(struct osmo_fd *bfd, struct msgb *msg)
{
	struct osmo_wqueue *queue;
	struct ctrl_connection *ccon;
	int rc;

	queue = container_of(bfd, struct osmo_wqueue, bfd);
	ccon = container_of(queue, struct ctrl_connection, write_queue);

	rc = write(bfd->fd, msg->data, msg->len);
	if (rc == 0) {
		control_close_conn(ccon);
		return -EBADF;
	}
	if (rc < 0) {
		LOGP(DLCTRL, LOGL_ERROR, "Failed to write message to the CTRL connection.\n");
		return 0;
	}
	if (rc < msg->len) {
		msgb_pull(msg, rc);
		return -EAGAIN;
	}

	return 0;
}

/*! Allocate CTRL connection
 *  \param[in] ctx Context from which talloc should allocate it
 *  \param[in] data caller's private data parameter which should assigned to
               write queue's file descriptor data parameter.
 *  \return Allocated CTRL connection structure or NULL in case of errors
 */
struct ctrl_connection *osmo_ctrl_conn_alloc(void *ctx, void *data)
{
	struct ctrl_connection *ccon = talloc_zero(ctx, struct ctrl_connection);
	if (!ccon)
		return NULL;

	osmo_wqueue_init(&ccon->write_queue, 100);
	/* Error handling here? */

	INIT_LLIST_HEAD(&ccon->cmds);
	INIT_LLIST_HEAD(&ccon->def_cmds);

	ccon->write_queue.bfd.data = data;
	ccon->write_queue.bfd.fd = -1;
	ccon->write_queue.write_cb = control_write_cb;
	ccon->write_queue.read_cb = handle_control_read;

	return ccon;
}

static int listen_fd_cb(struct osmo_fd *listen_bfd, unsigned int what)
{
	int ret, fd, on;
	struct ctrl_handle *ctrl;
	struct ctrl_connection *ccon;
	char *name;


	if (!(what & OSMO_FD_READ))
		return 0;

	fd = accept(listen_bfd->fd, NULL, NULL);
	if (fd < 0) {
		perror("accept");
		return fd;
	}

#ifdef TCP_NODELAY
	on = 1;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret != 0) {
		LOGP(DLCTRL, LOGL_ERROR, "Failed to set TCP_NODELAY: %s\n", strerror(errno));
		close(fd);
		return ret;
	}
#endif
	ctrl = listen_bfd->data;
	ccon = osmo_ctrl_conn_alloc(listen_bfd->data, ctrl);
	if (!ccon) {
		LOGP(DLCTRL, LOGL_ERROR, "Failed to allocate.\n");
		close(fd);
		return -1;
	}

	name = osmo_sock_get_name(ccon, fd);
	LOGP(DLCTRL, LOGL_INFO, "accept()ed new CTRL connection from %s\n", name);

	ccon->write_queue.bfd.fd = fd;
	ccon->write_queue.bfd.when = OSMO_FD_READ;

	ret = osmo_fd_register(&ccon->write_queue.bfd);
	if (ret < 0) {
		LOGP(DLCTRL, LOGL_ERROR, "Could not register FD.\n");
		close(ccon->write_queue.bfd.fd);
		talloc_free(ccon);
	}

	llist_add(&ccon->list_entry, &ctrl->ccon_list);

	return ret;
}

static uint64_t get_rate_ctr_value(const struct rate_ctr *ctr, int intv, const char *grp)
{
	if (intv >= RATE_CTR_INTV_NUM) {
		LOGP(DLCTRL, LOGL_ERROR, "Unexpected interval value %d while trying to get rate counter value in %s\n",
		     intv, grp);
		return 0;
	}

	/* Absolute value */
	if (intv == -1) {
		return  ctr->current;
	} else {
		return ctr->intv[intv].rate;
	}
}

static int get_rate_ctr_group_idx(struct rate_ctr_group *ctrg, int intv, struct ctrl_cmd *cmd)
{
	unsigned int i;
	for (i = 0; i < ctrg->desc->num_ctr; i++) {
		ctrl_cmd_reply_printf(cmd, "%s %"PRIu64";", ctrg->desc->ctr_desc[i].name,
				      get_rate_ctr_value(rate_ctr_group_get_ctr(ctrg, i), intv, ctrg->desc->group_name_prefix));
		if (!cmd->reply) {
			cmd->reply = "OOM";
			return CTRL_CMD_ERROR;
		}
	}

	return CTRL_CMD_REPLY;
}

static int ctrl_rate_ctr_group_handler(struct rate_ctr_group *ctrg, void *data)
{
	struct ctrl_cmd *cmd = data;

	cmd->reply = talloc_asprintf_append(cmd->reply, "%s.%u;", ctrg->desc->group_name_prefix, ctrg->idx);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return -1;
	}

	return 0;
}

/* rate_ctr */
CTRL_CMD_DEFINE(rate_ctr, "rate_ctr *");
static int get_rate_ctr(struct ctrl_cmd *cmd, void *data)
{
	int intv;
	unsigned int idx;
	char *ctr_group, *ctr_idx, *tmp, *dup, *saveptr, *interval;
	struct rate_ctr_group *ctrg;
	const struct rate_ctr *ctr;

	dup = talloc_strdup(cmd, cmd->variable);
	if (!dup)
		goto oom;

	/* Skip over possible prefixes (net.) */
	tmp = strstr(dup, "rate_ctr");
	if (!tmp) {
		talloc_free(dup);
		cmd->reply = "rate_ctr not a token in rate_ctr command!";
		goto err;
	}

	strtok_r(tmp, ".", &saveptr);
	interval = strtok_r(NULL, ".", &saveptr);
	if (!interval) {
		talloc_free(dup);
		cmd->reply = "Missing interval.";
		goto err;
	}

	if (!strcmp(interval, "abs")) {
		intv = -1;
	} else if (!strcmp(interval, "per_sec")) {
		intv = RATE_CTR_INTV_SEC;
	} else if (!strcmp(interval, "per_min")) {
		intv = RATE_CTR_INTV_MIN;
	} else if (!strcmp(interval, "per_hour")) {
		intv = RATE_CTR_INTV_HOUR;
	} else if (!strcmp(interval, "per_day")) {
		intv = RATE_CTR_INTV_DAY;
	} else if (!strcmp(interval, "*")) {
		intv = rate_ctr_for_each_group(ctrl_rate_ctr_group_handler, cmd);
		if (intv < 0)
			return CTRL_CMD_ERROR;
		return CTRL_CMD_REPLY;
	} else {
		talloc_free(dup);
		cmd->reply = "Wrong interval. Expecting 'per_sec', 'per_min', 'per_hour', 'per_day' or 'abs' value.";
		goto err;
	}

	ctr_group = strtok_r(NULL, ".", &saveptr);
	ctr_idx = strtok_r(NULL, ".", &saveptr);
	if (!ctr_group || !ctr_idx) {
		talloc_free(dup);
		cmd->reply = "Counter group must be of name.index form e. g. "
			"e1inp.0";
		goto err;
	}

	idx = atoi(ctr_idx);

	ctrg = rate_ctr_get_group_by_name_idx(ctr_group, idx);
	if (!ctrg) {
		talloc_free(dup);
		cmd->reply = "Counter group with given name and index not found";
		goto err;
	}

	if (!strlen(saveptr)) {
		talloc_free(dup);
		return get_rate_ctr_group_idx(ctrg, intv, cmd);
	}

	ctr = rate_ctr_get_by_name(ctrg, saveptr);
	if (!ctr) {
		cmd->reply = "Counter name not found.";
		talloc_free(dup);
		goto err;
	}

	talloc_free(dup);

	cmd->reply = talloc_asprintf(cmd, "%"PRIu64, get_rate_ctr_value(ctr, intv, ctrg->desc->group_name_prefix));
	if (!cmd->reply)
		goto oom;

	return CTRL_CMD_REPLY;
oom:
	cmd->reply = "OOM";
err:
	return CTRL_CMD_ERROR;
}

static int set_rate_ctr(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "Can't set rate counter.";

	return CTRL_CMD_ERROR;
}

static int verify_rate_ctr(struct ctrl_cmd *cmd, const char *value, void *data)
{
	return 0;
}

/* Expose all stat_item groups on CTRL, as read-only variables of the form:
 * stat_item.(last|...).group_name.N.item_name
 * stat_item.(last|...).group_name.by_name.group_idx_name.item_name
 */
CTRL_CMD_DEFINE_RO(stat_item, "stat_item *");
static int get_stat_item(struct ctrl_cmd *cmd, void *data)
{
	char *dup;
	char *saveptr;
	char *value_type;
	char *group_name;
	char *group_idx_str;
	char *item_name;
	char *tmp;
	int32_t val;
	struct osmo_stat_item_group *statg;
	const struct osmo_stat_item *stat_item;

	/* cmd will be freed in control_if.c after handling here, so no need to free the dup string. */
	dup = talloc_strdup(cmd, cmd->variable);
	if (!dup) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	/* Split off the first "stat_item." part */
	tmp = strtok_r(dup, ".", &saveptr);
	if (!tmp || strcmp(tmp, "stat_item") != 0)
		goto format_error;

	/* Split off the "last." part (validated further below) */
	value_type = strtok_r(NULL, ".", &saveptr);
	if (!value_type)
		goto format_error;

	/* Split off the "group_name." part */
	group_name = strtok_r(NULL, ".", &saveptr);
	if (!group_name)
		goto format_error;

	/* Split off the "N." part */
	group_idx_str = strtok_r(NULL, ".", &saveptr);
	if (!group_idx_str)
		goto format_error;
	if (strcmp(group_idx_str, "by_name") == 0) {
		/* The index is not given by "N" but by "by_name.foo". Get the "foo" idx-name */
		group_idx_str = strtok_r(NULL, ".", &saveptr);
		statg = osmo_stat_item_get_group_by_name_idxname(group_name, group_idx_str);
	} else {
		int idx;
		if (osmo_str_to_int(&idx, group_idx_str, 10, 0, INT_MAX))
			goto format_error;
		statg = osmo_stat_item_get_group_by_name_idx(group_name, idx);
	}
	if (!statg) {
		cmd->reply = "Stat group with given name and index not found";
		return CTRL_CMD_ERROR;
	}

	/* Split off the "item_name" part */
	item_name = strtok_r(NULL, ".", &saveptr);
	if (!item_name)
		goto format_error;
	stat_item = osmo_stat_item_get_by_name(statg, item_name);
	if (!stat_item) {
		cmd->reply = "No such stat item found";
		return CTRL_CMD_ERROR;
	}

	tmp = strtok_r(NULL, "", &saveptr);
	if (tmp) {
		cmd->reply = "Garbage after stat item name";
		return CTRL_CMD_ERROR;
	}

	if (!strcmp(value_type, "last"))
		val = osmo_stat_item_get_last(stat_item);
	else
		goto format_error;

	cmd->reply = talloc_asprintf(cmd, "%"PRIu32, val);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;

format_error:
	cmd->reply = "Stat item must be of form stat_item.type.group_name.N.item_name,"
		" e.g. 'stat_item.last.bsc.0.msc_num:connected'";
	return CTRL_CMD_ERROR;
}

/* counter */
CTRL_CMD_DEFINE(counter, "counter *");
static int get_counter(struct ctrl_cmd *cmd, void *data)
{
	char *ctr_name, *tmp, *dup, *saveptr;
	struct osmo_counter *counter;

	cmd->reply = "OOM";
	dup = talloc_strdup(cmd, cmd->variable);
	if (!dup)
		goto err;


	tmp = strstr(dup, "counter");
	if (!tmp) {
		talloc_free(dup);
		goto err;
	}

	strtok_r(tmp, ".", &saveptr);
	ctr_name = strtok_r(NULL, "\0", &saveptr);

	if (!ctr_name)
		goto err;

	counter = osmo_counter_get_by_name(ctr_name);
	if (!counter) {
		cmd->reply = "Counter name not found.";
		talloc_free(dup);
		goto err;
	}

	talloc_free(dup);

	cmd->reply = talloc_asprintf(cmd, "%lu", counter->value);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		goto err;
	}

	return CTRL_CMD_REPLY;
err:
	return CTRL_CMD_ERROR;
}

static int set_counter(struct ctrl_cmd *cmd, void *data)
{

	cmd->reply = "Can't set counter.";

	return CTRL_CMD_ERROR;
}

static int verify_counter(struct ctrl_cmd *cmd, const char *value, void *data)
{
	return 0;
}

struct ctrl_handle *ctrl_interface_setup(void *data, uint16_t port,
					 ctrl_cmd_lookup lookup)
{
	return ctrl_interface_setup_dynip(data, "127.0.0.1", port, lookup);
}

static int ctrl_initialized = 0;

/* global ctrl initialization */
static int ctrl_init(unsigned int node_count)
{
	int ret;

	if (!node_count)
		node_count = _LAST_CTRL_NODE;
	OSMO_ASSERT(node_count >= _LAST_CTRL_NODE);

	if (ctrl_initialized) {
		OSMO_ASSERT(ctrl_initialized == node_count);
		return 0;
	}

	ctrl_node_vec = vector_init(node_count);
	if (!ctrl_node_vec)
		goto err;

	ret = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_rate_ctr);
	if (ret)
		goto err_vec;
	ret = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_stat_item);
	if (ret)
		goto err_vec;
	ret = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_counter);
	if (ret)
		goto err_vec;

	ret = osmo_fsm_ctrl_cmds_install();
	if (ret)
		goto err_vec;

	ctrl_initialized = node_count;
	return 0;

err_vec:
	vector_free(ctrl_node_vec);
	ctrl_node_vec = NULL;
err:
	return -1;
}

/*! Allocate a CTRL interface handle.
 *  \param[in] ctx Talloc allocation context to be used
 *  \param[in] data Pointer which will be made available to each
               set_..() get_..() verify_..() control command function
 *  \param[in] lookup Lookup function pointer, can be NULL
 *  \param[in] node_count Number of CTRL nodes to allocate, 0 for default.
 *  \returns ctrl_handle pointer or NULL in case of errors
 *
 * Please see ctrl_interface_setup_dynip2() for a detailed description of \a
 * node_count semantics.
 */
struct ctrl_handle *ctrl_handle_alloc2(void *ctx, void *data,
				       ctrl_cmd_lookup lookup,
				       unsigned int node_count)
{
	struct ctrl_handle *ctrl;

	ctrl_init(node_count);

	ctrl = talloc_zero(ctx, struct ctrl_handle);
	if (!ctrl)
		return NULL;

	INIT_LLIST_HEAD(&ctrl->ccon_list);

	ctrl->data = data;
	ctrl->lookup = lookup;

	return ctrl;
}

/*! Allocate a CTRL interface handle.
 *  \param[in] ctx Talloc allocation context to be used
 *  \param[in] data Pointer which will be made available to each
               set_..() get_..() verify_..() control command function
 *  \param[in] lookup Lookup function pointer, can be NULL
 *  \returns ctrl_handle pointer or NULL in case of errors
 */
struct ctrl_handle *ctrl_handle_alloc(void *ctx, void *data, ctrl_cmd_lookup lookup)
{
	return ctrl_handle_alloc2(ctx, data, lookup, 0);
}

/*! Setup CTRL interface on a given address.
 *  \param[in] data Pointer which will be made available to each
               set_..() get_..() verify_..() control command function
 *  \param[in] bind_addr Address on which CTRL socket shall listen
 *  \param[in] port Port on which CTRL socket shall listen
 *  \param[in] lookup Lookup function pointer, can be NULL
 *  \param[in] node_count Number of CTRL nodes to allocate, 0 for default.
 *  \returns ctrl_handle pointer or NULL in case of errors
 *
 * Control interface nodes are identified by a node handle; some of these are
 * defined in enum ctrl_node_type, here in libosmocore. However, applications
 * defining own nodes may add own control nodes without having to extend the
 * enum in libosmocore. For example, in the calling application, define an enum
 * like "enum more_ctrl_nodes { CTRL_NODE_FOO = _LAST_CTRL_NODE, CTRL_NODE_BAR,
 * _LAST_CTRL_NODE_EXTENDED }".  In order to provide space for the additional
 * control nodes, pass _LAST_CTRL_NODE_EXTENDED to the \a node_count parameter.
 * Passing 0 is identical to passing _LAST_CTRL_NODE, i.e. to not define own
 * control nodes apart from libosmocore ones.
 */
struct ctrl_handle *ctrl_interface_setup_dynip2(void *data,
						const char *bind_addr,
						uint16_t port,
						ctrl_cmd_lookup lookup,
						unsigned int node_count)
{
	int ret;
	struct ctrl_handle *ctrl;

	ctrl = ctrl_handle_alloc2(data, data, lookup, node_count);
	if (!ctrl)
		return NULL;

	/* Listen for control connections */
	ctrl->listen_fd.cb = listen_fd_cb;
	ctrl->listen_fd.data = ctrl;
	ret = osmo_sock_init_ofd(&ctrl->listen_fd, AF_INET, SOCK_STREAM, IPPROTO_TCP,
				 bind_addr, port, OSMO_SOCK_F_BIND);
	if (ret < 0) {
		talloc_free(ctrl);
		return NULL;
	}

	LOGP(DLCTRL, LOGL_NOTICE, "CTRL at %s %u\n", bind_addr, port);
	return ctrl;
}

/*! Setup CTRL interface on a given address.
 *  \param[in] data Pointer which will be made available to each
               set_..() get_..() verify_..() control command function
 *  \param[in] bind_addr Address on which CTRL socket shall listen
 *  \param[in] port Port on which CTRL socket shall listen
 *  \param[in] lookup Lookup function pointer, can be NULL
 *  \returns ctrl_handle pointer or NULL in case of errors
 */
struct ctrl_handle *ctrl_interface_setup_dynip(void *data,
					       const char *bind_addr,
					       uint16_t port,
					       ctrl_cmd_lookup lookup)
{
	return ctrl_interface_setup_dynip2(data, bind_addr, port, lookup, 0);
}


/*! Install a lookup helper function for control nodes
 *  This function is used by e.g. library code to install lookup helpers
 *  for additional nodes in the control interface.
 *  \param[in] lookup The lookup helper function
 *  \retuns - on success; negative on error.
 */
int ctrl_lookup_register(ctrl_cmd_lookup lookup)
{
	struct lookup_helper *lh;

	/* avoid double registration */
	llist_for_each_entry(lh, &ctrl_lookup_helpers, list) {
		if (lh->lookup == lookup)
			return -EEXIST;
	}

	lh = talloc_zero(NULL, struct lookup_helper);
	if (!lh)
		return -ENOMEM;

	lh->lookup = lookup;
	llist_add_tail(&lh->list, &ctrl_lookup_helpers);
	return 0;
}

/*! Helper for "local execution" of a CTRL command from a string
 *  The function will parse + execute the given control command string
 *  and return a corresponding ctrl_cmd.  Caller is responsible to
 *  talloc_free() the return value.
 *  \param[in] Control Interface Command String
 *  \returns parsed command, including reply; NULL on error */
struct ctrl_cmd *ctrl_cmd_exec_from_string(struct ctrl_handle *ch, const char *cmdstr)
{
	struct msgb *msg = msgb_alloc(1024, "ctrl-cmd");
	struct ctrl_cmd *cmd;

	if (!msg)
		return NULL;
	msg->l2h = msg->data;
	osmo_strlcpy((char *)msg->data, cmdstr, msgb_tailroom(msg));
	msgb_put(msg, strlen(cmdstr));

	cmd = ctrl_cmd_parse2(ch, msg);
	msgb_free(msg);
	if (!cmd)
		return NULL;
	if (cmd->type == CTRL_TYPE_ERROR)
		return cmd;
	if (ctrl_cmd_handle(ch, cmd, NULL) == CTRL_CMD_HANDLED) {
		/* No reply should be sent back. */
		talloc_free(cmd);
		cmd = NULL;
	}
	return cmd;
}
