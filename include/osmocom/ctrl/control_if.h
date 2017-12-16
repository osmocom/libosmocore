/*! \file control_if.h */

#pragma once

#include <osmocom/core/write_queue.h>
#include <osmocom/ctrl/control_cmd.h>

int ctrl_parse_get_num(vector vline, int i, long *num);

typedef int (*ctrl_cmd_lookup)(void *data, vector vline, int *node_type,
				void **node_data, int *i);

struct ctrl_handle {
	struct osmo_fd listen_fd;
	void *data;

	ctrl_cmd_lookup lookup;

	/* List of control connections */
	struct llist_head ccon_list;
};


int ctrl_cmd_send(struct osmo_wqueue *queue, struct ctrl_cmd *cmd);
int ctrl_cmd_send_trap(struct ctrl_handle *ctrl, const char *name, char *value);
struct ctrl_handle *ctrl_handle_alloc(void *ctx, void *data, ctrl_cmd_lookup lookup);
struct ctrl_handle *ctrl_handle_alloc2(void *ctx, void *data,
				       ctrl_cmd_lookup lookup,
				       unsigned int node_count);
struct ctrl_handle *ctrl_interface_setup(void *data, uint16_t port,
					 ctrl_cmd_lookup lookup);
struct ctrl_handle *ctrl_interface_setup_dynip(void *data,
					       const char *bind_addr,
					       uint16_t port,
					       ctrl_cmd_lookup lookup);
struct ctrl_handle *ctrl_interface_setup_dynip2(void *data,
						const char *bind_addr,
						uint16_t port,
						ctrl_cmd_lookup lookup,
						unsigned int node_count);
struct ctrl_connection *osmo_ctrl_conn_alloc(void *ctx, void *data);
int ctrl_cmd_handle(struct ctrl_handle *ctrl, struct ctrl_cmd *cmd, void *data);
struct ctrl_cmd *ctrl_cmd_exec_from_string(struct ctrl_handle *ch, const char *cmdstr);

int ctrl_lookup_register(ctrl_cmd_lookup lookup);

int ctrl_handle_msg(struct ctrl_handle *ctrl, struct ctrl_connection *ccon, struct msgb *msg);
