/*! \file fsm_ctrl_commands.c */

/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <string.h>
#include <errno.h>

#include <osmocom/core/fsm.h>

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>

/*! control interface lookup function for FSM's
 * \param[in] data Private data passed to controlif_setup()
 * \param[in] vline Vector of the line holding the command string
 * \param[out] node_type type (CTRL_NODE_) that was determined
 * \param[out] node_data private data of node that was determined
 * \param i Current index into vline, up to which it is parsed
 */
static int fsm_ctrl_node_lookup(void *data, vector vline, int *node_type,
				void **node_data, int *i)
{
	struct osmo_fsm *fsm = NULL;
	struct osmo_fsm_inst *fi = NULL;;
	const char *token = vector_slot(vline, *i);

	switch (*node_type) {
	case CTRL_NODE_ROOT:
		if (!strcmp(token, "fsm")) {
			const char *fsm_name;
			(*i)++;
			fsm_name = vector_lookup(vline, *i);
			if (!fsm_name)
				return -ERANGE;
			fsm = osmo_fsm_find_by_name(fsm_name);
			if (!fsm)
				return -ENODEV;
			*node_data = fsm;
			*node_type = CTRL_NODE_FSM;
		} else
			return 0;
		break;
	case CTRL_NODE_FSM:
		fsm = *node_data;
		if (!strcmp(token, "name")) {
			const char *inst_name;
			(*i)++;
			inst_name = vector_lookup(vline, *i);
			if (!inst_name)
				return -ERANGE;
			fi = osmo_fsm_inst_find_by_name(fsm, inst_name);
			if (!fi)
				return -ENODEV;
			*node_data = fi;
			*node_type = CTRL_NODE_FSM_INST;
		} else if (!strcmp(token, "id")) {
			const char *inst_id;
			(*i)++;
			inst_id = vector_lookup(vline, *i);
			if (!inst_id)
				return -ERANGE;
			fi = osmo_fsm_inst_find_by_id(fsm, inst_id);
			if (!fi)
				return -ENODEV;
			*node_data = fi;
			*node_type = CTRL_NODE_FSM_INST;
		}
		break;
	default:
		return 0;
	}

	return 1;
}

static int get_fsm_inst_state(struct ctrl_cmd *cmd, void *data)
{
	struct osmo_fsm_inst *fi = cmd->node;

	if (!fi) {
		cmd->reply = "No such FSM found";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = talloc_strdup(cmd, osmo_fsm_state_name(fi->fsm, fi->state));
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(fsm_inst_state, "state");

static int get_fsm_inst_parent_name(struct ctrl_cmd *cmd, void *data)
{
	struct osmo_fsm_inst *fi = cmd->node;

	if (!fi) {
		cmd->reply = "No such FSM found";
		return CTRL_CMD_ERROR;
	}
	if (!fi->proc.parent) {
		cmd->reply = "No parent";
		return CTRL_CMD_ERROR;
	}
	cmd->reply = talloc_strdup(cmd, fi->proc.parent->name);
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(fsm_inst_parent_name, "parent-name");

static int get_fsm_inst_timer(struct ctrl_cmd *cmd, void *data)
{
	struct osmo_fsm_inst *fi = cmd->node;
	struct timeval remaining;

	if (!fi) {
		cmd->reply = "No such FSM found";
		return CTRL_CMD_ERROR;
	}
	if (osmo_timer_remaining(&fi->timer, NULL, &remaining) < 0)
		cmd->reply = "0,0,0";
	else
		cmd->reply = talloc_asprintf(cmd, "%u,%ld,%ld", fi->T, remaining.tv_sec, remaining.tv_usec);

	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(fsm_inst_timer, "timer");


static int get_fsm_inst_dump(struct ctrl_cmd *cmd, void *data)
{
	struct osmo_fsm_inst *fi = cmd->node;
	struct osmo_fsm_inst *child;

	if (!fi) {
		cmd->reply = "No such FSM found";
		return CTRL_CMD_ERROR;
	}

	/* Fixed Part: Name, ID, log_level, state, timer number */
	cmd->reply = talloc_asprintf(cmd, "'%s','%s','%s','%s',%u", fi->name, fi->id,
				log_level_str(fi->log_level),
				osmo_fsm_state_name(fi->fsm, fi->state), fi->T);

	/* Variable Parts below */
	if (fi->T) {
		struct timeval remaining;
		int rc;
		rc = osmo_timer_remaining(&fi->timer, NULL, &remaining);
		if (rc == 0) {
			cmd->reply = talloc_asprintf_append(cmd->reply, ",timeout_sec=%ld,timeout_usec=%ld",
							    remaining.tv_sec, remaining.tv_usec);
		}
	}

	if (fi->proc.parent)
		cmd->reply = talloc_asprintf_append(cmd->reply, ",parent='%s'", fi->proc.parent->name);

	llist_for_each_entry(child, &fi->proc.children, proc.child) {
		cmd->reply = talloc_asprintf_append(cmd->reply, ",child='%s'", child->name);
	}

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_RO(fsm_inst_dump, "dump");

int osmo_fsm_ctrl_cmds_install(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_FSM_INST, &cmd_fsm_inst_dump);
	rc |= ctrl_cmd_install(CTRL_NODE_FSM_INST, &cmd_fsm_inst_state);
	rc |= ctrl_cmd_install(CTRL_NODE_FSM_INST, &cmd_fsm_inst_parent_name);
	rc |= ctrl_cmd_install(CTRL_NODE_FSM_INST, &cmd_fsm_inst_timer);
	rc |= ctrl_lookup_register(fsm_ctrl_node_lookup);

	return rc;
}
