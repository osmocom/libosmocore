/*! \file control_cmd.c
 * SNMP-like status interface. */
/*
 * (C) 2010-2011 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2010-2011 by On-Waves
 * (C) 2014 by Harald Welte <laforge@gnumonks.org>
 * (C) 2017 by sysmocom - s.f.m.c. GmbH
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
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <osmocom/ctrl/control_cmd.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/vector.h>

extern vector ctrl_node_vec;

const struct value_string ctrl_type_vals[] = {
	{ CTRL_TYPE_UNKNOWN,	"(unknown)" },
	{ CTRL_TYPE_GET,	"GET" },
	{ CTRL_TYPE_SET,	"SET" },
	{ CTRL_TYPE_GET_REPLY,	"GET_REPLY" },
	{ CTRL_TYPE_SET_REPLY,	"SET_REPLY" },
	{ CTRL_TYPE_TRAP,	"TRAP" },
	{ CTRL_TYPE_ERROR,	"ERROR" },
	{ 0, NULL }
};

/* Functions from libosmocom */
extern vector cmd_make_descvec(const char *string, const char *descstr);

/* Get the ctrl_cmd_element that matches this command */
static struct ctrl_cmd_element *ctrl_cmd_get_element_match(vector vline, vector node)
{
	int index, j;
	const char *desc;
	struct ctrl_cmd_element *cmd_el;
	struct ctrl_cmd_struct *cmd_desc;
	char *str;

	for (index = 0; index < vector_active(node); index++) {
		if ((cmd_el = vector_slot(node, index))) {
			cmd_desc = &cmd_el->strcmd;
			if (cmd_desc->nr_commands > vector_active(vline))
				continue;
			for (j =0; j < vector_active(vline) && j < cmd_desc->nr_commands; j++) {
				str = vector_slot(vline, j);
				desc = cmd_desc->command[j];
				if (desc[0] == '*')
					return cmd_el; /* Partial match */
				if (strcmp(desc, str) != 0)
					break;
			}
			/* We went through all the elements and all matched */
			if (j == cmd_desc->nr_commands)
				return cmd_el;
		}
	}

	return NULL;
}

/*! Execute a given received command
 *  \param[in] vline vector representing the available/registered commands
 *  \param[inout] command parsed received command to be executed
 *  \param[in] node CTRL interface node
 *  \param[in] data opaque data passed to verify(), get() and set() call-backs
 *  \returns CTRL_CMD_HANDLED or CTRL_CMD_REPLY;  CTRL_CMD_ERROR on error */
int ctrl_cmd_exec(vector vline, struct ctrl_cmd *command, vector node, void *data)
{
	int ret = CTRL_CMD_ERROR;
	struct ctrl_cmd_element *cmd_el;

	if ((command->type != CTRL_TYPE_GET) && (command->type != CTRL_TYPE_SET)) {
		command->reply = "Trying to execute something not GET or SET";
		goto out;
	}
	if ((command->type == CTRL_TYPE_SET) && (!command->value)) {
		command->reply = "SET without a value";
		goto out;
	}

	if (!vline)
		goto out;

	cmd_el = ctrl_cmd_get_element_match(vline, node);

	if (!cmd_el) {
		command->reply = "Command not found";
		goto out;
	}

	if (command->type == CTRL_TYPE_SET) {
		if (!cmd_el->set) {
			command->reply = "SET not implemented";
			goto out;
		}
		if (cmd_el->verify) {
			if ((ret = cmd_el->verify(command, command->value, data))) {
				ret = CTRL_CMD_ERROR;
				/* If verify() set an appropriate error message, don't change it. */
				if (!command->reply)
					command->reply = "Value failed verification.";
				goto out;
			}
		}
		ret =  cmd_el->set(command, data);
		goto out;
	} else if (command->type == CTRL_TYPE_GET) {
		if (!cmd_el->get) {
			command->reply = "GET not implemented";
			goto out;
		}
		ret = cmd_el->get(command, data);
		goto out;
	}
out:
	if (ret == CTRL_CMD_REPLY) {
		if (command->type == CTRL_TYPE_SET) {
			command->type = CTRL_TYPE_SET_REPLY;
		} else if (command->type == CTRL_TYPE_GET) {
			command->type = CTRL_TYPE_GET_REPLY;
		}
	} else if (ret == CTRL_CMD_ERROR) {
		command->type = CTRL_TYPE_ERROR;
	}
	return ret;
}

static void add_word(struct ctrl_cmd_struct *cmd,
		     const char *start, const char *end)
{
	if (!cmd->command) {
		cmd->command = talloc_zero_array(tall_vty_vec_ctx,
						 char*, 1);
		cmd->nr_commands = 0;
	} else {
		cmd->command = talloc_realloc(tall_vty_vec_ctx,
					      cmd->command, char*,
					      cmd->nr_commands + 1);
	}

	cmd->command[cmd->nr_commands++] = talloc_strndup(cmd->command,
							  start, end - start);
}

static void create_cmd_struct(struct ctrl_cmd_struct *cmd, const char *name)
{
	const char *cur, *word;

	for (cur = name, word = NULL; cur[0] != '\0'; ++cur) {
		/* warn about optionals */
		if (cur[0] == '(' || cur[0] == ')' || cur[0] == '|') {
			LOGP(DLCTRL, LOGL_ERROR,
			     "Optionals are not supported in '%s'\n", name);
			goto failure;
		}

		if (isspace(cur[0])) {
			if (word) {
				add_word(cmd, word, cur);
				word = NULL;
			}
			continue;
		}

		if (!word)
			word = cur;
	}

	if (word)
		add_word(cmd, word, cur);

	return;
failure:
	cmd->nr_commands = 0;
	talloc_free(cmd->command);
}

/*! Install a given command definition at a given CTRL node.
 *  \param[in] node CTRL node at which \a cmd is to be installed
 *  \param[in] cmd command definition to be installed
 *  \returns 0 on success; negative on error */
int ctrl_cmd_install(enum ctrl_node_type node, struct ctrl_cmd_element *cmd)
{
	vector cmds_vec;

	/* If this assert triggers, it means the program forgot to initialize
	 * the CTRL interface first by calling ctrl_handle_alloc(2)() directly
	 * or indirectly through ctrl_interface_setup_dynip(2)()
	 */
	if (!ctrl_node_vec) {
		LOGP(DLCTRL, LOGL_ERROR,
		     "ctrl_handle must be initialized prior to installing cmds.\n");
		return -ENODEV;
	}

	cmds_vec = vector_lookup_ensure(ctrl_node_vec, node);

	if (!cmds_vec) {
		cmds_vec = vector_init(5);
		if (!cmds_vec) {
			LOGP(DLCTRL, LOGL_ERROR, "vector_init failed.\n");
			return -ENOMEM;
		}
		vector_set_index(ctrl_node_vec, node, cmds_vec);
	}

	vector_set(cmds_vec, cmd);

	create_cmd_struct(&cmd->strcmd, cmd->name);
	return 0;
}

/*! Allocate a control command of given \a type.
 *  \param[in] ctx talloc context from which to allocate
 *  \param[in] type command type to set after allocation
 *  \returns callee-allocated \ref ctrl_cmd. Caller must talloc_free() it. */
struct ctrl_cmd *ctrl_cmd_create(void *ctx, enum ctrl_type type)
{
	struct ctrl_cmd *cmd;

	cmd = talloc_zero(ctx, struct ctrl_cmd);
	if (!cmd)
		return NULL;

	cmd->type = type;
	return cmd;
}

/*! Perform a deepl copy of the given \a cmd, allocating memory from \a ctx.
 *  \param[in] ctx talloc context from which to allocate
 *  \param[in cmd CTRL command to be copied
 *  \returns deep copy of \a cmd on success; NULL on error */
struct ctrl_cmd *ctrl_cmd_cpy(void *ctx, struct ctrl_cmd *cmd)
{
	struct ctrl_cmd *cmd2;

	cmd2 = talloc_zero(ctx, struct ctrl_cmd);
	if (!cmd2)
		return NULL;

	cmd2->type = cmd->type;
	if (cmd->id) {
		cmd2->id = talloc_strdup(cmd2, cmd->id);
		if (!cmd2->id)
			goto err;
	}
	if (cmd->variable) {
		cmd2->variable = talloc_strdup(cmd2, cmd->variable);
		if (!cmd2->variable)
			goto err;
	}
	if (cmd->value) {
		cmd2->value = talloc_strdup(cmd2, cmd->value);
		if (!cmd2->value)
			goto err;
	}
	if (cmd->reply) {
		cmd2->reply = talloc_strdup(cmd2, cmd->reply);
		if (!cmd2->reply)
			goto err;
	}

	return cmd2;
err:
	talloc_free(cmd2);
	return NULL;
}

/*! Parse/Decode CTRL from \ref msgb into command struct.
 *  \param[in] ctx talloc context from which to allocate
 *  \param[in] msg message buffer containing command to be decoded
 *  \returns callee-allocated decoded CTRL command; NULL on allocation or other failure
 * The caller is responsible to talloc_free() the returned struct pointer. */
struct ctrl_cmd *ctrl_cmd_parse(void *ctx, struct msgb *msg)
{
	struct ctrl_cmd *res = ctrl_cmd_parse2(ctx, msg);
	if (res->type == CTRL_TYPE_ERROR) {
		talloc_free(res);
		return NULL;
	}
	return res;
}

static bool id_str_valid(const char *str)
{
	for (;*str;str++) {
		if (!isdigit(*str))
			return false;
	}
	return true;
}

/*! Parse/Decode CTRL from \ref msgb into command struct.
 *  \param[in] ctx talloc context from which to allocate
 *  \param[in] msg message buffer containing command to be decoded
 *  \returns callee-allocated decoded CTRL command; NULL on allocation failure,
 *  ctrl->type == CTRL_TYPE_ERROR and an error message in ctrl->reply on any error.
 * The caller is responsible to talloc_free() the returned struct pointer.
 * If information of the origin of the ERROR cmd returned is required (received
 * or local parsing failure), use \ref ctrl_cmd_parse3 instead. */
struct ctrl_cmd *ctrl_cmd_parse2(void *ctx, struct msgb *msg)
{
	bool unused;
	return ctrl_cmd_parse3(ctx, msg, &unused);
}

/*! Parse/Decode CTRL from \ref msgb into command struct.
 *  \param[in] ctx talloc context from which to allocate
 *  \param[in] msg message buffer containing command to be decoded
 *  \param[out] parse_failed Whether returned ERROR cmd was generatd locally
 *  		(due to parse failure) or was received.
 *  \returns callee-allocated decoded CTRL command; NULL on allocation failure,
 *  ctrl->type == CTRL_TYPE_ERROR and an error message in ctrl->reply on any error.
 * The caller is responsible to talloc_free() the returned struct pointer. */
struct ctrl_cmd *ctrl_cmd_parse3(void *ctx, struct msgb *msg, bool *parse_failed)
{
	char *str, *tmp, *saveptr = NULL;
	char *var, *val;
	struct ctrl_cmd *cmd;

	cmd = talloc_zero(ctx, struct ctrl_cmd);
	if (!cmd) {
		LOGP(DLCTRL, LOGL_ERROR, "Failed to allocate.\n");
		*parse_failed = true;
		return NULL;
	}

	/* Make sure input is NULL terminated */
	msgb_put_u8(msg, 0);
	str = (char *) msg->l2h;

	OSMO_ASSERT(str);
	tmp = strtok_r(str, " ",  &saveptr);
	if (!tmp) {
		cmd->type = CTRL_TYPE_ERROR;
		cmd->id = "err";
		cmd->reply = "Request malformed";
		LOGP(DLCTRL, LOGL_NOTICE, "Malformed request: \"%s\"\n", osmo_escape_str(str, -1));
		goto err;
	}

	cmd->type = get_string_value(ctrl_type_vals, tmp);
	if ((int)cmd->type < 0 || cmd->type == CTRL_TYPE_UNKNOWN) {
		cmd->type = CTRL_TYPE_ERROR;
		cmd->id = "err";
		cmd->reply = "Request type unknown";
		LOGP(DLCTRL, LOGL_NOTICE, "Request type unknown: \"%s\"\n", osmo_escape_str(str, -1));
		goto err;
	}

	tmp = strtok_r(NULL, " ",  &saveptr);

	if (!tmp) {
		cmd->type = CTRL_TYPE_ERROR;
		cmd->id = "err";
		cmd->reply = "Missing ID";
		LOGP(DLCTRL, LOGL_NOTICE, "Missing ID: \"%s\"\n", osmo_escape_str(str, -1));
		goto err;
	}

	if (!id_str_valid(tmp) &&
	    !(cmd->type == CTRL_TYPE_ERROR && strcmp(tmp, "err") == 0)) {
		LOGP(DLCTRL, LOGL_NOTICE, "Invalid %s message ID number: \"%s\"\n",
		     get_value_string(ctrl_type_vals, cmd->type), osmo_escape_str(tmp, -1));
		cmd->type = CTRL_TYPE_ERROR;
		cmd->id = "err";
		cmd->reply = "Invalid message ID number";
		goto err;
	}
	cmd->id = talloc_strdup(cmd, tmp);
	if (!cmd->id)
		goto oom;

	switch (cmd->type) {
		case CTRL_TYPE_GET:
			var = strtok_r(NULL, " \n", &saveptr);
			if (!var) {
				cmd->type = CTRL_TYPE_ERROR;
				cmd->reply = "GET incomplete";
				LOGP(DLCTRL, LOGL_NOTICE, "GET Command incomplete: \"%s\"\n",
				     osmo_escape_str(str, -1));
				goto err;
			}
			if (!osmo_separated_identifiers_valid(var, ".")) {
				cmd->type = CTRL_TYPE_ERROR;
				cmd->reply = "GET variable contains invalid characters";
				LOGP(DLCTRL, LOGL_NOTICE, "GET variable contains invalid characters: \"%s\"\n",
				     osmo_escape_str(var, -1));
				goto err;
			}
			cmd->variable = talloc_strdup(cmd, var);
			var = strtok_r(NULL, "", &saveptr);
			if (var) {
				cmd->type = CTRL_TYPE_ERROR;
				cmd->reply = "GET with trailing characters";
				LOGP(DLCTRL, LOGL_NOTICE, "GET with trailing characters: \"%s\"\n",
				     osmo_escape_str(var, -1));
				goto err;
			}
			LOGP(DLCTRL, LOGL_DEBUG, "Command: GET %s\n", cmd->variable);
			break;
		case CTRL_TYPE_SET:
			var = strtok_r(NULL, " ", &saveptr);
			val = strtok_r(NULL, "\n", &saveptr);
			if (!var || !val) {
				cmd->type = CTRL_TYPE_ERROR;
				cmd->reply = "SET incomplete";
				LOGP(DLCTRL, LOGL_NOTICE, "SET Command incomplete\n");
				goto err;
			}
			if (!osmo_separated_identifiers_valid(var, ".")) {
				cmd->type = CTRL_TYPE_ERROR;
				cmd->reply = "SET variable contains invalid characters";
				LOGP(DLCTRL, LOGL_NOTICE, "SET variable contains invalid characters: \"%s\"\n",
				     osmo_escape_str(var, -1));
				goto err;
			}
			cmd->variable = talloc_strdup(cmd, var);
			cmd->value = talloc_strdup(cmd, val);
			if (!cmd->variable || !cmd->value)
				goto oom;

			var = strtok_r(NULL, "", &saveptr);
			if (var) {
				cmd->type = CTRL_TYPE_ERROR;
				cmd->reply = "SET with trailing characters";
				LOGP(DLCTRL, LOGL_NOTICE, "SET with trailing characters: \"%s\"\n",
				     osmo_escape_str(var, -1));
				goto err;
			}

			LOGP(DLCTRL, LOGL_DEBUG, "Command: SET %s = \"%s\"\n", cmd->variable,
			     osmo_escape_str(cmd->value, -1));
			break;
#define REPLY_CASE(TYPE, NAME)  \
		case TYPE: \
			var = strtok_r(NULL, " ", &saveptr); \
			val = strtok_r(NULL, "", &saveptr); \
			if (!var) { \
				cmd->type = CTRL_TYPE_ERROR; \
				cmd->reply = NAME " incomplete"; \
				LOGP(DLCTRL, LOGL_NOTICE, NAME " incomplete\n"); \
				goto err; \
			} \
			if (!osmo_separated_identifiers_valid(var, ".")) { \
				cmd->type = CTRL_TYPE_ERROR; \
				cmd->reply = NAME " variable contains invalid characters"; \
				LOGP(DLCTRL, LOGL_NOTICE, NAME " variable contains invalid characters: \"%s\"\n", \
				     osmo_escape_str(var, -1)); \
				goto err; \
			} \
			cmd->variable = talloc_strdup(cmd, var); \
			cmd->reply = talloc_strdup(cmd, val); \
			if (!cmd->variable || !cmd->reply) \
				goto oom; \
			LOGP(DLCTRL, LOGL_DEBUG, "Command: " NAME " %s: %s\n", cmd->variable, \
			     osmo_escape_str(cmd->reply, -1)); \
			break
		REPLY_CASE(CTRL_TYPE_GET_REPLY, "GET REPLY");
		REPLY_CASE(CTRL_TYPE_SET_REPLY, "SET REPLY");
		REPLY_CASE(CTRL_TYPE_TRAP, "TRAP");
#undef REPLY_CASE
		case CTRL_TYPE_ERROR:
			var = strtok_r(NULL, "", &saveptr);
			if (!var) {
				cmd->reply = "";
				goto err;
			}
			cmd->reply = talloc_strdup(cmd, var);
			if (!cmd->reply)
				goto oom;
			LOGP(DLCTRL, LOGL_DEBUG, "Command: ERROR \"%s\"\n",
			     osmo_escape_str(cmd->reply, -1));
			break;
		case CTRL_TYPE_UNKNOWN:
		default:
			cmd->type = CTRL_TYPE_ERROR;
			cmd->reply = "Unknown type";
			goto err;
	}

	*parse_failed = false;
	return cmd;
oom:
	cmd->type = CTRL_TYPE_ERROR;
	cmd->id = "err";
	cmd->reply = "OOM";
err:
	*parse_failed = true;
	return cmd;
}

/*! Encode a given CTRL command from its parsed form into a message buffer.
 *  \param[in] cmd decoded/parsed form of to-be-encoded command
 *  \returns callee-allocated message buffer containing the encoded \a cmd; NULL on error */
struct msgb *ctrl_cmd_make(struct ctrl_cmd *cmd)
{
	struct msgb *msg = NULL;
	char *strbuf;
	size_t len;
	const char *type;

	if (!cmd->id)
		return NULL;

	type = get_value_string(ctrl_type_vals, cmd->type);

	switch (cmd->type) {
	case CTRL_TYPE_GET:
		if (!cmd->variable)
			return NULL;
		strbuf = talloc_asprintf(cmd, "%s %s %s", type, cmd->id, cmd->variable);
		break;
	case CTRL_TYPE_SET:
		if (!cmd->variable || !cmd->value)
			return NULL;
		strbuf = talloc_asprintf(cmd, "%s %s %s %s", type, cmd->id,
					 cmd->variable, cmd->value);
		break;
	case CTRL_TYPE_GET_REPLY:
	case CTRL_TYPE_SET_REPLY:
	case CTRL_TYPE_TRAP:
		if (!cmd->variable || !cmd->reply)
			return NULL;
		strbuf = talloc_asprintf(cmd, "%s %s %s %s", type, cmd->id,
					 cmd->variable, cmd->reply);
		break;
	case CTRL_TYPE_ERROR:
		if (!cmd->reply)
			return NULL;
		strbuf = talloc_asprintf(cmd, "%s %s %s", type, cmd->id, cmd->reply);
		break;
	default:
		LOGP(DLCTRL, LOGL_NOTICE, "Unknown command type %i\n", cmd->type);
		return NULL;
	}

	if (!strbuf) {
		LOGP(DLCTRL, LOGL_ERROR, "Failed to allocate cmd.\n");
		goto ret;
	}
	len = strlen(strbuf);

	msg = msgb_alloc_headroom(len + 128, 128, "ctrl ERROR command make");
	if (!msg)
		goto ret;
	msg->l2h = msgb_put(msg, len);
	memcpy(msg->l2h, strbuf, len);

ret:
	talloc_free(strbuf);
	return msg;
}

/*! Build a deferred control command state and keep it the per-connection list of deferred commands.
 *  This function is typically called by a ctrl command handler that wishes to defer returning a
 *  response.  The reutnred state can later be used to check if the deferred command is still alive,
 *  and to respond to the specific command.  This only works to defer the response to GET and SET.
 *  \param[in] ctx talloc context from whihc to allocate the ctrl_cmd_def
 *  \param[in] cmd the control command whose response is deferred
 *  \param[in] data opaque, user-defined pointer
 *  \param[in] secs number of seconds until the command times out
 *  \returns callee-allocated ctrl_cmd_def */
struct ctrl_cmd_def *
ctrl_cmd_def_make(const void *ctx, struct ctrl_cmd *cmd, void *data, unsigned int secs)
{
	struct ctrl_cmd_def *cd;

	if (!cmd->ccon)
		return NULL;

	cd = talloc_zero(ctx, struct ctrl_cmd_def);

	cmd->defer = cd;
	cd->cmd = cmd;
	cd->data = data;

	/* add to per-connection list of deferred commands */
	llist_add(&cd->list, &cmd->ccon->def_cmds);

	return cd;
}

/*! Determine if the given deferred control command is still alive or a zombie.
 *  \param[in] cd deferred ctrl command state
 *  \returns 0 is \a cd is still alive; 1 if it's a zombie */
int ctrl_cmd_def_is_zombie(struct ctrl_cmd_def *cd)
{
	/* luckily we're still alive */
	if (cd->cmd)
		return 0;

	/* if we are a zombie, make sure we really die */
	llist_del(&cd->list);
	talloc_free(cd);

	return 1;
}

/*! Send the response to a deferred ctrl command.
 *  The command can only be a resply to a SET or a GET operation.
 *  \param[in] cd deferred ctrl command state
 *  \returns 0 if command sent successfully; negative on error */
int ctrl_cmd_def_send(struct ctrl_cmd_def *cd)
{
	struct ctrl_cmd *cmd = cd->cmd;

	int rc;

	/* Deferred commands can only be responses to GET/SET or ERROR, but
	 * never TRAP or anything else */
	switch (cmd->type) {
	case CTRL_TYPE_GET:
		cmd->type = CTRL_TYPE_GET_REPLY;
		break;
	case CTRL_TYPE_SET:
		cmd->type = CTRL_TYPE_SET_REPLY;
		break;
	default:
		cmd->type = CTRL_TYPE_ERROR;
	}

	rc = ctrl_cmd_send(&cmd->ccon->write_queue, cmd);

	talloc_free(cmd);
	llist_del(&cd->list);
	talloc_free(cd);

	return rc;
}
