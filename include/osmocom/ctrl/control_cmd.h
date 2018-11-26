/*! \file control_cmd.h */

#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/vty/vector.h>

#define CTRL_CMD_ERROR		-1
#define CTRL_CMD_HANDLED	0
#define CTRL_CMD_REPLY		1
#define CTRL_CMD_TRAP_ID	"0"

struct ctrl_handle;

/*! The class of node at which a ctrl command is registered to */
enum ctrl_node_type {
	CTRL_NODE_ROOT,	/* Root elements */
	CTRL_NODE_BTS,	/* BTS specific (net.btsN.) */
	CTRL_NODE_TRX,	/* TRX specific (net.btsN.trxM.) */
	CTRL_NODE_TS,	/* TS specific (net.btsN.trxM.tsI.) */
	CTRL_NODE_FSM,	/* Finite State Machine (description) */
	CTRL_NODE_FSM_INST,	/* Finite State Machine (instance) */
	_LAST_CTRL_NODE
};

/*! Ctrl command types (GET, SET, ...) */
enum ctrl_type {
	CTRL_TYPE_UNKNOWN,
	CTRL_TYPE_GET,
	CTRL_TYPE_SET,
	CTRL_TYPE_GET_REPLY,
	CTRL_TYPE_SET_REPLY,
	CTRL_TYPE_TRAP,
	CTRL_TYPE_ERROR
};

/*! human-readable string names for \ref ctrl_type */
extern const struct value_string ctrl_type_vals[];

/*! Represents a single ctrl connection */
struct ctrl_connection {
	struct llist_head list_entry;

	/*! The queue for sending data back */
	struct osmo_wqueue write_queue;

	/*! Buffer for partial input data */
	struct msgb *pending_msg;

	/*! Callback if the connection was closed */
	void (*closed_cb)(struct ctrl_connection *conn);

	/*! Pending commands for this connection */
	struct llist_head cmds;

	/*! Pending deferred command responses for this connection */
	struct llist_head def_cmds;
};

struct ctrl_cmd_def;

/*! Represents a single ctrl command after parsing */
struct ctrl_cmd {
	/*! connection through which the command was received */
	struct ctrl_connection *ccon;
	/*! command type */
	enum ctrl_type type;
	char *id;
	/*! node of the specified variable */
	void *node;
	/*! name of the variable */
	char *variable;
	/*! value of the specified CTRL variable */
	char *value;
	/*! respnse message string */
	char *reply;
	/*! state representing deferred (async) response, if any */
	struct ctrl_cmd_def *defer;
};

#define ctrl_cmd_reply_printf(cmd, fmt, args ...) \
	osmo_talloc_asprintf(cmd, cmd->reply, fmt, ## args)

struct ctrl_cmd_struct {
	int nr_commands;
	char **command;
};

/*! Implementation of a given CTRL command. This is what a program registers
 *  using \r ctrl_cmd_install in order to implement a given control variable. */
struct ctrl_cmd_element {
	/*! textual name/id of the CTRL command */
	const char *name;
	struct ctrl_cmd_struct strcmd;
	/*! call-back function implementing the SET operation */
	int (*set)(struct ctrl_cmd *cmd, void *data);
	/*! call-back function implementing the GET operation */
	int (*get)(struct ctrl_cmd *cmd, void *data);
	/*! call-back function to validate a value; called before SET */
	int (*verify)(struct ctrl_cmd *cmd, const char *value, void *data);
};

struct ctrl_cmd_map {
	char *cmd;
	enum ctrl_type type;
};

/* deferred control command, i.e. responded asynchronously */
struct ctrl_cmd_def {
	struct llist_head list;		/* ctrl_connection.def_cmds */
	struct ctrl_cmd *cmd;
	void *data;			/* opaque user data */
};

struct ctrl_cmd_def *
ctrl_cmd_def_make(const void *ctx, struct ctrl_cmd *cmd, void *data, unsigned int secs);
int ctrl_cmd_def_is_zombie(struct ctrl_cmd_def *cd);
int ctrl_cmd_def_send(struct ctrl_cmd_def *cd);

int ctrl_cmd_exec(vector vline, struct ctrl_cmd *command, vector node, void *data);
int ctrl_cmd_install(enum ctrl_node_type node, struct ctrl_cmd_element *cmd);
int ctrl_cmd_send(struct osmo_wqueue *queue, struct ctrl_cmd *cmd);
int ctrl_cmd_send_to_all(struct ctrl_handle *ctrl, struct ctrl_cmd *cmd);
struct ctrl_cmd *ctrl_cmd_parse3(void *ctx, struct msgb *msg, bool *parse_failed);
struct ctrl_cmd *ctrl_cmd_parse2(void *ctx, struct msgb *msg);
struct ctrl_cmd *ctrl_cmd_parse(void *ctx, struct msgb *msg);
struct msgb *ctrl_cmd_make(struct ctrl_cmd *cmd);
struct ctrl_cmd *ctrl_cmd_cpy(void *ctx, struct ctrl_cmd *cmd);
struct ctrl_cmd *ctrl_cmd_create(void *ctx, enum ctrl_type);
struct ctrl_cmd *ctrl_cmd_trap(struct ctrl_cmd *cmd);

/*! Helper to generate static struct ctrl_cmd_element
 *  \param[in] cmdname symbol name of the command related functions/structures
 *  \param[in] cmdstr string name exposed on CTRL
 *  \param[in] verify_name full symbol name of verification function */
#define CTRL_CMD_DEFINE_STRUCT(cmdname, cmdstr, verify_name) \
static struct ctrl_cmd_element cmd_##cmdname = { \
	.name = cmdstr, \
	.get = &get_##cmdname, \
	.set = &set_##cmdname, \
	.verify = verify_name, \
}

/*! Helper to generate static GET function for integer
 *  \param[in] cmdname symbol name of the command related function
 *  \param[in] dtype name of outer struct of user data
 *  \param[in] element name of field within \a dtype */
#define CTRL_HELPER_GET_INT(cmdname, dtype, element) \
static int get_##cmdname(struct ctrl_cmd *cmd, void *_data) \
{ \
	dtype *node = cmd->node; \
	cmd->reply = talloc_asprintf(cmd, "%i", node->element); \
	if (!cmd->reply) { \
		cmd->reply = "OOM"; \
		return CTRL_CMD_ERROR; \
	} \
	return CTRL_CMD_REPLY; \
}

/*! Helper to generate static SET function for integer
 *  \param[in] cmdname symbol name of the command related function
 *  \param[in] dtype name of outer struct of user data
 *  \param[in] element name of field within \a dtype */
#define CTRL_HELPER_SET_INT(cmdname, dtype, element) \
static int set_##cmdname(struct ctrl_cmd *cmd, void *_data) \
{ \
	dtype *node = cmd->node; \
	int tmp = atoi(cmd->value); \
	node->element = tmp; \
	return get_##cmdname(cmd, _data); \
}

/*! Helper to generate static VERIFY unction validating a numeric range
 *  \param[in] cmdname symbol name of the command related function
 *  \param[in] min minimum permitted integer value
 *  \param[in] max maximum permitted integer value */
#define CTRL_HELPER_VERIFY_RANGE(cmdname, min, max) \
static int verify_##cmdname(struct ctrl_cmd *cmd, const char *value, void *_data) \
{ \
	int tmp = atoi(value); \
	if ((tmp >= min)&&(tmp <= max)) { \
		return 0; \
	} \
	cmd->reply = "Input not within the range"; \
	return -1; \
}

/*! Helper to generate GET, SET, VERIFY + ctrl_cmd_element for integer
 *  \param[in] cmdname symbol name of the command related function
 *  \param[in] cmdstr string name exposed on CTRL
 *  \param[in] dtype name of outer struct of user data
 *  \param[in] element name of field within \a dtype
 *  \param[in] min minimum permitted integer value
 *  \param[in] max maximum permitted integer value */
#define CTRL_CMD_DEFINE_RANGE(cmdname, cmdstr, dtype, element, min, max) \
	CTRL_HELPER_GET_INT(cmdname, dtype, element) \
	CTRL_HELPER_SET_INT(cmdname, dtype, element) \
	CTRL_HELPER_VERIFY_RANGE(cmdname, min, max) \
CTRL_CMD_DEFINE_STRUCT(cmdname, cmdstr, verify_##cmdname)

/*! Helper to generate static GET function for string
 *  \param[in] cmdname symbol name of the command related function
 *  \param[in] dtype name of outer struct of user data
 *  \param[in] element name of field within \a dtype */
#define CTRL_HELPER_GET_STRING(cmdname, dtype, element) \
static int get_##cmdname(struct ctrl_cmd *cmd, void *_data) \
{ \
	dtype *data = cmd->node; \
	cmd->reply = talloc_asprintf(cmd, "%s", data->element); \
	if (!cmd->reply) { \
		cmd->reply = "OOM"; \
		return CTRL_CMD_ERROR; \
	} \
	return CTRL_CMD_REPLY; \
}

/*! Helper to generate static SET function for string
 *  \param[in] cmdname symbol name of the command related function
 *  \param[in] dtype name of outer struct of user data
 *  \param[in] element name of field within \a dtype */
#define CTRL_HELPER_SET_STRING(cmdname, dtype, element) \
static int set_##cmdname(struct ctrl_cmd *cmd, void *_data) \
{ \
	dtype *data = cmd->node; \
	osmo_talloc_replace_string(cmd->node, &data->element, cmd->value); \
	return get_##cmdname(cmd, _data); \
}

/*! Helper to generate GET, SET, VERIFY + ctrl_cmd_element for string
 *  \param[in] cmdname symbol name of the command related function
 *  \param[in] cmdstr string name exposed on CTRL
 *  \param[in] dtype name of outer struct of user data
 *  \param[in] element name of field within \a dtype
 *  \param[in] min minimum permitted integer value
 *  \param[in] max maximum permitted integer value */
#define CTRL_CMD_DEFINE_STRING(cmdname, cmdstr, dtype, element) \
	CTRL_HELPER_GET_STRING(cmdname, dtype, element) \
	CTRL_HELPER_SET_STRING(cmdname, dtype, element) \
CTRL_CMD_DEFINE_STRUCT(cmdname, cmdstr, NULL)

/*! Declare a read-write attribute. Declares get, set, verify.
 *  \param[in] cmdname symbol name of the command related functions/structures
 *  \param[in] cmdstr string name exposed on CTRL */
#define CTRL_CMD_DEFINE(cmdname, cmdstr) \
static int get_##cmdname(struct ctrl_cmd *cmd, void *data); \
static int set_##cmdname(struct ctrl_cmd *cmd, void *data); \
static int verify_##cmdname(struct ctrl_cmd *cmd, const char *value, void *data); \
CTRL_CMD_DEFINE_STRUCT(cmdname, cmdstr, verify_##cmdname)

/*! Define a read-only attribute. Declares get, implements set+verify
 *  \param[in] cmdname symbol name of the command related functions/structures
 *  \param[in] cmdstr string name exposed on CTRL */
#define CTRL_CMD_DEFINE_RO(cmdname, cmdstr) \
static int get_##cmdname(struct ctrl_cmd *cmd, void *data);		\
static int set_##cmdname(struct ctrl_cmd *cmd, void *data)	\
{									\
	cmd->reply = "Read Only attribute";				\
	return CTRL_CMD_ERROR;						\
}									\
static int verify_##cmdname(struct ctrl_cmd *cmd, const char *value, void *data) \
{									\
	cmd->reply = "Read Only attribute";				\
	return 1;							\
}									\
CTRL_CMD_DEFINE_STRUCT(cmdname, cmdstr, verify_##cmdname)

/*! Define a write-only attribute. Declares set+verify, implements read call-back
 *  \param[in] cmdname symbol name of the command related functions/structures
 *  \param[in] cmdstr string name exposed on CTRL */
#define CTRL_CMD_DEFINE_WO(cmdname, cmdstr)					\
static int set_##cmdname(struct ctrl_cmd *cmd, void *data);			\
static int get_##cmdname(struct ctrl_cmd *cmd, void *data)			\
{										\
	cmd->reply = "Write Only attribute";					\
	return CTRL_CMD_ERROR;							\
}										\
static int verify_##cmdname(struct ctrl_cmd *cmd, const char *val, void *data);	\
CTRL_CMD_DEFINE_STRUCT(cmdname, cmdstr, verify_##cmdname)

/*! Define a write-only attribute without verify. Declares set, implements read+verify
 *  \param[in] cmdname symbol name of the command related functions/structures
 *  \param[in] cmdstr string name exposed on CTRL */
#define CTRL_CMD_DEFINE_WO_NOVRF(cmdname, cmdstr)				\
static int set_##cmdname(struct ctrl_cmd *cmd, void *data);			\
static int get_##cmdname(struct ctrl_cmd *cmd, void *data)			\
{										\
	cmd->reply = "Write Only attribute";					\
	return CTRL_CMD_ERROR;							\
}										\
static int verify_##cmdname(struct ctrl_cmd *cmd, const char *val, void *data)	\
{					      					\
	return 0;								\
}										\
CTRL_CMD_DEFINE_STRUCT(cmdname, cmdstr, verify_##cmdname)

struct gsm_network;
