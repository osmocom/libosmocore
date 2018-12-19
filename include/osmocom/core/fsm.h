/*! \file fsm.h
 *  Finite State Machine
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/utils.h>

/*! \defgroup fsm Finite State Machine abstraction
 *  @{
 * \file fsm.h */

struct osmo_fsm_inst;

enum osmo_fsm_term_cause {
	/*! terminate because parent terminated */
	OSMO_FSM_TERM_PARENT,
	/*! terminate on explicit user request */
	OSMO_FSM_TERM_REQUEST,
	/*! regular termination of process */
	OSMO_FSM_TERM_REGULAR,
	/*! erroneous termination of process */
	OSMO_FSM_TERM_ERROR,
	/*! termination due to time-out */
	OSMO_FSM_TERM_TIMEOUT,
};

extern const struct value_string osmo_fsm_term_cause_names[];
static inline const char *osmo_fsm_term_cause_name(enum osmo_fsm_term_cause cause)
{
	return get_value_string(osmo_fsm_term_cause_names, cause);
}


/*! description of a rule in the FSM */
struct osmo_fsm_state {
	/*! bit-mask of permitted input events for this state */
	uint32_t in_event_mask;
	/*! bit-mask to which other states this state may transiton */
	uint32_t out_state_mask;
	/*! human-readable name of this state */
	const char *name;
	/*! function to be called for events arriving in this state */
	void (*action)(struct osmo_fsm_inst *fi, uint32_t event, void *data);
	/*! function to be called just after entering the state */
	void (*onenter)(struct osmo_fsm_inst *fi, uint32_t prev_state);
	/*! function to be called just before leaving the state */
	void (*onleave)(struct osmo_fsm_inst *fi, uint32_t next_state);
};

/*! a description of an osmocom finite state machine */
struct osmo_fsm {
	/*! global list */
	struct llist_head list;
	/*! list of instances of this FSM */
	struct llist_head instances;
	/*! human readable name */
	const char *name;
	/*! table of state transition rules */
	const struct osmo_fsm_state *states;
	/*! number of entries in \ref states */
	unsigned int num_states;
	/*! bit-mask of events permitted in all states */
	uint32_t allstate_event_mask;
	/*! function pointer to be called for allstate events */
	void (*allstate_action)(struct osmo_fsm_inst *fi, uint32_t event, void *data);
	/*! clean-up function, called during termination */
	void (*cleanup)(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause);
	/*! timer call-back for states with time-out.
	 * \returns 1 to request termination, 0 to keep running. */
	int (*timer_cb)(struct osmo_fsm_inst *fi);
	/*! logging sub-system for this FSM */
	int log_subsys;
	/*! human-readable names of events */
	const struct value_string *event_names;
	/*! graceful exit function, called at the beginning of termination */
	void (*pre_term)(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause);
};

/*! a single instanceof an osmocom finite state machine */
struct osmo_fsm_inst {
	/*! member in the fsm->instances list */
	struct llist_head list;
	/*! back-pointer to the FSM of which we are an instance */
	struct osmo_fsm *fsm;
	/*! human readable identifier */
	const char *id;
	/*! human readable fully-qualified name */
	const char *name;
	/*! some private data of this instance */
	void *priv;
	/*! logging level for this FSM */
	int log_level;
	/*! current state of the FSM */
	uint32_t state;

	/*! timer number for states with time-out */
	int T;
	/*! timer back-end for states with time-out */
	struct osmo_timer_list timer;

	/*! support for fsm-based procedures */
	struct {
		/*! the parent FSM that has created us */
		struct osmo_fsm_inst *parent;
		/*! the event we should send upon termination */
		uint32_t parent_term_event;
		/*! a list of children processes */
		struct llist_head children;
		/*! \ref llist_head linked to parent->proc.children */
		struct llist_head child;
	} proc;
};

void osmo_fsm_log_addr(bool log_addr);

/*! Log using FSM instance's context, on explicit logging level.
 * \param fi  An osmo_fsm_inst.
 * \param level  A logging level, e.g. LOGL_INFO.
 * \param fmt  printf-like format string.
 * \param args  Format string arguments.
 */
#define LOGPFSML(fi, level, fmt, args...) \
		LOGPFSMLSRC(fi, level, __FILE__, __LINE__, fmt, ## args)

/*! Log using FSM instance's context, on explicit logging level, and with explicit source file and line info.
 * The log subsystem to log on is obtained from the underlying FSM definition.
 * \param fi  An osmo_fsm_inst.
 * \param level  A logging level, e.g. LOGL_INFO.
 * \param caller_file  A string constant containing a source file path, like __FILE__.
 * \param caller_line  A number constant containing a source file line, like __LINE__.
 * \param fmt  printf-like format string.
 * \param args  Format string arguments.
 */
#define LOGPFSMLSRC(fi, level, caller_file, caller_line, fmt, args...) \
		LOGPSRC((fi)->fsm->log_subsys, level, \
			caller_file, caller_line, \
			"%s{%s}: " fmt, \
			osmo_fsm_inst_name(fi), \
			osmo_fsm_state_name((fi)->fsm, (fi)->state), \
			## args)

/*! Log using FSM instance's context.
 * The log level to log on is obtained from the FSM instance.
 * The log subsystem to log on is obtained from the underlying FSM definition.
 * \param fi  An osmo_fsm_inst.
 * \param fmt  printf-like format string.
 * \param args  Format string arguments.
 */
#define LOGPFSM(fi, fmt, args...) \
		LOGPFSML(fi, (fi)->log_level, fmt, ## args)

/*! Log using FSM instance's context, with explicit source file and line info.
 * The log level to log on is obtained from the FSM instance.
 * The log subsystem to log on is obtained from the underlying FSM definition.
 * \param fi  An osmo_fsm_inst.
 * \param caller_file  A string constant containing a source file path, like __FILE__.
 * \param caller_line  A number constant containing a source file line, like __LINE__.
 * \param fmt  printf-like format string.
 * \param args  Format string arguments.
 */
#define LOGPFSMSRC(fi, caller_file, caller_line, fmt, args...) \
		LOGPFSMLSRC(fi, (fi)->log_level, \
			    caller_file, caller_line, \
			    fmt, ## args)

int osmo_fsm_register(struct osmo_fsm *fsm);
void osmo_fsm_unregister(struct osmo_fsm *fsm);
struct osmo_fsm *osmo_fsm_find_by_name(const char *name);
struct osmo_fsm_inst *osmo_fsm_inst_find_by_name(const struct osmo_fsm *fsm,
						 const char *name);
struct osmo_fsm_inst *osmo_fsm_inst_find_by_id(const struct osmo_fsm *fsm,
						const char *id);
struct osmo_fsm_inst *osmo_fsm_inst_alloc(struct osmo_fsm *fsm, void *ctx, void *priv,
					  int log_level, const char *id);
struct osmo_fsm_inst *osmo_fsm_inst_alloc_child(struct osmo_fsm *fsm,
						struct osmo_fsm_inst *parent,
						uint32_t parent_term_event);
void osmo_fsm_inst_unlink_parent(struct osmo_fsm_inst *fi, void *ctx);
void osmo_fsm_inst_change_parent(struct osmo_fsm_inst *fi,
				 struct osmo_fsm_inst *new_parent,
				 uint32_t new_parent_term_event);
void osmo_fsm_inst_free(struct osmo_fsm_inst *fi);

int osmo_fsm_inst_update_id(struct osmo_fsm_inst *fi, const char *id);
int osmo_fsm_inst_update_id_f(struct osmo_fsm_inst *fi, const char *fmt, ...);

const char *osmo_fsm_event_name(struct osmo_fsm *fsm, uint32_t event);
const char *osmo_fsm_inst_name(struct osmo_fsm_inst *fi);
const char *osmo_fsm_state_name(struct osmo_fsm *fsm, uint32_t state);

/*! return the name of the state the FSM instance is currently in. */
static inline const char *osmo_fsm_inst_state_name(struct osmo_fsm_inst *fi)
{ return osmo_fsm_state_name(fi->fsm, fi->state); }

/*! perform a state change of the given FSM instance
 *
 *  This is a macro that calls _osmo_fsm_inst_state_chg() with the given
 *  parameters as well as the caller's source file and line number for logging
 *  purposes. See there for documentation.
 */
#define osmo_fsm_inst_state_chg(fi, new_state, timeout_secs, T) \
	_osmo_fsm_inst_state_chg(fi, new_state, timeout_secs, T, \
				 __FILE__, __LINE__)
int _osmo_fsm_inst_state_chg(struct osmo_fsm_inst *fi, uint32_t new_state,
			     unsigned long timeout_secs, int T,
			     const char *file, int line);

/*! perform a state change while keeping the current timer running.
 *
 *  This is useful to keep a timeout across several states (without having to round the
 *  remaining time to seconds).
 *
 *  This is a macro that calls _osmo_fsm_inst_state_chg_keep_timer() with the given
 *  parameters as well as the caller's source file and line number for logging
 *  purposes. See there for documentation.
 */
#define osmo_fsm_inst_state_chg_keep_timer(fi, new_state) \
	_osmo_fsm_inst_state_chg_keep_timer(fi, new_state, \
				 __FILE__, __LINE__)
int _osmo_fsm_inst_state_chg_keep_timer(struct osmo_fsm_inst *fi, uint32_t new_state,
					const char *file, int line);

/*! dispatch an event to an osmocom finite state machine instance
 *
 *  This is a macro that calls _osmo_fsm_inst_dispatch() with the given
 *  parameters as well as the caller's source file and line number for logging
 *  purposes. See there for documentation.
 */
#define osmo_fsm_inst_dispatch(fi, event, data) \
	_osmo_fsm_inst_dispatch(fi, event, data, __FILE__, __LINE__)
int _osmo_fsm_inst_dispatch(struct osmo_fsm_inst *fi, uint32_t event, void *data,
			    const char *file, int line);

/*! Terminate FSM instance with given cause
 *
 *  This is a macro that calls _osmo_fsm_inst_term() with the given parameters
 *  as well as the caller's source file and line number for logging purposes.
 *  See there for documentation.
 */
#define osmo_fsm_inst_term(fi, cause, data) \
	_osmo_fsm_inst_term(fi, cause, data, __FILE__, __LINE__)
void _osmo_fsm_inst_term(struct osmo_fsm_inst *fi,
			 enum osmo_fsm_term_cause cause, void *data,
			 const char *file, int line);

/*! Terminate all child FSM instances of an FSM instance.
 *
 *  This is a macro that calls _osmo_fsm_inst_term_children() with the given
 *  parameters as well as the caller's source file and line number for logging
 *  purposes. See there for documentation.
 */
#define osmo_fsm_inst_term_children(fi, cause, data) \
	_osmo_fsm_inst_term_children(fi, cause, data, __FILE__, __LINE__)
void _osmo_fsm_inst_term_children(struct osmo_fsm_inst *fi,
				  enum osmo_fsm_term_cause cause,
				  void *data,
				  const char *file, int line);

/*! @} */
