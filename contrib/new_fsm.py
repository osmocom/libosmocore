#!/usr/bin/env python3
import jinja2
import sys

def as_tuple(str_or_tuple):
	if isinstance(str_or_tuple, str):
		return (str_or_tuple,)
	return tuple(str_or_tuple)

class State:
	def __init__(s, name, events=(), out_states=(), onenter=True):
		s.name = name
		s.const = name.upper()
		s.events = as_tuple(events)
		s.out_states = as_tuple(out_states)
		s.onenter = onenter
	def __eq__(s, name):
		return s.name == name

class Event:
	def __init__(s, name):
		s.name = name
		s.const = name.upper()

	def __eq__(s, name):
		return s.name == name

class FSM:
	def NAME(s, name):
		return '_'.join((s.prefix, name)).upper()

	def name(s, name):
		return '_'.join((s.prefix, name)).lower()

	def state_const(s, name):
		return s.NAME('ST_' + name)

	def event_const(s, name):
		return s.NAME('EV_' + name)

	def __init__(s, prefix, priv, states, head=''):
		s.head = head
		s.prefix = prefix
		s.priv = priv
		s.states = states
		for state in s.states:
			state.const = s.state_const(state.name)

			out_state_class_insts = []
			for out_state in state.out_states:
				out_state_class_insts.append(s.states[s.states.index(out_state)])
			state.out_states = out_state_class_insts

		s.events = []
		for state in s.states:
			state_event_class_insts = []
			for event in state.events:
				if event not in s.events:
					ev = Event(event)
					ev.const = s.event_const(event)
					s.events.append(ev)
				else:
					ev = s.events[s.events.index(event)]
				state_event_class_insts.append(ev)
			state.events = state_event_class_insts

	def to_c(s):
		template = jinja2.Template(
'''
{{head}}
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>

enum {{prefix}}_fsm_state {
{% for state in states %}	{{state.const}},
{% endfor -%}
};

enum {{prefix}}_fsm_event {
{% for event in events %}	{{event.const}},
{% endfor -%}
};

static const struct value_string {{prefix}}_fsm_event_names[] = {
{% for event in events %}	OSMO_VALUE_STRING({{event.const}}),
{% endfor %}	{}
};

static struct osmo_fsm {{prefix}}_fsm;

static const struct osmo_tdef_state_timeout {{prefix}}_fsm_timeouts[32] = {
{% for state in states %}	[{{state.const}}] = { .T = 0 },
{% endfor -%}
};

/* Transition to a state, using the T timer defined in {{prefix}}_fsm_timeouts.
 * Assumes local variable fi exists. */
#define {{prefix}}_fsm_state_chg(state) \\
       osmo_tdef_fsm_inst_state_chg(fi, state, \\
                                    {{prefix}}_fsm_timeouts, \\
                                    g_tdefs, \\
                                    5)

struct {{priv}} *{{prefix}}_alloc(struct osmo_fsm_inst *parent_fi, uint32_t parent_event_term)
{
	struct {{priv}} *{{priv}};

	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc_child(&{{prefix}}_fsm, parent_fi, parent_event_term);
	OSMO_ASSERT(fi);

	{{priv}} = talloc(fi, struct {{priv}});
	OSMO_ASSERT({{priv}});
	fi->priv = {{priv}};
	*{{priv}} = (struct {{priv}}){
		.fi = fi,
	};

	return {{priv}};
}

static int {{prefix}}_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	//struct {{priv}} *{{priv}} = fi->priv;
	/* Return 1 to terminate FSM instance, 0 to keep running */
	return 1;
}
{% for state in states %}
{%- if state.onenter %}
static void {{prefix}}_{{state.name}}_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	//struct {{priv}} *{{priv}} = fi->priv;
	// FIXME
}
{%  endif %}
static void {{prefix}}_{{state.name}}_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct {{priv}} *{{priv}} = fi->priv;

	switch (event) {
{% for event in state.events %}
	case {{event.const}}:
		// FIXME
		break;
{% endfor %}
	default:
		OSMO_ASSERT(false);
	}
}
{% endfor %}
#define S(x)    (1 << (x))

static const struct osmo_fsm_state {{prefix}}_fsm_states[] = {
{% for state in states %}	[{{state.const}}] = {
		.name = "{{state.name}}",
		.in_event_mask = 0
{% for event in state.events %}			| S({{event.const}})
{% endfor %}			,
		.out_state_mask = 0
{% for out_state in state.out_states %}			| S({{out_state.const}})
{% endfor %}			,{% if state.onenter %}
		.onenter = {{prefix}}_{{state.name}}_onenter,{% endif %}
		.action = {{prefix}}_{{state.name}}_action,
	},
{% endfor -%}
};

static struct osmo_fsm {{prefix}}_fsm = {
	.name = "{{prefix}}",
	.states = {{prefix}}_fsm_states,
	.num_states = ARRAY_SIZE({{prefix}}_fsm_states),
	.log_subsys = DLGLOBAL, // FIXME
	.event_names = {{prefix}}_fsm_event_names,
	.timer_cb = {{prefix}}_fsm_timer_cb,
};

static __attribute__((constructor)) void {{prefix}}_fsm_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&{{prefix}}_fsm) == 0);
}
''')

		return template.render(**vars(s))

fsm = FSM(head='#include <osmocom/hnbgw/context_map.h>',
	  prefix = 'cm_rua',
	  priv = 'hnbgw_context_map',
	  states = (
		    State('init',
			  events=(),
			  out_states=('connected',),
			  onenter=False
			 ),
		    State('connected',
			  events=('rx_id_direct_transfer',
				  'ranap_msg',
				  'sccp_rlsd'),
			  out_states=('disconnected',),
			  onenter=False
			 ),
		    State('disconnected',
			 ),
		   )
	 )
with open('context_map_rua.c', 'w') as f:
	f.write(fsm.to_c())

fsm = FSM(head='#include <osmocom/hnbgw/context_map.h>',
	  prefix = 'cm_sccp',
	  priv = 'hnbgw_context_map',
	  states = (
		    State('init',
			  events=('ranap_msg',
				 ),
			  out_states=('wait_cc',
				     ),
			  onenter=False
			 ),
		    State('wait_cc',
			  events=('rx_connection_confirm',
				 ),
			  out_states=('connected',
				     ),
			  onenter=False
			 ),
		    State('connected',
			  events=('rx_data_form_1',
				  'ranap_msg',
				  'rua_disc',
				 ),
			  out_states=('wait_rlc',
				      'disconnected',
				     ),
			  onenter=False
			 ),
		    State('wait_rlc',
			  events=('rx_release_complete',
				 ),
			  out_states=('disconnected',
				     ),
			  onenter=False
			 ),
		    State('disconnected',
			 ),
		   )
	 )
with open('context_map_sccp.c', 'w') as f:
	f.write(fsm.to_c())
