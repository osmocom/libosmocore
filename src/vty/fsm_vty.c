/*
 * (C) 2016 by Harald Welte <laforge@gnumonks.org>
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

#include <stdlib.h>
#include <string.h>

#include "config.h"

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>

/*! \file fsm_vty.c
 *  Osmocom FSM introspection via VTY.
 *
 *  This is code implementing generic VTY access to Osmocom FSMs from
 *  libosmocore.  This means that any application can expose all state
 *  of all instances of all registered FSM classes by calling a single
 *  command during startup: \ref osmo_fsm_vty_add_cmds
 */

/* we don't want to add this to a public header file; this is simply
 * exported by libosmocore and used by libmsomvty but not for public
 * consumption. */
extern struct llist_head osmo_g_fsms;

/*! Print information about a FSM [class] to the given VTY
 *  \param vty The VTY to which to print
 *  \param[in] prefix prefix to print at start of each line (typically indenting)
 *  \param[in] fsm The FSM class to print
 */
void vty_out_fsm2(struct vty *vty, const char *prefix, struct osmo_fsm *fsm)
{
	unsigned int i;
	const struct value_string *evt_name;

	vty_out(vty, "%sFSM Name: '%s', Log Subsys: '%s'%s", prefix, fsm->name,
		log_category_name(fsm->log_subsys), VTY_NEWLINE);
	/* list the events */
	if (fsm->event_names) {
		for (evt_name = fsm->event_names; evt_name->str != NULL; evt_name++) {
			vty_out(vty, "%s Event %02u (0x%08x): '%s'%s", prefix, evt_name->value,
				(1U << evt_name->value), evt_name->str, VTY_NEWLINE);
		}
	} else
		vty_out(vty, "%s No event names are defined for this FSM! Please fix!%s", prefix, VTY_NEWLINE);

	/* list the states */
	vty_out(vty, "%s Number of States: %u%s", prefix, fsm->num_states, VTY_NEWLINE);
	for (i = 0; i < fsm->num_states; i++) {
		const struct osmo_fsm_state *state = &fsm->states[i];
		vty_out(vty, "%s  State %-20s InEvtMask: 0x%08x, OutStateMask: 0x%08x%s", prefix,
			state->name, state->in_event_mask, state->out_state_mask,
			VTY_NEWLINE);
	}
}

/*! Print information about a FSM [class] to the given VTY
 *  \param vty The VTY to which to print
 *  \param[in] fsm The FSM class to print
 */
void vty_out_fsm(struct vty *vty, struct osmo_fsm *fsm)
{
	vty_out_fsm2(vty, "", fsm);
}

/*! Print a FSM instance to the given VTY
 *  \param vty The VTY to which to print
 *  \param[in] prefix prefix to print at start of each line (typically indenting)
 *  \param[in] fsmi The FSM instance to print
 */
void vty_out_fsm_inst2(struct vty *vty, const char *prefix, struct osmo_fsm_inst *fsmi)
{
	struct osmo_fsm_inst *child;

	vty_out(vty, "%sFSM Instance Name: '%s', ID: '%s'%s", prefix,
		fsmi->name, fsmi->id, VTY_NEWLINE);
	vty_out(vty, "%s Log-Level: '%s', State: '%s'%s", prefix,
		log_level_str(fsmi->log_level),
		osmo_fsm_state_name(fsmi->fsm, fsmi->state),
		VTY_NEWLINE);
	if (fsmi->T)
		vty_out(vty, "%s Timer: %u%s", prefix, fsmi->T, VTY_NEWLINE);
	if (fsmi->proc.parent) {
		vty_out(vty, "%s Parent: '%s', Term-Event: '%s'%s", prefix,
			fsmi->proc.parent->name,
			osmo_fsm_event_name(fsmi->proc.parent->fsm,
					    fsmi->proc.parent_term_event),
			VTY_NEWLINE);
	}
	llist_for_each_entry(child, &fsmi->proc.children, proc.child) {
		vty_out(vty, "%s Child: '%s'%s", prefix, child->name, VTY_NEWLINE);
	}
}

/*! Print a FSM instance to the given VTY
 *  \param vty The VTY to which to print
 *  \param[in] fsmi The FSM instance to print
 */
void vty_out_fsm_inst(struct vty *vty, struct osmo_fsm_inst *fsmi)
{
	vty_out_fsm_inst2(vty, "", fsmi);
}

#define SH_FSM_STR	SHOW_STR "Show information about finite state machines\n"
#define SH_FSMI_STR	SHOW_STR "Show information about finite state machine instances\n"

DEFUN(show_fsms, show_fsms_cmd,
	"show fsm all",
	SH_FSM_STR
	"Display a list of all registered finite state machines\n")
{
	struct osmo_fsm *fsm;

	llist_for_each_entry(fsm, &osmo_g_fsms, list)
		vty_out_fsm(vty, fsm);

	return CMD_SUCCESS;
}

DEFUN(show_fsm, show_fsm_cmd,
	"show fsm NAME",
	SH_FSM_STR
	"Display information about a single named finite state machine\n")
{
	struct osmo_fsm *fsm;

	fsm = osmo_fsm_find_by_name(argv[0]);
	if (!fsm) {
		vty_out(vty, "Error: FSM with name '%s' doesn't exist!%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out_fsm(vty, fsm);

	return CMD_SUCCESS;
}

DEFUN(show_fsm_insts, show_fsm_insts_cmd,
	"show fsm-instances all",
	SH_FSMI_STR
	"Display a list of all FSM instances of all finite state machine")
{
	struct osmo_fsm *fsm;

	llist_for_each_entry(fsm, &osmo_g_fsms, list) {
		struct osmo_fsm_inst *fsmi;
		llist_for_each_entry(fsmi, &fsm->instances, list)
			vty_out_fsm_inst(vty, fsmi);
	}

	return CMD_SUCCESS;
}

DEFUN(show_fsm_inst, show_fsm_inst_cmd,
	"show fsm-instances NAME",
	SH_FSMI_STR
	"Display a list of all FSM instances of the named finite state machine")
{
	struct osmo_fsm *fsm;
	struct osmo_fsm_inst *fsmi;

	fsm = osmo_fsm_find_by_name(argv[0]);
	if (!fsm) {
		vty_out(vty, "Error: FSM with name '%s' doesn't exist!%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	llist_for_each_entry(fsmi, &fsm->instances, list)
		vty_out_fsm_inst(vty, fsmi);

	return CMD_SUCCESS;
}

/*! Install VTY commands for FSM introspection
 *  This installs a couple of VTY commands for introspection of FSM
 *  classes as well as FSM instances. Call this once from your
 *  application if you want to support those commands. */
void osmo_fsm_vty_add_cmds(void)
{
	static bool osmo_fsm_vty_cmds_installed;

	/* Make sure FSM commands get installed only once.
	 * We might be called from libraries or from an application.
	 * An application might be oblivious to the fact that one or
	 * more of its libaries are using osmo_fsm. And likewise,
	 * any given library will not know if another library has
	 * already installled these commands. */
	if (osmo_fsm_vty_cmds_installed)
		return;

	install_lib_element_ve(&show_fsm_cmd);
	install_lib_element_ve(&show_fsms_cmd);
	install_lib_element_ve(&show_fsm_inst_cmd);
	install_lib_element_ve(&show_fsm_insts_cmd);
	osmo_fsm_vty_cmds_installed = true;
}
