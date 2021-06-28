/*
 * (C) 2008-2014,2017 by Harald Welte <laforge@gnumonks.org>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*! \addtogroup oml
 *  @{
 * GSM Network Management (OML) messages on the A-bis interface.
 * 3GPP TS 12.21 version 8.0.0 Release 1999 / ETSI TS 100 623 V8.0.0
 *
 * \file abis_nm.c */

#include <stdint.h>
#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>
#include <osmocom/gsm/abis_nm.h>

const char abis_nm_ipa_magic[13] = "com.ipaccess";
const char abis_nm_osmo_magic[12] = "org.osmocom";

/*! unidirectional messages from BTS to BSC */
const enum abis_nm_msgtype abis_nm_reports[4] = {
	NM_MT_SW_ACTIVATED_REP,
	NM_MT_TEST_REP,
	NM_MT_STATECHG_EVENT_REP,
	NM_MT_FAILURE_EVENT_REP,
};

/*! messages without ACK/NACK */
const enum abis_nm_msgtype abis_nm_no_ack_nack[3] = {
	NM_MT_MEAS_RES_REQ,
	NM_MT_STOP_MEAS,
	NM_MT_START_MEAS,
};

/*! messages related to software load */
const enum abis_nm_msgtype abis_nm_sw_load_msgs[9] = {
	NM_MT_LOAD_INIT_ACK,
	NM_MT_LOAD_INIT_NACK,
	NM_MT_LOAD_SEG_ACK,
	NM_MT_LOAD_ABORT,
	NM_MT_LOAD_END_ACK,
	NM_MT_LOAD_END_NACK,
	//NM_MT_SW_ACT_REQ,
	NM_MT_ACTIVATE_SW_ACK,
	NM_MT_ACTIVATE_SW_NACK,
	NM_MT_SW_ACTIVATED_REP,
};

/*! All NACKs (negative acknowledgements */
const enum abis_nm_msgtype abis_nm_nacks[33] = {
	NM_MT_LOAD_INIT_NACK,
	NM_MT_LOAD_END_NACK,
	NM_MT_SW_ACT_REQ_NACK,
	NM_MT_ACTIVATE_SW_NACK,
	NM_MT_ESTABLISH_TEI_NACK,
	NM_MT_CONN_TERR_SIGN_NACK,
	NM_MT_DISC_TERR_SIGN_NACK,
	NM_MT_CONN_TERR_TRAF_NACK,
	NM_MT_DISC_TERR_TRAF_NACK,
	NM_MT_CONN_MDROP_LINK_NACK,
	NM_MT_DISC_MDROP_LINK_NACK,
	NM_MT_SET_BTS_ATTR_NACK,
	NM_MT_SET_RADIO_ATTR_NACK,
	NM_MT_SET_CHAN_ATTR_NACK,
	NM_MT_PERF_TEST_NACK,
	NM_MT_SEND_TEST_REP_NACK,
	NM_MT_STOP_TEST_NACK,
	NM_MT_STOP_EVENT_REP_NACK,
	NM_MT_REST_EVENT_REP_NACK,
	NM_MT_CHG_ADM_STATE_NACK,
	NM_MT_CHG_ADM_STATE_REQ_NACK,
	NM_MT_REP_OUTST_ALARMS_NACK,
	NM_MT_CHANGEOVER_NACK,
	NM_MT_OPSTART_NACK,
	NM_MT_REINIT_NACK,
	NM_MT_SET_SITE_OUT_NACK,
	NM_MT_CHG_HW_CONF_NACK,
	NM_MT_GET_ATTR_NACK,
	NM_MT_SET_ALARM_THRES_NACK,
	(enum abis_nm_msgtype) NM_MT_BS11_BEGIN_DB_TX_NACK,
	(enum abis_nm_msgtype) NM_MT_BS11_END_DB_TX_NACK,
	(enum abis_nm_msgtype) NM_MT_BS11_CREATE_OBJ_NACK,
	(enum abis_nm_msgtype) NM_MT_BS11_DELETE_OBJ_NACK,
};

static const struct value_string nack_names[] = {
	{ NM_MT_LOAD_INIT_NACK,		"SOFTWARE LOAD INIT" },
	{ NM_MT_LOAD_END_NACK,		"SOFTWARE LOAD END" },
	{ NM_MT_SW_ACT_REQ_NACK,	"SOFTWARE ACTIVATE REQUEST" },
	{ NM_MT_ACTIVATE_SW_NACK,	"ACTIVATE SOFTWARE" },
	{ NM_MT_ESTABLISH_TEI_NACK,	"ESTABLISH TEI" },
	{ NM_MT_CONN_TERR_SIGN_NACK,	"CONNECT TERRESTRIAL SIGNALLING" },
	{ NM_MT_DISC_TERR_SIGN_NACK,	"DISCONNECT TERRESTRIAL SIGNALLING" },
	{ NM_MT_CONN_TERR_TRAF_NACK,	"CONNECT TERRESTRIAL TRAFFIC" },
	{ NM_MT_DISC_TERR_TRAF_NACK,	"DISCONNECT TERRESTRIAL TRAFFIC" },
	{ NM_MT_CONN_MDROP_LINK_NACK,	"CONNECT MULTI-DROP LINK" },
	{ NM_MT_DISC_MDROP_LINK_NACK,	"DISCONNECT MULTI-DROP LINK" },
	{ NM_MT_SET_BTS_ATTR_NACK,	"SET BTS ATTRIBUTE" },
	{ NM_MT_SET_RADIO_ATTR_NACK,	"SET RADIO ATTRIBUTE" },
	{ NM_MT_SET_CHAN_ATTR_NACK,	"SET CHANNEL ATTRIBUTE" },
	{ NM_MT_PERF_TEST_NACK,		"PERFORM TEST" },
	{ NM_MT_SEND_TEST_REP_NACK,	"SEND TEST REPORT" },
	{ NM_MT_STOP_TEST_NACK,		"STOP TEST" },
	{ NM_MT_STOP_EVENT_REP_NACK,	"STOP EVENT REPORT" },
	{ NM_MT_REST_EVENT_REP_NACK,	"RESET EVENT REPORT" },
	{ NM_MT_CHG_ADM_STATE_NACK,	"CHANGE ADMINISTRATIVE STATE" },
	{ NM_MT_CHG_ADM_STATE_REQ_NACK,
				"CHANGE ADMINISTRATIVE STATE REQUEST" },
	{ NM_MT_REP_OUTST_ALARMS_NACK,	"REPORT OUTSTANDING ALARMS" },
	{ NM_MT_CHANGEOVER_NACK,	"CHANGEOVER" },
	{ NM_MT_OPSTART_NACK,		"OPSTART" },
	{ NM_MT_REINIT_NACK,		"REINIT" },
	{ NM_MT_SET_SITE_OUT_NACK,	"SET SITE OUTPUT" },
	{ NM_MT_CHG_HW_CONF_NACK,	"CHANGE HARDWARE CONFIGURATION" },
	{ NM_MT_GET_ATTR_NACK,		"GET ATTRIBUTE" },
	{ NM_MT_SET_ALARM_THRES_NACK,	"SET ALARM THRESHOLD" },
	{ NM_MT_BS11_BEGIN_DB_TX_NACK,	"BS11 BEGIN DATABASE TRANSMISSION" },
	{ NM_MT_BS11_END_DB_TX_NACK,	"BS11 END DATABASE TRANSMISSION" },
	{ NM_MT_BS11_CREATE_OBJ_NACK,	"BS11 CREATE OBJECT" },
	{ NM_MT_BS11_DELETE_OBJ_NACK,	"BS11 DELETE OBJECT" },
	{ 0,				NULL }
};

/*! Get human-readable string for OML NACK message type */
const char *abis_nm_nack_name(uint8_t nack)
{
	return get_value_string(nack_names, nack);
}

/* Section 9.4.43: Manufacturer specific values */
const struct value_string abis_mm_event_cause_names[] = {
	{ OSMO_EVT_CRIT_SW_FATAL,	"Fatal software error" },
	{ OSMO_EVT_CRIT_PROC_STOP,	"Process stopped" },
	{ OSMO_EVT_CRIT_RTP_TOUT,	"RTP error" },
	{ OSMO_EVT_CRIT_BOOT_FAIL,	"Boot failure" },
	{ OSMO_EVT_MAJ_UKWN_MSG,	"Unknown message" },
	{ OSMO_EVT_MAJ_RSL_FAIL,	"RSL failure" },
	{ OSMO_EVT_MAJ_UNSUP_ATTR,	"Unsupported attribute" },
	{ OSMO_EVT_MAJ_NET_CONGEST,	"Network congestion" },
	{ OSMO_EVT_MIN_PAG_TAB_FULL,	"Paging table full" },
	{ OSMO_EVT_WARN_SW_WARN,	"Software warning" },
	{ OSMO_EVT_EXT_ALARM,		"External alarm" },
	{ OSMO_EVT_PCU_VERS,		"PCU version report" },
	{ 0, NULL }
};

const struct value_string abis_nm_pcause_type_names[] = {
	{ NM_PCAUSE_T_X721,	"ISO/CCITT values (X.721)"},
	{ NM_PCAUSE_T_GSM,	"GSM specific values"},
	{ NM_PCAUSE_T_MANUF,	"Manufacturer specific values"},
	{ 0, NULL }
};

/* Chapter 9.4.36 */
static const struct value_string nack_cause_names[] = {
	/* General Nack Causes */
	{ NM_NACK_INCORR_STRUCT,	"Incorrect message structure" },
	{ NM_NACK_MSGTYPE_INVAL,	"Invalid message type value" },
	{ NM_NACK_OBJCLASS_INVAL,	"Invalid Object class value" },
	{ NM_NACK_OBJCLASS_NOTSUPP,	"Object class not supported" },
	{ NM_NACK_BTSNR_UNKN,		"BTS no. unknown" },
	{ NM_NACK_TRXNR_UNKN,		"Baseband Transceiver no. unknown" },
	{ NM_NACK_OBJINST_UNKN,		"Object Instance unknown" },
	{ NM_NACK_ATTRID_INVAL,		"Invalid attribute identifier value" },
	{ NM_NACK_ATTRID_NOTSUPP,	"Attribute identifier not supported" },
	{ NM_NACK_PARAM_RANGE,		"Parameter value outside permitted range" },
	{ NM_NACK_ATTRLIST_INCONSISTENT,"Inconsistency in attribute list" },
	{ NM_NACK_SPEC_IMPL_NOTSUPP,	"Specified implementation not supported" },
	{ NM_NACK_CANT_PERFORM,		"Message cannot be performed" },
	/* Specific Nack Causes */
	{ NM_NACK_RES_NOTIMPL,		"Resource not implemented" },
	{ NM_NACK_RES_NOTAVAIL,		"Resource not available" },
	{ NM_NACK_FREQ_NOTAVAIL,	"Frequency not available" },
	{ NM_NACK_TEST_NOTSUPP,		"Test not supported" },
	{ NM_NACK_CAPACITY_RESTR,	"Capacity restrictions" },
	{ NM_NACK_PHYSCFG_NOTPERFORM,	"Physical configuration cannot be performed" },
	{ NM_NACK_TEST_NOTINIT,		"Test not initiated" },
	{ NM_NACK_PHYSCFG_NOTRESTORE,	"Physical configuration cannot be restored" },
	{ NM_NACK_TEST_NOSUCH,		"No such test" },
	{ NM_NACK_TEST_NOSTOP,		"Test cannot be stopped" },
	{ NM_NACK_MSGINCONSIST_PHYSCFG,	"Message inconsistent with physical configuration" },
	{ NM_NACK_FILE_INCOMPLETE,	"Complete file notreceived" },
	{ NM_NACK_FILE_NOTAVAIL,	"File not available at destination" },
	{ NM_NACK_FILE_NOTACTIVATE,	"File cannot be activate" },
	{ NM_NACK_REQ_NOT_GRANT,	"Request not granted" },
	{ NM_NACK_WAIT,			"Wait" },
	{ NM_NACK_NOTH_REPORT_EXIST,	"Nothing reportable existing" },
	{ NM_NACK_MEAS_NOTSUPP,		"Measurement not supported" },
	{ NM_NACK_MEAS_NOTSTART,	"Measurement not started" },
	{ 0,				NULL }
};

/*! Get human-readable string for NACK cause */
const char *abis_nm_nack_cause_name(uint8_t cause)
{
	return get_value_string(nack_cause_names, cause);
}

/* Chapter 9.4.16: Event Type */
static const struct value_string event_type_names[] = {
	{ NM_EVT_COMM_FAIL,		"communication failure" },
	{ NM_EVT_QOS_FAIL,		"quality of service failure" },
	{ NM_EVT_PROC_FAIL,		"processing failure" },
	{ NM_EVT_EQUIP_FAIL,		"equipment failure" },
	{ NM_EVT_ENV_FAIL,		"environment failure" },
	{ 0,				NULL }
};

/*! Get human-readable string for OML event type */
const char *abis_nm_event_type_name(uint8_t cause)
{
	return get_value_string(event_type_names, cause);
}

/* Chapter 9.4.63: Perceived Severity */
static const struct value_string severity_names[] = {
	{ NM_SEVER_CEASED,		"failure ceased" },
	{ NM_SEVER_CRITICAL,		"critical failure" },
	{ NM_SEVER_MAJOR,		"major failure" },
	{ NM_SEVER_MINOR,		"minor failure" },
	{ NM_SEVER_WARNING,		"warning level failure" },
	{ NM_SEVER_INDETERMINATE,	"indeterminate failure" },
	{ 0,				NULL }
};

/*! Get human-readable string for perceived OML severity */
const char *abis_nm_severity_name(uint8_t cause)
{
	return get_value_string(severity_names, cause);
}

/*! 3GPP TS 12.21 9.4.53 T200 values (in msec) */
const uint8_t abis_nm_t200_ms[] = {
	[T200_SDCCH]		= 5,
	[T200_FACCH_F]		= 5,
	[T200_FACCH_H]		= 5,
	[T200_SACCH_TCH_SAPI0]	= 10,
	[T200_SACCH_SDCCH]	= 10,
	[T200_SDCCH_SAPI3]	= 5,
	[T200_SACCH_TCH_SAPI3]	= 10
};

/*! 3GPP TS 52.021 §9.1 Message Types */
const struct value_string abis_nm_msgtype_names[] = {
	{ NM_MT_LOAD_INIT,		"Load Data Initiate" },				/* §8.3.1 */
	{ NM_MT_LOAD_INIT_ACK,		"Load Data Initiate Ack" },
	{ NM_MT_LOAD_INIT_NACK,		"Load Data Initiate Nack" },
	{ NM_MT_LOAD_SEG,		"Load Data Segment" },				/* §8.3.2 */
	{ NM_MT_LOAD_SEG_ACK,		"Load Data Segment Ack" },
	{ NM_MT_LOAD_ABORT,		"Load Data Abort" },				/* §8.3.3 */
	{ NM_MT_LOAD_END,		"Load Data End" },				/* §8.3.4 */
	{ NM_MT_LOAD_END_ACK,		"Load Data End Ack" },
	{ NM_MT_LOAD_END_NACK,		"Load Data End Nack" },
	{ NM_MT_SW_ACT_REQ,		"SW Activate Request" },			/* §8.3.5 */
	{ NM_MT_SW_ACT_REQ_ACK,		"SW Activate Request Ack" },
	{ NM_MT_SW_ACT_REQ_NACK,	"SW Activate Request Nack" },
	{ NM_MT_ACTIVATE_SW,		"Activate SW" },				/* §8.3.6 */
	{ NM_MT_ACTIVATE_SW_ACK,	"Activate SW Ack" },
	{ NM_MT_ACTIVATE_SW_NACK,	"Activate SW Nack" },
	{ NM_MT_SW_ACTIVATED_REP,	"SW Activated Report" },			/* §8.3.7 */
	{ NM_MT_ESTABLISH_TEI,		"Establish TEI" },				/* §8.4.1 */
	{ NM_MT_ESTABLISH_TEI_ACK,	"Establish TEI Ack" },
	{ NM_MT_ESTABLISH_TEI_NACK,	"Establish TEI Nack" },
	{ NM_MT_CONN_TERR_SIGN,		"Connect Terrestrial Signalling" },		/* §8.4.2 */
	{ NM_MT_CONN_TERR_SIGN_ACK,	"Connect Terrestrial Signalling Ack" },
	{ NM_MT_CONN_TERR_SIGN_NACK,	"Connect Terrestrial Signalling Nack" },
	{ NM_MT_DISC_TERR_SIGN,		"Disconnect Terrestrial Signalling" },		/* §8.4.3 */
	{ NM_MT_DISC_TERR_SIGN_ACK,	"Disconnect Terrestrial Signalling Ack" },
	{ NM_MT_DISC_TERR_SIGN_NACK,	"Disconnect Terrestrial Signalling Nack" },
	{ NM_MT_CONN_TERR_TRAF,		"Connect Terrestrial Traffic" },		/* §8.4.4 */
	{ NM_MT_CONN_TERR_TRAF_ACK,	"Connect Terrestrial Traffic Ack" },
	{ NM_MT_CONN_TERR_TRAF_NACK,	"Connect Terrestrial Traffic Nack" },
	{ NM_MT_DISC_TERR_TRAF,		"Disconnect Terrestrial Traffic" },		/* §8.4.5 */
	{ NM_MT_DISC_TERR_TRAF_ACK,	"Disconnect Terrestrial Traffic Ack" },
	{ NM_MT_DISC_TERR_TRAF_NACK,	"Disconnect Terrestrial Traffic Nack" },
	{ NM_MT_CONN_MDROP_LINK,	"Connect Multi-Drop Link" },			/* §8.5.1 */
	{ NM_MT_CONN_MDROP_LINK_ACK,	"Connect Multi-Drop Link Ack" },
	{ NM_MT_CONN_MDROP_LINK_NACK,	"Connect Multi-Drop Link Nack" },
	{ NM_MT_DISC_MDROP_LINK,	"Disconnect Multi-Drop Link" },			/* §8.5.2 */
	{ NM_MT_DISC_MDROP_LINK_ACK,	"Disconnect Multi-Drop Link Ack" },
	{ NM_MT_DISC_MDROP_LINK_NACK,	"Disconnect Multi-Drop Link Nack" },
	{ NM_MT_SET_BTS_ATTR,		"Set BTS Attributes" },				/* §8.6.1 */
	{ NM_MT_SET_BTS_ATTR_ACK,	"Set BTS Attributes Ack" },
	{ NM_MT_SET_BTS_ATTR_NACK,	"Set BTS Attributes Nack" },
	{ NM_MT_SET_RADIO_ATTR,		"Set Radio Carrier Attributes" },		/* §8.6.2 */
	{ NM_MT_SET_RADIO_ATTR_ACK,	"Set Radio Carrier Attributes Ack" },
	{ NM_MT_SET_RADIO_ATTR_NACK,	"Set Radio Carrier Attributes Nack" },
	{ NM_MT_SET_CHAN_ATTR,		"Set Channel Attributes" },			/* §8.6.3 */
	{ NM_MT_SET_CHAN_ATTR_ACK,	"Set Channel Attributes Ack" },
	{ NM_MT_SET_CHAN_ATTR_NACK,	"Set Channel Attributes Nack" },
	{ NM_MT_PERF_TEST,		"Perform Test" },				/* §8.7.1 */
	{ NM_MT_PERF_TEST_ACK,		"Perform Test Ack" },
	{ NM_MT_PERF_TEST_NACK,		"Perform Test Nack" },
	{ NM_MT_TEST_REP,		"Test Report" },				/* §8.7.2 */
	{ NM_MT_SEND_TEST_REP,		"Send Test Report" },				/* §8.7.3 */
	{ NM_MT_SEND_TEST_REP_ACK,	"Send Test Report Ack" },
	{ NM_MT_SEND_TEST_REP_NACK,	"Send Test Report Nack" },
	{ NM_MT_STOP_TEST,		"Stop Test" },					/* §8.7.4 */
	{ NM_MT_STOP_TEST_ACK,		"Stop Test Ack" },
	{ NM_MT_STOP_TEST_NACK,		"Stop Test Nack" },
	{ NM_MT_STATECHG_EVENT_REP,	"State Changed Event Report" },			/* §8.8.1 */
	{ NM_MT_FAILURE_EVENT_REP,	"Failure Event Report" },			/* §8.8.2 */
	{ NM_MT_STOP_EVENT_REP,		"Stop Sending Event Reports" },			/* §8.8.3 */
	{ NM_MT_STOP_EVENT_REP_ACK,	"Stop Sending Event Reports Ack" },
	{ NM_MT_STOP_EVENT_REP_NACK,	"Stop Sending Event Reports Nack" },
	{ NM_MT_REST_EVENT_REP,		"Restart Sending Event Reports" },		/* §8.8.4 */
	{ NM_MT_REST_EVENT_REP_ACK,	"Restart Sending Event Reports Ack" },
	{ NM_MT_REST_EVENT_REP_NACK,	"Restart Sending Event Reports Nack" },
	{ NM_MT_CHG_ADM_STATE,		"Change Administrative State" },		/* §8.8.5 */
	{ NM_MT_CHG_ADM_STATE_ACK,	"Change Administrative State Ack" },
	{ NM_MT_CHG_ADM_STATE_NACK,	"Change Administrative State Nack" },
	{ NM_MT_CHG_ADM_STATE_REQ,	"Change Administrative State Request" },	/* §8.8.6 */
	{ NM_MT_CHG_ADM_STATE_REQ_ACK,	"Change Administrative State Request Ack" },
	{ NM_MT_CHG_ADM_STATE_REQ_NACK,	"Change Administrative State Request Nack" },
	{ NM_MT_REP_OUTST_ALARMS,	"Report Outstanding Alarms" },			/* §8.8.7 */
	{ NM_MT_REP_OUTST_ALARMS_ACK,	"Report Outstanding Alarms Ack" },
	{ NM_MT_REP_OUTST_ALARMS_NACK,	"Report Outstanding Alarms Nack" },
	{ NM_MT_CHANGEOVER,		"Changeover" },					/* §8.9.1 */
	{ NM_MT_CHANGEOVER_ACK,		"Changeover Ack" },
	{ NM_MT_CHANGEOVER_NACK,	"Changeover Nack" },
	{ NM_MT_OPSTART,		"Opstart" },					/* §8.9.2 */
	{ NM_MT_OPSTART_ACK,		"Opstart Ack" },
	{ NM_MT_OPSTART_NACK,		"Opstart Nack" },
	{ NM_MT_REINIT,			"Reinitialize" },				/* §8.9.3 */
	{ NM_MT_REINIT_ACK,		"Reinitialize Ack" },
	{ NM_MT_REINIT_NACK,		"Reinitialize Nack" },
	{ NM_MT_SET_SITE_OUT,		"Set Site Outputs" },				/* §8.9.4 */
	{ NM_MT_SET_SITE_OUT_ACK,	"Set Site Outputs Ack" },
	{ NM_MT_SET_SITE_OUT_NACK,	"Set Site Outputs Nack" },
	{ NM_MT_CHG_HW_CONF,		"Change HW Configuration" },			/* §8.9.5 */
	{ NM_MT_CHG_HW_CONF_ACK,	"Change HW Configuration Ack" },
	{ NM_MT_CHG_HW_CONF_NACK,	"Change HW Configuration Nack" },
	{ NM_MT_MEAS_RES_REQ,		"Measurement Result Request" },			/* §8.10.1 */
	{ NM_MT_MEAS_RES_RESP,		"Measurement Result Response" },		/* §8.10.2 */
	{ NM_MT_STOP_MEAS,		"Stop Measurement" },				/* §8.10.4 */
	{ NM_MT_START_MEAS,		"Start Measurement" },				/* §8.10.3 */
	{ NM_MT_GET_ATTR,		"Get Attributes" },				/* §8.11.1 */
	{ NM_MT_GET_ATTR_RESP,		"Get Attributes Response" },			/* §8.11.3 */
	{ NM_MT_GET_ATTR_NACK,		"Get Attributes Nack" },
	{ NM_MT_SET_ALARM_THRES,	"Set Alarm Threshold" },			/* §8.11.2 */
	{ NM_MT_SET_ALARM_THRES_ACK,	"Set Alarm Threshold Ack" },
	{ NM_MT_SET_ALARM_THRES_NACK,	"Set Alarm Threshold Nack" },
	{ 0, NULL }
};

/*! 3GPP TS 52.021 §9.4 Attributes and Parameters */
const struct value_string abis_nm_att_names[] = {
	{ NM_ATT_ABIS_CHANNEL,		"Abis Channel" },			/* §9.4.1 */
	{ NM_ATT_ADD_INFO,		"Additional Info" },			/* §9.4.2 */
	{ NM_ATT_ADD_TEXT,		"Additional Text" },			/* §9.4.3 */
	{ NM_ATT_ADM_STATE,		"Administrative State" },		/* §9.4.4 */
	{ NM_ATT_ARFCN_LIST,		"ARFCN List" },				/* §9.4.5 */
	{ NM_ATT_AUTON_REPORT,		"Autonomously Report" },		/* §9.4.6 */
	{ NM_ATT_AVAIL_STATUS,		"Availability Status" },		/* §9.4.7 */
	{ NM_ATT_BCCH_ARFCN,		"BCCH ARFCN" },				/* §9.4.8 */
	{ NM_ATT_BSIC,			"BSIC" },				/* §9.4.9 */
	{ NM_ATT_BTS_AIR_TIMER,		"BTS Air Timer" },			/* §9.4.10 */
	{ NM_ATT_CCCH_L_I_P,		"CCCH Load Indication Period" },	/* §9.4.11 */
	{ NM_ATT_CCCH_L_T,		"CCCH Load Threshold" },		/* §9.4.12 */
	{ NM_ATT_CHAN_COMB,		"Channel Combination" },		/* §9.4.13 */
	{ NM_ATT_CONN_FAIL_CRIT,	"Connection Failure Criterion" },	/* §9.4.14 */
	{ NM_ATT_DEST,			"Destination" },			/* §9.4.15 */
	{ NM_ATT_EVENT_TYPE,		"Event Type" },				/* §9.4.16 */
	{ NM_ATT_FILE_DATA,		"File Data" },				/* §9.4.17 */
	{ NM_ATT_FILE_ID,		"File Id" },				/* §9.4.18 */
	{ NM_ATT_FILE_VERSION,		"File Version" },			/* §9.4.19 */
	{ NM_ATT_GSM_TIME,		"GSM Time" },				/* §9.4.20 */
	{ NM_ATT_HSN,			"HSN" },				/* §9.4.21 */
	{ NM_ATT_HW_CONFIG,		"HW Configuration" },			/* §9.4.22 */
	{ NM_ATT_HW_DESC,		"HW Description" },			/* §9.4.23 */
	{ NM_ATT_INTAVE_PARAM,		"Intave Parameter" },			/* §9.4.24 */
	{ NM_ATT_INTERF_BOUND,		"Interference level Boundaries" },	/* §9.4.25 */
	{ NM_ATT_LIST_REQ_ATTR,		"List of Required Attributes" },	/* §9.4.26 */
	{ NM_ATT_MAIO,			"MAIO" },				/* §9.4.27 */
	{ NM_ATT_MANUF_STATE,		"Manufacturer Dependent State" },	/* §9.4.28 */
	{ NM_ATT_MANUF_THRESH,		"Manufacturer Dependent Thresholds" },	/* §9.4.29 */
	{ NM_ATT_MANUF_ID,		"Manufacturer Id" },			/* §9.4.30 */
	{ NM_ATT_MAX_TA,		"Max Timing Advance" },			/* §9.4.31 */
	{ NM_ATT_MEAS_RES,		"Measurement Result" },			/* §9.4.32 */
	{ NM_ATT_MEAS_TYPE,		"Measurement Type" },			/* §9.4.33 */
	{ NM_ATT_MDROP_LINK,		"Multi-drop BSC Link" },		/* §9.4.34 */
	{ NM_ATT_MDROP_NEXT,		"Multi-drop next BTS Link" },		/* §9.4.35 */
	{ NM_ATT_NACK_CAUSES,		"Nack Causes" },			/* §9.4.36 */
	{ NM_ATT_NY1,			"Ny1" },				/* §9.4.37 */
	{ NM_ATT_OPER_STATE,		"Operational State" },			/* §9.4.38 */
	{ NM_ATT_OVERL_PERIOD,		"Overload Period" },			/* §9.4.39 */
	{ NM_ATT_PHYS_CONF,		"Physical Config" },			/* §9.4.40 */
	{ NM_ATT_POWER_CLASS,		"Power Class" },			/* §9.4.41 */
	{ NM_ATT_POWER_THRESH,		"Power Output Thresholds" },		/* §9.4.42 */
	{ NM_ATT_PROB_CAUSE,		"Probable Cause" },			/* §9.4.43 */
	{ NM_ATT_RACH_B_THRESH,		"RACH Busy Threshold" },		/* §9.4.44 */
	{ NM_ATT_LDAVG_SLOTS,		"RACH Load Averaging Slots" },		/* §9.4.45 */
	{ NM_ATT_RAD_SUBC,		"Radio Sub Channel" },			/* §9.4.46 */
	{ NM_ATT_RF_MAXPOWR_R,		"RF Max Power Reduction" },		/* §9.4.47 */
	{ NM_ATT_SITE_INPUTS,		"Site Inputs" },			/* §9.4.48 */
	{ NM_ATT_SITE_OUTPUTS,		"Site Outputs" },			/* §9.4.49 */
	{ NM_ATT_SOURCE,		"Source" },				/* §9.4.50 */
	{ NM_ATT_SPEC_PROB,		"Specific Problems" },			/* §9.4.51 */
	{ NM_ATT_START_TIME,		"Starting Time" },			/* §9.4.52 */
	{ NM_ATT_T200,			"T200" },				/* §9.4.53 */
	{ NM_ATT_TEI,			"TEI" },				/* §9.4.54 */
	{ NM_ATT_TEST_DUR,		"Test Duration" },			/* §9.4.55 */
	{ NM_ATT_TEST_NO,		"Test No" },				/* §9.4.56 */
	{ NM_ATT_TEST_REPORT,		"Test Report Info" },			/* §9.4.57 */
	{ NM_ATT_VSWR_THRESH,		"VSWR Thresholds" },			/* §9.4.58 */
	{ NM_ATT_WINDOW_SIZE,		"Window Size" },			/* §9.4.59 */
	{ NM_ATT_TSC,			"TSC" },				/* §9.4.60 */
	{ NM_ATT_SW_CONFIG,		"SW Configuration" },			/* §9.4.61 */
	{ NM_ATT_SW_DESCR,		"SW Description" },			/* §9.4.62 */
	{ NM_ATT_SEVERITY,		"Perceived Severity" },			/* §9.4.63 */
	{ NM_ATT_GET_ARI,		"Get Attribute Response Info" },	/* §9.4.64 */
	{ NM_ATT_OUTST_ALARM,		"Outstanding Alarm Sequence" },		/* §9.4.65 */
	{ NM_ATT_HW_CONF_CHG,		"HW Conf Change Info" },		/* §9.4.66 */
	{ 0, NULL }
};

/*! Attributes that the BSC can set, not only get, according to Section 9.4 */
const enum abis_nm_attr abis_nm_att_settable[] = {
	NM_ATT_ADD_INFO,
	NM_ATT_ADD_TEXT,
	NM_ATT_DEST,
	NM_ATT_EVENT_TYPE,
	NM_ATT_FILE_DATA,
	NM_ATT_GET_ARI,
	NM_ATT_HW_CONF_CHG,
	NM_ATT_LIST_REQ_ATTR,
	NM_ATT_MDROP_LINK,
	NM_ATT_MDROP_NEXT,
	NM_ATT_NACK_CAUSES,
	NM_ATT_OUTST_ALARM,
	NM_ATT_PHYS_CONF,
	NM_ATT_PROB_CAUSE,
	NM_ATT_RAD_SUBC,
	NM_ATT_SOURCE,
	NM_ATT_SPEC_PROB,
	NM_ATT_START_TIME,
	NM_ATT_TEST_DUR,
	NM_ATT_TEST_NO,
	NM_ATT_TEST_REPORT,
	NM_ATT_WINDOW_SIZE,
	NM_ATT_SEVERITY,
	NM_ATT_MEAS_RES,
	NM_ATT_MEAS_TYPE,
};

/*! GSM A-bis OML IPA TLV parser definition */
const struct tlv_definition abis_nm_att_tlvdef_ipa = {
	.def = {
		/* ip.access specifics */
		[NM_ATT_IPACC_DST_IP] =		{ TLV_TYPE_FIXED, 4 },
		[NM_ATT_IPACC_DST_IP_PORT] =	{ TLV_TYPE_FIXED, 2 },
		[NM_ATT_IPACC_STREAM_ID] =	{ TLV_TYPE_TV, },
		[NM_ATT_IPACC_SEC_OML_CFG] =	{ TLV_TYPE_FIXED, 6 },
		[NM_ATT_IPACC_IP_IF_CFG] =	{ TLV_TYPE_FIXED, 8 },
		[NM_ATT_IPACC_IP_GW_CFG] =	{ TLV_TYPE_FIXED, 12 },
		[NM_ATT_IPACC_IN_SERV_TIME] =	{ TLV_TYPE_FIXED, 4 },
		[NM_ATT_IPACC_LOCATION] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_PAGING_CFG] =	{ TLV_TYPE_FIXED, 2 },
		[NM_ATT_IPACC_UNIT_ID] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_UNIT_NAME] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_SNMP_CFG] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_PRIM_OML_CFG_LIST] = { TLV_TYPE_TL16V },
		[NM_ATT_IPACC_NV_FLAGS] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_FREQ_CTRL] =	{ TLV_TYPE_FIXED, 2 },
		[NM_ATT_IPACC_PRIM_OML_FB_TOUT] = { TLV_TYPE_TL16V },
		[NM_ATT_IPACC_CUR_SW_CFG] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_TIMING_BUS] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_CGI] =		{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_RAC] =		{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_OBJ_VERSION] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_GPRS_PAGING_CFG]= { TLV_TYPE_TL16V },
		[NM_ATT_IPACC_NSEI] =		{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_BVCI] =		{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_NSVCI] =		{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_NS_CFG] =		{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_BSSGP_CFG] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_NS_LINK_CFG] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_RLC_CFG] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_ALM_THRESH_LIST]=	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_MONIT_VAL_LIST] = { TLV_TYPE_TL16V },
		[NM_ATT_IPACC_TIB_CONTROL] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_SUPP_FEATURES] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_CODING_SCHEMES] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_RLC_CFG_2] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_HEARTB_TOUT] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_UPTIME] =		{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_RLC_CFG_3] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_SSL_CFG] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_SEC_POSSIBLE] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_IML_SSL_STATE] =	{ TLV_TYPE_TL16V },
		[NM_ATT_IPACC_REVOC_DATE] =	{ TLV_TYPE_TL16V },
	},
};

/*! GSM A-bis OML TLV parser definition */
const struct tlv_definition abis_nm_att_tlvdef = {
	.def = {
		[NM_ATT_ABIS_CHANNEL] =		{ TLV_TYPE_FIXED, 3 },
		[NM_ATT_ADD_INFO] =		{ TLV_TYPE_TL16V },
		[NM_ATT_ADD_TEXT] =		{ TLV_TYPE_TL16V },
		[NM_ATT_ADM_STATE] =		{ TLV_TYPE_TV },
		[NM_ATT_ARFCN_LIST]=		{ TLV_TYPE_TL16V },
		[NM_ATT_AUTON_REPORT] =		{ TLV_TYPE_TV },
		[NM_ATT_AVAIL_STATUS] =		{ TLV_TYPE_TL16V },
		[NM_ATT_BCCH_ARFCN] =		{ TLV_TYPE_FIXED, 2 },
		[NM_ATT_BSIC] =			{ TLV_TYPE_TV },
		[NM_ATT_BTS_AIR_TIMER] =	{ TLV_TYPE_TV },
		[NM_ATT_CCCH_L_I_P] =		{ TLV_TYPE_TV },
		[NM_ATT_CCCH_L_T] =		{ TLV_TYPE_TV },
		[NM_ATT_CHAN_COMB] =		{ TLV_TYPE_TV },
		[NM_ATT_CONN_FAIL_CRIT] =	{ TLV_TYPE_TL16V },
		[NM_ATT_DEST] =			{ TLV_TYPE_TL16V },
		[NM_ATT_EVENT_TYPE] =		{ TLV_TYPE_TV },
		[NM_ATT_FILE_DATA] =		{ TLV_TYPE_TL16V },
		[NM_ATT_FILE_ID] =		{ TLV_TYPE_TL16V },
		[NM_ATT_FILE_VERSION] =		{ TLV_TYPE_TL16V },
		[NM_ATT_GSM_TIME] =		{ TLV_TYPE_FIXED, 2 },
		[NM_ATT_HSN] =			{ TLV_TYPE_TV },
		[NM_ATT_HW_CONFIG] =		{ TLV_TYPE_TL16V },
		[NM_ATT_HW_DESC] =		{ TLV_TYPE_TL16V },
		[NM_ATT_INTAVE_PARAM] =		{ TLV_TYPE_TV },
		[NM_ATT_INTERF_BOUND] =		{ TLV_TYPE_FIXED, 6 },
		[NM_ATT_LIST_REQ_ATTR] =	{ TLV_TYPE_TL16V },
		[NM_ATT_MAIO] =			{ TLV_TYPE_TV },
		[NM_ATT_MANUF_STATE] =		{ TLV_TYPE_TV },
		[NM_ATT_MANUF_THRESH] =		{ TLV_TYPE_TL16V },
		[NM_ATT_MANUF_ID] =		{ TLV_TYPE_TL16V },
		[NM_ATT_MAX_TA] =		{ TLV_TYPE_TV },
		[NM_ATT_MDROP_LINK] =		{ TLV_TYPE_FIXED, 2 },
		[NM_ATT_MDROP_NEXT] =		{ TLV_TYPE_FIXED, 2 },
		[NM_ATT_NACK_CAUSES] =		{ TLV_TYPE_TV },
		[NM_ATT_NY1] =			{ TLV_TYPE_TV },
		[NM_ATT_OPER_STATE] =		{ TLV_TYPE_TV },
		[NM_ATT_OVERL_PERIOD] =		{ TLV_TYPE_TL16V },
		[NM_ATT_PHYS_CONF] =		{ TLV_TYPE_TL16V },
		[NM_ATT_POWER_CLASS] =		{ TLV_TYPE_TV },
		[NM_ATT_POWER_THRESH] =		{ TLV_TYPE_FIXED, 3 },
		[NM_ATT_PROB_CAUSE] =		{ TLV_TYPE_FIXED, 3 },
		[NM_ATT_RACH_B_THRESH] =	{ TLV_TYPE_TV },
		[NM_ATT_LDAVG_SLOTS] =		{ TLV_TYPE_FIXED, 2 },
		[NM_ATT_RAD_SUBC] =		{ TLV_TYPE_TV },
		[NM_ATT_RF_MAXPOWR_R] =		{ TLV_TYPE_TV },
		[NM_ATT_SITE_INPUTS] =		{ TLV_TYPE_TL16V },
		[NM_ATT_SITE_OUTPUTS] =		{ TLV_TYPE_TL16V },
		[NM_ATT_SOURCE] =		{ TLV_TYPE_TL16V },
		[NM_ATT_SPEC_PROB] =		{ TLV_TYPE_TV },
		[NM_ATT_START_TIME] =		{ TLV_TYPE_FIXED, 2 },
		[NM_ATT_T200] =			{ TLV_TYPE_FIXED, 7 },
		[NM_ATT_TEI] =			{ TLV_TYPE_TV },
		[NM_ATT_TEST_DUR] =		{ TLV_TYPE_FIXED, 2 },
		[NM_ATT_TEST_NO] =		{ TLV_TYPE_TV },
		[NM_ATT_TEST_REPORT] =		{ TLV_TYPE_TL16V },
		[NM_ATT_VSWR_THRESH] =		{ TLV_TYPE_FIXED, 2 },
		[NM_ATT_WINDOW_SIZE] = 		{ TLV_TYPE_TV },
		[NM_ATT_TSC] =			{ TLV_TYPE_TV },
		[NM_ATT_SW_CONFIG] =		{ TLV_TYPE_TL16V },
		[NM_ATT_SEVERITY] = 		{ TLV_TYPE_TV },
		[NM_ATT_GET_ARI] =		{ TLV_TYPE_TL16V },
		[NM_ATT_HW_CONF_CHG] = 		{ TLV_TYPE_TL16V },
		[NM_ATT_OUTST_ALARM] =		{ TLV_TYPE_TV },
		[NM_ATT_MEAS_RES] =		{ TLV_TYPE_TL16V },
		[NM_ATT_MEAS_TYPE] = 		{ TLV_TYPE_TV },
	},
};

/*! org.osmocom GSM A-bis OML TLV parser definition */
const struct tlv_definition abis_nm_osmo_att_tlvdef = {
	.def = {
		[NM_ATT_OSMO_NS_LINK_CFG] =	{ TLV_TYPE_TL16V },
		[NM_ATT_OSMO_REDUCEPOWER] =	{ TLV_TYPE_TV },
	},
};

/*! Human-readable strings for A-bis OML Object Class */
const struct value_string abis_nm_msg_disc_names[] = {
	{ ABIS_OM_MDISC_FOM,	"FOM" },
	{ ABIS_OM_MDISC_MMI,	"MMI" },
	{ ABIS_OM_MDISC_TRAU,	"TRAU" },
	{ ABIS_OM_MDISC_MANUF,	"MANUF" },
	{ 0, NULL }
};

/*! Human-readable strings for A-bis OML Object Class */
const struct value_string abis_nm_obj_class_names[] = {
	{ NM_OC_SITE_MANAGER,	"SITE-MANAGER" },
	{ NM_OC_BTS,		"BTS" },
	{ NM_OC_RADIO_CARRIER,	"RADIO-CARRIER" },
	{ NM_OC_BASEB_TRANSC,	"BASEBAND-TRANSCEIVER" },
	{ NM_OC_CHANNEL,	"CHANNEL" },
	{ NM_OC_IPAC_E1_TRUNK,	"IPAC-E1-TRUNK" },
	{ NM_OC_IPAC_E1_PORT,	"IPAC-E1-PORT" },
	{ NM_OC_IPAC_E1_CHAN,	"IPAC-E1-CHAN" },
	{ NM_OC_IPAC_CLK_MODULE,"IPAC-CLK-MODULE" },
	{ NM_OC_BS11_ADJC,	"ADJC" },
	{ NM_OC_BS11_HANDOVER,	"HANDOVER" },
	{ NM_OC_BS11_PWR_CTRL,	"POWER-CONTROL" },
	{ NM_OC_BS11_BTSE,	"BTSE" },
	{ NM_OC_BS11_RACK,	"RACK" },
	{ NM_OC_BS11_TEST,	"TEST" },
	{ NM_OC_BS11_ENVABTSE,	"ENVABTSE" },
	{ NM_OC_BS11_BPORT,	"BPORT" },
	{ NM_OC_GPRS_NSE,	"GPRS-NSE" },
	{ NM_OC_GPRS_CELL,	"GPRS-CELL" },
	{ NM_OC_GPRS_NSVC,	"GPRS-NSVC" },
	{ NM_OC_BS11,		"SIEMENSHW" },
	{ 0,			NULL }
};

/*! Get human-readable string for OML Operational State */
const char *abis_nm_opstate_name(uint8_t os)
{
	switch (os) {
	case NM_OPSTATE_DISABLED:
		return "Disabled";
	case NM_OPSTATE_ENABLED:
		return "Enabled";
	case NM_OPSTATE_NULL:
		return "NULL";
	default:
		return "RFU";
	}
}

/* Chapter 9.4.7 */
static const struct value_string avail_names[] = {
	{ 0, 	"In test" },
	{ 1,	"Failed" },
	{ 2,	"Power off" },
	{ 3,	"Off line" },
	/* Not used */
	{ 5,	"Dependency" },
	{ 6,	"Degraded" },
	{ 7,	"Not installed" },
	{ 0xff, "OK" },
	{ 0,	NULL }
};

/*! Get human-readable string for OML Availability State */
const char *abis_nm_avail_name(uint8_t avail)
{
	return get_value_string(avail_names, avail);
}

static const struct value_string test_names[] = {
	/* FIXME: standard test names */
	{ NM_IPACC_TESTNO_CHAN_USAGE, "Channel Usage" },
	{ NM_IPACC_TESTNO_BCCH_CHAN_USAGE, "BCCH Channel Usage" },
	{ NM_IPACC_TESTNO_FREQ_SYNC, "Frequency Synchronization" },
	{ NM_IPACC_TESTNO_BCCH_INFO, "BCCH Info" },
	{ NM_IPACC_TESTNO_TX_BEACON, "Transmit Beacon" },
	{ NM_IPACC_TESTNO_SYSINFO_MONITOR, "System Info Monitor" },
	{ NM_IPACC_TESTNO_BCCCH_MONITOR, "BCCH Monitor" },
	{ 0, NULL }
};

/*! Get human-readable string for OML test */
const char *abis_nm_test_name(uint8_t test)
{
	return get_value_string(test_names, test);
}

/*! Human-readable names for OML administrative state */
const struct value_string abis_nm_adm_state_names[] = {
	{ NM_STATE_LOCKED,	"Locked" },
	{ NM_STATE_UNLOCKED,	"Unlocked" },
	{ NM_STATE_SHUTDOWN,	"Shutdown" },
	{ NM_STATE_NULL,	"NULL" },
	{ 0, NULL }
};

static const enum abis_nm_chan_comb chcomb4pchan[] = {
	[GSM_PCHAN_NONE]	= 0xff,
	[GSM_PCHAN_CCCH]	= NM_CHANC_mainBCCH,
	[GSM_PCHAN_CCCH_SDCCH4]	= NM_CHANC_BCCHComb,
	[GSM_PCHAN_TCH_F]	= NM_CHANC_TCHFull,
	[GSM_PCHAN_TCH_H]	= NM_CHANC_TCHHalf,
	[GSM_PCHAN_SDCCH8_SACCH8C] = NM_CHANC_SDCCH,
	[GSM_PCHAN_PDCH]	= NM_CHANC_IPAC_PDCH,
	[GSM_PCHAN_TCH_F_PDCH]	= NM_CHANC_IPAC_TCHFull_PDCH,
	[GSM_PCHAN_UNKNOWN]	= 0xff,
	[GSM_PCHAN_CCCH_SDCCH4_CBCH]	= NM_CHANC_BCCH_CBCH,
	[GSM_PCHAN_SDCCH8_SACCH8C_CBCH] = NM_CHANC_SDCCH_CBCH,
	[GSM_PCHAN_OSMO_DYN]	= NM_CHANC_OSMO_DYN,
	/* FIXME: bounds check */
};

/*! Pack 3GPP TS 12.21 § 8.8.2 Failure Event Report into msgb */
struct msgb *abis_nm_fail_evt_rep(enum abis_nm_event_type t,
				  enum abis_nm_severity s,
				  enum abis_nm_pcause_type ct,
				  uint16_t cause_value, const char *fmt, ...)
{
	va_list ap;
	struct msgb *nmsg;

	va_start(ap, fmt);
	nmsg = abis_nm_fail_evt_vrep(t, s, ct, cause_value, fmt, ap);
	va_end(ap);

	return nmsg;
}

/*! Pack 3GPP TS 12.21 § 8.8.2 Failure Event Report into msgb */
struct msgb *abis_nm_fail_evt_vrep(enum abis_nm_event_type t,
				   enum abis_nm_severity s,
				   enum abis_nm_pcause_type ct,
				   uint16_t cause_value, const char *fmt,
				   va_list ap)
{
	uint8_t cause[3];
	int len;
	char add_text[ABIS_NM_MSG_HEADROOM];
	struct msgb *nmsg = msgb_alloc_headroom(ABIS_NM_MSG_SIZE,
						ABIS_NM_MSG_HEADROOM,
						"OML FAIL EV. REP.");
	if (!nmsg)
		return NULL;

	msgb_tv_put(nmsg, NM_ATT_EVENT_TYPE, t);
	msgb_tv_put(nmsg, NM_ATT_SEVERITY, s);

	cause[0] = ct;
	osmo_store16be(cause_value, cause + 1);

	msgb_tv_fixed_put(nmsg, NM_ATT_PROB_CAUSE, 3, cause);

	len = vsnprintf(add_text, ABIS_NM_MSG_HEADROOM, fmt, ap);
	if (len < 0) {
		msgb_free(nmsg);
		return NULL;
	}
	if (len)
		msgb_tl16v_put(nmsg, NM_ATT_ADD_TEXT, len, (const uint8_t *) add_text);

	return nmsg;
}

/*! Compute length of given 3GPP TS 52.021 §9.4.62 SW Description.
 *  \param[in] sw SW Description struct
 *  \param[in] put_sw_descr boolean, whether to put NM_ATT_SW_DESCR IE or not
 *  \returns length of buffer space necessary to store sw
 */
uint16_t abis_nm_sw_desc_len(const struct abis_nm_sw_desc *sw, bool put_sw_desc)
{
	/* +3: type is 1-byte, length is 2-byte */
	return (put_sw_desc ? 1 : 0) + (sw->file_id_len + 3) + (sw->file_version_len + 3);
}

/*! Put given 3GPP TS 52.021 §9.4.62 SW Description into msgb.
 *  \param[out] msg message buffer
 *  \param[in] sw SW Description struct
 *  \param[in] put_sw_descr boolean, whether to put NM_ATT_SW_DESCR IE or not
 *  \returns length of buffer space necessary to store sw
 */
uint16_t abis_nm_put_sw_desc(struct msgb *msg, const struct abis_nm_sw_desc *sw, bool put_sw_desc)
{
	if (put_sw_desc)
		msgb_v_put(msg, NM_ATT_SW_DESCR);

	msgb_tl16v_put(msg, NM_ATT_FILE_ID, sw->file_id_len, sw->file_id);
	msgb_tl16v_put(msg, NM_ATT_FILE_VERSION, sw->file_version_len, sw->file_version);

	return abis_nm_sw_desc_len(sw, put_sw_desc);
}

/*! Put given file ID/Version pair as 3GPP TS 52.021 §9.4.62 SW Description into msgb.
 *  \param[out] msg message buffer
 *  \param[in] id File ID part of SW Description
 *  \param[in] id File Version part of SW Description
 *  \param[in] put_sw_descr boolean, whether to put NM_ATT_SW_DESCR IE or not
 *  \returns length of buffer space necessary to store sw
 */
uint16_t abis_nm_put_sw_file(struct msgb *msg, const char *id, const char *ver, bool put_sw_desc)
{
	struct abis_nm_sw_desc sw = {
		.file_id_len = strlen(id),
		.file_version_len = strlen(ver),
	};

	memcpy(sw.file_id, id, sw.file_id_len);
	memcpy(sw.file_version, ver, sw.file_version_len);

	return abis_nm_put_sw_desc(msg, &sw, put_sw_desc);
}

/*! Get length of first 3GPP TS 52.021 §9.4.62 SW Description from buffer.
 *  \param[in] buf buffer, may contain several SW Descriptions
 *  \param[in] len buffer length
 *  \returns length if parsing succeeded, 0 otherwise
 */
uint32_t abis_nm_get_sw_desc_len(const uint8_t *buf, size_t len)
{
	uint16_t sw = 2; /* 1-byte SW tag + 1-byte FILE_* tag */

	if (buf[0] != NM_ATT_SW_DESCR)
		sw = 1; /* 1-byte FILE_* tag */

	if (buf[sw - 1] != NM_ATT_FILE_ID && buf[sw - 1] != NM_ATT_FILE_VERSION)
		return 0;

	/* + length of 1st FILE_* element + 1-byte tag + 2-byte length field of
	   1st FILE_* element */
	sw += (osmo_load16be(buf + sw) + 3);

	/* + length of 2nd FILE_* element */
	sw += osmo_load16be(buf + sw);

	return sw + 2; /* +  2-byte length field of 2nd FILE_* element */
}

/*! Parse single 3GPP TS 52.021 §9.4.62 SW Description from buffer.
 *  \param[out] sw SW Description struct
 *  \param[in] buf buffer
 *  \param[in] len buffer length
 *  \returns 0 if parsing succeeded, negative error code otherwise
 */
static inline int abis_nm_get_sw_desc(struct abis_nm_sw_desc *sw, const uint8_t *buf, size_t length)
{
	int rc;
	uint32_t len = abis_nm_get_sw_desc_len(buf, length);
	static struct tlv_parsed tp;
	const struct tlv_definition sw_tlvdef = {
		.def = {
			[NM_ATT_SW_DESCR] =		{ TLV_TYPE_TV },
			[NM_ATT_FILE_ID] =		{ TLV_TYPE_TL16V },
			[NM_ATT_FILE_VERSION] =		{ TLV_TYPE_TL16V },
		},
	};

	/* Basic sanity check */
	if (len > length)
		return -EFBIG;

	/* Note: current implementation of TLV parser fails on multilpe SW Descr:
	   we will only parse the first one */
	if (!len)
		return -EINVAL;

	/* Note: the return value is ignored here because SW Description tag
	   itself is considered optional. */
	tlv_parse(&tp, &sw_tlvdef, buf, len, 0, 0);

	/* Parsing SW Description is tricky for current implementation of TLV
	   parser which fails to properly handle TV when V has following
	   structure: | TL16V | TL16V |. Hence, the need for 2nd call: */
	rc = tlv_parse(&tp, &sw_tlvdef, buf + TLVP_LEN(&tp, NM_ATT_SW_DESCR), len - TLVP_LEN(&tp, NM_ATT_SW_DESCR),
		       0, 0);

	if (rc < 0)
		return rc;

	if (!TLVP_PRESENT(&tp, NM_ATT_FILE_ID))
		return -EBADF;

	if (!TLVP_PRESENT(&tp, NM_ATT_FILE_VERSION))
		return -EBADMSG;

	sw->file_id_len = TLVP_LEN(&tp, NM_ATT_FILE_ID);
	sw->file_version_len = TLVP_LEN(&tp, NM_ATT_FILE_VERSION);

	memcpy(sw->file_id, TLVP_VAL(&tp, NM_ATT_FILE_ID), sw->file_id_len);
	memcpy(sw->file_version, TLVP_VAL(&tp, NM_ATT_FILE_VERSION), sw->file_version_len);

	return 0;
}

/*! Parse 3GPP TS 52.021 §9.4.61 SW Configuration from buffer.
 *  \param[in] buf buffer
 *  \param[in] buf_len buffer length
 *  \param[out] sw SW Description struct array
 *  \param[in] sw_len Expected number of SW Description entries
 *  \returns Number fo parsed SW-Description entries, negative error code otherwise
 */
int abis_nm_get_sw_conf(const uint8_t * buf, size_t buf_len, struct abis_nm_sw_desc *sw, uint16_t sw_len)
{
	int rc;
	uint16_t len = 0, i;
	for (i = 0; i < sw_len; i++) {
		memset(&sw[i], 0, sizeof(sw[i]));
		rc = abis_nm_get_sw_desc(&sw[i], buf + len, buf_len - len);
		if (rc < 0)
			return rc;

		len += abis_nm_get_sw_desc_len(buf + len, buf_len - len);

		if (len >= buf_len)
			return i + 1;
	}

	return i;
}

/*! Obtain OML Channel Combination for phnsical channel config */
int abis_nm_chcomb4pchan(enum gsm_phys_chan_config pchan)
{
	if (pchan < ARRAY_SIZE(chcomb4pchan))
		return chcomb4pchan[pchan];

	return -EINVAL;
}

/*! Obtain physical channel config for OML Channel Combination */
enum gsm_phys_chan_config abis_nm_pchan4chcomb(uint8_t chcomb)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(chcomb4pchan); i++) {
		if (chcomb4pchan[i] == chcomb)
			return i;
	}
	return GSM_PCHAN_NONE;
}

char *abis_nm_dump_foh_buf(char *buf, size_t buf_len, const struct abis_om_fom_hdr *foh)
{
	snprintf(buf, buf_len, "OC=%s(%02x) INST=(%02x,%02x,%02x)",
		get_value_string(abis_nm_obj_class_names, foh->obj_class),
		foh->obj_class, foh->obj_inst.bts_nr, foh->obj_inst.trx_nr,
		foh->obj_inst.ts_nr);
	return buf;
}

const char *abis_nm_dump_foh(const struct abis_om_fom_hdr *foh)
{
	static __thread char foh_buf[128];
	return abis_nm_dump_foh_buf(foh_buf, sizeof(foh_buf), foh);
}

char *abis_nm_dump_foh_c(void *ctx, const struct abis_om_fom_hdr *foh)
{
	size_t len = 15 /* format */ + 22 /* obj_class_name */+ 4*3 /* uint8 */ + 1 /*nul*/;
	char *buf = talloc_size(ctx, len);
	if (!buf)
		return NULL;
	return abis_nm_dump_foh_buf(buf, len, foh);
}

/* this is just for compatibility reasons, it is now a macro */
#undef abis_nm_debugp_foh
OSMO_DEPRECATED("Use abis_nm_debugp_foh macro instead")
void abis_nm_debugp_foh(int ss, struct abis_om_fom_hdr *foh)
{
	DEBUGP(ss, "%s ", abis_nm_dump_foh(foh));
}

/*! @} */
