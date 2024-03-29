/*! \file gsm_04_11.h */

#pragma once

#include <stdint.h>

/* GSM TS 04.11  definitions */

/* Chapter 5.2.3: SMC-CS states at the user/network side */
enum gsm411_cp_state {
	GSM411_CPS_IDLE 		= 0,
	GSM411_CPS_MM_CONN_PENDING	= 1,	/* only MT ! */
	GSM411_CPS_WAIT_CP_ACK		= 2,
	GSM411_CPS_MM_ESTABLISHED	= 3,
};

/* Chapter 6.2.2: SMR states at the user/network side */
enum gsm411_rp_state {
	GSM411_RPS_IDLE			= 0,
	GSM411_RPS_WAIT_FOR_RP_ACK	= 1,
	GSM411_RPS_WAIT_TO_TX_RP_ACK	= 3,
	GSM411_RPS_WAIT_FOR_RETRANS_T	= 4,
};

/* Chapter 8.1.2 (refers to GSM 04.07 Chapter 11.2.3.1.1 */
#define GSM411_PDISC_SMS	0x09

/* Chapter 8.1.3 */
#define GSM411_MT_CP_DATA	0x01
#define GSM411_MT_CP_ACK	0x04
#define GSM411_MT_CP_ERROR	0x10

enum gsm411_cp_ie {
	GSM411_CP_IE_USER_DATA		= 0x01,	/* 8.1.4.1 */
	GSM411_CP_IE_CAUSE		= 0x02,	/* 8.1.4.2. */
};

/* Section 8.1.4.2 / Table 8.2 */
enum gsm411_cp_cause {
	GSM411_CP_CAUSE_NET_FAIL	= 17,
	GSM411_CP_CAUSE_CONGESTION	= 22,
	GSM411_CP_CAUSE_INV_TRANS_ID	= 81,
	GSM411_CP_CAUSE_SEMANT_INC_MSG	= 95,
	GSM411_CP_CAUSE_INV_MAND_INF	= 96,
	GSM411_CP_CAUSE_MSGTYPE_NOTEXIST= 97,
	GSM411_CP_CAUSE_MSG_INCOMP_STATE= 98,
	GSM411_CP_CAUSE_IE_NOTEXIST	= 99,
	GSM411_CP_CAUSE_PROTOCOL_ERR	= 111,
};

/* Chapter 8.2.2 */
#define GSM411_MT_RP_DATA_MO	0x00
#define GSM411_MT_RP_DATA_MT	0x01
#define GSM411_MT_RP_ACK_MO	0x02
#define GSM411_MT_RP_ACK_MT	0x03
#define GSM411_MT_RP_ERROR_MO	0x04
#define GSM411_MT_RP_ERROR_MT	0x05
#define GSM411_MT_RP_SMMA_MO	0x06

enum gsm411_rp_ie {
	GSM411_IE_RP_USER_DATA		= 0x41,	/* 8.2.5.3 */
	GSM411_IE_RP_CAUSE		= 0x42,	/* 8.2.5.4 */
};

/* Sections 8.2.5.1 and 8.2.5.2 set limits on the length of an SMSC-address.
 * The spec states these limits in terms of min and max values of the length
 * octet in type 4 IEs SM-RP-OA and SM-RP-DA; these IE length limits translate
 * into a minimum of 1 digit and a maximum of 20 digits.
 */
#define GSM411_SMSC_ADDR_MIN_OCTETS	2
#define GSM411_SMSC_ADDR_MAX_OCTETS	11
#define GSM411_SMSC_ADDR_MIN_DIGITS	1
#define GSM411_SMSC_ADDR_MAX_DIGITS	20

/* Chapter 8.2.5.4 Table 8.4 */
enum gsm411_rp_cause {
	/* valid only for MO */
	GSM411_RP_CAUSE_MO_NUM_UNASSIGNED	= 1,
	GSM411_RP_CAUSE_MO_OP_DET_BARR		= 8,
	GSM411_RP_CAUSE_MO_CALL_BARRED		= 10,
	GSM411_RP_CAUSE_MO_SMS_REJECTED		= 21,
	GSM411_RP_CAUSE_MO_DEST_OUT_OF_ORDER	= 27,
	GSM411_RP_CAUSE_MO_UNIDENTIFIED_SUBSCR	= 28,
	GSM411_RP_CAUSE_MO_FACILITY_REJ		= 29,
	GSM411_RP_CAUSE_MO_UNKNOWN_SUBSCR	= 30,
	GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER	= 38,
	GSM411_RP_CAUSE_MO_TEMP_FAIL		= 41,
	GSM411_RP_CAUSE_MO_CONGESTION		= 42,
	GSM411_RP_CAUSE_MO_RES_UNAVAIL		= 47,
	GSM411_RP_CAUSE_MO_REQ_FAC_NOTSUBSCR	= 50,
	GSM411_RP_CAUSE_MO_REQ_FAC_NOTIMPL	= 69,
	GSM411_RP_CAUSE_MO_INTERWORKING		= 127,
	/* valid only for MT */
	GSM411_RP_CAUSE_MT_MEM_EXCEEDED		= 22,
	/* valid for both directions */
	GSM411_RP_CAUSE_INV_TRANS_REF		= 81,
	GSM411_RP_CAUSE_SEMANT_INC_MSG		= 95,
	GSM411_RP_CAUSE_INV_MAND_INF		= 96,
	GSM411_RP_CAUSE_MSGTYPE_NOTEXIST	= 97,
	GSM411_RP_CAUSE_MSG_INCOMP_STATE	= 98,
	GSM411_RP_CAUSE_IE_NOTEXIST		= 99,
	GSM411_RP_CAUSE_PROTOCOL_ERR		= 111,
};

/* Chapter 10: Timers */
#define GSM411_TMR_TR1M		40, 0	/* 35 < x < 45 seconds */
#define GSM411_TMR_TRAM		30, 0	/* 25 < x < 35 seconds */
#define GSM411_TMR_TR2M		15, 0	/* 12 < x < 20 seconds */

#define GSM411_TMR_TC1A		30, 0	/* TR1M - 10 */
#define GSM411_TMR_TC1A_SEC	30	/* TR1M - 10 */

/* Chapter 8.2.1 */
struct gsm411_rp_hdr {
	uint8_t len;
	uint8_t msg_type;
	uint8_t msg_ref;
	uint8_t data[0];
} __attribute__ ((packed));

/* our own enum, not related to on-air protocol */
enum sms_alphabet {
	DCS_NONE,
	DCS_7BIT_DEFAULT,
	DCS_UCS2,
	DCS_8BIT_DATA,
};

/* GSM 03.40 / Chapter 9.2.3.1: TP-Message-Type-Indicator */
#define GSM340_SMS_DELIVER_SC2MS	0x00
#define GSM340_SMS_DELIVER_REP_MS2SC	0x00
#define GSM340_SMS_STATUS_REP_SC2MS	0x02
#define GSM340_SMS_COMMAND_MS2SC	0x02
#define GSM340_SMS_SUBMIT_MS2SC		0x01
#define GSM340_SMS_SUBMIT_REP_SC2MS	0x01
#define GSM340_SMS_RESERVED		0x03

/* GSM 03.40 / Chapter 9.2.3.2: TP-More-Messages-to-Send */
#define GSM340_TP_MMS_MORE		0
#define GSM340_TP_MMS_NO_MORE		1

/* GSM 03.40 / Chapter 9.2.3.3: TP-Validity-Period-Format */
#define GSM340_TP_VPF_NONE		0
#define GSM340_TP_VPF_RELATIVE		2
#define GSM340_TP_VPF_ENHANCED		1
#define GSM340_TP_VPF_ABSOLUTE		3

/* GSM 03.40 / Chapter 9.2.3.4: TP-Status-Report-Indication */
#define GSM340_TP_SRI_NONE		0
#define GSM340_TP_SRI_PRESENT		1

/* GSM 03.40 / Chapter 9.2.3.5: TP-Status-Report-Request */
#define GSM340_TP_SRR_NONE		0
#define GSM340_TP_SRR_REQUESTED		1

/* GSM 03.40 / Chapter 9.2.3.9: TP-Protocol-Identifier */
/* telematic interworking (001 or 111 in bits 7-5) */
#define GSM340_TP_PID_IMPLICIT		0x00
#define GSM340_TP_PID_TELEX		0x01
#define GSM340_TP_PID_FAX_G3		0x02
#define GSM340_TP_PID_FAX_G4		0x03
#define GSM340_TP_PID_VOICE		0x04
#define GSM430_TP_PID_ERMES		0x05
#define GSM430_TP_PID_NATIONAL_PAGING	0x06
#define GSM430_TP_PID_VIDEOTEX		0x07
#define GSM430_TP_PID_TELETEX_UNSPEC	0x08
#define GSM430_TP_PID_TELETEX_PSPDN	0x09
#define GSM430_TP_PID_TELETEX_CSPDN	0x0a
#define GSM430_TP_PID_TELETEX_PSTN	0x0b
#define GSM430_TP_PID_TELETEX_ISDN	0x0c
#define GSM430_TP_PID_TELETEX_UCI	0x0d
#define GSM430_TP_PID_MSG_HANDLING	0x10
#define GSM430_TP_PID_MSG_X400		0x11
#define GSM430_TP_PID_EMAIL		0x12
#define GSM430_TP_PID_GSM_MS		0x1f
/* if bit 7 = 0 and bit 6 = 1 */
#define GSM430_TP_PID_SMS_TYPE_0	0
#define GSM430_TP_PID_SMS_TYPE_1	1
#define GSM430_TP_PID_SMS_TYPE_2	2
#define GSM430_TP_PID_SMS_TYPE_3	3
#define GSM430_TP_PID_SMS_TYPE_4	4
#define GSM430_TP_PID_SMS_TYPE_5	5
#define GSM430_TP_PID_SMS_TYPE_6	6
#define GSM430_TP_PID_SMS_TYPE_7	7
#define GSM430_TP_PID_RETURN_CALL_MSG	0x1f
#define GSM430_TP_PID_ME_DATA_DNLOAD	0x3d
#define GSM430_TP_PID_ME_DE_PERSONAL	0x3e
#define GSM430_TP_PID_ME_SIM_DNLOAD	0x3f

/* GSM 03.38 Chapter 4: SMS Data Coding Scheme */
#define GSM338_DCS_00_

#define GSM338_DCS_1110_7BIT		(0 << 2)
#define GSM338_DCS_1111_7BIT		(0 << 2)
#define GSM338_DCS_1111_8BIT_DATA	(1 << 2)
#define GSM338_DCS_1111_CLASS0		0
#define GSM338_DCS_1111_CLASS1_ME	1
#define GSM338_DCS_1111_CLASS2_SIM	2
#define GSM338_DCS_1111_CLASS3_TE	3	/* See TS 07.05 */
