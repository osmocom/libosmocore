/*! \file gsm_03_40.h
 * GSM TS 03.40. */

#pragma once

/* SM-TP-UD (User-Data) field may contain up to 140 octets
 * (or 140 * 8 / 7 = 160 septets). See section 9.2.3.24. */
#define GSM340_UDL_OCT_MAX 140  /*!< Maximum TP-UD length (in octets) for 7-bit encoding */
#define GSM340_UDL_SPT_MAX 160  /*!< Maximum TP-UD length (in seplets) for 8-bit and UCS-2 encoding */

/**
 * 9.1.2.5 Type Of Number
 */
enum {
	GSM340_TYPE_UNKNOWN		= 0,
	GSM340_TYPE_INTERNATIONAL	= 1,
	GSM340_TYPE_NATIONAL		= 2,
	GSM340_TYPE_NETWORK		= 3,
	GSM340_TYPE_SUBSCRIBER		= 4,
	GSM340_TYPE_ALPHA_NUMERIC	= 5,
	GSM340_TYPE_ABBREVIATED		= 6,
	GSM340_TYPE_RESERVED		= 7,
};

/**
 * 9.1.2.5 Type of Numbering plan.
 * Applies for numbering plans (Unknown, International, National)
 */
enum {
	GSM340_PLAN_UNKNOWN		= 0,
	GSM340_PLAN_ISDN		= 1,
	GSM340_PLAN_DATA		= 3,
	GSM340_PLAN_TELEX		= 4,
	GSM340_PLAN_NATIONAL		= 8,
	GSM340_PLAN_PRIVATE		= 9,
	GSM340_PLAN_ERMES		= 10,
	GSM340_PLAN_RESERVED		= 15,
};
