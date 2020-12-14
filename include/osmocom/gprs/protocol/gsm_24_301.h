/*! \file gsm_24_301.h */

#pragma once

/*! Tracking area TS 24.301, section 9.9.3.32 */
struct osmo_eutran_tai {
	uint16_t mcc;
	uint16_t mnc;
	bool mnc_3_digits;
	uint16_t tac;
};
