/*! \defgroup bssmap_le 3GPP TS 49.031 BSSMAP-LE.
 *  @{
 *  \file gsm_49_031.h
 */
/*
 * (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

/*! 3GPP TS 49.031 10.13 LCS Cause, also in 3GPP TS 48.008 3.2.2.66, which simply refers to the former. */
enum lcs_cause {
	LCS_CAUSE_UNSPECIFIED = 0,
	LCS_CAUSE_SYSTEM_FAILURE = 1,
	LCS_CAUSE_PROTOCOL_ERROR = 2,
	LCS_CAUSE_DATA_MISSING_IN_REQ = 3,
	LCS_CAUSE_UNEXP_DATA_IN_REQ = 4,
	LCS_CAUSE_POS_METH_FAILURE = 5,
	LCS_CAUSE_TGT_MS_UNREACHABLE = 6,
	LCS_CAUSE_REQUEST_ABORTED = 7,
	LCS_CAUSE_FACILITY_NOTSUPP = 8,
	LCS_CAUSE_INTER_BSC_HO = 9,
	LCS_CAUSE_INTRA_BSC_HO = 10,
	LCS_CAUSE_CONGESTION = 11,
	LCS_CAUSE_INTER_NSE_CHG = 12,
	LCS_CAUSE_RA_UPDAT = 13,
	LCS_CAUSE_PTMSI_REALLOC = 14,
	LCS_CAUSE_GPRS_SUSPENSION = 15,
};

/*! 3GPP TS 49.031 10.13 LCS Cause, also in 3GPP TS 48.008 3.2.2.66, which simply refers to the former. */
struct lcs_cause_ie {
	bool present;
	enum lcs_cause cause_val;
	bool diag_val_present;
	uint8_t diag_val;
};

/*! @} */
