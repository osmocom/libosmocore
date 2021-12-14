/*! \defgroup bsslap 3GPP TS 48.071 BSS LCS Assistance Protocol (BSSLAP).
 *  @{
 *  \file gsm_48_071.h
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
 */
#pragma once

#include <osmocom/gsm/protocol/gsm_04_08.h>

enum bsslap_msgt {
	BSSLAP_MSGT_TA_REQUEST = 0x1,
	BSSLAP_MSGT_TA_RESPONSE = 0x2,
	BSSLAP_MSGT_REJECT = 0xa,
	BSSLAP_MSGT_RESET = 0xb,
	BSSLAP_MSGT_ABORT = 0xc,
	BSSLAP_MSGT_TA_LAYER3 = 0xd,
	BSSLAP_MSGT_MS_POS_CMD = 0xf,
	BSSLAP_MSGT_MS_POS_RESP = 0x10,
	BSSLAP_MSGT_UTDOA_REQ = 0x11,
	BSSLAP_MSGT_UTDOA_RESP = 0x12,
};

enum bsslap_cause {
	BSSLAP_CAUSE_CONGESTION = 0x0,
	BSSLAP_CAUSE_CHAN_MODE_NOT_SUPP = 0x1,
	BSSLAP_CAUSE_POS_PROC_NOT_SUPP = 0x2,
	BSSLAP_CAUSE_OTHER_RADIO_EVT_FAIL = 0x3,
	BSSLAP_CAUSE_INTRA_BSS_HO = 0x4,
	BSSLAP_CAUSE_SUPERV_TIMER_EXPIRED = 0x5,
	BSSLAP_CAUSE_INTER_BSS_HO = 0x6,
	BSSLAP_CAUSE_LOSS_SIG_CONN_MS = 0x7,
	BSSLAP_CAUSE_INCORR_SERV_CELL_ID = 0x8,
	BSSLAP_CAUSE_BSSAP_LE_SEGMENT_ERR = 0x9,
	BSSLAP_CAUSE_CONCUR_POS_PROC_NOT_EN = 0xa,
};

enum bsslap_iei {
	BSSLAP_IEI_TA = 0x1,
	BSSLAP_IEI_CELL_ID = 0x9,
	BSSLAP_IEI_CHAN_DESC = 0x10,
	BSSLAP_IEI_MEAS_REP = 0x14,
	BSSLAP_IEI_CAUSE = 0x18,
	BSSLAP_IEI_RRLP_FLAG = 0x19,
	BSSLAP_IEI_RRLP = 0x1b,
	BSSLAP_IEI_CELL_ID_LIST = 0x1c,
	BSSLAP_IEI_ENH_MEAS_REP = 0x1d,
	BSSLAP_IEI_LAC = 0x1e,
	BSSLAP_IEI_FREQ_LIST = 0x21,
	BSSLAP_IEI_MS_POWER = 0x22,
	BSSLAP_IEI_DELTA_TIMER = 0x23,
	BSSLAP_IEI_SERVING_CELL_ID = 0x24,
	BSSLAP_IEI_ENCR_KEY = 0x25,
	BSSLAP_IEI_CIPH_MODE_SET = 0x26,
	BSSLAP_IEI_CHAN_MODE = 0x27,
	BSSLAP_IEI_MR_CONFIG = 0x28,
	BSSLAP_IEI_POLLING_REPETITION = 0x29,
	BSSLAP_IEI_PACKET_CHAN_DESC = 0x2a,
	BSSLAP_IEI_TLLI = 0x2b,
	BSSLAP_IEI_TFI = 0x2c,
	BSSLAP_IEI_TBF_START_TIME = 0x2d,
	BSSLAP_IEI_PWRUP_START_TIME = 0x2e,
	BSSLAP_IEI_LONG_ENCR_KEY = 0x2f,
	BSSLAP_IEI_CONCUR_POS_PROC_F = 0x30,
};

struct bsslap_ta_response {
	uint16_t cell_id;
	uint8_t ta;

	bool more_items; /*!< always set this to false */
};

struct bsslap_ta_layer3 {
	uint8_t ta;

	bool more_items; /*!< always set this to false */
};

struct bsslap_reset {
	uint16_t cell_id;
	uint8_t ta;
	struct gsm48_chan_desc chan_desc;
	enum bsslap_cause cause;

	bool more_items; /*!< always set this to false */
};

struct bsslap_pdu {
	enum bsslap_msgt msg_type;
	union {
		/* ta_request: a TA Request message consists only of the message type. */
		struct bsslap_ta_response ta_response;
		enum bsslap_cause reject;
		struct bsslap_reset reset;
		enum bsslap_cause abort;
		struct bsslap_ta_layer3 ta_layer3;
	};
};

/*! @} */
