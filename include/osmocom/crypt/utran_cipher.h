/*! \file utran_cipher.h */

#pragma once

/* 3GPP TS 25.413 § 9.2.1.11 */
enum osmo_utran_integrity_algo {
	OSMO_UTRAN_UIA1 = 0,
	OSMO_UTRAN_UIA2 = 1,
	_OSMO_UTRAN_UIA_NUM
};

/* 3GPP TS 25.413 § 9.2.1.12 */
enum osmo_utran_encryption_algo {
	OSMO_UTRAN_UEA0 = 0,
	OSMO_UTRAN_UEA1 = 1,
	OSMO_UTRAN_UEA2 = 2,
	_OSMO_UTRAN_UEA_NUM
};

