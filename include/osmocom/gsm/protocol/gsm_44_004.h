#pragma once

#include <osmocom/core/endian.h>

/* TS 44.004 Section 7.1 */

struct gsm_sacch_l1_hdr {
#if OSMO_IS_LITTLE_ENDIAN
		uint8_t	ms_pwr:5,
			fpc_epc:1,
			srr_sro:1,
			reserved:1;
		uint8_t ta;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
		uint8_t	reserved:1, srr_sro:1, fpc_epc:1, ms_pwr:5;
		uint8_t ta;
#endif
} __attribute__ ((packed));
