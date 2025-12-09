/*
 * This header file captures the set of fixed RTP payload type definitions
 * specified in 3GPP TS 48.103 (GSM AoIP interface) Table 5.4.2.2.1.
 */

#pragma once

/* uncompressed speech */
#define	OSMO_AOIP_RTP_PT_PCMU		0
#define	OSMO_AOIP_RTP_PT_PCMA		8

/* compressed speech */
#define	OSMO_AOIP_RTP_PT_FR1		3
#define	OSMO_AOIP_RTP_PT_EFR		110
#define	OSMO_AOIP_RTP_PT_HR1		111
#define	OSMO_AOIP_RTP_PT_AMR		112
#define	OSMO_AOIP_RTP_PT_AMRWB		113

/* circuit-switched data */
#define	OSMO_AOIP_RTP_PT_CSD		120	/* without redundancy */
#define	OSMO_AOIP_RTP_PT_CSD_RED	121	/* with    redundancy */

/* Osmocom and Themyscira extensions */
#define	OSMO_AOIP_RTP_PT_TWTS007	127	/* compressed form of CSD */
