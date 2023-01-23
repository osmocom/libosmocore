/*! \file bts_features.c
 * osmo-bts features. */
/*
 * (C) 2018 by sysmocom s.f.m.c. GmbH
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#include <osmocom/gsm/bts_features.h>

const struct value_string osmo_bts_features_descs[] = {
	{ BTS_FEAT_HSCSD,		"HSCSD" },
	{ BTS_FEAT_GPRS,		"GPRS" },
	{ BTS_FEAT_EGPRS,		"EGPRS" },
	{ BTS_FEAT_ECSD,		"ECSD" },
	{ BTS_FEAT_HOPPING,		"Frequency Hopping" },
	{ BTS_FEAT_MULTI_TSC,		"Multi-TSC" },
	{ BTS_FEAT_OML_ALERTS,		"OML Alerts" },
	{ BTS_FEAT_AGCH_PCH_PROP,	"AGCH/PCH proportional allocation" },
	{ BTS_FEAT_CBCH,		"CBCH" },
	{ BTS_FEAT_SPEECH_F_V1,		"Fullrate speech V1" },
	{ BTS_FEAT_SPEECH_H_V1,		"Halfrate speech V1" },
	{ BTS_FEAT_SPEECH_F_EFR,	"Fullrate speech EFR" },
	{ BTS_FEAT_SPEECH_F_AMR,	"Fullrate speech AMR" },
	{ BTS_FEAT_SPEECH_H_AMR,	"Halfrate speech AMR" },
	{ BTS_FEAT_ETWS_PN,		"ETWS Primary Notification via PCH" },
	{ BTS_FEAT_PAGING_COORDINATION,	"BSS Paging Coordination" },
	{ BTS_FEAT_IPV6_NSVC,		"NSVC IPv6" },
	{ BTS_FEAT_ACCH_REP,		"FACCH/SACCH Repetition" },
	{ BTS_FEAT_CCN,			"Cell Change Notification (CCN)" },
	{ BTS_FEAT_VAMOS,		"VAMOS (Voice services over Adaptive Multi-user channels on One Slot)" },
	{ BTS_FEAT_ABIS_OSMO_PCU,	"OsmoPCU over OML link IPA multiplex" },
	{ BTS_FEAT_BCCH_POWER_RED,	"BCCH carrier power reduction mode" },
	{ BTS_FEAT_DYN_TS_SDCCH8,	"Dynamic Timeslot configuration as SDCCH8" },
	{ BTS_FEAT_ACCH_TEMP_OVP,	"FACCH/SACCH Temporary overpower" },
	{ BTS_FEAT_OSMUX,		"Osmux (Osmocom RTP multiplexing)" },
	{ BTS_FEAT_VBS,			"Voice Broadcast Service" },
	{ BTS_FEAT_VGCS,		"Voice Group Call Service" },
	{ 0, NULL }
};

/*! return description string of a BTS feature (osmo_bts_features_descs).
 * To get the plain feature name, use osmo_bts_features_name() instead. */
const char *osmo_bts_feature_name(enum osmo_bts_features feature)
{
	return get_value_string(osmo_bts_features_descs, feature);
}

const struct value_string osmo_bts_features_names[] = {
	{ BTS_FEAT_HSCSD, "HSCSD" },
	{ BTS_FEAT_GPRS, "GPRS" },
	{ BTS_FEAT_EGPRS, "EGPRS" },
	{ BTS_FEAT_ECSD, "ECSD" },
	{ BTS_FEAT_HOPPING, "HOPPING" },
	{ BTS_FEAT_MULTI_TSC, "MULTI_TSC" },
	{ BTS_FEAT_OML_ALERTS, "OML_ALERTS" },
	{ BTS_FEAT_AGCH_PCH_PROP, "AGCH_PCH_PROP" },
	{ BTS_FEAT_CBCH, "CBCH" },
	{ BTS_FEAT_SPEECH_F_V1, "SPEECH_F_V1" },
	{ BTS_FEAT_SPEECH_H_V1, "SPEECH_H_V1" },
	{ BTS_FEAT_SPEECH_F_EFR, "SPEECH_F_EFR" },
	{ BTS_FEAT_SPEECH_F_AMR, "SPEECH_F_AMR" },
	{ BTS_FEAT_SPEECH_H_AMR, "SPEECH_H_AMR" },
	{ BTS_FEAT_ETWS_PN, "ETWS_PN" },
	{ BTS_FEAT_PAGING_COORDINATION, "PAGING_COORDINATION" },
	{ BTS_FEAT_IPV6_NSVC, "IPV6_NSVC" },
	{ BTS_FEAT_ACCH_REP, "ACCH_REP" },
	{ BTS_FEAT_CCN, "CCN" },
	{ BTS_FEAT_VAMOS, "VAMOS" },
	{ BTS_FEAT_ABIS_OSMO_PCU, "ABIS_OSMO_PCU" },
	{ BTS_FEAT_BCCH_POWER_RED, "BCCH_PWR_RED" },
	{ BTS_FEAT_DYN_TS_SDCCH8, "DYN_TS_SDCCH8" },
	{ BTS_FEAT_ACCH_TEMP_OVP, "ACCH_TEMP_OVP" },
	{ BTS_FEAT_OSMUX, "OSMUX" },
	{}
};
