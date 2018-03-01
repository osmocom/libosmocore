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
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301, USA.
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
	{ 0, NULL }
};

/*! return string representation of a BTS feature */
const char *osmo_bts_feature_name(enum osmo_bts_features feature)
{
	return get_value_string(osmo_bts_features_descs, feature);
}
