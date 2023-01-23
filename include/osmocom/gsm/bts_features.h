#pragma once

#include <osmocom/core/utils.h>
#include <osmocom/core/bitvec.h>

#define MAX_BTS_FEATURES 128

/* N. B: always add new features to the end of the list (right before _NUM_BTS_FEAT) to avoid breaking compatibility
   with BTS compiled against earlier version of this header. Also make sure that the description strings
   osmo_bts_features_descs[] in gsm_data.c are also updated accordingly! */
enum osmo_bts_features {
	BTS_FEAT_HSCSD,
	BTS_FEAT_GPRS,
	BTS_FEAT_EGPRS,
	BTS_FEAT_ECSD,
	BTS_FEAT_HOPPING,
	BTS_FEAT_MULTI_TSC,
	BTS_FEAT_OML_ALERTS,
	BTS_FEAT_AGCH_PCH_PROP,
	BTS_FEAT_CBCH,
	BTS_FEAT_SPEECH_F_V1,
	BTS_FEAT_SPEECH_H_V1,
	BTS_FEAT_SPEECH_F_EFR,
	BTS_FEAT_SPEECH_F_AMR,
	BTS_FEAT_SPEECH_H_AMR,
	BTS_FEAT_ETWS_PN,
	BTS_FEAT_PAGING_COORDINATION,	/* BTS hands CS paging to PCU/PACCH */
	BTS_FEAT_IPV6_NSVC,
	BTS_FEAT_ACCH_REP,
	BTS_FEAT_CCN, /* Is CCN supported by the cell? TS 44.060 sec 8.8.2 */
	BTS_FEAT_VAMOS, /* Is the BTS VAMOS capable? */
	BTS_FEAT_ABIS_OSMO_PCU, /* BTS supports forwarding data to PCUIF over IPA OML multiplex */
	BTS_FEAT_BCCH_POWER_RED,
	BTS_FEAT_DYN_TS_SDCCH8, /* Osmo Dynamic TS supports configured as SDCCH8 */
	BTS_FEAT_ACCH_TEMP_OVP, /* FACCH/SACCH Temporary overpower */
	BTS_FEAT_OSMUX, /* Osmux (Osmocom RTP muxing) support */
	BTS_FEAT_VBS, /* Voice Broadcast Service support, 3GPP TS 43.069 */
	BTS_FEAT_VGCS, /* Voice Group Call Service support, 3GPP TS 44.068 */
	_NUM_BTS_FEAT
};

extern const struct value_string osmo_bts_features_descs[];

static inline const char *osmo_bts_features_desc(enum osmo_bts_features val)
{ return get_value_string(osmo_bts_features_descs, val); }

const char *osmo_bts_feature_name(enum osmo_bts_features feature)
	OSMO_DEPRECATED("Use osmo_bts_features_desc() instead");

extern const struct value_string osmo_bts_features_names[];

static inline const char *osmo_bts_features_name(enum osmo_bts_features val)
{ return get_value_string(osmo_bts_features_names, val); }

static inline int osmo_bts_set_feature(struct bitvec *features, enum osmo_bts_features feature)
{
	OSMO_ASSERT(_NUM_BTS_FEAT < MAX_BTS_FEATURES);
	return bitvec_set_bit_pos(features, feature, 1);
}

static inline int osmo_bts_unset_feature(struct bitvec *features, enum osmo_bts_features feature)
{
	OSMO_ASSERT(_NUM_BTS_FEAT < MAX_BTS_FEATURES);
	return bitvec_set_bit_pos(features, feature, 0);
}

static inline bool osmo_bts_has_feature(const struct bitvec *features, enum osmo_bts_features feature)
{
	OSMO_ASSERT(_NUM_BTS_FEAT < MAX_BTS_FEATURES);
	return bitvec_get_bit_pos(features, feature) == ONE;
}
