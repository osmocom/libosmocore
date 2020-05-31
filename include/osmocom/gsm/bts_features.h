#pragma once

#include <osmocom/core/utils.h>
#include <osmocom/core/bitvec.h>

#define MAX_BTS_FEATURES 128

/* N. B: always add new features to the end of the list (right before _NUM_BTS_FEAT) to avoid breaking compatibility
   with BTS compiled against earlier version of this header. Also make sure that the description strings
   gsm_bts_features_descs[] in gsm_data.c are also updated accordingly! */
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
	_NUM_BTS_FEAT
};

extern const struct value_string osmo_bts_features_descs[];

const char *osmo_bts_feature_name(enum osmo_bts_features feature);

static inline int osmo_bts_set_feature(struct bitvec *features, enum osmo_bts_features feature)
{
	OSMO_ASSERT(_NUM_BTS_FEAT < MAX_BTS_FEATURES);
	return bitvec_set_bit_pos(features, feature, 1);
}

static inline bool osmo_bts_has_feature(const struct bitvec *features, enum osmo_bts_features feature)
{
	OSMO_ASSERT(_NUM_BTS_FEAT < MAX_BTS_FEATURES);
	return bitvec_get_bit_pos(features, feature) == ONE;
}
