/*! \file gsm48.h */

#pragma once

#include <stdbool.h>

#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/gsm23003.h>

/* reserved according to GSM 03.03 § 2.4 */
#define GSM_RESERVED_TMSI   0xFFFFFFFF

/* Valid MCC and MNC range from 0 to 999.
 * To mark an invalid / unset MNC, this value shall be used. */
#define GSM_MCC_MNC_INVALID 0xFFFF

/* A parsed GPRS routing area */
struct gprs_ra_id {
	uint16_t	mcc;
	uint16_t	mnc;
	bool		mnc_3_digits;
	uint16_t	lac;
	uint8_t		rac;
};

extern const struct tlv_definition gsm48_att_tlvdef;
extern const struct tlv_definition gsm48_rr_att_tlvdef;
extern const struct tlv_definition gsm48_mm_att_tlvdef;
const char *gsm48_cc_state_name(uint8_t state);
const char *gsm48_cc_msg_name(uint8_t msgtype);
const char *gsm48_rr_msg_name(uint8_t msgtype);
const char *rr_cause_name(uint8_t cause);
const char *osmo_rai_name(const struct gprs_ra_id *rai);

int gsm48_decode_lai(struct gsm48_loc_area_id *lai, uint16_t *mcc,
		     uint16_t *mnc, uint16_t *lac)
	OSMO_DEPRECATED("Use gsm48_decode_lai2() instead, to not lose leading zeros in the MNC");
void gsm48_decode_lai2(const struct gsm48_loc_area_id *lai, struct osmo_location_area_id *decoded);
void gsm48_generate_lai(struct gsm48_loc_area_id *lai48, uint16_t mcc,
			uint16_t mnc, uint16_t lac)
	OSMO_DEPRECATED("Use gsm48_generate_lai2() instead, to not lose leading zeros in the MNC");
void gsm48_generate_lai2(struct gsm48_loc_area_id *lai48, const struct osmo_location_area_id *lai);

int gsm48_generate_mid_from_tmsi(uint8_t *buf, uint32_t tmsi);
int gsm48_generate_mid_from_imsi(uint8_t *buf, const char *imsi);
uint8_t gsm48_generate_mid(uint8_t *buf, const char *id, uint8_t mi_type);

/* Convert Mobile Identity (10.5.1.4) to string */
int gsm48_mi_to_string(char *string, const int str_len,
			const uint8_t *mi, const int mi_len);
const char *gsm48_mi_type_name(uint8_t mi);

/* Parse Routeing Area Identifier */
void gsm48_parse_ra(struct gprs_ra_id *raid, const uint8_t *buf);
void gsm48_encode_ra(struct gsm48_ra_id *out, const struct gprs_ra_id *raid);
int gsm48_construct_ra(uint8_t *buf, const struct gprs_ra_id *raid) OSMO_DEPRECATED("Use gsm48_encode_ra() instead");

int gsm48_number_of_paging_subchannels(struct gsm48_control_channel_descr *chan_desc);

void gsm48_mcc_mnc_to_bcd(uint8_t *bcd_dst, uint16_t mcc, uint16_t mnc)
	OSMO_DEPRECATED("Use osmo_plmn_to_bcd() instead, to not lose leading zeros in the MNC");
void gsm48_mcc_mnc_from_bcd(uint8_t *bcd_src, uint16_t *mcc, uint16_t *mnc)
	OSMO_DEPRECATED("Use osmo_plmn_from_bcd() instead, to not lose leading zeros in the MNC");
