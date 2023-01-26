/*! \file gsm48.h */

#pragma once

#include <stdbool.h>

#include <osmocom/core/defs.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
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
const char *gsm48_rr_short_pd_msg_name(uint8_t msgtype);
const char *rr_cause_name(uint8_t cause);
const char *osmo_rai_name(const struct gprs_ra_id *rai);
char *osmo_rai_name_buf(char *buf, size_t buf_len, const struct gprs_ra_id *rai);
char *osmo_rai_name_c(const void *ctx, const struct gprs_ra_id *rai);

int gsm48_decode_lai(struct gsm48_loc_area_id *lai, uint16_t *mcc,
		     uint16_t *mnc, uint16_t *lac)
	OSMO_DEPRECATED("Use gsm48_decode_lai2() instead, to not lose leading zeros in the MNC");
void gsm48_decode_lai2(const struct gsm48_loc_area_id *lai, struct osmo_location_area_id *decoded);
void gsm48_generate_lai(struct gsm48_loc_area_id *lai48, uint16_t mcc,
			uint16_t mnc, uint16_t lac)
	OSMO_DEPRECATED("Use gsm48_generate_lai2() instead, to not lose leading zeros in the MNC");
void gsm48_generate_lai2(struct gsm48_loc_area_id *lai48, const struct osmo_location_area_id *lai);

#define GSM48_MID_MAX_SIZE	11
int gsm48_generate_mid_from_tmsi(uint8_t *buf, uint32_t tmsi)
	OSMO_DEPRECATED_OUTSIDE("Instead use: l = msgb_tl_put(msg, GSM48_IE_MOBILE_ID);"
				" *l = osmo_mobile_identity_encode_msgb(...)");
int gsm48_generate_mid_from_imsi(uint8_t *buf, const char *imsi)
	OSMO_DEPRECATED_OUTSIDE("Instead use: l = msgb_tl_put(msg, GSM48_IE_MOBILE_ID);"
				" *l = osmo_mobile_identity_encode_msgb(...)");
uint8_t gsm48_generate_mid(uint8_t *buf, const char *id, uint8_t mi_type)
	OSMO_DEPRECATED_OUTSIDE("Instead use: l = msgb_tl_put(msg, GSM48_IE_MOBILE_ID);"
				" *l = osmo_mobile_identity_encode_msgb(...)");

const char *gsm48_mi_type_name(uint8_t mi);
/* Convert encoded Mobile Identity (10.5.1.4) to string */
int gsm48_mi_to_string(char *string, int str_len, const uint8_t *mi, int mi_len)
	OSMO_DEPRECATED_OUTSIDE("Instead use osmo_mobile_identity_decode()");
const char *osmo_mi_name(const uint8_t *mi, uint8_t mi_len)
	OSMO_DEPRECATED_OUTSIDE("Instead use osmo_mobile_identity_to_str_c()");
char *osmo_mi_name_buf(char *buf, size_t buf_len, const uint8_t *mi, uint8_t mi_len)
	OSMO_DEPRECATED_OUTSIDE("Instead use osmo_mobile_identity_to_str_buf()");
char *osmo_mi_name_c(const void *ctx, const uint8_t *mi, uint8_t mi_len)
	OSMO_DEPRECATED_OUTSIDE("Instead use osmo_mobile_identity_to_str_c()");

/*! Decoded representation of a Mobile Identity (3GPP TS 24.008 10.5.1.4).
 * See osmo_mobile_identity_decode() and osmo_mobile_identity_from_l3(). */
struct osmo_mobile_identity {
	/*! A GSM_MI_TYPE_* constant (like GSM_MI_TYPE_IMSI). */
	uint8_t type;
	/*! Decoded Mobile Identity digits or TMSI value. IMSI, IMEI and IMEISV as digits like
	 * "12345678", and TMSI is represented as raw uint32_t. */
	union {
		/*! type == GSM_MI_TYPE_IMSI. */
		char imsi[GSM23003_IMSI_MAX_DIGITS + 1];
		/*! type == GSM_MI_TYPE_IMEI. */
		char imei[GSM23003_IMEI_NUM_DIGITS + 1];
		/*! type == GSM_MI_TYPE_IMEISV. */
		char imeisv[GSM23003_IMEISV_NUM_DIGITS + 1];
		/*! TMSI / P-TMSI / M-TMSI integer value if type == GSM_MI_TYPE_TMSI. */
		uint32_t tmsi;
	};
};

int osmo_mobile_identity_to_str_buf(char *buf, size_t buflen, const struct osmo_mobile_identity *mi);
char *osmo_mobile_identity_to_str_c(void *ctx, const struct osmo_mobile_identity *mi);
int osmo_mobile_identity_cmp(const struct osmo_mobile_identity *a, const struct osmo_mobile_identity *b);
int osmo_mobile_identity_decode(struct osmo_mobile_identity *mi, const uint8_t *mi_data, uint8_t mi_len,
				bool allow_hex);
int osmo_mobile_identity_decode_from_l3(struct osmo_mobile_identity *mi, struct msgb *msg, bool allow_hex);
int osmo_mobile_identity_encoded_len(const struct osmo_mobile_identity *mi, int *mi_digits);
int osmo_mobile_identity_encode_buf(uint8_t *buf, size_t buflen, const struct osmo_mobile_identity *mi, bool allow_hex);
int osmo_mobile_identity_encode_msgb(struct msgb *msg, const struct osmo_mobile_identity *mi, bool allow_hex);

/* Parse Routeing Area Identifier */
void gsm48_parse_ra(struct gprs_ra_id *raid, const uint8_t *buf);
void gsm48_encode_ra(struct gsm48_ra_id *out, const struct gprs_ra_id *raid);
int gsm48_construct_ra(uint8_t *buf, const struct gprs_ra_id *raid) OSMO_DEPRECATED("Use gsm48_encode_ra() instead");
bool gsm48_ra_equal(const struct gprs_ra_id *raid1, const struct gprs_ra_id *raid2);

int gsm48_number_of_paging_subchannels(const struct gsm48_control_channel_descr *chan_desc);

void gsm48_mcc_mnc_to_bcd(uint8_t *bcd_dst, uint16_t mcc, uint16_t mnc)
	OSMO_DEPRECATED("Use osmo_plmn_to_bcd() instead, to not lose leading zeros in the MNC");
void gsm48_mcc_mnc_from_bcd(uint8_t *bcd_src, uint16_t *mcc, uint16_t *mnc)
	OSMO_DEPRECATED("Use osmo_plmn_from_bcd() instead, to not lose leading zeros in the MNC");

struct gsm48_hdr *gsm48_push_l3hdr(struct msgb *msg,
				   uint8_t pdisc, uint8_t msg_type);

#define gsm48_push_l3hdr_tid(msg, pdisc, tid, msg_type) \
	gsm48_push_l3hdr(msg, (pdisc & 0x0f) | (tid << 4), msg_type)

enum gsm48_chan_mode gsm48_chan_mode_to_vamos(enum gsm48_chan_mode mode);
enum gsm48_chan_mode gsm48_chan_mode_to_non_vamos(enum gsm48_chan_mode mode);
