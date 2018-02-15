/*! \file gsm23003.h */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/* 23.003 Chapter 12.1 */
struct osmo_plmn_id {
	uint16_t mcc;
	uint16_t mnc;
	bool mnc_3_digits; /*< ignored and implied true if mnc > 99, otherwise defines leading zeros. */
};

/* 4.1 */
struct osmo_location_area_id {
	struct osmo_plmn_id plmn;
	uint16_t lac;
};

/* 4.2 */
struct osmo_routing_area_id {
	struct osmo_location_area_id lac;
	uint8_t rac;
};

/* 4.3.1 */
struct osmo_cell_global_id {
	struct osmo_location_area_id lai;
	uint16_t cell_identity;
};

/* Actually defined in 3GPP TS 48.008 3.2.2.27 Cell Identifier List,
 * but conceptually belongs with the above structures. */
struct osmo_lac_and_ci_id {
	uint16_t lac;
	uint16_t ci;
};

/* 12.5 */
struct osmo_service_area_id {
	struct osmo_location_area_id lai;
	uint16_t sac;
};

/* 12.6 */
struct osmo_shared_network_area_id {
	struct osmo_plmn_id plmn;
	uint32_t snac;
};

/* 5.1 */
enum osmo_gsn_addr_type {
	GSN_ADDR_TYPE_IPV4	= 0,
	GSN_ADDR_TYPE_IPV6	= 1,
};

/* 5.1 */
struct osmo_gsn_address {
	enum osmo_gsn_addr_type type;
	uint8_t length;
	uint8_t addr[16];
};

/* 19.4.2.3 */
struct osmo_tracking_area_id {
	struct osmo_plmn_id plmn;
	uint16_t tac;
};

struct osmo_eutran_cell_global_id {
	struct osmo_plmn_id plmn;
	uint32_t eci; /* FIXME */
};

/* 2.8.1 */
struct osmo_mme_id {
	uint16_t group_id;
	uint8_t code;
};

/* 2.8.1 */
struct osmo_gummei {
	struct osmo_plmn_id plmn;
	struct osmo_mme_id mme;
};

/* 2.8.1 */
struct osmo_guti {
	struct osmo_gummei gummei;
	uint32_t mtmsi;
};

bool osmo_imsi_str_valid(const char *imsi);
bool osmo_msisdn_str_valid(const char *msisdn);

const char *osmo_mcc_name(uint16_t mcc);
const char *osmo_mnc_name(uint16_t mnc, bool mnc_3_digits);
const char *osmo_plmn_name(const struct osmo_plmn_id *plmn);
const char *osmo_plmn_name2(const struct osmo_plmn_id *plmn);
const char *osmo_lai_name(const struct osmo_location_area_id *lai);

void osmo_plmn_to_bcd(uint8_t *bcd_dst, const struct osmo_plmn_id *plmn);
void osmo_plmn_from_bcd(const uint8_t *bcd_src, struct osmo_plmn_id *plmn);

int osmo_mnc_from_str(const char *mnc_str, uint16_t *mnc, bool *mnc_3_digits);

/* Convert string to MCC.
 * \param mcc_str[in]	String representation of an MCC, with or without leading zeros.
 * \param mcc[out]	MCC result buffer, or NULL.
 * \returns zero on success, -EINVAL in case of surplus characters, negative errno in case of conversion
 *          errors. In case of error, do not modify the out-arguments.
 */
static inline int osmo_mcc_from_str(const char *mcc_str, uint16_t *mcc)
{
	return osmo_mnc_from_str(mcc_str, mcc, NULL);
}

int osmo_mnc_cmp(uint16_t a_mnc, bool a_mnc_3_digits, uint16_t b_mnc, bool b_mnc_3_digits);
int osmo_plmn_cmp(const struct osmo_plmn_id *a, const struct osmo_plmn_id *b);
