#pragma once

#include <stdbool.h>
#include <osmocom/gsm/sysinfo.h>
#include <osmocom/gprs/protocol/gsm_04_60.h>

/* 16 is the max. number of SI2quater messages according to 3GPP TS 44.018 Table 10.5.2.33b.1:
   4-bit index is used (2#1111 = 10#15) */
#define SI2Q_MAX_NUM 16
/* length in bits (for single SI2quater message) */
#define SI2Q_MAX_LEN 160
#define SI2Q_MIN_LEN 18

/* generate SI1 rest octets */
int osmo_gsm48_rest_octets_si1_encode(uint8_t *data, uint8_t *nch_pos, int is1800_net);
int osmo_gsm48_rest_octets_si2quater_encode(uint8_t *data, uint8_t si2q_index, uint8_t si2q_count,
					    const uint16_t *uarfcn_list, size_t *u_offset,
					    size_t uarfcn_length, uint16_t *scramble_list,
					    struct osmo_earfcn_si2q *si2quater_neigh_list,
					    size_t *e_offset);

struct osmo_gsm48_si_pch_nch_info {
	bool present;
	bool paging_channel_restructuring;
	uint8_t nln_sacch;
	bool call_priority_present;
	uint8_t call_priority;
	bool nln_status_sacch;
};

struct osmo_gsm48_si_vbs_vgcs_options {
	bool present;
	bool inband_notifications;
	bool inband_pagings;
};

struct osmo_gsm48_si_dtm_support {
	bool present;
	uint8_t rac;
	uint8_t max_lapdm;
};

struct osmo_gsm48_si_gprs_ms_txpwr_max_ccch {
	bool present;
	uint8_t max_txpwr;
};

struct osmo_gsm48_si6_ro_info {
	struct osmo_gsm48_si_pch_nch_info pch_nch_info;
	struct osmo_gsm48_si_vbs_vgcs_options vbs_vgcs_options;
	struct osmo_gsm48_si_dtm_support dtm_support;
	bool band_indicator_1900;
	struct osmo_gsm48_si_gprs_ms_txpwr_max_ccch gprs_ms_txpwr_max_ccch;
	/* MBMS: not supported in Osmocom */
	/* AMR config (group channel): not supported in Osmocom */
};

int osmo_gsm48_rest_octets_si6_encode(uint8_t *data, const struct osmo_gsm48_si6_ro_info *in);

struct osmo_gsm48_si_selection_params {
	uint16_t penalty_time:5,
		  temp_offs:3,
		  cell_resel_off:6,
		  cbq:1,
		  present:1;
};

struct osmo_gsm48_si_power_offset {
	uint8_t power_offset:2,
		 present:1;
};

struct osmo_gsm48_si3_gprs_ind {
	uint8_t si13_position:1,
		 ra_colour:3,
		 present:1;
};

struct osmo_gsm48_lsa_params {
	uint32_t prio_thr:3,
		 lsa_offset:3,
		 mcc:12,
		 mnc:12;
	unsigned int present;
};

struct osmo_gsm48_si_ro_info {
	struct osmo_gsm48_si_selection_params selection_params;
	struct osmo_gsm48_si_power_offset power_offset;
	bool si2ter_indicator;
	bool early_cm_ctrl;
	struct {
		uint8_t where:3,
			 present:1;
	} scheduling;
	struct osmo_gsm48_si3_gprs_ind gprs_ind;
	/* SI 3 specific */
	bool early_cm_restrict_3g;
	bool si2quater_indicator;
	/* SI 4 specific */
	struct osmo_gsm48_lsa_params lsa_params;
	uint16_t cell_id;
	uint8_t break_ind;	/* do we have SI7 + SI8 ? */
};

/* Generate SI3 Rest Octests (Chapter 10.5.2.34 / Table 10.4.72) */
int osmo_gsm48_rest_octets_si3_encode(uint8_t *data, const struct osmo_gsm48_si_ro_info *si3);

/* Generate SI4 Rest Octets (Chapter 10.5.2.35) */
int osmo_gsm48_rest_octets_si4_encode(uint8_t *data, const struct osmo_gsm48_si_ro_info *si4, int len);

struct osmo_gsm48_si13_info {
	struct osmo_gprs_cell_options cell_opts;
	struct osmo_gprs_power_ctrl_pars pwr_ctrl_pars;
	uint8_t bcch_change_mark;
	uint8_t si_change_field;
	uint8_t rac;
	uint8_t spgc_ccch_sup;
	uint8_t net_ctrl_ord;
	uint8_t prio_acc_thr;
};

/* Parse/Generate SI13 Rest Octests (Chapter 10.5.2.37b) */
int osmo_gsm48_rest_octets_si13_decode(struct osmo_gsm48_si13_info *si13, const uint8_t *data);
int osmo_gsm48_rest_octets_si13_encode(uint8_t *data, const struct osmo_gsm48_si13_info *si13);

/* Parse SI3 Rest Octets */
void osmo_gsm48_rest_octets_si3_decode(struct osmo_gsm48_si_ro_info *si3, const uint8_t *data);

/* Parse SI4 Rest Octets */
void osmo_gsm48_rest_octets_si4_decode(struct osmo_gsm48_si_ro_info *si4, const uint8_t *data, int len);
