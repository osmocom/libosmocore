/*! \file l1sap.h */

#pragma once

#include <osmocom/core/prim.h>

/*! PH-SAP related primitives (L1<->L2 SAP) */
enum osmo_ph_prim {
	PRIM_PH_DATA,		/*!< PH-DATA */
	PRIM_PH_RACH,		/*!< PH-RANDOM_ACCESS */
	PRIM_PH_CONN,		/*!< PH-CONNECT */
	PRIM_PH_EMPTY_FRAME,	/*!< PH-EMPTY_FRAME */
	PRIM_PH_RTS,		/*!< PH-RTS */
	PRIM_MPH_INFO,		/*!< MPH-INFO */
	PRIM_TCH,		/*!< TCH */
	PRIM_TCH_RTS,		/*!< TCH */
};

extern const struct value_string osmo_ph_prim_names[];

/*! PH-SAP related primitives (L1<->L2 SAP) */
enum osmo_mph_info_type {
	PRIM_INFO_TIME,		/*!< Current GSM time */
	PRIM_INFO_MEAS,		/*!< Measurement indication */
	PRIM_INFO_ACTIVATE,	/*!< Activation of channel */
	PRIM_INFO_DEACTIVATE,	/*!< Deactivation of channel */
	PRIM_INFO_MODIFY,	/*!< Mode Modify of channel */
	PRIM_INFO_ACT_CIPH,	/*!< Activation of ciphering */
	PRIM_INFO_DEACT_CIPH,	/*!< Deactivation of ciphering */
};

/*! PH-DATA presence information */
enum osmo_ph_pres_info_type {
	PRES_INFO_INVALID = 0,	/*!< Data is invalid */
	PRES_INFO_HEADER  = 1,	/*!< Only header is present and valid */
	PRES_INFO_FIRST   = 3,	/*!< First half of data + header are valid (2nd half may be present but invalid) */
	PRES_INFO_SECOND  = 5,	/*!< Second half of data + header are valid (1st halfmay be present but invalid) */
	PRES_INFO_BOTH    = 7,	/*!< Both parts + header are present and valid */
	PRES_INFO_UNKNOWN
};

/*! for PH-RANDOM_ACCESS.req */
struct ph_rach_req_param {
	uint8_t ra;		/*!< Random Access */
	uint8_t ta;		/*!< Timing Advance */
	uint8_t tx_power;	/*!< Transmit Power */
	uint8_t is_combined_ccch;/*!< Are we using a combined CCCH? */
	uint16_t offset;	/*!< Timing Offset */
};

/*! for PH_RA_IND burstType inforamtion */
enum ph_burst_type {
	GSM_L1_BURST_TYPE_NONE = 0,
	GSM_L1_BURST_TYPE_ACCESS_0,
	GSM_L1_BURST_TYPE_ACCESS_1,
	GSM_L1_BURST_TYPE_ACCESS_2
};

/*! for PH-RANDOM_ACCESS.ind */
struct ph_rach_ind_param {
	uint8_t chan_nr;	/*!< Channel Number (Like RSL) */
	uint16_t ra;		/*!< Random Access */
	uint8_t acc_delay;	/*!< Delay in bit periods */
	uint32_t fn;		/*!< GSM Frame Number at time of RA */
	uint8_t is_11bit;	/*!< no.of bits in RACH*/
	enum ph_burst_type burst_type; /*!< type of burst*/
	/* elements added on 2018-02-26 */
	int8_t rssi;		/*!< RSSI of RACH indication */
	uint16_t ber10k;	/*!< BER in units of 0.01% */
	int16_t acc_delay_256bits;/*!< Burst TA Offset in 1/256th bits */
	int16_t lqual_cb;	/*!< Link quality in centiBel */
};

/*! for PH-[UNIT]DATA.{req,ind} | PH-RTS.ind */
struct ph_data_param {
	uint8_t link_id;	/*!< Link Identifier (Like RSL) */
	uint8_t chan_nr;	/*!< Channel Number (Like RSL) */
	uint32_t fn;		/*!< GSM Frame Number */
	int8_t rssi;		/*!< RSSI of receivedindication */
	uint16_t ber10k;	/*!< BER in units of 0.01% */
	union {
		int16_t ta_offs_qbits;	/*!< Burst TA Offset in quarter bits */
		int16_t ta_offs_256bits;/*!< timing advance offset (in 1/256th bits) */
	};
	int16_t lqual_cb;	/*!< Link quality in centiBel */
	enum osmo_ph_pres_info_type pdch_presence_info; /*!< Info regarding presence/validity of header and data parts */
	uint8_t is_sub:1;	/*!< flags */
};

/*! for TCH.{req,ind} | TCH-RTS.ind */
struct ph_tch_param {
	uint8_t chan_nr;	/*!< Channel Number (Like RSL) */
	uint32_t fn;		/*!< GSM Frame Number */
	int8_t rssi;		/*!< RSSI of received indication */
	uint8_t marker;		/*!< RTP Marker bit (speech onset indicator) */
	uint16_t ber10k;	/*!< BER in units of 0.01% */
	int16_t lqual_cb;	/*!< Link quality in centiBel */
	int16_t ta_offs_256bits;/*!< timing advance offset (in 1/256th bits) */
	uint8_t is_sub:1;	/*!< flags */
};

/*! for PH-CONN.ind */
struct ph_conn_ind_param {
	uint32_t fn;		/*!< GSM Frame Number */
};

/*! for TIME MPH-INFO.ind */
struct info_time_ind_param {
	uint32_t fn;		/*!< GSM Frame Number */
};

/*! for MEAS MPH-INFO.ind */
struct info_meas_ind_param {
	uint8_t chan_nr;	/*!< Channel Number (Like RSL) */
	uint32_t fn;		/*!< GSM Frame Number */
	uint16_t ber10k;	/*!< BER in units of 0.01% */
	union {
		int16_t ta_offs_qbits;	/*!< timing advance offset (in qbits) */
		int16_t ta_offs_256bits;/*!< timing advance offset (in 1/256th bits) */
	};
	int16_t c_i_cb;		/*!< C/I ratio in 0.1 dB */
	uint8_t is_sub:1;	/*!< flags */
	uint8_t inv_rssi;	/*!< RSSI in dBm * -1 */
};

/*! for {ACTIVATE,DEACTIVATE,MODIFY} MPH-INFO.req */
struct info_act_req_param {
	uint8_t chan_nr;	/*!< Channel Number (Like RSL) */
	uint8_t sacch_only;	/*!< \brief Only deactivate SACCH */
};

/*! for {ACTIVATE,DEACTIVATE} MPH-INFO.cnf */
struct info_act_cnf_param {
	uint8_t chan_nr;	/*!< Channel Number (Like RSL) */
	uint8_t cause;		/*!< RSL cause in case of nack */
};

/*! for {ACTIVATE,DEACTIVATE} MPH-INFO.{req,cnf} */
struct info_ciph_req_param {
	uint8_t chan_nr;	/*!< Channel Number (Like RSL) */
	uint8_t downlink;	/*!< Apply to downlink */
	uint8_t uplink;		/*!< Apply to uplink */
};

/*! for MPH-INFO.ind */
struct mph_info_param {
	enum osmo_mph_info_type type; /*!< Info message type */
	union {
		struct info_time_ind_param time_ind;
		struct info_meas_ind_param meas_ind;
		struct info_act_req_param act_req;
		struct info_act_cnf_param act_cnf;
		struct info_ciph_req_param ciph_req;
	} u;
};

/*! primitive header for PH-SAP primitives */
struct osmo_phsap_prim {
	struct osmo_prim_hdr oph; /*!< generic primitive header */
	union {
		struct ph_data_param data;
		struct ph_tch_param tch;
		struct ph_rach_req_param rach_req;
		struct ph_rach_ind_param rach_ind;
		struct ph_conn_ind_param conn_ind;
		struct mph_info_param info;
	} u;			/*!< request-specific data */
};
