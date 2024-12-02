/*! \file gsm_04_08_gprs.h */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/core/endian.h>

/* Table 10.4 / 10.4a, GPRS Mobility Management (GMM) */
#define GSM48_MT_GMM_ATTACH_REQ		0x01
#define GSM48_MT_GMM_ATTACH_ACK		0x02
#define GSM48_MT_GMM_ATTACH_COMPL	0x03
#define GSM48_MT_GMM_ATTACH_REJ		0x04
#define GSM48_MT_GMM_DETACH_REQ		0x05
#define GSM48_MT_GMM_DETACH_ACK		0x06

#define GSM48_MT_GMM_RA_UPD_REQ		0x08
#define GSM48_MT_GMM_RA_UPD_ACK		0x09
#define GSM48_MT_GMM_RA_UPD_COMPL	0x0a
#define GSM48_MT_GMM_RA_UPD_REJ		0x0b

#define GSM48_MT_GMM_PTMSI_REALL_CMD	0x10
#define GSM48_MT_GMM_PTMSI_REALL_COMPL	0x11
#define GSM48_MT_GMM_AUTH_CIPH_REQ	0x12
#define GSM48_MT_GMM_AUTH_CIPH_RESP	0x13
#define GSM48_MT_GMM_AUTH_CIPH_REJ	0x14
#define GSM48_MT_GMM_AUTH_CIPH_FAIL	0x1C
#define GSM48_MT_GMM_ID_REQ		0x15
#define GSM48_MT_GMM_ID_RESP		0x16
#define GSM48_MT_GMM_STATUS		0x20
#define GSM48_MT_GMM_INFO		0x21

/* Table 10.4a, GPRS Session Management (GSM) */
#define GSM48_MT_GSM_ACT_PDP_REQ	0x41
#define GSM48_MT_GSM_ACT_PDP_ACK	0x42
#define GSM48_MT_GSM_ACT_PDP_REJ	0x43
#define GSM48_MT_GSM_REQ_PDP_ACT	0x44
#define GSM48_MT_GSM_REQ_PDP_ACT_REJ	0x45
#define GSM48_MT_GSM_DEACT_PDP_REQ	0x46
#define GSM48_MT_GSM_DEACT_PDP_ACK	0x47
#define GSM48_MT_GSM_ACT_AA_PDP_REQ	0x50
#define GSM48_MT_GSM_ACT_AA_PDP_ACK	0x51
#define GSM48_MT_GSM_ACT_AA_PDP_REJ	0x52
#define GSM48_MT_GSM_DEACT_AA_PDP_REQ	0x53
#define GSM48_MT_GSM_DEACT_AA_PDP_ACK	0x54
#define GSM48_MT_GSM_STATUS		0x55

/* Chapter 10.5.5.2 / Table 10.5.135 */
#define GPRS_ATT_T_ATTACH		1
#define GPRS_ATT_T_ATT_WHILE_IMSI	2
#define GPRS_ATT_T_COMBINED		3

extern const struct value_string *gprs_att_t_strs;
extern const struct value_string gprs_msgt_gmm_names[];

/* Chapter 10.5.5.5 / Table 10.5.138 */
#define GPRS_DET_T_MO_GPRS		1
#define GPRS_DET_T_MO_IMSI		2
#define GPRS_DET_T_MO_COMBINED		3
/* Network to MS direction */
#define GPRS_DET_T_MT_REATT_REQ		1
#define GPRS_DET_T_MT_REATT_NOTREQ	2
#define GPRS_DET_T_MT_IMSI		3

extern const struct value_string *gprs_det_t_mo_strs;
extern const struct value_string *gprs_det_t_mt_strs;

/* Chapter 10.5.5.18 / Table 105.150 */
#define GPRS_UPD_T_RA			0
#define GPRS_UPD_T_RA_LA		1
#define GPRS_UPD_T_RA_LA_IMSI_ATT	2
#define GPRS_UPD_T_PERIODIC		3

extern const struct value_string *gprs_upd_t_strs;

/* Table 10.4 in 3GPP TS 24.008 (successor to 04.08) */
#define GSM48_MT_GMM_SERVICE_REQ	0x0c
#define GSM48_MT_GMM_SERVICE_ACK	0x0d
#define GSM48_MT_GMM_SERVICE_REJ	0x0e

enum gsm48_gprs_ie_mm {
	GSM48_IE_GMM_CIPH_CKSN		= 0x08,	/* 10.5.1.2 */
	GSM48_IE_GMM_TMSI_STATUS	= 0x09,	/* 10.5.5.4 */
	GSM48_IE_GMM_MS_NET_FEAT_SUP	= 0x0c,	/* 10.5.1.15 */
	GSM48_IE_GMM_DEVICE_PROP	= 0x0d,	/* 10.5.7.8 */
	GSM48_IE_GMM_PTMSI_TYPE		= 0x0e,	/* 10.5.5.29 */
	GSM48_IE_GMM_ADD_UPDATE_TYPE	= 0x0f,	/* 10.5.5.0 */
	GSM48_IE_GMM_TMSI_BASED_NRI_C	= 0x10,	/* 10.5.5.31 */
	GSM48_IE_GMM_MS_CLASSMARK2	= 0x11,	/* 10.5.1.6 */
	GSM48_IE_GMM_OLD_LAI		= 0x14,	/* 10.5.5.30 */
	GSM48_IE_GMM_TIMER_READY	= 0x17,	/* 10.5.7.3 */
	GSM48_IE_GMM_ALLOC_PTMSI	= 0x18,	/* 10.5.1.4 */
	GSM48_IE_GMM_PTMSI_SIG		= 0x19,	/* 10.5.5.8 */
	GSM48_IE_GMM_ADD_IDENTITY	= 0x1a,	/* 10.5.1.4 */
	GSM48_IE_GMM_RAI2		= 0x1b,	/* 10.5.5.15a */
	GSM48_IE_GMM_MS_CLASSMARK3	= 0x20,	/* 10.5.1.7 */
	GSM48_IE_GMM_AUTH_RAND		= 0x21,	/* 10.5.3.1 */
	GSM48_IE_GMM_AUTH_SRES		= 0x22,	/* 10.5.3.2 */
	GSM48_IE_GMM_IMEISV		= 0x23,	/* 10.5.1.4 */
	GSM48_IE_GMM_CAUSE		= 0x25,	/* 10.5.5.14 */
	GSM48_IE_GMM_RX_NPDU_NUM_LIST	= 0x26,	/* 10.5.5.11 */
	GSM48_IE_GMM_DRX_PARAM		= 0x27,	/* 10.5.5.6 */
	GSM48_IE_GMM_AUTN		= 0x28,	/* 10.5.3.1.1 */
	GSM48_IE_GMM_AUTH_RES_EXT	= 0x29,	/* 10.5.3.2.1 */
	GSM48_IE_GMM_TIMER_T3302	= 0x2A,	/* 10.5.7.4 */
	GSM48_IE_GMM_AUTH_FAIL_PAR	= 0x30,	/* 10.5.3.2.2 */
	GSM48_IE_GMM_MS_NET_CAPA	= 0x31,	/* 10.5.5.12 */
	GSM48_IE_GMM_PDP_CTX_STATUS	= 0x32,	/* 10.5.7.1 */
	GSM48_IE_GMM_PS_LCS_CAPA	= 0x33,	/* 10.5.5.22 */
	GSM48_IE_GMM_GMM_MBMS_CTX_ST	= 0x35,	/* 10.5.7.6 */
	GSM48_IE_GMM_TIMER_T3312_EXT	= 0x39,	/* 10.5.7.4a */
	GSM48_IE_GMM_TIMER_T3346	= 0x3A,	/* 10.5.7.4 */
	GSM48_IE_GMM_SUPP_CODEC_LIST	= 0x40,	/* 10.5.4.32 */
	GSM48_IE_GMM_UE_NET_CAP		= 0x58,	/* 10.5.5.26 */
	GSM48_IE_GMM_VD_PREF_UE_USAGE	= 0x5d,	/* 10.5.5.28 */
	GMM48_IE_GMM_TIMER_T3324	= 0x6a,	/* 10.5.7.4 */
	GSM48_IE_GMM_EXT_DRX_PARAMS	= 0x6e,	/* 10.5.5.32 */
	GSM48_IE_GMM_NET_FEAT_SUPPORT	= 0xB0,	/* 10.5.5.23 */
};

enum gsm48_gprs_ie_sm {
	GSM48_IE_GSM_RADIO_PRIO		= 0x08,	/* 10.5.7.2 */
	GSM48_IE_GSM_DEV_PROP		= 0x0C,	/* 10.5.7.8 */
	GSM48_IE_GSM_APN		= 0x28,	/* 10.5.6.1 */
	GSM48_IE_GSM_PROTO_CONF_OPT	= 0x27,	/* 10.5.6.3 */
	GSM48_IE_GSM_PDP_ADDR		= 0x2b, /* 10.5.6.4 */
	GSM48_IE_GSM_AA_TMR		= 0x29,	/* 10.5.7.3 */
	GSM48_IE_GSM_QOS		= 0x30,	/* 10.5.6.5 */
	GSM48_IE_GSM_TFT		= 0x31,	/* 10.5.6.12 */
	GSM48_IE_GSM_LLC_SAPI		= 0x32,	/* 10.5.6.9 */
	GSM48_IE_GSM_MBIFOM_CONT	= 0x33,	/* 10.5.6.21 */
	GSM48_IE_GSM_PFI		= 0x34,	/* 10.5.6.11 */
	GSM48_IE_GSM_NAME_FULL		= 0x43, /* 10.5.3.5a */
	GSM48_IE_GSM_NAME_SHORT		= 0x45, /* 10.5.3.5a */
	GSM48_IE_GSM_TIMEZONE		= 0x46, /* 10.5.3.8 */
	GSM48_IE_GSM_UTC_AND_TZ		= 0x47, /* 10.5.3.9 */
	GSM48_IE_GSM_LSA_ID		= 0x48, /* 10.5.3.11 */
	GSM48_IE_GSM_EXT_QOS		= 0x5C, /* 10.5.6.5B */
	GSM48_IE_GSM_EXT_PROTO_CONF_OPT	= 0x7B, /* 10.5.6.3a */

	/* Fake IEs that are not present on the Layer3 air interface,
	 * but which we use to simplify internal APIs */
	OSMO_IE_GSM_CHARG_CHAR		= 0xfc,
	OSMO_IE_GSM_REQ_QOS		= 0xfd,
	OSMO_IE_GSM_REQ_PDP_ADDR	= 0xfe,
	OSMO_IE_GSM_SUB_QOS		= 0xff,
};

/* Chapter 9.4.15 / Table 9.4.15 */
struct gsm48_ra_upd_ack {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t force_stby:4,	/* 10.5.5.7 */
		 upd_result:4;	/* 10.5.5.17 */
	uint8_t ra_upd_timer;	/* 10.5.7.3 */
	struct gsm48_ra_id ra_id; /* 10.5.5.15 */
	uint8_t data[0];
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t upd_result:4, force_stby:4;
	uint8_t ra_upd_timer;
	struct gsm48_ra_id ra_id;
	uint8_t data[0];
#endif
} __attribute__((packed));

/* Chapter 10.5.7.3 */
enum gsm48_gprs_tmr_unit {
	GPRS_TMR_2SECONDS	= 0 << 5,
	GPRS_TMR_MINUTE		= 1 << 5,
	GPRS_TMR_6MINUTE	= 2 << 5,
	GPRS_TMR_DEACTIVATED	= 7 << 5,
};

#define GPRS_TMR_UNIT_MASK (7 << 5)
#define GPRS_TMR_FACT_MASK ((1 << 5)-1)

/* Chapter 9.4.2 / Table 9.4.2 */
struct gsm48_attach_ack {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t att_result:4,	/* 10.5.5.7 */
		 force_stby:4;	/* 10.5.5.1 */
	uint8_t ra_upd_timer;	/* 10.5.7.3 */
	uint8_t radio_prio;	/* 10.5.7.2 */
	struct gsm48_ra_id ra_id; /* 10.5.5.15 */
	uint8_t data[0];
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t force_stby:4, att_result:4;
	uint8_t ra_upd_timer;
	uint8_t radio_prio;
	struct gsm48_ra_id ra_id;
	uint8_t data[0];
#endif
} __attribute__((packed));

/* Chapter 9.4.9 / Table 9.4.9 */
struct gsm48_auth_ciph_req {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t ciph_alg:4,	/* 10.5.5.3 */
		imeisv_req:4;	/* 10.5.5.10 */
	uint8_t force_stby:4,	/* 10.5.5.7 */
		ac_ref_nr:4;	/* 10.5.5.19 */
	uint8_t data[0];
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t imeisv_req:4, ciph_alg:4;
	uint8_t ac_ref_nr:4, force_stby:4;
	uint8_t data[0];
#endif
} __attribute__((packed));
/* optional: TV RAND, TV CKSN */

struct gsm48_auth_ciph_resp {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t ac_ref_nr:4,
		spare:4;
	uint8_t data[0];
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t spare:4, ac_ref_nr:4;
	uint8_t data[0];
#endif
} __attribute__((packed));

/* Chapter 9.5.1 / Table 9.5.1 */
struct gsm48_act_pdp_ctx_req {
	uint8_t req_nsapi;
	uint8_t req_llc_sapi;
	uint8_t data[0];
} __attribute__((packed));

/* Chapter 10.5.5.14 / Table 10.5.147 */
enum gsm48_gmm_cause {
	GMM_CAUSE_IMSI_UNKNOWN		= 0x02,
	GMM_CAUSE_ILLEGAL_MS		= 0x03,
	GMM_CAUSE_IMEI_NOT_ACCEPTED	= 0x05,
	GMM_CAUSE_ILLEGAL_ME		= 0x06,
	GMM_CAUSE_GPRS_NOTALLOWED	= 0x07,
	GMM_CAUSE_GPRS_OTHER_NOTALLOWED	= 0x08,
	GMM_CAUSE_MS_ID_NOT_DERIVED	= 0x09,
	GMM_CAUSE_IMPL_DETACHED		= 0x0a,
	GMM_CAUSE_PLMN_NOTALLOWED	= 0x0b,
	GMM_CAUSE_LA_NOTALLOWED		= 0x0c,
	GMM_CAUSE_ROAMING_NOTALLOWED	= 0x0d,
	GMM_CAUSE_NO_GPRS_PLMN		= 0x0e,
	GMM_CAUSE_NO_SUIT_CELL_IN_LA	= 0x0f,
	GMM_CAUSE_MSC_TEMP_NOTREACH	= 0x10,
	GMM_CAUSE_NET_FAIL		= 0x11,
	GMM_CAUSE_MAC_FAIL		= 0x14,
	GMM_CAUSE_SYNC_FAIL		= 0x15,
	GMM_CAUSE_CONGESTION		= 0x16,
	GMM_CAUSE_GSM_AUTH_UNACCEPT	= 0x17,
	GMM_CAUSE_NOT_AUTH_FOR_CSG	= 0x19,
	GMM_CAUSE_SMS_VIA_GPRS_IN_RA	= 0x1c,
	GMM_CAUSE_NO_PDP_ACTIVATED	= 0x28,
	GMM_CAUSE_SEM_INCORR_MSG	= 0x5f,
	GMM_CAUSE_INV_MAND_INFO		= 0x60,
	GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL	= 0x61,
	GMM_CAUSE_MSGT_INCOMP_P_STATE	= 0x62,
	GMM_CAUSE_IE_NOTEXIST_NOTIMPL	= 0x63,
	GMM_CAUSE_COND_IE_ERR		= 0x64,
	GMM_CAUSE_MSG_INCOMP_P_STATE	= 0x65,
	GMM_CAUSE_PROTO_ERR_UNSPEC	= 0x6f,
};

extern const struct value_string *gsm48_gmm_cause_names;

/* 3GPP TS 24.008 10.5.6.6 / Table 10.5.157 */
enum gsm48_gsm_cause {
	GSM_CAUSE_OPER_DET_BARR		= 0x08,
	GSM_CAUSE_MBMS_CAP_INSUF	= 0x18,
	GSM_CAUSE_LLC_SNDCP_FAIL	= 0x19,
	GSM_CAUSE_INSUFF_RSRC		= 0x1a,
	GSM_CAUSE_MISSING_APN		= 0x1b,
	GSM_CAUSE_UNKNOWN_PDP		= 0x1c,
	GSM_CAUSE_AUTH_FAILED		= 0x1d,
	GSM_CAUSE_ACT_REJ_GGSN		= 0x1e,
	GSM_CAUSE_ACT_REJ_UNSPEC	= 0x1f,
	GSM_CAUSE_SERV_OPT_NOTSUPP	= 0x20,
	GSM_CAUSE_REQ_SERV_OPT_NOTSUB	= 0x21,
	GSM_CAUSE_SERV_OPT_TEMP_OOO	= 0x22,
	GSM_CAUSE_NSAPI_IN_USE		= 0x23,
	GSM_CAUSE_DEACT_REGULAR		= 0x24,
	GSM_CAUSE_QOS_NOT_ACCEPTED	= 0x25,
	GSM_CAUSE_NET_FAIL		= 0x26,
	GSM_CAUSE_REACT_RQD		= 0x27,
	GSM_CAUSE_FEATURE_NOTSUPP	= 0x28,
	GSM_CAUSE_INVALID_TRANS_ID	= 0x51,
	GSM_CAUSE_SEM_INCORR_MSG	= 0x5f,
	GSM_CAUSE_INV_MAND_INFO		= 0x60,
	GSM_CAUSE_MSGT_NOTEXIST_NOTIMPL	= 0x61,
	GSM_CAUSE_MSGT_INCOMP_P_STATE	= 0x62,
	GSM_CAUSE_IE_NOTEXIST_NOTIMPL	= 0x63,
	GSM_CAUSE_COND_IE_ERR		= 0x64,
	GSM_CAUSE_MSG_INCOMP_P_STATE	= 0x65,
	GSM_CAUSE_PROTO_ERR_UNSPEC	= 0x6f,
};

extern const struct value_string *gsm48_gsm_cause_names;

/* Section 6.1.2.2: Session management states on the network side */
enum gsm48_pdp_state {
	PDP_S_INACTIVE,
	PDP_S_ACTIVE_PENDING,
	PDP_S_ACTIVE,
	PDP_S_INACTIVE_PENDING,
	PDP_S_MODIFY_PENDING,
};

/* TS 24.008 Table 10.5.155/3GPP */
enum gsm48_pdp_type_org {
	PDP_TYPE_ORG_ETSI		= 0x00,
	PDP_TYPE_ORG_IETF		= 0x01,
	PDP_TYPE_ORG_EMPTY		= 0x0f,
};
enum gsm48_pdp_type_nr {
	PDP_TYPE_N_ETSI_RESERVED	= 0x00,
	PDP_TYPE_N_ETSI_PPP		= 0x01,
	PDP_TYPE_N_IETF_IPv4		= 0x21,
	PDP_TYPE_N_IETF_IPv6		= 0x57,
	PDP_TYPE_N_IETF_IPv4v6		= 0x8D,
};
/* TS 24.008 10.5.6.4 "Packet data protocol address" value
 * Note: This can be reused for 3GPP TS 29.060 7.7.27 "End User Address"
 * with minor changes in the values, like spare being 1111 instead.
*/
struct gsm48_pdp_address {
#if OSMO_IS_LITTLE_ENDIAN
uint8_t organization:4, /* enum gsm48_pdp_type_org */
	spare:4; /* 0000 */
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
uint8_t spare:4, organization:4;
#endif
uint8_t type; /* enum gsm48_pdp_type_nr */
	union {
		/* PDP_TYPE_ORG_ETSI */
		union {
		} etsi;
		/* PDP_TYPE_ORG_IETF */
		union {
			/* PDP_TYPE_N_IETF_IPv4 */
			uint32_t v4;

			/* PDP_TYPE_N_IETF_IPv6 */
			uint8_t v6[16];

			/* PDP_TYPE_N_IETF_IPv4v6 */
			struct {
				uint32_t v4;
				uint8_t v6[16];
			} __attribute__ ((packed)) v4v6;
		} ietf;
	};
} __attribute__ ((packed));

/* Figure 10.5.138/24.008 / Chapter 10.5.6.5 */
enum gsm48_qos_reliab_class {
	GSM48_QOS_RC_LLC_ACK_RLC_ACK_DATA_PROT	= 2,
	GSM48_QOS_RC_LLC_UN_RLC_ACK_DATA_PROT	= 3,
	GSM48_QOS_RC_LLC_UN_RLC_UN_PROT_DATA	= 4,
	GSM48_QOS_RC_LLC_UN_RLC_UN_DATA_UN	= 5,
};

/* Figure 10.5.138/24.008 / Chapter 10.5.6.5 */
enum gsm48_qos_preced_class {
	GSM48_QOS_PC_HIGH	= 1,
	GSM48_QOS_PC_NORMAL	= 2,
	GSM48_QOS_PC_LOW	= 3,
};

/* Figure 10.5.138/24.008 / Chapter 10.5.6.5 */
enum gsm48_qos_peak_tput {
	GSM48_QOS_PEAK_TPUT_1000bps	= 1,
	GSM48_QOS_PEAK_TPUT_2000bps	= 2,
	GSM48_QOS_PEAK_TPUT_4000bps	= 3,
	GSM48_QOS_PEAK_TPUT_8000bps	= 4,
	GSM48_QOS_PEAK_TPUT_16000bps	= 5,
	GSM48_QOS_PEAK_TPUT_32000bps	= 6,
	GSM48_QOS_PEAK_TPUT_64000bps	= 7,
	GSM48_QOS_PEAK_TPUT_128000bps	= 8,
	GSM48_QOS_PEAK_TPUT_256000bps	= 9,
};

/* Figure 10.5.138/24.008 / Chapter 10.5.6.5 */
enum gsm48_qos_mean_tput {
	GSM48_QOS_MEAN_TPUT_100bph	= 1,
	GSM48_QOS_MEAN_TPUT_200bph	= 2,
	GSM48_QOS_MEAN_TPUT_500bph	= 3,
	GSM48_QOS_MEAN_TPUT_1000bph	= 4,
	GSM48_QOS_MEAN_TPUT_2000bph	= 5,
	GSM48_QOS_MEAN_TPUT_5000bph	= 6,
	GSM48_QOS_MEAN_TPUT_10000bph	= 7,
	GSM48_QOS_MEAN_TPUT_20000bph	= 8,
	GSM48_QOS_MEAN_TPUT_50000bph	= 9,
	GSM48_QOS_MEAN_TPUT_100kbph	= 10,
	GSM48_QOS_MEAN_TPUT_200kbph	= 11,
	GSM48_QOS_MEAN_TPUT_500kbph	= 0xc,
	GSM48_QOS_MEAN_TPUT_1Mbph	= 0xd,
	GSM48_QOS_MEAN_TPUT_2Mbph	= 0xe,
	GSM48_QOS_MEAN_TPUT_5Mbph	= 0xf,
	GSM48_QOS_MEAN_TPUT_10Mbph	= 0x10,
	GSM48_QOS_MEAN_TPUT_20Mbph	= 0x11,
	GSM48_QOS_MEAN_TPUT_50Mbph	= 0x12,
	GSM48_QOS_MEAN_TPUT_BEST_EFFORT	= 0x1f,
};

/* Figure 10.5.138/24.008 / Chapter 10.5.6.5 */
enum gsm48_qos_err_sdu {
	GSM48_QOS_ERRSDU_NODETECT	= 1,
	GSM48_QOS_ERRSDU_YES		= 2,
	GSM48_QOS_ERRSDU_NO		= 3,
};

/* Figure 10.5.138/24.008 / Chapter 10.5.6.5 */
enum gsm48_qos_deliv_order {
	GSM48_QOS_DO_ORDERED		= 1,
	GSM48_QOS_DO_UNORDERED		= 2,
};

/* Figure 10.5.138/24.008 / Chapter 10.5.6.5 */
enum gsm48_qos_traf_class {
	GSM48_QOS_TC_CONVERSATIONAL	= 1,
	GSM48_QOS_TC_STREAMING		= 2,
	GSM48_QOS_TC_INTERACTIVE	= 3,
	GSM48_QOS_TC_BACKGROUND		= 4,
};

/* Figure 10.5.138/24.008 / Chapter 10.5.6.5 */
enum gsm48_qos_max_sdu_size {
	/* values below in 10 octet granularity */
	GSM48_QOS_MAXSDU_1502		= 0x97,
	GSM48_QOS_MAXSDU_1510		= 0x98,
	GSM48_QOS_MAXSDU_1520		= 0x99,
};

/* Figure 10.5.138/24.008 / Chapter 10.5.6.5 */
enum gsm48_qos_max_bitrate {
	GSM48_QOS_MBRATE_1k		= 0x01,
	GSM48_QOS_MBRATE_63k		= 0x3f,
	GSM48_QOS_MBRATE_64k		= 0x40,
	GSM48_QOS_MBRATE_568k		= 0x7f,
	GSM48_QOS_MBRATE_576k		= 0x80,
	GSM48_QOS_MBRATE_8640k		= 0xfe,
	GSM48_QOS_MBRATE_0k		= 0xff,
};

/* Figure 10.5.138/24.008 / Chapter 10.5.6.5 */
enum gsm48_qos_resid_ber {
	GSM48_QOS_RBER_5e_2		= 0x01,
	GSM48_QOS_RBER_1e_2		= 0x02,
	GSM48_QOS_RBER_5e_3		= 0x03,
	GSM48_QOS_RBER_4e_3		= 0x04,
	GSM48_QOS_RBER_1e_3		= 0x05,
	GSM48_QOS_RBER_1e_4		= 0x06,
	GSM48_QOS_RBER_1e_5		= 0x07,
	GSM48_QOS_RBER_1e_6		= 0x08,
	GSM48_QOS_RBER_6e_8		= 0x09,
};

/* Figure 10.5.138/24.008 / Chapter 10.5.6.5 */
enum gsm48_qos_sdu_err {
	GSM48_QOS_SERR_1e_2		= 0x01,
	GSM48_QOS_SERR_7e_2		= 0x02,
	GSM48_QOS_SERR_1e_3		= 0x03,
	GSM48_QOS_SERR_1e_4		= 0x04,
	GSM48_QOS_SERR_1e_5		= 0x05,
	GSM48_QOS_SERR_1e_6		= 0x06,
	GSM48_QOS_SERR_1e_1		= 0x07,
};

/* 3GPP 24.008 / Chapter 10.5.5.20 / Table 10.5.153a */
enum gsm48_gmm_service_type {
	GPRS_SERVICE_T_SIGNALLING	= 0x00,
	GPRS_SERVICE_T_DATA		= 0x01,
	GPRS_SERVICE_T_PAGING_RESP	= 0x02,
	GPRS_SERVICE_T_MBMS_MC_SERV	= 0x03,
	GPRS_SERVICE_T_MBMS_BC_SERV	= 0x04,
};

extern const struct value_string *gprs_service_t_strs;

bool gprs_ms_net_cap_gea_supported(const uint8_t *ms_net_cap, uint8_t cap_len,
				   enum gprs_ciph_algo gea);

/* Figure 10.5.138/24.008 / Chapter 10.5.6.5 */
struct gsm48_qos {
	/* octet 3 */
	uint8_t reliab_class:3;
	uint8_t delay_class:3;
	uint8_t spare:2;
	/* octet 4 */
	uint8_t preced_class:3;
	uint8_t spare2:1;
	uint8_t peak_tput:4;
	/* octet 5 */
	uint8_t mean_tput:5;
	uint8_t spare3:3;
	/* octet 6 */
	uint8_t deliv_err_sdu:3;
	uint8_t deliv_order:2;
	uint8_t traf_class:3;
	/* octet 7 */
	uint8_t max_sdu_size;
	/* octet 8 */
	uint8_t max_bitrate_up;
	/* octet 9 */
	uint8_t max_bitrate_down;
	/* octet 10 */
	uint8_t sdu_err_ratio:4;
	uint8_t resid_ber:4;
	/* octet 11 */
	uint8_t handling_prio:2;
	uint8_t xfer_delay:6;
	/* octet 12 */
	uint8_t guar_bitrate_up;
	/* octet 13 */
	uint8_t guar_bitrate_down;
	/* octet 14 */
	uint8_t src_stats_desc:4;
	uint8_t sig_ind:1;
	uint8_t spare5:3;
	/* octet 15 */
	uint8_t max_bitrate_down_ext;
	/* octet 16 */
	uint8_t guar_bitrate_down_ext;
};

/* TS 24.008 Table 10.5.5.29 */
enum gsm48_ptsmi_type {
	PTMSI_TYPE_NATIVE		= 0x00,
	PTMSI_TYPE_MAPPED		= 0x01,
};

