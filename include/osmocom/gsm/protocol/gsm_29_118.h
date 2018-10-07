#pragma once


/* TS 29.118 Section 9.2 */
enum sgsap_msg_type {
	/* unassigned */
	SGSAP_MSGT_PAGING_REQ			= 0x01,
	SGSAP_MSGT_PAGING_REJ			= 0x02,
	/* unassigned */
	SGSAP_MSGT_SERVICE_REQ			= 0x06,
	SGSAP_MSGT_DL_UD			= 0x07,
	SGSAP_MSGT_UL_UD			= 0x08,
	SGSAP_MSGT_LOC_UPD_REQ			= 0x09,
	SGSAP_MSGT_LOC_UPD_ACK			= 0x0a,
	SGSAP_MSGT_LOC_UPD_REJ			= 0x0b,
	SGSAP_MSGT_TMSI_REALL_CMPL		= 0x0c,
	SGSAP_MSGT_ALERT_REQ			= 0x0d,
	SGSAP_MSGT_ALERT_ACK			= 0x0e,
	SGSAP_MSGT_ALERT_REJ			= 0x0f,
	SGSAP_MSGT_UE_ACT_IND			= 0x10,
	SGSAP_MSGT_EPS_DET_IND			= 0x11,
	SGSAP_MSGT_EPS_DET_ACK			= 0x12,
	SGSAP_MSGT_IMSI_DET_IND			= 0x13,
	SGSAP_MSGT_IMSI_DET_ACK			= 0x14,
	SGSAP_MSGT_RESET_IND			= 0x15,
	SGSAP_MSGT_RESET_ACK			= 0x16,
	SGSAP_MSGT_SERVICE_ABORT_REQ		= 0x17,
	SGSAP_MSGT_MO_CSFB_IND			= 0x18,
	/* unassigned */
	SGSAP_MSGT_MM_INFO_REQ			= 0x1a,
	SGSAP_MSGT_RELEASE_REQ			= 0x1b,
	/* unassigned */
	SGSAP_MSGT_STATUS			= 0x1d,
	/* unassigned */
	SGSAP_MSGT_UE_UNREACHABLE		= 0x1f,
};
const struct value_string sgsap_msg_type_names[];
static inline const char *sgsap_msg_type_name(enum sgsap_msg_type msgt) {
	return get_value_string(sgsap_msg_type_names, msgt);
}

/* TS 29.118 Section 9.3 */
enum sgsap_iei {
	SGSAP_IE_IMSI				= 0x01,
	SGSAP_IE_VLR_NAME			= 0x02,
	SGSAP_IE_TMSI				= 0x03,
	SGSAP_IE_LAI				= 0x04,
	SGSAP_IE_CHAN_NEEDED			= 0x05,
	SGSAP_IE_EMLPP_PRIORITY			= 0x06,
	SGSAP_IE_TMSI_STATUS			= 0x07,
	SGSAP_IE_SGS_CAUSE			= 0x08,
	SGSAP_IE_MME_NAME			= 0x09,
	SGSAP_IE_EPS_LU_TYPE			= 0x0a,
	SGSAP_IE_GLOBAL_CN_ID			= 0x0b,
	SGSAP_IE_MOBILE_ID			= 0x0e,
	SGSAP_IE_REJECT_CAUSE			= 0x0f,
	SGSAP_IE_IMSI_DET_EPS_TYPE		= 0x10,
	SGSAP_IE_IMSI_DET_NONEPS_TYPE		= 0x11,
	SGSAP_IE_IMEISV				= 0x15,
	SGSAP_IE_NAS_MSG_CONTAINER		= 0x16,
	SGSAP_IE_MM_INFO			= 0x17,
	SGSAP_IE_ERR_MSG			= 0x1b,
	SGSAP_IE_CLI				= 0x1c,
	SGSAP_IE_LCS_CLIENT_ID			= 0x1d,
	SGSAP_IE_LCS_INDICATOR			= 0x1e,
	SGSAP_IE_SS_CODE			= 0x1f,
	SGSAP_IE_SERVICE_INDICATOR		= 0x20,
	SGSAP_IE_UE_TIMEZONE			= 0x21,
	SGSAP_IE_MS_CLASSMARK2			= 0x22,
	SGSAP_IE_TAI				= 0x23,
	SGSAP_IE_EUTRAN_CGI			= 0x24,
	SGSAP_IE_UE_EMM_MODE			= 0x25,
	SGSAP_IE_ADDL_PAGING_INDICATORS		= 0x26,
	SGSAP_IE_TMSI_BASED_NRI_CONT		= 0x27,
};


/* TS 29.118 Section 9.4.2 */
enum sgsap_eps_lu_type {
	SGSAP_EPS_LUT_IMSI_ATTACH		= 0x01,
	SGSAP_EPS_LUT_NORMAL			= 0x02,
};
const struct value_string sgsap_eps_lu_type_names[];
static inline const char *sgsap_eps_lu_type_name(enum sgsap_eps_lu_type lut) {
	return get_value_string(sgsap_eps_lu_type_names, lut);
}

/* TS 29.118 Section 9.4.7 */
enum sgsap_imsi_det_eps_type {
	SGSAP_ID_EPS_T_NETWORK_INITIATED	= 0x01,
	SGSAP_ID_EPS_T_UE_INITIATED		= 0x02,
	SGSAP_ID_EPS_T_EPS_NOT_ALLOWED		= 0x03,
};
const struct value_string sgsap_ismi_det_eps_type_names[];
static inline const char *sgsap_imsi_det_eps_type_name(enum sgsap_imsi_det_eps_type idt) {
	return get_value_string(sgsap_ismi_det_eps_type_names, idt);
}

/* TS 29.118 Section 9.4.8 */
enum sgsap_imsi_det_noneps_type {
	SGSAP_ID_NONEPS_T_EXPLICIT_UE_NONEPS		= 0x01,
	SGSAP_ID_NONEPS_T_COMBINED_UE_EPS_NONEPS	= 0x02,
	SGSAP_ID_NONEPS_T_IMPLICIT_UE_EPS_NONEPS	= 0x03,
};
const struct value_string sgsap_ismi_det_noneps_type_names[];
static inline const char *sgsap_imsi_det_noneps_type_name(enum sgsap_imsi_det_noneps_type idt) {
	return get_value_string(sgsap_ismi_det_noneps_type_names, idt);
}

/* TS 29.118 Section 9.4.17 */
enum sgsap_service_ind {
	SGSAP_SERV_IND_CS_CALL		= 0x01,
	SGSAP_SERV_IND_SMS		= 0x02,
};
const struct value_string sgsap_service_ind_names[];
static inline const char *sgsap_service_ind_name(enum sgsap_service_ind si) {
	return get_value_string(sgsap_service_ind_names, si);
}

/* TS 29.118 Section 9.4.18 */
enum sgsap_sgs_cause {
	SGSAP_SGS_CAUSE_IMSI_DET_EPS		= 0x01,
	SGSAP_SGS_CAUSE_IMSI_DET_EPS_NONEPS	= 0x02,
	SGSAP_SGS_CAUSE_IMSI_UNKNOWN		= 0x03,
	SGSAP_SGS_CAUSE_IMSI_DET_NON_EPS	= 0x04,
	SGSAP_SGS_CAUSE_IMSI_IMPL_DET_NON_EPS	= 0x05,
	SGSAP_SGS_CAUSE_UE_UNREACHABLE		= 0x06,
	SGSAP_SGS_CAUSE_MSG_INCOMP_STATE	= 0x07,
	SGSAP_SGS_CAUSE_MISSING_MAND_IE		= 0x08,
	SGSAP_SGS_CAUSE_INVALID_MAND_IE		= 0x09,
	SGSAP_SGS_CAUSE_COND_IE_ERROR		= 0x0a,
	SGSAP_SGS_CAUSE_SEMANT_INCORR_MSG	= 0x0b,
	SGSAP_SGS_CAUSE_MSG_UNKNOWN		= 0x0c,
	SGSAP_SGS_CAUSE_MT_CSFB_REJ_USER	= 0x0d,
	SGSAP_SGS_CAUSE_UE_TEMP_UNREACHABLE	= 0x0e,
};
const struct value_string sgsap_sgs_cause_names[];
static inline const char *sgsap_sgs_cause_name(enum sgsap_sgs_cause cause) {
	return get_value_string(sgsap_sgs_cause_names, cause);
}

/* TS 29.118 Section 9.4.21c */
enum sgsap_ue_emm_mode {
	SGSAP_UE_EMM_MODE_IDLE			= 0x00,
	SGSAP_UE_EMM_MODE_CONNECTED		= 0x01,
};
const struct value_string sgsap_ue_emm_mode_names[];
static inline const char *sgsap_ue_emm_mode_name(enum sgsap_ue_emm_mode mode) {
	return get_value_string(sgsap_ue_emm_mode_names, mode);
}

/* TS 29.118 Section 10.1 Table 10.1.2 */
#define SGS_TS5_DEFAULT		10	/* Guards the Paging Procedure at the VLR */
#define SGS_TS6_2_DEFAULT	40	/* Guards the TMSI reallocation procedure */
#define SGS_TS7_DEFAULT		 4	/* Guards the non-EPS alert procedure */
#define SGS_TS11_DEFAULT	 4	/* Guards the VLR reset procedure */
#define SGS_TS14_DEFAULT	10	/* Guards the UE fallback to UTRAN/GERAN */
#define SGS_TS15_DEFAULT	10	/* Guards the MO UE fallback to UTRAN/GERAN */

/* TS 29.118 Section 10.2 Table 10.2.1 */
#define SGS_NS7_DEFAULT		2
#define SGS_NS11_DEFAULT	2
/* TS 29.118 Section 10.2 Table 10.2.2 */
#define SGS_NS8_DEFAULT		2
#define SGS_NS9_DEFAULT		2
#define SGS_NS10_DEFAULT	2
#define SGS_NS12_DEFAULT	2

const struct tlv_definition sgsap_ie_tlvdef;
