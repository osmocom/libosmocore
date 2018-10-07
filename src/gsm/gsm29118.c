#include <osmocom/core/utils.h>
#include <osmocom/gsm/tlv.h>

#include <osmocom/gsm/protocol/gsm_29_118.h>

const struct value_string sgsap_msg_type_names[] = {
	{ SGSAP_MSGT_PAGING_REQ,	"PAGING-REQUEST" },
	{ SGSAP_MSGT_PAGING_REJ,	"PAGING-REJECT" },
	{ SGSAP_MSGT_SERVICE_REQ,	"SERVICE-REQUEST" },
	{ SGSAP_MSGT_DL_UD,		"DOWNLINK-UNITDATA" },
	{ SGSAP_MSGT_UL_UD,		"UPLINK-UNITDATA" },
	{ SGSAP_MSGT_LOC_UPD_REQ,	"LOCATION-UPDATE-REQUEST" },
	{ SGSAP_MSGT_LOC_UPD_ACK,	"LOCATION-UPDATE-ACCEPT" },
	{ SGSAP_MSGT_LOC_UPD_REJ,	"LOCATION-UPDATE-REJECT" },
	{ SGSAP_MSGT_TMSI_REALL_CMPL,	"TMSI-REALLOCATION-COMPLETE" },
	{ SGSAP_MSGT_ALERT_REQ,		"ALERT-REQQUEST" },
	{ SGSAP_MSGT_ALERT_ACK,		"ALERT-ACK" },
	{ SGSAP_MSGT_ALERT_REJ,		"ALERT-REJECT" },
	{ SGSAP_MSGT_UE_ACT_IND,	"UE-ACTIVITY-INDICATION" },
	{ SGSAP_MSGT_EPS_DET_IND,	"EPS-DETACH-INDICATION" },
	{ SGSAP_MSGT_EPS_DET_ACK,	"EPS-DETACH-ACK" },
	{ SGSAP_MSGT_IMSI_DET_IND,	"IMSI-DETACH-INDICATION" },
	{ SGSAP_MSGT_IMSI_DET_ACK,	"IMSI-DETACH-ACK" },
	{ SGSAP_MSGT_RESET_IND,		"RESET-INDICATION" },
	{ SGSAP_MSGT_RESET_ACK,		"RESET-ACK" },
	{ SGSAP_MSGT_SERVICE_ABORT_REQ,	"SERVICE-ABORT-REQUEST" },
	{ SGSAP_MSGT_MO_CSFB_IND,	"MO-CSFB-INDICATION" },
	{ SGSAP_MSGT_MM_INFO_REQ,	"MM-INFO-REQUEST" },
	{ SGSAP_MSGT_RELEASE_REQ,	"RELEASE-REQUEST" },
	{ SGSAP_MSGT_STATUS,		"STATUS" },
	{ SGSAP_MSGT_UE_UNREACHABLE,	"UE-UNREACHABLE" },
	{ 0, NULL }
};

const struct value_string sgsap_eps_lu_type_names[] = {
	{ SGSAP_EPS_LUT_IMSI_ATTACH,	"IMSI Attach" },
	{ SGSAP_EPS_LUT_NORMAL,		"Normal" },
	{ 0, NULL }
};

const struct value_string sgsap_ismi_det_eps_type_names[] = {
	{ SGSAP_ID_EPS_T_NETWORK_INITIATED,	"Network initiated IMSI detach from EPS" },
	{ SGSAP_ID_EPS_T_UE_INITIATED,		"UE initiated IMSI detach from EPS" },
	{ SGSAP_ID_EPS_T_EPS_NOT_ALLOWED,	"EPS not allowed" },
	{ 0, NULL }
};

const struct value_string sgsap_ismi_det_noneps_type_names[] = {
	{ SGSAP_ID_NONEPS_T_EXPLICIT_UE_NONEPS,
	  "Explicit UE initiated IMSI detach from non-EPS" },
	{ SGSAP_ID_NONEPS_T_COMBINED_UE_EPS_NONEPS,
	  "Combined UE initiated IMSI detach from EPS and non-EPS" },
	{ SGSAP_ID_NONEPS_T_IMPLICIT_UE_EPS_NONEPS,
	  "Implicit network initiated IMSI detach from EPS and non-EPS" },
	{ 0, NULL }
};

const struct value_string sgsap_service_ind_names[] = {
	{ SGSAP_SERV_IND_CS_CALL,	"CS Call" },
	{ SGSAP_SERV_IND_SMS,		"SMS" },
	{ 0, NULL }
};

const struct value_string sgsap_sgs_cause_names[] = {
	{ SGSAP_SGS_CAUSE_IMSI_DET_EPS,		"IMSI detached for EPS" },
	{ SGSAP_SGS_CAUSE_IMSI_DET_EPS_NONEPS,	"IMSI detached for EPS and non-EPS" },
	{ SGSAP_SGS_CAUSE_IMSI_UNKNOWN,		"IMSI unknown" },
	{ SGSAP_SGS_CAUSE_IMSI_DET_NON_EPS,	"IMSI detached for non-EPS" },
	{ SGSAP_SGS_CAUSE_IMSI_IMPL_DET_NON_EPS,"IMSI implicitly detached for non-EPS" },
	{ SGSAP_SGS_CAUSE_UE_UNREACHABLE,	"UE unreachable" },
	{ SGSAP_SGS_CAUSE_MSG_INCOMP_STATE,	"Message not compatible with protocol state" },
	{ SGSAP_SGS_CAUSE_MISSING_MAND_IE,	"Missing mandatory IE" },
	{ SGSAP_SGS_CAUSE_INVALID_MAND_IE,	"Invalid mandatory IE" },
	{ SGSAP_SGS_CAUSE_COND_IE_ERROR,	"Conditional IE error" },
	{ SGSAP_SGS_CAUSE_SEMANT_INCORR_MSG,	"Semantically incorrect message" },
	{ SGSAP_SGS_CAUSE_MSG_UNKNOWN,		"Message unknown" },
	{ SGSAP_SGS_CAUSE_MT_CSFB_REJ_USER,	"MT CSFB call rejected by user" },
	{ SGSAP_SGS_CAUSE_UE_TEMP_UNREACHABLE,	"UE temporarily unreachable" },
	{ 0, NULL }
};


const struct value_string sgsap_ue_emm_mode_names[] = {
	{ SGSAP_UE_EMM_MODE_IDLE, 		"EMM-IDLE" },
	{ SGSAP_UE_EMM_MODE_CONNECTED,		"EMM-CONNECTED" },
	{ 0, NULL }
};

const struct tlv_definition sgsap_ie_tlvdef = {
	.def = {
		[SGSAP_IE_IMSI]			= { TLV_TYPE_TLV },
		[SGSAP_IE_VLR_NAME]		= { TLV_TYPE_TLV },
		[SGSAP_IE_TMSI]			= { TLV_TYPE_TLV },
		[SGSAP_IE_LAI]			= { TLV_TYPE_TLV },
		[SGSAP_IE_CHAN_NEEDED]		= { TLV_TYPE_TLV },
		[SGSAP_IE_EMLPP_PRIORITY]	= { TLV_TYPE_TLV },
		[SGSAP_IE_TMSI_STATUS]		= { TLV_TYPE_TLV },
		[SGSAP_IE_SGS_CAUSE]		= { TLV_TYPE_TLV },
		[SGSAP_IE_MME_NAME]		= { TLV_TYPE_TLV },
		[SGSAP_IE_EPS_LU_TYPE]		= { TLV_TYPE_TLV },
		[SGSAP_IE_GLOBAL_CN_ID]		= { TLV_TYPE_TLV },
		[SGSAP_IE_MOBILE_ID]		= { TLV_TYPE_TLV },
		[SGSAP_IE_REJECT_CAUSE]		= { TLV_TYPE_TLV },
		[SGSAP_IE_IMSI_DET_EPS_TYPE]	= { TLV_TYPE_TLV },
		[SGSAP_IE_IMSI_DET_NONEPS_TYPE]	= { TLV_TYPE_TLV },
		[SGSAP_IE_IMEISV]		= { TLV_TYPE_TLV },
		[SGSAP_IE_NAS_MSG_CONTAINER]	= { TLV_TYPE_TLV },
		[SGSAP_IE_MM_INFO]		= { TLV_TYPE_TLV },
		[SGSAP_IE_ERR_MSG]		= { TLV_TYPE_TLV },
		[SGSAP_IE_CLI]			= { TLV_TYPE_TLV },
		[SGSAP_IE_LCS_CLIENT_ID]	= { TLV_TYPE_TLV },
		[SGSAP_IE_LCS_INDICATOR]	= { TLV_TYPE_TLV },
		[SGSAP_IE_SS_CODE]		= { TLV_TYPE_TLV },
		[SGSAP_IE_SERVICE_INDICATOR]	= { TLV_TYPE_TLV },
		[SGSAP_IE_UE_TIMEZONE]		= { TLV_TYPE_TLV },
		[SGSAP_IE_MS_CLASSMARK2]	= { TLV_TYPE_TLV },
		[SGSAP_IE_TAI]			= { TLV_TYPE_TLV },
		[SGSAP_IE_EUTRAN_CGI]		= { TLV_TYPE_TLV },
		[SGSAP_IE_UE_EMM_MODE]		= { TLV_TYPE_TLV },
		[SGSAP_IE_ADDL_PAGING_INDICATORS]={ TLV_TYPE_TLV },
		[SGSAP_IE_TMSI_BASED_NRI_CONT]	= { TLV_TYPE_TLV },
	},
};
