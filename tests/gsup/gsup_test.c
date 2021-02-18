#include <string.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
#include <osmocom/gsm/gsup.h>

#define VERBOSE_FPRINTF(...)

/* Tests for osmo_gsup_messages.c */

/* Complete IEs used multiple times (sorted alphabetically)
 * 1st byte: IEI from osmo_gsup_iei, 2nd byte: length */
#define TEST_IMSI_IE 0x01, 0x08, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xf5
#define TEST_IMSI_STR "123456789012345"
#define TEST_CLASS_SUBSCR_IE 0xa, 0x1, 0x1
#define TEST_CLASS_INTER_MSC_IE 0xa, 0x1, 0x4
#define TEST_MSISDN_IE 0x08, 0x07, 0x91, 0x94, 0x61, 0x46, 0x32, 0x24, 0x43
#define TEST_AN_APDU_IE 0x62, 0x05, 0x01, 0x42, 0x42, 0x42, 0x42
#define TEST_SOURCE_NAME_IE 0x60, 0x05, 'M', 'S', 'C', '-', 'A'
#define TEST_DESTINATION_NAME_IE 0x61, 0x05, 'M', 'S', 'C', '-', 'B'
#define TEST_NUM_VEC_IE(x) 0x52, 1, x

static void test_gsup_messages_dec_enc(void)
{
	int test_idx;
	int rc;
	uint8_t buf[1024];

	static const uint8_t send_auth_info_req[] = {
		0x08,
		TEST_IMSI_IE,
		TEST_CLASS_SUBSCR_IE
	};

	static const uint8_t send_auth_info_req10[] = {
		0x08,
		TEST_IMSI_IE,
		TEST_NUM_VEC_IE(10),
		TEST_CLASS_SUBSCR_IE
	};

	static const uint8_t send_auth_info_err[] = {
		0x09,
		TEST_IMSI_IE,
		0x02, 0x01, 0x07 /* GPRS no allowed */
	};

	static const uint8_t send_auth_info_res[] = {
		0x0a,
		TEST_IMSI_IE,
		0x03, 0x22, /* Auth tuple */
			0x20, 0x10,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x21, 0x04,
				0x21, 0x22, 0x23, 0x24,
			0x22, 0x08,
				0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x03, 0x22, /* Auth tuple */
			0x20, 0x10,
				0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
				0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
			0x21, 0x04,
				0xa1, 0xa2, 0xa3, 0xa4,
			0x22, 0x08,
				0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
	};

	static const uint8_t update_location_req[] = {
		0x04,
		TEST_IMSI_IE,
	};

	static const uint8_t update_location_err[] = {
		0x05,
		TEST_IMSI_IE,
		0x02, 0x01, 0x07 /* GPRS no allowed */
	};

	static const uint8_t update_location_res[] = {
		0x06,
		TEST_IMSI_IE,
		TEST_MSISDN_IE,
		0x09, 0x07, /* HLR-Number of the subscriber */
			0x91, 0x83, 0x52, 0x38, 0x48, 0x83, 0x93,
		0x04, 0x00, /* PDP info complete */
		0x05, 0x19,
			0x10, 0x01, 0x01,
			0x11, 0x02, 0xf1, 0x21, /* IPv4 */
			0x12, 0x09, 0x04, 't', 'e', 's', 't', 0x03, 'a', 'p', 'n',
			0x13, 0x01, 0x02,
			0x14, 0x02, 0xFF, 0x23,
		0x05, 0x11,
			0x10, 0x01, 0x02,
			0x11, 0x02, 0xf1, 0x21, /* IPv4 */
			0x12, 0x08, 0x03, 'f', 'o', 'o', 0x03, 'a', 'p', 'n',
		0x14, 0x02,
			0xAE, 0xFF
	};

	static const uint8_t location_cancellation_req[] = {
		0x1c,
		TEST_IMSI_IE,
		0x06, 0x01, 0x00,
	};

	static const uint8_t location_cancellation_err[] = {
		0x1d,
		TEST_IMSI_IE,
		0x02, 0x01, 0x03 /* Illegal MS */
	};

	static const uint8_t location_cancellation_res[] = {
		0x1e,
		TEST_IMSI_IE,
	};

	static const uint8_t purge_ms_req[] = {
		0x0c,
		TEST_IMSI_IE,
	};

	static const uint8_t purge_ms_err[] = {
		0x0d,
		TEST_IMSI_IE,
		0x02, 0x01, 0x03, /* Illegal MS */
	};

	static const uint8_t purge_ms_res[] = {
		0x0e,
		TEST_IMSI_IE,
		0x07, 0x00,
	};

	static const uint8_t send_auth_info_res_umts[] = {
		0x0a,
		TEST_IMSI_IE,
		0x03, 0x62, /* Auth tuple */
			0x20, 0x10, /* rand */
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x21, 0x04, /* sres */
				0x21, 0x22, 0x23, 0x24,
			0x22, 0x08, /* kc */
				0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
			0x23, 0x10, /* IK (UMTS) */
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x24, 0x10, /* CK (UMTS) */
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x25, 0x10, /* AUTN (UMTS) */
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x27, 0x08, /* RES (UMTS) */
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x03, 0x62, /* Auth tuple */
			0x20, 0x10, /* rand */
				0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
				0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0x10,
			0x21, 0x04, /* sres */
				0xb1, 0xb2, 0xb3, 0xb4,
			0x22, 0x08, /* kc */
				0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
			0x23, 0x10, /* IK (UMTS) */
				0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
				0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xd0,
			0x24, 0x10, /* CK (UMTS) */
				0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8,
				0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xe0,
			0x25, 0x10, /* AUTN (UMTS) */
				0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
				0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0xf0,
			0x27, 0x08, /* RES (UMTS) */
				0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
	};

	static const uint8_t send_auth_info_req_auts[] = {
		0x08,
		TEST_IMSI_IE,
		0x26, 0x0e, /* AUTS (UMTS) */
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
		0x20, 0x10, /* rand */
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};

	static const uint8_t dummy_session_ies[] = {
		0x2b, /* Dummy value, we only interested in IE coding */
		TEST_IMSI_IE,

		/* Session ID and state */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x01,
	};

	static const uint8_t send_ussd_req[] = {
		0x20, /* OSMO_GSUP_MSGT_PROC_SS_REQUEST */
		TEST_IMSI_IE,

		/* Session ID and state */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x01,

		/* SS/USSD information IE */
		0x35, 0x14,
			/* ASN.1 encoded MAP payload */
			0xa1, 0x12,
				0x02, 0x01, /* Component: invoke */
				0x01, /* invokeID = 1 */
				/* opCode: processUnstructuredSS-Request */
				0x02, 0x01, 0x3b, 0x30, 0x0a, 0x04, 0x01, 0x0f,
				0x04, 0x05, 0xaa, 0x18, 0x0c, 0x36, 0x02,
	};

	static const uint8_t send_ussd_res[] = {
		0x22, /* OSMO_GSUP_MSGT_PROC_SS_RESULT */
		TEST_IMSI_IE,

		/* Session ID and state */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x03,

		/* SS/USSD information IE */
		0x35, 0x08,
			/* ASN.1 encoded MAP payload */
			0xa3, 0x06,
				0x02, 0x01, /* Component: returnError */
				0x01, /* invokeID = 1 */
				/* localValue: unknownAlphabet */
				0x02, 0x01, 0x47,
	};

	static const uint8_t send_mo_forward_sm_req[] = {
		0x24, /* OSMO_GSUP_MSGT_MO_FORWARD_SM_REQUEST */
		TEST_IMSI_IE,

		/* SM related IEs */
		0x40, 0x01, /* SM-RP-MR (Message Reference) */
			0xfa,
		0x41, 0x08, /* SM-RP-DA (Destination Address) */
			0x03, /* SMSC address */
				0x91, 0x52, 0x75, 0x47, 0x99, 0x09, 0x82,
		0x42, 0x01, /* SM-RP-OA (Originating Address) */
			0xff, /* Special case: noSM-RP-OA */
		0x43, 0x04, /* SM-RP-UI (TPDU) */
			0xde, 0xad, 0xbe, 0xef,
	};

	static const uint8_t send_mt_forward_sm_req[] = {
		0x28, /* OSMO_GSUP_MSGT_MT_FORWARD_SM_REQUEST */
		TEST_IMSI_IE,

		/* SM related IEs */
		0x40, 0x01, /* SM-RP-MR (Message Reference) */
			0xfa,
		0x41, 0x09, /* SM-RP-DA (Destination Address) */
			0x01, /* IMSI */
				0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xf5,
		0x42, 0x08, /* SM-RP-OA (Originating Address) */
			0x03, /* SMSC address */
				0x91, 0x52, 0x75, 0x47, 0x99, 0x09, 0x82,
		0x43, 0x04, /* SM-RP-UI (TPDU) */
			0xde, 0xad, 0xbe, 0xef,
		0x45, 0x01, /* SM-RP-MMS (More Messages to Send) */
			0x01,
	};

	static const uint8_t send_mo_mt_forward_sm_err[] = {
		0x25, /* OSMO_GSUP_MSGT_MO_FORWARD_SM_ERROR */
		TEST_IMSI_IE,

		/* SM related IEs */
		0x40, 0x01, /* SM-RP-MR (Message Reference) */
			0xfa,
		0x44, 0x01, /* SM-RP-Cause value */
			0xaf,
	};

	static const uint8_t send_mo_mt_forward_sm_rsp[] = {
		0x2a, /* OSMO_GSUP_MSGT_MT_FORWARD_SM_RESULT */
		TEST_IMSI_IE,

		/* SM related IEs */
		0x40, 0x01, /* SM-RP-MR (Message Reference) */
			0xfa,
		0x43, 0x04, /* SM-RP-UI (TPDU) */
			0xde, 0xad, 0xbe, 0xef,
	};

	static const uint8_t send_ready_for_sm_ind[] = {
		0x2c, /* OSMO_GSUP_MSGT_READY_FOR_SM_REQUEST */
		TEST_IMSI_IE,

		/* SM related IEs */
		0x46, 0x01, /* Alert reason */
			0x02, /* Memory Available (SMMA) */
	};

	static const uint8_t send_check_imei_req[] = {
		0x30, /* OSMO_GSUP_MSGT_CHECK_IMEI_REQUEST */
		TEST_IMSI_IE,

		/* imei */
		0x50, 0x09,
			0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	};

	static const uint8_t send_check_imei_err[] = {
		0x31, /* OSMO_GSUP_MSGT_CHECK_IMEI_ERROR */
		TEST_IMSI_IE,

		/* cause */
		0x02, 0x01,
			0x60, /* GMM_CAUSE_INV_MAND_INFO */
	};

	static const uint8_t send_check_imei_res[] = {
		0x32, /* OSMO_GSUP_MSGT_CHECK_IMEI_RESULT */
		TEST_IMSI_IE,

		/* imei_result */
		0x51, 0x01,
			0x00, /* OSMO_GSUP_IMEI_RESULT_ACK */
	};

	/* Handover related test messages. Oftentimes they only differ in the
	 * AN_APDU_IE, which is mostly a blob in GSUP. To give a better example
	 * of how the messages can be used, I've added the information an_apdu
	 * holds in brackets (see osmo-msc.git's doc/interMSC_HO_GSUP_msgs.txt).
	 * The session states are from the ASCII art in this e-mail:
	 * https://lists.osmocom.org/pipermail/openbsc/2019-January/012653.html */
	static const uint8_t send_e_prepare_handover_req[] = {
		0x34, /* OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_REQUEST */
		TEST_IMSI_IE,

		/* Session ID and state (begin) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x01,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,
		TEST_AN_APDU_IE, /* (Handover Request) */
	};

	static const uint8_t send_e_prepare_handover_err[] = {
		0x35, /* OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_ERROR */
		TEST_IMSI_IE,

		/* Session ID and state (continue) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x02,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,

		/* cause_bssap */
		0x64, 0x01,
			0x51, /* GSM0808_CAUSE_INVALID_MESSAGE_CONTENTS */
	};

	static const uint8_t send_e_prepare_handover_res[] = {
		0x36, /* OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_RESULT */
		TEST_IMSI_IE,
		TEST_MSISDN_IE, /* (Handover Number) */

		/* Session ID and state (continue) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x02,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,
		TEST_AN_APDU_IE, /* (Handover Request Ack) */
	};

	static const uint8_t send_e_prepare_subsequent_handover_req[] = {
		0x38, /* OSMO_GSUP_MSGT_E_PREPARE_SUBSEQUENT_HANDOVER_REQUEST */
		TEST_IMSI_IE,

		/* Session ID and state (begin) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x01,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,
		TEST_AN_APDU_IE, /* (Handover Required) */
	};

	static const uint8_t send_e_prepare_subsequent_handover_err[] = {
		0x39, /* OSMO_GSUP_MSGT_E_PREPARE_SUBSEQUENT_HANDOVER_ERROR */
		TEST_IMSI_IE,

		/* Session ID and state (continue) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x02,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,

		/* cause_bssap */
		0x64, 0x01,
			0x51, /* GSM0808_CAUSE_INVALID_MESSAGE_CONTENTS */
	};

	static const uint8_t send_e_prepare_subsequent_handover_res[] = {
		0x3A, /* OSMO_GSUP_MSGT_E_PREPARE_SUBSEQUENT_HANDOVER_RESULT */
		TEST_IMSI_IE,

		/* Session ID and state (continue) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x02,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,
		TEST_AN_APDU_IE, /* (Handover Request Ack) */
	};

	static const uint8_t send_e_send_end_signal_req[] = {
		0x3C, /* OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_REQUEST */
		TEST_IMSI_IE,

		/* Session ID and state (end) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x03,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,
		TEST_AN_APDU_IE, /* (Handover Complete) */
	};

	static const uint8_t send_e_send_end_signal_err[] = {
		0x3D, /* OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_ERROR */
		TEST_IMSI_IE,

		/* Session ID and state (continue) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x02,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,

		/* cause_bssap */
		0x64, 0x01,
			0x51, /* GSM0808_CAUSE_INVALID_MESSAGE_CONTENTS */
	};

	static const uint8_t send_e_process_access_signalling_req[] = {
		0x40, /* OSMO_GSUP_MSGT_E_PROCESS_ACCESS_SIGNALLING_REQUEST */
		TEST_IMSI_IE,

		/* Session ID and state (continue) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x02,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,
		TEST_AN_APDU_IE, /* (Handover Detect) */
	};

	static const uint8_t send_e_send_end_signal_res[] = {
		0x3E, /* OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_RESULT */
		TEST_IMSI_IE,

		/* Session ID and state (end) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x03,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,
		TEST_AN_APDU_IE, /* (Handover Complete) */
	};

	static const uint8_t send_e_forward_access_signalling_req [] = {
		0x44, /* OSMO_GSUP_MSGT_E_FORWARD_ACCESS_SIGNALLING_REQUEST */
		TEST_IMSI_IE,

		/* Session ID and state (continue) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x02,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,
		TEST_AN_APDU_IE, /* (DTAP, e.g. CC, SMS, ...) */
	};

	static const uint8_t send_e_close[] = {
		0x47, /* OSMO_GSUP_MSGT_E_CLOSE */
		TEST_IMSI_IE,

		/* Session ID and state (end) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x03,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,
	};

	static const uint8_t send_e_abort[] = {
		0x4B, /* OSMO_GSUP_MSGT_E_ABORT */
		TEST_IMSI_IE,

		/* Session ID and state (end) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x03,

		TEST_CLASS_INTER_MSC_IE,

		/* cause_bssap */
		0x64, 0x01,
			0x51, /* GSM0808_CAUSE_INVALID_MESSAGE_CONTENTS */
	};

	static const uint8_t send_e_routing_error[] = {
		0x4E, /* OSMO_GSUP_MSGT_E_ROUTING_ERROR */
		TEST_IMSI_IE,

		/* Session ID and state (end) */
		0x30, 0x04, 0xde, 0xad, 0xbe, 0xef,
		0x31, 0x01, 0x03,

		TEST_CLASS_INTER_MSC_IE,
		TEST_SOURCE_NAME_IE,
		TEST_DESTINATION_NAME_IE,
	};

	static const struct test {
		char *name;
		const uint8_t *data;
		size_t data_len;
	} test_messages[] = {
		{"Send Authentication Info Request",
			send_auth_info_req, sizeof(send_auth_info_req)},
		{"Send Authentication Info Error",
			send_auth_info_err, sizeof(send_auth_info_err)},
		{"Send Authentication Info Result",
			send_auth_info_res, sizeof(send_auth_info_res)},
		{"Update Location Request",
			update_location_req, sizeof(update_location_req)},
		{"Update Location Error",
			update_location_err, sizeof(update_location_err)},
		{"Update Location Result",
			update_location_res, sizeof(update_location_res)},
		{"Location Cancellation Request",
			location_cancellation_req, sizeof(location_cancellation_req)},
		{"Location Cancellation Error",
			location_cancellation_err, sizeof(location_cancellation_err)},
		{"Location Cancellation Result",
			location_cancellation_res, sizeof(location_cancellation_res)},
		{"Purge MS Request",
			purge_ms_req, sizeof(purge_ms_req)},
		{"Purge MS Error",
			purge_ms_err, sizeof(purge_ms_err)},
		{"Purge MS Result",
			purge_ms_res, sizeof(purge_ms_res)},
		{"Send Authentication Info Result with IK, CK, AUTN and RES (UMTS)",
			send_auth_info_res_umts, sizeof(send_auth_info_res_umts)},
		{"Send Authentication Info Request with AUTS and RAND (UMTS)",
			send_auth_info_req_auts, sizeof(send_auth_info_req_auts)},
		{"Dummy message with session IEs",
			dummy_session_ies, sizeof(dummy_session_ies)},
		{"SS/USSD processUnstructuredSS-Request / Invoke",
			send_ussd_req, sizeof(send_ussd_req)},
		{"SS/USSD processUnstructuredSS-Request / ReturnResult",
			send_ussd_res, sizeof(send_ussd_res)},
		{"MO-ForwardSM (MSC -> SMSC) Request",
			send_mo_forward_sm_req, sizeof(send_mo_forward_sm_req)},
		{"MT-ForwardSM (MSC -> SMSC) Request",
			send_mt_forward_sm_req, sizeof(send_mt_forward_sm_req)},
		{"MO-/MT-ForwardSM Response",
			send_mo_mt_forward_sm_rsp, sizeof(send_mo_mt_forward_sm_rsp)},
		{"MO-/MT-ForwardSM Error",
			send_mo_mt_forward_sm_err, sizeof(send_mo_mt_forward_sm_err)},
		{"ReadyForSM (MSC -> SMSC) Indication",
			send_ready_for_sm_ind, sizeof(send_ready_for_sm_ind)},
		{"Check IMEI Request",
			send_check_imei_req, sizeof(send_check_imei_req)},
		{"Check IMEI Error",
			send_check_imei_err, sizeof(send_check_imei_err)},
		{"Check IMEI Result",
			send_check_imei_res, sizeof(send_check_imei_res)},
		{"E Prepare Handover Request",
			send_e_prepare_handover_req, sizeof(send_e_prepare_handover_req)},
		{"E Prepare Handover Error",
			send_e_prepare_handover_err, sizeof(send_e_prepare_handover_err)},
		{"E Prepare Handover Result",
			send_e_prepare_handover_res, sizeof(send_e_prepare_handover_res)},
		{"E Prepare Subsequent Handover Request",
			send_e_prepare_subsequent_handover_req, sizeof(send_e_prepare_subsequent_handover_req)},
		{"E Prepare Subsequent Handover Error",
			send_e_prepare_subsequent_handover_err, sizeof(send_e_prepare_subsequent_handover_err)},
		{"E Prepare Subsequent Handover Result",
			send_e_prepare_subsequent_handover_res, sizeof(send_e_prepare_subsequent_handover_res)},
		{"E Send End Signal Request",
			send_e_send_end_signal_req, sizeof(send_e_send_end_signal_req)},
		{"E Send End Signal Error",
			send_e_send_end_signal_err, sizeof(send_e_send_end_signal_err)},
		{"E Send End Signal Result",
			send_e_send_end_signal_res, sizeof(send_e_send_end_signal_res)},
		{"E Process Access Signalling Request",
			send_e_process_access_signalling_req, sizeof(send_e_process_access_signalling_req)},
		{"E Forward Access Signalling Request",
			send_e_forward_access_signalling_req, sizeof(send_e_forward_access_signalling_req)},
		{"E Close",
			send_e_close, sizeof(send_e_close)},
		{"E Abort",
			send_e_abort, sizeof(send_e_abort)},
		{"E Routing Error",
			send_e_routing_error, sizeof(send_e_routing_error)},
		{"Send Authentication Info Request (10 Vectors)",
			send_auth_info_req10, sizeof(send_auth_info_req10)},
	};

	printf("Test GSUP message decoding/encoding\n");

	for (test_idx = 0; test_idx < ARRAY_SIZE(test_messages); test_idx++) {
		const struct test *t = &test_messages[test_idx];
		struct osmo_gsup_message gm = {0};
		struct msgb *msg = msgb_alloc(4096, "gsup_test");
		bool passed = true;

		printf("  Testing %s\n", t->name);

		rc = osmo_gsup_decode(t->data, t->data_len, &gm);
		if (rc < 0)
			passed = false;

		rc = osmo_gsup_encode(msg, &gm);
		if (rc < 0)
			passed = false;

		fprintf(stderr, "  generated message: %s\n", msgb_hexdump(msg));
		fprintf(stderr, "  original message:  %s\n", osmo_hexdump(t->data, t->data_len));
		fprintf(stderr, "  IMSI:              %s\n", gm.imsi);

		if (strcmp(gm.imsi, TEST_IMSI_STR) != 0 ||
		    msgb_length(msg) != t->data_len ||
		    memcmp(msgb_data(msg), t->data, t->data_len) != 0)
			passed = false;

		if (passed)
			printf("          %s OK\n", t->name);
		else
			printf("          %s FAILED: %d<%s> [%u,%u,%zu,%u]\n",
			       t->name, rc, strerror(-rc),
			       strcmp(gm.imsi, TEST_IMSI_STR),
			       msgb_length(msg), t->data_len,
			       memcmp(msgb_data(msg), t->data, t->data_len));
		msgb_free(msg);
	}

	/* simple truncation test */
	for (test_idx = 0; test_idx < ARRAY_SIZE(test_messages); test_idx++) {
		int j;
		const struct test *t = &test_messages[test_idx];
		int ie_end = t->data_len;
		struct osmo_gsup_message gm = {0};
		int counter = 0;
		int parse_err = 0;

		for (j = t->data_len - 1; j >= 0; --j) {
			rc = osmo_gsup_decode(t->data, j, &gm);
			counter += 1;

			VERBOSE_FPRINTF(stderr,
				"  partial message decoding: "
				"orig_len = %d, trunc = %d, rc = %d, ie_end = %d\n",
				t->data_len, j, rc, ie_end);
			if (rc >= 0) {
				VERBOSE_FPRINTF(stderr,
					"    remaing partial message: %s\n",
					osmo_hexdump(t->data + j, ie_end - j));

				OSMO_ASSERT(j <= ie_end - 2);
				OSMO_ASSERT(t->data[j+0] < _OSMO_GSUP_IEI_END_MARKER);
				OSMO_ASSERT(t->data[j+1] <= ie_end - j - 2);

				ie_end = j;
			} else {
				parse_err += 1;
			}
		}

		fprintf(stderr,
			"  message %d: tested %d truncations, %d parse failures\n",
			test_idx, counter, parse_err);
	}

	/* Don't log thousands of message modification errors */
	LOGP(DLGSUP, LOGL_NOTICE, "Stopping DLGSUP logging\n");
	log_set_category_filter(osmo_stderr_target, DLGSUP, 0, 0);

	/* message modification test (relies on ASAN or valgrind being used) */
	for (test_idx = 0; test_idx < ARRAY_SIZE(test_messages); test_idx++) {
		int j;
		const struct test *t = &test_messages[test_idx];
		struct osmo_gsup_message gm = {0};
		uint8_t val;
		int counter = 0;
		int parse_err = 0;

		OSMO_ASSERT(sizeof(buf) >= t->data_len);

		for (j = t->data_len - 1; j >= 0; --j) {
			memcpy(buf, t->data, t->data_len);
			val = 0;
			do {
				VERBOSE_FPRINTF(stderr,
					"t = %d, len = %d, val = %d\n",
					test_idx, j, val);
				buf[j] = val;
				rc = osmo_gsup_decode(buf, t->data_len, &gm);
				counter += 1;
				if (rc < 0)
					parse_err += 1;

				val += 1;
			} while (val != (uint8_t)256);
		}

		fprintf(stderr,
			"  message %d: tested %d modifications, %d parse failures\n",
			test_idx, counter, parse_err);
	}
}

const struct log_info_cat default_categories[] = {
};

static struct log_info info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	void *ctx = talloc_named_const(NULL, 0, "gsup_test");
	osmo_init_logging2(ctx, &info);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

	test_gsup_messages_dec_enc();

	printf("Done.\n");
	return EXIT_SUCCESS;
}
