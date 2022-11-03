#include <stdio.h>

#include <osmocom/core/utils.h>
#include <osmocom/gsm/bssmap_le.h>

struct bssmap_le_pdu bssmap_le_test_pdus[] = {
	{
		.msg_type = BSSMAP_LE_MSGT_RESET,
		.reset = GSM0808_CAUSE_EQUIPMENT_FAILURE,
	},
	{
		.msg_type = BSSMAP_LE_MSGT_RESET_ACK,
	},
	{
		.msg_type = BSSMAP_LE_MSGT_PERFORM_LOC_REQ,
		.perform_loc_req = {
			.location_type = {
				.location_information = BSSMAP_LE_LOC_INFO_CURRENT_GEOGRAPHIC,
			},

			.cell_id = {
				.id_discr = CELL_IDENT_LAC_AND_CI,
				.id.lac_and_ci = {
					.lac = 23,
					.ci = 42,
				},
			},

			.lcs_client_type_present = true,
			.lcs_client_type = BSSMAP_LE_LCS_CTYPE_VALUE_ADDED_UNSPECIFIED,

			.imsi = {
				.type = GSM_MI_TYPE_IMSI,
				.imsi = "1234567890",
			},

			.imei = {
				.type = GSM_MI_TYPE_IMEI,
				.imei = "123456789012345",
			},

			.apdu_present = true,
			.apdu = {
				.msg_type = BSSLAP_MSGT_TA_LAYER3,
				.ta_layer3 = {
					.ta = 23,
				},
			},
		},
	},
	{
		.msg_type = BSSMAP_LE_MSGT_PERFORM_LOC_RESP,
		.perform_loc_resp = {
			.location_estimate_present = true,
			.location_estimate = {
				.ell_point_unc_circle = {
					.h = { .type = GAD_TYPE_ELL_POINT_UNC_CIRCLE },
					.lat = { 1, 2, 3 },
					.lon = { 4, 5, 6 },
					.unc = 123,
				},
			},
		},
	},
	{
		.msg_type = BSSMAP_LE_MSGT_PERFORM_LOC_RESP,
		.perform_loc_resp = {
			.lcs_cause = {
				.present = true,
				.cause_val = LCS_CAUSE_REQUEST_ABORTED,
			},
		},
	},
	{
		.msg_type = BSSMAP_LE_MSGT_PERFORM_LOC_RESP,
		.perform_loc_resp = {
			.lcs_cause = {
				.present = true,
				.cause_val = LCS_CAUSE_POS_METH_FAILURE,
				.diag_val_present = true,
				.diag_val = 23,
			},
		},
	},
	{
		.msg_type = BSSMAP_LE_MSGT_PERFORM_LOC_ABORT,
		.perform_loc_abort = {
			.present = true,
			.cause_val = LCS_CAUSE_REQUEST_ABORTED,
		},
	},
	{
		.msg_type = BSSMAP_LE_MSGT_CONN_ORIENTED_INFO,
		.conn_oriented_info = {
			.apdu = {
				.msg_type = BSSLAP_MSGT_TA_REQUEST,
			},
		},
	},
	{
		.msg_type = BSSMAP_LE_MSGT_CONN_ORIENTED_INFO,
		.conn_oriented_info = {
			.apdu = {
				.msg_type = BSSLAP_MSGT_TA_RESPONSE,
				.ta_response = {
					.cell_id = 23,
					.ta = 42,
				},
			},
		},
	},
	{
		.msg_type = BSSMAP_LE_MSGT_CONN_ORIENTED_INFO,
		.conn_oriented_info = {
			.apdu = {
				.msg_type = BSSLAP_MSGT_REJECT,
				.reject = BSSLAP_CAUSE_CONGESTION,
			},
		},
	},
	{
		.msg_type = BSSMAP_LE_MSGT_PERFORM_LOC_REQ,
		.perform_loc_req = {
			.location_type = {
				.location_information = BSSMAP_LE_LOC_INFO_CURRENT_GEOGRAPHIC,
			},

			.cell_id = {
				.id_discr = CELL_IDENT_LAC_AND_CI,
				.id.lac_and_ci = {
					.lac = 23,
					.ci = 42,
				},
			},

			.lcs_client_type_present = true,
			.lcs_client_type = BSSMAP_LE_LCS_CTYPE_EMERG_SVC_UNSPECIFIED,

			.more_items = true,

			.lcs_priority_present = true,
			.lcs_priority = 0x00, /* highest */

			.lcs_qos_present = true,
			.lcs_qos = {
				.ha_ind = 1,
				.ha_val = 0x12,
			},
		},
	},
};

void test_bssmap_le_enc_dec(void)
{
	struct bssmap_le_pdu *pdu;
	printf("--- %s\n", __func__);

	for (pdu = bssmap_le_test_pdus; (pdu - bssmap_le_test_pdus) < ARRAY_SIZE(bssmap_le_test_pdus); pdu++) {
		struct msgb *msg;
		struct bssap_le_pdu enc_pdu = {
			.discr = BSSAP_LE_MSG_DISCR_BSSMAP_LE,
			.bssmap_le = *pdu,
		};
		struct bssap_le_pdu dec_pdu;
		struct osmo_bssap_le_err *err = NULL;
		void *loop_ctx;
		int rc;

		msg = osmo_bssap_le_enc(&enc_pdu);
		if (!msg) {
			printf("[%td] %s: ERROR: failed to encode pdu\n", (pdu - bssmap_le_test_pdus),
			       osmo_bssmap_le_msgt_name(pdu->msg_type));
			goto loop_end;
		}
		loop_ctx = msg;

		memset(&dec_pdu, 0xff, sizeof(dec_pdu));
		rc = osmo_bssap_le_dec(&dec_pdu, &err, loop_ctx, msg);
		if (rc) {
			printf("[%td] %s: ERROR: failed to decode pdu: %s\n", (pdu - bssmap_le_test_pdus),
			       osmo_bssmap_le_msgt_name(pdu->msg_type), err->logmsg);
			printf("     encoded data: %s\n", osmo_hexdump(msg->data, msg->len));
			goto loop_end;
		}

		if (memcmp(&enc_pdu, &dec_pdu, sizeof(dec_pdu))) {
			printf("[%td] %s: ERROR: decoded PDU != encoded PDU\n", (pdu - bssmap_le_test_pdus),
			       osmo_bssmap_le_msgt_name(pdu->msg_type));
			printf("     original struct: %s\n", osmo_hexdump((void*)&enc_pdu, sizeof(enc_pdu)));
			printf("      decoded struct: %s\n", osmo_hexdump((void*)&dec_pdu, sizeof(dec_pdu)));
			printf("        encoded data: %s\n", osmo_hexdump(msg->data, msg->len));
			goto loop_end;
		}

		printf("[%td] %s: ok (encoded len = %d)\n", (pdu - bssmap_le_test_pdus),
		       osmo_bssmap_le_msgt_name(pdu->msg_type), msg->len);

loop_end:
		msgb_free(msg);
	}
}

int main(int argc, char **argv)
{
	test_bssmap_le_enc_dec();
	return 0;
}
