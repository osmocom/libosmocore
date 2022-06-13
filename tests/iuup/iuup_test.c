#include <stdint.h>
#include <stdio.h>

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/select.h>

#include <osmocom/gsm/prim.h>
#include <osmocom/gsm/iuup.h>

static void *iuup_test_ctx;

static struct osmo_iuup_rnl_config def_configure_req = {
	.transparent = false,
	.active = true,
	.supported_versions_mask = 0x0001,
	.num_rfci = 3,
	.num_subflows = 3,
	.IPTIs_present = true,
	.rfci = {
		{.used = 1, .id = 0, .IPTI = 1, .subflow_sizes = {81, 103, 60} },
		{.used = 1, .id = 1, .IPTI = 7, .subflow_sizes = {39, 0, 0} },
		{.used = 1, .id = 2, .IPTI = 1, .subflow_sizes = {0, 0, 0} },
	},
	/* .delivery_err_sdu = All set to 0 (YES) by default, */
	.IPTIs_present = true,
	.t_init = { .t_ms = IUUP_TIMER_INIT_T_DEFAULT, .n_max = IUUP_TIMER_INIT_N_DEFAULT },
	.t_ta = { .t_ms = IUUP_TIMER_TA_T_DEFAULT, .n_max = IUUP_TIMER_TA_N_DEFAULT },
	.t_rc = { .t_ms = IUUP_TIMER_RC_T_DEFAULT, .n_max = IUUP_TIMER_RC_N_DEFAULT },
};

/*  Frame 33, "Initialization",  OS#4744 3g_call_23112021.pcapng
IuUP
	1110 .... = PDU Type: Control Procedure (14)
	.... 00.. = Ack/Nack: Procedure (0)
	.... ..00 = Frame Number: 0
	0000 .... = Mode Version: 0x0
	.... 0000 = Procedure: Initialization (0)
	1101 11.. = Header CRC: 0x37 [correct]
	.... ..11 1001 1001 = Payload CRC: 0x399
	000. .... = Spare: 0x0
	...1 .... = TI: IPTIs present in frame (1)
	.... 011. = Subflows: 3
	.... ...0 = Chain Indicator: this frame is the last frame for the procedure (0)
	RFCI 0 Initialization
		0... .... = RFCI 0 LRI: Not last RFCI (0x0)
		.0.. .... = RFCI 0 LI: one octet used (0x0)
		..00 0000 = RFCI 0: 0
		RFCI 0 Flow 0 Len: 81
		RFCI 0 Flow 1 Len: 103
		RFCI 0 Flow 2 Len: 60
	RFCI 1 Initialization
		0... .... = RFCI 1 LRI: Not last RFCI (0x0)
		.0.. .... = RFCI 1 LI: one octet used (0x0)
		..00 0001 = RFCI 1: 1
		RFCI 1 Flow 0 Len: 39
		RFCI 1 Flow 1 Len: 0
		RFCI 1 Flow 2 Len: 0
	RFCI 2 Initialization
		1... .... = RFCI 2 LRI: Last RFCI in current frame (0x1)
		.0.. .... = RFCI 2 LI: one octet used (0x0)
		..00 0010 = RFCI 2: 2
		RFCI 2 Flow 0 Len: 0
		RFCI 2 Flow 1 Len: 0
		RFCI 2 Flow 2 Len: 0
	IPTIs
		0001 .... = RFCI 0 IPTI: 0x1
		.... 0111 = RFCI 1 IPTI: 0x7
		0001 .... = RFCI 2 IPTI: 0x1
	Iu UP Mode Versions Supported: 0x0001
		0... .... .... .... = Version 16: not supported (0x0)
		.0.. .... .... .... = Version 15: not supported (0x0)
		..0. .... .... .... = Version 14: not supported (0x0)
		...0 .... .... .... = Version 13: not supported (0x0)
		.... 0... .... .... = Version 12: not supported (0x0)
		.... .0.. .... .... = Version 11: not supported (0x0)
		.... ..0. .... .... = Version 10: not supported (0x0)
		.... ...0 .... .... = Version  9: not supported (0x0)
		.... .... 0... .... = Version  8: not supported (0x0)
		.... .... .0.. .... = Version  7: not supported (0x0)
		.... .... ..0. .... = Version  6: not supported (0x0)
		.... .... ...0 .... = Version  5: not supported (0x0)
		.... .... .... 0... = Version  4: not supported (0x0)
		.... .... .... .0.. = Version  3: not supported (0x0)
		.... .... .... ..0. = Version  2: not supported (0x0)
		.... .... .... ...1 = Version  1: supported (0x1)
	0000 .... = RFCI Data Pdu Type: PDU type 0 (0x0)
*/
static const uint8_t iuup_initialization[] = {
	0xe0, 0x00, 0xdf, 0x99, 0x16, 0x00, 0x51, 0x67, 0x3c, 0x01, 0x27, 0x00,
	0x00, 0x82, 0x00, 0x00, 0x00, 0x17, 0x10, 0x00, 0x01, 0x00
};

/*  Frame 87, "Data RFCI=0 FN = 1",  OS#4744 3g_call_23112021.pcapng
IuUP
	0000 .... = PDU Type: Data with CRC (0)
	.... 0001 = Frame Number: 1
	00.. .... = FQC: Frame Good (0)
	..00 0000 = RFCI: 0x00
	1110 00.. = Header CRC: 0x38 [correct]
	.... ..11 1111 1111 = Payload CRC: 0x3ff
	Payload Data: 08556d944c71a1a081e7ead204244480000ecd82b81118000097c4794e7740
*/
static const uint8_t iuup_data[] = {
	0x01, 0x00, 0xe3, 0xff, /*payload starts here: */ 0x08, 0x55, 0x6d, 0x94, 0x4c, 0x71, 0xa1, 0xa0,
	0x81, 0xe7, 0xea, 0xd2, 0x04, 0x24, 0x44, 0x80, 0x00, 0x0e, 0xcd, 0x82,
	0xb8, 0x11, 0x18, 0x00, 0x00, 0x97, 0xc4, 0x79, 0x4e, 0x77, 0x40
};

#define IUUP_MSGB_SIZE 4096

static struct osmo_iuup_tnl_prim *itp_ctrl_nack_alloc(enum iuup_procedure proc_ind, enum iuup_error_cause error_cause, uint8_t fn)
{
	struct osmo_iuup_tnl_prim *tnp;
	struct iuup_ctrl_nack *nack;
	tnp = osmo_iuup_tnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION, IUUP_MSGB_SIZE);
	tnp->oph.msg->l2h = msgb_put(tnp->oph.msg, sizeof(struct iuup_ctrl_nack));
	nack = (struct iuup_ctrl_nack *) msgb_l2(tnp->oph.msg);
	*nack = (struct iuup_ctrl_nack){
		.hdr = {
			.frame_nr = fn,
			.ack_nack = IUUP_AN_NACK,
			.pdu_type = IUUP_PDU_T_CONTROL,
			.proc_ind = proc_ind,
			.mode_version = 0,
			.payload_crc_hi = 0,
			.header_crc = 0,
			.payload_crc_lo = 0,
		},
		.spare = 0,
		.error_cause = error_cause,
	};
	nack->hdr.header_crc = osmo_iuup_compute_header_crc(msgb_l2(tnp->oph.msg), msgb_l2len(tnp->oph.msg));
	return tnp;
}

static struct osmo_iuup_tnl_prim *itp_ctrl_ack_alloc(enum iuup_procedure proc_ind, uint8_t fn)
{
	struct osmo_iuup_tnl_prim *tnp;
	struct iuup_ctrl_ack *ack;
	tnp = osmo_iuup_tnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION, IUUP_MSGB_SIZE);
	tnp->oph.msg->l2h = msgb_put(tnp->oph.msg, sizeof(struct iuup_ctrl_ack));
	ack = (struct iuup_ctrl_ack *) msgb_l2(tnp->oph.msg);
	*ack = (struct iuup_ctrl_ack){
		.hdr = {
			.frame_nr = fn,
			.ack_nack = IUUP_AN_ACK,
			.pdu_type = IUUP_PDU_T_CONTROL,
			.proc_ind = proc_ind,
			.mode_version = 0,
			.payload_crc_hi = 0,
			.header_crc = 0,
			.payload_crc_lo = 0,
		},
	};
	ack->hdr.header_crc = osmo_iuup_compute_header_crc(msgb_l2(tnp->oph.msg), msgb_l2len(tnp->oph.msg));
	return tnp;
}

static void clock_override_set(long sec, long usec)
{
	osmo_gettimeofday_override_time.tv_sec = sec + usec / (1000*1000);
	osmo_gettimeofday_override_time.tv_usec = usec % (1000*1000);
	printf("sys={%lu.%06lu}, %s\n", osmo_gettimeofday_override_time.tv_sec,
		osmo_gettimeofday_override_time.tv_usec, __func__);
}

void test_crc(void)
{
	int rc;

	/* Frame 34, "Initialization ACK",  OS#4744 3g_call_23112021.pcapng */
	static const uint8_t iuup_initialization_ack[] = {
		0xe4, 0x00, 0xdf, 0x99, 0x16, 0x00, 0x51, 0x67, 0x3c, 0x01, 0x27, 0x00,
		0x00, 0x82, 0x00, 0x00, 0x00, 0x17, 0x10, 0x00, 0x01, 0x00
	};

	printf("=== start: %s ===\n", __func__);

	rc = osmo_iuup_compute_header_crc(iuup_initialization, sizeof(iuup_initialization));
	printf("iuup_initialization: Header CRC = 0x%02x\n", rc);
	rc = osmo_iuup_compute_payload_crc(iuup_initialization, sizeof(iuup_initialization));
	printf("iuup_initialization: Payload CRC = 0x%03x\n", rc);

	rc = osmo_iuup_compute_header_crc(iuup_initialization_ack, sizeof(iuup_initialization_ack));
	printf("iuup_initialization_ack: Header CRC = 0x%02x\n", rc);
	rc = osmo_iuup_compute_payload_crc(iuup_initialization_ack, sizeof(iuup_initialization_ack));
	printf("iuup_initialization_ack: Payload CRC = 0x%03x\n", rc);

	printf("=== end: %s ===\n", __func__);
}


/****************************
 * test_tinit_timeout_retrans
 ****************************/
static unsigned int _tinit_timeout_retrans_user_rx_prim = 0;
static int _tinit_timeout_retrans_user_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_iuup_rnl_prim *irp = (struct osmo_iuup_rnl_prim *)oph;
	printf("%s()\n", __func__);

	OSMO_ASSERT(OSMO_PRIM_HDR(&irp->oph) == OSMO_PRIM(OSMO_IUUP_RNL_STATUS, PRIM_OP_INDICATION));

	OSMO_ASSERT(irp->u.status.procedure == IUUP_PROC_ERR_EVENT);
	OSMO_ASSERT(irp->u.status.u.error_event.cause == IUUP_ERR_CAUSE_INIT_FAILURE_NET_TMR);
	OSMO_ASSERT(irp->u.status.u.error_event.distance == IUUP_ERR_DIST_LOCAL);
	_tinit_timeout_retrans_user_rx_prim++;
	msgb_free(oph->msg);
	return 0;
}
static unsigned int _tinit_timeout_retrans_transport_rx_prim = 0;
static int _tinit_timeout_retrans_transport_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_iuup_tnl_prim *itp = (struct osmo_iuup_tnl_prim *)oph;
	struct msgb *msg = oph->msg;

	printf("%s()\n", __func__);
	OSMO_ASSERT(OSMO_PRIM_HDR(&itp->oph) == OSMO_PRIM(OSMO_IUUP_TNL_UNITDATA, PRIM_OP_REQUEST));
	printf("Transport: DL len=%u: %s\n", msgb_l2len(msg),
	       osmo_hexdump((const unsigned char *) msgb_l2(msg), msgb_l2len(msg)));
	_tinit_timeout_retrans_transport_rx_prim++;

	msgb_free(msg);
	return 0;
}
void test_tinit_timeout_retrans(void)
{
	struct osmo_iuup_instance *iui;
	struct osmo_iuup_rnl_prim *rnp;
	int rc, i;

	iui = osmo_iuup_instance_alloc(iuup_test_ctx, __func__);
	OSMO_ASSERT(iui);
	osmo_iuup_instance_set_user_prim_cb(iui, _tinit_timeout_retrans_user_prim_cb, NULL);
	osmo_iuup_instance_set_transport_prim_cb(iui, _tinit_timeout_retrans_transport_prim_cb, NULL);

	clock_override_set(0, 0);

	/* Tx CONFIG.req */
	rnp = osmo_iuup_rnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_RNL_CONFIG, PRIM_OP_REQUEST, IUUP_MSGB_SIZE);
	rnp->u.config = def_configure_req;
	OSMO_ASSERT((rc = osmo_iuup_rnl_prim_down(iui, rnp)) == 0);
	/* STATUS-INIT.req is transmitted automatically: */
	OSMO_ASSERT(_tinit_timeout_retrans_transport_rx_prim == 1);

	/* After one sec, INITIALIZATION msg is retransmitted */
	for (i = 1; i < IUUP_TIMER_INIT_N_DEFAULT + 1; i++) {
		clock_override_set(0, IUUP_TIMER_INIT_T_DEFAULT*1000 * i);
		osmo_select_main(0);
		OSMO_ASSERT(_tinit_timeout_retrans_transport_rx_prim == i + 1);
	}
	/* Last one should send an error event: */
	OSMO_ASSERT(_tinit_timeout_retrans_user_rx_prim == 0);
	clock_override_set(0, IUUP_TIMER_INIT_T_DEFAULT*1000 * i);
	osmo_select_main(0);
	OSMO_ASSERT(_tinit_timeout_retrans_transport_rx_prim == i);
	OSMO_ASSERT(_tinit_timeout_retrans_user_rx_prim == 1);

	/* Nothing else is received afterwards. osmo_select_main() will block forever. */
	/*clock_override_set(i + 1, 0);
	osmo_select_main(0);
	OSMO_ASSERT(_tinit_timeout_retrans_transport_rx_prim == i);
	OSMO_ASSERT(_tinit_timeout_retrans_user_rx_prim == 1);*/

	osmo_iuup_instance_free(iui);
}

/****************************
 * test_tinit_nack
 ****************************/
static unsigned int _init_nack_retrans_user_rx_prim = 0;
static int _init_nack_retrans_user_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_iuup_rnl_prim *irp = (struct osmo_iuup_rnl_prim *)oph;

	printf("%s()\n", __func__);

	OSMO_ASSERT(OSMO_PRIM_HDR(&irp->oph) == OSMO_PRIM(OSMO_IUUP_RNL_STATUS, PRIM_OP_INDICATION));

	OSMO_ASSERT(irp->u.status.procedure == IUUP_PROC_ERR_EVENT);
	OSMO_ASSERT(irp->u.status.u.error_event.cause == IUUP_ERR_CAUSE_INIT_FAILURE_REP_NACK);
	OSMO_ASSERT(irp->u.status.u.error_event.distance == IUUP_ERR_DIST_SECOND_FWD);
	_init_nack_retrans_user_rx_prim++;
	msgb_free(oph->msg);
	return 0;
}
static int _init_nack_retrans_transport_rx_prim = 0;
static int _init_nack_retrans_transport_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_iuup_tnl_prim *itp = (struct osmo_iuup_tnl_prim *)oph;
	struct msgb *msg = oph->msg;

	printf("%s()\n", __func__);
	OSMO_ASSERT(OSMO_PRIM_HDR(&itp->oph) == OSMO_PRIM(OSMO_IUUP_TNL_UNITDATA, PRIM_OP_REQUEST));
	printf("Transport: DL len=%u: %s\n", msgb_l2len(msg),
	       osmo_hexdump((const unsigned char *) msgb_l2(msg), msgb_l2len(msg)));
	_init_nack_retrans_transport_rx_prim++;

	msgb_free(msg);
	return 0;
}
void test_init_nack_retrans(void)
{
	struct osmo_iuup_instance *iui;
	struct osmo_iuup_rnl_prim *rnp;
	struct osmo_iuup_tnl_prim *tnp;
	int rc, i;

	iui = osmo_iuup_instance_alloc(iuup_test_ctx, __func__);
	OSMO_ASSERT(iui);
	osmo_iuup_instance_set_user_prim_cb(iui, _init_nack_retrans_user_prim_cb, NULL);
	osmo_iuup_instance_set_transport_prim_cb(iui, _init_nack_retrans_transport_prim_cb, NULL);

	clock_override_set(0, 0);

	/* Tx CONFIG.req */
	rnp = osmo_iuup_rnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_RNL_CONFIG, PRIM_OP_REQUEST, IUUP_MSGB_SIZE);
	rnp->u.config = def_configure_req;
	OSMO_ASSERT((rc = osmo_iuup_rnl_prim_down(iui, rnp)) == 0);
	/* STATUS-INIT.req is transmitted automatically: */
	OSMO_ASSERT(_init_nack_retrans_transport_rx_prim == 1);

	/* After one sec, INITIALIZATION msg is retransmitted */
	for (i = 1; i < IUUP_TIMER_INIT_N_DEFAULT + 1; i++) {
		/* Send NACK: */
		tnp = itp_ctrl_nack_alloc(IUUP_PROC_INIT, IUUP_ERR_CAUSE_MODE_VERSION_NOT_SUPPORTED, 0);
		OSMO_ASSERT((rc = osmo_iuup_tnl_prim_up(iui, tnp)) == 0);
		/* A new INIT is retransmitted: */
		OSMO_ASSERT(_init_nack_retrans_transport_rx_prim == i + 1);
	}
	/* Last one should send an error event: */
	OSMO_ASSERT(_init_nack_retrans_user_rx_prim == 0);
	tnp = itp_ctrl_nack_alloc(IUUP_PROC_INIT, IUUP_ERR_CAUSE_MODE_VERSION_NOT_SUPPORTED, 0);
	OSMO_ASSERT((rc = osmo_iuup_tnl_prim_up(iui, tnp)) == 0);
	OSMO_ASSERT(_init_nack_retrans_transport_rx_prim == i);
	OSMO_ASSERT(_init_nack_retrans_user_rx_prim == 1);

	/* Nothing else is received afterwards. osmo_select_main() will block forever. */

	osmo_iuup_instance_free(iui);
}


/****************************
 * test_init_ack
 ****************************/
static unsigned int _init_ack_user_rx_prim = 0;
static int _init_ack_user_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_iuup_rnl_prim *irp = (struct osmo_iuup_rnl_prim *)oph;
	struct msgb *msg = oph->msg;

	printf("%s()\n", __func__);

	OSMO_ASSERT(OSMO_PRIM_HDR(&irp->oph) == OSMO_PRIM(OSMO_IUUP_RNL_DATA, PRIM_OP_INDICATION));
	printf("User: UL len=%u: %s\n", msgb_l3len(msg),
	       osmo_hexdump((const unsigned char *) msgb_l3(msg), msgb_l3len(msg)));

	_init_ack_user_rx_prim++;
	msgb_free(oph->msg);
	return 0;
}
static int _init_ack_transport_rx_prim = 0;
static int _init_ack_transport_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_iuup_tnl_prim *itp = (struct osmo_iuup_tnl_prim *)oph;
	struct msgb *msg = oph->msg;

	printf("%s()\n", __func__);
	OSMO_ASSERT(OSMO_PRIM_HDR(&itp->oph) == OSMO_PRIM(OSMO_IUUP_TNL_UNITDATA, PRIM_OP_REQUEST));
	printf("Transport: DL len=%u: %s\n", msgb_l2len(msg),
	       osmo_hexdump((const unsigned char *) msgb_l2(msg), msgb_l2len(msg)));
	_init_ack_transport_rx_prim++;

	msgb_free(msg);
	return 0;
}
void test_init_ack(void)
{
	struct osmo_iuup_instance *iui;
	struct osmo_iuup_rnl_prim *rnp;
	struct osmo_iuup_tnl_prim *tnp;
	struct iuup_pdutype0_hdr *hdr0;
	int rc;

	iui = osmo_iuup_instance_alloc(iuup_test_ctx, __func__);
	OSMO_ASSERT(iui);
	osmo_iuup_instance_set_user_prim_cb(iui, _init_ack_user_prim_cb, NULL);
	osmo_iuup_instance_set_transport_prim_cb(iui, _init_ack_transport_prim_cb, NULL);

	clock_override_set(0, 0);

	/* Tx CONFIG.req */
	rnp = osmo_iuup_rnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_RNL_CONFIG, PRIM_OP_REQUEST, IUUP_MSGB_SIZE);
	rnp->u.config = def_configure_req;
	OSMO_ASSERT((rc = osmo_iuup_rnl_prim_down(iui, rnp)) == 0);
	/* STATUS-INIT.req is transmitted automatically: */
	OSMO_ASSERT(_init_ack_transport_rx_prim == 1);

	/* Send ACK: */
	tnp = itp_ctrl_ack_alloc(IUUP_PROC_INIT, 0);
	OSMO_ASSERT((rc = osmo_iuup_tnl_prim_up(iui, tnp)) == 0);
	OSMO_ASSERT(_init_ack_transport_rx_prim == 1); /* Make sure there's no retrans */
	OSMO_ASSERT(_init_ack_user_rx_prim == 0); /* Make sure there's no error event */

	/* Send IuUP incoming data to the implementation: */
	tnp = osmo_iuup_tnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION, IUUP_MSGB_SIZE);
	tnp->oph.msg->l2h = msgb_put(tnp->oph.msg, sizeof(iuup_data));
	hdr0 = (struct iuup_pdutype0_hdr *)msgb_l2(tnp->oph.msg);
	memcpy(hdr0, iuup_data, sizeof(iuup_data));
	OSMO_ASSERT((rc = osmo_iuup_tnl_prim_up(iui, tnp)) == 0);
	/* We receive it in RNL: */
	OSMO_ASSERT(_init_ack_user_rx_prim == 1);

	/* Now in opposite direction, RNL->[IuuP]->TNL: */
	rnp = osmo_iuup_rnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_RNL_DATA, PRIM_OP_REQUEST, IUUP_MSGB_SIZE);
	rnp->u.data.rfci = 0;
	rnp->u.data.frame_nr = 1;
	rnp->u.data.fqc = IUUP_FQC_FRAME_GOOD;
	rnp->oph.msg->l3h = msgb_put(rnp->oph.msg, sizeof(iuup_data) - 4);
	memcpy(rnp->oph.msg->l3h, iuup_data + 4, sizeof(iuup_data) - 4);
	OSMO_ASSERT((rc = osmo_iuup_rnl_prim_down(iui, rnp)) == 0);
	OSMO_ASSERT(_init_ack_transport_rx_prim == 2); /* We receive data in TNL */

	osmo_iuup_instance_free(iui);
}

/****************************
 * test_passive_init
 ****************************/
static unsigned int _passive_init_user_rx_prim = 0;
static int _passive_init_user_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_iuup_rnl_prim *irp = (struct osmo_iuup_rnl_prim *)oph;
	struct msgb *msg = oph->msg;

	printf("%s()\n", __func__);

	switch (_passive_init_user_rx_prim) {
	case 0:
		OSMO_ASSERT(OSMO_PRIM_HDR(&irp->oph) == OSMO_PRIM(OSMO_IUUP_RNL_STATUS, PRIM_OP_INDICATION));
		OSMO_ASSERT(irp->u.status.procedure == IUUP_PROC_INIT);
		break;
	case 1:
	default:
		OSMO_ASSERT(OSMO_PRIM_HDR(&irp->oph) == OSMO_PRIM(OSMO_IUUP_RNL_DATA, PRIM_OP_INDICATION));
		printf("User: UL len=%u: %s\n", msgb_l3len(msg),
		       osmo_hexdump((const unsigned char *) msgb_l3(msg), msgb_l3len(msg)));
	}

	_passive_init_user_rx_prim++;
	msgb_free(oph->msg);
	return 0;
}
static int _passive_init_transport_rx_prim = 0;
static int _passive_init_transport_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_iuup_tnl_prim *itp = (struct osmo_iuup_tnl_prim *)oph;
	struct msgb *msg;

	printf("%s()\n", __func__);
	msg = oph->msg;
	OSMO_ASSERT(OSMO_PRIM_HDR(&itp->oph) == OSMO_PRIM(OSMO_IUUP_TNL_UNITDATA, PRIM_OP_REQUEST));
	printf("Transport: DL len=%u: %s\n", msgb_l2len(msg),
	       osmo_hexdump((const unsigned char *) msgb_l2(msg), msgb_l2len(msg)));
	_passive_init_transport_rx_prim++;

	msgb_free(msg);
	return 0;
}
void test_passive_init(void)
{
	/* Here we check the passive INIT code path, aka receiving INIT and returning INIT_ACK/NACK */
	struct osmo_iuup_instance *iui;
	struct osmo_iuup_rnl_prim *rnp;
	struct osmo_iuup_tnl_prim *tnp;
	struct iuup_pdutype14_hdr *hdr14;
	struct iuup_pdutype0_hdr *hdr0;
	int rc;

	iui = osmo_iuup_instance_alloc(iuup_test_ctx, __func__);
	OSMO_ASSERT(iui);
	osmo_iuup_instance_set_user_prim_cb(iui, _passive_init_user_prim_cb, NULL);
	osmo_iuup_instance_set_transport_prim_cb(iui, _passive_init_transport_prim_cb, NULL);

	clock_override_set(0, 0);

	/* Tx CONFIG.req */
	rnp = osmo_iuup_rnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_RNL_CONFIG, PRIM_OP_REQUEST, IUUP_MSGB_SIZE);
	rnp->u.config = def_configure_req;
	rnp->u.config.active = false;
	OSMO_ASSERT((rc = osmo_iuup_rnl_prim_down(iui, rnp)) == 0);
	/* STATUS-INIT.req is NOT transmitted automatically: */
	OSMO_ASSERT(_passive_init_transport_rx_prim == 0);

	/* Send Init: */
	tnp = osmo_iuup_tnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION, IUUP_MSGB_SIZE);
	tnp->oph.msg->l2h = msgb_put(tnp->oph.msg, sizeof(iuup_initialization));
	hdr14 = (struct iuup_pdutype14_hdr *)msgb_l2(tnp->oph.msg);
	memcpy(hdr14, iuup_initialization, sizeof(iuup_initialization));
	OSMO_ASSERT((rc = osmo_iuup_tnl_prim_up(iui, tnp)) == 0);
	OSMO_ASSERT(_passive_init_transport_rx_prim == 1); /* We receive an Init ACK */
	OSMO_ASSERT(_passive_init_user_rx_prim == 1); /* We receive the Status-Init.ind */

	/* Send IuUP incoming data to the implementation: */
	tnp = osmo_iuup_tnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION, IUUP_MSGB_SIZE);
	tnp->oph.msg->l2h = msgb_put(tnp->oph.msg, sizeof(iuup_data));
	hdr0 = (struct iuup_pdutype0_hdr *)msgb_l2(tnp->oph.msg);
	memcpy(hdr0, iuup_data, sizeof(iuup_data));
	OSMO_ASSERT((rc = osmo_iuup_tnl_prim_up(iui, tnp)) == 0);
	/* We receive it in RNL: */
	OSMO_ASSERT(_passive_init_user_rx_prim == 2);

	/* Now in opposite direction, RNL->[IuuP]->TNL: */
	rnp = osmo_iuup_rnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_RNL_DATA, PRIM_OP_REQUEST, IUUP_MSGB_SIZE);
	rnp->u.data.rfci = 0;
	rnp->u.data.frame_nr = 1;
	rnp->u.data.fqc = IUUP_FQC_FRAME_GOOD;
	rnp->oph.msg->l3h = msgb_put(rnp->oph.msg, sizeof(iuup_data) - 4);
	memcpy(rnp->oph.msg->l3h, iuup_data + 4, sizeof(iuup_data) - 4);
	OSMO_ASSERT((rc = osmo_iuup_rnl_prim_down(iui, rnp)) == 0);
	OSMO_ASSERT(_passive_init_transport_rx_prim == 2); /* We receive data in TNL */

	osmo_iuup_instance_free(iui);
}

/****************************
 * test_passive_init_retrans
 ****************************/
static unsigned int _passive_init_retrans_user_rx_prim = 0;
static int _passive_init_retrans_user_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_iuup_rnl_prim *irp = (struct osmo_iuup_rnl_prim *)oph;
	struct msgb *msg = oph->msg;

	printf("%s()\n", __func__);

	switch (_passive_init_retrans_user_rx_prim) {
	case 0:
	case 1:
		OSMO_ASSERT(OSMO_PRIM_HDR(&irp->oph) == OSMO_PRIM(OSMO_IUUP_RNL_STATUS, PRIM_OP_INDICATION));
		OSMO_ASSERT(irp->u.status.procedure == IUUP_PROC_INIT);
		break;
	case 2:
	default:
		OSMO_ASSERT(OSMO_PRIM_HDR(&irp->oph) == OSMO_PRIM(OSMO_IUUP_RNL_DATA, PRIM_OP_INDICATION));
		printf("User: UL len=%u: %s\n", msgb_l3len(msg),
		       osmo_hexdump((const unsigned char *) msgb_l3(msg), msgb_l3len(msg)));
	}

	_passive_init_retrans_user_rx_prim++;
	msgb_free(oph->msg);
	return 0;
}
void test_passive_init_retrans(void)
{
	/* Here we check the passive INIT code path, aka receiving INIT and
	 * returning INIT_ACK/NACK. We emulate the peer not receiving the INIT
	 * ACK and hence retransmitting the INIT. The IuUP stack should then
	 * push the new INIT info up the stack and ACK it. */
	struct osmo_iuup_instance *iui;
	struct osmo_iuup_rnl_prim *rnp;
	struct osmo_iuup_tnl_prim *tnp;
	struct iuup_pdutype14_hdr *hdr14;
	struct iuup_pdutype0_hdr *hdr0;
	int rc;

	/* reset global var, we reuse it together wth callback from test_passive_init(): */
	_passive_init_transport_rx_prim = 0;

	iui = osmo_iuup_instance_alloc(iuup_test_ctx, __func__);
	OSMO_ASSERT(iui);
	osmo_iuup_instance_set_user_prim_cb(iui, _passive_init_retrans_user_prim_cb, NULL);
	osmo_iuup_instance_set_transport_prim_cb(iui, _passive_init_transport_prim_cb, NULL);

	clock_override_set(0, 0);

	/* Tx CONFIG.req */
	rnp = osmo_iuup_rnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_RNL_CONFIG, PRIM_OP_REQUEST, IUUP_MSGB_SIZE);
	rnp->u.config = def_configure_req;
	rnp->u.config.active = false;
	OSMO_ASSERT((rc = osmo_iuup_rnl_prim_down(iui, rnp)) == 0);
	/* STATUS-INIT.req is NOT transmitted automatically: */
	OSMO_ASSERT(_passive_init_transport_rx_prim == 0);

	/* Send Init: */
	tnp = osmo_iuup_tnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION, IUUP_MSGB_SIZE);
	tnp->oph.msg->l2h = msgb_put(tnp->oph.msg, sizeof(iuup_initialization));
	hdr14 = (struct iuup_pdutype14_hdr *)msgb_l2(tnp->oph.msg);
	memcpy(hdr14, iuup_initialization, sizeof(iuup_initialization));
	OSMO_ASSERT((rc = osmo_iuup_tnl_prim_up(iui, tnp)) == 0);
	OSMO_ASSERT(_passive_init_transport_rx_prim == 1); /* We receive an Init ACK */
	OSMO_ASSERT(_passive_init_retrans_user_rx_prim == 1); /* We receive the Status-Init.ind */

	/* Send Init (retrans): */
	tnp = osmo_iuup_tnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION, IUUP_MSGB_SIZE);
	tnp->oph.msg->l2h = msgb_put(tnp->oph.msg, sizeof(iuup_initialization));
	hdr14 = (struct iuup_pdutype14_hdr *)msgb_l2(tnp->oph.msg);
	memcpy(hdr14, iuup_initialization, sizeof(iuup_initialization));
	OSMO_ASSERT((rc = osmo_iuup_tnl_prim_up(iui, tnp)) == 0);
	OSMO_ASSERT(_passive_init_transport_rx_prim == 2); /* We receive another Init ACK */
	OSMO_ASSERT(_passive_init_retrans_user_rx_prim == 2); /* We receive another Status-Init.ind */

	/* Send IuUP incoming data to the implementation: */
	tnp = osmo_iuup_tnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION, IUUP_MSGB_SIZE);
	tnp->oph.msg->l2h = msgb_put(tnp->oph.msg, sizeof(iuup_data));
	hdr0 = (struct iuup_pdutype0_hdr *)msgb_l2(tnp->oph.msg);
	memcpy(hdr0, iuup_data, sizeof(iuup_data));
	OSMO_ASSERT((rc = osmo_iuup_tnl_prim_up(iui, tnp)) == 0);
	/* We receive it in RNL: */
	OSMO_ASSERT(_passive_init_retrans_user_rx_prim == 3);

	/* Now in opposite direction, RNL->[IuuP]->TNL: */
	rnp = osmo_iuup_rnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_RNL_DATA, PRIM_OP_REQUEST, IUUP_MSGB_SIZE);
	rnp->u.data.rfci = 0;
	rnp->u.data.frame_nr = 1;
	rnp->u.data.fqc = IUUP_FQC_FRAME_GOOD;
	rnp->oph.msg->l3h = msgb_put(rnp->oph.msg, sizeof(iuup_data) - 4);
	memcpy(rnp->oph.msg->l3h, iuup_data + 4, sizeof(iuup_data) - 4);
	OSMO_ASSERT((rc = osmo_iuup_rnl_prim_down(iui, rnp)) == 0);
	OSMO_ASSERT(_passive_init_transport_rx_prim == 3); /* We receive data in TNL */

	osmo_iuup_instance_free(iui);
}

static int _decode_passive_init_2_rfci_no_iptis_user_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_iuup_rnl_prim *irp = (struct osmo_iuup_rnl_prim *)oph;
	printf("%s(): Initialization decoded fine!\n", __func__);
	OSMO_ASSERT(OSMO_PRIM_HDR(&irp->oph) == OSMO_PRIM(OSMO_IUUP_RNL_STATUS, PRIM_OP_INDICATION));
	OSMO_ASSERT(irp->u.status.procedure == IUUP_PROC_INIT);
	OSMO_ASSERT(irp->u.status.u.initialization.num_rfci == 2);
	OSMO_ASSERT(irp->u.status.u.initialization.num_subflows == 3);
	OSMO_ASSERT(irp->u.status.u.initialization.data_pdu_type == 0);
	OSMO_ASSERT(irp->u.status.u.initialization.IPTIs_present == false);
	msgb_free(oph->msg);
	return 0;
}
static int _decode_passive_init_2_rfci_no_iptis_transport_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_iuup_tnl_prim *itp = (struct osmo_iuup_tnl_prim *)oph;
	struct msgb *msg;
	struct iuup_pdutype14_hdr *hdr;

	printf("%s()\n", __func__);
	msg = oph->msg;
	OSMO_ASSERT(OSMO_PRIM_HDR(&itp->oph) == OSMO_PRIM(OSMO_IUUP_TNL_UNITDATA, PRIM_OP_REQUEST));
	printf("Transport: DL len=%u: %s\n", msgb_l2len(msg),
	       osmo_hexdump((const unsigned char *) msgb_l2(msg), msgb_l2len(msg)));
	hdr = msgb_l2(msg);
	OSMO_ASSERT(hdr->pdu_type == IUUP_PDU_T_CONTROL);
	OSMO_ASSERT(hdr->ack_nack == IUUP_AN_ACK);
	msgb_free(msg);
	return 0;
}
void test_decode_passive_init_2_rfci_no_iptis(void)
{
	/* Here we check the passive INIT code path, aka receiving INIT and returning INIT_ACK/NACK */
	struct osmo_iuup_instance *iui;
	struct osmo_iuup_rnl_prim *rnp;
	struct osmo_iuup_tnl_prim *tnp;
	struct iuup_pdutype14_hdr *hdr14;
	int rc;

	/*  Frame 46, "Initialization",  SYS#5969 call4_Iu_Iuh.pcap
	1110 .... = PDU Type: Control Procedure (14)
	.... 00.. = Ack/Nack: Procedure (0)
	.... ..00 = Frame Number: 0
	0000 .... = Mode Version: 0x0
	.... 0000 = Procedure: Initialization (0)
	1101 11.. = Header CRC: 0x37 [correct]
	.... ..01 1011 0100 = Payload CRC: 0x1b4
	000. .... = Spare: 0x0
	...0 .... = TI: IPTIs not present (0)
	.... 011. = Subflows: 3
	.... ...0 = Chain Indicator: this frame is the last frame for the procedure (0)
	RFCI 1 Initialization
	0... .... = RFCI 0 LRI: Not last RFCI (0x0)
	.0.. .... = RFCI 0 LI: one octet used (0x0)
	..00 0001 = RFCI 0: 1
	RFCI 0 Flow 0 Len: 81
	RFCI 0 Flow 1 Len: 103
	RFCI 0 Flow 2 Len: 60
	RFCI 6 Initialization
	1... .... = RFCI 1 LRI: Last RFCI in current frame (0x1)
	.0.. .... = RFCI 1 LI: one octet used (0x0)
	..00 0110 = RFCI 1: 6
	RFCI 1 Flow 0 Len: 39
	RFCI 1 Flow 1 Len: 0
	RFCI 1 Flow 2 Len: 0
	Iu UP Mode Versions Supported: 0x0001
	0... .... .... .... = Version 16: not supported (0x0)
	.0.. .... .... .... = Version 15: not supported (0x0)
	..0. .... .... .... = Version 14: not supported (0x0)
	...0 .... .... .... = Version 13: not supported (0x0)
	.... 0... .... .... = Version 12: not supported (0x0)
	.... .0.. .... .... = Version 11: not supported (0x0)
	.... ..0. .... .... = Version 10: not supported (0x0)
	.... ...0 .... .... = Version  9: not supported (0x0)
	.... .... 0... .... = Version  8: not supported (0x0)
	.... .... .0.. .... = Version  7: not supported (0x0)
	.... .... ..0. .... = Version  6: not supported (0x0)
	.... .... ...0 .... = Version  5: not supported (0x0)
	.... .... .... 0... = Version  4: not supported (0x0)
	.... .... .... .0.. = Version  3: not supported (0x0)
	.... .... .... ..0. = Version  2: not supported (0x0)
	.... .... .... ...1 = Version  1: supported (0x1)
	0000 .... = RFCI Data Pdu Type: PDU type 0 (0x0)
	*/
	const uint8_t iuup_init[] = {
		0xe0, 0x00, 0xdd, 0xb4, 0x06, 0x01, 0x51, 0x67, 0x3c, 0x86, 0x27,
		0x00, 0x00, 0x00, 0x01, 0x00
	};

	iui = osmo_iuup_instance_alloc(iuup_test_ctx, __func__);
	OSMO_ASSERT(iui);
	osmo_iuup_instance_set_user_prim_cb(iui, _decode_passive_init_2_rfci_no_iptis_user_prim_cb, NULL);
	osmo_iuup_instance_set_transport_prim_cb(iui, _decode_passive_init_2_rfci_no_iptis_transport_prim_cb, NULL);

	clock_override_set(0, 0);

	/* Tx CONFIG.req */
	rnp = osmo_iuup_rnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_RNL_CONFIG, PRIM_OP_REQUEST, IUUP_MSGB_SIZE);
	rnp->u.config = def_configure_req;
	rnp->u.config.active = false;
	OSMO_ASSERT((rc = osmo_iuup_rnl_prim_down(iui, rnp)) == 0);

	/* Send Init: */
	tnp = osmo_iuup_tnl_prim_alloc(iuup_test_ctx, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION, IUUP_MSGB_SIZE);
	tnp->oph.msg->l2h = msgb_put(tnp->oph.msg, sizeof(iuup_init));
	hdr14 = (struct iuup_pdutype14_hdr *)msgb_l2(tnp->oph.msg);
	memcpy(hdr14, iuup_init, sizeof(iuup_init));
	OSMO_ASSERT((rc = osmo_iuup_tnl_prim_up(iui, tnp)) == 0);

	osmo_iuup_instance_free(iui);
}

int main(int argc, char **argv)
{
	iuup_test_ctx = talloc_named_const(NULL, 0, "iuup_test");
	osmo_init_logging2(iuup_test_ctx, NULL);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_category_filter(osmo_stderr_target, DLIUUP, 1, LOGL_DEBUG);
	osmo_fsm_log_addr(false);

	osmo_gettimeofday_override = true;

	test_crc();
	test_tinit_timeout_retrans();
	test_init_nack_retrans();
	test_init_ack();
	test_passive_init();
	test_passive_init_retrans();
	test_decode_passive_init_2_rfci_no_iptis();

	printf("OK.\n");
}
