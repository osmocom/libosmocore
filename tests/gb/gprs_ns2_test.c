/* test routines for NS connection handling
 * (C) 2020 sysmocom - s.f.m.c. GmbH
 * Author: Alexander Couzens <lynxis@fe80.eu>
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include "../../src/gb/gprs_ns2_internal.h"

int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	return -1;
}

static struct log_info info = {};
static struct osmo_wqueue *unitdata = NULL;

static int ns_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	OSMO_ASSERT(oph->sap == SAP_NS);
	if (oph->msg) {
		if (oph->primitive == PRIM_NS_UNIT_DATA) {
			osmo_wqueue_enqueue(unitdata, oph->msg);
		} else {
			msgb_free(oph->msg);
		}
	}
	return 0;
}

static struct msgb *get_pdu(struct gprs_ns2_vc_bind *bind, enum ns_pdu_type pdu_type)
{
	struct gprs_ns_hdr *nsh;
	struct osmo_wqueue *queue = bind->priv;

	while (!llist_empty(&queue->msg_queue)) {
		struct msgb *msg = msgb_dequeue(&queue->msg_queue);
		nsh = (struct gprs_ns_hdr *) msg->l2h;
		if (nsh->pdu_type == pdu_type)
			return msg;
		msgb_free(msg);
	}

	return NULL;
}

static bool find_pdu(struct gprs_ns2_vc_bind *bind, enum ns_pdu_type pdu_type)
{
	struct msgb *msg;
	msg = get_pdu(bind, pdu_type);
	if (msg) {
		msgb_free(msg);
		return true;
	}

	return false;
}

static void clear_pdus(struct gprs_ns2_vc_bind *bind)
{
	struct osmo_wqueue *queue = bind->priv;
	osmo_wqueue_clear(queue);
}

struct gprs_ns2_vc_driver vc_driver_dummy = {
	.name = "GB UDP dummy",
	.free_bind = clear_pdus,
};

static int vc_sendmsg(struct gprs_ns2_vc *nsvc, struct msgb *msg)
{
	struct gprs_ns2_vc_bind *bind = nsvc->bind;
	struct osmo_wqueue *queue = bind->priv;

	osmo_wqueue_enqueue(queue, msg);
	return 0;
}

static struct gprs_ns2_vc_bind *dummy_bind(struct gprs_ns2_inst *nsi, const char *name)
{
	struct gprs_ns2_vc_bind *bind = talloc_zero(nsi, struct gprs_ns2_vc_bind);
	OSMO_ASSERT(bind);

	bind->name = talloc_strdup(bind, name);
	bind->driver = &vc_driver_dummy;
	bind->ll = GPRS_NS2_LL_UDP;
	bind->transfer_capability = 42;
	bind->nsi = nsi;
	bind->send_vc = vc_sendmsg;
	bind->priv = talloc_zero(bind, struct osmo_wqueue);
	struct osmo_wqueue *queue = bind->priv;

	INIT_LLIST_HEAD(&bind->nsvc);
	llist_add(&bind->list, &nsi->binding);
	osmo_wqueue_init(queue, 100);

	return bind;
}

static void free_loopback(struct gprs_ns2_vc_bind *bind) {}

struct gprs_ns2_vc_driver vc_driver_loopback = {
	.name = "loopback dummy",
	.free_bind = free_loopback,
};

/* loopback the msg */
static int loopback_sendmsg(struct gprs_ns2_vc *nsvc, struct msgb *msg)
{
	struct gprs_ns2_vc *target = nsvc->priv;
	return ns2_recv_vc(target, msg);
}

/* create a loopback nsvc object which can be used with ns2_tx_* functions. it's not fully registered etc. */
static struct gprs_ns2_vc *loopback_nsvc(struct gprs_ns2_vc_bind *bind, struct gprs_ns2_vc *target)
{
	struct gprs_ns2_vc *nsvc = talloc_zero(bind, struct gprs_ns2_vc);
	memcpy(nsvc, target, sizeof(struct gprs_ns2_vc));
	nsvc->bind = bind;
	nsvc->priv = target;
	return nsvc;
}

/* a loop back bind to use the tx_ functions from gprs_ns2_message.c */
static struct gprs_ns2_vc_bind *loopback_bind(struct gprs_ns2_inst *nsi, const char *name)
{
	struct gprs_ns2_vc_bind *bind = talloc_zero(nsi, struct gprs_ns2_vc_bind);
	OSMO_ASSERT(bind);
	bind->name = talloc_strdup(bind, name);
	bind->driver = &vc_driver_loopback;
	bind->ll = GPRS_NS2_LL_UDP;
	bind->transfer_capability = 99;
	bind->nsi = nsi;
	bind->send_vc = loopback_sendmsg;
	INIT_LLIST_HEAD(&bind->nsvc);
	llist_add(&bind->list, &nsi->binding);
	return bind;
}

void test_nse_transfer_cap(void *ctx)
{
	struct gprs_ns2_inst *nsi;
	struct gprs_ns2_vc_bind *bind[2];
	struct gprs_ns2_nse *nse;
	struct gprs_ns2_vc *nsvc[3];

	/* create a UDP dummy bind[0] with transfer cap 42.
	 * create nse (nsei 1001)
	 * create 2x nsvc with the same bind.
	 * nsvc[0] or nsvc[1] is alive (or both) cap == 42
	 *
	 * create a second bind with transfer cap == 23
	 * create 3rd nsvc with bind[1]
	 * transfer cap should be 42 + 23
	 */

	printf("--- Testing NSE transfer cap\n");

	printf("---- Create NSE + Binds\n");
	nsi = gprs_ns2_instantiate(ctx, ns_prim_cb, NULL);
	bind[0] = dummy_bind(nsi, "transfercap1");
	bind[1] = dummy_bind(nsi, "transfercap2");
	bind[1]->transfer_capability = 23;
	nse = gprs_ns2_create_nse(nsi, 1001, GPRS_NS2_LL_UDP, NS2_DIALECT_STATIC_ALIVE);
	OSMO_ASSERT(nse);

	printf("---- Test with NSVC[0]\n");
	nsvc[0] = ns2_vc_alloc(bind[0], nse, false, NS2_VC_MODE_ALIVE, NULL);
	OSMO_ASSERT(nsvc[0]);
	OSMO_ASSERT(ns2_count_transfer_cap(nse, 0) == 0);
	nsvc[0]->fi->state = 3;	/* HACK: 3 = GPRS_NS2_ST_UNBLOCKED */
	ns2_nse_notify_unblocked(nsvc[0], true);
	OSMO_ASSERT(ns2_count_transfer_cap(nse, 0) == 42);

	printf("---- Test with NSVC[1]\n");
	nsvc[1] = ns2_vc_alloc(bind[0], nse, false, NS2_VC_MODE_ALIVE, NULL);
	OSMO_ASSERT(nsvc[1]);
	OSMO_ASSERT(ns2_count_transfer_cap(nse, 0) == 42);
	nsvc[1]->fi->state = 3; /* HACK: 3 = GPRS_NS2_ST_UNBLOCKED */
	ns2_nse_notify_unblocked(nsvc[1], true);
	OSMO_ASSERT(ns2_count_transfer_cap(nse, 0) == 42);

	printf("---- Test with NSVC[2]\n");
	nsvc[2] = ns2_vc_alloc(bind[1], nse, false, NS2_VC_MODE_ALIVE, NULL);
	OSMO_ASSERT(nsvc[2]);
	OSMO_ASSERT(ns2_count_transfer_cap(nse, 0) == 42);
	nsvc[2]->fi->state = 3; /* HACK: 3 = GPRS_NS2_ST_UNBLOCKED */
	ns2_nse_notify_unblocked(nsvc[2], true);
	OSMO_ASSERT(ns2_count_transfer_cap(nse, 0) == 42 + 23);

	printf("---- Test with NSVC[1] removed\n");
	/* reset nsvc[1] to be unconfigured - shouldn't change anything */
	nsvc[1]->fi->state = 0; /* HACK: 0 = GPRS_NS2_ST_UNCONFIGURED */
	ns2_nse_notify_unblocked(nsvc[1], false);
	OSMO_ASSERT(ns2_count_transfer_cap(nse, 0) == 42 + 23);

	gprs_ns2_free(nsi);
	printf("--- Finish NSE transfer cap\n");

}

/* setup NSE with 2x NSVCs.
 * block 1x NSVC
 * unblock 1x NSVC*/
void test_block_unblock_nsvc(void *ctx)
{
	struct gprs_ns2_inst *nsi;
	struct gprs_ns2_vc_bind *bind[2];
	struct gprs_ns2_nse *nse;
	struct gprs_ns2_vc *nsvc[2];
	struct gprs_ns_hdr *nsh;
	struct msgb *msg;
	char idbuf[32];
	int i;

	printf("--- Testing NSE block unblock nsvc\n");
	printf("---- Create NSE + Binds\n");
	nsi = gprs_ns2_instantiate(ctx, ns_prim_cb, NULL);
	bind[0] = dummy_bind(nsi, "bblock1");
	bind[1] = dummy_bind(nsi, "bblock2");
	nse = gprs_ns2_create_nse(nsi, 1001, GPRS_NS2_LL_UDP, NS2_DIALECT_STATIC_RESETBLOCK);
	OSMO_ASSERT(nse);

	for (i=0; i<2; i++) {
		printf("---- Create NSVC[i]\n");
		snprintf(idbuf, sizeof(idbuf), "NSE%05u-dummy-%i", nse->nsei, i);
		nsvc[i] = ns2_vc_alloc(bind[i], nse, false, NS2_VC_MODE_BLOCKRESET, idbuf);
		OSMO_ASSERT(nsvc[i]);
		nsvc[i]->fi->state = 3;	/* HACK: 3 = GPRS_NS2_ST_UNBLOCKED */
		/* ensure the fi->state works correct */
		OSMO_ASSERT(ns2_vc_is_unblocked(nsvc[i]));
		ns2_nse_notify_unblocked(nsvc[i], true);
	}

	/* both nsvcs are unblocked and alive. Let's block it. */
	OSMO_ASSERT(!find_pdu(bind[0], NS_PDUT_BLOCK));
	clear_pdus(bind[0]);
	ns2_vc_block(nsvc[0]);
	OSMO_ASSERT(find_pdu(bind[0], NS_PDUT_BLOCK));
	/* state == BLOCKED */
	clear_pdus(bind[0]);

	/* now unblocking it */
	ns2_vc_unblock(nsvc[0]);
	OSMO_ASSERT(find_pdu(bind[0], NS_PDUT_UNBLOCK));
	clear_pdus(bind[0]);

	msg = msgb_alloc_headroom(NS_ALLOC_SIZE, NS_ALLOC_HEADROOM, "test_unblock");
	msg->l2h = msgb_put(msg, sizeof(*nsh));
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_UNBLOCK_ACK;
	ns2_recv_vc(nsvc[0], msg);

	OSMO_ASSERT(ns2_vc_is_unblocked(nsvc[0]));
	gprs_ns2_free(nsi);
	printf("--- Finish NSE block unblock nsvc\n");
}

static struct msgb *generate_unitdata(const char *msgname)
{
	struct gprs_ns_hdr *nsh;
	struct msgb *msg = msgb_alloc_headroom(NS_ALLOC_SIZE, NS_ALLOC_HEADROOM, msgname);
	OSMO_ASSERT(msg);

	msg->l2h = msgb_put(msg, sizeof(*nsh) + 6);
	nsh = (struct gprs_ns_hdr *) msg->l2h;
	nsh->pdu_type = NS_PDUT_UNITDATA;
	nsh->data[0] = 0; /* sdu control */
	nsh->data[1] = 0; /* msb bvci */
	nsh->data[2] = 12; /* lsb bvci */
	nsh->data[3] = 0xab; /* first data byte */
	nsh->data[4] = 0xcd;
	nsh->data[5] = 0xef;

	return msg;
}

void test_unitdata(void *ctx)
{
	struct gprs_ns2_inst *nsi;
	struct gprs_ns2_vc_bind *bind[2];
	struct gprs_ns2_vc_bind *loopbind;
	struct gprs_ns2_nse *nse;
	struct gprs_ns2_vc *nsvc[2];
	struct gprs_ns2_vc *loop[2];

	struct msgb *msg, *other;
	char idbuf[32];
	int i;

	printf("--- Testing unitdata test\n");
	osmo_wqueue_clear(unitdata);
	printf("---- Create NSE + Binds\n");
	nsi = gprs_ns2_instantiate(ctx, ns_prim_cb, NULL);
	bind[0] = dummy_bind(nsi, "bblock1");
	bind[1] = dummy_bind(nsi, "bblock2");
	loopbind = loopback_bind(nsi, "loopback");
	nse = gprs_ns2_create_nse(nsi, 1004, GPRS_NS2_LL_UDP, NS2_DIALECT_STATIC_RESETBLOCK);
	OSMO_ASSERT(nse);

	for (i=0; i<2; i++) {
		printf("---- Create NSVC[%d]\n", i);
		snprintf(idbuf, sizeof(idbuf), "NSE%05u-dummy-%i", nse->nsei, i);
		nsvc[i] = ns2_vc_alloc(bind[i], nse, false, NS2_VC_MODE_BLOCKRESET, idbuf);
		loop[i] = loopback_nsvc(loopbind, nsvc[i]);
		OSMO_ASSERT(nsvc[i]);
		ns2_vc_fsm_start(nsvc[i]);
		OSMO_ASSERT(!ns2_vc_is_unblocked(nsvc[i]));
		ns2_tx_reset(loop[i], NS_CAUSE_OM_INTERVENTION);
		ns2_tx_unblock(loop[i]);
		OSMO_ASSERT(ns2_vc_is_unblocked(nsvc[i]));
	}

	/* both nsvcs are unblocked and alive */
	printf("---- Send UNITDATA to NSVC[0]\n");
	msg = generate_unitdata("test_unitdata");
	ns2_recv_vc(nsvc[0], msg);
	other = msgb_dequeue(&unitdata->msg_queue);
	OSMO_ASSERT(msg == other);
	other = msgb_dequeue(&unitdata->msg_queue);
	OSMO_ASSERT(NULL == other);

	printf("---- Send Block NSVC[0]\n");
	ns2_vc_block(nsvc[0]);
	ns2_tx_block_ack(loop[0]);

	/* try to receive a unitdata - this should be dropped & freed by NS */
	printf("---- Try to receive over blocked NSVC[0]\n");
	ns2_recv_vc(nsvc[0], msg);
	other = msgb_dequeue(&unitdata->msg_queue);
	OSMO_ASSERT(NULL == other);

	/* nsvc[1] should be still good */
	printf("---- Receive over NSVC[1]\n");
	msg = generate_unitdata("test_unitdata2");
	ns2_recv_vc(nsvc[1], msg);
	other = msgb_dequeue(&unitdata->msg_queue);
	OSMO_ASSERT(msg == other);
	msgb_free(msg);

	gprs_ns2_free(nsi);
	printf("--- Finish unitdata test\n");
}


int main(int argc, char **argv)
{
	void *ctx = talloc_named_const(NULL, 0, "gprs_ns2_test");
	osmo_init_logging2(ctx, &info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);
	unitdata = talloc_zero(ctx, struct osmo_wqueue);
	osmo_wqueue_init(unitdata, 100);
	setlinebuf(stdout);

	printf("===== NS2 protocol test START\n");
	test_nse_transfer_cap(ctx);
	test_block_unblock_nsvc(ctx);
	test_unitdata(ctx);
	printf("===== NS2 protocol test END\n\n");

	talloc_free(ctx);
	exit(EXIT_SUCCESS);
}
