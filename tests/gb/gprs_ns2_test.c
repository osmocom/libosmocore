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

static int ns_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
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
		OSMO_ASSERT(gprs_ns2_vc_is_unblocked(nsvc[i]));
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

	OSMO_ASSERT(gprs_ns2_vc_is_unblocked(nsvc[0]));
	gprs_ns2_free(nsi);
	printf("--- Finish NSE block unblock nsvc\n");
}

int main(int argc, char **argv)
{
	void *ctx = talloc_named_const(NULL, 0, "gprs_ns2_test");
	osmo_init_logging2(ctx, &info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);
	setlinebuf(stdout);

	printf("===== NS2 protocol test START\n");
	test_nse_transfer_cap(ctx);
	test_block_unblock_nsvc(ctx);
	printf("===== NS2 protocol test END\n\n");

	talloc_free(ctx);
	exit(EXIT_SUCCESS);
}
