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

void free_bind(struct gprs_ns2_vc_bind *bind)
{
	OSMO_ASSERT(bind);
	talloc_free(bind);
}

struct gprs_ns2_vc_driver vc_driver_dummy = {
	.name = "GB UDP dummy",
	.free_bind = free_bind,
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

	printf("--- Finish NSE transfer cap\n");

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
	printf("===== NS2 protocol test END\n\n");

	talloc_free(ctx);
	exit(EXIT_SUCCESS);
}
