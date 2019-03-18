#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/eventfd.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>

static struct osmo_fd g_evfd;

static void *alloc_res_select;
static void *alloc_res_global;

static int destructor_called;

static int talloc_destructor(void *ptr)
{
	printf("destructor was called automatically\n");
	/* ensure the destructor is only called for the chunk allocated from the
	 * volatile select context */
	OSMO_ASSERT(ptr == alloc_res_select);
	destructor_called += 1;
	return 0;
}

static int evfd_cb(struct osmo_fd *ofd, unsigned int what)
{
	uint64_t rval;
	int rc;

	rc = read(ofd->fd, &rval, sizeof(rval));
	OSMO_ASSERT(rc == sizeof(rval));

	printf("allocating from select context\n");
	alloc_res_select = talloc_named_const(OTC_SELECT, 23, "alloc_select");
	OSMO_ASSERT(alloc_res_select);
	talloc_set_destructor(alloc_res_select, talloc_destructor);

	printf("allocating from global context\n");
	alloc_res_global = talloc_named_const(OTC_GLOBAL, 42, "alloc_global");
	OSMO_ASSERT(alloc_res_global);
	talloc_set_destructor(alloc_res_global, talloc_destructor);
	return 0;
}

const struct log_info_cat default_categories[] = {
};

static struct log_info info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	int rc;

	osmo_init_logging2(OTC_GLOBAL, &info);

	rc = eventfd(0, 0);
	OSMO_ASSERT(rc >= 0);
	osmo_fd_setup(&g_evfd, rc, OSMO_FD_READ, evfd_cb, NULL, 0);
	osmo_fd_register(&g_evfd);

	/* make sure the select loop will immediately call the callback */
	uint64_t val = 1;
	rc = write(g_evfd.fd, &val, sizeof(val));
	OSMO_ASSERT(rc == sizeof(val));

	/* enter osmo_select_main_ctx() once */
	printf("entering osmo_select_main\n");
	osmo_select_main_ctx(1);

	/* the allocation must have happened, and the destructor must have been called
	 * automatically exactly once */
	OSMO_ASSERT(destructor_called == 1);

	exit(0);
}
