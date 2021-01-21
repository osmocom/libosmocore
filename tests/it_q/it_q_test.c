#include <stdio.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/it_q.h>

struct it_q_test1 {
	struct llist_head list;
	int *foo;
};

struct it_q_test2 {
	int foo;
	struct llist_head list;
};

#define ENTER_TC	printf("\n== Entering test case %s\n", __func__)

static void tc_alloc(void)
{
	struct osmo_it_q *q1, *q2;

	ENTER_TC;

	printf("allocating q1\n");
	q1 = osmo_it_q_alloc(OTC_GLOBAL, "q1", 3, NULL, NULL);
	OSMO_ASSERT(q1);

	/* ensure that no duplicate allocation for the */
	printf("attempting duplicate allocation of qa\n");
	q2 = osmo_it_q_alloc(OTC_GLOBAL, "q1", 3, NULL, NULL);
	OSMO_ASSERT(!q2);

	/* ensure that same name can be re-created after destroying old one */
	osmo_it_q_destroy(q1);
	printf("re-allocating q1\n");
	q1 = osmo_it_q_alloc(OTC_GLOBAL, "q1", 3, NULL, NULL);
	OSMO_ASSERT(q1);

	osmo_it_q_destroy(q1);
}

static void tc_queue_length(void)
{
	struct osmo_it_q *q1;
	unsigned int qlen = 3;
	struct it_q_test1 *item;
	int i, rc;

	ENTER_TC;

	printf("allocating q1\n");
	q1 = osmo_it_q_alloc(OTC_GLOBAL, "q1", qlen, NULL, NULL);
	OSMO_ASSERT(q1);

	printf("adding queue entries up to the limit\n");
	for (i = 0; i < qlen; i++) {
		item = talloc_zero(OTC_GLOBAL, struct it_q_test1);
		rc = osmo_it_q_enqueue(q1, item, list);
		OSMO_ASSERT(rc == 0);
	}
	printf("attempting to add more than the limit\n");
	item = talloc_zero(OTC_GLOBAL, struct it_q_test1);
	rc = osmo_it_q_enqueue(q1, item, list);
	OSMO_ASSERT(rc == -ENOSPC);

	osmo_it_q_destroy(q1);
}

static int g_read_cb_count;

static void q_read_cb(struct osmo_it_q *q, struct llist_head *item)
{
	struct it_q_test1 *it = container_of(item, struct it_q_test1, list);
	*it->foo += 1;
	talloc_free(item);
}

static void tc_eventfd(void)
{
	struct osmo_it_q *q1;
	unsigned int qlen = 30;
	struct it_q_test1 *item;
	int i, rc;

	ENTER_TC;

	printf("allocating q1\n");
	q1 = osmo_it_q_alloc(OTC_GLOBAL, "q1", qlen, q_read_cb, NULL);
	OSMO_ASSERT(q1);
	osmo_fd_register(&q1->event_ofd);

	/* ensure read-cb isn't called unless we enqueue something */
	osmo_select_main(1);
	OSMO_ASSERT(g_read_cb_count == 0);

	/* ensure read-cb is called for each enqueued msg once */
	printf("adding %u queue entries up to the limit\n", qlen);
	for (i = 0; i < qlen; i++) {
		item = talloc_zero(OTC_GLOBAL, struct it_q_test1);
		item->foo = &g_read_cb_count;
		rc = osmo_it_q_enqueue(q1, item, list);
		OSMO_ASSERT(rc == 0);
	}

	osmo_select_main(1);
	printf("%u entries were dequeued\n", qlen);
	OSMO_ASSERT(g_read_cb_count == qlen);

	osmo_it_q_destroy(q1);
}

int main(int argc, char **argv)
{
	tc_alloc();
	tc_queue_length();
	tc_eventfd();
	return 0;
}
