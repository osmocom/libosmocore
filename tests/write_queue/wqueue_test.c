/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH.
 * Authors: Holger Hans Peter Freyther
 *	    Alexander Rehbein
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/write_queue.h>

static const struct log_info_cat default_categories[] = {
};

static const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

static void test_wqueue_limit(void)
{
	struct msgb *msg;
	struct osmo_wqueue wqueue;
	int rc;
	size_t dropped_msgs;

	osmo_wqueue_init(&wqueue, 0);
	OSMO_ASSERT(wqueue.max_length == 0);
	OSMO_ASSERT(wqueue.current_length == 0);
	OSMO_ASSERT(wqueue.read_cb == NULL);
	OSMO_ASSERT(wqueue.write_cb == NULL);
	OSMO_ASSERT(wqueue.except_cb == NULL);

	/* try to add and fail */
	msg = msgb_alloc(4096, "msg1");
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(rc < 0);

	/* add one and fail on the second */
	wqueue.max_length = 1;
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(wqueue.current_length == 1);
	msg = msgb_alloc(4096, "msg2");
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(rc < 0);

	/* add one more */
	wqueue.max_length = 2;
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(wqueue.current_length == 2);

	/* release everything */
	osmo_wqueue_clear(&wqueue);
	OSMO_ASSERT(wqueue.current_length == 0);
	OSMO_ASSERT(wqueue.max_length == 2);

	/* Add two, fail on the third, free it and the queue */
	msg = msgb_alloc(4096, "msg3");
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(wqueue.current_length == 1);
	msg = msgb_alloc(4096, "msg4");
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(wqueue.current_length == 2);
	msg = msgb_alloc(4096, "msg5");
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(rc < 0);
	OSMO_ASSERT(wqueue.current_length == 2);
	msgb_free(msg);
	osmo_wqueue_clear(&wqueue);

	/* Update limit */
	OSMO_ASSERT(osmo_wqueue_set_maxlen(&wqueue, 5) == 0);
	OSMO_ASSERT(osmo_wqueue_set_maxlen(&wqueue, 1) == 0);
	OSMO_ASSERT(osmo_wqueue_set_maxlen(&wqueue, 4) == 0);

	/* Add three, update limit to 1 */
	OSMO_ASSERT(wqueue.max_length == 4);
	msg = msgb_alloc(4096, "msg6");
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(wqueue.current_length == 1);
	msg = msgb_alloc(4096, "msg7");
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(wqueue.current_length == 2);
	msg = msgb_alloc(4096, "msg8");
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(wqueue.current_length == 3);
	dropped_msgs = osmo_wqueue_set_maxlen(&wqueue, 1);
	OSMO_ASSERT(dropped_msgs == 2);
	osmo_wqueue_clear(&wqueue);

	/* Add three, reduce limit to 3 from 6 */
	OSMO_ASSERT(osmo_wqueue_set_maxlen(&wqueue, 6) == 0);
	OSMO_ASSERT(wqueue.max_length == 6);
	msg = msgb_alloc(4096, "msg9");
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(wqueue.current_length == 1);
	msg = msgb_alloc(4096, "msg10");
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(wqueue.current_length == 2);
	msg = msgb_alloc(4096, "msg11");
	rc = osmo_wqueue_enqueue(&wqueue, msg);
	OSMO_ASSERT(wqueue.current_length == 3);
	dropped_msgs = osmo_wqueue_set_maxlen(&wqueue, 3);
	OSMO_ASSERT(dropped_msgs == 0);
	osmo_wqueue_clear(&wqueue);
}

int main(int argc, char **argv)
{
	struct log_target *stderr_target;

	log_init(&log_info, NULL);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);
	log_set_print_filename2(stderr_target, LOG_FILENAME_NONE);
	log_set_print_category_hex(stderr_target, 0);
	log_set_print_category(stderr_target, 0);

	test_wqueue_limit();

	printf("Done\n");
	return 0;
}
