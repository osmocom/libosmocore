#pragma once

/*! \file statistics.h
 *  Common routines regarding statistics */

/*! structure representing a single counter */
struct osmo_counter {
	struct llist_head list;		/*!< internal list head */
	const char *name;		/*!< human-readable name */
	const char *description;	/*!< humn-readable description */
	unsigned long value;		/*!< current value */
	unsigned long previous;		/*!< previous value */
};

/*! Decrement counter */
static inline void osmo_counter_dec(struct osmo_counter *ctr)
{
	ctr->value--;
}

/*! Increment counter */
static inline void osmo_counter_inc(struct osmo_counter *ctr)
{
	ctr->value++;
}

/*! Get current value of counter */
static inline unsigned long osmo_counter_get(struct osmo_counter *ctr)
{
	return ctr->value;
}

/*! Reset current value of counter to 0 */
static inline void osmo_counter_reset(struct osmo_counter *ctr)
{
	ctr->value = 0;
}

/*! Allocate a new counter */
struct osmo_counter *osmo_counter_alloc(const char *name);

/*! Free the specified counter
 *  \param[in] ctr Counter
 */
void osmo_counter_free(struct osmo_counter *ctr);

/*! Iterate over all counters
 *  \param[in] handle_counter Call-back function, aborts if rc < 0
 *  \param[in] data Private dtata handed through to \a handle_counter
 */
int osmo_counters_for_each(int (*handle_counter)(struct osmo_counter *, void *), void *data);

/*! Resolve counter by human-readable name
 *  \param[in] name human-readable name of counter
 *  \returns pointer to counter (\ref osmo_counter) or NULL otherwise
 */
struct osmo_counter *osmo_counter_get_by_name(const char *name);

/*! Return the counter difference since the last call to this function */
int osmo_counter_difference(struct osmo_counter *ctr);
