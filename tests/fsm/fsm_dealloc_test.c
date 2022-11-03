/* Scenarios of parent/child FSM instances cleaning up and deallocating from various triggers. */

#include <talloc.h>

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/use_count.h>

enum event {
	EV_DESTROY,
	EV_CHILD_GONE,
	EV_OTHER_GONE,
};

static const struct value_string test_fsm_event_names[] = {
	OSMO_VALUE_STRING(EV_DESTROY),
	OSMO_VALUE_STRING(EV_CHILD_GONE),
	OSMO_VALUE_STRING(EV_OTHER_GONE),
	{}
};

enum state {
	ST_ALIVE,
};

enum objname {
	root = 0,
	 branch0,
	  twig0a,
	  twig0b,
	 branch1,
	  twig1a,
	  twig1b,

	other,
	scene_size
};

struct scene {
	struct obj *o[scene_size];

	/* The use count is actually just to help tracking what functions have not exited yet */
	struct osmo_use_count use_count;
};

int use_cb(struct osmo_use_count_entry *use_count_entry, int32_t old_use_count, const char *file, int line)
{
	char buf[128];
	LOGP(DLGLOBAL, LOGL_DEBUG, "%s\n", osmo_use_count_name_buf(buf, sizeof(buf), use_count_entry->use_count));
	return 0;
}

/* References to related actual objects that are tied to FSM instances. */
struct obj {
	struct osmo_fsm_inst *fi;
	struct scene *s;
	struct obj *parent;
	struct obj *child[2];
	struct obj *other[3];
};

static void scene_forget_obj(struct scene *s, struct obj *obj)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(obj->s->o); i++) {
		if (obj->s->o[i] != obj)
			continue;
		LOGPFSML(obj->fi, LOGL_DEBUG, "scene forgets %s\n", obj->fi->id);
		obj->s->o[i] = NULL;
	}
}

struct scene *g_scene = NULL;

#define GET() \
	char *token = talloc_asprintf(g_scene, "%s.%s()", obj->fi->id, __func__); \
	osmo_use_count_get_put(&g_scene->use_count, token, 1)

#define PUT() osmo_use_count_get_put(&g_scene->use_count, token, -1)

void alive_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	LOGPFSML(fi, LOGL_DEBUG, "%s()\n", __func__);
}

/* Remove obj->other[*] reference, return true if found and removed, false if not. */
bool other_gone(struct obj *obj, struct obj *other)
{
	int i;
	GET();
	for (i = 0; i < ARRAY_SIZE(obj->other); i++) {
		if (obj->other[i] == other) {
			obj->other[i] = NULL;
			LOGPFSML(obj->fi, LOGL_DEBUG, "EV_OTHER_GONE: Dropped reference %s.other[%d] = %s\n", obj->fi->id, i,
				 other->fi->id);
			PUT();
			return true;
		}
	}
	PUT();
	return false;
}

/* Remove obj->child[*] reference, return true if more children remain after this, false if all are gone */
bool child_gone(struct obj *obj, struct obj *child)
{
	int i;
	bool found;
	if (!child) {
		LOGPFSML(obj->fi, LOGL_DEBUG, "EV_CHILD_GONE with NULL data, must be a parent_term event. Ignore.\n");
		return true;
	}
	GET();
	found = false;
	for (i = 0; i < ARRAY_SIZE(obj->child); i++) {
		if (obj->child[i] == child) {
			obj->child[i] = NULL;
			LOGPFSML(obj->fi, LOGL_DEBUG, "EV_CHILD_GONE: Dropped reference %s.child[%d] = %s\n", obj->fi->id, i,
				 child->fi->id);
			found = true;
		}
	}
	if (!found)
		LOGPFSML(obj->fi, LOGL_ERROR, "EV_CHILD_GONE: cannot find child %s\n",
			 child && child->fi ? child->fi->id : "(null)");

	/* Any children left? */
	for (i = 0; i < ARRAY_SIZE(obj->child); i++) {
		if (obj->child[i]) {
			LOGPFSML(obj->fi, LOGL_DEBUG, "still exists: child[%d]\n", i);
			PUT();
			return true;
		}
	}
	LOGPFSML(obj->fi, LOGL_DEBUG, "No more children\n");
	PUT();
	return false;
}

void alive(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct obj *obj = fi->priv;
	GET();
	LOGPFSML(fi, LOGL_DEBUG, "%s(%s)\n", __func__, osmo_fsm_event_name(fi->fsm, event));
	switch (event) {
	case EV_OTHER_GONE:
		if (other_gone(obj, data)) {
			/* Something this object depends on is gone, trigger deallocation */
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, 0);
		}
		break;

	case EV_CHILD_GONE:
		if (!child_gone(obj, data)) {
			/* All children are gone. Deallocate. */
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, 0);
		}
		break;

	case EV_DESTROY:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, 0);
		break;

	default:
		OSMO_ASSERT(false);
	}
	PUT();
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state test_fsm_states[] = {
	[ST_ALIVE] = {
		.name = "alive",
		.in_event_mask = 0
			| S(EV_CHILD_GONE)
			| S(EV_OTHER_GONE)
			| S(EV_DESTROY)
			,
		.out_state_mask = 0
			| S(ST_ALIVE)
			,
		.onenter = alive_onenter,
		.action = alive,
	},
};

void cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct obj *obj = fi->priv;
	int i;
	GET();
	LOGPFSML(fi, LOGL_DEBUG, "%s()\n", __func__);

	/* Remove from the scene overview for this test */
	scene_forget_obj(obj->s, obj);

	/* Signal "other" objects */
	for (i = 0; i < ARRAY_SIZE(obj->other); i++) {
		struct obj *other = obj->other[i];
		if (!other)
			continue;
		LOGPFSML(fi, LOGL_DEBUG, "removing reference %s.other[%d] -> %s\n",
			 obj->fi->id, i, other->fi->id);
		obj->other[i] = NULL;
		osmo_fsm_inst_dispatch(other->fi, EV_OTHER_GONE, obj);
	}

	if (obj->parent)
		osmo_fsm_inst_dispatch(obj->parent->fi, EV_CHILD_GONE, obj);

	/* children are handled by fsm.c: term event / osmo_fsm_inst_term_children() */
	LOGPFSML(fi, LOGL_DEBUG, "%s() done\n", __func__);
	PUT();
}

int timer_cb(struct osmo_fsm_inst *fi)
{
	LOGPFSML(fi, LOGL_DEBUG, "%s()\n", __func__);
	return 1;
}

void pre_term(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	LOGPFSML(fi, LOGL_DEBUG, "%s()\n", __func__);
}

struct osmo_fsm test_fsm = {
	.name = "test",
	.states = test_fsm_states,
	.num_states = ARRAY_SIZE(test_fsm_states),
	.cleanup = cleanup,
	.timer_cb = timer_cb,
	.event_names = test_fsm_event_names,
	.pre_term = pre_term,
	.log_subsys = DLGLOBAL,
};

void *ctx = NULL;

static struct obj *obj_alloc(struct scene *s, struct obj *parent, const char *id) {
	struct osmo_fsm_inst *fi;
	struct obj *obj;
	if (!parent) {
		fi = osmo_fsm_inst_alloc(&test_fsm, s, NULL, LOGL_DEBUG, id);
		OSMO_ASSERT(fi);
	} else {
		fi = osmo_fsm_inst_alloc_child(&test_fsm, parent->fi, EV_CHILD_GONE);
		OSMO_ASSERT(fi);
		osmo_fsm_inst_update_id(fi, id);
	}

	obj = talloc_zero(fi, struct obj);
	fi->priv = obj;
	*obj = (struct obj){
		.fi = fi,
			.s = s,
			.parent = parent,
	};

	if (parent) {
		int i;
		for (i = 0; i < ARRAY_SIZE(parent->child); i++) {
			if (parent->child[i])
				continue;
			parent->child[i] = obj;
			break;
		}
	}

	return obj;
};

void obj_add_other(struct obj *a, struct obj *b)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(a->other); i++) {
		if (a->other[i])
			i++;
		a->other[i] = b;
		LOGPFSML(a->fi, LOGL_DEBUG, "%s.other[%d] = %s\n", a->fi->id, i, b->fi->id);
		return;
	}
}

void obj_set_other(struct obj *a, struct obj *b)
{
	obj_add_other(a, b);
	obj_add_other(b, a);
}

static struct scene *scene_alloc(void)
{
	struct scene *s = talloc_zero(ctx, struct scene);
	s->use_count.talloc_object = s;
	s->use_count.use_cb = use_cb;

	LOGP(DLGLOBAL, LOGL_DEBUG, "%s()\n", __func__);

	s->o[root] = obj_alloc(s, NULL, "root");

	s->o[branch0] = obj_alloc(s, s->o[root], "_branch0");

	s->o[twig0a] = obj_alloc(s, s->o[branch0], "__twig0a");

	s->o[twig0b] = obj_alloc(s, s->o[branch0], "__twig0b");

	s->o[branch1] = obj_alloc(s, s->o[root], "_branch1");
	s->o[twig1a] = obj_alloc(s, s->o[branch1], "__twig1a");
	s->o[twig1b] = obj_alloc(s, s->o[branch1], "__twig1b");

	s->o[other] = obj_alloc(s, NULL, "other");

	obj_set_other(s->o[branch0], s->o[other]);
	obj_set_other(s->o[twig0a], s->o[other]);
	obj_set_other(s->o[branch1], s->o[other]);
	obj_set_other(s->o[twig1a], s->o[root]);

	return s;
}

static int scene_dump(struct scene *s)
{
	int i;
	int got = 0;
	for (i = 0; i < ARRAY_SIZE(s->o); i++) {
		if (!s->o[i])
			continue;
		LOGP(DLGLOBAL, LOGL_DEBUG, "  %s\n", s->o[i]->fi->id);
		got++;
	}
	return got;
}

static void scene_clean(struct scene *s)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(s->o); i++) {
		if (!s->o[i])
			continue;
		osmo_fsm_inst_term(s->o[i]->fi, OSMO_FSM_TERM_ERROR, 0);
		s->o[i] = NULL;
	}
	talloc_free(s);
}

void obj_destroy(struct obj *obj)
{
	osmo_fsm_inst_dispatch(obj->fi, EV_DESTROY, NULL);
}

void obj_term(struct obj *obj)
{
	osmo_fsm_inst_term(obj->fi, OSMO_FSM_TERM_REGULAR, NULL);
}

void test_dealloc(enum objname trigger, bool by_destroy_event, void *loop_ctx)
{
	struct scene *s = scene_alloc();
	const char *label = by_destroy_event ? "destroy-event" : "term";
	int remain;
	g_scene = s;
	if (!s->o[trigger]) {
		LOGP(DLGLOBAL, LOGL_DEBUG, "--- Test disabled: object %d was not created. Cleaning up.\n",
		     trigger);
		scene_clean(s);
		return;
	}
	LOGP(DLGLOBAL, LOGL_DEBUG, "------ before %s cascade, got:\n", label);
	scene_dump(s);
	LOGP(DLGLOBAL, LOGL_DEBUG, "---\n");
	LOGP(DLGLOBAL, LOGL_DEBUG, "--- %s at %s\n", label, s->o[trigger]->fi->id);

	if (by_destroy_event)
		obj_destroy(s->o[trigger]);
	else
		obj_term(s->o[trigger]);

	LOGP(DLGLOBAL, LOGL_DEBUG, "--- after %s cascade:\n", label);
	remain = scene_dump(s);
	if (remain) {
		LOGP(DLGLOBAL, LOGL_DEBUG, "--- %d objects remain. cleaning up\n", remain);
	} else
		LOGP(DLGLOBAL, LOGL_DEBUG, "--- all deallocated.\n");

	if (loop_ctx) {
		fprintf(stderr, "*** loop_ctx contains %zu blocks, deallocating.\n",
			talloc_total_blocks(loop_ctx));
		talloc_free_children(loop_ctx);
	}

	/* Silently free the remaining objects. */
	scene_clean(s);
	if (loop_ctx)
		talloc_free_children(loop_ctx);
}

static void trigger_tests(void *loop_ctx)
{
	size_t ctx_blocks;
	size_t ctx_size;
	enum objname trigger;
	int by_destroy_event;

	ctx_blocks = talloc_total_blocks(ctx);
	ctx_size = talloc_total_size(ctx);

	for (trigger = 0; trigger < scene_size; trigger++) {
		for (by_destroy_event = 0; by_destroy_event < 2; by_destroy_event++) {
			test_dealloc(trigger, (bool)by_destroy_event, loop_ctx);

			if (ctx_blocks != talloc_total_blocks(ctx)
			    || ctx_size != talloc_total_size(ctx)) {
				talloc_report_full(ctx, stderr);
				OSMO_ASSERT(false);
			}
		}
	}
}

void test_osmo_fsm_term_safely(void)
{
	fprintf(stderr, "\n\n%s()\n", __func__);
	osmo_fsm_term_safely(true);
	trigger_tests(NULL);
	osmo_fsm_term_safely(false);
	fprintf(stderr, "\n\n%s() done\n", __func__);
}

void test_osmo_fsm_set_dealloc_ctx(void)
{
	fprintf(stderr, "\n\n%s()\n", __func__);
	void *dealloc_ctx = talloc_named_const(ctx, 0, "fsm_dealloc");
	osmo_fsm_set_dealloc_ctx(dealloc_ctx);
	trigger_tests(dealloc_ctx);
	osmo_fsm_set_dealloc_ctx(NULL);
	fprintf(stderr, "\n\n%s() done\n", __func__);
}

int main(void)
{
	ctx = talloc_named_const(NULL, 0, "main");
	osmo_init_logging2(ctx, NULL);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	osmo_fsm_log_addr(false);

	log_set_category_filter(osmo_stderr_target, DLGLOBAL, 1, LOGL_DEBUG);

	OSMO_ASSERT(osmo_fsm_register(&test_fsm) == 0);

	test_osmo_fsm_term_safely();
	test_osmo_fsm_set_dealloc_ctx();

	talloc_free(ctx);
	return 0;
}
