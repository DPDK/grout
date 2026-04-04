// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "control_queue.h"
#include "log.h"
#include "metrics.h"
#include "module.h"

#include <gr_macro.h>

#include <event2/event.h>
#include <rte_ring.h>

#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>

struct control_queue_item {
	control_queue_cb_t callback;
	void *obj;
	uintptr_t priv;
};

#define CONTROL_QUEUE_SIZE RTE_GRAPH_BURST_SIZE * 4
static atomic_uint_fast64_t push_failed_items;
static atomic_uint_fast64_t pushed_items;
static atomic_uint_fast64_t popped_items;
static struct rte_ring *ctrlq_ring;

int control_queue_push(control_queue_cb_t cb, void *obj, uintptr_t priv) {
	struct control_queue_item item = {
		.callback = cb,
		.obj = obj,
		.priv = priv,
	};
	int ret;

	assert(cb != NULL);
	assert(obj != NULL);

	ret = rte_ring_enqueue_elem(ctrlq_ring, &item, sizeof(item));
	if (ret == 0)
		atomic_fetch_add_explicit(&pushed_items, 1, memory_order_relaxed);
	else
		atomic_fetch_add_explicit(&push_failed_items, 1, memory_order_relaxed);

	return ret;
}

static void control_queue_poll(evutil_socket_t, short, void *priv) {
	struct control_queue_item items[RTE_GRAPH_BURST_SIZE];
	struct control_queue_drain *drain = priv;
	unsigned count, drained = 0;

again:
	count = rte_ring_dequeue_burst_elem(
		ctrlq_ring, items, sizeof(items[0]), ARRAY_DIM(items), NULL
	);

	atomic_fetch_add_explicit(&popped_items, count, memory_order_relaxed);

	for (unsigned i = 0; i < count; i++) {
		items[i].callback(items[i].obj, items[i].priv, drain);
	}
	drained += ARRAY_DIM(items);

	if (drain != NULL && count == ARRAY_DIM(items) && drained < CONTROL_QUEUE_SIZE)
		goto again;
}

static atomic_bool thread_shutdown;
static pthread_t thread_id;
static sem_t sem;
static struct event *ctrlq_ev;

void control_queue_done(void) {
	sem_post(&sem);
}

int control_queue_set_affinity(size_t set_size, const cpu_set_t *affinity) {
	return pthread_setaffinity_np(thread_id, set_size, affinity);
}

static void *sem_wait_to_event(void *) {
	pthread_setname_np(pthread_self(), "grout:ctrlq");

	while (!atomic_load(&thread_shutdown)) {
		sem_wait(&sem);
		for (unsigned i = 0; i < RTE_GRAPH_BURST_SIZE; i++) {
			// Drain the semaphore to coalesce control_queue_poll calls.
			// Only drain up to RTE_GRAPH_BURST_SIZE to prevent the ring
			// from getting full before control_queue_poll is invoked.
			if (sem_trywait(&sem) < 0)
				break;
		}
		evuser_trigger(ctrlq_ev);
	}

	return NULL;
}

void control_queue_drain(uint32_t event, const void *obj) {
	struct control_queue_drain drain = {event, obj};
	control_queue_poll(0, 0, &drain);
}

METRIC_COUNTER(m_cqueue_fail, "control_queue_fail", "Total number of enqueue failures");
METRIC_COUNTER(m_cqueue_push, "control_queue_push", "Total number of enqueued items");
METRIC_COUNTER(m_cqueue_pop, "control_queue_pop", "Total number of enqueued items");

static void control_queue_metrics_collect(struct metrics_writer *w) {
	struct metrics_ctx ctx;

	metrics_ctx_init(&ctx, w, NULL);
	metric_emit(
		&ctx, &m_cqueue_push, atomic_load_explicit(&pushed_items, memory_order_relaxed)
	);
	metric_emit(&ctx, &m_cqueue_pop, atomic_load_explicit(&popped_items, memory_order_relaxed));
	metric_emit(
		&ctx, &m_cqueue_fail, atomic_load_explicit(&push_failed_items, memory_order_relaxed)
	);
}

static struct metrics_collector control_queue_collector = {
	.name = "control queue",
	.collect = control_queue_metrics_collect,
};

static void control_queue_init(struct event_base *ev_base) {
	atomic_init(&thread_shutdown, false);

	if (sem_init(&sem, 0, 0))
		ABORT("sem_init");

	ctrlq_ring = rte_ring_create_elem(
		"control_queue",
		sizeof(struct control_queue_item),
		CONTROL_QUEUE_SIZE,
		SOCKET_ID_ANY,
		RING_F_MP_RTS_ENQ | RING_F_SC_DEQ
	);
	if (ctrlq_ring == NULL)
		ABORT("rte_ring_create(control_queue): %s", rte_strerror(rte_errno));

	ctrlq_ev = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, control_queue_poll, NULL);
	if (ctrlq_ev == NULL)
		ABORT("event_new() failed");

	if (pthread_create(&thread_id, NULL, sem_wait_to_event, NULL))
		ABORT("pthread_create() failed");
}

static void control_queue_fini(struct event_base *) {
	atomic_store(&thread_shutdown, true);
	control_queue_done();
	pthread_join(thread_id, NULL);
	sem_destroy(&sem);
	event_free(ctrlq_ev);
	rte_ring_free(ctrlq_ring);
}

static struct gr_module module = {
	.name = "control_queue",
	.init = control_queue_init,
	.fini = control_queue_fini,
};

RTE_INIT(control_queue_module_init) {
	gr_register_module(&module);
	metrics_register(&control_queue_collector);
}
