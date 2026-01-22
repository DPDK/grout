// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_control_output.h>
#include <gr_control_queue.h>
#include <gr_event.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_mbuf.h>
#include <gr_module.h>
#include <gr_nexthop.h>

#include <event2/event.h>

#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdlib.h>

#define CONTROL_QUEUE_SIZE RTE_GRAPH_BURST_SIZE * 4
static struct rte_ring *ctrlq_ring;

int control_queue_push(struct rte_mbuf *m) {
	return rte_ring_enqueue(ctrlq_ring, m);
}

static void control_queue_poll(evutil_socket_t, short, void *priv) {
	struct control_queue_drain *drain = priv;
	struct control_output_mbuf_data *data;
	void *mbufs[RTE_GRAPH_BURST_SIZE];
	unsigned count, drained = 0;

again:
	count = rte_ring_dequeue_burst(ctrlq_ring, mbufs, ARRAY_DIM(mbufs), NULL);
	for (unsigned i = 0; i < count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];
		data = control_output_mbuf_data(mbuf);
		assert(data->callback != NULL);
		data->callback(mbuf, drain);
	}
	drained += ARRAY_DIM(mbufs);

	if (drain != NULL && count == ARRAY_DIM(mbufs) && drained < CONTROL_QUEUE_SIZE)
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

// When interfaces or nexthops are deleted, drain the control queue
// to free any packets that reference the deleted object. This prevents
// callbacks from being invoked with dangling pointers.
static void event_handler(uint32_t event, const void *obj) {
	struct control_queue_drain drain = {event, obj};
	control_queue_poll(0, 0, &drain);
}

static struct gr_event_subscription event_sub = {
	.callback = event_handler,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IFACE_REMOVE,
		GR_EVENT_NEXTHOP_DELETE,
	},
};

static void control_queue_init(struct event_base *ev_base) {
	atomic_init(&thread_shutdown, false);

	if (sem_init(&sem, 0, 0))
		ABORT("sem_init");

	ctrlq_ring = rte_ring_create(
		"control_queue",
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
	gr_event_subscribe(&event_sub);
}
