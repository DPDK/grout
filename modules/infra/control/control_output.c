// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_mbuf.h>
#include <gr_module.h>

#include <event2/event.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>

static struct rte_ring *ctrlout_ring;

int control_output_enqueue(struct rte_mbuf *m) {
	return rte_ring_enqueue(ctrlout_ring, m);
}

static void control_output_poll(evutil_socket_t, short, void *) {
	struct control_output_mbuf_data *data;
	struct rte_mbuf *mbuf;
	void *ring_item;

	while (rte_ring_dequeue(ctrlout_ring, &ring_item) == 0) {
		mbuf = ring_item;
		data = control_output_mbuf_data(mbuf);
		if (data->callback != NULL)
			control_output_mbuf_data(mbuf)->callback(mbuf);
		else
			rte_pktmbuf_free(mbuf);
	}
}

static atomic_bool thread_shutdown;
static pthread_t thread_id;
static pthread_cond_t cond;
static pthread_mutex_t mutex;
static struct event *ctrlout_ev;

void control_output_done(void) {
	pthread_cond_signal(&cond);
}

static void *cond_wait_to_event(void *) {
	pthread_setname_np(pthread_self(), "gr:ctrl-output");

	while (!atomic_load(&thread_shutdown)) {
		pthread_mutex_lock(&mutex);
		if (pthread_cond_wait(&cond, &mutex) == 0)
			evuser_trigger(ctrlout_ev);
		pthread_mutex_unlock(&mutex);
	}

	return NULL;
}

static pthread_attr_t attr;

static void control_output_init(struct event_base *ev_base) {
	atomic_init(&thread_shutdown, false);

	if (pthread_attr_init(&attr))
		ABORT("pthread_attr_init");

	if (pthread_mutex_init(&mutex, NULL))
		ABORT("pthread_mutex_init failed");

	if (pthread_cond_init(&cond, NULL))
		ABORT("pthread_cond_init failed");

	ctrlout_ring = rte_ring_create(
		"control_output",
		RTE_GRAPH_BURST_SIZE * 4,
		SOCKET_ID_ANY,
		RING_F_MP_RTS_ENQ | RING_F_SC_DEQ
	);
	if (ctrlout_ring == NULL)
		ABORT("rte_ring_create(ctrl_output): %s", rte_strerror(rte_errno));

	ctrlout_ev = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, control_output_poll, NULL);
	if (ctrlout_ev == NULL)
		ABORT("event_new() failed");

	pthread_create(&thread_id, &attr, cond_wait_to_event, NULL);
}

static void control_output_fini(struct event_base *) {
	atomic_store(&thread_shutdown, true);
	control_output_done();
	pthread_join(thread_id, NULL);
	pthread_attr_destroy(&attr);
	pthread_cond_destroy(&cond);
	event_free(ctrlout_ev);
	rte_ring_free(ctrlout_ring);
	pthread_mutex_destroy(&mutex);
}

static struct gr_module control_output_module = {
	.name = "control_output",
	.init = control_output_init,
	.fini = control_output_fini,
};

RTE_INIT(control_output_module_init) {
	gr_register_module(&control_output_module);
}
