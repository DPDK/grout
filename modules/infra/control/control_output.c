// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_control.h>
#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_mbuf.h>

#include <event2/event.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>

static struct rte_ring *ctrlout_ring;
static struct event *ctrlout_ev;

static bool tshutdown;
static pthread_t thread_id;
static pthread_cond_t cv;
static pthread_mutex_t mp;

int control_output_push(struct rte_mbuf *m) {
	return rte_ring_enqueue(ctrlout_ring, m);
}

static void poll_control_output_ring(evutil_socket_t, short, void *) {
	struct rte_mbuf *mbuf;

	while (rte_ring_dequeue(ctrlout_ring, (void *)&mbuf) == 0)
		control_output_mbuf_data(mbuf)->callback(mbuf);
}

void signal_control_ouput_message() {
	pthread_cond_signal(&cv);
}

static void *cond_wait_to_event(void *) {
	struct timespec ts;
	pthread_setname_np(pthread_self(), "gr:ctrl-output");
	clock_gettime(CLOCK_REALTIME, &ts);

	while (atomic_load_explicit(&tshutdown, memory_order_acquire) == 0) {
		ts.tv_sec += 1;
		pthread_mutex_lock(&mp);
		if (pthread_cond_timedwait(&cv, &mp, &ts) == 0) {
			evuser_trigger(ctrlout_ev);
		}
		pthread_mutex_unlock(&mp);
	}
	return NULL;
}

static pthread_attr_t attr;

static void control_output_init(struct event_base *ev_base) {
	atomic_init(&tshutdown, 0);

	if (pthread_attr_init(&attr))
		ABORT("pthread_attr_init");

	if (pthread_mutex_init(&mp, NULL))
		ABORT("pthread_mutex_init failed");

	if (pthread_cond_init(&cv, NULL))
		ABORT("pthread_cond_init failed");

	ctrlout_ring = rte_ring_create(
		"control_output",
		RTE_GRAPH_BURST_SIZE * 4,
		SOCKET_ID_ANY,
		RING_F_MP_RTS_ENQ | RING_F_MC_RTS_DEQ
	);
	if (ctrlout_ring == NULL)
		ABORT("rte_ring_create(ctrl_output): %s", rte_strerror(rte_errno));

	ctrlout_ev = event_new(
		ev_base, -1, EV_PERSIST | EV_FINALIZE, poll_control_output_ring, NULL
	);
	if (ctrlout_ev == NULL)
		ABORT("event_new() failed");

	pthread_create(&thread_id, &attr, cond_wait_to_event, 0);
}

static void control_output_fini(struct event_base *) {
	atomic_store_explicit(&tshutdown, 1, memory_order_release);
	signal_control_ouput_message();
	pthread_attr_destroy(&attr);
	pthread_join(thread_id, NULL);
	pthread_cond_destroy(&cv);
	event_free(ctrlout_ev);
	rte_ring_free(ctrlout_ring);
	pthread_mutex_destroy(&mp);
}

static struct gr_module control_output_module = {
	.name = "control_output",
	.init = control_output_init,
	.fini = control_output_fini,
};

RTE_INIT(control_output_module_init) {
	gr_register_module(&control_output_module);
}
